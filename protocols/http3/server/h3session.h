#ifndef __H3SESSION__
#define __H3SESSION__

#include <stddef.h>
#include <stdint.h>

#include "h3error.h"
#include "h3frame.h"
#include "h3priority.h"
#include "h3unistream.h"

/* "No stream". Stream ids are 62-bit (RFC 9000 §2.1), so the top of the range
 * cannot collide with a real one. */
#define H3_STREAM_ID_NONE UINT64_MAX

struct qpack_decoder;
struct qpack_encoder;
struct env;

/* The connection-level half of HTTP/3 (RFC 9114 §6, §7.2) -- everything that is
 * true of the connection rather than of one request: the service streams, the
 * peer's SETTINGS, GOAWAY, and the QPACK codecs every stream shares.
 *
 * The per-request half is h3stream. The transport glue that reads QUIC streams
 * and writes bytes back is phase 7 (docs/http3/07-integration.md); this module
 * deliberately touches neither quicconn_t nor connection_t, so the protocol
 * rules can be driven by a test that feeds bytes and reads verdicts. What it
 * produces instead of I/O is: the bytes our own service streams must carry
 * (h3session_control_preamble and friends) and a verdict per feed.
 *
 * ## The two rules that shape the whole module
 *
 * **Service streams and request streams arrive independently.** A QUIC stream
 * is ordered within itself and unordered against every other, so SETTINGS may
 * land after the first request and QPACK instructions on either side of the
 * block that needs them. Nothing here may block waiting for SETTINGS.
 *
 * **Closing a critical stream ends the connection.** The control stream and
 * both QPACK streams (§6.2.6): FIN and RESET_STREAM alike are
 * H3_CLOSED_CRITICAL_STREAM. This is the opposite of a request stream, where
 * FIN is how it is supposed to end. */

typedef enum {
    H3SESSION_OK = 0,
    /* Discard this stream: STOP_SENDING(verdict.error) and forget it. Not fatal
     * to the connection (§6.2.3). */
    H3SESSION_STOP_SENDING,
    /* CONNECTION_CLOSE(verdict.error) with an HTTP/3 application code. */
    H3SESSION_CONN_ERROR
} h3session_action_e;

typedef struct {
    h3session_action_e action;
    uint64_t           error;
} h3session_verdict_t;

/* ---- One inbound unidirectional stream ---- *
 *
 * Held in quicstream_t::app for peer-initiated uni-streams. The type prefix is
 * a varint that may straddle chunks, so the state has to live per stream and
 * survive between feeds -- and until it is read, the session cannot know which
 * of the four kinds of stream it is dealing with. */

typedef struct h3uni_recv {
    uint64_t         id;         /* the QUIC stream id, for logs and diagnostics */
    h3uni_parser_t   prefix;
    int              typed;      /* the prefix has been read; `type` is valid */
    uint64_t         type;
    h3uni_action_e   action;     /* what h3uni_server_classify said about it */

    /* Control stream only: frames are parsed out of the rest of the stream. */
    h3frame_parser_t frames;
    int              settings_seen;

    int              closed;     /* FIN or RESET has been reported */

    /* QPACK instructions, unlike control frames, have no outer length. Their
     * prefix integer or string may straddle QUIC reads, so an unconsumed suffix
     * lives here until the next feed. Unused for other uni-stream types. */
    uint8_t*         qpack_pending;
    size_t           qpack_pending_len;
    size_t           qpack_pending_cap;
} h3uni_recv_t;

h3uni_recv_t* h3uni_recv_create(uint64_t id);
void h3uni_recv_free(h3uni_recv_t* uni);

/* ---- The session ---- */

/* ---- Policy ---- *
 *
 * Parsed and validated from an unpublished reload candidate first, then
 * published through atomics because old and new worker generations overlap.
 * Called from module_loader next to h2_policy_init().
 *
 * Until this existed the field-section limit rode on http2_max_header_list_size
 * because it happens to be the same budget for the same reason. That was a
 * stopgap and said so: two protocols sharing one operator-facing key means
 * neither can be tuned without the other. */
int h3_policy_validate(const struct env* candidate);
int h3_policy_init(void);

/* One accepted PRIORITY_UPDATE, waiting for the transport to apply it. */
typedef struct {
    uint64_t     stream_id;
    h3priority_t priority;
} h3session_priority_t;

/* How many may be outstanding between two drains. Eight is well past what a
 * browser sends in one flight; the queue exists to survive a burst, not to
 * store a history. */
#define H3SESSION_PRIORITY_QUEUE 8

typedef struct h3session {
    /* Owned by h3conn, not by the connection context: it is h3conn_t that lives
     * in connection_server_ctx_t::parser and therefore h3conn_t that carries
     * the `void (*free)(void*)` first-field contract. */

    /* Shared by every stream on the connection. */
    struct qpack_decoder* qdec;
    struct qpack_encoder* qenc;
    size_t                 qpack_memory_reserved;

    /* What we advertise, and what the peer advertised. */
    h3settings_t local_settings;
    h3settings_t peer_settings;
    int          peer_settings_seen;

    /* Peer service streams: uniqueness is tracked here, the ids are kept for
     * logging and for telling a critical close apart from an ordinary one. */
    h3uni_seen_t peer_uni;
    uint64_t     ctrl_recv_id, qpack_enc_recv_id, qpack_dec_recv_id;

    /* Our own, assigned when the glue opens them (phase 7). The grease stream
     * is optional and may be H3_STREAM_ID_NONE -- the peer is entitled to grant
     * only the three the protocol requires. */
    uint64_t     ctrl_send_id, qpack_enc_send_id, qpack_dec_send_id, grease_send_id;

    /* §7.2.7: a client may raise MAX_PUSH_ID but never lower it. We never push,
     * so this is kept only to enforce that rule and to answer CANCEL_PUSH. */
    int          max_push_id_seen;
    uint64_t     max_push_id;

    /* §5.2. Ours carries a stream id, theirs a push id; both may only ever
     * shrink. */
    int          goaway_sent;
    uint64_t     goaway_id;
    int          peer_goaway_seen;
    uint64_t     peer_goaway_id;

    /* ---- Abuse budgets (docs/http3/07-integration.md §4) ---- *
     *
     * Leaky buckets in milli-tokens, the same shape docs/http2/08 phase A
     * settled on. Two buckets rather than one because an honest client's rate
     * of cancellations is nothing like its rate of control frames, and a single
     * bucket would have to be set by the looser of the two. */
    int64_t      abort_tokens;
    uint64_t     abort_epoch_ms;
    int64_t      ctrl_tokens;
    uint64_t     ctrl_epoch_ms;

    /* PRIORITY_UPDATE frames that have been accepted and not yet handed to the
     * transport (RFC 9218 §7). A queue rather than a field on the verdict,
     * because one feed can carry several frames and a verdict describes the
     * feed, not each frame in it -- reporting only the last would silently drop
     * the others.
     *
     * Bounded and oldest-dropped: the peer chooses how fast these arrive, and
     * they already cost a control-frame token, so the queue must not be a way
     * to make the server allocate. Losing the oldest is safe in the way losing
     * a priority signal always is -- it is advisory, and a later one for the
     * same stream supersedes it anyway. */
    h3session_priority_t priority_queue[H3SESSION_PRIORITY_QUEUE];
    size_t               priority_head;    /* next to hand out */
    size_t               priority_count;
} h3session_t;

/* Take the oldest pending PRIORITY_UPDATE. Returns 0 when there are none. */
int h3session_take_priority(h3session_t* s, h3session_priority_t* out);

/* Charge one stream cancellation. Returns 0 when the budget is spent and the
 * caller must close the connection with H3_EXCESSIVE_LOAD.
 *
 * A stream opened and immediately reset costs a QPACK decode, a dispatch and a
 * concurrency slot held for no measurable time -- Rapid Reset (CVE-2023-44487)
 * by another name. QUIC makes it *cheaper* than it was in HTTP/2: no
 * three-way handshake stands between the attacker and the next stream, so the
 * budget matters more here, not less. */
int h3session_abort_spend(h3session_t* s);

/* Charge one control-stream frame that advances nothing: a GOAWAY or
 * MAX_PUSH_ID that changes no state, or a frame type we skip. Each is legal,
 * costs the peer almost nothing to send, and makes us parse. */
int h3session_ctrl_spend(h3session_t* s);

/* What we advertise as SETTINGS_MAX_FIELD_SECTION_SIZE, from the policy. */
uint64_t h3_policy_max_field_section_size(void);

/* The SETTINGS a client is allowed to remember and encode 0-RTT requests
 * against (RFC 9114 §7.2.4.2), written into `out` as
 * {qpack_max_table_capacity, qpack_blocked_streams, max_field_section_size}.
 *
 * Exists for the 0-RTT resumption context (docs/http3/09 §3.1): a client that
 * resumes uses the values it remembers *before* our SETTINGS arrive, so a
 * server that reduced any of them would be decoding a field section against a
 * table the client sized differently. Reading them through one function keeps
 * that list in the module that advertises it, rather than copied into the
 * transport where it would drift. */
#define H3_SETTINGS_DIGEST_VALUES 3
void h3_local_settings_digest(uint64_t out[H3_SETTINGS_DIGEST_VALUES]);

/* `max_field_section_size` is what we advertise (UINT64_MAX = unlimited, which
 * is what "absent" means on the wire). `enable_connect_protocol` advertises
 * RFC 9220 Extended CONNECT. Returns NULL on OOM. */
h3session_t* h3session_create(uint64_t max_field_section_size, int enable_connect_protocol);
void h3session_free(h3session_t* s);

/* ---- What our own service streams must carry ---- */

/* The control stream's opening bytes: the stream-type varint 0x00 followed by
 * the SETTINGS frame, which §6.2.1 requires to be the first frame on it.
 * Returns bytes written, or 0 if they do not fit. */
size_t h3session_control_preamble(const h3session_t* s, uint8_t* dst, size_t cap);

/* The stream-type varint for one of our other outbound uni-streams: the QPACK
 * encoder (0x02) and decoder (0x03) streams, which carry table instructions and
 * acknowledgements once either side advertises a capacity, and one
 * grease stream, which stays empty forever. */
size_t h3session_uni_preamble(uint8_t* dst, size_t cap, uint64_t type);

/* A GOAWAY frame for our control stream. `stream_id` is the first client bidi
 * stream we will not serve; it may only ever shrink (§5.2), and a call that
 * would raise it is refused with 0. */
size_t h3session_goaway_encode(h3session_t* s, uint8_t* dst, size_t cap, uint64_t stream_id);

/* ---- Driving inbound service streams ---- */

/* Feed bytes received on a peer-initiated unidirectional stream. Reads the type
 * prefix on first sight, classifies it, and routes the remainder: control-stream
 * frames are interpreted here, QPACK encoder instructions are validated against
 * what we advertised, and grease/unknown streams are discarded.
 *
 * `fin` marks the chunk that ends the stream, which for a critical stream is
 * itself the error H3_CLOSED_CRITICAL_STREAM. */
h3session_verdict_t h3session_uni_feed(h3session_t* s, h3uni_recv_t* uni,
                                       const uint8_t* data, size_t len, int fin);

/* The peer reset a unidirectional stream, or it ended. Same verdict as a FIN:
 * fatal if the stream was critical, harmless otherwise. */
h3session_verdict_t h3session_uni_closed(h3session_t* s, h3uni_recv_t* uni);

/* Whether a request may still be accepted on `stream_id`: false once we have
 * sent a GOAWAY naming it or a lower id (§5.2). Such a request is rejected with
 * H3_REQUEST_REJECTED, which tells the client it is safe to retry elsewhere. */
int h3session_accepts_request(const h3session_t* s, uint64_t stream_id);

#endif

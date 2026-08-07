#ifndef __H3SESSION__
#define __H3SESSION__

#include <stddef.h>
#include <stdint.h>

#include "h3error.h"
#include "h3frame.h"
#include "h3unistream.h"

struct qpack_decoder;
struct qpack_encoder;

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
} h3uni_recv_t;

h3uni_recv_t* h3uni_recv_create(uint64_t id);
void h3uni_recv_free(h3uni_recv_t* uni);

/* ---- The session ---- */

typedef struct h3session {
    /* MUST be first: the session lives in connection_server_ctx_t::parser,
     * which is a void* freed through this pointer -- the same contract
     * h2session_t carries. */
    void (*free)(void*);

    /* Shared by every stream on the connection. */
    struct qpack_decoder* qdec;
    struct qpack_encoder* qenc;

    /* What we advertise, and what the peer advertised. */
    h3settings_t local_settings;
    h3settings_t peer_settings;
    int          peer_settings_seen;

    /* Peer service streams: uniqueness is tracked here, the ids are kept for
     * logging and for telling a critical close apart from an ordinary one. */
    h3uni_seen_t peer_uni;
    uint64_t     ctrl_recv_id, qpack_enc_recv_id, qpack_dec_recv_id;

    /* Our own, assigned when the glue opens them (phase 7). */
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
} h3session_t;

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
 * encoder (0x02) and decoder (0x03) streams, which stay empty in lite, and one
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

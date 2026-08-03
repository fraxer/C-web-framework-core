#ifndef __H2SESSION__
#define __H2SESSION__

#include "connection.h"
#include "request.h"      /* requestparser_t (first member: free vtable) */
#include "h2frame.h"
#include "h2stream.h"
#include "hpack.h"
#include "cqueue.h"       /* publish_queue (docs/concurrency/01 §4.1, phase B) */
#include "httpcontext.h"  /* httpctx_t — h2c_upgrade() entry point */

/* Per-connection HTTP/2 session.
 *
 * Stored in connection_server_ctx_t.parser (replacing the HTTP/1.1 parser), so
 * its first field MUST be the requestparser_t free vtable that __ctx_free calls.
 * The HTTP/1.1 dispatch path is reused unchanged: a request built from frames is
 * handed to http_server_dispatch(), the handler fills httpresponse_t as usual,
 * and the h2 write filter (terminal stage of the h2 filter chain) serializes it
 * back into HEADERS/DATA frames. See docs/http2/05.
 *
 * Several streams may be in flight at once; each owns its request/response, so
 * connection_server_ctx_t.request/response stay NULL on an h2 connection.
 *
 * Concurrency: every field is touched only under connection_s_lock(), from the
 * worker event loop (read/write guards) or from a handler thread, which holds
 * that same lock for the whole handler run. See h2stream.h. */

#define H2_DEFAULT_WINDOW 65535

/* Concurrency limit advertised in SETTINGS_MAX_CONCURRENT_STREAMS. Handlers are
 * serialized per connection by the connection lock, so this bounds how many
 * requests may be outstanding, not how many run at once. */
#define H2_MAX_CONCURRENT_STREAMS 100

typedef struct h2session {
    void (*free)(void*);            /* requestparser_t.base — must be first */

    connection_t* connection;

    /* Own read buffer (the worker's connection->buffer is a shared scratch that
     * is overwritten on every recv, so h2 accumulates frame bytes here). */
    uint8_t* read_buf;
    size_t   read_len;
    size_t   read_cap;

    h2frame_parser_t frame;
    hpack_decoder_t* decoder;
    hpack_encoder_t* encoder;

    /* Stream table (see h2stream.c) and the ids bounding it. Kept in arrival
     * order; the tail pointer makes append and the scheduler's rotate O(1). */
    h2stream_t* streams;
    h2stream_t* streams_tail;
    size_t      stream_count;
    uint32_t    last_stream_id; /* highest id accepted, reported in GOAWAY */

    /* Ready-response handoff from handler threads to the worker
     * (docs/concurrency/01 §4.1, phase B). A handler that has finished fills a
     * response, pushes it here under the queue's own short lock, and re-arms
     * epoll — without walking the stream table. The worker drains this at the
     * start of every write pass (single-threaded, where the table is already
     * its) and does the stream lookup there. Order does not matter: h2 has
     * stream ids. Lock order is connection_s_lock -> publish_queue, never the
     * reverse, matching the WebSocket write_queue (00 §4.4). */
    cqueue_t* publish_queue;

    /* CONTINUATION accumulation (HEADERS without END_HEADERS + CONTINUATION*).
     * Connection-level: a header block may not be interleaved with any other
     * frame, so at most one is ever in progress. */
    uint8_t* cont;
    size_t   cont_len;
    uint32_t cont_stream_id;
    int      cont_end_stream;
    int      cont_active;
    /* Frames in the block being accumulated, HEADERS included. The byte limit
     * above bounds memory but not work: an empty CONTINUATION adds nothing to
     * cont_len and can be repeated forever (docs/http2/08, phase A.3). */
    uint32_t cont_frames;

    /* Peer settings (RFC defaults until the peer sends SETTINGS). */
    uint32_t peer_max_frame_size;
    uint32_t peer_initial_window;
    uint32_t peer_header_table_size;
    /* SETTINGS_MAX_HEADER_LIST_SIZE the peer advertised, 0 = unlimited (its
     * absence and its "no limit" are the same thing to us). Advisory: §6.5.2
     * makes it a hint, so an oversize response is logged, not truncated. */
    uint32_t peer_max_header_list_size;

    /* Budget for stream aborts (docs/http2/08, phase A.2), in milli-tokens.
     * Spent by RST_STREAM on an unanswered stream and by streams we refuse over
     * the concurrency limit — the two ways a peer can make the server do work
     * without ever holding a slot. */
    int64_t  abort_tokens;
    uint64_t abort_epoch_ms;

    /* Connection-level send window (RFC 9113 §6.9); each stream has its own. */
    int64_t  send_window;
    /* Every stream that can still send is out of connection-level window: stop
     * arming EPOLLOUT (the socket is writable, we simply may not send) and wait
     * for a WINDOW_UPDATE. */
    int      window_blocked;

    /* Receive side: the connection window we advertise, plus the counters that
     * auto-scale it (§6.9.1). Streams carry the same state of their own. */
    h2_recv_window_t recv;
    /* A stream window has credit queued but not yet handed over (see
     * h2_recv_settle). Keeps the settle off the stream table on the connections
     * — the overwhelming majority — that never receive a request body. */
    int      stream_credit_pending;
    /* Receive window a stream on this connection has grown to; new streams open
     * there rather than ramping again from the advertised initial value. */
    int64_t  stream_recv_learned;

    /* The stream that stopped mid-frame and must finish before any other may
     * use the socket — otherwise its bytes would be spliced into an unfinished
     * DATA frame. NULL when no frame is in progress.
     *
     * "Mid-frame" is meant literally: a stream that stops on a frame boundary
     * (out of window, or out of write quantum) does NOT get pinned here, because
     * letting somebody else write is exactly the point. See h2_write(). */
    h2stream_t* writing;

    /* Pending outbound frames that did not fit the socket (control frames, the
     * trailing empty DATA). All frame writing happens on the worker's write
     * path under the connection lock, so this needs no lock of its own. */
    uint8_t* out;
    size_t   out_len;
    size_t   out_pos;
    size_t   out_cap;

    /* Error code to report in GOAWAY once a connection error is raised. */
    uint32_t error_code;
    int      goaway_sent;

    /* Lifecycle (Phase 5). last_activity_ms advances on every byte received
     * from the peer (a frame read or a PING ACK) — never on our own writes, so
     * that a server-side response cannot mask a silent client. CLOCK_MONOTONIC.
     * All touched under the connection lock, like the rest of the session. */
    uint64_t last_activity_ms;
    uint64_t ping_sent_ms;      /* 0 = no watchdog PING outstanding */
    uint8_t  ping_payload[8];   /* opaque data of the outstanding PING (for ACK) */

    /* Window tuning (§6.9.1): path RTT measured by our own PING, and the probe
     * currently outstanding. Separate from the watchdog above — this one only
     * measures, it never declares the peer dead. */
    uint32_t rtt_us;
    uint64_t tune_ping_sent_ms; /* 0 = no tuning PING outstanding */
    uint64_t tune_ping_done_ms; /* when the last one was answered (rate limit) */
    uint8_t  tune_ping_payload[8];
    int      draining;          /* GOAWAY(NO_ERROR) sent on shutdown; close once idle */
} h2session_t;

/* Entry point called from __handshake once ALPN selects h2. Returns 1 on
 * success (connection->read/write installed), 0 on allocation failure. */
int h2_server_set_http2(connection_t* connection);

/* h2c prior-knowledge (RFC 9113 §3.4): the first bytes read off a plaintext
 * connection were the 24-byte client preface, possibly followed by more frames
 * in the same packet. Called from __read with the connection lock already held;
 * `len` is how many bytes connection_data_read() already staged in
 * connection->buffer. Builds the session (which expects the client preface),
 * feeds those bytes through the frame parser, and drains pending writes.
 * Returns 1 to keep the connection, 0 to close it. */
int h2_server_set_http2_prior_knowledge(connection_t* connection, size_t len);

/* h2c Upgrade (RFC 9113 §3.2): the decoded HTTP2-Settings header payload, handed
 * to the switch callback after the 101 Switching Protocols response is flushed. */
typedef struct h2_upgrade_settings {
    uint8_t* payload;   /* decoded SETTINGS frame payload (6 bytes per setting) */
    size_t   len;
} h2_upgrade_settings_t;

/* switch_to_protocol callback for the h2c Upgrade path. Called from
 * connection_after_write() under the connection lock, after the 101 is on the
 * wire. `data` is an h2_upgrade_settings_t* (may be NULL if no HTTP2-Settings
 * header was sent). Builds the session (which still expects the client preface —
 * §3.2 has the client send it on seeing the 101), applies the peer settings from
 * the header, makes stream 1 out of the upgraded HTTP/1.1 request, and
 * dispatches it. Returns 1 to keep the connection. */
int h2_server_set_http2_upgrade(connection_t* connection, void* data);
void h2_upgrade_settings_free(void* data);

/* HTTP/1.1 → HTTP/2 cleartext upgrade helper (RFC 9113 §3.2). Detects an
 * `Upgrade: h2c` request, decodes its HTTP2-Settings header, stages a 101
 * Switching Protocols response, and arranges the protocol switch. Returns 1 if
 * the request was an upgrade it handled (the caller must stop processing — the
 * 101 is staged and the handler must not run), or 0 for an ordinary request. */
int h2c_upgrade(httpctx_t* ctx);

/* Read the process-wide h2 policy (idle timeout, PING watchdog, receive window,
 * write quantum) from main.env. Call once per config load, after the config is
 * readable and BEFORE any worker or handler thread exists — the values are
 * plain globals, and that ordering is the only thing making them safe to read
 * from every thread afterwards. Until it runs, the built-in defaults apply. */
void h2_policy_init(void);

int h2_server_guard_read(connection_t* connection);
int h2_server_guard_write(connection_t* connection);

/* requestparser_t.free — frees the session (called by __ctx_free). */
void h2_session_free(void* arg);

/* The session behind an h2 connection, or NULL when it is not HTTP/2. The write
 * filter uses it: all it holds is the response. */
h2session_t* h2_session_of(connection_t* connection);

/* Bind a freshly created response to the stream owning `request`, so the write
 * path and the write filter can find it later from the response alone. */
void h2_server_attach_response(connection_t* connection, httprequest_t* request,
                               httpresponse_t* response);

/* Called once a queued handler thread has filled its response. Pushes the
 * response onto the session's publish queue (the queue's own short lock) and
 * re-arms epoll under connection_s_lock, which it takes itself — so the caller
 * must NOT hold the connection lock (it is a non-recursive spinlock). The stream
 * table is not touched here; the worker drains the queue at the start of its
 * write pass (docs/concurrency/01 §4.1). */
int h2_server_response_ready(connection_t* connection, httpresponse_t* response);

/* The inline counterpart, for responses the worker produced itself while it was
 * already on the read path under connection_s_lock (the h2_dispatch fallback for
 * 404/403/static/redirect, via __post_response). The worker owns the stream
 * table exclusively here, so publish directly — no queue — and skip the re-arm:
 * the read path's h2_drain_and_rearm sees the stream become writable and arms
 * EPOLLOUT. The caller MUST already hold connection_s_lock. */
int h2_server_publish_inline(connection_t* connection, httpresponse_t* response);

/* Append a frame to the pending outbound buffer. Returns 1 on success, 0 on
 * allocation failure. Nothing is written to the socket here — h2_flush_out()
 * does that, so a partial write never splits a frame across event loops. */
int h2_session_queue_frame(h2session_t* s, uint8_t type, uint8_t flags,
                           uint32_t stream_id, const uint8_t* payload, size_t len);

/* Worker-timer entry point (Phase 5). Called once per h2 connection on each tick
 * of the multiplexing sweep. Owns the whole lock lifecycle: it trylocks, and
 * every path out releases the lock (a close frees/unlocks via
 * connection_close_locked, otherwise it unlocks explicitly). Because a close
 * may free the connection, the caller MUST NOT touch it after this returns —
 * it should capture connection->next beforehand. shutdown_now is
 * appconfig->shutdown. */
void h2_server_tick(connection_t* connection, int shutdown_now);

#endif

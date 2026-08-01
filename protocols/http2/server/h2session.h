#ifndef __H2SESSION__
#define __H2SESSION__

#include "connection.h"
#include "request.h"      /* requestparser_t (first member: free vtable) */
#include "h2frame.h"
#include "hpack.h"

/* Per-connection HTTP/2 session (Phase 3: a single in-flight stream).
 *
 * Stored in connection_server_ctx_t.parser (replacing the HTTP/1.1 parser), so
 * its first field MUST be the requestparser_t free vtable that __ctx_free calls.
 * The HTTP/1.1 dispatch path is reused unchanged: a request built from frames is
 * handed to http_server_dispatch(), the handler fills httpresponse_t as usual,
 * and the h2 write filter (terminal stage of the h2 filter chain) serializes it
 * back into HEADERS/DATA frames. See docs/http2/05.
 *
 * Concurrency: every field is touched only under connection_s_lock(), from the
 * worker event loop (read/write guards) or from the write filter that those
 * guards drive. Handler threads never see it — they only fill httpresponse_t. */

#define H2_DEFAULT_WINDOW 65535

/* Stream lifecycle (RFC 9113 §5.1), trimmed to the states a server reaches for
 * a client-initiated stream. Phase 3 tracks it for the single active stream;
 * every other id is derived — above last_stream_id it is idle, at or below it
 * is closed. Frames arriving in the wrong state are protocol errors, so this is
 * not bookkeeping we can skip. */
typedef enum {
    H2_STREAM_IDLE = 0,
    H2_STREAM_OPEN,               /* HEADERS received, END_STREAM not yet */
    H2_STREAM_HALF_CLOSED_REMOTE, /* request complete, response still owed */
    H2_STREAM_CLOSED,
} h2_stream_state_e;

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

    /* Current stream (single in-flight for Phase 3). */
    uint32_t stream_id;         /* 0 = none */
    uint32_t last_stream_id;    /* highest stream id accepted, reported in GOAWAY */
    h2_stream_state_e stream_state;
    size_t   req_body_len;      /* DATA bytes spooled into request->payload_.file */
    /* Declared content-length, or -1 when the request carried none. RFC 9113
     * §8.1.1 makes a mismatch with the DATA total a malformed request. */
    int64_t  content_length;
    int      end_stream_sent;   /* the response already carried END_STREAM */

    /* Error code to report in GOAWAY once a connection error is raised. */
    uint32_t error_code;

    /* CONTINUATION accumulation (HEADERS without END_HEADERS + CONTINUATION*). */
    uint8_t* cont;
    size_t   cont_len;
    uint32_t cont_stream_id;
    int      cont_end_stream;
    int      cont_active;

    /* Peer settings (RFC defaults until the peer sends SETTINGS). */
    uint32_t peer_max_frame_size;
    uint32_t peer_initial_window;
    uint32_t peer_header_table_size;

    /* Send-side flow control (RFC 9113 §6.9). Signed: a SETTINGS_INITIAL_WINDOW
     * _SIZE decrease may push an open stream's window negative, which is legal
     * and must not wrap around. */
    int64_t  send_window;         /* connection level */
    int64_t  stream_send_window;  /* current stream */
    /* The write filter ran out of window mid-body: the socket is writable, we
     * simply may not send, so wait for WINDOW_UPDATE instead of EPOLLOUT. */
    int      window_blocked;

    /* Receive side: bytes of our advertised window the peer has consumed and
     * that we have not yet given back with WINDOW_UPDATE. */
    int64_t  recv_pending;
    int64_t  stream_recv_pending;

    /* Pending outbound frames that did not fit the socket (control frames, the
     * trailing empty DATA). Phase 4 grows this into the real outbox serializer
     * described in docs/http2/06. */
    uint8_t* out;
    size_t   out_len;
    size_t   out_pos;
    size_t   out_cap;

    int goaway_sent;
} h2session_t;

/* Entry point called from __handshake once ALPN selects h2. Returns 1 on
 * success (connection->read/write installed), 0 on allocation failure. */
int h2_server_set_http2(connection_t* connection);

int h2_server_guard_read(connection_t* connection);
int h2_server_guard_write(connection_t* connection);

/* requestparser_t.free — frees the session (called by __ctx_free). */
void h2_session_free(void* arg);

/* The session behind an h2 connection, or NULL when it is not HTTP/2. The write
 * filter uses it: all it holds is the response. */
h2session_t* h2_session_of(connection_t* connection);

/* Append a frame to the pending outbound buffer. Returns 1 on success, 0 on
 * allocation failure. Nothing is written to the socket here — h2_flush_out()
 * does that, so a partial write never splits a frame across event loops. */
int h2_session_queue_frame(h2session_t* s, uint8_t type, uint8_t flags,
                           uint32_t stream_id, const uint8_t* payload, size_t len);

#endif

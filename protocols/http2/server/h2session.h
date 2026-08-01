#ifndef __H2SESSION__
#define __H2SESSION__

#include "connection.h"
#include "request.h"      /* requestparser_t (first member: free vtable) */
#include "h2frame.h"
#include "h2stream.h"
#include "hpack.h"

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

    /* Stream table (see h2stream.c) and the ids bounding it. */
    h2stream_t* streams;
    size_t      stream_count;
    uint32_t    last_stream_id; /* highest id accepted, reported in GOAWAY */

    /* CONTINUATION accumulation (HEADERS without END_HEADERS + CONTINUATION*).
     * Connection-level: a header block may not be interleaved with any other
     * frame, so at most one is ever in progress. */
    uint8_t* cont;
    size_t   cont_len;
    uint32_t cont_stream_id;
    int      cont_end_stream;
    int      cont_active;

    /* Peer settings (RFC defaults until the peer sends SETTINGS). */
    uint32_t peer_max_frame_size;
    uint32_t peer_initial_window;
    uint32_t peer_header_table_size;

    /* Connection-level send window (RFC 9113 §6.9); each stream has its own. */
    int64_t  send_window;
    /* Every stream that can still send is out of connection-level window: stop
     * arming EPOLLOUT (the socket is writable, we simply may not send) and wait
     * for a WINDOW_UPDATE. */
    int      window_blocked;

    /* Receive side: bytes of our advertised connection window the peer has
     * consumed and that we have not yet given back. */
    int64_t  recv_pending;

    /* The stream that stopped mid-frame and must finish before any other may
     * use the socket — otherwise its bytes would be spliced into an unfinished
     * DATA frame. NULL when no frame is in progress. */
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

/* Bind a freshly created response to the stream owning `request`, so the write
 * path and the write filter can find it later from the response alone. */
void h2_server_attach_response(connection_t* connection, httprequest_t* request,
                               httpresponse_t* response);

/* Called once a handler has filled the response (or once the dispatch path
 * produced one inline), from whichever thread ran it. Marks the owning stream
 * ready and wakes the connection's write path. The caller must already hold the
 * connection lock — every path into here does. */
int h2_server_response_ready(connection_t* connection, httpresponse_t* response);

/* Append a frame to the pending outbound buffer. Returns 1 on success, 0 on
 * allocation failure. Nothing is written to the socket here — h2_flush_out()
 * does that, so a partial write never splits a frame across event loops. */
int h2_session_queue_frame(h2session_t* s, uint8_t type, uint8_t flags,
                           uint32_t stream_id, const uint8_t* payload, size_t len);

#endif

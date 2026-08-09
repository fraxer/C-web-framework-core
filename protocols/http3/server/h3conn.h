#ifndef __H3CONN__
#define __H3CONN__

#include <stddef.h>
#include <stdint.h>

#include "h3session.h"
#include "h3stream.h"
#include "quicconn.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "quicstream.h"

/* Where HTTP/3 meets QUIC (docs/http3/05-http3.md §6.2).
 *
 * h3session and h3stream are pure state machines that take bytes; this is the
 * piece that gets the bytes out of QUIC streams, decides which machine each
 * stream belongs to, and turns their verdicts back into transport actions --
 * RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE.
 *
 * ## What lives in quicstream_t::app
 *
 * A stream is one of two things, and which one is decided by its id, not by
 * its contents: a client-initiated bidirectional stream is a request, a
 * client-initiated unidirectional stream is a service stream whose kind is
 * announced by its first varint. Both hang off `app` as an h3app_t, and the
 * `app` pointer is the only per-stream state HTTP/3 adds to the transport.
 *
 * ## What this module does not do
 *
 * It does not dispatch. Reporting H3CONN_REQUEST_DONE and letting the caller
 * hand the request to the shared pipeline keeps the QUIC lock discipline where
 * it already is, and keeps this file testable against streams built by hand. */

typedef enum {
    H3CONN_OK = 0,
    /* The request's headers are in. Reported for the cases that must act
     * before the body arrives -- Expect: 100-continue, and the Extended CONNECT
     * tunnel of §8. A request whose body arrives in the same read reports DONE
     * instead; the two only ever coincide for a request that has no body, and
     * neither of those cases has one. */
    H3CONN_REQUEST_HEADERS,
    /* The request is complete: dispatch it. */
    H3CONN_REQUEST_DONE,
    /* The stream was reset (result.h3_error says why). The caller drops it. */
    H3CONN_REQUEST_RESET,
    /* The request is well-formed but refused: answer result.http_status
     * (413, 431 or 500) on a stream that is still perfectly usable. */
    H3CONN_REQUEST_REFUSED,
    /* The connection must close with result.h3_error. */
    H3CONN_CLOSED
} h3conn_status_e;

typedef struct {
    h3conn_status_e status;
    uint64_t        h3_error;     /* RESET / CLOSED */
    int             http_status;  /* REFUSED */
} h3conn_result_t;

/* Per-stream HTTP/3 state, in quicstream_t::app. */
typedef struct h3app {
    int            is_request;
    h3uni_recv_t*  uni;      /* is_request == 0 */
    h3stream_t*    req;      /* is_request == 1 */
    /* Nothing further on this stream is worth parsing: a discarded uni-stream,
     * a request that was refused, or -- the common case -- a request that has
     * been dispatched. Bytes still have to be read so the flow-control window
     * keeps moving, but nothing looks at them. */
    int            drained;
} h3app_t;

typedef struct h3conn {
    /* MUST be first: an h3conn_t lives in connection_server_ctx_t::parser,
     * which __ctx_free releases through this pointer without knowing what it
     * points at -- the same contract h2session_t carries for HTTP/2. */
    void (*free)(void*);

    /* The connection this belongs to -- &quicconn_t::conn. Kept because every
     * request built here needs it: routing, redirects and virtual-host
     * selection all read request->connection, and a NULL there is a null
     * dereference the moment a redirect rule is consulted. */
    connection_t* connection;

    h3session_t* session;
    uint64_t     max_field_section_size;

    /* Our outbound service streams, opened once the handshake completes. */
    int          service_streams_open;
} h3conn_t;

h3conn_t* h3conn_create(connection_t* connection, uint64_t max_field_section_size,
                        int enable_connect_protocol);
void h3conn_free(h3conn_t* c);

/* Open our control, QPACK encoder, QPACK decoder and grease streams and write
 * their opening bytes -- for the control stream that is the SETTINGS frame
 * §6.2.1 requires first. Called once the handshake completes, before anything
 * else is sent. Returns 0 if the peer's stream limit or memory would not allow
 * it, which is fatal to the connection: without SETTINGS we cannot speak. */
int h3conn_open_service_streams(h3conn_t* c, quicconn_t* qc);

/* Drive one stream that has readable bytes, has ended, or has been reset.
 * Safe to call on a stream with nothing new. */
h3conn_result_t h3conn_stream_read(h3conn_t* c, quicstream_t* qs);

/* Read every stream of the connection that has something new, dispatching the
 * requests that completed and answering the ones that were refused. This is
 * what the transport calls after quicconn_recv and before quicconn_send.
 *
 * Returns 0 when the connection must close; *error then carries the HTTP/3
 * application code for CONNECTION_CLOSE. The caller must hold
 * connection_s_lock, which is why dispatch from here reaches the inline publish
 * path rather than the handler-thread one. */
int h3conn_read(h3conn_t* c, quicconn_t* qc, uint64_t* error);

/* The request state on a stream, or NULL if it is not a request stream. */
h3stream_t* h3conn_request_of(quicstream_t* qs);

/* The HTTP/3 state of a connection, or NULL if it is not one.
 *
 * The check is connection->transport, not a protocol bit on the ctx. That is a
 * stronger guarantee than h2's: QUIC carries HTTP/3 and nothing else here --
 * h1.1 and h2 are both TCP -- so a QUIC transport *is* the proof that
 * ctx->parser is an h3conn_t. The two type-confusion bugs h2 hit on that same
 * void* (docs/http2/09) came from a flag someone had to remember to set;
 * nobody has to remember what transport a connection arrived on. */
h3conn_t* h3_conn_of(connection_t* connection);

/* The QUIC stream carrying `response`, or NULL. Walks the connection's streams,
 * as h2stream_find_by_response does: a response is answered once, on a list
 * bounded by the peer's stream limit. */
quicstream_t* h3conn_stream_by_response(quicconn_t* qc, const httpresponse_t* response);

/* Release the per-stream state. Called before quicstream_free. */
void h3conn_stream_release(quicstream_t* qs);

/* ---- Dispatch and publication ---- *
 *
 * The same three-way split HTTP/2 arrived at (docs/concurrency/01 phase B), for
 * the same reasons:
 *
 *  - attach binds the response to its stream *before* user code runs, so the
 *    write filter can find its way back from a response alone;
 *  - response_ready is what a handler thread calls, and it must be called
 *    WITHOUT connection_s_lock -- it takes the lock itself;
 *  - publish_inline is what the worker calls when it built the response on the
 *    read path and is already holding that lock. connection_s_lock is a
 *    non-recursive spinlock, so calling the wrong one deadlocks. h2 hit exactly
 *    this and the second entry point is the fix it landed on.
 */

/* Bind `response` to the stream carrying `request`. Returns 0 if no stream
 * owns the request, which means it was cancelled while the handler queued. */
int h3_server_attach_response(connection_t* connection, httprequest_t* request,
                              httpresponse_t* response);

/* A handler thread finished a response. Marks the stream ready and wakes the
 * endpoint so the send path picks it up. Call without connection_s_lock. */
int h3_server_response_ready(connection_t* connection, httpresponse_t* response);

/* The worker built the response itself, on the read path, under
 * connection_s_lock. Marks the stream ready without taking anything. */
int h3_server_publish_inline(connection_t* connection, httpresponse_t* response);

/* Stage a 103 Early Hints for the response's stream (RFC 8297). `fields` is
 * taken over on success and must be freed by the caller on failure. Returns 0
 * if no stream owns the response, or if its final headers already went out --
 * a 1xx after them would be out of order by definition.
 *
 * Called from a handler thread, so it takes connection_s_lock itself: the
 * stream list belongs to the worker. Early hints happen once or twice per
 * request, never per byte, so the lock costs nothing worth avoiding. */
int h3_server_early_hints(connection_t* connection, httpresponse_t* response,
                          http_header_t* fields);

/* Send an interim 100 (Continue) on `qs` at once (RFC 9110 §10.1.1). Called
 * from the read path, where the request's headers have just been built and the
 * client is holding its body back waiting for permission -- which is the whole
 * point of sending it immediately rather than staging it. */
int h3_server_continue(h3conn_t* c, quicstream_t* qs);

/* Run the write turn: for every stream whose response is ready, drive the
 * filter chain until it finishes or the write-ahead budget is spent. Called by
 * the transport before it builds packets. Returns 0 if the connection must
 * close. */
int h3conn_write(h3conn_t* c, quicconn_t* qc);

/* Is any response still unfinished? A response larger than the write-ahead
 * budget stops mid-body and needs another turn once the send path has drained
 * it, and nothing else would ask for one: quicconn_want_write is edge-driven,
 * and the edge -- the handler finishing -- has already passed. */
int h3conn_has_pending(const h3conn_t* c, const quicconn_t* qc);

/* ---- Graceful shutdown (docs/http3/07-integration.md §5) ---- */

/* Tell the peer that no request after `qc`'s current high-water mark will be
 * served: an h3 GOAWAY on our control stream (§5.2). Idempotent -- a second
 * call writes nothing, because §5.2 lets the id only shrink and repeating it
 * would be the control-frame flood the budget next door exists to stop.
 *
 * Returns 0 only if the frame could not be written at all. */
int h3conn_goaway(h3conn_t* c, quicconn_t* qc);

/* Requests still being served: a stream that has a request and has not finished
 * answering it. This is what a drain waits for -- not the stream count, which
 * includes our own service streams and stays non-zero forever. */
size_t h3conn_requests_in_flight(const h3conn_t* c, const quicconn_t* qc);

#endif

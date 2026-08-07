#ifndef __H3CONN__
#define __H3CONN__

#include <stddef.h>
#include <stdint.h>

#include "h3session.h"
#include "h3stream.h"
#include "quicconn.h"
#include "quicstream.h"

struct httpresponse;

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
    /* The stream's bytes are no longer wanted: a discarded uni-stream, or a
     * request already answered. Bytes still have to be drained so the flow
     * control window keeps moving, but nothing looks at them. */
    int            drained;
} h3app_t;

typedef struct h3conn {
    h3session_t* session;
    uint64_t     max_field_section_size;

    /* Our outbound service streams, opened once the handshake completes. */
    int          service_streams_open;
} h3conn_t;

h3conn_t* h3conn_create(uint64_t max_field_section_size, int enable_connect_protocol);
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
struct connection;
h3conn_t* h3_conn_of(struct connection* connection);

/* The QUIC stream carrying `response`, or NULL. Walks the connection's streams,
 * as h2stream_find_by_response does: a response is answered once, on a list
 * bounded by the peer's stream limit. */
quicstream_t* h3conn_stream_by_response(quicconn_t* qc, const struct httpresponse* response);

/* Release the per-stream state. Called before quicstream_free. */
void h3conn_stream_release(quicstream_t* qs);

#endif

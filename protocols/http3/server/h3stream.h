#ifndef __H3STREAM__
#define __H3STREAM__

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "h3error.h"
#include "h3frame.h"
#include "httprequest.h"

/* Forward declaration: the QPACK decoder is shared across every stream on a
 * connection, so h3session owns it and hands it to h3stream_feed. Defined in
 * protocols/http3/qpack/qpack.h. */
struct qpack_decoder;

/* One HTTP/3 request stream (RFC 9114 §7) — the receive half: turns the bytes
 * a QUIC client-initiated bidi stream delivers into a dispatched httprequest_t.
 * QUIC owns multiplexing, ordering and flow control, so unlike h2stream this
 * carries no window state; what is left is the frame-order state machine and the
 * QPACK + httpfields pipeline.
 *
 * Transport glue — stream lifecycle, uni-stream routing, dispatching the built
 * request, the response side — lives in h3session. h3stream is the unit-testable
 * core a feed of frame bytes drives; a qpack_decoder_t is passed in because in
 * full QPACK the decoder is shared across every stream on a connection. */

/* The status split below is not cosmetic. RFC 9114 draws a hard line: a
 * malformed *message* kills the stream, a malformed *frame* kills the
 * connection -- §4.1 ("an invalid sequence of frames MUST be treated as a
 * connection error of type H3_FRAME_UNEXPECTED") and §7.1 (a frame truncated
 * or overrun is a connection error of type H3_FRAME_ERROR). Collapsing the two
 * is the single most common h3spec complaint (docs/http3/05-http3.md §10), so
 * each error carries the one code it maps to and h3stream_status_is_connection
 * says which half it belongs to. */
typedef enum {
    /* Internal success sentinel (feed itself never returns it — it reports
     * NEED_MORE/BODY_CHUNK when there is no caller-visible event). */
    H3STREAM_OK = 0,
    /* No complete frame yet; feed more bytes. */
    H3STREAM_NEED_MORE,
    /* The first HEADERS completed — the request is built and may be dispatched.
     * *pp stops at the byte after the HEADERS frame; the caller re-feeds the
     * rest (a body, trailers) once the handler is queued. */
    H3STREAM_REQUEST_READY,
    /* One or more DATA chunks were spooled into the request body. */
    H3STREAM_BODY_CHUNK,
    /* HEADERS is complete but references a dynamic entry that has not arrived
     * yet. This is flow-control state, not an HTTP/3 error. */
    H3STREAM_QPACK_BLOCKED,
    /* FIN: the request is fully received (no handler could still want more). */
    H3STREAM_DONE,

    /* ---- Stream errors: the caller RESET_STREAM(code) and frees the stream ---- */
    /* Malformed message: bad fields, or a content-length that disagrees with the
     * body actually delivered (§4.1.2) → H3_MESSAGE_ERROR. */
    H3STREAM_ERR_MESSAGE,
    /* FIN before the request was complete → H3_REQUEST_INCOMPLETE. */
    H3STREAM_ERR_REQUEST_INCOMPLETE,
    /* The body exceeded client_max_body_size: answered 413 on the stream. */
    H3STREAM_ERR_BODY_TOO_LARGE,
    /* The field section exceeded our MAX_FIELD_SECTION_SIZE: answered 431. */
    H3STREAM_ERR_FIELDS_TOO_LARGE,
    /* :authority names a host this listener does not serve: answered 404.
     *
     * Deliberately not H3STREAM_ERR_MESSAGE. §4.1.2 defines a malformed request
     * by its shape -- a missing, repeated or syntactically invalid pseudo-header
     * -- and this request has none of those problems: it is well formed and
     * addressed elsewhere. Resetting it would also make the same request answer
     * differently depending on the protocol that carried it, since HTTP/1.1 has
     * answered 404 here since long before HTTP/3 existed. */
    H3STREAM_ERR_MISDIRECTED,
    /* Allocation or spool failure → 500 on the stream. */
    H3STREAM_ERR_INTERNAL,

    /* ---- Connection errors: the caller CONNECTION_CLOSE(code) ---- */
    /* A frame that may not appear here, or in this order, or an HTTP/2
     * codepoint (§4.1, §11.2.1) → H3_FRAME_UNEXPECTED. */
    H3STREAM_ERR_FRAME_UNEXPECTED,
    /* A frame that is truncated, malformed, or still half-read when the stream
     * ended cleanly (§7.1) → H3_FRAME_ERROR. */
    H3STREAM_ERR_FRAME,
    /* A control frame over the accumulation cap → H3_EXCESSIVE_LOAD. */
    H3STREAM_ERR_EXCESSIVE_LOAD,
    /* A field section that will not decode. The QPACK context is shared across
     * the connection and cannot be resynchronised, so this is fatal to the
     * connection → QPACK_DECOMPRESSION_FAILED (0x0200, *not*
     * H3_CLOSED_CRITICAL_STREAM). */
    H3STREAM_ERR_QPACK_DECOMPRESSION
} h3stream_status_e;

/* Whether the status must close the connection rather than the stream. */
static inline int h3stream_status_is_connection(h3stream_status_e st) {
    return st == H3STREAM_ERR_FRAME_UNEXPECTED ||
           st == H3STREAM_ERR_FRAME ||
           st == H3STREAM_ERR_EXCESSIVE_LOAD ||
           st == H3STREAM_ERR_QPACK_DECOMPRESSION;
}

/* The HTTP/3 error code a status maps to (h3error.h), or H3_NO_ERROR when the
 * status is not an error. The statuses answered with a response rather than a
 * reset (413, 431, 500) map to H3_NO_ERROR too -- the caller answers instead. */
uint64_t h3stream_status_error(h3stream_status_e st);

struct httpresponse;

typedef struct h3stream {
    h3frame_parser_t parser;
    httprequest_t*   request;
    /* Set when the request is dispatched, so the write filter can find its way
     * back from a response to the QUIC stream that carries it
     * (h3conn_stream_by_response).
     *
     * The stream owns it, exactly as h2stream owns its own: a response outlives
     * the handler that filled it and has to survive until the write turn has
     * drained it, and the stream is the only thing whose lifetime covers that.
     * h3stream_free releases it. */
    struct httpresponse* response;

    enum {
        H3STREAM_EXPECT_HEADERS = 0,
        H3STREAM_BODY,
        H3STREAM_TRAILERS
    } stage;

    int      headers_done;     /* first HEADERS received */
    int64_t  content_length;   /* declared, or -1 when the request carried none */
    size_t   req_body_len;     /* DATA bytes spooled into request->payload_ */

    /* Bytes already removed from QUIC receive buffering after a HEADERS frame
     * that blocked on QPACK. Owned and memory-budgeted until decode resumes. */
    uint8_t* qpack_deferred;
    size_t   qpack_deferred_len;
    size_t   qpack_deferred_cap;
    int      qpack_deferred_fin;
    int      qpack_blocked;
    uint64_t qpack_required_insert_count;

    /* The response is filled and the write turn may run the filter chain for
     * this stream. Atomic because a handler thread sets it and the worker reads
     * it; release/acquire, so seeing the flag implies seeing the response.
     * The same contract as h2stream_t::response_ready. */
    atomic_int response_ready;
    /* The filter chain has run to completion on this stream. */
    int      response_done;
    /* The final HEADERS frame is on the wire. After that an informational
     * response would arrive out of order -- 1xx precedes the final status by
     * definition -- so a late 103 is dropped rather than sent. */
    int      response_headers_sent;

    /* Fields staged for a 103 Early Hints, owned by the stream until the write
     * turn encodes them. Staged rather than encoded on the spot for the reason
     * h2 stages its own: a handler thread must not run the field encoder,
     * because sections have to reach the peer in the order they were encoded
     * and only the worker can guarantee that. */
    struct http_header* early_hints;
    struct http_header* last_early_hint;

    /* Our advertised SETTINGS_MAX_FIELD_SECTION_SIZE. A decoded field section
     * larger than this is refused with 431 rather than decompressed into
     * memory (docs/http2/08 phase A.4, the same budget h2 applies). 0 = no
     * limit, which is what the unit harness uses. */
    size_t   max_field_section_size;
    /* Where decoding stops instead of answering. Above the advertised limit the
     * client is told 431 and keeps its connection; above this one there is no
     * answer worth making, so the decoder abandons the block mid-way and the
     * connection ends with H3_EXCESSIVE_LOAD. 0 = no limit. */
    size_t   max_field_section_hard;
} h3stream_t;

/* How far above the advertised field-section limit decoding still happens. The
 * figure HTTP/2 arrived at (docs/http2/08 phase A); shared so that raising one
 * protocol's limit does not silently change the shape of the other's. */
#define H3STREAM_FIELD_SECTION_HARD_FACTOR 8

/* Create a stream with its own (empty) request. `connection` is the one the
 * request arrived on: it goes on the request, where the routing, redirect and
 * virtual-host code all read it, and it is what select_server needs. NULL is
 * accepted (the unit harness has no connection) and then no vhost is selected.
 * `max_field_section_size` is the limit above; pass 0 for none. */
h3stream_t* h3stream_create(connection_t* connection, size_t max_field_section_size);
void h3stream_free(h3stream_t* st);

int h3stream_qpack_defer(h3stream_t* st, const uint8_t* data, size_t len, int fin);
void h3stream_qpack_deferred_clear(h3stream_t* st);
int h3stream_qpack_block(h3stream_t* st, uint64_t required,
                         const uint8_t* tail, size_t tail_len, int fin);
int h3stream_qpack_can_resume(const h3stream_t* st, uint64_t insert_count);
void h3stream_qpack_unblock(h3stream_t* st);

/* Feed bytes received on this request stream, advancing *pp. Processes complete
 * frames and stops on the first event the caller must act on (REQUEST_READY, an
 * error, DONE) — otherwise runs to *pp==end and returns NEED_MORE/BODY_CHUNK.
 * `fin` is set on the chunk that ends the stream. */
h3stream_status_e h3stream_feed(h3stream_t* st, struct qpack_decoder* qdec,
                                const uint8_t** pp, const uint8_t* end, int fin);

#endif

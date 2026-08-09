#include "h3_write_filter.h"

#include <stdlib.h>
#include <string.h>

#include "connection_s.h"
#include "h3conn.h"
#include "h3data.h"
#include "h3response.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "log.h"
#include "metrics.h"
#include "qpack.h"

/* Terminal stage of the h3 filter chain. See h3_write_filter.h. */

typedef struct {
    http_module_t base;

    /* The HEADERS frame, built once and queued whole. Unlike h2's, it is not
     * drained through buf->pos across several turns: writing to a QUIC stream
     * is a copy into the send buffer, which either takes it all or fails on
     * allocation -- there is no partial socket write to resume from. The buffer
     * is still kept so that a rebuild cannot happen: a second QPACK encode of
     * the same fields would be a second field section, and in full QPACK (6.2)
     * that would desynchronise the encoder's dynamic table. */
    uint8_t* head;
    size_t   head_len;
    int      head_sent;

    h3_data_writer_t writer;
} h3_module_write_t;

static int __header(httprequest_t* request, httpresponse_t* response);
static int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf);
static void __free(void* arg);
static void __reset(void* arg);

/* The QUIC stream and connection behind a response, or a pair of NULLs. */
static int __locate(httpresponse_t* response, quicconn_t** qc_out, quicstream_t** qs_out) {
    h3conn_t* c = h3_conn_of(response->connection);
    if (c == NULL) return 0;

    /* connection_t is the first member of quicconn_t, which is what makes this
     * cast legal -- and h3_conn_of has already established that the transport
     * really is QUIC. */
    quicconn_t* qc = (quicconn_t*)response->connection;

    quicstream_t* qs = h3conn_stream_by_response(qc, response);
    if (qs == NULL) return 0;

    *qc_out = qc;
    *qs_out = qs;

    return 1;
}

/* A body will follow the HEADERS frame. Mirrors h2_write_filter's __has_body,
 * and for the same reason: those cases emit no body buffer at all, so the FIN
 * has to ride on the header frame or the stream would never close.
 * Conservative on purpose -- a wrong "no body" truncates the response, while a
 * wrong "has body" is repaired by the empty final pass. */
static int __has_body(httprequest_t* request, httpresponse_t* response) {
    if (request != NULL && request->method == ROUTE_HEAD) return 0;
    if (response->status_code == 304) return 0;
    if (response->file_.fd > -1) return response->file_.size > 0;

    return response->body.size > 0;
}

static int __has_trailers(httpresponse_t* response) {
    return response->trailer_ != NULL;
}

static int __header(httprequest_t* request, httpresponse_t* response) {
    h3_module_write_t* module = response->cur_filter->module;

    quicconn_t* qc = NULL;
    quicstream_t* qs = NULL;
    if (!__locate(response, &qc, &qs)) {
        log_error("h3_write_filter: no HTTP/3 stream owns this response\n");
        return CWF_ERROR;
    }

    if (module->head == NULL) {
        h3conn_t* c = h3_conn_of(response->connection);

        const h3response_status_e st =
            h3response_headers(c->session->qenc, response, &module->head, &module->head_len);
        if (st != H3RESPONSE_OK) {
            log_error("h3_write_filter: qpack encode failed (%d)\n", (int)st);
            return CWF_ERROR;
        }
    }

    if (!module->head_sent) {
        if (!quicstream_write(qs, module->head, module->head_len)) {
            log_error("h3_write_filter: stream %llu would not take the header frame\n",
                      (unsigned long long)qs->id);
            return CWF_ERROR;
        }
        module->head_sent = 1;

        /* Counted where the field section reaches the stream, not where the
         * response was built: everything before this point can still fail into
         * a reset, and a response nobody received is not one. */
        metrics_h3_status(response->status_code);

        /* From here on an informational response would be out of order: 1xx
         * precedes the final status by definition. */
        h3stream_t* st = h3conn_request_of(qs);
        if (st != NULL) st->response_headers_sent = 1;

        /* No body and no trailers: the response is over, so the stream ends
         * here. The tunnel case of §8 is deliberately absent -- an Extended
         * CONNECT stream never ends on its own response -- and will add its
         * condition alongside these two. */
        if (!__has_body(request, response) && !__has_trailers(response)) {
            quicstream_finish(qs);
            module->writer.fin_sent = 1;
        }
    }

    quicconn_want_write(response->connection);

    return CWF_OK;
}

static int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    (void)request;

    h3_module_write_t* module = response->cur_filter->module;

    quicconn_t* qc = NULL;
    quicstream_t* qs = NULL;
    if (!__locate(response, &qc, &qs)) return CWF_ERROR;

    module->base.parent_buf = parent_buf;
    if (parent_buf == NULL) return CWF_ERROR;

    /* The framing and the write-ahead budget live in h3data.c: the Extended
     * CONNECT tunnel of §8 needs the same two, and one copy of that arithmetic
     * is the point (the lesson h2 learned the other way round, docs/http2/09
     * §4.3). What stays here is the translation into the chain's vocabulary. */
    const h3_data_status_e st = h3_data_write(&module->writer, qc, qs, parent_buf,
                                              parent_buf->is_last,
                                              !__has_trailers(response));

    quicconn_want_write(response->connection);

    switch (st) {
    case H3_DATA_DRAINED:
        return CWF_DATA_AGAIN;

    case H3_DATA_BLOCKED:
        /* The write-ahead budget is spent. Resumed when the send path has
         * packetised what is queued, which is the QUIC equivalent of the
         * EPOLLOUT that resumes h1.1 and h2. */
        response->event_again = 1;
        return CWF_EVENT_AGAIN;

    default:
        log_error("h3_write_filter: stream %llu write failed\n", (unsigned long long)qs->id);
        return CWF_ERROR;
    }
}

static void __free(void* arg) {
    h3_module_write_t* module = arg;

    free(module->head);
    free(module);
}

static void __reset(void* arg) {
    h3_module_write_t* module = arg;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;

    free(module->head);
    module->head = NULL;
    module->head_len = 0;
    module->head_sent = 0;

    h3_data_writer_reset(&module->writer);
}

http_filter_t* h3_write_filter_create(void) {
    http_filter_t* filter = malloc(sizeof * filter);
    if (filter == NULL) return NULL;

    h3_module_write_t* module = malloc(sizeof * module);
    if (module == NULL) {
        free(filter);
        return NULL;
    }

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = __free;
    module->base.reset = __reset;
    module->head = NULL;
    module->head_len = 0;
    module->head_sent = 0;
    h3_data_writer_reset(&module->writer);

    filter->handler_header = __header;
    filter->handler_body = __body;
    filter->module = module;
    filter->next = NULL;

    return filter;
}

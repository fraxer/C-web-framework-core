#include "h2_write_filter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "connection_s.h"
#include "h2data.h"
#include "h2frame.h"
#include "h2session.h"
#include "h2stream.h"
#include "hpack.h"
#include "httpfields.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "log.h"
#include "openssl.h"

/* Terminal stage of the h2 filter chain. See h2_write_filter.h. */

typedef struct {
    http_module_t base;

    /* HEADERS (+ CONTINUATION) frames, fully built up front and drained
     * resumably through buf->pos — the block is small and building it twice
     * after an EAGAIN would corrupt the HPACK encoder's dynamic table. */
    bufo_t* buf;

    /* DATA frame currently in flight (h2data.c owns the state machine). */
    h2_data_writer_t writer;
} h2_module_write_t;

static int __header(httprequest_t* request, httpresponse_t* response);
static int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf);
static void __free(void* arg);
static void __reset(void* arg);

/* ======================================================================= *
 *  Socket I/O (mirrors http_write_filter's __wr error handling)
 * ======================================================================= */

/* Worker thread only — see the invariant on connection_data_write(). */
static ssize_t __raw_write(connection_t* connection, const char* data, size_t size) {
    return connection->ssl ?
        openssl_write(connection->ssl, data, size) :
        send(connection->fd, data, size, MSG_NOSIGNAL);
}

/* Map a failed write to a filter status. */
static int __write_status(httpresponse_t* response, ssize_t written) {
    connection_t* connection = response->connection;

    if (connection->ssl != NULL) {
        switch (openssl_io_status(connection->ssl, (int)written)) {
        case OPENSSL_IO_WANT_READ:
        case OPENSSL_IO_WANT_WRITE:
            response->event_again = 1;
            return CWF_EVENT_AGAIN;
        default:
            log_error("h2_write_filter: ssl write failure\n");
            return CWF_ERROR;
        }
    }

    if (errno == EINTR)
        return CWF_DATA_AGAIN; /* caller retries the same bytes */

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        response->event_again = 1;
        return CWF_EVENT_AGAIN;
    }

    log_error("h2_write_filter: write error: %s\n", strerror(errno));

    return CWF_ERROR;
}

static int __write_bufo(httpresponse_t* response, bufo_t* buf) {
    size_t chunk = 0;
    while ((chunk = bufo_chunk_size(buf, buf->size)) > 0) {
        const ssize_t written = __raw_write(response->connection, bufo_data(buf), chunk);
        if (written < 0) {
            const int r = __write_status(response, written);
            if (r == CWF_DATA_AGAIN) continue; /* EINTR */
            return r;
        }
        if (written == 0) {
            log_error("h2_write_filter: connection closed\n");
            return CWF_ERROR;
        }
        bufo_move_front_pos(buf, (size_t)written);
    }

    return CWF_OK;
}

/* ======================================================================= *
 *  HEADERS frame
 * ======================================================================= */

/* The forbidden-field, sensitive-field and lowercasing rules moved to
 * protocols/http/httpfields.c when HTTP/3 needed the same three (RFC 9113
 * §8.2.2 and RFC 9114 §4.2 are word-for-word here). Thin aliases keep this
 * file's call sites readable. */
#define __is_forbidden(key, len) httpfields_is_forbidden_response_header((key), (len))
#define __is_sensitive(key, len) httpfields_is_sensitive_header((key), (len))
#define __lowercase(dst, src, len) httpfields_lowercase((dst), (src), (len))

/* This response ends with a trailing HEADERS block (RFC 9113 §8.1), so
 * END_STREAM belongs there and nowhere earlier — docs/http2/08, phase E.1. */
static int __has_trailers(httpresponse_t* response) {
    return response->trailer_ != NULL;
}

/* A body will follow the HEADERS frame. Mirrors the early returns of
 * http_data_filter's __body: those cases emit no body buffer at all, so
 * END_STREAM has to ride on HEADERS or the stream would never close.
 * Conservative by design — a wrong "no body" guess truncates the response,
 * while a wrong "has body" guess is repaired by the empty trailing DATA frame
 * that the session sends once the chain is done. */
static int __has_body(httprequest_t* request, httpresponse_t* response) {
    if (request != NULL && request->method == ROUTE_HEAD) return 0;
    if (response->status_code == 304) return 0;
    if (response->file_.fd > -1) return response->file_.size > 0;

    return response->body.size > 0;
}

/* Build the HEADERS frame (plus CONTINUATION frames when the HPACK block
 * exceeds the peer's max frame size) into `out`. */
static int __build_headers(httprequest_t* request, httpresponse_t* response,
                           h2session_t* s, h2stream_t* stream, bufo_t* out) {
    size_t count = 1; /* :status */
    size_t names_size = 0;
    for (http_header_t* h = response->header_; h != NULL; h = h->next) {
        if (h->key_length == 0 || __is_forbidden(h->key, h->key_length)) continue;
        count++;
        names_size += h->key_length;
    }

    hpack_header_t* fields = malloc(sizeof(*fields) * count);
    char* names = malloc(names_size > 0 ? names_size : 1);
    if (fields == NULL || names == NULL) {
        free(fields);
        free(names);
        return 0;
    }

    char status[8];
    const int status_len = snprintf(status, sizeof(status), "%d", response->status_code);
    if (status_len < 1) {
        free(fields);
        free(names);
        return 0;
    }

    size_t n = 0;
    fields[n].name = ":status";
    fields[n].name_len = 7;
    fields[n].value = status;
    fields[n].value_len = (size_t)status_len;
    fields[n].never_indexed = 0;
    n++;

    size_t names_off = 0;
    for (http_header_t* h = response->header_; h != NULL; h = h->next) {
        if (h->key_length == 0 || __is_forbidden(h->key, h->key_length)) continue;

        __lowercase(names + names_off, h->key, h->key_length);
        fields[n].name = names + names_off;
        fields[n].name_len = h->key_length;
        fields[n].value = h->value;
        fields[n].value_len = h->value_length;
        fields[n].never_indexed = __is_sensitive(names + names_off, h->key_length);
        names_off += h->key_length;
        n++;
    }

    /* RFC 9113 §6.5.2 is explicit that this limit is advisory, and truncating is
     * worse than exceeding it: the fields a response cannot afford to lose
     * (Set-Cookie, Location, Content-Type) are not distinguishable from the ones
     * it can. So the response goes out whole and the log says why the client may
     * reject it — otherwise that arrives as an unexplained RST_STREAM. */
    if (s->peer_max_header_list_size != 0) {
        size_t list_size = 0;
        for (size_t i = 0; i < n; i++)
            list_size += fields[i].name_len + fields[i].value_len + 32;

        if (list_size > s->peer_max_header_list_size)
            log_error("h2_write_filter: response header list %zu > peer limit %u on stream %u\n",
                      list_size, s->peer_max_header_list_size, stream->id);
    }

    uint8_t* block = NULL;
    size_t block_len = 0;
    const hpack_status_e st = hpack_encoder_encode(s->encoder, fields, n, 1, &block, &block_len);

    free(fields);
    free(names);

    if (st != HPACK_OK) {
        log_error("h2_write_filter: hpack encode failed (%d)\n", (int)st);
        return 0;
    }

    const size_t mfs = s->peer_max_frame_size ? s->peer_max_frame_size : H2_MAX_FRAME_SIZE_DEFAULT;
    const size_t frames = block_len > mfs ? (block_len + mfs - 1) / mfs : 1;
    const size_t total = frames * H2_FRAME_HEADER_LEN + block_len;

    if (!bufo_alloc(out, total)) {
        free(block);
        return 0;
    }

    const int has_body = __has_body(request, response);
    /* A WebSocket tunnel's 200 must not carry END_STREAM even though no body
     * follows it: the stream stays open in both directions, which is the whole
     * point (RFC 8441, docs/http2/09). */
    const int end_stream = !has_body && stream->ws == NULL && !__has_trailers(response);
    size_t off = 0;
    size_t written = 0;
    for (size_t i = 0; i < frames; i++) {
        const size_t chunk = block_len - off < mfs ? block_len - off : mfs;
        const int last = (i + 1 == frames);

        uint8_t type = (i == 0) ? H2_FRAME_HEADERS : H2_FRAME_CONTINUATION;
        uint8_t flags = 0;
        if (last) flags |= H2_FLAG_END_HEADERS;
        if (i == 0 && end_stream) flags |= H2_FLAG_END_STREAM;

        const size_t got = h2frame_encode((uint8_t*)out->data + written, total - written,
                                          type, flags, stream->id, block + off, chunk);
        if (got == 0) {
            free(block);
            return 0;
        }

        written += got;
        off += chunk;
    }

    free(block);

    bufo_set_size(out, written);
    bufo_reset_pos(out);

    /* From here on an informational response would be out of order. */
    stream->response_headers_sent = 1;

    if (end_stream)
        stream->end_stream_sent = 1;

    return 1;
}

static int __header(httprequest_t* request, httpresponse_t* response) {
    h2_module_write_t* module = response->cur_filter->module;
    h2session_t* s = h2_session_of(response->connection);
    h2stream_t* stream = s != NULL ? h2stream_find_by_response(s, response) : NULL;
    if (stream == NULL) {
        log_error("h2_write_filter: no HTTP/2 stream owns this response\n");
        return CWF_ERROR;
    }

    /* Before the block is encoded: once HPACK has run, the fields are bytes. */
    httpfields_apply_alt_svc(response);

    if (module->buf->size == 0)
        if (!__build_headers(request, response, s, stream, module->buf))
            return CWF_ERROR;

    /* A body is coming: hand the block to the DATA writer instead of sending it
     * now, and it goes out in the same TLS record as the first DATA frame. What
     * this saves is mostly the *peer's* work -- a record costs the reader two
     * reads, so two records per response had clients doing 4.3 reads where one
     * record needs 2.2 (docs/http2/10 §6).
     *
     * Ordering is safe because the writer puts the prefix ahead of the frame it
     * joins, and a response that turns out to have no body at all still sends
     * the block: h2_data_flush_prefix runs when the body stage finds nothing to
     * frame. __has_body is deliberately conservative in the same direction it
     * always was -- guessing "no body" here only means the old two-write path. */
    if (__has_body(request, response) && !__has_trailers(response)) {
        h2_data_writer_prefix(&module->writer,
                              (const uint8_t*)bufo_data(module->buf),
                              bufo_chunk_size(module->buf, module->buf->size));
        return CWF_OK;
    }

    return __write_bufo(response, module->buf);
}

/* ======================================================================= *
 *  DATA frames
 * ======================================================================= */

static int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    (void)request;

    h2_module_write_t* module = response->cur_filter->module;
    h2session_t* s = h2_session_of(response->connection);
    h2stream_t* stream = s != NULL ? h2stream_find_by_response(s, response) : NULL;
    if (stream == NULL) return CWF_ERROR;

    module->base.parent_buf = parent_buf;
    if (parent_buf == NULL) return CWF_ERROR;

    /* The framing itself lives in h2data.c — the WebSocket tunnel of RFC 8441
     * needs the same windows, quantum and frame-boundary rules, and having one
     * copy of that arithmetic is the point (docs/http2/09 §4.3). What stays
     * here is the translation into the filter chain's vocabulary. */
    switch (h2_data_write(&module->writer, s, stream, parent_buf, !__has_trailers(response))) {
    case H2_DATA_DRAINED:
        /* Nothing was framed, so a HEADERS block held back for a ride has no
         * ride: __has_body said there would be a body and there was none (an
         * empty file, a handler that changed its mind). Sending it here is what
         * keeps that guess from truncating the response into silence. */
        switch (h2_data_flush_prefix(&module->writer, s)) {
        case H2_DATA_DRAINED:
            break;
        case H2_DATA_SOCKET:
            response->event_again = 1;
            return CWF_EVENT_AGAIN;
        default:
            return CWF_ERROR;
        }

        return CWF_DATA_AGAIN;

    case H2_DATA_YIELD:
    case H2_DATA_WINDOW:
    case H2_DATA_SOCKET:
        /* All three resume through the same path; which one it was is already
         * recorded on the stream (yielded / window_blocked), and that is what
         * the write scheduler reads. */
        response->event_again = 1;
        return CWF_EVENT_AGAIN;

    default:
        return CWF_ERROR;
    }
}

/* ======================================================================= *
 *  Lifecycle
 * ======================================================================= */

static void __free(void* arg) {
    h2_module_write_t* module = arg;

    bufo_free(module->buf);
    free(module);
}

static void __reset(void* arg) {
    h2_module_write_t* module = arg;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    h2_data_writer_reset(&module->writer);

    bufo_clear(module->buf);
}

/* Trailing fields as their own HPACK block. Shares the encoder with the header
 * block, which is exactly why it may not be encoded early: blocks must reach the
 * peer in the order they were encoded (RFC 9113 §4.3). Encoding here, at the
 * point of sending, keeps that true by construction. */
/* Encode a field list into HEADERS (+CONTINUATION) and queue it. Shared by the
 * two blocks that are not the response's own: the trailing one and the
 * informational ones. `status` is NULL for trailers, which carry no
 * pseudo-header at all (§8.1). */
static int __queue_extra_block(h2session_t* s, h2stream_t* stream,
                               const http_header_t* list, const char* status,
                               int end_stream) {
    size_t count = status != NULL ? 1 : 0;
    size_t names_size = 0;
    for (const http_header_t* h = list; h != NULL; h = h->next) {
        if (h->key_length == 0 || h->key[0] == ':' || __is_forbidden(h->key, h->key_length))
            continue;
        count++;
        names_size += h->key_length;
    }

    if (count == 0) return 0;

    hpack_header_t* fields = malloc(sizeof(*fields) * count);
    char* names = malloc(names_size > 0 ? names_size : 1);
    if (fields == NULL || names == NULL) {
        free(fields);
        free(names);
        return 0;
    }

    size_t n = 0;
    if (status != NULL) {
        fields[n].name = ":status";
        fields[n].name_len = 7;
        fields[n].value = (char*)status;
        fields[n].value_len = strlen(status);
        fields[n].never_indexed = 0;
        n++;
    }

    size_t names_off = 0;
    for (const http_header_t* h = list; h != NULL; h = h->next) {
        if (h->key_length == 0 || h->key[0] == ':' || __is_forbidden(h->key, h->key_length))
            continue;

        __lowercase(names + names_off, h->key, h->key_length);
        fields[n].name = names + names_off;
        fields[n].name_len = h->key_length;
        fields[n].value = (char*)h->value;
        fields[n].value_len = h->value_length;
        fields[n].never_indexed = __is_sensitive(names + names_off, h->key_length);
        names_off += h->key_length;
        n++;
    }

    uint8_t* block = NULL;
    size_t block_len = 0;
    const hpack_status_e st = hpack_encoder_encode(s->encoder, fields, n, 1, &block, &block_len);

    free(fields);
    free(names);

    if (st != HPACK_OK) {
        log_error("h2_write_filter: hpack encode failed (%d)\n", (int)st);
        return 0;
    }

    const size_t mfs = s->peer_max_frame_size ? s->peer_max_frame_size : H2_MAX_FRAME_SIZE_DEFAULT;
    const size_t frames = block_len > mfs ? (block_len + mfs - 1) / mfs : 1;

    int ok = 1;
    size_t off = 0;
    for (size_t i = 0; i < frames && ok; i++) {
        const size_t chunk = block_len - off < mfs ? block_len - off : mfs;
        const int last = (i + 1 == frames);

        uint8_t flags = 0;
        if (last) flags |= H2_FLAG_END_HEADERS;
        if (i == 0 && end_stream) flags |= H2_FLAG_END_STREAM;

        ok = h2_session_queue_frame(s, i == 0 ? H2_FRAME_HEADERS : H2_FRAME_CONTINUATION,
                                    flags, stream->id, block + off, chunk);
        off += chunk;
    }

    free(block);

    return ok;
}

int h2_write_filter_early_hints(h2session_t* s, h2stream_t* stream, const http_header_t* fields) {
    /* 103 has no body and does not end the stream: the final response follows
     * on the same one (RFC 8297). */
    return __queue_extra_block(s, stream, fields, "103", 0);
}

int h2_write_filter_continue(h2session_t* s, h2stream_t* stream) {
    /* 100 (Continue) is a bare :status with no fields at all (RFC 9110
     * §10.1.1) — and, like 103, it leaves the stream open for the response that
     * follows. Queued from the read path the moment the request headers are in,
     * which is the only moment it is worth anything. */
    return __queue_extra_block(s, stream, NULL, "100", 0);
}

int h2_write_filter_trailers(h2session_t* s, h2stream_t* stream, httpresponse_t* response) {
    /* Trailers carry no :status and close the stream. Encoded here, at the
     * point of sending, because they share the encoder with the header block
     * and blocks must reach the peer in the order they were encoded (§4.3). */
    const int ok = __queue_extra_block(s, stream, response->trailer_, NULL, 1);

    if (ok) stream->end_stream_sent = 1;

    return ok;
}

http_filter_t* h2_write_filter_create(void) {
    http_filter_t* filter = malloc(sizeof * filter);
    if (filter == NULL) return NULL;

    h2_module_write_t* module = malloc(sizeof * module);
    if (module == NULL) {
        free(filter);
        return NULL;
    }

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = __free;
    module->base.reset = __reset;
    h2_data_writer_reset(&module->writer);
    module->buf = bufo_create();

    if (module->buf == NULL) {
        free(module);
        free(filter);
        return NULL;
    }

    filter->handler_header = __header;
    filter->handler_body = __body;
    filter->handler_flush = NULL;
    filter->module = module;
    filter->next = NULL;

    return filter;
}

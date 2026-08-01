#include "h2_write_filter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "connection_s.h"
#include "h2frame.h"
#include "h2session.h"
#include "hpack.h"
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

    /* DATA frame currently in flight. */
    uint8_t fh[H2_FRAME_HEADER_LEN];
    size_t  fh_len;                 /* 0 = no frame header pending/being built */
    size_t  fh_pos;
    size_t  frame_remaining;        /* payload bytes still owed for this frame */
    unsigned frame_end_stream : 1;
} h2_module_write_t;

static int __header(httprequest_t* request, httpresponse_t* response);
static int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf);
static void __free(void* arg);
static void __reset(void* arg);

/* ======================================================================= *
 *  Socket I/O (mirrors http_write_filter's __wr error handling)
 * ======================================================================= */

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

/* Drain data[*pos..size) to the socket, advancing *pos. */
static int __write_from(httpresponse_t* response, const char* data, size_t size, size_t* pos) {
    while (*pos < size) {
        const ssize_t written = __raw_write(response->connection, data + *pos, size - *pos);
        if (written < 0) {
            const int r = __write_status(response, written);
            if (r == CWF_DATA_AGAIN) continue; /* EINTR */
            return r;
        }
        if (written == 0) {
            log_error("h2_write_filter: connection closed\n");
            return CWF_ERROR;
        }
        *pos += (size_t)written;
    }

    return CWF_OK;
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

/* Connection-specific fields banned in HTTP/2 (RFC 9113 §8.2.2). Compared
 * case-insensitively because h1.1 response headers are canonical-cased. */
static int __is_forbidden(const char* key, size_t len) {
    static const char* const banned[] = {
        "connection", "keep-alive", "proxy-connection", "transfer-encoding",
        "upgrade", "te",
    };

    for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++) {
        const size_t n = strlen(banned[i]);
        if (n != len) continue;

        size_t j = 0;
        for (; j < n; j++) {
            char c = key[j];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            if (c != banned[i][j]) break;
        }
        if (j == n) return 1;
    }

    return 0;
}

/* RFC 9113 §8.2.1: field names MUST be lowercase on the wire; nghttp2-based
 * clients (curl, browsers) treat an uppercase byte as a PROTOCOL_ERROR. */
static void __lowercase(char* dst, const char* src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char c = src[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
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
                           h2session_t* s, bufo_t* out) {
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
    n++;

    size_t names_off = 0;
    for (http_header_t* h = response->header_; h != NULL; h = h->next) {
        if (h->key_length == 0 || __is_forbidden(h->key, h->key_length)) continue;

        __lowercase(names + names_off, h->key, h->key_length);
        fields[n].name = names + names_off;
        fields[n].name_len = h->key_length;
        fields[n].value = h->value;
        fields[n].value_len = h->value_length;
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
    const size_t total = frames * H2_FRAME_HEADER_LEN + block_len;

    if (!bufo_alloc(out, total)) {
        free(block);
        return 0;
    }

    const int has_body = __has_body(request, response);
    size_t off = 0;
    size_t written = 0;
    for (size_t i = 0; i < frames; i++) {
        const size_t chunk = block_len - off < mfs ? block_len - off : mfs;
        const int last = (i + 1 == frames);

        uint8_t type = (i == 0) ? H2_FRAME_HEADERS : H2_FRAME_CONTINUATION;
        uint8_t flags = 0;
        if (last) flags |= H2_FLAG_END_HEADERS;
        if (i == 0 && !has_body) flags |= H2_FLAG_END_STREAM;

        const size_t got = h2frame_encode((uint8_t*)out->data + written, total - written,
                                          type, flags, s->stream_id, block + off, chunk);
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

    if (!has_body)
        s->end_stream_sent = 1;

    return 1;
}

static int __header(httprequest_t* request, httpresponse_t* response) {
    h2_module_write_t* module = response->cur_filter->module;
    h2session_t* s = h2_session_of(response->connection);
    if (s == NULL) {
        log_error("h2_write_filter: response is not on an HTTP/2 connection\n");
        return CWF_ERROR;
    }

    if (module->buf->size == 0)
        if (!__build_headers(request, response, s, module->buf))
            return CWF_ERROR;

    return __write_bufo(response, module->buf);
}

/* ======================================================================= *
 *  DATA frames
 * ======================================================================= */

static int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    (void)request;

    h2_module_write_t* module = response->cur_filter->module;
    h2session_t* s = h2_session_of(response->connection);
    if (s == NULL) return CWF_ERROR;

    module->base.parent_buf = parent_buf;
    if (parent_buf == NULL) return CWF_ERROR;

    for (;;) {
        /* Start a new DATA frame. */
        if (module->fh_len == 0) {
            const size_t remaining = parent_buf->size > parent_buf->pos ?
                parent_buf->size - parent_buf->pos : 0;

            /* Upstream is drained. END_STREAM rides on the last non-empty frame;
             * when the final buffer arrives empty the session appends a trailing
             * empty DATA frame instead. */
            if (remaining == 0)
                return CWF_DATA_AGAIN;

            size_t chunk = remaining;
            if (chunk > s->peer_max_frame_size)
                chunk = s->peer_max_frame_size;

            const int64_t window = s->send_window < s->stream_send_window ?
                s->send_window : s->stream_send_window;
            if (window <= 0) {
                /* Nothing may be sent until the peer enlarges a window. Waiting
                 * on EPOLLOUT would spin: the socket is writable already. */
                s->window_blocked = 1;
                response->event_again = 1;
                return CWF_EVENT_AGAIN;
            }
            if ((int64_t)chunk > window)
                chunk = (size_t)window;

            module->frame_end_stream = (parent_buf->is_last && chunk == remaining) ? 1 : 0;
            module->frame_remaining = chunk;
            module->fh_pos = 0;
            module->fh_len = h2frame_encode_header(module->fh, H2_FRAME_DATA,
                                                   module->frame_end_stream ? H2_FLAG_END_STREAM : 0,
                                                   s->stream_id, chunk);
            if (module->fh_len == 0) return CWF_ERROR;
        }

        const int r = __write_from(response, (const char*)module->fh, module->fh_len, &module->fh_pos);
        if (r != CWF_OK) return r;

        /* Payload: written straight from the upstream buffer. */
        while (module->frame_remaining > 0) {
            const size_t chunk = bufo_chunk_size(parent_buf, module->frame_remaining);
            if (chunk == 0) {
                log_error("h2_write_filter: DATA frame underrun\n");
                return CWF_ERROR;
            }

            const ssize_t written = __raw_write(response->connection, bufo_data(parent_buf), chunk);
            if (written < 0) {
                const int st = __write_status(response, written);
                if (st == CWF_DATA_AGAIN) continue; /* EINTR */
                return st;
            }
            if (written == 0) {
                log_error("h2_write_filter: connection closed\n");
                return CWF_ERROR;
            }

            bufo_move_front_pos(parent_buf, (size_t)written);
            module->frame_remaining -= (size_t)written;
            s->send_window -= written;
            s->stream_send_window -= written;
        }

        if (module->frame_end_stream)
            s->end_stream_sent = 1;

        module->fh_len = 0;
        module->fh_pos = 0;
        module->frame_end_stream = 0;

        if (parent_buf->pos >= parent_buf->size)
            return CWF_DATA_AGAIN;
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
    module->fh_len = 0;
    module->fh_pos = 0;
    module->frame_remaining = 0;
    module->frame_end_stream = 0;

    bufo_clear(module->buf);
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
    module->fh_len = 0;
    module->fh_pos = 0;
    module->frame_remaining = 0;
    module->frame_end_stream = 0;
    module->buf = bufo_create();

    if (module->buf == NULL) {
        free(module);
        free(filter);
        return NULL;
    }

    filter->handler_header = __header;
    filter->handler_body = __body;
    filter->module = module;
    filter->next = NULL;

    return filter;
}

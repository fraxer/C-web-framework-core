#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "http_write_filter.h"
#include "log.h"
#include "openssl.h"
#include "httpfields.h"

#define BUF_SIZE 16384

void http_write_free(void* arg);
void http_write_reset(void* arg);

/* Worker thread only — see the invariant on connection_data_write(). */
ssize_t __write(connection_t* connection, const char* data, size_t size) {
    return connection->ssl ?
        openssl_write(connection->ssl, data, size) :
        send(connection->fd, data, size, MSG_NOSIGNAL);
}

size_t __head_size(httpresponse_t* response) {
    size_t size = 0;

    size += 9; // "HTTP/X.X "

    size += httpresponse_status_length(response->status_code);

    http_header_t* header = response->header_;

    while (header) {
        size += header->key_length;
        size += 2; // ": "
        size += header->value_length;
        size += 2; // "\r\n"

        header = header->next;
    }

    size += 2; // "\r\n"

    return size;
}

/* bufo_append() возвращает число скопированных байт: 0 — это и «нечего
 * копировать» (пустое значение заголовка — легально по RFC 7230), и «буфер
 * полон», а -1 — не выделенный буфер. Ошибкой считается только неполное
 * копирование, иначе пустой value рвал бы весь ответ. */
static int __append_full(bufo_t* buf, const char* data, size_t size) {
    return bufo_append(buf, data, size) == (ssize_t)size;
}

int __build_head(httpresponse_t* response, bufo_t* buf) {
    /* Неизвестный код: status_string() == NULL, status_length() == 0 —
     * без проверки ушла бы стартовая строка без статуса. */
    const char* status_string = httpresponse_status_string(response->status_code);
    const size_t status_length = httpresponse_status_length(response->status_code);
    if (status_string == NULL) {
        log_error("http_write_filter: unknown status code %d\n", response->status_code);
        return 0;
    }

    /* An interim 100 the parser could not finish writing (docs/http2/10, T.2).
     * It goes in the same buffer, ahead of the head: the peer must see a whole
     * status line, never the tail of one spliced into the final response. */
    connection_t* connection = response->connection;
    connection_server_ctx_t* ctx = connection->ctx;
    /* The `cont_sent < LEN` half is not redundant: subtracting an out-of-range
     * counter underflows size_t into a gigantic length, and bufo_append clamps
     * that to whatever the buffer has left instead of refusing it — so the
     * mistake would surface as a memcpy reading past the string literal, not as
     * a failed allocation. */
    const size_t cont_left = ctx->cont_pending && ctx->cont_sent < HTTP_CONTINUE_LINE_LEN ?
        HTTP_CONTINUE_LINE_LEN - ctx->cont_sent : 0;

    if (!bufo_alloc(buf, __head_size(response) + cont_left)) return 0;

    if (cont_left > 0) {
        if (!__append_full(buf, HTTP_CONTINUE_LINE + ctx->cont_sent, cont_left)) return 0;

        ctx->cont_pending = 0;
        ctx->cont_sent = 0;
    }

    if (!__append_full(buf, "HTTP/1.1 ", 9)) return 0;
    if (!__append_full(buf, status_string, status_length)) return 0;

    http_header_t* header = response->header_;
    while (header) {
        if (!__append_full(buf, header->key, header->key_length)) return 0;
        if (!__append_full(buf, ": ", 2)) return 0;
        if (!__append_full(buf, header->value, header->value_length)) return 0;
        if (!__append_full(buf, "\r\n", 2)) return 0;

        header = header->next;
    }

    if (!__append_full(buf, "\r\n", 2)) return 0;

    bufo_reset_pos(buf);

    return 1;
}

http_filter_t* http_write_filter_create(void) {
    http_filter_t* filter = malloc(sizeof * filter);
    if (filter == NULL) return NULL;

    filter->handler_header = http_write_header;
    filter->handler_body = http_write_body;
    filter->module = http_write_create();
    filter->next = NULL;

    if (filter->module == NULL) {
        free(filter);
        return NULL;
    }

    return filter;
}

http_module_write_t* http_write_create(void) {
    http_module_write_t* module = malloc(sizeof * module);
    if (module == NULL) return NULL;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = http_write_free;
    module->base.reset = http_write_reset;
    module->buf = bufo_create();
    if (module->buf == NULL) {
        free(module);
        return NULL;
    }

    return module;
}

void http_write_free(void* arg) {
    http_module_write_t* module = arg;

    bufo_free(module->buf);
    free(module);
}

void http_write_reset(void* arg) {
    http_module_write_t* module = arg;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;

    bufo_clear(module->buf);
}

int __wr(httpresponse_t* response, bufo_t* buf) {
    size_t readed = 0;
    while ((readed = bufo_chunk_size(buf, BUF_SIZE)) > 0) {
        const ssize_t writed = __write(response->connection, bufo_data(buf), readed);
        if (writed < 0) {
            connection_t* connection = response->connection;

            if (connection->ssl != NULL) {
                /* Для SSL errno неприменим — причина через SSL_get_error.
                 * WANT_READ/WANT_WRITE → отложить запись (event_again), как и
                 * EAGAIN для открытого сокета. */
                switch (openssl_io_status(connection->ssl, (int)writed)) {
                case OPENSSL_IO_WANT_READ:
                case OPENSSL_IO_WANT_WRITE:
                    response->event_again = 1;
                    return CWF_EVENT_AGAIN;
                case OPENSSL_IO_CLOSED:
                case OPENSSL_IO_ERROR:
                default:
                    log_error("write error: ssl failure\n");
                    return CWF_ERROR;
                }
            }

            if (errno == EINTR)
                continue;

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                response->event_again = 1;
                return CWF_EVENT_AGAIN;
            }

            log_error("write error: %s\n", strerror(errno));

            return CWF_ERROR;
        }

        if (writed == 0) {
            /* send(2) не возвращает 0 при size > 0, а SSL_write() возвращает
             * на закрытом соединении; сдвиг на 0 байт зациклил бы event-поток. */
            log_error("write error: connection closed\n");
            return CWF_ERROR;
        }

        bufo_move_front_pos(buf, writed);
    }

    return CWF_OK;
}

int http_write_header(httprequest_t* request, httpresponse_t* response) {
    (void)request;
    http_module_write_t* module = response->cur_filter->module;
    bufo_t* buf = module->buf;

    /* Before the head is serialised, because from here on the fields are bytes.
     * HTTP/3 is advertised on the protocols that are not it (RFC 7838). */
    httpfields_apply_alt_svc(response);

    if (buf->size == 0)
        if (!__build_head(response, buf))
            return CWF_ERROR;

    return __wr(response, buf);
}

int http_write_body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    (void)request;
    http_module_write_t* module = response->cur_filter->module;
    module->base.parent_buf = parent_buf;

    const int r = __wr(response, parent_buf);
    if (r == CWF_OK)
        return CWF_DATA_AGAIN;

    return r;
}

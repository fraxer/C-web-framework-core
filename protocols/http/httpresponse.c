#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

#include "connection_s.h"
#include "h2session.h"
#include "log.h"
#include "helpers.h"
#include "json.h"
#include "appconfig.h"
#include "mimetype.h"
#include "httpresponse.h"
#include "httpresponseparser.h"
#include "storage.h"
#include "view.h"
#include "json.h"
#include "model.h"
#include "str.h"
#ifdef CWFR_HTTP3
#include "h3conn.h"
#endif

static void __httpresponse_data(httpresponse_t* response, const char* data);
static void __httpresponse_datan(httpresponse_t* response, const char* data, size_t length);
static void __httpresponse_file(httpresponse_t* response, const char* path);
static void __httpresponse_filen(httpresponse_t* response, const char* path, size_t length);
static void __httpresponse_filef(httpresponse_t*, const char*, const char*, ...);
static void __httpresponse_json(httpresponse_t* response, json_doc_t* document);
static void __httpresponse_model(httpresponse_t* response, void* model, ...);
static void __httpresponse_models(httpresponse_t* response, array_t* models, ...);

static http_header_t* __httpresponse_header_get(httpresponse_t* response, const char* key);
static int __httpresponse_header_add(httpresponse_t* response, const char* key, const char* value);
static int __httpresponse_headern_add(httpresponse_t* response, const char* key, size_t key_length, const char* value, size_t value_length);
static int __httpresponse_trailer_add(httpresponse_t* response, const char* key, const char* value);
static int __httpresponse_early_hint_add(httpresponse_t* response, const char* key, const char* value);
static int __httpresponse_early_hints_send(httpresponse_t* response);
static int __httpresponse_trailern_add(httpresponse_t* response, const char* key, size_t key_length, const char* value, size_t value_length);
static int __httpresponse_headeru_add(httpresponse_t* response, const char* key, size_t key_length, const char* value, size_t value_length);
static int __httpresponse_header_exist(httpresponse_t* response, const char* key);
static int __httpresponse_header_remove(httpresponse_t* response, const char* key);
static int __httpresponse_alloc_body(httpresponse_t* response, const char* data, size_t length);
static int __httpresponse_header_add_content_length(httpresponse_t* response, size_t length);
static const char* __httpresponse_get_mimetype(const char* extension);

static int __httpresponse_keepalive_enabled(httpresponse_t* response);
static void __httpresponse_try_enable_gzip(httpresponse_t* response, const char* directive);
static void __httpresponse_try_enable_te(httpresponse_t* response, const char* directive);
static int __httpresponse_prepare_body(httpresponse_t* response, size_t length);
static void __httpresponse_cookie_add(httpresponse_t* response, cookie_t cookie);
static void __httpresponse_payload_free(http_payload_t* payload);
static void __httpresponse_init_payload(httpresponse_t* response);
static void __httpresponse_payload_parse_plain(httpresponse_t* response);
static char* __httpresponse_payload(httpresponse_t* response);
static file_content_t __httpresponse_payload_file(httpresponse_t* response);
static json_doc_t* __httpresponse_payload_json(httpresponse_t* response);


static int __httpresponse_init_parser(httpresponse_t* response);
static void __httpresponse_reset(httpresponse_t* response);
/* Which terminal write stage the response's filter chain ends in. The three
 * differ only there; every stage above is shared verbatim. */
typedef enum {
    HTTP_CHAIN_H1 = 0,
    HTTP_CHAIN_H2,
    HTTP_CHAIN_H3
} http_chain_e;

static httpresponse_t* __httpresponse_create(connection_t* connection, http_chain_e chain);

void __httpresponse_view(httpresponse_t* response, json_doc_t* document, const char* storage_name, const char* path_format, ...);

void httpresponse_free(void* arg) {
    httpresponse_t* response = arg;

    __httpresponse_reset(response);
    filters_free(response->filter);
    httpresponseparser_free(response->parser);
    /* Reset only recycles the blocks; this is where they go back. */
    arena_free(&response->arena);

    free(response);
}

int __httpresponse_init_parser(httpresponse_t* response) {
    response->parser = malloc(sizeof(httpresponseparser_t));
    if (response->parser == NULL) return 0;

    httpresponseparser_init(response->parser);

    return 1;
}

void __httpresponse_view(httpresponse_t* response, json_doc_t* document, const char* storage_name, const char* path_format, ...)
{
    char path[PATH_MAX];

    va_list args;
    va_start(args, path_format);
    vsnprintf(path, sizeof(path), path_format, args);
    va_end(args);

    char* data = render(document, storage_name, path);
    if (data == NULL) {
        response->send_data(response, "Render view error");
        return;
    }

    response->send_data(response, data);

    free(data);
}

httpresponse_t* httpresponse_create(connection_t* connection) {
    return __httpresponse_create(connection, HTTP_CHAIN_H1);
}

httpresponse_t* httpresponse_create_h2(connection_t* connection) {
    return __httpresponse_create(connection, HTTP_CHAIN_H2);
}

httpresponse_t* httpresponse_create_h3(connection_t* connection) {
    return __httpresponse_create(connection, HTTP_CHAIN_H3);
}

static httpresponse_t* __httpresponse_create(connection_t* connection, http_chain_e chain) {
    httpresponse_t* response = malloc(sizeof * response);
    if (response == NULL) return NULL;

    response->status_code = 200;
    response->version = HTTP1_VER_NONE;
    response->transfer_encoding = TE_NONE;
    response->content_encoding = CE_NONE;
    response->content_length = 0;
    response->file_ = file_alloc();
    response->header_ = NULL;
    response->last_header = NULL;
    response->trailer_ = NULL;
    response->last_trailer = NULL;
    response->early_hint_ = NULL;
    response->last_early_hint = NULL;
    switch (chain) {
    case HTTP_CHAIN_H2: response->filter = filters_create_h2(); break;
    case HTTP_CHAIN_H3: response->filter = filters_create_h3(); break;
    default:            response->filter = filters_create();    break;
    }
    if (response->filter == NULL) {
        free(response);
        return NULL;
    }
    arena_init(&response->arena);
    response->cur_filter = response->filter;
    response->event_again = 0;
    response->headers_sended = 0;
    /* The client-side response object is created without a connection, so the
     * snapshot has to tolerate NULL — and defaults to "not persistent", which
     * is the safe half of the choice. */
    response->keepalive = connection != NULL && connection->keepalive ? 1 : 0;
    response->range = 0;
    response->last_modified = 0;
    response->client_gzip = 0;
    response->vary_encoding = 0;
    response->connection = connection;
    response->send_data = __httpresponse_data;
    response->send_datan = __httpresponse_datan;
    response->send_view = __httpresponse_view;
    response->send_default = httpresponse_default;
    response->send_json = __httpresponse_json;
    response->send_model = __httpresponse_model;
    response->send_models = __httpresponse_models;
    response->redirect = httpresponse_redirect;
    response->get_header = __httpresponse_header_get;
    response->add_header = __httpresponse_header_add;
    response->add_headern = __httpresponse_headern_add;
    response->add_trailer = __httpresponse_trailer_add;
    response->add_trailern = __httpresponse_trailern_add;
    response->add_early_hint = __httpresponse_early_hint_add;
    response->send_early_hints = __httpresponse_early_hints_send;
    response->add_headeru = __httpresponse_headeru_add;
    response->add_content_length = __httpresponse_header_add_content_length;
    response->remove_header = __httpresponse_header_remove;
    response->send_file = __httpresponse_file;
    response->send_filen = __httpresponse_filen;
    response->send_filef = __httpresponse_filef;
    response->add_cookie = __httpresponse_cookie_add;
    response->base.reset = (void(*)(void*))__httpresponse_reset;
    response->base.free = (void(*)(void*))httpresponse_free;

    __httpresponse_init_payload(response);

    bufo_init(&response->body);

    if (!__httpresponse_init_parser(response)) {
        filters_free(response->filter);
        free(response);
        return NULL;
    }

    return response;
}

void __httpresponse_reset(httpresponse_t* response) {
    response->status_code = 200;
    response->version = HTTP1_VER_NONE;
    response->transfer_encoding = TE_NONE;
    response->content_encoding = CE_NONE;
    /* Клиентский парсер пишет content_length прямо в response; без обнуления
     * httpresponse_has_payload() на переиспользованном keep-alive соединении
     * видит длину предыдущего ответа. */
    response->content_length = 0;
    response->event_again = 0;
    response->headers_sended = 0;
    /* Re-snapshotted, not cleared: a reused response object serves the request
     * the connection is on now. */
    const connection_t* conn = response->connection;
    response->keepalive = conn != NULL && conn->keepalive ? 1 : 0;
    response->range = 0;
    response->last_modified = 0;
    response->client_gzip = 0;
    response->vary_encoding = 0;

    filters_reset(response->filter);
    response->cur_filter = response->filter;

    __httpresponse_payload_free(&response->payload_);

    response->file_.close(&response->file_);

    bufo_clear(&response->body);

    /* One call instead of a walk with three frees per header: the arena takes
     * the whole header block back and keeps the memory for the next request on
     * this connection (docs/http2/10 §10.2). */
    arena_reset(&response->arena);
    response->header_ = NULL;
    response->last_header = NULL;

    http_headers_free(response->trailer_);
    response->trailer_ = NULL;
    response->last_trailer = NULL;

    http_headers_free(response->early_hint_);
    response->early_hint_ = NULL;
    response->last_early_hint = NULL;
    response->early_hint_ = NULL;
    response->last_early_hint = NULL;

    httpresponseparser_reset(response->parser);
}

void __httpresponse_data(httpresponse_t* response, const char* data) {
    __httpresponse_datan(response, data, strlen(data));
}

void __httpresponse_datan(httpresponse_t* response, const char* data, size_t length) {
    connection_t* connection = response->connection;
    connection_server_ctx_t* ctx = connection->ctx;

    if (!__httpresponse_alloc_body(response, data, length)) {
        connection->keepalive = 0;
        response->keepalive = 0;
        ctx->destroyed = 1;
        return;
    }

    const char* keep_alive = __httpresponse_keepalive_enabled(response) ? "keep-alive" : "close";
    response->add_headeru(response, "Content-Type", 12, "text/html; charset=utf-8", 24);
    response->add_headeru(response, "Connection", 10, keep_alive, strlen(keep_alive));
    response->add_headeru(response, "Cache-Control", 13, "no-store, no-cache", 18);

    if (!__httpresponse_prepare_body(response, length)) {
        connection->keepalive = 0;
        response->keepalive = 0;
        ctx->destroyed = 1;
    }
}

void __httpresponse_file(httpresponse_t* response, const char* path) {
    __httpresponse_filen(response, path, strlen(path));
}

void __httpresponse_filen(httpresponse_t* response, const char* path, size_t length) {
    connection_t* connection = response->connection;
    connection_server_ctx_t* ctx = connection->ctx;
    char file_full_path[PATH_MAX];
    file_t file;
    const file_status_e status_code = http_open_file(ctx->server, file_full_path, PATH_MAX, path, length, &file);
    if (status_code != FILE_OK) {
        response->send_default(response, status_code == FILE_UNAVAILABLE ? 503 : 404);
        return;
    }

    http_response_file_opened(response, &file, file_full_path);
}

/* open() failed: say which HTTP outcome that is.
 *
 * EMFILE/ENFILE/ENOMEM are the server running out of capacity, not a missing
 * representation — calling those 404 once hid descriptor exhaustion in the h3
 * benchmark and told clients to cache the lie (see http_response_file). Every
 * other errno (ENOENT, EACCES, ENOTDIR, ELOOP, …) means the client cannot have
 * this path, which is what stat() used to report here as FILE_NOTFOUND. */
static file_status_e __open_errno_status(int err) {
    return err == EMFILE || err == ENFILE || err == ENOMEM
           ? FILE_UNAVAILABLE : FILE_NOTFOUND;
}

file_status_e http_open_file(server_t* server, char* file_full_path, size_t file_full_path_size, const char* path, size_t length, file_t* out) {
    *out = file_alloc();

    size_t pos = 0;

    if (!data_appendn(file_full_path, &pos, file_full_path_size, server->root, server->root_length))
        return FILE_NOTFOUND;

    if (path[0] != '/')
        if (!data_appendn(file_full_path, &pos, file_full_path_size, "/", 1))
            return FILE_NOTFOUND;

    if (!data_appendn(file_full_path, &pos, file_full_path_size, path, length))
        return FILE_NOTFOUND;

    file_full_path[pos] = 0;

    /* Two syscalls per response, not three. The stat()-then-open() shape asked
     * the kernel the same question twice: open() reports a missing path by
     * itself, and file_open() already fstat()s the descriptor it returns, so
     * S_ISDIR is answerable without a second lookup by name. A directory pays
     * one extra open/close pair — the rare case pays for the hot one.
     * docs/http2/10-performance.md §10.4. */
    for (int attempt = 0; ; attempt++) {
        errno = 0;
        /* O_NONBLOCK is what makes opening-before-knowing-the-type safe: a fifo
         * opened for reading blocks until a writer appears, and stat() used to
         * be what kept the worker out of that. It has no effect on the regular
         * files this actually serves, so nothing below has to clear it. */
        *out = file_open(file_full_path, O_RDONLY | O_NONBLOCK);
        if (!out->ok) {
            /* An index that cannot be opened is a directory we refuse to list,
             * not a missing path — the directory itself does exist. */
            const file_status_e status = __open_errno_status(errno);
            return attempt > 0 && status == FILE_NOTFOUND ? FILE_FORBIDDEN : status;
        }

        if (S_ISREG(out->mode))
            return FILE_OK;

        const int isdir = S_ISDIR(out->mode);
        out->close(out);

        /* A directory reached through the index is refused, as is anything that
         * is neither a regular file nor a directory (socket, device, fifo). */
        if (!isdir) return attempt > 0 ? FILE_FORBIDDEN : FILE_NOTFOUND;
        if (attempt > 0) return FILE_FORBIDDEN;

        index_t* index = server->index;
        if (index == NULL)
            return FILE_FORBIDDEN;

        if (file_full_path[pos - 1] != '/')
            if (!data_appendn(file_full_path, &pos, file_full_path_size, "/", 1))
                return FILE_NOTFOUND;

        if (!data_appendn(file_full_path, &pos, file_full_path_size, index->value, index->length))
            return FILE_NOTFOUND;

        file_full_path[pos] = 0;
    }
}

void http_response_file(httpresponse_t* response, const char* file_full_path) {
    errno = 0;
    file_t file = file_open(file_full_path, O_RDONLY | O_NONBLOCK);
    if (!file.ok) {
        /* EMFILE/ENFILE is temporary server capacity exhaustion, not a missing
         * representation. Calling it 404 hid descriptor exhaustion in the
         * high-concurrency h3 benchmark and encouraged clients to cache the
         * lie. ENOMEM belongs to the same retryable resource class. */
        const int status = __open_errno_status(errno) == FILE_UNAVAILABLE ? 503 : 404;
        response->send_default(response, status);
        return;
    }

    /* A route's static_file may expand {N} from the request path, so what it
     * names is not necessarily a regular file. Only regular files have a size
     * to serve and a descriptor sendfile() accepts. */
    if (!S_ISREG(file.mode)) {
        file.close(&file);
        response->send_default(response, 404);
        return;
    }

    http_response_file_opened(response, &file, file_full_path);
}

/* The response side of an already-open file: everything below needs only the
 * descriptor and the name, which is why resolving a path and answering with it
 * are two functions now — the resolver opens, this one answers. */
void http_response_file_opened(httpresponse_t* response, file_t* file, const char* file_full_path) {
    response->file_ = *file;

    const char* ext = file_extension(file_full_path);
    const char* mimetype = __httpresponse_get_mimetype(ext);
    const char* connection = __httpresponse_keepalive_enabled(response) ? "keep-alive" : "close";
    response->add_headeru(response, "Connection", 10, connection, strlen(connection));
    response->add_headeru(response, "Content-Type", 12, mimetype, strlen(mimetype));

    if (!__httpresponse_prepare_body(response, response->file_.size))
        response->send_default(response, 500);
}

void __httpresponse_filef(httpresponse_t* response, const char* storage_name, const char* path_format, ...) {
    char path[PATH_MAX];
    va_list args;
    va_start(args, path_format);
    vsnprintf(path, sizeof(path), path_format, args);
    va_end(args);

    response->file_ = storage_file_get(storage_name, path);
    if (!response->file_.ok) {
        response->send_default(response, 404);
        return;
    }

    const char* ext = file_extension(response->file_.name);
    const char* mimetype = __httpresponse_get_mimetype(ext);
    const char* connection = __httpresponse_keepalive_enabled(response) ? "keep-alive" : "close";
    response->add_headeru(response, "Connection", 10, connection, strlen(connection));
    response->add_headeru(response, "Content-Type", 12, mimetype, strlen(mimetype));

    if (!__httpresponse_prepare_body(response, response->file_.size))
        response->send_default(response, 500);
}

http_header_t* __httpresponse_header_get(httpresponse_t* response, const char* key) {
    http_header_t* header = response->header_;
    while (header != NULL) {
        if (cmpstr_lower(header->key, key))
            return header;

        header = header->next;
    }

    return NULL;
}

int __httpresponse_header_add(httpresponse_t* response, const char* key, const char* value) {
    return __httpresponse_headern_add(response, key, strlen(key), value, strlen(value));
}

int __httpresponse_early_hint_add(httpresponse_t* response, const char* key, const char* value) {
    if (key == NULL || value == NULL) return 0;

    /* HTTP/1.1 can carry 1xx, but its write path has no notion of an interim
     * response, and the feature exists for browsers — which speak HTTP/2 or
     * HTTP/3 to anything that offers them. Refused loudly rather than silently
     * dropped.
     *
     * HTTP/3 is recognised by its transport, not by the h2 bit: QUIC carries
     * nothing else here. Left as an h2-only check, this refused every early
     * hint on an h3 connection while the h3 write path was sitting there ready
     * to send them — which is exactly how it behaved until an end-to-end probe
     * asked for one. */
    const connection_t* connection = response->connection;
    const connection_server_ctx_t* ctx = connection != NULL ? connection->ctx : NULL;
    const int multiplexed = ctx != NULL &&
        (ctx->is_http2 || connection->transport == CONN_TRANSPORT_QUIC);

    if (ctx != NULL && !multiplexed) {
        log_error("httpresponse: early hints need HTTP/2 or HTTP/3, dropping \"%s\"\n", key);
        return 0;
    }

    http_header_t* hint = http_header_create(key, strlen(key), value, strlen(value));
    if (hint == NULL) return 0;
    if (hint->key == NULL || hint->value == NULL) {
        http_header_free(hint);
        return 0;
    }

    if (response->early_hint_ == NULL)
        response->early_hint_ = hint;

    if (response->last_early_hint != NULL)
        response->last_early_hint->next = hint;

    response->last_early_hint = hint;

    return 1;
}

int __httpresponse_early_hints_send(httpresponse_t* response) {
    if (response->early_hint_ == NULL) return 0;

    /* Ownership of the list moves to the stream, which encodes and sends it on
     * the worker — the handler thread must not encode HPACK, because blocks
     * have to reach the peer in the order they were encoded (RFC 9113 §4.3)
     * and only the worker can guarantee that. */
    http_header_t* fields = response->early_hint_;
    response->early_hint_ = NULL;
    response->last_early_hint = NULL;

    const connection_t* connection = response->connection;

    if (connection != NULL && connection->transport == CONN_TRANSPORT_QUIC) {
#ifdef CWFR_HTTP3
        if (h3_server_early_hints(response->connection, response, fields))
            return 1;
#endif
    }
    else if (h2_server_early_hints(response->connection, response, fields))
        return 1;

    http_headers_free(fields);

    return 0;
}

int __httpresponse_trailer_add(httpresponse_t* response, const char* key, const char* value) {
    if (key == NULL || value == NULL) return 0;

    return __httpresponse_trailern_add(response, key, strlen(key), value, strlen(value));
}

/* Trailers are kept apart from the headers rather than flagged among them: they
 * are encoded into their own HPACK block after the body, and nothing that walks
 * the header list (the write filter, gzip, range) should ever see them. */
int __httpresponse_trailern_add(httpresponse_t* response, const char* key, size_t key_length, const char* value, size_t value_length) {
    /* HTTP/1.1 would need chunked encoding and a Trailer header to carry these,
     * and the one thing that wants them — gRPC — is a multiplexed-protocol
     * feature. Rather than pretend, say so: silently dropping a gRPC status is
     * the kind of thing that gets debugged from the client side for a day.
     *
     * HTTP/3 carries them too (a second HEADERS frame before the FIN), and it
     * is recognised by its transport rather than by the h2 bit -- QUIC carries
     * nothing else here. Left as an h2-only check, an h3 handler's trailers
     * would have been dropped with a message blaming the wrong protocol. */
    const connection_t* connection = response->connection;
    const connection_server_ctx_t* ctx = connection != NULL ? connection->ctx : NULL;
    const int multiplexed = ctx != NULL &&
        (ctx->is_http2 || connection->transport == CONN_TRANSPORT_QUIC);

    if (ctx != NULL && !multiplexed) {
        log_error("httpresponse: trailers need HTTP/2 or HTTP/3, dropping \"%.*s\"\n",
                  (int)(key_length > 64 ? 64 : key_length), key);
        return 0;
    }

    http_header_t* trailer = http_header_create(key, key_length, value, value_length);
    if (trailer == NULL) return 0;
    if (trailer->key == NULL || trailer->value == NULL) {
        http_header_free(trailer);
        return 0;
    }

    if (response->trailer_ == NULL)
        response->trailer_ = trailer;

    if (response->last_trailer != NULL)
        response->last_trailer->next = trailer;

    response->last_trailer = trailer;

    return 1;
}

int __httpresponse_headern_add(httpresponse_t* response, const char* key, size_t key_length, const char* value, size_t value_length) {
    /* key может быть слайсом без нуль-терминатора — сравниваем по key_length. */
    if (response->range &&
        (cmpstrn_lower(key, key_length, "Transfer-Encoding", 17) ||
         cmpstrn_lower(key, key_length, "Content-Encoding", 16)
    )) {
        return 1;
    }

    http_header_t* header = http_header_create_in(&response->arena, key, key_length,
                                                 value, value_length);
    if (header == NULL) return 0;

    if (response->header_ == NULL)
        response->header_ = header;

    if (response->last_header != NULL)
        response->last_header->next = header;

    response->last_header = header;

    size_t data_size = response->body.size;
    if (response->file_.fd > -1)
        data_size = response->file_.size;

    if (!response->range) {
        if (cmpstr_lower(header->key, "Content-Type") && data_size >= 1024) {
            __httpresponse_try_enable_gzip(response, header->value);
        }
        else if (cmpstr_lower(header->key, "Transfer-Encoding")) {
            __httpresponse_try_enable_te(response, header->value);
        }
        else if (cmpstr_lower(header->key, "Content-Encoding") &&
            cmpstr_lower(header->value, "gzip")) {
            response->content_encoding = CE_GZIP;
        }
    }

    return 1;
}

int __httpresponse_headeru_add(httpresponse_t* response, const char* key, size_t key_length, const char* value, size_t value_length) {
    if (!__httpresponse_header_exist(response, key))
        return __httpresponse_headern_add(response, key, key_length, value, value_length);

    return 1;
}

int __httpresponse_header_exist(httpresponse_t* response, const char* key) {
    http_header_t* header = response->header_;
    while (header) {
        if (cmpstr_lower(header->key, key))
            return 1;

        header = header->next;
    }

    return 0;
}

int __httpresponse_header_remove(httpresponse_t* response, const char* key) {
    if (response->header_ == NULL)
        return 0;

    /* http_header_delete удаляет и не-головной узел — тогда голова не меняется
     * и по ней нельзя судить об успехе. Проверяем наличие заранее. */
    if (!__httpresponse_header_exist(response, key))
        return 0;

    response->header_ = http_header_unlink(response->header_, key);

    /* Unlinking can drop the node last_header pointed at (the tail). The
     * pointer is rebuilt from scratch, or the next add_header would write
     * through a stale one: last_header->next = new. The node itself stays
     * valid until the arena is reset — it is simply no longer in the list. */
    response->last_header = NULL;
    http_header_t* header = response->header_;
    while (header != NULL) {
        if (header->next == NULL) {
            response->last_header = header;
            break;
        }
        header = header->next;
    }

    return 1;
}

int __httpresponse_header_add_content_length(httpresponse_t* response, size_t length) {
    if (length == 0)
        return response->add_headern(response, "Content-Length", 14, "0", 1);

    size_t value = length;
    size_t content_length = 0;
    while (value) { content_length++; value /= 10; }

    char content_string[32];
    snprintf(content_string, sizeof(content_string), "%zu", length);

    return response->add_headern(response, "Content-Length", 14, content_string, content_length);
}

const char* httpresponse_status_string(int status_code) {
    switch (status_code) {
    case 100: return "100 Continue\r\n";
    case 101: return "101 Switching Protocols\r\n";
    case 102: return "102 Processing\r\n";
    case 103: return "103 Early Hints\r\n";
    case 200: return "200 OK\r\n";
    case 201: return "201 Created\r\n";
    case 202: return "202 Accepted\r\n";
    case 203: return "203 Non-Authoritative Information\r\n";
    case 204: return "204 No Content\r\n";
    case 205: return "205 Reset Content\r\n";
    case 206: return "206 Partial Content\r\n";
    case 207: return "207 Multi-Status\r\n";
    case 208: return "208 Already Reported\r\n";
    case 226: return "226 IM Used\r\n";
    case 300: return "300 Multiple Choices\r\n";
    case 301: return "301 Moved Permanently\r\n";
    case 302: return "302 Found\r\n";
    case 303: return "303 See Other\r\n";
    case 304: return "304 Not Modified\r\n";
    case 305: return "305 Use Proxy\r\n";
    case 306: return "306 Switch Proxy\r\n";
    case 307: return "307 Temporary Redirect\r\n";
    case 308: return "308 Permanent Redirect\r\n";
    case 400: return "400 Bad Request\r\n";
    case 401: return "401 Unauthorized\r\n";
    case 402: return "402 Payment Required\r\n";
    case 403: return "403 Forbidden\r\n";
    case 404: return "404 Not Found\r\n";
    case 405: return "405 Method Not Allowed\r\n";
    case 406: return "406 Not Acceptable\r\n";
    case 407: return "407 Proxy Authentication Required\r\n";
    case 408: return "408 Request Timeout\r\n";
    case 409: return "409 Conflict\r\n";
    case 410: return "410 Gone\r\n";
    case 411: return "411 Length Required\r\n";
    case 412: return "412 Precondition Failed\r\n";
    case 413: return "413 Payload Too Large\r\n";
    case 414: return "414 URI Too Long\r\n";
    case 415: return "415 Unsupported Media Type\r\n";
    case 416: return "416 Range Not Satisfiable\r\n";
    case 417: return "417 Expectation Failed\r\n";
    case 418: return "418 I'm a teapot\r\n";
    case 421: return "421 Misdirected Request\r\n";
    case 422: return "422 Unprocessable Entity\r\n";
    case 423: return "423 Locked\r\n";
    case 424: return "424 Failed Dependency\r\n";
    case 426: return "426 Upgrade Required\r\n";
    case 428: return "428 Precondition Required\r\n";
    case 429: return "429 Too Many Requests\r\n";
    case 431: return "431 Request Header Fields Too Large\r\n";
    case 451: return "451 Unavailable For Legal Reasons\r\n";
    case 500: return "500 Internal Server Error\r\n";
    case 501: return "501 Not Implemented\r\n";
    case 502: return "502 Bad Gateway\r\n";
    case 503: return "503 Service Unavailable\r\n";
    case 504: return "504 Gateway Timeout\r\n";
    case 505: return "505 HTTP Version Not Supported\r\n";
    case 506: return "506 Variant Also Negotiates\r\n";
    case 507: return "507 Insufficient Storage\r\n";
    case 508: return "508 Loop Detected\r\n";
    case 510: return "510 Not Extended\r\n";
    case 511: return "511 Network Authentication Required\r\n";
    }

    return NULL;
}

size_t httpresponse_status_length(int status_code) {
    switch (status_code) {
    case 100: return 14;
    case 101: return 25;
    case 102: return 16;
    case 103: return 17;
    case 200: return 8;
    case 201: return 13;
    case 202: return 14;
    case 203: return 35;
    case 204: return 16;
    case 205: return 19;
    case 206: return 21;
    case 207: return 18;
    case 208: return 22;
    case 226: return 13;
    case 300: return 22;
    case 301: return 23;
    case 302: return 11;
    case 303: return 15;
    case 304: return 18;
    case 305: return 15;
    case 306: return 18;
    case 307: return 24;
    case 308: return 24;
    case 400: return 17;
    case 401: return 18;
    case 402: return 22;
    case 403: return 15;
    case 404: return 15;
    case 405: return 24;
    case 406: return 20;
    case 407: return 35;
    case 408: return 21;
    case 409: return 14;
    case 410: return 10;
    case 411: return 21;
    case 412: return 25;
    case 413: return 23;
    case 414: return 18;
    case 415: return 28;
    case 416: return 27;
    case 417: return 24;
    case 418: return 18;
    case 421: return 25;
    case 422: return 26;
    case 423: return 12;
    case 424: return 23;
    case 426: return 22;
    case 428: return 27;
    case 429: return 23;
    case 431: return 37;
    case 451: return 35;
    case 500: return 27;
    case 501: return 21;
    case 502: return 17;
    case 503: return 25;
    case 504: return 21;
    case 505: return 32;
    case 506: return 29;
    case 507: return 26;
    case 508: return 19;
    case 510: return 18;
    case 511: return 37;
    }

    return 0;
}

const char* __httpresponse_get_mimetype(const char* extension) {
    const char* mimetype = mimetype_find_type(appconfig()->mimetype, extension);

    return mimetype == NULL ? "text/plain" : mimetype;
}

void httpresponse_default(httpresponse_t* response, int status_code) {
    /* Неизвестный код: status_string == NULL, а status_length() - 2 уходит в
     * underflow size_t. Отвечаем 500 вместо чтения NULL и гигантского VLA. */
    if (httpresponse_status_string(status_code) == NULL)
        status_code = 500;

    response->status_code = status_code;

    const char* str1 = "<html><head></head><body style=\"text-align:center;margin:20px\"><h1>";
    size_t str1_length = strlen(str1);

    const char* str2 = "</h1></body></html>";
    size_t str2_length = strlen(str2);

    size_t status_code_length = httpresponse_status_length(status_code) - 2;
    size_t data_length = str1_length + status_code_length + str2_length;
    size_t pos = 0;

    char data[data_length + 1];
    const char* status_code_string = httpresponse_status_string(status_code);

    memcpy(data, str1, str1_length); pos += str1_length;
    memcpy(&data[pos], status_code_string, status_code_length); pos += status_code_length;
    memcpy(&data[pos], str2, str2_length);

    data[data_length] = 0;

    response->send_datan(response, data, data_length);
}

void __httpresponse_json(httpresponse_t* response, json_doc_t* document) {
    const char* connection = __httpresponse_keepalive_enabled(response) ? "keep-alive" : "close";
    response->add_headeru(response, "Content-Type", 12, "application/json", 16);
    response->add_headeru(response, "Connection", 10, connection, strlen(connection));
    response->add_headeru(response, "Cache-Control", 13, "no-store, no-cache", 18);

    if (document == NULL) {
        response->send_default(response, 500);
        return;
    }

    const char* data = json_stringify(document);
    const size_t length = json_stringify_size(document);

    if (!__httpresponse_prepare_body(response, length)) {
        response->send_default(response, 500);
        return;
    }

    if (!__httpresponse_alloc_body(response, data, length))
        response->send_default(response, 500);
}

void __httpresponse_model(httpresponse_t* response, void* model, ...) {
    const char* connection = __httpresponse_keepalive_enabled(response) ? "keep-alive" : "close";
    response->add_headeru(response, "Content-Type", 12, "application/json", 16);
    response->add_headeru(response, "Connection", 10, connection, strlen(connection));
    response->add_headeru(response, "Cache-Control", 13, "no-store, no-cache", 18);

    if (model == NULL) {
        response->send_default(response, 500);
        return;
    }

    va_list va_args;
    va_start(va_args, model);

    char** display_fields = va_arg(va_args, char**);

    va_end(va_args);

    json_doc_t* doc = json_create_empty();
    if (!doc) {
        response->send_default(response, 500);
        return;
    }

    json_token_t* object = model_json_create_object(model, display_fields);
    if (object == NULL) {
        json_free(doc);
        response->send_default(response, 500);
        return;
    }

    json_set_root(doc, object);

    const char* data = json_stringify(doc);
    const size_t length = json_stringify_size(doc);

    if (!__httpresponse_prepare_body(response, length)) {
        response->send_default(response, 500);
        json_free(doc);
        return;
    }

    if (!__httpresponse_alloc_body(response, data, length))
        response->send_default(response, 500);

    json_free(doc);
}

void __httpresponse_models(httpresponse_t* response, array_t* models, ...) {
    const char* connection = __httpresponse_keepalive_enabled(response) ? "keep-alive" : "close";
    response->add_headeru(response, "Content-Type", 12, "application/json", 16);
    response->add_headeru(response, "Connection", 10, connection, strlen(connection));
    response->add_headeru(response, "Cache-Control", 13, "no-store, no-cache", 18);

    if (models == NULL) {
        response->send_default(response, 500);
        return;
    }

    va_list va_args;
    va_start(va_args, models);

    char** display_fields = va_arg(va_args, char**);

    va_end(va_args);

    json_doc_t* doc = json_root_create_array();
    if (!doc) {
        response->send_default(response, 500);
        return;
    }

    json_token_t* json_array = json_root(doc);
    for (size_t i = 0; i < array_size(models); i++) {
        void* model = array_get(models, i);
        json_token_t* object = model_json_create_object(model, display_fields);
        if (object == NULL) {
            json_free(doc);
            response->send_default(response, 500);
            return;
        }

        json_array_append(json_array, object);
    }

    const char* data = json_stringify(doc);
    const size_t length = json_stringify_size(doc);

    if (!__httpresponse_prepare_body(response, length)) {
        response->send_default(response, 500);
        json_free(doc);
        return;
    }

    if (!__httpresponse_alloc_body(response, data, length))
        response->send_default(response, 500);

    json_free(doc);
}

int __httpresponse_keepalive_enabled(httpresponse_t* response) {
    /* The response's own snapshot, not the connection's current value — see
     * httpresponse_t::keepalive. */
    return response->keepalive;
}

void httpresponse_redirect(httpresponse_t* response, const char* path, int status_code) {
    response->status_code = status_code;

    if (!response->add_header(response, "Location", path))
        return;

    if (httpresponse_redirect_is_external(path))
        response->add_header(response, "Connection", "Close");
}

int __httpresponse_alloc_body(httpresponse_t* response, const char* data, size_t length) {
    if (!bufo_alloc(&response->body, length + 1)) return 0; // +1 for \0 only for http client
    if (bufo_append(&response->body, data, length) < 0) return 0;

    response->body.data[response->body.size] = 0;

    bufo_reset_pos(&response->body);

    return 1;
}

/* The q value of one Accept-Encoding element, or -1 when the element carries no
 * q parameter. The exact weight is never needed -- the only question this
 * server asks is whether the coding is refused (q=0, in any of its spellings)
 * or allowed -- so the return is a coarse "zero or not". */
static int __qvalue(const char* params, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (params[i] != 'q' && params[i] != 'Q') continue;

        size_t j = i + 1;
        while (j < length && (params[j] == ' ' || params[j] == '\t')) j++;
        if (j >= length || params[j] != '=') continue;

        j++;
        while (j < length && (params[j] == ' ' || params[j] == '\t')) j++;
        if (j >= length) return -1;

        /* "0", "0.", "0.000" are the only refusals; anything starting with 1,
         * or a zero with a non-zero digit after the point, is acceptable. */
        if (params[j] != '0') return 100;

        j++;
        if (j >= length || params[j] != '.') return 0;

        for (j++; j < length; j++) {
            if (params[j] < '0' || params[j] > '9') break;
            if (params[j] != '0') return 1;
        }

        return 0;
    }

    return -1;
}

/* Whether Accept-Encoding lets this server send gzip (RFC 9110 §12.5.3).
 * "gzip" named outright decides it; "*" stands in when it is not named, and
 * either of them with q=0 is a refusal, not a weak preference. An absent or
 * empty field means identity only -- the same reading nginx takes, and the one
 * that keeps a client which never asked from being handed compressed bytes. */
static int __accept_encoding_allows_gzip(const char* value, size_t length) {
    if (value == NULL || length == 0) return 0;

    int gzip_q = -1;
    int star_q = -1;

    size_t pos = 0;
    while (pos < length) {
        size_t end = pos;
        while (end < length && value[end] != ',') end++;

        size_t start = pos;
        while (start < end && (value[start] == ' ' || value[start] == '\t')) start++;

        size_t token_end = start;
        while (token_end < end && value[token_end] != ';' &&
               value[token_end] != ' ' && value[token_end] != '\t') token_end++;

        const size_t token_length = token_end - start;
        int* slot = NULL;

        if (token_length == 4 && strncasecmp(&value[start], "gzip", 4) == 0)
            slot = &gzip_q;
        else if (token_length == 1 && value[start] == '*')
            slot = &star_q;

        if (slot != NULL) {
            const int q = __qvalue(&value[token_end], end - token_end);
            *slot = q < 0 ? 100 : q;
        }

        pos = end + 1;
    }

    if (gzip_q >= 0) return gzip_q > 0;

    return star_q > 0;
}

void httpresponse_set_accept_encoding(httpresponse_t* response, const char* value, size_t length) {
    response->client_gzip = __accept_encoding_allows_gzip(value, length) ? 1 : 0;
}

void __httpresponse_try_enable_gzip(httpresponse_t* response, const char* directive) {
    if (response->range) return;

    env_gzip_str_t* item = env()->main.gzip;
    while (item != NULL) {
        if (cmpstr_lower(item->mimetype, directive)) {
            /* The type is negotiable whoever asked; the compression itself
             * happens only for a client that said it would take it. */
            response->vary_encoding = 1;

            if (response->client_gzip) {
                response->content_encoding = CE_GZIP;
                response->transfer_encoding = TE_CHUNKED;
            }
            break;
        }
        item = item->next;
    }
}

void __httpresponse_try_enable_te(httpresponse_t* response, const char* directive) {
    if (response->range) return;

    if (!cmpstr_lower(directive, "chunked")) return;

    response->transfer_encoding = TE_CHUNKED;
}

http_ranges_t* httpresponse_init_ranges(void) {
    http_ranges_t* range = malloc(sizeof * range);
    if (range == NULL) return NULL;

    range->start = -1;
    range->end = -1;
    range->next = NULL;

    return range;
}

int __httpresponse_prepare_body(httpresponse_t* response, size_t length) {
    (void)length;
    response->add_headeru(response, "Accept-Ranges", 13, "bytes", 5);

    return 1;
}

void __httpresponse_cookie_add(httpresponse_t* response, cookie_t cookie) {
    if (cookie.name == NULL || cookie.name[0] == 0)
        return;
    if (cookie.value == NULL)
        return;

    str_t str;
    if (!str_init(&str, 256))
        return;

    if (!str_appendf(&str, "%s=%s", cookie.name, cookie.value))
        goto cleanup;

    if (cookie.seconds == 0) {
        if (!str_append(&str, "; Max-Age=0", 11))
            goto cleanup;
    } else if (cookie.seconds > 0) {
        time_t t = time(NULL) + cookie.seconds;
        char date[64];
        if (http_format_date(t, date, sizeof(date)) == 0)
            goto cleanup;

        if (!str_appendf(&str, "; Expires=%s", date))
            goto cleanup;
    }

    if (cookie.path != NULL && cookie.path[0] != 0)
        if (!str_appendf(&str, "; Path=%s", cookie.path))
            goto cleanup;

    if (cookie.domain != NULL && cookie.domain[0] != 0)
        if (!str_appendf(&str, "; Domain=%s", cookie.domain))
            goto cleanup;

    if (cookie.secure)
        if (!str_append(&str, "; Secure", 8))
            goto cleanup;

    if (cookie.http_only)
        if (!str_append(&str, "; HttpOnly", 10))
            goto cleanup;

    if (cookie.same_site != NULL && cookie.same_site[0] != 0)
        if (!str_appendf(&str, "; SameSite=%s", cookie.same_site))
            goto cleanup;

    response->add_header(response, "Set-Cookie", str_get(&str));

    cleanup:

    str_clear(&str);
}

int httpresponse_redirect_is_external(const char* url) {
    if (strlen(url) < 8) return 0;

    if (url[0] == 'h'
        && url[1] == 't'
        && url[2] == 't'
        && url[3] == 'p'
        && url[4] == ':'
        && url[5] == '/'
        && url[6] == '/'
        ) return 1;

    if (url[0] == 'h'
        && url[1] == 't'
        && url[2] == 't'
        && url[3] == 'p'
        && url[4] == 's'
        && url[5] == ':'
        && url[6] == '/'
        && url[7] == '/'
        ) return 1;

    return 0;
}

int httpresponse_has_payload(httpresponse_t* response) {
    return response->content_length > 0
        || response->transfer_encoding != TE_NONE;
}

void __httpresponse_payload_free(http_payload_t* payload) {
    /* path/boundary/part могли быть выделены и без открытого файла (например,
     * mkstemp не удался после create_tmppath) — освобождаем их всегда. */
    if (payload->file.fd > -1) {
        payload->file.close(&payload->file);
        if (payload->path != NULL)
            unlink(payload->path);
    }

    payload->pos = 0;

    free(payload->path);
    payload->path = NULL;

    free(payload->boundary);
    payload->boundary = NULL;

    http_payloadpart_free(payload->part);
    payload->part = NULL;

    payload->type = NONE;
}

void __httpresponse_init_payload(httpresponse_t* response) {
    response->payload_.pos = 0;
    response->payload_.file = file_alloc();
    response->payload_.path = NULL;
    response->payload_.part = NULL;
    response->payload_.boundary = NULL;
    response->payload_.type = NONE;

    response->get_payload = __httpresponse_payload;
    response->get_payload_file = __httpresponse_payload_file;
    response->get_payload_json = __httpresponse_payload_json;
}

void __httpresponse_payload_parse_plain(httpresponse_t* response) {
    /* Повторный вызов (get_payload + get_payload_file) не должен терять
     * уже созданный part — иначе утечка. */
    http_payloadpart_t* part = response->payload_.part;
    if (part == NULL) {
        part = http_payloadpart_create();
        if (part == NULL) return;
    }

    part->size = response->payload_.file.size;

    response->payload_.type = PLAIN;
    response->payload_.part = part;
}

char* __httpresponse_payload(httpresponse_t* response) {
    char* buffer = NULL;

    if (response->body.size > 0) {
        buffer = malloc(response->body.size + 1); // body already has \0
        if (buffer == NULL) return NULL;

        memcpy(buffer, response->body.data, response->body.size + 1);
    } else {
        if (response->payload_.file.fd < 0) return NULL;

        __httpresponse_payload_parse_plain(response);

        http_payloadpart_t* part = response->payload_.part;
        if (part == NULL) return NULL;

        buffer = malloc(part->size + 1);
        if (buffer == NULL) return NULL;

        size_t total = 0;
        while (total < part->size) {
            ssize_t r = pread(response->payload_.file.fd, buffer + total, part->size - total,
                              (off_t)part->offset + (off_t)total);
            if (r < 0) {
                log_error("httpresponse: payload read error: %s\n", strerror(errno));
                free(buffer);
                return NULL;
            }
            if (r == 0) {
                log_error("httpresponse: payload truncated (%zu of %zu bytes)\n", total, part->size);
                free(buffer);
                return NULL;
            }
            total += (size_t)r;
        }

        buffer[part->size] = 0;
    }

    return buffer;
}

file_content_t __httpresponse_payload_file(httpresponse_t* response) {
    __httpresponse_payload_parse_plain(response);

    file_content_t file_content = file_content_create(0, NULL, 0, 0);
    http_payloadpart_t* part = response->payload_.part;
    if (part == NULL) return file_content;

    char* filename = NULL;
    http_payloadfield_t* pfield = part->field;

    while (pfield) {
        if (pfield->key && strcmp(pfield->key, "filename") == 0) {
            filename = pfield->value;
            break;
        }
        pfield = pfield->next;
    }

    /* Валидность содержимого определяется наличием payload-файла: вызывающие
     * (например, storages3) по ok решают, можно ли читать из fd. */
    file_content.ok = response->payload_.file.fd > -1;
    file_content.fd = response->payload_.file.fd;
    file_content.offset = part->offset;
    file_content.size = part->size;
    file_content.set_filename(&file_content, filename);

    return file_content;
}

json_doc_t* __httpresponse_payload_json(httpresponse_t* response) {
    char* payload = __httpresponse_payload(response);
    if (payload == NULL) return NULL;

    json_doc_t* document = json_parse(payload);
    free(payload);

    return document;
}

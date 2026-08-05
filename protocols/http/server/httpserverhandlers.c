#include "httpserverhandlers.h"

#include <string.h>
#include <sys/socket.h>

#include "httpcontext.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "httprequestparser.h"
#include "log.h"
#include "connection_queue.h"
#include "openssl.h"
#include "idn_utils.h"
#include "h2session.h"

typedef struct {
    connection_queue_item_data_t base;
    httprequest_t* request;
    httpresponse_t* response;
    connection_t* connection;
    ratelimiter_t* ratelimiter;
    /* The virtual host this request resolved to, captured at dispatch time.
     *
     * ctx->server is per-connection but rewritten per request by
     * httpparser_select_server, so reading it from the handler thread is both a
     * data race and wrong: under h2 the worker may already have parsed a later
     * request — possibly for a different :authority, hence a different vhost —
     * on the same connection. The request's own server is the one its
     * middlewares belong to. */
    server_t* server;
} connection_queue_http_data_t;

struct middleware_item;

typedef int(*deferred_handler)(httprequest_t* request, httpresponse_t* response);
typedef void(*queue_handler)(void*);
typedef void*(*queue_data_create)(connection_t* connection, httprequest_t* request, httpresponse_t* response, ratelimiter_t* ratelimiter);

int run_middlewares(struct middleware_item* middleware_item, void* ctx);

typedef enum {
    H2C_SNIFF_NO,         /* not the h2 preface — continue as HTTP/1.1 */
    H2C_SNIFF_YES,        /* the h2 preface — switch to HTTP/2 */
    H2C_SNIFF_INCOMPLETE, /* a prefix so far — wait for more bytes, decide later */
    H2C_SNIFF_ERROR       /* peer closed or the socket failed */
} h2c_sniff_e;

static h2c_sniff_e __h2c_sniff_preface(connection_t* connection, size_t* len);

static int __tls_read(connection_t* connection);
static int __tls_write(connection_t* connection);
static int __read(connection_t* connection);
static int __write(connection_t* connection);
static int __deferred_handler(connection_t* connection, httprequest_t* request, httpresponse_t* response, queue_handler runner, queue_handler handle, queue_data_create data_create, ratelimiter_t* ratelimiter);
static int __handle(connection_t* connection, httprequest_t* request, deferred_handler handler);
static int __handler_added_to_queue(httprequest_t* request, httpresponse_t* response);
static int __get_redirect(connection_t* connection, httprequest_t* request);
static int __apply_redirect(httprequest_t* request, httpresponse_t* response, deferred_handler handler);
static void __queue_request_handler(void* arg);
static void __queue_response_handler(void* arg);
static void* __queue_data_request_create(connection_t* connection, httprequest_t* request, httpresponse_t* response, ratelimiter_t* ratelimiter);
static void __queue_data_request_free(void* arg);
static int __handshake(connection_t* connection);
static int __sni_callback(SSL* ssl, int* ad, void* arg);
static void* __queue_data_response_create(connection_t* connection, httprequest_t* request, httpresponse_t* response, ratelimiter_t* ratelimiter);
static void __queue_data_response_free(void* arg);
static int __post_response_default(connection_t* connection, int status_code);
static int __handler_finished(connection_t* connection, httprequest_t* request, httpresponse_t* response);
static int __post_response(httprequest_t* request, httpresponse_t* response);
static int __post_deffered_response(httprequest_t* request, httpresponse_t* response);
static ratelimiter_t* __ratelimiter_find(server_http_t* http_config, route_t* route);
static int __prepare_static_file_response(connection_server_ctx_t* ctx, httpresponse_t* response, const char* static_file_path);

int __tls_read(connection_t* connection) {
    return __handshake(connection);
}

int __tls_write(connection_t* connection) {
    (void)connection;
    log_error("tls write\n");
    return 1;
}

int set_tls(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    connection->ssl_ctx = ctx->server->openssl->ctx;

    connection->read = __tls_read;
    connection->write = __tls_write;
    return 1;
}

int set_http(connection_t* connection) {
    connection->read = http_server_guard_read;
    connection->write = http_server_guard_write;

    connection_server_ctx_t* ctx = connection->ctx;

    if (ctx->parser != NULL) {
        requestparser_t* parser = ctx->parser;
        parser->free(parser);
    }

    ctx->parser = httpparser_create(connection);
    if (ctx->parser == NULL)
        return 0;

    return 1;
}

int http_server_guard_read(connection_t* connection) {
    connection_s_lock(connection, LOCK_SITE_HTTP_READ);
    const int r = __read(connection);
    connection_s_unlock(connection);

    return r;
}

int http_server_guard_write(connection_t* connection) {
    if (connection == NULL) {
        log_error("http_server_guard_write: connection is NULL\n");
        return 0;
    }

    connection_s_lock(connection, LOCK_SITE_HTTP_WRITE);
    const int r = __write(connection);
    connection_s_unlock(connection);

    return r;
}

/* Read the first bytes of a plaintext connection and tell an HTTP/2 connection
 * preface from an HTTP/1.1 request line. On return `*len` is how many bytes are
 * staged at the front of connection->buffer for the winning protocol to consume.
 *
 * The preface can be split across TCP segments, so one read is not always enough
 * to decide. Bytes accumulate at the front of connection->buffer across calls
 * (ctx->h2c_peeked counts them) and the next read appends after them, which
 * keeps the undecided bytes owned by us: whichever protocol wins gets the whole
 * prefix back. MSG_PEEK would be simpler, but leaving the bytes unread on a
 * level-triggered epoll makes EPOLLIN refire immediately — a client that stalls
 * mid-preface would spin a worker at 100%.
 *
 * A short prefix is never resolved early: "P"/"PR" also start POST, PUT and
 * PROPFIND, so only the full 24 bytes decide. TLS connections never get here —
 * ALPN has already settled the protocol. */
static h2c_sniff_e __h2c_sniff_preface(connection_t* connection, size_t* len) {
    connection_server_ctx_t* ctx = connection->ctx;
    const size_t have = ctx->h2c_peeked;

    const ssize_t n = recv(connection->fd, connection->buffer + have,
                           connection->buffer_size - have, 0);
    if (n < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? H2C_SNIFF_INCOMPLETE : H2C_SNIFF_ERROR;
    if (n == 0)
        return H2C_SNIFF_ERROR;

    const size_t total = have + (size_t)n;
    const size_t cmp = total < H2_CONNECTION_PREFACE_LEN ? total : H2_CONNECTION_PREFACE_LEN;

    *len = total;

    if (memcmp(connection->buffer, H2_CONNECTION_PREFACE, cmp) != 0)
        return H2C_SNIFF_NO;

    if (total < H2_CONNECTION_PREFACE_LEN) {
        ctx->h2c_peeked = total & 0x1f; /* < 24, fits the bitfield */
        return H2C_SNIFF_INCOMPLETE;
    }

    return H2C_SNIFF_YES;
}

int __read(connection_t* connection) {
    if (connection == NULL) {
        log_error("__read: connection is NULL\n");
        return 0;
    }

    connection_server_ctx_t* ctx = connection->ctx;
    if (ctx == NULL) {
        log_error("__read: ctx is NULL\n");
        return 0;
    }

    httprequestparser_t* parser = ctx->parser;
    if (parser == NULL) {
        log_error("__read: parser is NULL\n");
        return 0;
    }

    /* h2c prior-knowledge (RFC 9113 §3.4): a plaintext client may open with the
     * 24-byte HTTP/2 connection preface instead of an HTTP/1.1 request line.
     * Settled once per connection, before any byte reaches the h1.1 parser, so
     * from the second read on h1.1 keeps its untouched fast path. */
    size_t sniffed = 0; /* bytes the sniff already staged in connection->buffer */
    if (ctx->h2c_preface) {
        switch (__h2c_sniff_preface(connection, &sniffed)) {
        case H2C_SNIFF_INCOMPLETE:
            return 1; /* still a prefix — held in the buffer until the next read */
        case H2C_SNIFF_ERROR:
            return 0;
        case H2C_SNIFF_YES:
            ctx->h2c_preface = 0;
            ctx->h2c_peeked = 0;
            return h2_server_set_http2_prior_knowledge(connection, sniffed);
        case H2C_SNIFF_NO:
        default:
            /* An ordinary HTTP/1.1 request: hand the sniffed bytes straight to
             * the parser below instead of re-reading the socket. */
            ctx->h2c_preface = 0;
            ctx->h2c_peeked = 0;
            break;
        }
    }

    while (1) {
        ssize_t bytes_readed = 0;
        read_data:

        if (sniffed > 0) {
            bytes_readed = (ssize_t)sniffed;
            sniffed = 0;
        }
        else
            bytes_readed = connection_data_read(connection);

        switch (bytes_readed) {
        case -1:
        {
            if (connection->ssl != NULL) {
                /* Для SSL errno не определён при WANT_READ/WANT_WRITE — причина
                 * читается только через SSL_get_error. WANT_* — это «подожди», а
                 * не ошибка: соединение остаётся живым, LT-epoll снова разбудит
                 * по готовности сокета. Раньше WANT_READ ронял соединение. */
                switch (openssl_io_status(connection->ssl, (int)bytes_readed)) {
                case OPENSSL_IO_WANT_READ:
                case OPENSSL_IO_WANT_WRITE:
                    return 1;
                case OPENSSL_IO_CLOSED:
                case OPENSSL_IO_ERROR:
                default:
                    return 0;
                }
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1;

            return 0;
        }
        case 0:
            return 0;
        default:
        {
            httpparser_set_bytes_readed(parser, (size_t)bytes_readed);
            parser->pos_start = 0;
            parser->pos = 0;

            while (1) {
                switch (httpparser_run(parser)) {
                case HTTP1PARSER_ERROR:
                case HTTP1PARSER_OUT_OF_MEMORY:
                    return 0;
                case HTTP1PARSER_PAYLOAD_LARGE:
                    return __post_response_default(connection, 413);
                case HTTP1PARSER_BAD_REQUEST:
                    return __post_response_default(connection, 400);
                case HTTP1PARSER_HOST_NOT_FOUND:
                    return __post_response_default(connection, 404);
                case HTTP1PARSER_CONTINUE:
                    goto read_data;
                case HTTP1PARSER_HANDLE_AND_CONTINUE:
                {
                    if (!__handle(connection, parser->request, __post_deffered_response))
                        return 0;

                    httpparser_prepare_continue(parser);
                    break;
                }
                case HTTP1PARSER_COMPLETE:
                {
                    if (!__handle(connection, parser->request, __post_response))
                        return 0;

                    httpparser_reset(parser);
                    return 1;
                }
                default:
                    return 0;
                }
            }
        }
        }
    }

    return 0;
}

int __write(connection_t* connection) {
    if (connection == NULL) {
        log_error("__write: connection is NULL\n");
        return 0;
    }

    connection_server_ctx_t* ctx = connection->ctx;
    if (ctx == NULL) {
        log_error("__write: ctx is NULL\n");
        return 0;
    }

    httpresponse_t* response = ctx->response;
    if (response == NULL) {
        log_error("__write: response is NULL\n");
        return 0;
    }

    int r = __run_header_filters(ctx->request, response);
    if (r == CWF_EVENT_AGAIN)
        return 1;
    if (r == CWF_ERROR)
        return 0;

    r = __run_body_filters(ctx->request, response);
    if (r == CWF_EVENT_AGAIN)
        return 1;
    if (r == CWF_ERROR)
        return 0;

    return connection_after_write(connection);
 }

int __deferred_handler(connection_t* connection, httprequest_t* request, httpresponse_t* response, queue_handler runner, queue_handler handle, queue_data_create data_create, ratelimiter_t* ratelimiter) {
    connection_queue_item_t* item = connection_queue_item_create();
    if (item == NULL) return 0;

    item->run = runner;
    item->handle = handle;
    item->connection = connection;
    item->data = data_create(connection, request, response, ratelimiter);

    if (item->data == NULL) {
        item->free(item);
        return 0;
    }

    connection_server_ctx_t* ctx = connection->ctx;

    /* h2 hands every item to its own worker; h1.1 keeps one request in flight
     * and lets the chain pass the next one on (docs/concurrency/00 §5.2). */
    const int parallel = ctx->is_http2;

    /* ctx->queue used to be covered by connection_s_lock, which the worker held
     * for the whole handler run. It does not any more, so the queue needs its
     * own mutual exclusion — and the "was it empty" test has to be taken
     * together with the append, or two dispatches both decide they were first. */
    cqueue_lock(ctx->queue);
    const int queue_empty = cqueue_empty(ctx->queue);
    const int appended = cqueue_append(ctx->queue, item);
    cqueue_unlock(ctx->queue);

    if (!appended) {
        item->free(item);
        return 0;
    }

    /* Past this point the item belongs to ctx->queue and must not be freed here
     * — a worker may already be running it. */
    if (!parallel && !queue_empty)
        return 1;

    if (parallel ? !connection_queue_append_parallel(item) : !connection_queue_append(item)) {
        /* The item cannot be taken back out: cqueue has no removal by identity,
         * and under fan-out the head of the queue need not be the item we just
         * appended. Failing here means epoll or an allocation gave up, so take
         * the connection down instead and let __ctx_free drain the queue — the
         * caller closes it on our 0. */
        atomic_store(&ctx->destroyed, 1);
        return 0;
    }

    return 1;
}

/* Publication runs through the same code for both protocols, but the two are
 * measured apart: docs/concurrency/01 accepts phase B on the h2 publish tag
 * specifically, and h1.1 — one request in flight — has nothing to contend with
 * there. Hence a runtime tag instead of a constant one. */
static metrics_lock_site_t __publish_site(connection_server_ctx_t* ctx) {
    return ctx->is_http2 ? LOCK_SITE_H2_PUBLISH : LOCK_SITE_HTTP_PUBLISH;
}

/* A handler (or the inline dispatch path) has finished filling a response. h1.1
 * has exactly one in flight and lets __write pick it up off the connection
 * context; h2 must tell the owning stream, since the write path serves whichever
 * streams are ready. */
int __handler_finished(connection_t* connection, httprequest_t* request, httpresponse_t* response) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (ctx->is_http2)
        return h2_server_response_ready(connection, response);

    (void)request;

    return connection_after_read(connection);
}

/* Publish a finished response. The two protocols need different locking:
 *
 *  - h1.1 keeps one request in flight, and connection_after_read must re-arm
 *    under connection_s_lock, so the caller's lock is taken here.
 *  - h2 pushes to the session's publish queue under the queue's own short lock
 *    and takes connection_s_lock itself only for the re-arm (the table walk runs
 *    later, in the worker's drain — docs/concurrency/01 §4.1). h2 must therefore
 *    be called WITHOUT the connection lock held: connection_s_lock is a
 *    non-recursive spinlock, and h2_server_response_ready acquires it.
 *
 * Wrapping the branch keeps every caller out of the business of knowing which
 * path locks. */
static void __publish_response(connection_t* connection, httprequest_t* request, httpresponse_t* response) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (ctx->is_http2) {
        __handler_finished(connection, request, response);
        return;
    }

    connection_s_lock(connection, __publish_site(ctx));
    __handler_finished(connection, request, response);
    connection_s_unlock(connection);
}

int http_server_dispatch(connection_t* connection, httprequest_t* request) {
    return __handle(connection, request, __post_response);
}

int __handle(connection_t* connection, httprequest_t* request, deferred_handler handler) {
    connection_server_ctx_t* conn_ctx = connection->ctx;
    httpresponse_t* response = conn_ctx->is_http2 ?
        httpresponse_create_h2(connection) : httpresponse_create(connection);
    if (response == NULL) return 0;

    /* Under h2 the response belongs to a stream, not to the connection: bind it
     * now so the write path and the write filter can reach it from the response
     * alone, and so it is freed with the stream. */
    if (conn_ctx->is_http2)
        h2_server_attach_response(connection, request, response);

    /* asterisk-form (RFC 9110 §9.3.7): "OPTIONS *" asks what the server as a
     * whole can do, not what one resource can do. There is nothing to route it
     * to and no file to serve, so this is the only place it can be answered —
     * ahead of the redirects, which are about resources too. The parsers let
     * "*" through for no other method (docs/http2/10, S.2). */
    if (request->asterisk_form) {
        response->status_code = 200;
        response->add_header(response, "Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS");
        /* An empty body, and no Content-Type to describe it: the response says
         * what the server accepts, it does not carry a representation. */
        response->send_datan(response, "", 0);
        response->remove_header(response, "Content-Type");

        return handler(request, response);
    }

    switch (__apply_redirect(request, response, handler)) {
    case -1:
        return 0;
    case 1:
        return 1;
    case 0:
    default:
        break;
    }

    if (__handler_added_to_queue(request, response))
        return 1;

    connection_server_ctx_t* ctx = connection->ctx;
    char file_full_path[PATH_MAX];
    const file_status_e file_status = http_get_file_full_path(ctx->server, file_full_path, PATH_MAX, request->path, request->path_length);

    if (file_status == FILE_OK) {
        if (!ratelimiter_allow(ctx->server->http.ratelimiter, connection->remote_ip, 1)) {
            httpresponse_default(response, 429);
            response->add_header(response, "Retry-After", "1");
        }
        else
            http_response_file(response, file_full_path);
    }
    else if (file_status == FILE_FORBIDDEN)
        httpresponse_default(response, 403);
    else
        httpresponse_default(response, 404);

    return handler(request, response);
}

int __handler_added_to_queue(httprequest_t* request, httpresponse_t* response) {
    connection_t* connection = request->connection;
    connection_server_ctx_t* ctx = connection->ctx;

    for (route_t* route = ctx->server->http.route; route; route = route->next) {
        ratelimiter_t* ratelimiter = __ratelimiter_find(&ctx->server->http, route);

        if (route->is_primitive && route_compare_primitive(route, request->path, request->path_length)) {
            if (route->static_file[request->method] != NULL) {
                if (!__prepare_static_file_response(ctx, response, route->static_file[request->method]))
                    return 0;

                return __deferred_handler(connection, request, response, __queue_response_handler, NULL, __queue_data_response_create, ratelimiter);
            }

            if (route->handler[request->method] == NULL) continue;

            return __deferred_handler(connection, request, response, __queue_request_handler, route->handler[request->method], __queue_data_request_create, ratelimiter);
        }

        int vector_size = route->params_count > 0 ? route->params_count * 6 : 20 * 6;
        int vector[vector_size];

        // find resource by template
        int matches_count = pcre_exec(route->location, NULL, request->path, request->path_length, 0, 0, vector, vector_size);

        if (matches_count > 1) {
            int i = 1; // escape full string match

            for (route_param_t* param = route->param; param; param = param->next, i++) {
                size_t substring_length = vector[i * 2 + 1] - vector[i * 2];

                query_t* query = query_create(param->string, param->string_len, &request->path[vector[i * 2]], substring_length);

                if (query == NULL || query->key == NULL || query->value == NULL) return 0;

                httpparser_append_query(request, query);
            }

            if (route->static_file[request->method] != NULL) {
                if (!__prepare_static_file_response(ctx, response, route->static_file[request->method]))
                    return 0;

                return __deferred_handler(connection, request, response, __queue_response_handler, NULL, __queue_data_response_create, ratelimiter);
            }

            if (route->handler[request->method] == NULL) continue;

            return __deferred_handler(connection, request, response,  __queue_request_handler, route->handler[request->method], __queue_data_request_create, ratelimiter);
        }
        else if (matches_count == 1) {
            if (route->static_file[request->method] != NULL) {
                if (!__prepare_static_file_response(ctx, response, route->static_file[request->method]))
                    return 0;

                return __deferred_handler(connection, request, response, __queue_response_handler, NULL, __queue_data_response_create, ratelimiter);
            }

            if (route->handler[request->method] == NULL) continue;

            return __deferred_handler(connection, request, response,  __queue_request_handler, route->handler[request->method], __queue_data_request_create, ratelimiter);
        }
    }

    return 0;
}

int __apply_redirect(httprequest_t* request, httpresponse_t* response, deferred_handler handler) {
    connection_t* connection = request->connection;
    
    switch (__get_redirect(connection, request)) {
    case REDIRECT_OUT_OF_MEMORY:
    {
        httpresponse_default(response, 500);
        return handler(request, response);
    }
    case REDIRECT_BAD_REQUEST:
    {
        httpresponse_default(response, 400);
        return handler(request, response);
    }
    case REDIRECT_LOOP_CYCLE:
    {
        httpresponse_default(response, 508);
        return handler(request, response);
    }
    case REDIRECT_FOUND:
    {
        httpresponse_redirect(response, request->uri, 301);
        return handler(request, response);
    }
    case REDIRECT_NOT_FOUND:
    default:
        break;
    }

    return 0;
}

int __get_redirect(connection_t* connection, httprequest_t* request) {
    int loop_cycle = 1;
    int find_new_location = 0;

    connection_server_ctx_t* ctx = connection->ctx;
    redirect_t* redirect = ctx->server->http.redirect;

    while (redirect) {
        if (loop_cycle >= 10) return REDIRECT_LOOP_CYCLE;

        int vector_size = (redirect->params_count + 1) * 3;
        int vector[vector_size];
        // pcre_exec leaves entries of non-participating capture groups untouched,
        // so pre-mark all offsets as "unset" for redirect_get_uri
        memset(vector, -1, sizeof(vector));
        int matches_count = pcre_exec(redirect->location, NULL, request->path, request->path_length, 0, 0, vector, vector_size);

        if (matches_count < 0) {
            redirect = redirect->next;
            continue;
        }

        find_new_location = 1;

        char* new_uri = redirect_get_uri(redirect, request->path, vector);
        if (new_uri == NULL) return REDIRECT_OUT_OF_MEMORY;

        if (request->uri) free((void*)request->uri);
        request->uri = NULL;

        if (request->path) free((void*)request->path);
        request->path = NULL;

        if (httpresponse_redirect_is_external(new_uri)) {
            request->uri = new_uri;
            connection->keepalive = 0;
            return REDIRECT_FOUND;
        }

        int uri_result = httpparser_set_uri(request, new_uri, strlen(new_uri));
        if (uri_result == HTTP1PARSER_OUT_OF_MEMORY) {
            request->uri = NULL;
            free(new_uri);
            return REDIRECT_OUT_OF_MEMORY;
        }
        if (uri_result != HTTP1PARSER_CONTINUE) {
            request->uri = NULL;
            free(new_uri);
            return REDIRECT_BAD_REQUEST;
        }

        redirect = ctx->server->http.redirect;

        loop_cycle++;
    }

    return find_new_location ? REDIRECT_FOUND : REDIRECT_NOT_FOUND;
}

void* __queue_data_request_create(connection_t* connection, httprequest_t* request, httpresponse_t* response, ratelimiter_t* ratelimiter) {
    connection_queue_http_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    data->base.free = __queue_data_request_free;
    data->request = request;
    data->connection = connection;
    data->response = response;
    data->ratelimiter = ratelimiter;
    data->server = ((connection_server_ctx_t*)connection->ctx)->server;

    return data;
}

void* __queue_data_response_create(connection_t* connection, httprequest_t* request, httpresponse_t* response, ratelimiter_t* ratelimiter) {
    connection_queue_http_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    data->base.free = __queue_data_response_free;
    data->request = request;
    data->connection = connection;
    data->response = response;
    data->ratelimiter = ratelimiter;
    data->server = ((connection_server_ctx_t*)connection->ctx)->server;

    return data;
}

void __queue_data_request_free(void* arg) {
    if (arg == NULL) return;

    connection_queue_http_data_t* data = arg;

    free(data);
}

void __queue_data_response_free(void* arg) {
    if (arg == NULL) return;

    connection_queue_http_data_t* data = arg;

    free(data);
}

void __queue_request_handler(void* arg) {
    if (arg == NULL) {
        log_error("__queue_request_handler: arg is NULL\n");
        return;
    }

    connection_queue_item_t* item = arg;
    if (item->data == NULL) {
        log_error("__queue_request_handler: item->data is NULL\n");
        return;
    }

    connection_queue_http_data_t* data = (connection_queue_http_data_t*)item->data;
    if (item->connection == NULL) {
        log_error("__queue_request_handler: item->connection is NULL\n");
        return;
    }

    connection_server_ctx_t* conn_ctx = item->connection->ctx;
    if (conn_ctx == NULL) {
        log_error("__queue_request_handler: conn_ctx is NULL\n");
        return;
    }

    /* The critical section is deliberately narrow (docs/concurrency/00 §5.1):
     * the lock guards connection state, not the user's handler. Between the two
     * short sections below, another worker may be running another handler of
     * this same connection — for h2 that is the point of the exercise; for h1.1
     * it cannot happen anyway, since only one item at a time is ever dispatched
     * (connection_queue_append, the serialized variant).
     *
     * h2 keeps request and response on the stream — several in flight would
     * clobber the single pair on the connection context — so for h2 there is
     * nothing to bind here. Taking the lock anyway left an empty lock/unlock
     * that was the single largest source of contention on the dispatch path
     * (~7400 waited acquisitions, ~10k sched_yield per 10k requests, guarding
     * nothing). Skip the acquisition on h2 (docs/concurrency/01 §6 A.4 п.3). */
    if (!conn_ctx->is_http2) {
        connection_s_lock(item->connection, LOCK_SITE_HTTP_DISPATCH);
        conn_ctx->request = data->request;
        conn_ctx->response = data->response;
        connection_s_unlock(item->connection);
    }

    if (!ratelimiter_allow(data->ratelimiter, item->connection->remote_ip, 1)) {
        if (data->response != NULL) {
            httpresponse_default(data->response, 429);
            data->response->add_header(data->response, "Retry-After", "1");
        }

        __publish_response(item->connection, data->request, data->response);
        return;
    }

    /* --- user code: middlewares and the route handler, no lock held --- */
    httpctx_t ctx;
    httpctx_init(&ctx, data->request, data->response);

    if (run_middlewares(data->server->http.middleware, &ctx))
        item->handle(&ctx);

    httpctx_clear(&ctx);

    /* Publishing: h2 pushes to the session queue and re-arms under its own
     * acquisition; h1.1 needs connection_s_lock for the re-arm. __publish_response
     * owns that difference (docs/concurrency/01 §4.1, phase B). */
    __publish_response(item->connection, data->request, data->response);
}

void __queue_response_handler(void* arg) {
    if (arg == NULL) {
        log_error("__queue_response_handler: arg is NULL\n");
        return;
    }

    connection_queue_item_t* item = arg;
    if (item->data == NULL || item->connection == NULL) {
        log_error("__queue_response_handler: item->data or item->connection is NULL\n");
        return;
    }

    connection_queue_http_data_t* data = (connection_queue_http_data_t*)item->data;
    connection_server_ctx_t* conn_ctx = item->connection->ctx;
    if (conn_ctx == NULL) {
        log_error("__queue_response_handler: conn_ctx is NULL\n");
        return;
    }

    /* No user code here — the response is already built (a static file, or a
     * handler that finished earlier). h1.1 binds request/response under the
     * lock; h2 keeps them on the stream. __publish_response owns the lock split
     * for the actual publish (h2 re-arms under its own acquisition, h1.1 under
     * the caller's) — the whole runner no longer stays under one lock. */
    if (!conn_ctx->is_http2) {
        connection_s_lock(item->connection, __publish_site(conn_ctx));
        conn_ctx->request = data->request;
        conn_ctx->response = data->response;
        connection_s_unlock(item->connection);
    }

    __publish_response(item->connection, data->request, data->response);
}

int __run_header_filters(httprequest_t* request, httpresponse_t* response) {
    if (response == NULL) {
        log_error("__run_header_filters: response is NULL\n");
        return CWF_ERROR;
    }

    if (response->headers_sended)
        return CWF_OK;

    if (response->filter == NULL) {
        log_error("__run_header_filters: response->filter is NULL\n");
        return CWF_ERROR;
    }

    response->event_again = 0;
    response->cur_filter = response->filter;

    while (1) {
        if (response->cur_filter == NULL) {
            log_error("__run_header_filters: cur_filter is NULL\n");
            return CWF_ERROR;
        }

        if (response->cur_filter->handler_header == NULL) {
            log_error("__run_header_filters: handler_header is NULL\n");
            return CWF_ERROR;
        }

        const int r = response->cur_filter->handler_header(request, response);
        switch (r)
        {
        case CWF_ERROR: /* close connection */
            return r;
        case CWF_EVENT_AGAIN:
            response->event_again = 1;
            return r;
        case CWF_OK:
            response->headers_sended = 1;
            return r;
        }
    }

    return CWF_OK;
}

int __run_body_filters(httprequest_t* request, httpresponse_t* response) {
    if (response == NULL) {
        log_error("__run_body_filters: response is NULL\n");
        return CWF_ERROR;
    }

    if (response->filter == NULL) {
        log_error("__run_body_filters: response->filter is NULL\n");
        return CWF_ERROR;
    }

    if (response->event_again)
        response->event_again = 0;

    while (1) {
        response->cur_filter = response->filter;

        if (response->cur_filter == NULL) {
            log_error("__run_body_filters: cur_filter is NULL\n");
            return CWF_ERROR;
        }

        if (response->cur_filter->handler_body == NULL) {
            log_error("__run_body_filters: handler_body is NULL\n");
            return CWF_ERROR;
        }

        int r = response->cur_filter->handler_body(request, response, NULL);
        switch (r)
        {
        case CWF_OK:
            return CWF_OK;
        case CWF_ERROR: /* close connection */
            return r;
        case CWF_EVENT_AGAIN:
            response->event_again = 1;
            return r;
        case CWF_DATA_AGAIN:
            continue;
        }
    }

    return CWF_OK;
}

int __handshake(connection_t* connection) {
    if (connection->ssl == NULL) {
        connection->ssl = SSL_new(connection->ssl_ctx);
        if (connection->ssl == NULL) {
            log_error(TLS_ERROR_ALLOC_SSL);
            goto epoll_ssl_error;
        }

        if (!SSL_set_fd(connection->ssl, connection->fd)) {
            log_error(TLS_ERROR_SET_SSL_FD);
            goto epoll_ssl_error;
        }

        SSL_set_app_data(connection->ssl, connection);

        SSL_set_accept_state(connection->ssl);
        SSL_set_shutdown(connection->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    }

    const int result = SSL_do_handshake(connection->ssl);
    if (result == 1) {
        /* Выбор протокола приложения по ALPN: h2 → HTTP/2-уровень (фаза 0 —
         * заглушка), иначе HTTP/1.1 как раньше. SNI уже отработал выше и
         * подменил ssl_ctx, так что ALPN-выбор корректен для выбранного vhost. */
        const unsigned char* alpn = NULL;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(connection->ssl, &alpn, &alpn_len);

        if (alpn != NULL && alpn_len == 2 && memcmp(alpn, "h2", 2) == 0) {
            /* RFC 9113 §9.2.2: HTTP/2 over a cipher suite from Appendix A is a
             * connection error of type INADEQUATE_SECURITY. Reachable only when
             * the operator has configured such a suite and a client picked it,
             * so the log line matters as much as the refusal — otherwise this
             * looks like the client's fault (docs/http2/08, phase F.3). */
            if (!openssl_cipher_ok_for_http2(connection->ssl)) {
                const SSL_CIPHER* cipher = SSL_get_current_cipher(connection->ssl);
                log_error("__handshake: HTTP/2 refused, cipher %s is forbidden by RFC 9113 "
                          "§9.2.2 (fd %d) — remove it from the vhost's \"ciphers\"\n",
                          cipher != NULL ? SSL_CIPHER_get_name(cipher) : "(unknown)",
                          connection->fd);

                /* The connection preface must lead, even when the next thing on
                 * it is a refusal: SETTINGS (empty) then GOAWAY(0x0c). Both
                 * frames are constant, so no session has to be built for them. */
                static const unsigned char refusal[] = {
                    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
                };
                openssl_write(connection->ssl, refusal, sizeof(refusal));

                return 0;
            }

            if (!h2_server_set_http2(connection))
                return 0;
        } else {
            if (!set_http(connection))
                return 0;
        }

        return 1;
    }

    switch (SSL_get_error(connection->ssl, result)) {
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
        epoll_ssl_error:

        if (errno > 0)
            log_error("__handshake: error %d, %d\n", connection->fd, errno);
        return 0;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        /* WANT_WRITE при хендшейке требует EPOLLOUT; возвращаем 1, чтобы
         * остаться в живых. Полная реарм-логика IN|OUT — вместе с h2-состоянием
         * соединения в фазе 4. */
        return 1;
    default:
        return 0;
    }

    return 1;
}

int __sni_callback(SSL* ssl, int* ad, void* arg) {
    (void)ad;
    (void)arg;

    connection_t* connection = SSL_get_app_data(ssl);
    const char* server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (server_name == NULL)
        return SSL_TLSEXT_ERR_NOACK;

    union tls_addr {
        struct in_addr ip4;
        struct in6_addr ip6;
    } addrbuf;

    // Per RFC 6066 section 3: ensure that name is not an IP literal.
    if (inet_pton(AF_INET, server_name, &addrbuf) == 1 ||
        inet_pton(AF_INET6, server_name, &addrbuf) == 1)
        return SSL_TLSEXT_ERR_NOACK;

    // Convert SNI to ASCII/Punycode
    char* ascii_server_name = idn_to_ascii(server_name);
    if (ascii_server_name == NULL) {
        log_warning("Invalid SNI domain: %s\n", server_name);
        return SSL_TLSEXT_ERR_NOACK;
    }

    size_t server_name_length = strlen(ascii_server_name);
    int vector_struct_size = 6;
    int substring_count = 20;
    int vector_size = substring_count * vector_struct_size;
    int vector[vector_size];

    connection_server_ctx_t* ctx = connection->ctx;
    connection_t* listener_connection = ctx->listener->connection;
    cqueue_item_t* item = cqueue_first(&ctx->listener->servers);

    while (item) {
        server_t* server = item->data;

        if (server->ip == listener_connection->ip && server->port == listener_connection->port) {
            for (domain_t* domain = server->domain; domain; domain = domain->next) {
                int matches_count = pcre_exec(domain->pcre_template, NULL, ascii_server_name, server_name_length, 0, 0, vector, vector_size);
                if (matches_count > 0) {
                    ctx->server = server;
                    connection->ssl_ctx = server->openssl->ctx;

                    SSL_set_SSL_CTX(ssl, server->openssl->ctx);

    #if OPENSSL_VERSION_NUMBER >= 0x009080dfL
                    /* only in 0.9.8m+ */
                    SSL_clear_options(ssl, SSL_get_options(ssl) & ~SSL_CTX_get_options(server->openssl->ctx));
    #endif

                    SSL_set_options(ssl, SSL_CTX_get_options(server->openssl->ctx));

    #ifdef SSL_OP_NO_RENEGOTIATION
                    SSL_set_options(ssl, SSL_OP_NO_RENEGOTIATION);
    #endif

                    free(ascii_server_name);
                    return SSL_TLSEXT_ERR_OK;
                }
            }
        }

        item = item->next;
    }

    free(ascii_server_name);
    return SSL_TLSEXT_ERR_NOACK;
}

int __post_response_default(connection_t* connection, int status_code) {
    connection_server_ctx_t* conn_ctx = connection->ctx;
    httpresponse_t* response = conn_ctx->is_http2 ?
        httpresponse_create_h2(connection) : httpresponse_create(connection);
    if (response == NULL) return 0;

    httpresponse_default(response, status_code);

    return __post_response(NULL, response);
}

int __post_response(httprequest_t* request, httpresponse_t* response) {
    if (response == NULL) {
        log_error("__post_response: response is NULL\n");
        return 0;
    }

    connection_t* connection = response->connection;
    if (connection == NULL) {
        log_error("__post_response: connection is NULL\n");
        return 0;
    }

    connection_server_ctx_t* ctx = connection->ctx;
    if (ctx == NULL) {
        log_error("__post_response: ctx is NULL\n");
        return 0;
    }

    /* h2 responses are per-stream and may complete in any order, so there is no
     * queue to wait behind. This is the inline path — the worker produced the
     * response itself on the read path (h2_dispatch fallback for 404/static/
     * redirect), so it already holds connection_s_lock; publish straight to the
     * stream and let h2_drain_and_rearm re-arm. The queued-handler path uses
     * h2_server_response_ready via __publish_response instead. */
    if (ctx->is_http2)
        return h2_server_publish_inline(connection, response);

    cqueue_lock(ctx->queue);
    const int queue_empty = cqueue_empty(ctx->queue);
    cqueue_unlock(ctx->queue);

    if (queue_empty) {
        ctx->request = request;
        ctx->response = response;
        atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
        return connection_after_read(connection);
    }

    return __deferred_handler(connection, request, response, __queue_response_handler, NULL, __queue_data_response_create, NULL);
}

int __post_deffered_response(httprequest_t* request, httpresponse_t* response) {
    if (response == NULL) {
        log_error("__post_deffered_response: response is NULL\n");
        return 0;
    }

    connection_t* connection = response->connection;
    if (connection == NULL) {
        log_error("__post_deffered_response: connection is NULL\n");
        return 0;
    }

    return __deferred_handler(connection, request, response, __queue_response_handler, NULL, __queue_data_response_create, NULL);
}

ratelimiter_t* __ratelimiter_find(server_http_t* http_config, route_t* route) {
    if (route->ratelimiter != NULL) return route->ratelimiter;

    return http_config->ratelimiter;
}

int __prepare_static_file_response(connection_server_ctx_t* ctx, httpresponse_t* response, const char* static_file_path) {
    char file_full_path[PATH_MAX];
    size_t pos = 0;
    size_t static_file_len = strlen(static_file_path);

    if (!data_appendn(file_full_path, &pos, PATH_MAX, ctx->server->root, ctx->server->root_length))
        return 0;
    if (ctx->server->root[ctx->server->root_length - 1] != '/') {
        if (!data_appendn(file_full_path, &pos, PATH_MAX, "/", 1))
            return 0;
    }
    if (static_file_path[0] == '/') {
        if (!data_appendn(file_full_path, &pos, PATH_MAX, static_file_path + 1, static_file_len - 1))
            return 0;
    }
    else {
        if (!data_appendn(file_full_path, &pos, PATH_MAX, static_file_path, static_file_len))
            return 0;
    }

    file_full_path[pos] = '\0';

    http_response_file(response, file_full_path);

    return 1;
}

void http_server_init_sni_callbacks(server_t* servers) {
    for (server_t* server = servers; server; server = server->next)
        if (server->openssl != NULL)
            openssl_set_sni_callback(server->openssl, __sni_callback);
}

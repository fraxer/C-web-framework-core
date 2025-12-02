#include "httpserverhandlers.h"

#include "httpcontext.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "httprequestparser.h"
#include "log.h"
#include "connection_queue.h"
#include "openssl.h"

typedef struct {
    connection_queue_item_data_t base;
    httprequest_t* request;
    httpresponse_t* response;
    connection_t* connection;
    ratelimiter_t* ratelimiter;
} connection_queue_http_data_t;

struct middleware_item;

typedef int(*deferred_handler)(httpresponse_t* response);
typedef void(*queue_handler)(void*);
typedef void*(*queue_data_create)(connection_t* connection, httprequest_t* request, httpresponse_t* response, ratelimiter_t* ratelimiter);

int run_middlewares(struct middleware_item* middleware_item, void* ctx);

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
static int __run_header_filters(httpresponse_t* response);
static int __run_body_filters(httpresponse_t* response);
static int __handshake(connection_t* connection);
static int __sni_callback(SSL* ssl, int* ad, void* arg);
static void* __queue_data_response_create(connection_t* connection, httprequest_t* request, httpresponse_t* response, ratelimiter_t* ratelimiter);
static void __queue_data_response_free(void* arg);
static int __post_reponse_default(connection_t* connection, int status_code);
static int __post_response(httpresponse_t* response);
static int __post_deffered_response(httpresponse_t* response);
static void __move_headers(httprequest_t* request, httpresponse_t* response);
static ratelimiter_t* __ratelimiter_find(server_http_t* http_config, route_t* route);

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
        httpparser_free(ctx->parser);
        ctx->parser = NULL;
    }

    ctx->parser = httpparser_create(connection);
    if (ctx->parser == NULL)
        return 0;

    return 1;
}

int http_server_guard_read(connection_t* connection) {
    connection_s_lock(connection);
    const int r = __read(connection);
    connection_s_unlock(connection);

    return r;
}

int http_server_guard_write(connection_t* connection) {
    if (connection == NULL) {
        log_error("http_server_guard_write: connection is NULL\n");
        return 0;
    }

    connection_s_lock(connection);
    const int r = __write(connection);
    connection_s_unlock(connection);

    return r;
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

    while (1) {
        int bytes_readed = 0;
        read_data:

        bytes_readed = connection_data_read(connection);

        switch (bytes_readed) {
        case -1:
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1;

            return 0;
        }
        case 0:
            return 0;
        default:
        {
            httpparser_set_bytes_readed(parser, bytes_readed);
            parser->pos_start = 0;
            parser->pos = 0;

            while (1) {
                switch (httpparser_run(parser)) {
                case HTTP1PARSER_ERROR:
                case HTTP1PARSER_OUT_OF_MEMORY:
                    return 0;
                case HTTP1PARSER_PAYLOAD_LARGE:
                    return __post_reponse_default(connection, 413);
                case HTTP1PARSER_BAD_REQUEST:
                    return __post_reponse_default(connection, 400);
                case HTTP1PARSER_HOST_NOT_FOUND:
                    return __post_reponse_default(connection, 404);
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

    int r = __run_header_filters(response);
    if (r == CWF_EVENT_AGAIN)
        return 1;
    if (r == CWF_ERROR)
        return 0;

    r = __run_body_filters(response);
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
    const int queue_empty = cqueue_empty(ctx->queue);
    cqueue_append(ctx->queue, item);

    if (!queue_empty)
        return 1;

    if (!connection_queue_append(item)) {
        item->free(item);
        return 0;
    }

    return 1;
}

int __handle(connection_t* connection, httprequest_t* request, deferred_handler handler) {
    httpresponse_t* response = httpresponse_create(connection);
    if (response == NULL) return 0;

    __move_headers(request, response);

    switch (__apply_redirect(request, response, handler)) {
    case -1:
    {
        httprequest_free(request);
        return 0;
    }
    case 1:
    {
        httprequest_free(request);
        return 1;
    }
    case 0:
    default:
        break;
    }

    if (__handler_added_to_queue(request, response))
        return 1;

    connection_server_ctx_t* ctx = connection->ctx;
    char file_full_path[PATH_MAX];
    const file_status_e file_status = http_get_file_full_path(ctx->server, file_full_path, PATH_MAX, request->path, request->path_length);
    httprequest_free(request);

    if (file_status == FILE_OK) {
        if (!ratelimiter_allow(ctx->server->http.ratelimiter, connection->ip, 1)) {
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

    return handler(response);
}

int __handler_added_to_queue(httprequest_t* request, httpresponse_t* response) {
    connection_t* connection = request->connection;
    connection_server_ctx_t* ctx = connection->ctx;

    for (route_t* route = ctx->server->http.route; route; route = route->next) {
        ratelimiter_t* ratelimiter = __ratelimiter_find(&ctx->server->http, route);

        if (route->is_primitive && route_compare_primitive(route, request->path, request->path_length)) {
            if (route->handler[request->method] == NULL) return 0;

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

            if (route->handler[request->method] == NULL) return 0;

            return __deferred_handler(connection, request, response,  __queue_request_handler, route->handler[request->method], __queue_data_request_create, ratelimiter);
        }
        else if (matches_count == 1) {
            if (route->handler[request->method] == NULL) return 0;

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
        return handler(response);
    }
    case REDIRECT_LOOP_CYCLE:
    {
        httpresponse_default(response, 508);
        return handler(response);
    }
    case REDIRECT_FOUND:
    {
        httpresponse_redirect(response, request->uri, 301);
        return handler(response);
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

        int vector_size = redirect->params_count * 6;
        int vector[vector_size];
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

        if (!httpparser_set_uri(request, new_uri, strlen(new_uri)))
            return REDIRECT_OUT_OF_MEMORY;

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

    return data;
}

void* __queue_data_response_create(connection_t* connection, httprequest_t* request, httpresponse_t* response, ratelimiter_t* ratelimiter) {
    (void)ratelimiter;

    connection_queue_http_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    data->base.free = __queue_data_response_free;
    data->request = request;
    data->connection = connection;
    data->response = response;
    data->ratelimiter = NULL;

    return data;
}

void __queue_data_request_free(void* arg) {
    if (arg == NULL) return;

    connection_queue_http_data_t* data = arg;

    if (data->request != NULL)
        httprequest_free(data->request);

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

    conn_ctx->response = data->response;

    if (!ratelimiter_allow(data->ratelimiter, item->connection->ip, 1)) {
        httpresponse_t* response = conn_ctx->response;
        if (response != NULL) {
            httpresponse_default(response, 429);
            response->add_header(response, "Retry-After", "1");
        }
        connection_after_read(item->connection);
        return;
    }

    httpctx_t ctx;
    httpctx_init(&ctx, data->request, conn_ctx->response);

    if (run_middlewares(conn_ctx->server->http.middleware, &ctx))
        item->handle(&ctx);

    httpctx_clear(&ctx);

    connection_after_read(item->connection);
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

    conn_ctx->response = data->response;

    connection_after_read(item->connection);
}

int __run_header_filters(httpresponse_t* response) {
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

        const int r = response->cur_filter->handler_header(response);
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

int __run_body_filters(httpresponse_t* response) {
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

        int r = response->cur_filter->handler_body(response, NULL);
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
        if (!set_http(connection))
            return 0;

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

    size_t server_name_length = strlen(server_name);
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
                int matches_count = pcre_exec(domain->pcre_template, NULL, server_name, server_name_length, 0, 0, vector, vector_size);
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

                    return SSL_TLSEXT_ERR_OK;
                }
            }
        }

        item = item->next;
    }

    return SSL_TLSEXT_ERR_NOACK;
}

int __post_reponse_default(connection_t* connection, int status_code) {
    httpresponse_t* response = httpresponse_create(connection);
    if (response == NULL) return 0;

    httpresponse_default(response, status_code);

    return __post_response(response);
}

int __post_response(httpresponse_t* response) {
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

    if (cqueue_empty(ctx->queue)) {
        ctx->response = response;
        ctx->need_write = 1;
        return connection_after_read(connection);
    }

    return __deferred_handler(connection, NULL, response, __queue_response_handler, NULL, __queue_data_response_create, NULL);
}

int __post_deffered_response(httpresponse_t* response) {
    if (response == NULL) {
        log_error("__post_deffered_response: response is NULL\n");
        return 0;
    }

    connection_t* connection = response->connection;
    if (connection == NULL) {
        log_error("__post_deffered_response: connection is NULL\n");
        return 0;
    }

    return __deferred_handler(connection, NULL, response, __queue_response_handler, NULL, __queue_data_response_create, NULL);
}

void __move_headers(httprequest_t* request, httpresponse_t* response) {
    response->ranges = request->ranges;
    request->ranges = NULL;
}

ratelimiter_t* __ratelimiter_find(server_http_t* http_config, route_t* route) {
    if (route->ratelimiter != NULL) return route->ratelimiter;

    return http_config->ratelimiter;
}

void http_server_init_sni_callbacks(server_t* servers) {
    for (server_t* server = servers; server; server = server->next)
        if (server->openssl != NULL)
            openssl_set_sni_callback(server->openssl, __sni_callback);
}

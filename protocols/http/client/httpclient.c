#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>

#include "log.h"
#include "httpclienthandlers.h"
#include "httpclientparser.h"
#include "httpclienthandlers_async.h"
#include "httpclient.h"
#include "connection_c_async.h"
#include "appconfig.h"
#include "server.h"
#include "multiplexing.h"

#define HTTPCLIENT_BUFSIZ 16384

httpclient_t* __httpclient_create();
int __httpclient_init_parser(httpclient_t*);
int __httpclient_connection_close(connection_t*);
void __httpclient_free(httpclient_t*);
void __httpclient_set_method(httpclient_t*, route_methods_e);
int __httpclient_set_url(httpclient_t*, const char*);
httpresponse_t* __httpclient_send(httpclient_t*);
int __httpclient_create_connection(httpclient_t*);
connection_t* __httpclient_resolve(const char*, const short);
int __httpclient_establish_connection(httpclient_t*);
int __httpclient_connect(httpclient_t*);
int __httpclient_set_socket_keepalive(int fd);
int __httpclient_set_socket_timeout(int fd, int);
int __httpclient_alloc_ssl(httpclient_t* client);
int __httpclient_handshake(httpclient_t*);
int __httpclient_set_request_uri(httpclient_t*);
int __httpclient_set_header_host(httpclient_t*);
int __httpclient_try_set_content_length(httpclient_t*);
int __httpclient_send_recv_data(httpclient_t*);
int __httpclient_free_connection(httpclient_t*);
int __httpclient_is_redirect(httpclient_t*);

// Async forward declarations
int __httpclient_send_async(httpclient_t*, httpclient_callback_t, void*, struct mpxapi*, struct appconfig*);
httpclient_async_ctx_t* __httpclient_async_ctx_create(httpclient_callback_t, void*, struct mpxapi*, struct appconfig*, int);
void __httpclient_async_ctx_free(httpclient_async_ctx_t*);
int __httpclient_async_check_self_invocation(httpclient_t*);
int __httpclient_self_invoke(httpclient_t*);
int __httpclient_async_start(httpclient_t*);
void __httpclient_async_complete(httpclient_t*, int);
uint64_t __get_current_time_ms(void);

// Async handlers (будут реализованы в httpclienthandlers_async.c)
int __httpclient_async_read(connection_t* connection);
int __httpclient_async_write(connection_t* connection);
int __httpclient_async_close(connection_t* connection);

httpclient_t* httpclient_init(route_methods_e method, const char* url, int timeout) {
    httpclient_t* result = NULL;
    httpclient_t* client = __httpclient_create();
    if (client == NULL) return NULL;

    if (!__httpclient_init_parser(client))
        goto failed;

    client->ssl_ctx = SSL_CTX_new(TLS_method());
    if (client->ssl_ctx == NULL) goto failed;

    if (timeout > 0)
        client->timeout = timeout;

    if (!client->set_url(client, url)) goto failed;

    client->request = httprequest_create(client->connection);
    if (client->request == NULL) goto failed;

    client->response = httpresponse_create(client->connection);
    if (client->response == NULL) goto failed;

    client->set_method(client, method);

    result = client;

    failed:

    if (result == NULL)
        client->free(client);

    return result;
}

httpclient_t* __httpclient_create() {
    httpclient_t* client = malloc(sizeof * client);
    if (client == NULL) return NULL;

    client->method = ROUTE_NONE;
    client->use_ssl = 0;
    client->redirect_count = 0;
    client->port = 0;
    client->timeout = 10;
    client->host = NULL;
    client->ssl_ctx = NULL;
    client->connection = NULL;
    client->request = NULL;
    client->response = NULL;
    client->parser = NULL;
    client->send = __httpclient_send;
    client->error = NULL;
    client->set_method = __httpclient_set_method;
    client->set_url = __httpclient_set_url;
    client->free = __httpclient_free;
    client->buffer_size = BUF_SIZE;
    client->buffer = malloc(sizeof(char) * client->buffer_size);
    if (client->buffer == NULL) {
        free(client);
        return NULL;
    }

    // Async поля
    client->async_ctx = NULL;
    client->send_async = __httpclient_send_async;

    return client;
}

int __httpclient_init_parser(httpclient_t* client) {
    client->parser = malloc(sizeof(httpclientparser_t));
    if (client->parser == NULL) return 0;

    httpclientparser_init(client->parser);

    return 1;
}

int __httpclient_connection_close(connection_t* connection) {
    if (connection->ssl != NULL) {
        SSL_shutdown(connection->ssl);
        SSL_clear(connection->ssl);
    }

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    return 0;
}

void __httpclient_free(httpclient_t* client) {
    if (client == NULL) return;

    httpclientparser_free(client->parser);

    if (client->request != NULL) {
        client->request->base.free(client->request);
        client->request = NULL;
    }

    if (client->response != NULL) {
        client->response->base.free(client->response);
        client->response = NULL;
    }

    if (client->ssl_ctx != NULL) {
        SSL_CTX_free(client->ssl_ctx);
        client->ssl_ctx = NULL;
    }

    if (client->host != NULL) {
        free(client->host);
        client->host = NULL;
    }

    if (client->buffer != NULL) {
        free(client->buffer);
        client->buffer = NULL;
    }

    free(client);
}

void __httpclient_set_method(httpclient_t* client, route_methods_e method) {
    client->method = method;
}

int __httpclient_set_url(httpclient_t* client, const char* url) {
    httpclientparser_reset(client->parser);

    client->parser->use_ssl = client->use_ssl;

    if (httpclientparser_parse(client->parser, url) != CLIENTPARSER_OK)
        return 0;

    client->use_ssl = httpclientparser_move_use_ssl(client->parser);

    if (client->parser->port > 0)
        client->port = httpclientparser_move_port(client->parser);

    if (client->parser->host)
        client->host = httpclientparser_move_host(client->parser);

    return 1;
}

httpresponse_t* __httpclient_send(httpclient_t* client) {
    int result = 0;

    client->redirect_count = 0;

    if (!__httpclient_try_set_content_length(client))
        goto failed;

    start:

    if (!__httpclient_set_header_host(client))
        goto failed;

    if (!__httpclient_create_connection(client))
        goto failed;

    if (!__httpclient_set_request_uri(client))
        goto failed;

    if (!__httpclient_send_recv_data(client))
        goto failed;

    if (!__httpclient_free_connection(client))
        goto failed;

    switch (__httpclient_is_redirect(client)) {
        case CLIENTREDIRECT_NONE: break;
        case CLIENTREDIRECT_EXIST: {
            http_header_t* header = client->response->get_header(client->response, "Location");
            if (!(header && header->value_length > 0) || !client->set_url(client, header->value))
                goto failed;

            client->redirect_count++;
            client->response->base.reset(client->response);
            goto start;
        }
        case CLIENTREDIRECT_ERROR: goto failed;
    }

    result = 1;

    failed:

    if (client->connection != NULL)
        __httpclient_free_connection(client);

    if (!result) {
        client->response->status_code = 500;
    }

    return client->response;
}

int __httpclient_create_connection(httpclient_t* client) {
    connection_t* connection = __httpclient_resolve(client->host, client->port);
    if (connection == NULL)
        return 0;

    client->connection = connection;
    client->connection->buffer = client->buffer;
    client->connection->buffer_size = client->buffer_size;
    client->request->connection = connection;
    client->response->connection = connection;

    connection_client_ctx_t* ctx = connection->ctx;

    connection->ssl_ctx = client->ssl_ctx;
    connection->close = __httpclient_connection_close;
    ctx->request = (request_t*)client->request;
    ctx->response = (response_t*)client->response;

    // if (!__httpclient_establish_connection(client)) {
    //     log_error("error establish connection\n");
    //     return 0;
    // }

    return 1;
}

connection_t* __httpclient_resolve(const char* host, const short port) {
    if (host == NULL) {
        log_error("__httpclient_resolve: host is NULL\n");
        return NULL;
    }
    struct addrinfo addr;
    memset(&addr, 0, sizeof(struct addrinfo));
    addr.ai_family = AF_INET;
    addr.ai_socktype = SOCK_STREAM;
    addr.ai_flags = 0;
    addr.ai_protocol = IPPROTO_TCP;

    char port_string[7] = {0};
    sprintf(port_string, "%d", port);

    struct addrinfo* result = NULL;
    const int r = getaddrinfo(host, port_string, &addr, &result);
    if (r != 0) {
        log_error("__httpclient_resolve: http client can't resolve host: %s\n", gai_strerror(r));
        return NULL;
    }

    int fd = -1;
    struct addrinfo* rp = NULL;
    connection_t* connection = NULL;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd >= 0) {
            const in_addr_t ip = ((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr;
            connection = connection_c_create(fd, ip, port);
            if (connection == NULL) {
                close(fd);
                fd = -1;
            }
            else break;
        }
    }

    freeaddrinfo(result);

    if (connection == NULL)
        if (fd > 0)
            close(fd);

    return connection;
}

int __httpclient_establish_connection(httpclient_t* client) {
    if (!__httpclient_set_socket_timeout(client->connection->fd, client->timeout))
        return 0;

    // if (!__httpclient_set_socket_keepalive(client->connection->fd))
    //     return 0;

    if (!__httpclient_connect(client))
        return 0;

    if (client->use_ssl) {
        if (!__httpclient_alloc_ssl(client))
            return 0;

        if (!__httpclient_handshake(client))
            return 0;
    }
    else
        set_client_http(client->connection);

    return 1;
}

int __httpclient_connect(httpclient_t* client) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET; 
    addr.sin_port = htons(client->connection->port); 
    addr.sin_addr.s_addr = client->connection->ip;

    if (connect(client->connection->fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_error("connect error %d %d\n", client->connection->fd, errno);
        return 0;
    }

    return 1;
}

int __httpclient_set_socket_keepalive(int fd) {
    int kenable = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &kenable, sizeof(kenable));

    int keepcnt = 15;
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    int keepidle = 5;
    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));

    int keepintvl = 5;
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));

    return 1;
}

int __httpclient_set_socket_timeout(int fd, int timeout) {
    struct timeval tm;      
    tm.tv_sec = timeout;
    tm.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tm, sizeof(tm)) < 0)
        return 0;

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tm, sizeof(tm)) < 0)
        return 0;
    
    return 1;
}

int __httpclient_alloc_ssl(httpclient_t* client) {
    connection_t* connection = client->connection;

    if (connection->ssl != NULL) return 1;

    int result = 0;

    connection->ssl = SSL_new(connection->ssl_ctx);
    if (connection->ssl == NULL)
        goto failed;

    if (!SSL_set_fd(connection->ssl, connection->fd))
        goto failed;

    SSL_set_connect_state(connection->ssl);
    SSL_set_post_handshake_auth(connection->ssl, 1);
    SSL_set_tlsext_host_name(connection->ssl, client->host);

    result = 1;

    failed:

    if (result == 0) {
        if (connection->ssl) {
            SSL_free(connection->ssl);
            connection->ssl = NULL;
        }
    }

    return result;
}

int __httpclient_handshake(httpclient_t* client) {
    set_client_tls(client->connection);
    client->connection->write(client->connection);

    connection_client_ctx_t* ctx = client->connection->ctx;
    if (ctx->request == NULL || client->connection->fd == 0)
        return 0;

    return 1;
}

int __httpclient_set_request_uri(httpclient_t* client) {
    httprequest_t* request = (httprequest_t*)client->request;

    if (request->uri) free((void*)request->uri);
    request->uri = httpclientparser_move_uri(client->parser);
    request->uri_length = strlen(request->uri);

    if (request->path) free((void*)request->path);
    request->path = httpclientparser_move_path(client->parser);
    request->path_length = strlen(request->path);

    queries_free(request->query_);
    request->query_ = httpclientparser_move_query(client->parser);
    request->last_query = httpclientparser_move_last_query(client->parser);
    request->method = client->method;

    return 1;
}

int __httpclient_set_header_host(httpclient_t* client) {
    httprequest_t* request = (httprequest_t*)client->request;
    request->remove_header(request, "Host");

    char host[128];
    if (client->port == 80 || client->port == 443)
        snprintf(host, sizeof(host), "%s", client->host);
    else
        snprintf(host, sizeof(host), "%s:%d", client->host, client->port);

    request->add_header(request, "Host", host);

    return 1;
}

int __httpclient_try_set_content_length(httpclient_t* client) {
    if (client->request->transfer_encoding == TE_CHUNKED)
        return 1;

    client->request->remove_header(client->request, "Content-Length");
    const size_t file_size = client->request->payload_.file.size;

    if (file_size == 0 && client->request->transfer_encoding != TE_CHUNKED) {
        client->request->add_header(client->request, "Content-Length", "0");
        return 1;
    }

    char content_string[32];
    sprintf(content_string, "%ld", file_size);

    client->request->add_header(client->request, "Content-Length", content_string);

    return 1;
}

int __httpclient_send_recv_data(httpclient_t* client) {
    client->connection->write(client->connection);
    client->connection->read(client->connection);

    return 1;
}

int __httpclient_free_connection(httpclient_t* client) {
    connection_t* connection = client->connection;
    if (connection == NULL) return 1;

    // Для async соединений ctx имеет другую структуру
    if (connection->type == CONNECTION_TYPE_CLIENT_ASYNC) {
        // Для async клиента просто закрываем и освобождаем
        connection->close(connection);
        connection_free(connection);
    } else {
        // Для обычного синхронного клиента
        connection_client_ctx_t* ctx = connection->ctx;
        ctx->request = NULL;
        ctx->response = NULL;
        connection->close(connection);
        connection_free(connection);
    }

    client->connection = NULL;

    return 1;
}

int __httpclient_is_redirect(httpclient_t* client) {
    if (client->response->status_code != 301 && client->response->status_code != 302)
        return CLIENTREDIRECT_NONE;

    if (client->redirect_count > 9)
        return CLIENTREDIRECT_MANY_REDIRECTS;

    http_header_t* header = client->response->get_header(client->response, "Location");
    if (!(header && header->value_length > 0))
        return CLIENTREDIRECT_ERROR;

    return CLIENTREDIRECT_EXIST;
}

// ============================================================================
// ASYNC HTTP CLIENT IMPLEMENTATION
// ============================================================================

// Helper: получить текущее время в миллисекундах
uint64_t __get_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Создание async контекста
httpclient_async_ctx_t* __httpclient_async_ctx_create(
    httpclient_callback_t callback,
    void* userdata,
    struct mpxapi* api,
    struct appconfig* appconfig,
    int timeout) {

    httpclient_async_ctx_t* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->callback = callback;
    ctx->userdata = userdata;
    ctx->api = api;
    ctx->appconfig = appconfig;
    ctx->state = ASYNC_STATE_INIT;
    ctx->timeout_ms = timeout * 1000;  // секунды -> миллисекунды
    ctx->start_time_ms = 0;

    ctx->write_buffer = malloc(16384);
    if (!ctx->write_buffer) {
        free(ctx);
        return NULL;
    }
    ctx->write_buffer_size = 16384;
    ctx->write_buffer_pos = 0;

    ctx->registered_in_epoll = 0;
    ctx->write_completed = 0;
    ctx->read_completed = 0;
    ctx->is_self_invocation = 0;

    return ctx;
}

// Освобождение async контекста
void __httpclient_async_ctx_free(httpclient_async_ctx_t* ctx) {
    if (!ctx) return;
    if (ctx->write_buffer) free(ctx->write_buffer);
    free(ctx);
}

// Проверка self-invocation
int __httpclient_async_check_self_invocation(httpclient_t* client) {
    httpclient_async_ctx_t* ctx = client->async_ctx;
    struct appconfig* appconfig = ctx->appconfig;

    // Проверить localhost или 127.0.0.1
    int is_localhost = 0;
    if (strcmp(client->host, "localhost") == 0 ||
        strcmp(client->host, "127.0.0.1") == 0) {
        is_localhost = 1;
    }

    if (!is_localhost) {
        return 0;  // Не self-invocation
    }

    // Проверить порт против серверов
    server_chain_t* chain = appconfig->server_chain;
    if (!chain) return 0;

    pthread_mutex_lock(&chain->mutex);

    server_t* server = chain->server;
    while (server) {
        if (server->port == client->port) {
            pthread_mutex_unlock(&chain->mutex);
            return 1;  // Self-invocation обнаружен!
        }
        server = server->next;
    }

    pthread_mutex_unlock(&chain->mutex);
    return 0;
}

// Self-invocation: упрощенная версия - просто возвращаем ошибку
// TODO: Полная реализация с прямым вызовом route handler
int __httpclient_self_invoke(httpclient_t* client) {
    log_info("Self-invocation detected for %s:%d, but direct handler invocation not implemented yet\n",
             client->host, client->port);

    // Пока просто вызываем callback с ошибкой
    // В будущем здесь будет поиск route и прямой вызов handler
    client->response->status_code = 501;  // Not Implemented
    __httpclient_async_complete(client, 0);
    return 1;
}

// Завершение async операции
void __httpclient_async_complete(httpclient_t* client, int success) {
    httpclient_async_ctx_t* ctx = client->async_ctx;
    if (!ctx) return;

    // Удалить из epoll если зарегистрирован
    if (ctx->registered_in_epoll && client->connection) {
        ctx->api->control_del(client->connection);
        ctx->registered_in_epoll = 0;
    }

    // Закрыть соединение
    if (client->connection) {
        __httpclient_free_connection(client);
    }

    // Установить status_code при ошибке
    if (!success && client->response->status_code == 0) {
        client->response->status_code = 500;
    }

    // Вызвать callback
    if (ctx->callback) {
        ctx->callback(client->response, ctx->userdata);
    }

    // Освободить async_ctx
    __httpclient_async_ctx_free(ctx);
    client->async_ctx = NULL;
}

// Освобождение async connection context
static void __httpclient_async_connection_ctx_free(void* arg) {
    connection_client_async_ctx_t* ctx = arg;
    free(ctx);
}

// Запуск async операции
int __httpclient_async_start(httpclient_t* client) {
    httpclient_async_ctx_t* ctx = client->async_ctx;

    // Self-invocation обработка
    if (ctx->is_self_invocation) {
        return __httpclient_self_invoke(client);
    }

    // Создать соединение (DNS resolve пока синхронный - TODO: async DNS)
    if (!__httpclient_create_connection(client)) {
        log_error("Async: failed to create connection\n");
        __httpclient_async_complete(client, 0);
        return 0;
    }

    if (!__httpclient_set_request_uri(client)) {
        log_error("Async: failed to set request URI\n");
        __httpclient_async_complete(client, 0);
        return 0;
    }

    // Установить socket в non-blocking режим
    int flags = fcntl(client->connection->fd, F_GETFL, 0);
    if (flags == -1 || fcntl(client->connection->fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_error("Async: failed to set non-blocking mode\n");
        __httpclient_async_complete(client, 0);
        return 0;
    }

    // Создать async connection context
    connection_client_async_ctx_t* conn_ctx = malloc(sizeof(*conn_ctx));
    if (!conn_ctx) {
        log_error("Async: failed to allocate connection context\n");
        __httpclient_async_complete(client, 0);
        return 0;
    }

    conn_ctx->base.reset = NULL;
    conn_ctx->base.free = __httpclient_async_connection_ctx_free;
    conn_ctx->api = ctx->api;
    conn_ctx->client = client;
    conn_ctx->destroyed = 0;
    conn_ctx->registered = 0;

    // Заменить ctx в connection (освободить старый client ctx)
    connection_client_ctx_t* old_ctx = client->connection->ctx;
    if (old_ctx && old_ctx->base.free) {
        old_ctx->base.free(old_ctx);
    }

    client->connection->ctx = conn_ctx;
    client->connection->type = CONNECTION_TYPE_CLIENT_ASYNC;

    // Установить async handlers
    client->connection->read = __httpclient_async_read;
    client->connection->write = __httpclient_async_write;
    client->connection->close = __httpclient_async_close;

    // Non-blocking connect
    ctx->state = ASYNC_STATE_CONNECTING;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(client->connection->port);
    addr.sin_addr.s_addr = client->connection->ip;

    int result = connect(client->connection->fd, (struct sockaddr*)&addr, sizeof(addr));
    int e = errno;
    if (result == -1 && errno != EINPROGRESS) {
        log_error("Async connect error: %d\n", errno);
        __httpclient_async_complete(client, 0);
        return 0;
    }

    // Добавить в epoll (ждем EPOLLOUT для завершения connect)
    if (!ctx->api->control_add(client->connection, MPXOUT | MPXRDHUP)) {
        log_error("Async: failed to add to epoll\n");
        __httpclient_async_complete(client, 0);
        return 0;
    }

    ctx->registered_in_epoll = 1;
    ctx->start_time_ms = __get_current_time_ms();
    conn_ctx->registered = 1;

    return 1;  // Success: запрос в процессе
}

// Главная async функция
int __httpclient_send_async(
    httpclient_t* client,
    httpclient_callback_t callback,
    void* userdata,
    struct mpxapi* api,
    struct appconfig* appconfig) {

    if (!client || !callback || !api || !appconfig) {
        log_error("Async: invalid parameters\n");
        return 0;
    }

    // Создать async контекст
    client->async_ctx = __httpclient_async_ctx_create(
        callback, userdata, api, appconfig, client->timeout);

    if (!client->async_ctx) {
        log_error("Async: failed to create async context\n");
        return 0;
    }

    // Проверить self-invocation
    if (__httpclient_async_check_self_invocation(client)) {
        client->async_ctx->is_self_invocation = 1;
        log_info("Async: self-invocation detected\n");
    }

    // Подготовить request
    if (!__httpclient_try_set_content_length(client)) {
        log_error("Async: failed to set content length\n");
        __httpclient_async_ctx_free(client->async_ctx);
        client->async_ctx = NULL;
        return 0;
    }

    if (!__httpclient_set_header_host(client)) {
        log_error("Async: failed to set host header\n");
        __httpclient_async_ctx_free(client->async_ctx);
        client->async_ctx = NULL;
        return 0;
    }

    // Запустить async операцию
    return __httpclient_async_start(client);
}

#include "log.h"
#include "socket.h"
#include "broadcast.h"
#include "multiplexing.h"
#include "multiplexingserver.h"
#include "server.h"
#include "httpserverhandlers.h"
#include "h2session.h"

static int BUFFER_SIZE = 16384;

static listener_t* __listeners_create(mpxapi_t* api, char* buffer, server_t* server);
static listener_t* __listener_create(mpxapi_t* api, char* buffer, server_t* server);
static listener_t* __listener_get(listener_t* listener, server_t* server);
static void __listeners_free(listener_t* listener);
static void __listener_free(listener_t* listener);
static int __listeners_listen(listener_t* listener);
static void __listeners_unlisten(listener_t* listener);
static void __listener_unlisten(listener_t* listener);
static int __listener_read(connection_t* listener_connection);
static void __set_protocol(connection_t* connection);
static void __mpx_on_tick(mpxapi_t* api);

int mpxserver_run(appconfig_t* appconfig) {
    int result = 0;
    mpxapi_t* api = mpx_create();
    if (api == NULL) return result;

    listener_t* listeners = NULL;
    char* buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) goto failed;

    listeners = __listeners_create(api, buffer, appconfig->server_chain->server);
    if (listeners == NULL)
        goto failed;

    /* Wire the worker timer sweep (idle/PING timeouts, graceful shutdown). */
    api->on_tick = __mpx_on_tick;

    if (!__listeners_listen(listeners))
        goto failed;

    while (1) {
        api->process_events(appconfig, api);

        if (atomic_load(&appconfig->shutdown)) {
            if (appconfig->env.main.reload != APPCONFIG_RELOAD_HARD)
                __listeners_unlisten(listeners);

            if (atomic_load(&api->connection_count) == 0)
                break;
        }
    }

    result = 1;

    failed:

    __listeners_free(listeners);

    if (buffer != NULL)
        free(buffer);

    api->free(api);

    return result;
}

int __listener_connection_close(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    listener_t* listener = ctx->listener;

    connection_s_lock(connection);

    // Отсоединяем соединение от listener до освобождения: цикл может закрыть
    // listener-сокет напрямую (config_shutdown/ошибка сокета), и без отсоединения
    // указатель listener->connection стал бы висячим к моменту __listener_free.
    if (listener != NULL && listener->connection == connection)
        listener->connection = NULL;

    if (!ctx->listener->api->control_del(connection))
        log_error("Connection not removed from api\n");

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    atomic_store(&ctx->destroyed, 1);

    if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_s_unlock(connection);

    return 1;
}

listener_t* __listeners_create(mpxapi_t* api, char* buffer, server_t* first_server) {
    listener_t* listeners = NULL;
    listener_t* last_listener = NULL;
    int result = 0;
    for (server_t* server = first_server; server; server = server->next) {
        listener_t* l = __listener_get(listeners, server);
        if (l != NULL) {
            cqueue_append(&l->servers, server);
            continue;
        }

        listener_t* listener = __listener_create(api, buffer, server);
        if (listener == NULL) goto failed;

        if (listeners == NULL)
            listeners = listener;

        if (last_listener != NULL)
            last_listener->next = listener;

        last_listener = listener;
    }

    result = 1;

    failed:

    if (!result) {
        __listeners_free(listeners);
        listeners = NULL;
    }

    return listeners;
}

listener_t* __listener_create(mpxapi_t* api, char* buffer, server_t* server) {
    listener_t* listener = malloc(sizeof * listener);
    if (listener == NULL) return NULL;

    memset(listener, 0, sizeof * listener);

    int result = 0;
    connection_t* connection = NULL;

    const int socketfd = socket_listen_create(server->ip, server->port);
    if (socketfd == -1) goto failed;

    connection = connection_s_alloc(listener, socketfd, server->ip, server->port, server->ip, server->port, buffer, BUFFER_SIZE);
    if (connection == NULL) goto failed;

    connection->read = __listener_read;
    connection->write = NULL;
    connection->close = __listener_connection_close;

    listener->connection = connection;
    listener->api = api;
    listener->next = NULL;
    cqueue_init(&listener->servers);

    if (!cqueue_append(&listener->servers, server))
        goto failed;

    result = 1;

    failed:

    if (!result) {
        __listener_free(listener);
        listener = NULL;
    }

    return listener;
}

listener_t* __listener_get(listener_t* listener, server_t* server) {
    while (listener) {
        if (listener->connection->ip == server->ip && listener->connection->port == server->port)
            return listener;

        listener = listener->next;
    }

    return NULL;
}

void __listeners_free(listener_t* listener) {
    while (listener) {
        listener_t* next = listener->next;
        __listener_free(listener);
        listener = next;
    }
}

void __listener_free(listener_t* listener) {
    if (listener == NULL) return;

    // На путях ошибок соединение могло быть не закрыто циклом — освобождаем здесь.
    // Если уже закрыто (циклом или __listener_unlisten), listener->connection == NULL
    // благодаря отсоединению в __listener_connection_close.
    if (listener->connection != NULL) {
        listener->connection->close(listener->connection);
        listener->connection = NULL;
    }

    cqueue_clear(&listener->servers);
    free(listener);
}

int __listeners_listen(listener_t* listener) {
    while (listener) {
        if (!listener->api->control_add(listener->connection, MPXIN | MPXRDHUP))
            return 0;

        listener = listener->next;
    }

    return 1;
}

void __listeners_unlisten(listener_t* listener) {
    while (listener) {
        __listener_unlisten(listener);
        listener = listener->next;
    }
}

void __listener_unlisten(listener_t* listener) {
    if (listener == NULL || listener->connection == NULL)
        return;

    listener->connection->close(listener->connection);
    listener->connection = NULL;
}

int __listener_read(connection_t* listener_connection) {
    const int fd = listener_connection->fd;
    const in_addr_t ip = listener_connection->ip;
    const unsigned short int port = listener_connection->port;
    connection_server_ctx_t* ctx = listener_connection->ctx;
    char* buffer = listener_connection->buffer;
    const size_t buffer_size = listener_connection->buffer_size;

    // Всегда возвращаем 1: listener не должен закрываться из-за сбоя accept()
    // одного соединения (EAGAIN/EWOULDBLOCK при SO_REUSEPORT, ECONNABORTED,
    // EMFILE/ENFILE и т.п.) — возврат 0 приводил к закрытию самого слушающего
    // сокета. Очередь разбирается по соединению за итерацию; level-triggered
    // epoll снова сообщит EPOLLIN, пока accept-очередь не опустеет.
    connection_t* connection = connection_s_create(fd, ip, port, ctx, buffer, buffer_size);
    if (connection == NULL)
        return 1;

    __set_protocol(connection);
    return 1;
}

void __set_protocol(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    int r = 0;
    if (ctx->server->openssl)
        r = set_tls(connection);
    else {
        r = set_http(connection);
        /* h2c prior-knowledge (RFC 9113 §3.4): a plaintext client may open the
         * connection with the 24-byte HTTP/2 preface instead of an HTTP/1.1
         * request line. The first read sniffs for it (one-shot, one memcmp)
         * before the connection is committed to h1.1. TLS skips this — ALPN has
         * already negotiated the protocol. */
        if (r)
            ctx->h2c_preface = 1;
    }

    if (!r) {
        connection_free(connection);
        return;
    }

    // control_add может провалиться (epoll_ctl) — соединение не попало в epoll,
    // поэтому его нужно освободить явно, иначе утечка.
    if (!ctx->listener->api->control_add(connection, MPXIN | MPXRDHUP))
        connection_free(connection);
}

/* Worker-timer sweep: runs every tick (Phase 5) over this worker's connections.
 * Only h2 connections carry timeout state — h1.1 keep-alive is handled by the
 * HTTP layer, and the listener is never h2. h2_server_tick owns the lock
 * lifecycle and may close (and free) the connection, so next is captured first
 * and the connection is not touched after the call. */
static void __mpx_on_tick(mpxapi_t* api) {
    const int shutdown_now = atomic_load(&appconfig()->shutdown);

    connection_t* connection = api->conns;
    while (connection != NULL) {
        connection_t* next = connection->next;

        if (((connection_server_ctx_t*)connection->ctx)->is_http2)
            h2_server_tick(connection, shutdown_now);

        connection = next;
    }
}
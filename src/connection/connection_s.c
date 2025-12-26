#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "openssl.h"
#include "connection_s.h"
#include "connection_queue.h"
#include "multiplexing.h"
#include "threadpool.h"

void broadcast_clear(connection_t*);
void httpparser_free(void*);

static connection_server_ctx_t* __ctx_create(listener_t* listener);
static void __ctx_reset(void* arg);
static void __ctx_free(void* arg);

connection_t* connection_s_create(int fd, in_addr_t ip, unsigned short int port, connection_server_ctx_t* ctx, char* buffer, size_t buffer_size) {
    connection_t* result = NULL;
    struct sockaddr in_addr;
    socklen_t in_len = sizeof(in_addr);
    connection_t* connection = NULL;

    const int connfd = accept(fd, &in_addr, &in_len);
    if (connfd == -1)
        return NULL;

    // int size = 16384;
    // if (setsockopt(connfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == -1) goto failed;

    if (socket_set_keepalive(connfd) == -1) {
        log_error("Connection error: Error set keepalive\n");
        goto failed;
    }

    if (socket_set_nonblocking(connfd) == -1) {
        log_error("Connection error: Error make_socket_nonblocking failed\n");
        goto failed;
    }

    if (socket_set_timeouts(connfd) == -1) {
        log_error("Connection error: Error set timeouts\n");
        goto failed;
    }

    connection = connection_s_alloc(ctx->listener, connfd, ip, port, buffer, buffer_size);
    if (connection == NULL) goto failed;

    connection->close = connection_close;

    result = connection;

    failed:

    if (result == NULL) {
        close(connfd);
    }

    return result;
}

connection_t* connection_s_alloc(listener_t* listener, int fd, in_addr_t ip, unsigned short int port, char* buffer, size_t buffer_size) {
    connection_t* connection = tpool_alloc(POOL_CONNECTION);
    if (connection == NULL) return NULL;

    connection_server_ctx_t* ctx = __ctx_create(listener);
    if (ctx == NULL) {
        tpool_free(POOL_CONNECTION, connection);
        return NULL;
    }

    connection->fd = fd;
    connection->keepalive = 0;
    connection->ip = ip;
    connection->port = port;
    connection->ctx = ctx;
    connection->ssl = NULL;
    connection->ssl_ctx = NULL;
    connection->buffer = buffer;
    connection->buffer_size = buffer_size;

    return connection;
}

connection_t* connection_s_create_local(server_t* server) {
    connection_t* connection = connection_s_alloc(NULL, -1, inet_addr("127.0.0.1"), server->port, NULL, 0);
    if (connection == NULL) return NULL;

    connection_server_ctx_t* ctx = connection->ctx;
    ctx->server = server;

    connection->close = NULL;
    connection->read = NULL;
    connection->write = NULL;

    return connection;
}

void connection_s_free_local(connection_t* connection) {
    if (connection == NULL) return;

    __ctx_free(connection->ctx);
    tpool_free(POOL_CONNECTION, connection);
}

int connection_s_lock(connection_t* connection) {
    if (connection == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    _Bool expected = 0;
    _Bool desired = 1;

    do {
        expected = 0;
    } while (!atomic_compare_exchange_strong(&ctx->locked, &expected, desired));

    return 1;
}

int connection_s_unlock(connection_t* connection) {
    if (connection == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    atomic_store(&ctx->locked, 0);

    return 1;
}

void connection_s_inc(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    atomic_fetch_add(&ctx->ref_count, 1);
}

connection_dec_result_e connection_s_dec(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    atomic_fetch_sub(&ctx->ref_count, 1);
    if (atomic_load(&ctx->ref_count) == 0) {
        connection_free(connection);
        return CONNECTION_DEC_RESULT_DESTROY;
    }

    return CONNECTION_DEC_RESULT_DECREMENT;
}

int connection_after_write(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (connection->keepalive == 0) {
        atomic_store(&ctx->destroyed, 1);
        return ctx->listener->api->control_mod(connection, MPXOUT | MPXIN | MPXHUP);
    }

    connection_reset(connection);

    if (ctx->switch_to_protocol.fn != NULL) {
        ctx->switch_to_protocol.fn(connection, ctx->switch_to_protocol.data);
        if (ctx->switch_to_protocol.data_free != NULL) {
            ctx->switch_to_protocol.data_free(ctx->switch_to_protocol.data);
        }
        ctx->switch_to_protocol.fn = NULL;
        ctx->switch_to_protocol.data = NULL;
        ctx->switch_to_protocol.data_free = NULL;
    }

    cqueue_lock(ctx->broadcast_queue);
    const int broadcast_empty = cqueue_empty(ctx->broadcast_queue);
    cqueue_unlock(ctx->broadcast_queue);

    if (!cqueue_empty(ctx->queue) || !broadcast_empty) {
        connection_queue_guard_append(connection);
        return ctx->listener->api->control_mod(connection, MPXONESHOT);
    }

    int expected = 2;
    atomic_compare_exchange_strong(&ctx->broadcast_ref_count, &expected, 1);

    return ctx->listener->api->control_mod(connection, MPXIN | MPXRDHUP);
}

int connection_queue_append(connection_queue_item_t* item) {
    connection_server_ctx_t* ctx = item->connection->ctx;

    int expected = 1;
    if (!atomic_compare_exchange_strong(&ctx->broadcast_ref_count, &expected, 2)) {
        return 1;
    }

    if (!ctx->listener->api->control_mod(item->connection, MPXONESHOT)) {
        atomic_store(&ctx->broadcast_ref_count, 1);
        return 0;
    }

    connection_queue_guard_append_item(item);
    return 1;
}

int connection_queue_append_broadcast(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (!ctx->listener->api->control_mod(connection, MPXONESHOT)) {
        atomic_store(&ctx->broadcast_ref_count, 1);
        return 0;
    }

    connection_queue_guard_append(connection);
    return 1;
}

int connection_after_read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    return ctx->listener->api->control_mod(connection, MPXOUT | MPXRDHUP);
}

int connection_close(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    connection_s_lock(connection);

    if (!ctx->listener->api->control_del(connection))
        log_error("Connection not removed from api\n");

    if (connection->ssl != NULL) {
        SSL_shutdown(connection->ssl);
        SSL_clear(connection->ssl);
    }

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    atomic_store(&ctx->destroyed, 1);
    broadcast_clear(connection);

    if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_s_unlock(connection);

    return 1;
}

connection_server_ctx_t* __ctx_create(listener_t* listener) {
    connection_server_ctx_t* ctx = tpool_alloc(POOL_CONNECTION_SERVER_CTX);
    if (ctx == NULL) return NULL;

    ctx->base.reset = __ctx_reset;
    ctx->base.free = __ctx_free;
    ctx->need_write = 0;
    atomic_store(&ctx->destroyed, 0);
    atomic_store(&ctx->ref_count, 1);
    atomic_store(&ctx->broadcast_ref_count, 1);
    atomic_store(&ctx->locked, 0);
    ctx->listener = listener;
    ctx->parser = NULL;
    ctx->server = NULL;
    ctx->request = NULL;
    ctx->response = NULL;
    ctx->queue = cqueue_create();
    ctx->broadcast_queue = cqueue_create();
    ctx->switch_to_protocol.fn = NULL;
    ctx->switch_to_protocol.data = NULL;
    ctx->switch_to_protocol.data_free = NULL;

    if (listener != NULL) {
        cqueue_item_t* item = cqueue_first(&listener->servers);
        if (item)
            ctx->server = item->data;
    }

    if (ctx->queue == NULL) {
        tpool_free(POOL_CONNECTION_SERVER_CTX, ctx);
        return NULL;
    }
    if (ctx->broadcast_queue == NULL) {
        cqueue_free(ctx->queue);
        tpool_free(POOL_CONNECTION_SERVER_CTX, ctx);
        return NULL;
    }

    return ctx;
}

void __ctx_reset(void* arg) {
    connection_server_ctx_t* ctx = arg;

    ctx->need_write = 0;

    request_t* request = ctx->request;
    if (request != NULL) {
        request->free(request);
        ctx->request = NULL;
    }

    response_t* response = ctx->response;
    if (response != NULL) {
        response->free(response);
        ctx->response = NULL;
    }
}

static void __ctx_queue_item_free_callback(void* data) {
    if (data == NULL) return;
    connection_queue_item_t* item = data;
    item->free(item);
}

void __ctx_free(void* arg) {
    connection_server_ctx_t* ctx = arg;

    if (ctx->parser != NULL)
        ((requestparser_t*)ctx->parser)->free(ctx->parser);

    // Освобождаем очереди с callback'ом для освобождения item'ов
    cqueue_freecb(ctx->queue, __ctx_queue_item_free_callback);
    cqueue_freecb(ctx->broadcast_queue, __ctx_queue_item_free_callback);

    request_t* request = ctx->request;
    if (request != NULL) {
        request->free(request);
        ctx->request = NULL;
    }

    response_t* response = ctx->response;
    if (response != NULL) {
        response->free(response);
        ctx->response = NULL;
    }

    tpool_free(POOL_CONNECTION_SERVER_CTX, ctx);
}
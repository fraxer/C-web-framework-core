#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "openssl.h"
#include "connection_s.h"
#include "multiplexing.h"

void broadcast_clear(connection_t*);

connection_t* connection_s_create(connection_t* listener_connection) {
    connection_t* result = NULL;
    connection_server_ctx_t* ctx = listener_connection->ctx;
    struct sockaddr in_addr;
    socklen_t in_len = sizeof(in_addr);

    #pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
    const int connfd = accept(listener_connection->fd, &in_addr, &in_len);
    if (connfd == -1)
        return NULL;

    // int size = 56000;
    // if (setsockopt(connfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == -1) goto failed;

    if (socket_set_keepalive(connfd) == -1) {
        log_error("Connection error: Error set keepalive\n");
        goto failed;
    }

    if (socket_set_nonblocking(connfd) == -1) {
        log_error("Connection error: Error make_socket_nonblocking failed\n");
        goto failed;
    }

    connection_t* connection = connection_s_alloc(ctx->listener, connfd, listener_connection->ip, listener_connection->port);
    if (connection == NULL) goto failed;

    connection->close = connection_close;

    result = connection;

    failed:

    if (result == NULL)
        close(connfd);

    return result;
}

connection_t* connection_s_alloc(listener_t* listener, int fd, in_addr_t ip, unsigned short int port) {
    connection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection_server_ctx_t* ctx = malloc(sizeof * ctx);
    if (ctx == NULL) {
        free(connection);
        return NULL;
    }

    connection->fd = fd;
    connection->keepalive = 0;
    connection->ip = ip;
    connection->port = port;
    connection->ctx = ctx;
    connection->ssl = NULL;
    connection->ssl_ctx = NULL;

    ctx->destroyed = 0;
    atomic_store(&ctx->ref_count, 1);
    atomic_store(&ctx->locked, 0);
    ctx->listener = listener;
    ctx->listener = NULL;
    ctx->response = NULL;
    ctx->queue = cqueue_create();

    if (ctx->queue == NULL) {
        free(connection);
        free(ctx);
        return NULL;
    }

    return connection;
}

void connection_s_free(connection_t* connection) {
    if (connection == NULL) return;

    connection_server_ctx_t* ctx = connection->ctx;

    if (connection->ssl != NULL) {
        SSL_free_buffers(connection->ssl);
        SSL_free(connection->ssl);
        connection->ssl = NULL;
    }

    if (ctx->response != NULL) {
        ctx->response->free(ctx->response);
        ctx->response = NULL;
    }

    free(ctx->queue);
    free(connection);
}

void connection_s_reset(connection_t* connection) {
    if (connection == NULL) return;

    connection_server_ctx_t* ctx = connection->ctx;
    if (ctx->response != NULL)
        ctx->response->reset(ctx->response);
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

int connection_trylockwrite(connection_t* connection) {
    if (connection == NULL) return 0;

    _Bool expected = 0;
    _Bool desired = 1;

    // if (atomic_compare_exchange_strong(&connection->onwrite, &expected, desired)) return 1;
    return 1;

    return 0;
}

void connection_s_inc(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    atomic_fetch_add(&ctx->ref_count, 1);
}

connection_dec_result_e connection_s_dec(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    atomic_fetch_sub(&ctx->ref_count, 1);
    if (atomic_load(&ctx->ref_count) == 0) {
        connection_s_free(connection);
        return CONNECTION_DEC_RESULT_DESTROY;
    }

    return CONNECTION_DEC_RESULT_DECREMENT;
}

int connection_after_read_request(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    return ctx->listener->api->control_mod(connection, MPXOUT | MPXRDHUP);
}

int connection_after_write_request(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (connection->keepalive == 0) {
        ctx->destroyed = 1;
        return ctx->listener->api->control_mod(connection, MPXOUT | MPXIN | MPXHUP);
    }

    connection_s_reset(connection);

    if (ctx->switch_to_protocol != NULL) {
        ctx->switch_to_protocol(connection);
        ctx->switch_to_protocol = NULL;
    }

    if (!cqueue_empty(ctx->queue)) {
        connection_queue_guard_append2(connection);
        return ctx->listener->api->control_mod(connection, MPXONESHOT);
    }

    return ctx->listener->api->control_mod(connection, MPXIN | MPXRDHUP);
}

int connection_queue_append(connection_queue_item_t* item) {
    connection_server_ctx_t* ctx = item->connection->ctx;
    if (!ctx->listener->api->control_mod(item->connection, MPXONESHOT))
        return 0;

    connection_queue_guard_append(item);

    // atomic_store(&item->connection->onwrite, 0);

    return 1;
}

void connection_queue_append_broadcast(connection_queue_item_t* item) {
    connection_queue_guard_append(item);
}

int connection_queue_pop(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    return ctx->listener->api->control_mod(connection, MPXOUT | MPXRDHUP);
}

int connection_close(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    connection_lock(connection);

    if (!ctx->listener->api->control_del(connection))
        log_error("Connection not removed from api\n");

    if (connection->ssl != NULL) {
        SSL_shutdown(connection->ssl);
        SSL_clear(connection->ssl);
    }

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    ctx->destroyed = 1;
    broadcast_clear(connection);

    if (connection_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_unlock(connection);

    return 1;
}

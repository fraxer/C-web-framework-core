#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "openssl.h"
#include "connection_s.h"
#include "multiplexing.h"

void broadcast_clear(connection_s_t*);

connection_s_t* connection_s_create(connection_s_t* socket_connection) {
    connection_s_t* result = NULL;
    struct sockaddr in_addr;
    socklen_t in_len = sizeof(in_addr);

    #pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
    const int connfd = accept(socket_connection->base.fd, &in_addr, &in_len);
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

    connection_s_t* connection = connection_s_alloc(connfd, socket_connection->api, socket_connection->base.ip, socket_connection->base.port);
    if (connection == NULL) goto failed;

    result = connection;

    failed:

    if (result == NULL)
        close(connfd);

    return result;
}

connection_s_t* connection_s_alloc(int fd, mpxapi_t* api, in_addr_t ip, unsigned short int port) {
    connection_s_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection->base.fd = fd;
    connection->base.keepalive_enabled = 0;
    connection->base.ip = ip;
    connection->base.port = port;
    connection->base.ssl = NULL;
    connection->base.ssl_ctx = NULL;

    connection->destroyed = 0;
    atomic_store(&connection->ref_count, 1);
    atomic_store(&connection->locked, 0);
    connection->api = api;
    connection->server = NULL;
    connection->response = NULL;
    connection->queue = cqueue_create();

    if (connection->queue == NULL) {
        free(connection);
        return NULL;
    }

    return connection;
}

void connection_s_free(connection_s_t* connection) {
    if (connection == NULL) return;

    if (connection->base.ssl != NULL) {
        SSL_free_buffers(connection->base.ssl);
        SSL_free(connection->base.ssl);
        connection->base.ssl = NULL;
    }

    if (connection->response != NULL) {
        connection->response->free(connection->response);
        connection->response = NULL;
    }

    free(connection->queue);
    free(connection);
}

void connection_s_reset(connection_s_t* connection) {
    if (connection == NULL) return;

    if (connection->response != NULL)
        connection->response->reset(connection->response);
}

int connection_s_lock(connection_s_t* connection) {
    if (connection == NULL) return 0;

    _Bool expected = 0;
    _Bool desired = 1;

    do {
        expected = 0;
    } while (!atomic_compare_exchange_strong(&connection->locked, &expected, desired));

    return 1;
}

int connection_s_unlock(connection_s_t* connection) {
    if (connection == NULL) return 0;

    atomic_store(&connection->locked, 0);

    return 1;
}

int connection_s_trylockwrite(connection_s_t* connection) {
    if (connection == NULL) return 0;

    _Bool expected = 0;
    _Bool desired = 1;

    // if (atomic_compare_exchange_strong(&connection->onwrite, &expected, desired)) return 1;
    return 1;

    return 0;
}

void connection_s_inc(connection_s_t* connection) {
    atomic_fetch_add(&connection->ref_count, 1);
}

connection_dec_result_e connection_s_dec(connection_s_t* connection) {
    atomic_fetch_sub(&connection->ref_count, 1);
    if (atomic_load(&connection->ref_count) == 0) {
        connection_s_free(connection);
        return CONNECTION_DEC_RESULT_DESTROY;
    }

    return CONNECTION_DEC_RESULT_DECREMENT;
}

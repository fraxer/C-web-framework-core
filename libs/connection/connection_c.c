#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "openssl.h"
#include "connection_c.h"

connection_c_t* __connection_c_alloc(int fd, in_addr_t ip, unsigned short int port);

connection_c_t* connection_c_create(const int fd, const in_addr_t ip, const short port) {
    return __connection_c_alloc(fd, ip, port);
}

connection_c_t* __connection_c_alloc(int fd, in_addr_t ip, unsigned short int port) {
    connection_c_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection->base.fd = fd;
    connection->base.keepalive_enabled = 0;
    connection->base.ip = ip;
    connection->base.port = port;
    connection->base.ssl = NULL;
    connection->base.ssl_ctx = NULL;
    connection->client = NULL;
    connection->request = NULL;
    connection->response = NULL;

    if (!gzip_init(&connection->gzip)) {
        free(connection);
        return NULL;
    }

    return connection;
}

void connection_free(connection_c_t* connection) {
    if (connection == NULL) return;

    gzip_free(&connection->gzip);

    if (connection->base.ssl != NULL) {
        SSL_free_buffers(connection->base.ssl);
        SSL_free(connection->base.ssl);
        connection->base.ssl = NULL;
    }

    if (connection->request != NULL) {
        connection->request->free(connection->request);
        connection->request = NULL;
    }

    if (connection->response != NULL) {
        connection->response->free(connection->response);
        connection->response = NULL;
    }

    free(connection);
}

void connection_reset(connection_c_t* connection) {
    if (connection == NULL) return;

    gzip_free(&connection->gzip);

    if (connection->request != NULL)
        connection->request->reset(connection->request);

    if (connection->response != NULL)
        connection->response->reset(connection->response);
}

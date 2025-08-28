#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "openssl.h"
#include "connection_c.h"

connection_t* __connection_c_alloc(int fd, in_addr_t ip, unsigned short int port);

connection_t* connection_c_create(const int fd, const in_addr_t ip, const short port) {
    return __connection_c_alloc(fd, ip, port);
}

connection_t* __connection_c_alloc(int fd, in_addr_t ip, unsigned short int port) {
    connection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection->fd = fd;
    connection->keepalive = 0;
    connection->ip = ip;
    connection->port = port;
    connection->ssl = NULL;
    connection->ssl_ctx = NULL;
    // connection->client = NULL;
    connection->request = NULL;
    connection->response = NULL;

    // if (!gzip_init(&connection->gzip)) {
    //     free(connection);
    //     return NULL;
    // }

    return connection;
}

void connection_free(connection_t* connection) {
    if (connection == NULL) return;

    // gzip_free(&connection->gzip);

    if (connection->ssl != NULL) {
        SSL_free_buffers(connection->ssl);
        SSL_free(connection->ssl);
        connection->ssl = NULL;
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

void connection_reset(connection_t* connection) {
    if (connection == NULL) return;

    // gzip_free(&connection->gzip);

    if (connection->request != NULL)
        connection->request->reset(connection->request);

    if (connection->response != NULL)
        connection->response->reset(connection->response);
}

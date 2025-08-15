#include <netinet/tcp.h>

#include "connection.h"
#include "openssl.h"

void connection_reset(connection_t* connection) {
    if (connection == NULL) return;

    connection_ctx_t* ctx = connection->ctx;

    ctx->reset(ctx);
}

void connection_free(connection_t* connection) {
    if (connection == NULL) return;

    connection_ctx_t* ctx = connection->ctx;

    if (connection->ssl != NULL) {
        SSL_free_buffers(connection->ssl);
        SSL_free(connection->ssl);
        connection->ssl = NULL;
    }

    ctx->free(ctx);

    free(connection);
}

ssize_t connection_data_read(connection_t* connection) {
    return connection->ssl ?
        openssl_read(connection->ssl, connection->buffer, connection->buffer_size) :
        recv(connection->fd, connection->buffer, connection->buffer_size, 0);
}

ssize_t connection_data_write(connection_t* connection, const char* data, size_t size) {
    return connection->ssl ?
        openssl_write(connection->ssl, data, size) :
        send(connection->fd, data, size, MSG_NOSIGNAL);
}

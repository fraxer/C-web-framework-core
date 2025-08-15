#ifndef __CONNECTION__
#define __CONNECTION__

#include <openssl/ssl.h>

#include "socket.h"

typedef struct {
    void(*free)(void*);
    void(*reset)(void*);
} connection_ctx_t;

typedef struct connection {
    int fd;
    char* buffer;
    void* ctx; // connection_ctx_t

    SSL* ssl;
    SSL_CTX* ssl_ctx;
    in_addr_t ip;
    unsigned short int port;
    unsigned keepalive: 1;

    size_t buffer_size;

    int(*close)(struct connection* connection);
    int(*read)(struct connection* connection);
    int(*write)(struct connection* connection);
} connection_t;

void connection_reset(connection_t* connection);
void connection_free(connection_t* connection);
ssize_t connection_data_read(connection_t* connection);
ssize_t connection_data_write(connection_t* connection, const char* data, size_t size);

#endif

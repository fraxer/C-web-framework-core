#ifndef __CONNECTION__
#define __CONNECTION__

#include <openssl/ssl.h>

#include "socket.h"

typedef struct connection {
    int fd;
    in_addr_t ip;
    unsigned short int port;
    unsigned keepalive: 1;
    void* ctx;
    SSL* ssl;
    SSL_CTX* ssl_ctx;

    int(*close)(struct connection* connection);
    ssize_t(*read)(struct connection* connection);
    ssize_t(*write)(struct connection* connection);
} connection_t;

#endif

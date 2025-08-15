#ifndef __CONNECTION__
#define __CONNECTION__

#include <stdatomic.h>

#include "socket.h"
#include "openssl.h"

typedef struct connection {
    int fd;
    unsigned keepalive_enabled: 1;
    in_addr_t ip;
    unsigned short int port;
    SSL* ssl;
    SSL_CTX* ssl_ctx;
} connection_t;

#endif

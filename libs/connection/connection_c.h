#ifndef __CONNECTION_C__
#define __CONNECTION_C__

#include <stdatomic.h>

#include "connection.h"
#include "socket.h"
#include "openssl.h"
#include "request.h"
#include "response.h"
#include "gzip.h"

typedef struct connection_c {
    connection_t base;
    gzip_t gzip;
    void* client;
    request_t* request;
    response_t* response;
} connection_c_t;

connection_c_t* connection_c_create(const int fd, const in_addr_t ip, const short port);

#endif

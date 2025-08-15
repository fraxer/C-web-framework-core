#ifndef __CONNECTION_C__
#define __CONNECTION_C__

#include <stdatomic.h>

#include "connection.h"
#include "request.h"
#include "response.h"
#include "gzip.h"

typedef struct {
    connection_ctx_t base;
    gzip_t gzip;

    void* request;
    void* response;
} connection_client_ctx_t;

connection_t* connection_c_create(const int fd, const in_addr_t ip, const short port);

#endif

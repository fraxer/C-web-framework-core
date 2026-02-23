#include "connection_c.h"

static connection_t* __connection_c_alloc(int fd, in_addr_t ip, unsigned short int port);
static connection_client_ctx_t* __ctx_create(void);
static void __ctx_reset(void* arg);
static void __ctx_free(void* arg);

connection_t* connection_c_create(const int fd, const in_addr_t ip, const short port) {
    return __connection_c_alloc(fd, ip, port);
}

connection_t* __connection_c_alloc(int fd, in_addr_t ip, unsigned short int port) {
    connection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection_client_ctx_t* ctx = __ctx_create();
    if (ctx == NULL) {
        free(connection);
        return NULL;
    }

    connection->fd = fd;
    connection->keepalive = 0;
    connection->ip = ip;
    connection->port = port;
    connection->remote_ip = 0;
    connection->remote_port = 0;
    connection->ctx = ctx;
    connection->ssl = NULL;
    connection->ssl_ctx = NULL;
    connection->buffer = NULL;
    connection->buffer_size = 0;

    return connection;
}

connection_client_ctx_t *__ctx_create(void) {
    connection_client_ctx_t* ctx = malloc(sizeof * ctx);
    if (ctx == NULL)
        return NULL;

    ctx->base.reset = __ctx_reset;
    ctx->base.free = __ctx_free;
    ctx->request = NULL;
    ctx->response = NULL;

    gzip_init(&ctx->gzip);

    return ctx;
}

void __ctx_reset(void* arg) {
    connection_client_ctx_t* ctx = arg;

    request_t* request = ctx->request;
    if (request != NULL)
        request->reset(request);

    response_t* response = ctx->response;
    if (response != NULL)
        response->reset(response);

    gzip_free(&ctx->gzip);
}

void __ctx_free(void* arg) {
    connection_client_ctx_t* ctx = arg;

    request_t* request = ctx->request;
    if (request != NULL)
        request->free(request);

    response_t* response = ctx->response;
    if (response != NULL)
        response->free(response);

    gzip_free(&ctx->gzip);
}
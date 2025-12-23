#include <stdlib.h>
#include "connection_c_async.h"

static connection_t* __connection_c_async_alloc(int fd, in_addr_t ip, unsigned short int port, struct mpxapi* api);
static connection_client_async_ctx_t* __ctx_create(struct mpxapi* api);
static void __ctx_reset(void* arg);
static void __ctx_free(void* arg);

connection_t* connection_c_async_create(int fd, in_addr_t ip, unsigned short int port, struct mpxapi* api) {
    return __connection_c_async_alloc(fd, ip, port, api);
}

connection_t* __connection_c_async_alloc(int fd, in_addr_t ip, unsigned short int port, struct mpxapi* api) {
    connection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection_client_async_ctx_t* ctx = __ctx_create(api);
    if (ctx == NULL) {
        free(connection);
        return NULL;
    }

    connection->fd = fd;
    connection->keepalive = 0;
    connection->ip = ip;
    connection->port = port;
    connection->ctx = ctx;
    connection->type = CONNECTION_TYPE_CLIENT_ASYNC;  // Установить тип
    connection->ssl = NULL;
    connection->ssl_ctx = NULL;
    connection->buffer = NULL;                          // Будет установлен позже
    connection->buffer_size = 0;

    return connection;
}

connection_client_async_ctx_t* __ctx_create(struct mpxapi* api) {
    connection_client_async_ctx_t* ctx = malloc(sizeof * ctx);
    if (ctx == NULL)
        return NULL;

    ctx->base.reset = __ctx_reset;
    ctx->base.free = __ctx_free;
    ctx->api = api;
    ctx->client = NULL;           // Будет установлено позже
    ctx->destroyed = 0;
    ctx->registered = 0;

    return ctx;
}

void __ctx_reset(void* arg) {
    connection_client_async_ctx_t* ctx = arg;
    // Для async клиента reset не требуется - соединение используется один раз
    ctx->destroyed = 0;
    ctx->registered = 0;
}

void __ctx_free(void* arg) {
    connection_client_async_ctx_t* ctx = arg;
    free(ctx);
}

void connection_c_async_free(connection_t* connection) {
    if (connection == NULL) return;

    connection_client_async_ctx_t* ctx = connection->ctx;
    if (ctx != NULL) {
        ctx->base.free(ctx);
    }

    free(connection);
}

int connection_c_async_close(connection_t* connection) {
    // Закрытие соединения будет выполнено в async handler
    return 0;
}

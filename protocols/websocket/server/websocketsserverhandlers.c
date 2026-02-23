#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "route.h"
#include "websocketsparser.h"
#include "websocketsserverhandlers.h"
#include "wscontext.h"
#include "middleware.h"
#include "connection_s.h"

typedef struct connection_queue_websockets_data {
    connection_queue_item_data_t base;
    websocketsrequest_t* request;
    websocketsresponse_t* response;
    connection_t* connection;
    ratelimiter_t* ratelimiter;
} connection_queue_websockets_data_t;

static int __read(connection_t* connection);
static int __write(connection_t* connection);
static int __handle(websocketsparser_t* parser, deferred_handler handler);

static void __queue_data_request_free(void* arg);
static void __queue_response_handler(void* arg);
static void* __queue_data_response_create(connection_t* connection, void* component, ratelimiter_t* ratelimiter);
static void __queue_data_response_free(void* arg);
static int __post_response_default(connection_t* connection, const char* status_text);
static int __post_response(websocketsresponse_t* response);
static int __post_deffered_response(websocketsresponse_t* response);

int websockets_guard_read(connection_t* connection) {
    connection_s_lock(connection);
    const int r = __read(connection);
    connection_s_unlock(connection);

    return r;
}

int websockets_guard_write(connection_t* connection) {
    connection_s_lock(connection);
    const int r = __write(connection);
    connection_s_unlock(connection);

    return r;
}

int __read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    websocketsparser_t* parser = ctx->parser;

    while (1) {
        int bytes_readed = 0;
        read_data:

        bytes_readed = connection_data_read(connection);

        switch (bytes_readed) {
        case -1:
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1;

            return 0;
        }
        case 0:
            return 0;
        default:
            websocketsparser_set_bytes_readed(parser, bytes_readed);
            parser->pos_start = 0;
            parser->pos = 0;

            while (1) {
                switch (websocketsparser_run(parser)) {
                case WSPARSER_ERROR:
                case WSPARSER_OUT_OF_MEMORY:
                    return 0;
                case WSPARSER_PAYLOAD_LARGE:
                    return __post_response_default(connection, "Payload large");
                case WSPARSER_BAD_REQUEST:
                    return __post_response_default(connection, "Bad request");
                case WSPARSER_CONTINUE:
                    goto read_data;
                case WSPARSER_HANDLE_AND_CONTINUE:
                {
                    if (!__handle(parser, __post_deffered_response))
                        return 0;
                    
                    websocketsparser_prepare_remains(parser);
                    break;
                }
                case WSPARSER_COMPLETE:
                {
                    if (!__handle(parser, __post_response))
                        return 0;

                    websocketsparser_reset(parser);
                    return 1;
                }
                default:
                    return 0;
                }
            }
        }
    }

    return 0;
}

int __write(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    websocketsresponse_t* response = ctx->response;

    if (response->body.data == NULL)
        return 0;

    // body
    if (response->body.pos < response->body.size) {
        size_t size = response->body.size - response->body.pos;

        if (size > connection->buffer_size)
            size = connection->buffer_size;

        ssize_t writed = connection_data_write(connection, &response->body.data[response->body.pos], size);

        if (writed == -1) return 0;

        response->body.pos += writed;

        if ((size_t)writed == connection->buffer_size) return 1;
    }

    // file
    if (response->file_.fd > 0 && response->file_.pos < response->file_.size) {
        lseek(response->file_.fd, response->file_.pos, SEEK_SET);

        size_t size = response->file_.size - response->file_.pos;

        if (size > connection->buffer_size)
            size = connection->buffer_size;

        size_t readed = read(response->file_.fd, connection->buffer, size);

        ssize_t writed = connection_data_write(connection, connection->buffer, readed);

        if (writed == -1) return 0;

        response->file_.pos += writed;

        if (response->file_.pos < response->file_.size) return 1;
    }

    return connection_after_write(connection);
}

int __handle(websocketsparser_t* parser, deferred_handler handler) {
    connection_t* connection = parser->connection;

    /* Handle control frames (FIN=1 already validated in parser) */
    switch (parser->frame.opcode) {
    case WSOPCODE_CLOSE:
    {
        websocketsresponse_t* response = websocketsresponse_create(connection);
        if (response == NULL) return 0;
        websocketsresponse_close(response, bufferdata_get(&parser->buf), bufferdata_writed(&parser->buf));
        connection->keepalive = 0;
        return handler(response);
    }
    case WSOPCODE_PING:
    {
        websocketsresponse_t* response = websocketsresponse_create(connection);
        if (response == NULL) return 0;
        websocketsresponse_pong(response, bufferdata_get(&parser->buf), bufferdata_writed(&parser->buf));
        return handler(response);
    }
    case WSOPCODE_PONG:
        return 1;
    default:
        break;
    }

    /* Data frames: only process when complete (FIN=1) */
    if (!parser->frame.fin)
        return 1;

    if (parser->request->protocol->get_resource(connection, parser->request))
        return 1;

    websocketsresponse_t* response = websocketsresponse_create(connection);
    if (response == NULL) return 0;

    websocketsresponse_default(response, "resource not found");

    return handler(response);
}

void websockets_queue_request_handler(void* arg) {
    connection_queue_item_t* item = arg;
    connection_queue_websockets_data_t* data = (connection_queue_websockets_data_t*)item->data;
    connection_server_ctx_t* conn_ctx = item->connection->ctx;

    websocketsresponse_t* response = websocketsresponse_create(item->connection);
    if (response == NULL) {
        atomic_store(&conn_ctx->destroyed, 1);
        connection_after_read(item->connection);
        return;
    }

    conn_ctx->response = response;

    if (!ratelimiter_allow(data->ratelimiter, item->connection->remote_ip, 1)) {
        websocketsresponse_t* response = conn_ctx->response;
        websocketsresponse_default(response, "Too Many Requests");
        connection_after_read(item->connection);
        return;
    }

    wsctx_t ctx;
    wsctx_init(&ctx, data->request, conn_ctx->response);

    if (run_middlewares(conn_ctx->server->websockets.middleware, &ctx))
        item->handle(&ctx);

    wsctx_clear(&ctx);

    connection_after_read(item->connection);
}

void* websockets_queue_data_request_create(connection_t* connection, void* component, ratelimiter_t* ratelimiter) {
    connection_queue_websockets_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    data->base.free = __queue_data_request_free;
    data->request = component;
    data->connection = connection;
    data->response = NULL;
    data->ratelimiter = ratelimiter;

    return data;
}

void __queue_data_request_free(void* arg) {
    if (arg == NULL) return;

    connection_queue_websockets_data_t* data = arg;

    if (data->request != NULL)
        websocketsrequest_free(data->request);

    free(data);
}

int __post_response_default(connection_t* connection, const char* status_text) {
    websocketsresponse_t* response = websocketsresponse_create(connection);
    if (response == NULL) return 0;

    websocketsresponse_default(response, status_text);

    return __post_response(response);
}

int __post_response(websocketsresponse_t* response) {
    connection_t* connection = response->connection;
    connection_server_ctx_t* ctx = connection->ctx;

    if (cqueue_empty(ctx->queue)) {
        ctx->response = response;
        ctx->need_write = 1;
        return connection_after_read(connection);
    }

    return websockets_deferred_handler(connection, response, __queue_response_handler, NULL, __queue_data_response_create, NULL);
}

int __post_deffered_response(websocketsresponse_t* response) {
    connection_t* connection = response->connection;

    return websockets_deferred_handler(connection, response, __queue_response_handler, NULL, __queue_data_response_create, NULL);
}

int websockets_deferred_handler(connection_t* connection, void* component, queue_handler runner, queue_handler handle, queue_data_create data_create, ratelimiter_t* ratelimiter) {
    connection_queue_item_t* item = connection_queue_item_create();
    if (item == NULL) return 0;

    item->run = runner;
    item->handle = handle;
    item->connection = connection;
    item->data = data_create(connection, component, ratelimiter);

    if (item->data == NULL) {
        item->free(item);
        return 0;
    }

    connection_server_ctx_t* ctx = connection->ctx;
    const int queue_empty = cqueue_empty(ctx->queue);
    cqueue_append(ctx->queue, item);

    if (!queue_empty)
        return 1;

    if (!connection_queue_append(item)) {
        item->free(item);
        return 0;
    }

    return 1;
}

void __queue_response_handler(void* arg) {
    connection_queue_item_t* item = arg;
    connection_queue_websockets_data_t* data = (connection_queue_websockets_data_t*)item->data;
    connection_server_ctx_t* conn_ctx = item->connection->ctx;

    conn_ctx->response = data->response;

    connection_after_read(item->connection);
}

void* __queue_data_response_create(connection_t* connection, void* component, ratelimiter_t* ratelimiter) {
    (void)ratelimiter;

    websocketsresponse_t* response = component;
    connection_queue_websockets_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    data->base.free = __queue_data_response_free;
    data->request = NULL;
    data->connection = connection;
    data->response = response;
    data->ratelimiter = NULL;

    return data;
}

void __queue_data_response_free(void* arg) {
    if (arg == NULL) return;

    connection_queue_websockets_data_t* data = arg;

    free(data);
}

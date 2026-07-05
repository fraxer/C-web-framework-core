#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

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
static int __post_close_default(connection_t* connection, unsigned short status_code, const char* reason);
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
        ssize_t bytes_readed = 0;
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
                    return __post_close_default(connection, 1009, "Payload large");
                case WSPARSER_BAD_REQUEST:
                    return __post_close_default(connection, 1002, "Bad request");
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

    /* A write event with no staged response (spurious EPOLLOUT, a handler
     * that never called send_*) must not dereference NULL. */
    if (response == NULL)
        return 0;

    /* A handler is allowed not to reply (push-style flows): finish the write
     * phase as a no-op — closing here punished every silent handler. */
    if (response->body.data == NULL)
        return connection_after_write(connection);

    // body
    if (response->body.pos < response->body.size) {
        size_t size = response->body.size - response->body.pos;

        if (size > connection->buffer_size)
            size = connection->buffer_size;

        const ssize_t writed = connection_data_write(connection, &response->body.data[response->body.pos], size);

        /* EAGAIN/EINTR are not fatal: the socket buffer is full (the peer is
         * slow), the event loop will call us again on the next EPOLLOUT. */
        if (writed < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;

        response->body.pos += writed;

        /* A short write leaves the tail of the frame unsent: finishing here
         * (falling through to connection_after_write) would truncate it. */
        if (response->body.pos < response->body.size) return 1;
    }

    // file
    if (response->file_.fd > -1 && response->file_.pos < response->file_.size) {
        lseek(response->file_.fd, response->file_.pos, SEEK_SET);

        size_t size = response->file_.size - response->file_.pos;

        if (size > connection->buffer_size)
            size = connection->buffer_size;

        const ssize_t readed = read(response->file_.fd, connection->buffer, size);

        /* read() failure folded into size_t handed send() an SIZE_MAX-sized
         * buffer; 0 (file truncated behind us) would spin the event loop
         * forever since pos never advances. */
        if (readed < 0)
            return errno == EINTR;
        if (readed == 0)
            return 0;

        const ssize_t writed = connection_data_write(connection, connection->buffer, (size_t)readed);

        if (writed < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;

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

    /* Not dispatched (no matching route or the queue rejected it): ownership
     * never left the parser, and the parser drops its pointer on reset/
     * prepare_remains without freeing — so every message to an unknown route
     * leaked its request. */
    websocketsrequest_free(parser->request);
    parser->request = NULL;

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

/* RFC 6455 §7.1.7: a protocol error fails the connection — reply with a CLOSE
 * frame carrying the status code and stop reading the (now desynced) stream.
 * Replying with a text frame kept the connection parsing garbage. */
int __post_close_default(connection_t* connection, unsigned short status_code, const char* reason) {
    websocketsresponse_t* response = websocketsresponse_create(connection);
    if (response == NULL) return 0;

    char payload[125]; /* RFC 6455 §5.5: control frame payload limit */
    size_t length = 0;

    payload[length++] = (char)((status_code >> 8) & 0xFF);
    payload[length++] = (char)(status_code & 0xFF);

    size_t reason_length = strlen(reason);
    if (reason_length > sizeof(payload) - length)
        reason_length = sizeof(payload) - length;

    memcpy(payload + length, reason, reason_length);
    length += reason_length;

    websocketsresponse_close(response, payload, length);
    connection->keepalive = 0;

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

    /* On queueing failure ownership stays here (see websockets_deferred_handler
     * contract): the caller only sees 0 and closes the connection. */
    if (!websockets_deferred_handler(connection, response, __queue_response_handler, NULL, __queue_data_response_create, NULL)) {
        response->base.free(response);
        return 0;
    }

    return 1;
}

int __post_deffered_response(websocketsresponse_t* response) {
    connection_t* connection = response->connection;

    if (!websockets_deferred_handler(connection, response, __queue_response_handler, NULL, __queue_data_response_create, NULL)) {
        response->base.free(response);
        return 0;
    }

    return 1;
}

/* Queues the component for a worker thread. On failure returns 0 and the
 * component's ownership stays with the caller (nothing here frees it). */
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

    if (!cqueue_append(ctx->queue, item)) {
        connection_queue_websockets_data_t* data = (connection_queue_websockets_data_t*)item->data;
        data->request = NULL;
        data->response = NULL;
        item->free(item);
        return 0;
    }

    if (!queue_empty)
        return 1;

    if (!connection_queue_append(item)) {
        /* The item is already in ctx->queue: freeing it in place left a
         * dangling pointer that the worker thread or __ctx_free freed again.
         * It was appended to an empty queue, so pop takes this same item. */
        cqueue_pop(ctx->queue);

        connection_queue_websockets_data_t* data = (connection_queue_websockets_data_t*)item->data;
        data->request = NULL;
        data->response = NULL;
        item->free(item);
        return 0;
    }

    return 1;
}

void __queue_response_handler(void* arg) {
    connection_queue_item_t* item = arg;
    connection_queue_websockets_data_t* data = (connection_queue_websockets_data_t*)item->data;
    connection_server_ctx_t* conn_ctx = item->connection->ctx;

    /* Ownership moves to the connection ctx; drop it from the item so
     * __queue_data_response_free does not free what the ctx now owns. */
    conn_ctx->response = data->response;
    data->response = NULL;

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

    /* Still owned by the item when it is discarded without running (the
     * connection closed with responses queued): the response leaked. */
    if (data->response != NULL)
        data->response->base.free(data->response);

    free(data);
}

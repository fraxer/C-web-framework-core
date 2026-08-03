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
    connection_t* connection;
    ratelimiter_t* ratelimiter;
    /* This message's place in the output order, reserved at dispatch time and
     * filled by the runner when the handler returns. Owned by ctx->write_queue,
     * not by the item. */
    connection_out_slot_t* out;
    /* The virtual host the connection was upgraded on, captured at dispatch.
     * Same reasoning as the HTTP runner: ctx->server belongs to the worker, and
     * a handler thread has no business reading it. */
    server_t* server;
} connection_queue_websockets_data_t;

static int __read(connection_t* connection);
static int __write(connection_t* connection);
static int __handle(websocketsparser_t* parser);

static void __queue_data_request_free(void* arg);
static int __post_close_default(connection_t* connection, unsigned short status_code, const char* reason);
static int __post_response(websocketsresponse_t* response);
static connection_out_slot_t* __out_reserve(connection_t* connection);
static int __out_promote(connection_t* connection);
static int __out_publish(connection_t* connection, connection_out_slot_t* slot, websocketsresponse_t* response);
static void __out_finish_current(connection_t* connection);

/* --------------------------------------------------------------------------
 * Output ordering (docs/concurrency/00 §4.4, phase C)
 *
 * WebSocket has no stream ids: the peer sees one ordered message stream and
 * matches replies by position. So handlers of one connection may run in
 * parallel, but their frames must leave in the order the messages arrived.
 *
 * ctx->write_queue is that order. A slot is reserved — empty — the moment a
 * message is dispatched, and filled when its handler finishes. The write path
 * only ever takes the head, and only once the head is filled, so a slow handler
 * holds up output while the other handlers keep running. That is the trade the
 * protocol forces; it is still the difference between N×T and T.
 *
 * ctx->response stays what it always was: the response currently being written
 * (a frame can need several EPOLLOUT turns). It is promoted out of the queue by
 * whoever notices the head is ready — the publisher or the write path.
 *
 * Every operation here runs under connection_s_lock, which is what orders
 * publish against take; the inner cqueue_lock only keeps the list itself
 * consistent. Lock order is connection_s_lock -> cqueue_lock, never the
 * reverse.
 * -------------------------------------------------------------------------- */

/* Reserve this message's place. Caller holds connection_s_lock. */
connection_out_slot_t* __out_reserve(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    if (ctx->write_queue == NULL) return NULL;

    connection_out_slot_t* slot = malloc(sizeof * slot);
    if (slot == NULL) return NULL;

    slot->response = NULL;

    cqueue_lock(ctx->write_queue);
    const int appended = cqueue_append(ctx->write_queue, slot);
    cqueue_unlock(ctx->write_queue);

    if (!appended) {
        free(slot);
        return NULL;
    }

    return slot;
}

/* Move a filled head slot into ctx->response. Returns 1 when something became
 * writable. Caller holds connection_s_lock. */
int __out_promote(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (ctx->response != NULL) return 0;
    if (ctx->write_queue == NULL) return 0;

    cqueue_lock(ctx->write_queue);
    cqueue_item_t* first = cqueue_first(ctx->write_queue);
    connection_out_slot_t* slot = first != NULL ? first->data : NULL;
    const int ready = slot != NULL && slot->response != NULL;
    if (ready)
        cqueue_pop(ctx->write_queue);
    cqueue_unlock(ctx->write_queue);

    if (!ready) return 0;

    ctx->response = slot->response;
    free(slot);

    return 1;
}

/* True when nothing is staged and nothing is pending — a genuinely spurious
 * write event. Caller holds connection_s_lock. */
static int __out_idle(connection_server_ctx_t* ctx) {
    if (ctx->response != NULL) return 0;
    if (ctx->write_queue == NULL) return 1;

    cqueue_lock(ctx->write_queue);
    const int empty = cqueue_empty(ctx->write_queue);
    cqueue_unlock(ctx->write_queue);

    return empty;
}

/* The staged response has been written (or had nothing to write): release it
 * and clear the stage for the next one. Caller holds connection_s_lock. */
void __out_finish_current(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    websocketsresponse_t* response = ctx->response;

    ctx->response = NULL;

    if (response != NULL)
        response->base.free(response);
}

/* Publish a finished response into its reserved slot and, if that makes the
 * head writable, hand it to the event loop. Takes connection_s_lock, so the
 * caller must not hold it. */
int __out_publish(connection_t* connection, connection_out_slot_t* slot, websocketsresponse_t* response) {
    connection_server_ctx_t* ctx = connection->ctx;

    connection_s_lock(connection, LOCK_SITE_WS_PUBLISH);

    slot->response = &response->base;

    int r = 1;

    /* Arming only when the head became writable is what keeps a level-triggered
     * EPOLLOUT from spinning on a connection whose head is still unfilled. The
     * handler that does fill the head arms it then; because publish and take
     * are both under this lock, the wakeup cannot be lost between them. */
    if (__out_promote(connection)) {
        atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
        r = connection_after_read(connection);
    }

    connection_s_unlock(connection);

    return r;
}

/* Publish a response that needs no slot of its own reserved in advance — a
 * broadcast frame, or a reply produced straight on the read path. Takes
 * connection_s_lock; use __post_response instead when it is already held.
 *
 * Takes ownership of the response either way: it is freed here on failure. */
int websockets_response_post(websocketsresponse_t* response) {
    connection_t* connection = response->connection;

    connection_s_lock(connection, LOCK_SITE_WS_RESERVE);
    connection_out_slot_t* slot = __out_reserve(connection);
    connection_s_unlock(connection);

    if (slot == NULL) {
        response->base.free(response);
        return 0;
    }

    return __out_publish(connection, slot, response);
}

static int __handle_locked(connection_t* connection, websocketsparser_t* parser) {
    connection_s_lock(connection, LOCK_SITE_WS_READ);
    const int r = __handle(parser);
    connection_s_unlock(connection);

    return r;
}

static int __post_close_default_locked(connection_t* connection, unsigned short status_code, const char* reason) {
    connection_s_lock(connection, LOCK_SITE_WS_READ);
    const int r = __post_close_default(connection, status_code, reason);
    connection_s_unlock(connection);

    return r;
}

int websockets_guard_read(connection_t* connection) {
    return __read(connection);
}

int websockets_guard_write(connection_t* connection) {
    connection_s_lock(connection, LOCK_SITE_WS_WRITE);
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
                    return __post_close_default_locked(connection, 1009, "Payload large");
                case WSPARSER_BAD_REQUEST:
                    return __post_close_default_locked(connection, 1002, "Bad request");
                case WSPARSER_CONTINUE:
                    goto read_data;
                case WSPARSER_HANDLE_AND_CONTINUE:
                {
                    if (!__handle_locked(connection, parser))
                        return 0;

                    websocketsparser_prepare_remains(parser);
                    break;
                }
                case WSPARSER_COMPLETE:
                {
                    if (!__handle_locked(connection, parser))
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

/* Push one staged response out. Returns 1 when the whole frame has left, 0 on a
 * fatal error, -1 when the socket took only part of it and the rest has to wait
 * for the next EPOLLOUT. */
static int __write_staged(connection_t* connection, websocketsresponse_t* response) {
    /* A handler is allowed not to reply (push-style flows): finish the write
     * phase as a no-op — closing here punished every silent handler. */
    if (response->body.data == NULL)
        return 1;

    // body
    if (response->body.pos < response->body.size) {
        size_t size = response->body.size - response->body.pos;

        if (size > connection->buffer_size)
            size = connection->buffer_size;

        const ssize_t writed = connection_data_write(connection, &response->body.data[response->body.pos], size);

        /* EAGAIN/EINTR are not fatal: the socket buffer is full (the peer is
         * slow), the event loop will call us again on the next EPOLLOUT. */
        if (writed < 0)
            return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? -1 : 0;

        response->body.pos += writed;

        /* A short write leaves the tail of the frame unsent: finishing here
         * (falling through to connection_after_write) would truncate it. */
        if (response->body.pos < response->body.size) return -1;
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
            return errno == EINTR ? -1 : 0;
        if (readed == 0)
            return 0;

        const ssize_t writed = connection_data_write(connection, connection->buffer, (size_t)readed);

        if (writed < 0)
            return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? -1 : 0;

        response->file_.pos += writed;

        if (response->file_.pos < response->file_.size) return -1;
    }

    return 1;
}

int __write(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    /* A write event with nothing staged and nothing pending (spurious EPOLLOUT,
     * a handler that never called send_*) must not dereference NULL. A head
     * that exists but is not filled yet is a different case: it is not spurious
     * and not an error — fall through and re-arm for reading, the handler
     * filling it will ask for EPOLLOUT again. */
    if (__out_idle(ctx))
        return 0;

    /* Drain as far as the output order allows: everything already filled goes
     * out in one pass, which is what keeps N parallel handlers from costing N
     * event-loop turns. */
    while (ctx->response != NULL || __out_promote(connection)) {
        const int r = __write_staged(connection, ctx->response);
        if (r == 0) return 0;
        if (r < 0) return 1; /* stays staged for the next EPOLLOUT */

        __out_finish_current(connection);

        /* A CLOSE frame just left; anything behind it is moot. */
        if (connection->keepalive == 0)
            break;
    }

    return connection_after_write(connection);
}

int __handle(websocketsparser_t* parser) {
    connection_t* connection = parser->connection;

    /* Handle control frames (FIN=1 already validated in parser) */
    switch (parser->frame.opcode) {
    case WSOPCODE_CLOSE:
    {
        websocketsresponse_t* response = websocketsresponse_create(connection);
        if (response == NULL) return 0;
        websocketsresponse_close(response, bufferdata_get(&parser->buf), bufferdata_writed(&parser->buf));
        connection->keepalive = 0;
        return __post_response(response);
    }
    case WSOPCODE_PING:
    {
        websocketsresponse_t* response = websocketsresponse_create(connection);
        if (response == NULL) return 0;
        websocketsresponse_pong(response, bufferdata_get(&parser->buf), bufferdata_writed(&parser->buf));
        return __post_response(response);
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

    /* The two reasons for a 0 need different answers, and `destroyed` is what
     * tells them apart. A rejected dispatch already took this message's place
     * in the output order and cannot fill it, so replying "resource not found"
     * would only queue a frame behind a slot nobody will ever complete. */
    connection_server_ctx_t* ctx = connection->ctx;
    if (atomic_load(&ctx->destroyed))
        return 0;

    websocketsresponse_t* response = websocketsresponse_create(connection);
    if (response == NULL) return 0;

    websocketsresponse_default(response, "resource not found");

    return __post_response(response);
}

/* The critical section is narrow (docs/concurrency/00 §5.1): the lock guards
 * the connection's output order, not the user's handler. While this runs,
 * another worker may be running another message of this same connection — the
 * point of phase C. The reply goes into the slot reserved for this message at
 * dispatch time, so parallel handlers cannot reorder the stream. */
void websockets_queue_request_handler(void* arg) {
    connection_queue_item_t* item = arg;
    connection_queue_websockets_data_t* data = (connection_queue_websockets_data_t*)item->data;
    connection_t* connection = item->connection;

    /* Disowned by a failed dispatch (websockets_deferred_handler): the request
     * went back to the read path and the connection is already on its way down.
     * Nothing to run and nothing to reply with. */
    if (data->request == NULL)
        return;

    websocketsresponse_t* response = websocketsresponse_create(connection);
    if (response == NULL) {
        /* The slot stays unfilled and would block the output order forever, so
         * the connection has to go: there is no reply to send and no way to
         * skip a place in the stream. */
        connection_server_ctx_t* conn_ctx = connection->ctx;
        atomic_store(&conn_ctx->destroyed, 1);

        connection_s_lock(connection, LOCK_SITE_WS_PUBLISH);
        connection_after_read(connection);
        connection_s_unlock(connection);
        return;
    }

    if (!ratelimiter_allow(data->ratelimiter, connection->remote_ip, 1)) {
        websocketsresponse_default(response, "Too Many Requests");
        __out_publish(connection, data->out, response);
        return;
    }

    /* --- user code: middlewares and the route handler, no lock held --- */
    wsctx_t ctx;
    wsctx_init(&ctx, data->request, response);

    if (run_middlewares(data->server->websockets.middleware, &ctx))
        item->handle(&ctx);

    wsctx_clear(&ctx);

    __out_publish(connection, data->out, response);
}

void* websockets_queue_data_request_create(connection_t* connection, void* component, ratelimiter_t* ratelimiter) {
    connection_queue_websockets_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    connection_server_ctx_t* ctx = connection->ctx;

    data->base.free = __queue_data_request_free;
    data->request = component;
    data->connection = connection;
    data->ratelimiter = ratelimiter;
    data->server = ctx->server;
    /* Reserved here, before the item is handed to a worker: the output order
     * has to be the order messages were dispatched in, and this is the last
     * point at which the read path is still the only thread involved. */
    data->out = __out_reserve(connection);

    if (data->out == NULL) {
        free(data);
        return NULL;
    }

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

/* Post a reply produced on the read path (a PONG, a CLOSE, "resource not
 * found"). The caller already holds connection_s_lock, and connection_s_lock is
 * not recursive — so this is the flavour that does not take it. Takes ownership
 * of the response.
 *
 * It used to matter whether ctx->queue was empty: with one response slot on the
 * connection, a reply produced while a handler was pending had to be deferred
 * to a worker so it would not clobber the handler's. The output queue keeps the
 * order by itself now, so every reply takes the same path. */
int __post_response(websocketsresponse_t* response) {
    connection_t* connection = response->connection;
    connection_server_ctx_t* ctx = connection->ctx;

    connection_out_slot_t* slot = __out_reserve(connection);
    if (slot == NULL) {
        response->base.free(response);
        return 0;
    }

    slot->response = &response->base;

    if (!__out_promote(connection))
        return 1; /* queued behind a handler that has not replied yet */

    atomic_store_explicit(&ctx->need_write, 1, memory_order_release);

    return connection_after_read(connection);
}

/* permessage-deflate (RFC 7692) is negotiated per connection and, with context
 * takeover, compresses every outgoing message against one sliding window. That
 * z_stream lives on the parser and is shared by every response of the
 * connection, and the order it is fed in has to match the order the frames
 * reach the wire — neither survives handlers running in parallel. Compression
 * happens inside send_*, i.e. in the handler, so the only honest answer for now
 * is to keep compressed connections serialized. Moving framing and compression
 * into the (ordered, single-threaded) write path would lift this; see phase C
 * in docs/concurrency/00. */
static int __fanout_allowed(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    const websocketsparser_t* parser = ctx->parser;

    return parser != NULL && !parser->ws_deflate_enabled;
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

    const int parallel = __fanout_allowed(connection);

    cqueue_lock(ctx->queue);
    const int queue_empty = cqueue_empty(ctx->queue);
    const int appended = cqueue_append(ctx->queue, item);
    cqueue_unlock(ctx->queue);

    if (!appended) {
        connection_queue_websockets_data_t* data = (connection_queue_websockets_data_t*)item->data;
        data->request = NULL;
        item->free(item);
        return 0;
    }

    if (!parallel && !queue_empty)
        return 1;

    if (parallel ? !connection_queue_append_parallel(item) : !connection_queue_append(item)) {
        /* Either way the request goes back to the caller — that is the contract
         * for a 0 — so the item must stop pointing at it. */
        connection_queue_websockets_data_t* data = (connection_queue_websockets_data_t*)item->data;
        data->request = NULL;

        /* In the serialized case the item was appended to an empty queue, so the
         * head is this item and unlinking it is safe. Under fan-out it is not:
         * cqueue has no removal by identity and the head need not be the item
         * just appended. The item stays in the queue with no request, the
         * connection goes down on the caller's 0, and __ctx_free drains it —
         * the runner recognizes a disowned item and does nothing. */
        if (!parallel) {
            cqueue_pop(ctx->queue);
            item->free(item);
        }
        else
            atomic_store(&ctx->destroyed, 1);

        return 0;
    }

    return 1;
}

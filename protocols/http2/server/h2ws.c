#include "h2ws.h"

#include <stdlib.h>

#include "broadcast.h"
#include "connection_s.h"
#include "h2session.h"
#include "log.h"
#include "websocketscommon.h"
#include "websocketsprotocoldefault.h"
#include "websocketsprotocolresource.h"
#include "websocketsrequest.h"
#include "websocketsserverhandlers.h"

h2_ws_tunnel_t* h2_ws_tunnel_create(connection_t* connection, int resource_protocol) {
    h2_ws_tunnel_t* tunnel = calloc(1, sizeof(*tunnel));
    if (tunnel == NULL) return NULL;

    /* Same choice the HTTP/1.1 handshake makes from Sec-WebSocket-Protocol
     * (websocketsswitch.c): "resource" routes each message by its own
     * method+location, the default protocol sends everything to one handler. */
    tunnel->connection = connection;
    tunnel->parser = websocketsparser_create(connection, resource_protocol ?
                                             websockets_protocol_resource_create :
                                             websockets_protocol_default_create);
    tunnel->out = cqueue_create();
    if (tunnel->parser == NULL || tunnel->out == NULL) {
        h2_ws_tunnel_free(tunnel);
        return NULL;
    }

    h2_data_writer_reset(&tunnel->writer);

    return tunnel;
}

void h2_ws_tunnel_free(h2_ws_tunnel_t* tunnel) {
    if (tunnel == NULL) return;

    /* Unsubscribe before anything is released: a fan-out in flight would
     * otherwise publish into this tunnel's queue after it is gone. The
     * connection may well live on — only this stream is ending — so
     * broadcast_clear() would be both too much and too late. */
    if (tunnel->connection != NULL)
        broadcast_clear_owner(tunnel->connection, tunnel);

    if (tunnel->parser != NULL)
        tunnel->parser->base.free(tunnel->parser);

    /* Frames the peer will never receive. A slot may still be empty — its
     * handler never came back — and both the slot and whatever it holds belong
     * to the tunnel. */
    if (tunnel->out != NULL) {
        cqueue_lock(tunnel->out);
        connection_out_slot_t* slot;
        while ((slot = cqueue_pop(tunnel->out)) != NULL) {
            if (slot->response != NULL)
                slot->response->free(slot->response);
            free(slot);
        }
        cqueue_unlock(tunnel->out);
        cqueue_free(tunnel->out);
    }

    if (tunnel->writing != NULL)
        tunnel->writing->base.free(tunnel->writing);

    free(tunnel);
}

/* Queue an answer the read path produced itself (a control frame). Reserving
 * and filling in one go keeps it in the right place relative to the data
 * messages around it, whose handlers may still be running. */
static int h2_ws_queue_now(h2_ws_tunnel_t* tunnel, websocketsresponse_t* response) {
    if (response == NULL) return 0;

    connection_out_slot_t* slot = __out_reserve_in(tunnel->out);
    if (slot == NULL) {
        response->base.free(response);
        return 0;
    }

    slot->response = &response->base;

    return 1;
}

int h2_ws_tunnel_has_output(const h2_ws_tunnel_t* tunnel) {
    if (tunnel == NULL) return 0;
    if (tunnel->writing != NULL) return 1;
    if (tunnel->out == NULL) return 0;

    /* Only a *filled* head counts. An empty head is a handler still running,
     * and its message's place in the stream is already taken — waiting is what
     * keeps replies in order (docs/concurrency/00 §4.4, per tunnel here). */
    cqueue_t* out = (cqueue_t*)tunnel->out;
    cqueue_lock(out);
    cqueue_item_t* first = cqueue_first(out);
    const connection_out_slot_t* slot = first != NULL ? first->data : NULL;
    const int ready = slot != NULL && slot->response != NULL;
    cqueue_unlock(out);

    return ready;
}

/* A handler thread finished and filled a slot: make the worker write it. Runs
 * under connection_s_lock, taken by the publisher. */
static int h2_ws_wake(connection_t* connection, void* owner) {
    connection_server_ctx_t* ctx = connection->ctx;
    (void)owner;

    atomic_store_explicit(&ctx->need_write, 1, memory_order_release);

    return connection_after_read(connection);
}

h2_data_status_e h2_ws_tunnel_write(h2session_t* s, h2stream_t* stream) {
    h2_ws_tunnel_t* tunnel = stream->ws;

    for (;;) {
        if (tunnel->writing == NULL) {
            /* Take the head only once it is filled: an unfilled head is a
             * handler still running, and skipping it would reorder the stream. */
            cqueue_lock(tunnel->out);
            cqueue_item_t* first = cqueue_first(tunnel->out);
            connection_out_slot_t* slot = first != NULL ? first->data : NULL;
            const int ready = slot != NULL && slot->response != NULL;
            if (ready) cqueue_pop(tunnel->out);
            cqueue_unlock(tunnel->out);

            if (!ready) return H2_DATA_DRAINED;

            tunnel->writing = (websocketsresponse_t*)slot->response;
            free(slot);

            h2_data_writer_reset(&tunnel->writer);
        }

        websocketsresponse_t* response = tunnel->writing;

        /* A transient view of the WebSocket frame bytes, so the shared DATA
         * framing can work on them without knowing what a websockets_body_t is.
         * Position is carried back out: a frame that stops on a full socket
         * resumes exactly where it stopped. */
        bufo_t view = {0};
        view.data = response->body.data;
        view.size = response->body.size;
        view.pos = response->body.pos;
        view.capacity = response->body.size;
        /* END_STREAM only ever rides a CLOSE frame. Any other frame ending the
         * stream would shut the tunnel the client is still using. */
        view.is_last = (response->frame_code == WEBSOCKETS_CLOSE) ? 1 : 0;

        const h2_data_status_e st = h2_data_write(&tunnel->writer, s, stream, &view);

        response->body.pos = view.pos;

        if (st != H2_DATA_DRAINED) return st;

        if (response->frame_code == WEBSOCKETS_CLOSE)
            tunnel->close_sent = 1;

        response->base.free(response);
        tunnel->writing = NULL;

        if (tunnel->close_sent) return H2_DATA_DRAINED;
    }
}

/* One complete WebSocket frame has been parsed.
 *
 * Control frames are answered here, exactly as websocketsserverhandlers.c
 * __handle answers them on the HTTP/1.1 path — the difference is only where the
 * reply goes: this tunnel's queue rather than the connection's. Data frames
 * still have nowhere to go until handlers are wired up (step 4), so they are
 * logged and dropped.
 *
 * The request is freed for the same reason __handle frees it when no route
 * matches — ownership never left the parser, and the parser drops its pointer
 * on reset without freeing, so not freeing it leaks one request per message. */
static int h2_ws_message_seen(h2_ws_tunnel_t* tunnel, connection_t* connection) {
    websocketsparser_t* parser = tunnel->parser;
    int ok = 1;

    tunnel->messages++;

    switch (parser->frame.opcode) {
    case WSOPCODE_CLOSE: {
        /* Echo the close and stop: END_STREAM rides the reply out, and this
         * stream is finished (the full lifecycle is step 7). */
        websocketsresponse_t* response = websocketsresponse_create(connection);
        if (response != NULL) {
            websocketsresponse_close(response, bufferdata_get(&parser->buf),
                                     bufferdata_writed(&parser->buf));
            ok = h2_ws_queue_now(tunnel, response);
        }
        break;
    }
    case WSOPCODE_PING: {
        websocketsresponse_t* response = websocketsresponse_create(connection);
        if (response != NULL) {
            websocketsresponse_pong(response, bufferdata_get(&parser->buf),
                                    bufferdata_writed(&parser->buf));
            ok = h2_ws_queue_now(tunnel, response);
        }
        break;
    }
    case WSOPCODE_PONG:
        break; /* answer to our own ping; nothing is owed */

    default:
        /* A data message. Only complete ones are dispatched — the HTTP/1.1 path
         * has the same rule, fragments accumulate until FIN. */
        if (!parser->frame.fin) return 1;
        if (parser->request == NULL) return 1;

        /* Bind the reply to this tunnel before routing. get_resource() reaches
         * the same dispatch machinery the HTTP/1.1 path uses; these four fields
         * are the whole difference, and they are what stops it reaching for the
         * connection's output queue (docs/http2/09, step 4). */
        parser->request->out_queue = tunnel->out;
        parser->request->out_owner = tunnel;
        parser->request->out_wake = h2_ws_wake;
        /* permessage-deflate is still a per-tunnel z_stream written inside the
         * handler, so a compressed tunnel keeps its handlers serialized —
         * exactly the limitation docs/concurrency/00 phase C records. */
        parser->request->out_parallel = !parser->ws_deflate_enabled;

        if (parser->request->protocol->get_resource(connection, parser->request)) {
            /* Dispatched: the queue item owns the request now. The parser drops
             * its pointer on reset without freeing, so nothing is done here. */
            return 1;
        }

        /* No route matched, or the queue refused it: ownership never left the
         * parser and the request has to be released, or every message to an
         * unknown route leaks one. */
        break;
    }

    if (parser->request != NULL) {
        websocketsrequest_free(parser->request);
        parser->request = NULL;
    }

    return ok;
}

int h2_ws_tunnel_feed(h2_ws_tunnel_t* tunnel, connection_t* connection,
                      uint8_t* data, size_t len) {
    websocketsparser_t* parser = tunnel->parser;

    if (len == 0) return 1;

    /* Point the parser at this DATA payload and treat it as one read. The
     * buffer belongs to the HTTP/2 frame parser and is reused by the next
     * frame, which is fine: everything the parser keeps across calls it has
     * already copied into its own storage (the control-frame buffer, or the
     * request payload) — see websocketsparser_parse_payload. */
    parser->buffer = (char*)data;
    websocketsparser_set_bytes_readed(parser, len);
    parser->pos_start = 0;
    parser->pos = 0;

    /* The loop mirrors websocketsserverhandlers.c __read, minus the socket: a
     * DATA payload is what a recv() gives that path. */
    for (;;) {
        switch (websocketsparser_run(parser)) {
        case WSPARSER_CONTINUE:
            /* The frame is not complete; the rest arrives in a later DATA. */
            return 1;

        case WSPARSER_HANDLE_AND_CONTINUE:
            if (!h2_ws_message_seen(tunnel, connection)) return 0;
            websocketsparser_prepare_remains(parser);
            break;

        case WSPARSER_COMPLETE:
            if (!h2_ws_message_seen(tunnel, connection)) return 0;
            websocketsparser_reset(parser);
            return 1;

        case WSPARSER_PAYLOAD_LARGE:
            log_error("h2 ws tunnel: payload too large\n");
            return 0;

        case WSPARSER_BAD_REQUEST:
            log_error("h2 ws tunnel: malformed WebSocket frame\n");
            return 0;

        default:
            log_error("h2 ws tunnel: parser error\n");
            return 0;
        }
    }
}

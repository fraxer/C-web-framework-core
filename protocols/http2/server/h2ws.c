#include "h2ws.h"

#include <stdlib.h>

#include "h2session.h"
#include "log.h"
#include "websocketscommon.h"
#include "websocketsprotocoldefault.h"
#include "websocketsrequest.h"

h2_ws_tunnel_t* h2_ws_tunnel_create(connection_t* connection) {
    h2_ws_tunnel_t* tunnel = calloc(1, sizeof(*tunnel));
    if (tunnel == NULL) return NULL;

    /* The default protocol for now. Choosing between default and resource by
     * Sec-WebSocket-Protocol is step 4, where the message actually reaches a
     * handler and the choice starts to mean something. */
    tunnel->parser = websocketsparser_create(connection, websockets_protocol_default_create);
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

    if (tunnel->parser != NULL)
        tunnel->parser->base.free(tunnel->parser);

    /* Frames the peer will never receive: the tunnel owns everything still
     * queued, and the queue owns nothing, so both have to be released here. */
    if (tunnel->out != NULL) {
        cqueue_lock(tunnel->out);
        websocketsresponse_t* response;
        while ((response = cqueue_pop(tunnel->out)) != NULL)
            response->base.free(response);
        cqueue_unlock(tunnel->out);
        cqueue_free(tunnel->out);
    }

    if (tunnel->writing != NULL)
        tunnel->writing->base.free(tunnel->writing);

    free(tunnel);
}

/* Queue one response for this tunnel. Takes ownership either way. */
static int h2_ws_queue(h2_ws_tunnel_t* tunnel, websocketsresponse_t* response) {
    if (response == NULL) return 0;

    cqueue_lock(tunnel->out);
    const int ok = cqueue_append(tunnel->out, response);
    cqueue_unlock(tunnel->out);

    if (!ok) {
        response->base.free(response);
        return 0;
    }

    return 1;
}

int h2_ws_tunnel_has_output(const h2_ws_tunnel_t* tunnel) {
    if (tunnel == NULL) return 0;
    if (tunnel->writing != NULL) return 1;
    if (tunnel->out == NULL) return 0;

    cqueue_t* out = (cqueue_t*)tunnel->out;
    cqueue_lock(out);
    const int empty = cqueue_empty(out);
    cqueue_unlock(out);

    return !empty;
}

h2_data_status_e h2_ws_tunnel_write(h2session_t* s, h2stream_t* stream) {
    h2_ws_tunnel_t* tunnel = stream->ws;

    for (;;) {
        if (tunnel->writing == NULL) {
            cqueue_lock(tunnel->out);
            tunnel->writing = cqueue_pop(tunnel->out);
            cqueue_unlock(tunnel->out);

            if (tunnel->writing == NULL) return H2_DATA_DRAINED;

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
            ok = h2_ws_queue(tunnel, response);
        }
        break;
    }
    case WSOPCODE_PING: {
        websocketsresponse_t* response = websocketsresponse_create(connection);
        if (response != NULL) {
            websocketsresponse_pong(response, bufferdata_get(&parser->buf),
                                    bufferdata_writed(&parser->buf));
            ok = h2_ws_queue(tunnel, response);
        }
        break;
    }
    case WSOPCODE_PONG:
        break; /* answer to our own ping; nothing is owed */
    default:
        log_info("h2 ws tunnel: frame opcode=0x%x fin=%d payload=%llu (message %llu, dropped — "
                 "dispatch is step 4)\n",
                 (unsigned)parser->frame.opcode, (int)parser->frame.fin,
                 (unsigned long long)parser->frame.payload_length,
                 (unsigned long long)tunnel->messages);
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

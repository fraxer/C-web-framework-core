#include "h2ws.h"

#include <stdlib.h>

#include "log.h"
#include "websocketsprotocoldefault.h"
#include "websocketsrequest.h"

h2_ws_tunnel_t* h2_ws_tunnel_create(connection_t* connection) {
    h2_ws_tunnel_t* tunnel = calloc(1, sizeof(*tunnel));
    if (tunnel == NULL) return NULL;

    /* The default protocol for now. Choosing between default and resource by
     * Sec-WebSocket-Protocol is step 4, where the message actually reaches a
     * handler and the choice starts to mean something. */
    tunnel->parser = websocketsparser_create(connection, websockets_protocol_default_create);
    if (tunnel->parser == NULL) {
        free(tunnel);
        return NULL;
    }

    return tunnel;
}

void h2_ws_tunnel_free(h2_ws_tunnel_t* tunnel) {
    if (tunnel == NULL) return;

    if (tunnel->parser != NULL)
        tunnel->parser->base.free(tunnel->parser);

    free(tunnel);
}

/* Step 2 stands in for the handler: report what arrived and drop it.
 *
 * The request is freed here for the same reason websocketsserverhandlers.c
 * frees it when no route matches — ownership never left the parser, and the
 * parser drops its pointer on reset without freeing, so not freeing it leaks
 * one request per message. */
static void h2_ws_message_seen(h2_ws_tunnel_t* tunnel) {
    websocketsparser_t* parser = tunnel->parser;

    tunnel->messages++;

    log_info("h2 ws tunnel: frame opcode=0x%x fin=%d payload=%llu (message %llu, dropped — "
             "dispatch is step 4)\n",
             (unsigned)parser->frame.opcode, (int)parser->frame.fin,
             (unsigned long long)parser->frame.payload_length,
             (unsigned long long)tunnel->messages);

    if (parser->request != NULL) {
        websocketsrequest_free(parser->request);
        parser->request = NULL;
    }
}

int h2_ws_tunnel_feed(h2_ws_tunnel_t* tunnel, uint8_t* data, size_t len) {
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
            h2_ws_message_seen(tunnel);
            websocketsparser_prepare_remains(parser);
            break;

        case WSPARSER_COMPLETE:
            h2_ws_message_seen(tunnel);
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

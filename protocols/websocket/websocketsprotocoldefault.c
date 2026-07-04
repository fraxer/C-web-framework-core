#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "websocketsserverhandlers.h"
#include "websocketsprotocoldefault.h"
#include "websocketsresponse.h"
#include "websocketsparser.h"
#include "websocketsswitch.h"
#include "appconfig.h"

int websocketsrequest_get_default(connection_t* connection, websocketsrequest_t* request);
void websockets_protocol_default_reset(void*);
void websockets_protocol_default_free(void*);
int websockets_protocol_default_payload_parse(websocketsparser_t* parser, char* data, size_t size, int unmasking);

websockets_protocol_t* websockets_protocol_default_create(void) {
    websockets_protocol_default_t* protocol = malloc(sizeof * protocol);
    if (protocol == NULL) return NULL;

    protocol->base.payload_parse = websockets_protocol_default_payload_parse;
    protocol->base.get_resource = websocketsrequest_get_default;
    protocol->base.reset = websockets_protocol_default_reset;
    protocol->base.free = websockets_protocol_default_free;
    protocol->get_payload = (char*(*)(websockets_protocol_default_t*))websocketsrequest_payload;
    protocol->get_payload_file = (file_content_t(*)(websockets_protocol_default_t*))websocketsrequest_payload_file;
    protocol->get_payload_json = (json_doc_t*(*)(websockets_protocol_default_t*))websocketsrequest_payload_json;

    websockets_protocol_init_payload((websockets_protocol_t*)protocol);

    return (websockets_protocol_t*)protocol;
}

int websocketsrequest_get_default(connection_t* connection, websocketsrequest_t* request) {
    connection_server_ctx_t* ctx = connection->ctx;

    ratelimiter_t* ratelimiter = ctx->server->websockets.ratelimiter;

    return websockets_deferred_handler(connection, request, websockets_queue_request_handler, ctx->server->websockets.default_handler, websockets_queue_data_request_create, ratelimiter);
}

void websockets_protocol_default_reset(void* protocol) {
    (void)protocol;
}

void websockets_protocol_default_free(void* protocol) {
    websockets_protocol_default_reset(protocol);
    free(protocol);
}

int websockets_protocol_default_payload_parse(websocketsparser_t* parser, char* string, size_t length, int unmasking) {
    websocketsrequest_t* request = parser->request;

    if (unmasking)
        for (size_t i = 0; i < length; i++)
            string[i] ^= parser->frame.mask[parser->payload_index++ % 4];

    /* An empty chunk is a valid call: write(fd, p, 0) below returns 0, which
     * the error check would misread as a failed write and kill the connection. */
    if (length == 0)
        return 1;

    const char* tmp_dir = env()->main.tmp;
    if (!websockets_create_tmpfile(request->protocol, tmp_dir))
        return 0;

    /* A failed lseek returns -1, which the unsigned comparison below would
     * fold into length - 1 and wave past the body-size limit. */
    off_t payloadlength = lseek(request->protocol->payload.fd, 0, SEEK_END);
    if (payloadlength < 0)
        return 0;

    if ((size_t)payloadlength + length > env()->main.client_max_body_size)
        return 0;

    /* A single write may legally be short (EINTR, ENOSPC, rlimit); accepting
     * a partial write here silently truncated the message handed to the
     * handler, so write until every byte of the chunk is on disk. */
    size_t written = 0;
    while (written < length) {
        const ssize_t r = write(request->protocol->payload.fd, string + written, length - written);

        if (r < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if (r == 0)
            return 0;

        written += (size_t)r;
    }

    lseek(request->protocol->payload.fd, 0, SEEK_SET);

    return 1;
}

int set_websockets_default(connection_t* connection, void* data) {
    /* Create the replacement parser before touching connection state: the
     * caller (connection_after_write) ignores this function's result, so
     * installing the websocket guards or freeing the old parser first left a
     * connection whose guard read dereferences ctx->parser == NULL. On
     * failure the connection must keep its previous protocol intact. */
    websocketsparser_t* parser = websocketsparser_create(connection, websockets_protocol_default_create);
    if (parser == NULL)
        return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    if (ctx->parser != NULL) {
        requestparser_t* old_parser = ctx->parser;
        old_parser->free(old_parser);
    }

    ctx->parser = parser;
    connection->read = websockets_guard_read;
    connection->write = websockets_guard_write;

    /* Initialize deflate if negotiated during handshake */
    ws_handshake_data_t* handshake_data = data;
    if (handshake_data != NULL && handshake_data->deflate_enabled) {
        parser->ws_deflate.config = handshake_data->deflate_config;
        if (ws_deflate_start(&parser->ws_deflate)) {
            parser->ws_deflate_enabled = 1;
        }
        else
            /* Degrade, but not silently: the 101 response already advertised
             * permessage-deflate, so every compressed message from this client
             * will now be rejected as a bad request. */
            log_error("set_websockets_default: ws_deflate_start failed, compressed frames will be rejected\n");
    }

    return 1;
}

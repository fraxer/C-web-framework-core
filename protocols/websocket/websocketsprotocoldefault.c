#include <string.h>

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

    const char* tmp_dir = env()->main.tmp;
    if (!websockets_create_tmpfile(request->protocol, tmp_dir))
        return 0;

    off_t payloadlength = lseek(request->protocol->payload.fd, 0, SEEK_END);
    if (payloadlength + length > env()->main.client_max_body_size)
        return 0;

    int r = write(request->protocol->payload.fd, string, length);
    lseek(request->protocol->payload.fd, 0, SEEK_SET);
    if (r <= 0) return 0;
    
    return 1;
}

int set_websockets_default(connection_t* connection, void* data) {
    connection->read = websockets_guard_read;
    connection->write = websockets_guard_write;

    connection_server_ctx_t* ctx = connection->ctx;

    if (ctx->parser != NULL) {
        requestparser_t* parser = ctx->parser;
        parser->free(parser);
    }

    ctx->parser = websocketsparser_create(connection, websockets_protocol_default_create);
    if (ctx->parser == NULL)
        return 0;

    /* Initialize deflate if negotiated during handshake */
    ws_handshake_data_t* handshake_data = data;
    if (handshake_data != NULL && handshake_data->deflate_enabled) {
        websocketsparser_t* parser = ctx->parser;
        parser->ws_deflate.config = handshake_data->deflate_config;
        if (ws_deflate_start(&parser->ws_deflate)) {
            parser->ws_deflate_enabled = 1;
        }
    }

    return 1;
}

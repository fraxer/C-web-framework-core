#include <stdlib.h>

#include "websocketsswitch.h"

void switch_to_websockets(httpctx_t* ctx) {
    const http_header_t* connection  = ctx->request->get_headern(ctx->request, "Connection", 10);
    const http_header_t* upgrade     = ctx->request->get_headern(ctx->request, "Upgrade", 7);
    const http_header_t* ws_version  = ctx->request->get_headern(ctx->request, "Sec-WebSocket-Version", 21);
    const http_header_t* ws_key      = ctx->request->get_headern(ctx->request, "Sec-WebSocket-Key", 17);
    const http_header_t* ws_protocol = ctx->request->get_headern(ctx->request, "Sec-WebSocket-Protocol", 22);
    const http_header_t* ws_extensions = ctx->request->get_headern(ctx->request, "Sec-WebSocket-Extensions", 24);

    if (connection == NULL || upgrade == NULL || ws_version == NULL || ws_key == NULL) {
        ctx->response->send_data(ctx->response, "error connect to web socket");
        return;
    }

    char key[128] = {0};
    const char* magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    strcpy(key, ws_key->value);
    strcat(key, magic_string);

    unsigned char result[40];
    sha1((const unsigned char*)key, strlen(key), result);

    char base64_string[base64_encode_len(20)];
    int retlen = base64_encode(base64_string, (const char*)result, 20);

    ctx->response->add_headern(ctx->response, "Upgrade", 7, "websocket", 9);
    ctx->response->add_headern(ctx->response, "Connection", 10, "Upgrade", 7);
    ctx->response->add_headern(ctx->response, "Sec-WebSocket-Accept", 20, base64_string, retlen);

    connection_t* server_connection = ctx->response->connection;
    connection_server_ctx_t* conn_ctx = server_connection->ctx;

    ws_handshake_data_t* handshake_data = malloc(sizeof * handshake_data);
    if (handshake_data == NULL) {
        ctx->response->send_data(ctx->response, "error connect to web socket");
        return;
    }
    handshake_data->deflate_enabled = 0;

    conn_ctx->switch_to_protocol.fn = set_websockets_default;
    conn_ctx->switch_to_protocol.data = handshake_data;
    conn_ctx->switch_to_protocol.data_free = free;

    if (ws_protocol != NULL && strcmp(ws_protocol->value, "resource") == 0) {
        ctx->response->add_headern(ctx->response, "Sec-WebSocket-Protocol", 22, ws_protocol->value, ws_protocol->value_length);
        conn_ctx->switch_to_protocol.fn = set_websockets_resource;
    }

    /* Negotiate permessage-deflate extension */
    if (ws_extensions != NULL) {
        ws_deflate_config_t deflate_config;
        if (ws_deflate_parse_header(ws_extensions->value, &deflate_config)) {
            handshake_data->deflate_config = deflate_config;
            handshake_data->deflate_enabled = 1;
            char ext_response[256];
            int ext_len = ws_deflate_build_header(&deflate_config, ext_response, sizeof(ext_response));
            if (ext_len > 0) {
                ctx->response->add_headern(ctx->response, "Sec-WebSocket-Extensions", 24, ext_response, ext_len);
            }
        }
    }

    ctx->response->status_code = 101;
    server_connection->keepalive = 1;
}

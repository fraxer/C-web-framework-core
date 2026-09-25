#include <stdlib.h>
#include <strings.h>

#include "websocketsswitch.h"

/* The key is the base64 of 16 bytes (RFC 6455 §4.1 item 7): 22 characters
 * of the alphabet and "==". */
#define WS_KEY_LENGTH 24

static int __is_base64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/';
}

static int __key_valid(const http_header_t* key) {
    if (key == NULL || key->value_length != WS_KEY_LENGTH) return 0;

    for (size_t i = 0; i < WS_KEY_LENGTH - 2; i++)
        if (!__is_base64_char(key->value[i])) return 0;

    return key->value[22] == '=' && key->value[23] == '=';
}

/* A comma-separated list with optional whitespace, compared without case --
 * "Connection: keep-alive, Upgrade" is what Firefox sends. */
static int __has_token(const http_header_t* header, const char* token) {
    if (header == NULL) return 0;

    const size_t token_length = strlen(token);
    const char* p = header->value;
    const char* end = header->value + header->value_length;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) p++;
        const char* start = p;
        while (p < end && *p != ',') p++;
        const char* stop = p;
        while (stop > start && (stop[-1] == ' ' || stop[-1] == '\t')) stop--;

        if ((size_t)(stop - start) == token_length && strncasecmp(start, token, token_length) == 0)
            return 1;
    }

    return 0;
}

static void __refuse(httpctx_t* ctx, int status_code) {
    ctx->response->send_default(ctx->response, status_code);
}

/* RFC 6455 §4.2.1: a handshake that does not match is refused with 400 before
 * anything is switched, and §4.2.2: a version the server does not speak gets
 * 426 with the one it does. The key used to be strcpy'd into a 128-byte stack
 * buffer, so a client sending a key longer than 91 bytes overflowed it; it is
 * checked for its one legal shape now, and only that is ever copied. */
void switch_to_websockets(httpctx_t* ctx) {
    const http_header_t* connection  = ctx->request->get_headern(ctx->request, "Connection", 10);
    const http_header_t* upgrade     = ctx->request->get_headern(ctx->request, "Upgrade", 7);
    const http_header_t* ws_version  = ctx->request->get_headern(ctx->request, "Sec-WebSocket-Version", 21);
    const http_header_t* ws_key      = ctx->request->get_headern(ctx->request, "Sec-WebSocket-Key", 17);
    const http_header_t* ws_protocol = ctx->request->get_headern(ctx->request, "Sec-WebSocket-Protocol", 22);
    const http_header_t* ws_extensions = ctx->request->get_headern(ctx->request, "Sec-WebSocket-Extensions", 24);

    if (!__has_token(upgrade, "websocket") || !__has_token(connection, "upgrade") || !__key_valid(ws_key)) {
        __refuse(ctx, 400);
        return;
    }

    if (ws_version == NULL || ws_version->value_length != 2 || memcmp(ws_version->value, "13", 2) != 0) {
        __refuse(ctx, 426);
        ctx->response->add_headern(ctx->response, "Sec-WebSocket-Version", 21, "13", 2);
        return;
    }

    static const char magic_string[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char key[WS_KEY_LENGTH + sizeof magic_string];
    memcpy(key, ws_key->value, WS_KEY_LENGTH);
    memcpy(key + WS_KEY_LENGTH, magic_string, sizeof magic_string);

    unsigned char result[40];
    sha1((const unsigned char*)key, WS_KEY_LENGTH + sizeof magic_string - 1, result);

    char base64_string[base64_encode_len(20)];
    int retlen = base64_encode(base64_string, (const char*)result, 20);

    /* Before any upgrade field goes on: a 500 must not say "Upgrade". */
    ws_handshake_data_t* handshake_data = malloc(sizeof * handshake_data);
    if (handshake_data == NULL) {
        __refuse(ctx, 500);
        return;
    }
    handshake_data->deflate_enabled = 0;

    ctx->response->add_headern(ctx->response, "Upgrade", 7, "websocket", 9);
    ctx->response->add_headern(ctx->response, "Connection", 10, "Upgrade", 7);
    ctx->response->add_headern(ctx->response, "Sec-WebSocket-Accept", 20, base64_string, retlen);

    connection_t* server_connection = ctx->response->connection;
    connection_server_ctx_t* conn_ctx = server_connection->ctx;

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

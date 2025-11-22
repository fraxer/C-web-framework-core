#include "websockets.h"

void websockets_default_handler(wsctx_t* ctx) {
    if (ctx->request->type == WEBSOCKETS_TEXT) {
        ctx->response->send_text(ctx->response, "");
        return;
    }

    ctx->response->send_binary(ctx->response, "");
}
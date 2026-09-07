#include <stddef.h>

#include "log.h"
#include "appconfig.h"

#include "wscontext.h"

/* Separate from the http one on purpose: an application may well store a
 * different payload on a websocket context than on a request context. */

int wsctx_set_user_data_free(void (*fn)(void*)) {
    appconfig_t* config = appconfig_loading();
    if (config == NULL) {
        log_error_stderr("wsctx_set_user_data_free: called outside app_init() -- there is "
                          "no configuration being built to register the destructor with\n");
        return 0;
    }

    if (config->wsctx_user_data_free != NULL && config->wsctx_user_data_free != fn) {
        log_error_stderr("wsctx_set_user_data_free: a different destructor is already "
                          "registered -- ctx->user_data has one owner, so only one "
                          "application module may claim it\n");
        return 0;
    }

    config->wsctx_user_data_free = fn;

    return 1;
}

void wsctx_init(wsctx_t* ctx, void* request, void* response,
                void (*user_data_free)(void*)) {
    ctx->request = request;
    ctx->response = response;
    ctx->user_data = NULL;
    ctx->user_data_free = user_data_free;
}

void wsctx_set_user_data(wsctx_t* ctx, void* user_data) {
    ctx->user_data = user_data;
}

void wsctx_clear(wsctx_t* ctx) {
    if (ctx->user_data_free != NULL)
        ctx->user_data_free(ctx->user_data);

    ctx->user_data = NULL;
}

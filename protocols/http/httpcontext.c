#include <stddef.h>

#include "log.h"
#include "appconfig.h"

#include "httpcontext.h"

int httpctx_set_user_data_free(void (*fn)(void*)) {
    appconfig_t* config = appconfig_loading();
    if (config == NULL) {
        log_error_stderr("httpctx_set_user_data_free: called outside app_init() -- there is "
                          "no configuration being built to register the destructor with\n");
        return 0;
    }

    if (config->httpctx_user_data_free != NULL && config->httpctx_user_data_free != fn) {
        log_error_stderr("httpctx_set_user_data_free: a different destructor is already "
                          "registered -- ctx->user_data has one owner, so only one "
                          "application module may claim it\n");
        return 0;
    }

    config->httpctx_user_data_free = fn;

    return 1;
}

void httpctx_init(httpctx_t* ctx, void* request, void* response,
                  void (*user_data_free)(void*)) {
    ctx->request = request;
    ctx->response = response;
    ctx->user_data = NULL;
    ctx->user_data_free = user_data_free;
}

void httpctx_set_user_data(httpctx_t* ctx, void* user_data) {
    ctx->user_data = user_data;
}

void httpctx_clear(httpctx_t* ctx) {
    if (ctx->user_data_free != NULL)
        ctx->user_data_free(ctx->user_data);

    ctx->user_data = NULL;
}

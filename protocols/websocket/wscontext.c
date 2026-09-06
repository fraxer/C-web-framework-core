#include <stddef.h>

#include "log.h"

#include "wscontext.h"

/* Separate from the http one on purpose: an application may well store a
 * different payload on a websocket context than on a request context. */
static void (*__user_data_free)(void*) = NULL;

int wsctx_set_user_data_free(void (*fn)(void*)) {
    if (__user_data_free != NULL && __user_data_free != fn) {
        log_error_stderr("wsctx_set_user_data_free: a different destructor is already "
                          "registered -- ctx->user_data has one owner, so only one "
                          "application module may claim it\n");
        return 0;
    }

    __user_data_free = fn;

    return 1;
}

void wsctx_init(wsctx_t* ctx, void* request, void* response) {
    ctx->request = request;
    ctx->response = response;
    ctx->user_data = NULL;
}

void wsctx_set_user_data(wsctx_t* ctx, void* user_data) {
    ctx->user_data = user_data;
}

void wsctx_clear(wsctx_t* ctx) {
    if (__user_data_free != NULL)
        __user_data_free(ctx->user_data);

    ctx->user_data = NULL;
}

#include <stddef.h>

#include "log.h"

#include "httpcontext.h"

/* Set once at startup (app_init), read by every worker afterwards -- so it needs
 * no synchronisation, the same contract as the h2/h3 policy globals. */
static void (*__user_data_free)(void*) = NULL;

int httpctx_set_user_data_free(void (*fn)(void*)) {
    if (__user_data_free != NULL && __user_data_free != fn) {
        log_error_stderr("httpctx_set_user_data_free: a different destructor is already "
                          "registered -- ctx->user_data has one owner, so only one "
                          "application module may claim it\n");
        return 0;
    }

    __user_data_free = fn;

    return 1;
}

void httpctx_init(httpctx_t* ctx, void* request, void* response) {
    ctx->request = request;
    ctx->response = response;
    ctx->user_data = NULL;
}

void httpctx_set_user_data(httpctx_t* ctx, void* user_data) {
    ctx->user_data = user_data;
}

void httpctx_clear(httpctx_t* ctx) {
    if (__user_data_free != NULL)
        __user_data_free(ctx->user_data);

    ctx->user_data = NULL;
}

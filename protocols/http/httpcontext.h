#ifndef __HTTPCONTEXT__
#define __HTTPCONTEXT__

#include "httprequest.h"
#include "httpresponse.h"

typedef struct httpctx {
    httprequest_t* request;
    httpresponse_t* response;
    void* user_data;
} httpctx_t;

void httpctx_init(httpctx_t* ctx, void* request, void* response);
void httpctx_clear(httpctx_t* ctx);

/**
 * Attach an application-owned payload to the request context.
 *
 * The context does not take ownership by itself: it is released by the
 * destructor registered with httpctx_set_user_data_free(), which is what makes
 * the core independent of whatever type the application stores here.
 */
void httpctx_set_user_data(httpctx_t* ctx, void* user_data);

/**
 * Register the destructor httpctx_clear() calls on ctx->user_data.
 *
 * Process-wide and meant to be set once, from the application module's
 * app_init() -- before any request context exists. NULL (the default) means the
 * payload is not freed by the core, which is correct for an application that
 * never sets one: the http client builds contexts too, and never does.
 *
 * There is one destructor per process, so the payload has exactly one owner. A
 * second module trying to claim it with a different function is refused (0) and
 * told so, rather than quietly taking over and leaving the first module's
 * payloads to be freed by the wrong function. Re-registering the SAME function
 * succeeds, which is what makes app_init() safe to re-run on a config reload.
 *
 * @return 1 on success, 0 if another destructor is already registered
 */
int httpctx_set_user_data_free(void (*fn)(void*));

#endif

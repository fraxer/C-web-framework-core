#ifndef __HTTPCONTEXT__
#define __HTTPCONTEXT__

#include "httprequest.h"
#include "httpresponse.h"

typedef struct httpctx {
    httprequest_t* request;
    httpresponse_t* response;
    void* user_data;
    /* The destructor for user_data, taken from the configuration generation this
     * request belongs to. Carried in the context rather than looked up when it
     * is needed, so that a request outliving a reload is still freed by the
     * module that allocated its payload. */
    void (*user_data_free)(void*);
} httpctx_t;

/**
 * `user_data_free` comes from the vhost's configuration
 * (appconfig_t::httpctx_user_data_free) -- server_t carries a link back to it.
 * NULL means the core does not free the payload, which is right for the HTTP
 * client: it builds contexts too and never sets one.
 */
void httpctx_init(httpctx_t* ctx, void* request, void* response,
                  void (*user_data_free)(void*));
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
 * Called from the application module's app_init(), while the configuration that
 * loaded the module is still being built -- and recorded in *that*
 * configuration, not in a global. A rebuilt module registers a different address,
 * and requests still running under the old generation have to keep being freed
 * by the old one (docs/hotreload/01-soname-per-generation.md §3.5).
 *
 * There is one destructor per configuration, so the payload has exactly one
 * owner. A second module of the same generation trying to claim it with a
 * different function is refused (0) and told so, rather than quietly taking over
 * and leaving the first module's payloads to be freed by the wrong function.
 * Re-registering the SAME function succeeds.
 *
 * @return 1 on success, 0 outside module loading or if this generation already
 *         has a different destructor
 */
int httpctx_set_user_data_free(void (*fn)(void*));

#endif

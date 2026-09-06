#ifndef __APPMODULE__
#define __APPMODULE__

#include "json.h"

/**
 * Application modules -- the runtime replacement for the link-time hooks the
 * core used to require from the embedding application (middlewares_init(),
 * httpctx_init/clear, wsctx_init/clear).
 *
 * `main.modules` in the config is an array of shared-object paths, each
 * exporting `int app_init(void)`. They are dlopen'd and initialised before the
 * `servers` section is parsed, because routes reference middlewares by name and
 * the names only exist once the application has registered them.
 *
 * Paths are handed to dlopen() verbatim, exactly like the handler `.so` paths in
 * a route's "file" field, so both are written the same way in one config.
 */
int app_modules_load(const json_token_t* root);

/**
 * Release the module list.
 *
 * The modules themselves are never dlclose'd: the middleware handlers and the
 * context destructors they registered are plain function pointers into their
 * text, held by a running config. Called on shutdown only.
 */
void app_modules_free(void);

#endif

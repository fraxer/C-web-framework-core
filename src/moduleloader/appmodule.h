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
 * Can every path in `main.modules` be loaded, and does each export app_init()?
 *
 * Called from module_loader_config_correct(), which is the phase that refuses a
 * bad configuration while the running one is still serving. Without it a typo in
 * a module path is only found by app_modules_load(), and by then signal_reload()
 * has -- under `reload: hard` -- already shut the listening sockets: the process
 * stays alive and serves nothing, which no supervisor notices.
 *
 * app_init() is deliberately NOT called here. Its failure is an application bug
 * rather than a configuration mistake, and it surfaces on the first start.
 *
 * @return 1 when the section is absent, empty or wholly loadable; 0 otherwise.
 */
int app_modules_check(const json_token_t* root);

/**
 * Release the module list.
 *
 * The modules themselves are never dlclose'd: the middleware handlers and the
 * context destructors they registered are plain function pointers into their
 * text, held by a running config. Called on shutdown only.
 */
void app_modules_free(void);

#endif

#ifndef __APPMODULE__
#define __APPMODULE__

#include "json.h"
#include "appconfig.h"

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
 *
 * A module belongs to the configuration generation that loaded it: rebuilt in
 * place, it is loaded again -- as a copy, under a SONAME of that generation's own
 * (docs/hotreload/01-soname-per-generation.md) -- and the previous one is closed
 * when the last thread of the previous generation is gone.
 */
int app_modules_load(appconfig_t* config, const json_token_t* root);

/**
 * Can every path in `main.modules` be loaded, and does each export app_init()?
 *
 * Called from module_loader_config_correct(), which is the phase that refuses a
 * bad configuration while the running one is still serving. Without it a typo in
 * a module path is only found by app_modules_load(), and by then signal_reload()
 * has -- under `reload: hard` -- already shut the listening sockets: the process
 * stays alive and serves nothing, which no supervisor notices.
 *
 * The modules are opened into `config`, the SONAMEs of this generation are
 * reserved, and app_init() is run -- the whole of what the real pass does, on a
 * throwaway configuration. Anything less would be checking a different program:
 * the handlers loaded next resolve their DT_NEEDED against these very objects,
 * and a route may name a middleware that only the rebuilt module registers.
 *
 * The caller MUST set the middleware registry aside first
 * (middleware_registry_save()): app_init() registers pointers into modules this
 * pass unloads when `config` is freed, and the running configuration must not be
 * left holding them.
 *
 * A consequence worth knowing: app_init() runs twice per reload, once here and
 * once for real. It has always had to be idempotent, and each run starts from an
 * empty registry, so nothing about that changes.
 *
 * @return 1 when the section is absent, empty or wholly loadable; 0 otherwise.
 */
int app_modules_check(appconfig_t* config, const json_token_t* root);

/**
 * Close this generation's modules and release the list.
 *
 * Called from appconfig_clear(), that is, once the last thread of the generation
 * has gone: until then a worker may still be inside a middleware from one of
 * them, and the function pointers the module registered are held by the
 * configuration being torn down.
 */
void app_modules_free(app_module_t* modules);

#endif

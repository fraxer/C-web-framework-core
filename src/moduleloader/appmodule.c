#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "appmodule.h"


typedef struct app_module {
    char* path;
    void* handle;
    struct app_module* next;
} app_module_t;

/* Loaded once per process and kept for its lifetime. A reload re-runs app_init()
 * against the cleared middleware registry, but does not re-dlopen: old-generation
 * workers may still be executing a middleware from this module, so unmapping it
 * is never safe. Rebuilt application modules therefore need a restart, not a
 * reload -- the same constraint handler .so files carry. */
static app_module_t* __modules = NULL;

static app_module_t* __app_module_find(const char* path) {
    for (app_module_t* module = __modules; module != NULL; module = module->next)
        if (strcmp(module->path, path) == 0)
            return module;

    return NULL;
}

static void* __app_module_open(const char* path) {
    app_module_t* module = __app_module_find(path);
    if (module != NULL)
        return module->handle;

    /* RTLD_NOW: app_init() is about to be called and the module's unresolved
     * framework symbols must be diagnosed here, with the path in hand, rather
     * than as a lazy-binding abort in a worker.
     *
     * RTLD_LOCAL, deliberately: with several modules loaded, RTLD_GLOBAL makes
     * the first one win every name they happen to share -- a second module's
     * own user_create() would silently bind to the first module's, with no
     * diagnostic anywhere. Local scope is not a loss, because it is not what
     * lets handlers reach the module: a handler .so records libapp.so in
     * DT_NEEDED, and the loader satisfies that from the already-loaded object by
     * SONAME regardless of the scope it was opened in. */
    void* handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        log_error_stderr("app_modules_load: can't load module %s: %s\n", path, dlerror());
        return NULL;
    }

    module = malloc(sizeof * module);
    if (module == NULL) {
        log_error_stderr("app_modules_load: memory alloc error\n");
        dlclose(handle);
        return NULL;
    }

    module->path = strdup(path);
    if (module->path == NULL) {
        log_error_stderr("app_modules_load: memory alloc error\n");
        free(module);
        dlclose(handle);
        return NULL;
    }

    module->handle = handle;
    module->next = __modules;
    __modules = module;

    return handle;
}

static int __app_module_init(const char* path) {
    void* handle = __app_module_open(path);
    if (handle == NULL)
        return 0;

    int (*app_init)(void);
    *(void**)(&app_init) = dlsym(handle, "app_init");
    if (app_init == NULL) {
        log_error_stderr("app_modules_load: module %s exports no app_init()\n", path);

        /* The shape of the mistake this framework version is most likely to
         * meet: a module carried over from the link-time hook the core used to
         * call. Nothing calls middlewares_init() any more, so without saying so
         * the failure would surface much later, as an unrelated-looking
         * "failed to find middleware <name>" while the config is parsed. */
        if (dlsym(handle, "middlewares_init") != NULL)
            log_error_stderr("app_modules_load: %s exports middlewares_init(), which the "
                      "framework no longer calls -- rename it to app_init() and add "
                      "the httpctx_set_user_data_free()/wsctx_set_user_data_free() "
                      "calls that replaced httpctx_init/clear and wsctx_init/clear\n",
                      path);

        return 0;
    }

    if (!app_init()) {
        log_error_stderr("app_modules_load: app_init() failed in %s\n", path);
        return 0;
    }

    return 1;
}

/* Walk main.modules, handing each path to `apply`. The section is optional and
 * an application with no modules at all is a valid configuration, so an absent
 * one is success; a malformed one is not. */
static int __app_modules_foreach(const json_token_t* root, const char* who, int (*apply)(const char*)) {
    const json_token_t* token_main = json_object_get(root, "main");
    if (token_main == NULL || !json_is_object(token_main))
        return 1;

    const json_token_t* token_modules = json_object_get(token_main, "modules");
    if (token_modules == NULL)
        return 1;

    if (!json_is_array(token_modules)) {
        log_error_stderr("%s: main.modules must be array\n", who);
        return 0;
    }

    json_it_t it = json_init_it(token_modules);
    if (!it.ok) {
        log_error_stderr("%s: memory alloc error for main.modules\n", who);
        return 0;
    }

    for (; !json_end_it(&it); it = json_next_it(&it)) {
        const json_token_t* token_path = json_it_value(&it);
        if (!json_is_string(token_path)) {
            log_error_stderr("%s: main.modules items must be strings\n", who);
            return 0;
        }
        if (json_string_size(token_path) == 0) {
            log_error_stderr("%s: main.modules items must be not empty\n", who);
            return 0;
        }

        if (!apply(json_string(token_path)))
            return 0;
    }

    return 1;
}

/* Can this path be loaded at all, and does it export app_init()?
 *
 * Answered without calling app_init(), and without keeping the module: this
 * runs from module_loader_config_correct(), whose whole job is to reject a bad
 * configuration while the running one is still serving. app_modules_load()
 * itself is far too late for that -- see docs/hotreload/00-shadow-copy.md §4.
 *
 * A module this process has already loaded needs no check: it is running, so it
 * loaded and its app_init() returned success. Everything else -- a new entry in
 * main.modules, and every entry at all if the check is run before anything is
 * loaded -- is opened here and closed again, which means a newly added module
 * has its ELF constructors run once more than it otherwise would. That is the
 * price of finding out before the old generation is gone, and it is only paid
 * for modules that are not loaded yet.
 *
 * What deliberately stays fatal is app_init() returning 0. That is a bug in the
 * application, not a mistake in the configuration, and it shows up on the first
 * start rather than on some later reload. */
static int __app_module_check(const char* path) {
    if (__app_module_find(path) != NULL)
        return 1;

    void* handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        log_error_stderr("app_modules_check: can't load module %s: %s\n", path, dlerror());
        return 0;
    }

    const int exports_init = dlsym(handle, "app_init") != NULL;
    if (!exports_init)
        log_error_stderr("app_modules_check: module %s exports no app_init()\n", path);

    dlclose(handle);

    return exports_init;
}

int app_modules_load(const json_token_t* root) {
    return __app_modules_foreach(root, "app_modules_load", __app_module_init);
}

int app_modules_check(const json_token_t* root) {
    return __app_modules_foreach(root, "app_modules_check", __app_module_check);
}

void app_modules_free(void) {
    app_module_t* module = __modules;

    while (module != NULL) {
        app_module_t* next = module->next;

        free(module->path);
        free(module);

        module = next;
    }

    __modules = NULL;
}

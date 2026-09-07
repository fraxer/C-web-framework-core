#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "shadowload.h"
#include "appmodule.h"


struct app_module {
    char* path;
    void* handle;
    struct app_module* next;
};

static struct app_module* __app_module_find(const struct app_module* first, const char* path) {
    for (const struct app_module* module = first; module != NULL; module = module->next)
        if (strcmp(module->path, path) == 0)
            return (struct app_module*)module;

    return NULL;
}

/* main.tmp, straight out of the document.
 *
 * The modules are loaded before `servers` is parsed and therefore before
 * appconfig_set() publishes anything, so env() still describes the *previous*
 * generation and config->env is empty. The value is only a fallback directory
 * for a shadow copy, so a missing or malformed key is not worth failing over --
 * module_loader_config_load validates it properly a moment later. */
static const char* __app_modules_tmp(const json_token_t* root) {
    const json_token_t* token_main = json_object_get(root, "main");
    if (token_main == NULL || !json_is_object(token_main)) return NULL;

    const json_token_t* token_tmp = json_object_get(token_main, "tmp");
    if (token_tmp == NULL || !json_is_string(token_tmp)) return NULL;
    if (json_string_size(token_tmp) == 0) return NULL;

    return json_string(token_tmp);
}

/* Was this module given a SONAME of its own for this generation? */
static int __app_module_retagged(const appconfig_t* config, const char* path) {
    char soname[256];
    if (!shadow_read_soname(path, soname, sizeof soname)) return 0;

    return shadow_sonames_tagged(config->sonames, soname) != NULL;
}

static void* __app_module_open(appconfig_t* config, const char* path,
                               const char* tmpdir, const char* who) {
    struct app_module* module = __app_module_find(config->modules, path);
    if (module != NULL)
        return module->handle;

    /* A rebuilt module with no name of its own must not be loaded as a copy:
     * the handlers of this generation would still bind the *old* one by SONAME,
     * and one generation would end up running code from two builds
     * (docs/hotreload/01-soname-per-generation.md §1). Keeping the running module
     * is the honest answer -- it is what the server did before any of this
     * existed -- and the reservation pass has already said why there is no tag. */
    if (shadow_needs_copy(path) && !__app_module_retagged(config, path)) {
        void* running = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (running == NULL) {
            log_error_stderr("%s: can't load module %s: %s\n", who, path, dlerror());
            return NULL;
        }

        module = malloc(sizeof * module);
        if (module == NULL) {
            log_error_stderr("%s: memory alloc error\n", who);
            dlclose(running);
            return NULL;
        }

        module->path = strdup(path);
        if (module->path == NULL) {
            log_error_stderr("%s: memory alloc error\n", who);
            free(module);
            dlclose(running);
            return NULL;
        }

        module->handle = running;
        module->next = config->modules;
        config->modules = module;

        return running;
    }

    /* RTLD_NOW: app_init() is about to be called and the module's unresolved
     * framework symbols must be diagnosed here, with the path in hand, rather
     * than as a lazy-binding abort in a worker.
     *
     * RTLD_LOCAL, deliberately: with several modules loaded, RTLD_GLOBAL makes
     * the first one win every name they happen to share -- a second module's
     * own user_create() would silently bind to the first module's, with no
     * diagnostic anywhere. Local scope is not a loss, because it is not what
     * lets handlers reach the module: a handler .so records the module in
     * DT_NEEDED, and the loader satisfies that from the already-loaded object by
     * SONAME regardless of the scope it was opened in. Which is exactly why the
     * SONAME has to differ per generation -- see shadowload.h. */
    void* handle = shadow_dlopen_ex(path, RTLD_NOW | RTLD_LOCAL, tmpdir, config->sonames);
    if (handle == NULL) {
        log_error_stderr("%s: can't load module %s: %s\n", who, path, shadow_dlerror());
        return NULL;
    }

    module = malloc(sizeof * module);
    if (module == NULL) {
        log_error_stderr("%s: memory alloc error\n", who);
        dlclose(handle);
        return NULL;
    }

    module->path = strdup(path);
    if (module->path == NULL) {
        log_error_stderr("%s: memory alloc error\n", who);
        free(module);
        dlclose(handle);
        return NULL;
    }

    module->handle = handle;
    module->next = config->modules;
    config->modules = module;

    return handle;
}

static int __app_module_init(const char* path, void* handle) {
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

/* Everything the modules do to the process, done once against a throwaway
 * generation so that a bad configuration is refused while the running one is
 * still serving. app_modules_load() itself is far too late for that -- see
 * docs/hotreload/00-shadow-copy.md §4.
 *
 * app_init() IS called here, and that matters: the reload may bring a rebuilt
 * module registering a middleware the previous build did not have, and a route
 * naming it has to resolve. The caller has set the middleware registry aside
 * first, so these registrations -- pointers into modules this pass is about to
 * unload -- never reach the running configuration. */
static int __app_module_check(const char* path, void* handle) {
    return __app_module_init(path, handle);
}

/* Walk main.modules, handing each path to `apply`. The section is optional and
 * an application with no modules at all is a valid configuration, so an absent
 * one is success; a malformed one is not. */
static int __app_modules_foreach(const json_token_t* root, const char* who,
                                 int (*apply)(const char* path, void* arg), void* arg) {
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

        if (!apply(json_string(token_path), arg))
            return 0;
    }

    return 1;
}

/* First pass: reserve a SONAME for every module that is about to be replaced
 * under a live generation.
 *
 * "About to be replaced" is exactly shadow_needs_copy(): the file changed and
 * the old one is still loaded. Anything else -- a first load, an unchanged file,
 * a module whose generation has already gone -- keeps its own name, because
 * there is nothing for it to collide with.
 *
 * The tags have to exist before any module is loaded, and certainly before the
 * handlers are: they all carry the same map. */
static int __app_module_reserve(const char* path, void* arg) {
    appconfig_t* config = arg;

    char reason[256];
    if (!shadow_sonames_reserve(config->sonames, path, reason, sizeof reason))
        log_error_stderr("app_modules_load: %s was rebuilt but will not be reloaded: %s -- "
                         "the running module is kept, and a restart is what picks the new "
                         "one up\n", path, reason);

    /* Never fatal: a module that cannot be renamed is a module that is not
     * swapped, and the rest of the reload is still worth doing. */
    return 1;
}

typedef struct {
    appconfig_t* config;
    const char* tmpdir;
    const char* who;
} app_module_open_t;

static int __app_module_open_apply(const char* path, void* arg) {
    const app_module_open_t* state = arg;

    return __app_module_open(state->config, path, state->tmpdir, state->who) != NULL;
}

/* Reserve the SONAMEs and open every module of `main.modules`, without calling
 * app_init(). Shared by the validation pass and the real one, because the
 * handlers loaded afterwards resolve their DT_NEEDED against these very objects
 * -- a validation that skipped them would be validating a different program. */
static int __app_modules_open_all(appconfig_t* config, const json_token_t* root, const char* who) {
    if (config->sonames == NULL) {
        config->sonames = shadow_sonames_create();
        if (config->sonames == NULL) {
            log_error_stderr("%s: memory alloc error\n", who);
            return 0;
        }
    }

    if (!__app_modules_foreach(root, who, __app_module_reserve, config))
        return 0;

    app_module_open_t state = { .config = config, .tmpdir = __app_modules_tmp(root), .who = who };

    return __app_modules_foreach(root, who, __app_module_open_apply, &state);
}

int app_modules_load(appconfig_t* config, const json_token_t* root) {
    if (!__app_modules_open_all(config, root, "app_modules_load"))
        return 0;

    /* app_init() registers this generation's context destructors, and it has to
     * be able to reach the configuration to do it -- which is not yet published
     * (appconfig.h). Cleared before returning either way. */
    appconfig_set_loading(config);

    int result = 1;
    for (const struct app_module* module = config->modules;
         module != NULL && result; module = module->next)
        result = __app_module_init(module->path, module->handle);

    appconfig_set_loading(NULL);

    return result;
}

int app_modules_check(appconfig_t* config, const json_token_t* root) {
    if (!__app_modules_open_all(config, root, "app_modules_check"))
        return 0;

    appconfig_set_loading(config);

    int result = 1;
    for (const struct app_module* module = config->modules;
         module != NULL && result; module = module->next)
        result = __app_module_check(module->path, module->handle);

    appconfig_set_loading(NULL);

    return result;
}

void app_modules_free(struct app_module* modules) {
    struct app_module* module = modules;

    while (module != NULL) {
        struct app_module* next = module->next;

        /* Safe now and not a moment earlier: the caller is appconfig_clear(),
         * reached when the last thread of this generation has gone, so nothing
         * can be executing the module's middleware and no live configuration
         * holds a pointer into its text. */
        dlclose(module->handle);

        free(module->path);
        free(module);

        module = next;
    }
}

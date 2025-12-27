#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include "log.h"
#include "appconfig.h"

void taskmanager_free(taskmanager_t* manager);

static char* __appconfig_path = NULL;
static appconfig_t* __appconfig = NULL;

static const char* __appconfig_get_path(int argc, char* argv[]);
static void __appconfig_env_init(env_t* env);
static void __appconfig_env_free(env_t* env);
static void __appconfig_env_gzip_free(env_gzip_str_t* item);

int appconfig_init(int argc, char* argv[]) {
    appconfig_t* config = appconfig_create(__appconfig_get_path(argc, argv));
    if (config == NULL) return 0;

    __appconfig_path = strdup(config->path);
    if (__appconfig_path == NULL) {
        appconfig_free(config);
        return 0;
    }

    appconfig_set(config);

    return 1;
}

appconfig_t* appconfig_create(const char* path) {
    if (path == NULL)
        return NULL;

    // Проверяем существование файла
    if (access(path, F_OK) != 0) {
        printf("Error: Config file not found: %s\n", path);
        return NULL;
    }
    if (access(path, R_OK) != 0) {
        printf("Error: Config file is not readable: %s\n", path);
        return NULL;
    }

    appconfig_t* config = malloc(sizeof * config);
    if (config == NULL) {
        printf("Error: Memory allocation failed\n");
        return NULL;
    }

    atomic_store(&config->shutdown, 0);
    atomic_store(&config->threads_count, 0);
    __appconfig_env_init(&config->env);
    config->mimetype = NULL;
    config->databases = NULL;
    config->storages = NULL;
    config->viewstore = NULL;
    config->server_chain = NULL;
    config->taskmanager_loader = NULL;
    config->taskmanager = NULL;
    memset(&config->sessionconfig, 0, sizeof(config->sessionconfig));
    config->path = strdup(path);
    if (config->path == NULL) {
        printf("Error: Memory allocation failed for config path\n");
        free(config);
        return NULL;
    }

    config->prepared_queries = array_create();
    if (config->prepared_queries == NULL) {
        free(config->path);
        free(config);
        return NULL;
    }

    return config;
}

appconfig_t* appconfig(void) {
    return __appconfig;
}

env_t* env(void) {
    if (__appconfig == NULL)
        return NULL;

    return &__appconfig->env;
}

void appconfig_set(appconfig_t* config) {
    __appconfig = config;
}

void appconfig_clear(appconfig_t* config) {
    if (config == NULL) return;

    atomic_store(&config->shutdown, 0);
    atomic_store(&config->threads_count, 0);
    __appconfig_env_free(&config->env);

    mimetype_destroy(config->mimetype);
    config->mimetype = NULL;

    array_free(config->databases);
    config->databases = NULL;

    storages_free(config->storages);
    config->storages = NULL;

    viewstore_destroy(config->viewstore);
    config->viewstore = NULL;

    server_chain_destroy(config->server_chain);
    config->server_chain = NULL;

    sessionconfig_clear(&config->sessionconfig);

    array_free(config->prepared_queries);
    config->prepared_queries = NULL;

    routeloader_free(config->taskmanager_loader);
    config->taskmanager_loader = NULL;

    taskmanager_free(config->taskmanager);
}

void appconfig_free(appconfig_t* config) {
    if (config == NULL) return;

    appconfig_clear(config);

    if (config->path != NULL) free(config->path);

    free(config);
}

char* appconfig_path(void) {
    return __appconfig_path;
}

void appconfg_threads_increment(appconfig_t* config) {
    atomic_fetch_add(&config->threads_count, 1);
}

void appconfg_threads_decrement(appconfig_t* config) {
    atomic_fetch_sub(&config->threads_count, 1);

    if (atomic_load(&config->threads_count) == 0)
        appconfig_free(config);
}

void __appconfig_env_init(env_t* env) {
    if (env == NULL) return;

    env->main.reload = APPCONFIG_RELOAD_SOFT;
    env->main.client_max_body_size = 0;
    env->main.gzip = NULL;
    env->main.threads = 0;
    env->main.workers = 0;
    env->main.tmp = NULL;
    env->main.log.enabled = false;
    env->main.log.level = 0;
    env->mail.dkim_private = NULL;
    env->mail.dkim_selector = NULL;
    env->mail.host = NULL;
    env->migrations.source_directory = NULL;
    env->custom_store = NULL;
}

void __appconfig_env_free(env_t* env) {
    if (env == NULL) return;

    env->main.client_max_body_size = 0;
    env->main.threads = 0;
    env->main.workers = 0;

    if (env->main.gzip != NULL) {
        __appconfig_env_gzip_free(env->main.gzip);
        env->main.gzip = NULL;
    }

    if (env->main.tmp != NULL) {
        free(env->main.tmp);
        env->main.tmp = NULL;
    }

    env->main.log.enabled = false;
    env->main.log.level = 0;

    if (env->mail.dkim_private != NULL) {
        free(env->mail.dkim_private);
        env->mail.dkim_private = NULL;
    }

    if (env->mail.dkim_selector != NULL) {
        free(env->mail.dkim_selector);
        env->mail.dkim_selector = NULL;
    }

    if (env->mail.host != NULL) {
        free(env->mail.host);
        env->mail.host = NULL;
    }

    if (env->migrations.source_directory != NULL) {
        free(env->migrations.source_directory);
        env->migrations.source_directory = NULL;
    }

    if (env->custom_store != NULL) {
        json_free(env->custom_store);
        env->custom_store = NULL;
    }
}

void __appconfig_env_gzip_free(env_gzip_str_t* item) {
    while (item != NULL) {
        env_gzip_str_t* next = item->next;
        free(item->mimetype);
        free(item);
        item = next;
    }
}

const char* __appconfig_get_path(int argc, char* argv[]) {
    int opt = 0;
    const char* path = NULL;
    int c_found = 0;

    opterr = 0;
    optopt = 0;
    optind = 0;
    optarg = NULL;

    while ((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt) {
            case 'c':
                if (optarg == NULL) {
                    printf("Error: -c flag requires a config file path\n");
                    return NULL;
                }

                path = optarg;
                c_found = 1;
                break;
            default:
                printf("Error: Unknown option '-%c'\n", optopt);
                printf("Usage: %s -c <path to config file>\n", argv[0]);
                return NULL;
        }
    }

    if (!c_found) {
        printf("Error: Config file path is required\n");
        printf("Usage: %s -c <path to config file>\n", argv[0]);
        return NULL;
    }
    if (argc < 3) {
        printf("Error: Invalid arguments\n");
        printf("Usage: %s -c <path to config file>\n", argv[0]);
        return NULL;
    }

    return path;
}

static json_token_t* __env_get_token(const char* key) {
    if (key == NULL) return NULL;
    if (__appconfig == NULL) return NULL;
    if (__appconfig->env.custom_store == NULL) return NULL;

    json_token_t* root = json_root(__appconfig->env.custom_store);
    if (root == NULL) return NULL;

    return json_object_get(root, key);
}

const char* env_get_string(const char* key) {
    json_token_t* token = __env_get_token(key);
    if (token == NULL || !json_is_string(token)) return NULL;

    return json_string(token);
}

int env_get_int(const char* key, int default_value) {
    json_token_t* token = __env_get_token(key);
    if (token == NULL || !json_is_number(token)) return default_value;

    int ok = 0;
    int value = json_int(token, &ok);
    return ok ? value : default_value;
}

long long env_get_llong(const char* key, long long default_value) {
    json_token_t* token = __env_get_token(key);
    if (token == NULL || !json_is_number(token)) return default_value;

    int ok = 0;
    long long value = json_llong(token, &ok);
    return ok ? value : default_value;
}

int env_get_bool(const char* key, int default_value) {
    json_token_t* token = __env_get_token(key);
    if (token == NULL || !json_is_bool(token)) return default_value;

    return json_bool(token);
}

double env_get_double(const char* key, double default_value) {
    json_token_t* token = __env_get_token(key);
    if (token == NULL || !json_is_number(token)) return default_value;

    int ok = 0;
    double value = json_double(token, &ok);
    return ok ? value : default_value;
}

long double env_get_ldouble(const char* key, long double default_value) {
    json_token_t* token = __env_get_token(key);
    if (token == NULL || !json_is_number(token)) return default_value;

    return json_ldouble(token);
}
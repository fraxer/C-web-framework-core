#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <syslog.h>

#include "log.h"
#include "file.h"
#include "database.h"
#include "json.h"
#include "map.h"
#include "redirect.h"
#include "route.h"
#include "routeloader.h"
#include "domain.h"
#include "server.h"
#include "websockets.h"
#include "openssl.h"
#include "mimetype.h"
#include "session.h"
#include "storagefs.h"
#include "storages3.h"
#include "viewstore.h"
#include "threadhandler.h"
#include "threadworker.h"
#include "broadcast.h"
#include "connection_queue.h"
#include "statement_registry.h"
#include "middleware_registry.h"
#include "httpserverhandlers.h"
#include "taskmanager.h"
#include "i18n.h"
#ifdef MySQL_FOUND
    #include "mysql.h"
#endif
#ifdef PostgreSQL_FOUND
    #include "postgresql.h"
#endif
#ifdef Redis_FOUND
    #include "redis.h"
#endif

#include "moduleloader.h"

static atomic_bool __module_loader_wait_signal = ATOMIC_VAR_INIT(0);

static void __free_gzip_list(env_gzip_str_t* item) {
    while (item != NULL) {
        env_gzip_str_t* next = item->next;
        free(item->mimetype);
        free(item);
        item = next;
    }
}

static int __module_loader_init_modules(appconfig_t* config, json_doc_t* document);
static int __module_loader_taskmanager_load(appconfig_t* config, taskmanager_t* manager, const json_token_t* token_taskmanager);
static int __module_loader_servers_load(appconfig_t* config, const json_token_t* servers);
static domain_t* __module_loader_domains_load(const json_token_t* token_array);
static int __module_loader_databases_load(appconfig_t* config, const json_token_t* databases);
static int __module_loader_storages_load(appconfig_t* config, const json_token_t* storages);
static int __module_loader_mimetype_load(appconfig_t* config, const json_token_t* mimetypes);
static int __module_loader_viewstore_load(appconfig_t* config);
static int __module_loader_sessionconfig_load(appconfig_t* config, const json_token_t* sessionconfig);
static int __module_loader_prepared_queries_load(appconfig_t* config);
static int __module_loader_taskmanager_init(appconfig_t* config, json_token_t* task_manager);
static int __module_loader_translations_load(appconfig_t* config, json_token_t* translations);

static int __module_loader_http_routes_load(routeloader_lib_t** first_lib, const json_token_t* token_object, route_t** route, map_t* ratelimiter_config);
static int __module_loader_set_http_route(routeloader_lib_t** first_lib, routeloader_lib_t** last_lib, route_t* route, const json_token_t* token_object, map_t* ratelimiter_config);
static void __module_loader_pass_memory_sharedlib(routeloader_lib_t*, const char*);
static int __module_loader_http_redirects_load(const json_token_t* token_object, redirect_t** redirect);
static int __module_loader_middlewares_load(const json_token_t* token_object, middleware_item_t** middleware_item);
static int __module_loader_websockets_default_load(void(**fn)(void*), routeloader_lib_t** first_lib, const json_token_t* token_object, map_t* ratelimiter_config);
static int __module_loader_websockets_routes_load(routeloader_lib_t** first_lib, const json_token_t* token_object, route_t** route, map_t* ratelimiter_config);
static int __module_loader_set_websockets_route(routeloader_lib_t** first_lib, routeloader_lib_t** last_lib, route_t* route, const json_token_t* token_object, map_t* ratelimiter_config);
static openssl_t* __module_loader_tls_load(const json_token_t* token_object);
static int __module_loader_check_unique_domainport(server_t* first_server);
static void* __module_loader_storage_fs_load(const json_token_t* token_object, const char* storage_name);
static void* __module_loader_storage_s3_load(const json_token_t* token_object, const char* storage_name);
static const char* __module_loader_storage_field(const char* storage_name, const json_token_t* token_object, const char* key);
static int __module_loader_thread_taskmanager_load(appconfig_t* config);
static int __module_loader_thread_workers_load(appconfig_t* config);
static int __module_loader_thread_handlers_load(appconfig_t* config);
static void __module_loader_on_shutdown_cb(void);
static map_t* __module_loader_ratelimits_configs_load(const json_token_t* token_object);
static ratelimiter_config_t* __module_loader_ratelimits_config_load(const json_token_t* token_object);
static int __module_loader_http_ratelimit_load(const json_token_t* token_string, ratelimiter_t** ratelimiter, map_t* ratelimits_config);
static int __module_loader_websockets_ratelimit_load(const json_token_t* token_string, ratelimiter_t** ratelimiter, map_t* ratelimits_config);

int module_loader_init(appconfig_t* config) {
    int result = 0;

    if (!prepare_statements_init()) {
        log_error("module_loader_init: failed to initialize prepared statements\n");
        goto failed;
    }

    if (!middlewares_init()) {
        log_error("module_loader_init: failed to initialize middlewares\n");
        goto failed;
    }

    json_doc_t* document = NULL;
    if (!module_loader_load_json_config(config->path, &document))
        goto failed;
    if (!__module_loader_init_modules(config, document))
        goto failed;

    result = 1;

    failed:

    json_free(document);

    return result;
}

int module_loader_config_correct(const char* path) {
    int result = 0;
    appconfig_t* config = NULL;
    json_doc_t* document = NULL;
    if (!module_loader_load_json_config(path, &document))
        goto failed;

    config = appconfig_create(path);
    if (!module_loader_config_load(config, document))
        goto failed;

    result = 1;

    failed:

    appconfig_free(config);

    json_free(document);

    return result;
}

int module_loader_load_json_config(const char* path, json_doc_t** document) {
    if (path == NULL) return 0;

    file_t file = file_open(path, O_RDONLY);
    if (!file.ok) {
        log_error("module_loader_load_json_config: file_open error\n");
        return 0;
    }

    char* data = file.content(&file);

    file.close(&file);
   
    if (data == NULL) {
        log_error("module_loader_load_json_config: file_read error\n");
        return 0;
    }

    int result = 0;

    *document = json_parse(data);
    if (*document == NULL) {
        log_error("module_loader_load_json_config: json_parse error\n");
        goto failed;
    }
    if (!json_is_object(json_root(*document))) {
        log_error("module_loader_load_json_config: json document must be object\n");
        goto failed;
    }

    result = 1;

    failed:

    free(data);

    return result;
}

int __module_loader_init_modules(appconfig_t* config, json_doc_t* document) {
    int result = 0;

    if (!connection_queue_init()) {
        log_error("__module_loader_init_modules: connection_queue_init error\n");
        goto failed;
    }
    if (!module_loader_config_load(config, document))
        goto failed;

    if (config->server_chain && config->server_chain->server)
        http_server_init_sni_callbacks(config->server_chain->server);

    if (!__module_loader_thread_taskmanager_load(config))
        goto failed;
    if (!__module_loader_thread_workers_load(config))
        goto failed;
    if (!__module_loader_thread_handlers_load(config))
        goto failed;

    result = 1;

    failed:

    if (!result) {
        appconfig_free(appconfig());
        appconfig_set(NULL);
    }

    return result;
}

int module_loader_config_load(appconfig_t* config, json_doc_t* document) {
    env_t* env = &config->env;
    const json_token_t* root = json_root(document);

    const json_token_t* token_migrations = json_object_get(root, "migrations");
    if (token_migrations == NULL) {
        env->migrations.source_directory = malloc(sizeof(char) * 1);
        if (env->migrations.source_directory == NULL) {
            log_error("module_loader_config_load: memory alloc error\n");
            return 0;
        }

        strcpy(env->migrations.source_directory, "");
    }
    else {
        if (!json_is_object(token_migrations)) {
            log_error("module_loader_config_load: migrations must be object\n");
            return 0;
        }

        const json_token_t* token_source_directory = json_object_get(token_migrations, "source_directory");
        if (token_source_directory == NULL) {
            env->migrations.source_directory = malloc(sizeof(char) * 1);
            if (env->migrations.source_directory == NULL) {
                log_error("module_loader_config_load: memory alloc error\n");
                return 0;
            }

            strcpy(env->migrations.source_directory, "");
        }
        else {
            if (!json_is_string(token_source_directory)) {
                log_error("module_loader_config_load: source_directory must be string\n");
                return 0;
            }

            env->migrations.source_directory = malloc(sizeof(char) * (json_string_size(token_source_directory) + 1));
            if (env->migrations.source_directory == NULL) {
                log_error("module_loader_config_load: memory alloc error\n");
                return 0;
            }

            strcpy(env->migrations.source_directory, json_string(token_source_directory));
        }
    }


    const json_token_t* token_main = json_object_get(root, "main");
    if (token_main == NULL) {
        log_error("module_loader_config_load: main not found\n");
        return 0;
    }
    if (!json_is_object(token_main)) {
        log_error("module_loader_config_load: main must be object\n");
        return 0;
    }


    const json_token_t* token_reload = json_object_get(token_main, "reload");
    if (token_reload == NULL) {
        log_error("module_loader_config_load: reload not found\n");
        return 0;
    }
    if (!json_is_string(token_reload)) {
        log_error("module_loader_config_load: reload must be string\n");
        return 0;
    }
    if (strcmp(json_string(token_reload), "hard") == 0) {
        env->main.reload = APPCONFIG_RELOAD_HARD;
    }
    else if (strcmp(json_string(token_reload), "soft") == 0) {
        env->main.reload = APPCONFIG_RELOAD_SOFT;
    }
    else {
        log_error("module_loader_config_load: reload must be contain soft or hard\n");
        return 0;
    }


    const json_token_t* token_workers = json_object_get(token_main, "workers");
    if (token_workers == NULL) {
        log_error("module_loader_config_load: workers not found\n");
        return 0;
    }
    if (!json_is_number(token_workers)) {
        log_error("module_loader_config_load: workers must be int\n");
        return 0;
    }
    int ok = 0;
    int workers_count = json_int(token_workers, &ok);
    if (!ok || workers_count < 1) {
        log_error("module_loader_config_load: workers must be >= 1\n");
        return 0;
    }
    env->main.workers = workers_count;


    const json_token_t* token_threads = json_object_get(token_main, "threads");
    if (token_threads == NULL) {
        log_error("module_loader_config_load: threads not found\n");
        return 0;
    }
    if (!json_is_number(token_threads)) {
        log_error("module_loader_config_load: threads must be int\n");
        return 0;
    }
    ok = 0;
    int threads_count = json_int(token_threads, &ok);
    if (!ok || threads_count < 1) {
        log_error("module_loader_config_load: threads must be >= 1\n");
        return 0;
    }
    env->main.threads = threads_count;


    const json_token_t* token_client_max_body_size = json_object_get(token_main, "client_max_body_size");
    if (token_client_max_body_size == NULL) {
        log_error("module_loader_config_load: client_max_body_size not found\n");
        return 0;
    }
    if (!json_is_number(token_client_max_body_size)) {
        log_error("module_loader_config_load: client_max_body_size must be int\n");
        return 0;
    }
    ok = 0;
    unsigned int client_max_body_size = json_int(token_client_max_body_size, &ok);
    if (!ok || client_max_body_size < 1) {
        log_error("module_loader_config_load: client_max_body_size must be >= 1\n");
        return 0;
    }
    env->main.client_max_body_size = client_max_body_size;


    const json_token_t* token_tmp = json_object_get(token_main, "tmp");
    if (token_tmp == NULL) {
        log_error("module_loader_config_load: tmp not found\n");
        return 0;
    }
    if (!json_is_string(token_tmp)) {
        log_error("module_loader_config_load: tmp must be string\n");
        return 0;
    }
    env->main.tmp = malloc(sizeof(char) * (json_string_size(token_tmp) + 1));
    if (env->main.tmp == NULL) {
        log_error("module_loader_config_load: memory alloc error for tmp\n");
        return 0;
    }
    strcpy(env->main.tmp, json_string(token_tmp));
    const size_t tmp_length = json_string_size(token_tmp);
    if (env->main.tmp[tmp_length - 1] == '/') {
        log_error("module_loader_config_load: remove last slash from main.tmp\n");
        return 0;
    }


    const json_token_t* token_gzip = json_object_get(token_main, "gzip");
    if (token_gzip == NULL) {
        log_error("module_loader_config_load: gzip not found\n");
        return 0;
    }
    if (!json_is_array(token_gzip)) {
        log_error("module_loader_config_load: gzip must be array\n");
        return 0;
    }

    env_gzip_str_t* last_gzip_item = NULL;
    for (json_it_t it = json_init_it(token_gzip); !json_end_it(&it); it = json_next_it(&it)) {
        const json_token_t* token_mimetype = json_it_value(&it);
        if (!json_is_string(token_mimetype)) {
            log_error("module_loader_config_load: gzip must be array of strings\n");
            __free_gzip_list(env->main.gzip);
            env->main.gzip = NULL;
            return 0;
        }
        if (json_string_size(token_mimetype) == 0) {
            log_error("module_loader_config_load: gzip item must be not empty\n");
            __free_gzip_list(env->main.gzip);
            env->main.gzip = NULL;
            return 0;
        }

        env_gzip_str_t* str = malloc(sizeof * str);
        if (str == NULL) {
            log_error("module_loader_config_load: memory alloc error for gzip item\n");
            __free_gzip_list(env->main.gzip);
            env->main.gzip = NULL;
            return 0;
        }
        str->next = NULL;
        str->mimetype = malloc(sizeof(char) * (json_string_size(token_mimetype) + 1));
        if (str->mimetype == NULL) {
            log_error("module_loader_config_load: memory alloc error for gzip item value\n");
            free(str);
            __free_gzip_list(env->main.gzip);
            env->main.gzip = NULL;
            return 0;
        }
        strcpy(str->mimetype, json_string(token_mimetype));

        if (env->main.gzip == NULL)
            env->main.gzip = str;

        if (last_gzip_item != NULL)
            last_gzip_item->next = str;

        last_gzip_item = str;
    }


    const json_token_t* token_log = json_object_get(token_main, "log");
    if (token_log == NULL) {
        log_error("module_loader_config_load: log not found\n");
        goto failed;
    }
    if (!json_is_object(token_log)) {
        log_error("module_loader_config_load: log must be object\n");
        goto failed;
    }

    const json_token_t* token_log_enabled = json_object_get(token_log, "enabled");
    if (token_log_enabled == NULL) {
        log_error("module_loader_config_load: log.enabled not found\n");
        goto failed;
    }
    if (!json_is_bool(token_log_enabled)) {
        log_error("module_loader_config_load: log.enabled must be boolean\n");
        goto failed;
    }
    env->main.log.enabled = json_bool(token_log_enabled);

    const json_token_t* token_log_level = json_object_get(token_log, "level");
    if (token_log_level == NULL) {
        log_error("module_loader_config_load: log.level not found\n");
        goto failed;
    }
    if (!json_is_string(token_log_level)) {
        log_error("module_loader_config_load: log.level must be string\n");
        goto failed;
    }
    const char* level_str = json_string(token_log_level);
    if (strcmp(level_str, "emerg") == 0) {
        env->main.log.level = LOG_EMERG;
    }
    else if (strcmp(level_str, "alert") == 0) {
        env->main.log.level = LOG_ALERT;
    }
    else if (strcmp(level_str, "crit") == 0) {
        env->main.log.level = LOG_CRIT;
    }
    else if (strcmp(level_str, "err") == 0 || strcmp(level_str, "error") == 0) {
        env->main.log.level = LOG_ERR;
    }
    else if (strcmp(level_str, "warning") == 0 || strcmp(level_str, "warn") == 0) {
        env->main.log.level = LOG_WARNING;
    }
    else if (strcmp(level_str, "notice") == 0) {
        env->main.log.level = LOG_NOTICE;
    }
    else if (strcmp(level_str, "info") == 0) {
        env->main.log.level = LOG_INFO;
    }
    else if (strcmp(level_str, "debug") == 0) {
        env->main.log.level = LOG_DEBUG;
    }
    else {
        log_error("module_loader_config_load: log.level must be one of: emerg, alert, crit, err, warning, notice, info, debug\n");
        goto failed;
    }


    const json_token_t* token_env = json_object_get(token_main, "env");
    if (token_env != NULL) {
        if (!json_is_object(token_env)) {
            log_error("module_loader_config_load: main.env must be object\n");
            return 0;
        }

        env->custom_store = json_root_create_object();
        if (env->custom_store == NULL) {
            log_error("module_loader_config_load: failed to create custom_store\n");
            return 0;
        }

        json_token_t* store_root = json_root(env->custom_store);
        for (json_it_t it = json_init_it(token_env); !json_end_it(&it); it = json_next_it(&it)) {
            const char* key = json_it_key(&it);
            json_token_t* value = json_it_value(&it);

            json_token_t* new_value = NULL;
            if (json_is_string(value)) {
                new_value = json_create_string(json_string(value));
            } else if (json_is_number(value)) {
                new_value = json_create_number(json_ldouble(value));
            } else if (json_is_bool(value)) {
                new_value = json_create_bool(json_bool(value));
            } else if (json_is_null(value)) {
                new_value = json_create_null();
            }

            if (new_value != NULL) {
                json_object_set(store_root, key, new_value);
            }
        }
    }


    if (!__module_loader_servers_load(config, json_object_get(root, "servers")))
        goto failed;
    if (!__module_loader_databases_load(config, json_object_get(root, "databases")))
        goto failed;
    if (!__module_loader_storages_load(config, json_object_get(root, "storages")))
        goto failed;
    if (!__module_loader_mimetype_load(config, json_object_get(root, "mimetypes")))
        goto failed;
    if (!__module_loader_viewstore_load(config))
        goto failed;
    if (!__module_loader_sessionconfig_load(config, json_object_get(root, "sessions")))
        goto failed;
    if (!__module_loader_prepared_queries_load(config))
        goto failed;
    if (!__module_loader_taskmanager_init(config, json_object_get(root, "task_manager")))
        goto failed;
    if (!__module_loader_translations_load(config, json_object_get(root, "translations")))
        goto failed;


    const json_token_t* token_mail = json_object_get(root, "mail");
    if (token_mail == NULL) {
        env->mail.dkim_private = malloc(sizeof(char) * 1);
        if (env->mail.dkim_private == NULL) {
            log_error("module_loader_config_load: memory alloc error mail.dkim_private\n");
            goto failed;
        }
        strcpy(env->mail.dkim_private, "");


        env->mail.dkim_selector = malloc(sizeof(char) * 1);
        if (env->mail.dkim_selector == NULL) {
            log_error("module_loader_config_load: memory alloc error mail.dkim_selector\n");
            goto failed;
        }
        strcpy(env->mail.dkim_selector, "");


        env->mail.host = malloc(sizeof(char) * 1);
        if (env->mail.host == NULL) {
            log_error("module_loader_config_load: memory alloc error mail.host\n");
            goto failed;
        }
        strcpy(env->mail.host, "");
    }
    else {
        const json_token_t* token_dkim_private = json_object_get(token_mail, "dkim_private");
        if (token_dkim_private == NULL) {
            env->mail.dkim_private = malloc(sizeof(char) * 1);
            if (env->mail.dkim_private == NULL) {
                log_error("module_loader_config_load: memory alloc error mail.dkim_private\n");
                goto failed;
            }
            strcpy(env->mail.dkim_private, "");
        }
        else {
            if (!json_is_string(token_dkim_private)) {
                log_error("module_loader_config_load: mail.dkim_private must be string\n");
                goto failed;
            }
            if (json_string_size(token_dkim_private) == 0) {
                log_error("module_loader_config_load: mail.dkim_private must be not empty\n");
                goto failed;
            }

            file_t file = file_open(json_string(token_dkim_private), O_RDONLY);
            if (!file.ok) {
                log_error("module_loader_config_load: open mail.dkim_private error\n");
                goto failed;
            }

            env->mail.dkim_private = file.content(&file);
            file.close(&file);

            if (env->mail.dkim_private == NULL) {
                log_error("module_loader_config_load: read mail.dkim_private error\n");
                goto failed;
            }
        }

        const json_token_t* token_dkim_selector = json_object_get(token_mail, "dkim_selector");
        if (token_dkim_selector == NULL) {
            env->mail.dkim_selector = malloc(sizeof(char) * 1);
            if (env->mail.dkim_selector == NULL) {
                log_error("module_loader_config_load: memory alloc error mail.dkim_selector\n");
                goto failed;
            }
            strcpy(env->mail.dkim_selector, "");
        }
        else {
            if (!json_is_string(token_dkim_selector)) {
                log_error("module_loader_config_load: mail.dkim_selector must be string\n");
                goto failed;
            }
            if (json_string_size(token_dkim_selector) == 0) {
                log_error("module_loader_config_load: mail.dkim_selector must be not empty\n");
                goto failed;
            }

            env->mail.dkim_selector = malloc(sizeof(char) * (json_string_size(token_dkim_selector) + 1));
            if (env->mail.dkim_selector == NULL) {
                log_error("module_loader_config_load: memory alloc error mail.dkim_selector\n");
                goto failed;
            }
            strcpy(env->mail.dkim_selector, json_string(token_dkim_selector));
        }

        const json_token_t* token_host = json_object_get(token_mail, "host");
        if (token_host == NULL) {
            env->mail.host = malloc(sizeof(char) * 1);
            if (env->mail.host == NULL) {
                log_error("module_loader_config_load: memory alloc error mail.host\n");
                goto failed;
            }
            strcpy(env->mail.host, "");
        }
        else {
            if (!json_is_string(token_host)) {
                log_error("module_loader_config_load: mail.host must be string\n");
                goto failed;
            }
            if (json_string_size(token_host) == 0) {
                log_error("module_loader_config_load: mail.host must be not empty\n");
                goto failed;
            }

            env->mail.host = malloc(sizeof(char) * (json_string_size(token_host) + 1));
            if (env->mail.host == NULL) {
                log_error("module_loader_config_load: memory alloc error mail.host\n");
                goto failed;
            }
            strcpy(env->mail.host, json_string(token_host));
        }
    }

    return 1;

    failed:

    __free_gzip_list(env->main.gzip);
    env->main.gzip = NULL;
    return 0;
}

int __module_loader_servers_load(appconfig_t* config, const json_token_t* token_servers) {
    if (token_servers == NULL) {
        log_error("__module_loader_servers_load: servers not found\n");
        return 0;
    }
    if (!json_is_object(token_servers)) {
        log_error("__module_loader_servers_load: servers must be object\n");
        return 0;
    }

    int result = 0;
    server_t* first_server = NULL;
    server_t* last_server = NULL;
    routeloader_lib_t* first_lib = NULL;
    for (json_it_t it_servers = json_init_it(token_servers); !json_end_it(&it_servers); json_next_it(&it_servers)) {
        enum required_fields { R_DOMAINS = 0, R_IP, R_PORT, R_ROOT, R_FIELDS_COUNT };
        char* str_required_fields[R_FIELDS_COUNT] = {"domains", "ip", "port", "root"};
        enum fields { DOMAINS = 0, IP, PORT, ROOT, INDEX, RATELIMITS, HTTP, WEBSOCKETS, DATABASE, OPENSSL, FIELDS_COUNT };

        int finded_fields[FIELDS_COUNT] = {0};

        server_t* server = server_create();
        if (server == NULL) {
            log_error("__module_loader_servers_load: can't create server\n");
            goto failed;
        }

        if (first_server == NULL)
            first_server = server;

        if (last_server != NULL)
            last_server->next = server;

        last_server = server;

        server->broadcast = broadcast_init();
        if (server->broadcast == NULL) {
            log_error("__module_loader_servers_load: can't create broadcast\n");
            goto failed;
        }

        const json_token_t* token_server = json_it_value(&it_servers);
        if (!json_is_object(token_server)) {
            log_error("__module_loader_servers_load: server must be object\n");
            goto failed;
        }

        const json_token_t* token_domains = json_object_get(token_server, "domains");
        if (token_domains != NULL) {
            finded_fields[DOMAINS] = 1;

            if (!json_is_array(token_domains)) {
                log_error("__module_loader_servers_load: domains must be array\n");
                goto failed;
            }
            server->domain = __module_loader_domains_load(token_domains);
            if (server->domain == NULL) {
                log_error("__module_loader_servers_load: can't load domains\n");
                goto failed;
            }
        }

        const json_token_t* token_ip = json_object_get(token_server, "ip");
        if (token_ip != NULL) {
            finded_fields[IP] = 1;

            if (!json_is_string(token_ip)) {
                log_error("__module_loader_servers_load: ip must be string\n");
                goto failed;
            }
            server->ip = inet_addr(json_string(token_ip));
        }

        const json_token_t* token_port = json_object_get(token_server, "port");
        if (token_port != NULL) {
            finded_fields[PORT] = 1;

            if (!json_is_number(token_port)) {
                log_error("__module_loader_servers_load: port must be number\n");
                goto failed;
            }
            int ok = 0;
            server->port = json_int(token_port, &ok);
            if (!ok) {
                log_error("__module_loader_servers_load: port must be integer\n");
                goto failed;
            }
        }

        const json_token_t* token_root = json_object_get(token_server, "root");
        if (token_root != NULL) {
            finded_fields[ROOT] = 1;

            if (!json_is_string(token_root)) {
                log_error("__module_loader_servers_load: root must be string\n");
                goto failed;
            }
            const char* value = json_string(token_root);
            size_t value_length = json_string_size(token_root);

            if (value[value_length - 1] == '/')
                value_length--;

            server->root = malloc(value_length + 1);
            if (server->root == NULL) {
                log_error("__module_loader_servers_load: can't alloc memory for root path\n");
                goto failed;
            }

            strncpy(server->root, value, value_length);

            server->root[value_length] = 0;
            server->root_length = value_length;

            struct stat stat_obj;
            stat(server->root, &stat_obj);
            if (!S_ISDIR(stat_obj.st_mode)) {
                log_error("__module_loader_servers_load: root directory not found\n");
                goto failed;
            }
        }

        const json_token_t* token_index = json_object_get(token_server, "index");
        if (token_index != NULL) {
            finded_fields[INDEX] = 1;

            if (!json_is_string(token_index)) {
                log_error("__module_loader_servers_load: index must be string\n");
                goto failed;
            }

            server->index = server_index_create(json_string(token_index));
            if (server->index == NULL) {
                log_error("__module_loader_servers_load: can't alloc memory for index file\n");
                goto failed;
            }
        }

        const json_token_t* token_ratelimits = json_object_get(token_server, "ratelimits");
        if (token_ratelimits != NULL) {
            finded_fields[RATELIMITS] = 1;

            if (!json_is_object(token_ratelimits)) {
                log_error("__module_loader_servers_load: ratelimits must be object\n");
                goto failed;
            }

            server->ratelimits_config = __module_loader_ratelimits_configs_load(token_ratelimits);
            if (server->ratelimits_config == NULL) {
                log_error("__module_loader_servers_load: can't load ratelimits config\n");
                goto failed;
            }
        }

        const json_token_t* token_http = json_object_get(token_server, "http");
        if (token_http != NULL) {
            finded_fields[HTTP] = 1;

            if (!json_is_object(token_http)) {
                log_error("__module_loader_servers_load: http must be object\n");
                goto failed;
            }

            if (!__module_loader_http_ratelimit_load(json_object_get(token_http, "ratelimit"), &server->http.ratelimiter, server->ratelimits_config)) {
                log_error("__module_loader_servers_load: can't load routes\n");
                goto failed;
            }
            if (!__module_loader_http_routes_load(&first_lib, json_object_get(token_http, "routes"), &server->http.route, server->ratelimits_config)) {
                log_error("__module_loader_servers_load: can't load routes\n");
                goto failed;
            }
            if (!__module_loader_http_redirects_load(json_object_get(token_http, "redirects"), &server->http.redirect)) {
                log_error("__module_loader_servers_load: can't load redirects\n");
                goto failed;
            }
            if (!__module_loader_middlewares_load(json_object_get(token_http, "middlewares"), &server->http.middleware)) {
                log_error("__module_loader_servers_load: can't load middlewares\n");
                goto failed;
            }
        }

        const json_token_t* token_websockets = json_object_get(token_server, "websockets");
        if (token_websockets != NULL) {
            finded_fields[WEBSOCKETS] = 1;

            if (!json_is_object(token_websockets)) {
                log_error("__module_loader_servers_load: websockets must be object\n");
                goto failed;
            }

            if (!__module_loader_websockets_default_load(&server->websockets.default_handler, &first_lib, json_object_get(token_websockets, "default"), server->ratelimits_config)) {
                log_error("__module_loader_servers_load: can't load default handler\n");
                goto failed;
            }
            if (!__module_loader_websockets_ratelimit_load(json_object_get(token_websockets, "ratelimit"), &server->websockets.ratelimiter, server->ratelimits_config)) {
                log_error("__module_loader_servers_load: can't load routes\n");
                goto failed;
            }
            if (!__module_loader_websockets_routes_load(&first_lib, json_object_get(token_websockets, "routes"), &server->websockets.route, server->ratelimits_config)) {
                log_error("__module_loader_servers_load: can't load routes\n");
                goto failed;
            }
            if (!__module_loader_middlewares_load(json_object_get(token_websockets, "middlewares"), &server->websockets.middleware)) {
                log_error("__module_loader_servers_load: can't load middlewares\n");
                goto failed;
            }
        }

        const json_token_t* token_tls = json_object_get(token_server, "tls");
        if (token_tls != NULL) {
            finded_fields[OPENSSL] = 1;

            if (!json_is_object(token_tls)) {
                log_error("__module_loader_servers_load: database must be object\n");
                goto failed;
            }

            server->openssl = __module_loader_tls_load(token_tls);
            if (server->openssl == NULL) {
                log_error("__module_loader_servers_load: can't load tls\n");
                goto failed;
            }
        }

        for (int i = 0; i < R_FIELDS_COUNT; i++) {
            if (finded_fields[i] == 0) {
                log_error("__module_loader_servers_load: Section %s not found in config\n", str_required_fields[i]);
                goto failed;
            }
        }

        if (finded_fields[INDEX] == 0) {
            server->index = server_index_create("index.html");
            if (server->index == NULL) {
                log_error("__module_loader_servers_load: can't create index file\n");
                goto failed;
            }
        }

        if (finded_fields[WEBSOCKETS] == 0)
            server->websockets.default_handler = (void(*)(void*))websockets_default_handler;

        if (!__module_loader_check_unique_domainport(first_server)) {
            log_error("__module_loader_servers_load: domains with ports must be unique\n");
            goto failed;
        }
    }

    if (first_server == NULL) {
        log_error("__module_loader_servers_load: section server is empty\n");
        goto failed;
    }

    config->server_chain = server_chain_create(first_server, first_lib);
    if (config->server_chain == NULL) {
        log_error("__module_loader_servers_load: can't create server chain\n");
        goto failed;
    }

    result = 1;

    failed:

    if (result == 0) {
        servers_free(first_server);
        routeloader_free(first_lib);
    }

    return result;
}

domain_t* __module_loader_domains_load(const json_token_t* token_array) {
    domain_t* result = NULL;
    domain_t* first_domain = NULL;
    domain_t* last_domain = NULL;

    for (json_it_t it = json_init_it(token_array); !json_end_it(&it); json_next_it(&it)) {
        json_token_t* token_domain = json_it_value(&it);
        if (!json_is_string(token_domain)) {
            log_error("__module_loader_domains_load: domain must be string\n");
            goto failed;
        }

        domain_t* domain = domain_create(json_string(token_domain));
        if (domain == NULL) {
            log_error("__module_loader_domains_load: can't create domain\n");
            goto failed;
        }

        if (first_domain == NULL)
            first_domain = domain;

        if (last_domain != NULL)
            last_domain->next = domain;

        last_domain = domain;
    }

    result = first_domain;

    failed:

    if (result == NULL)
        domains_free(first_domain);

    return result;
}

int __module_loader_databases_load(appconfig_t* config, const json_token_t* token_databases) {
    if (token_databases == NULL) return 1;
    if (!json_is_object(token_databases)) {
        log_error("__module_loader_databases_load: databases must be object\n");
        return 0;
    }

    config->databases = array_create();
    if (config->databases == NULL) {
        log_error("__module_loader_databases_load: can't create databases array\n");
        return 0;
    }

    int result = 0;
    for (json_it_t it = json_init_it(token_databases); !json_end_it(&it); json_next_it(&it)) {
        json_token_t* token_array = json_it_value(&it);
        if (!json_is_array(token_array)) {
            log_error("__module_loader_databases_load: database driver must be array\n");
            goto failed;
        }
        if (json_array_size(token_array) == 0) {
            log_error("__module_loader_databases_load: database driver must be not empty\n");
            goto failed;
        }

        const char* driver = json_it_key(&it);
        db_t* database = NULL;

        #ifdef PostgreSQL_FOUND
        if (strcmp(driver, "postgresql") == 0)
            database = postgresql_load(driver, token_array);
        #endif

        #ifdef MySQL_FOUND
        if (strcmp(driver, "mysql") == 0)
            database = my_load(driver, token_array);
        #endif

        #ifdef Redis_FOUND
        if (strcmp(driver, "redis") == 0)
            database = redis_load(driver, token_array);
        #endif

        if (database == NULL) {
            log_error("__module_loader_databases_load: database driver <%s> not found\n", driver);
            continue;
        }

        array_push_back(config->databases, array_create_pointer(database, array_nocopy, db_free));
    }

    result = 1;

    failed:

    return result;
}

int __module_loader_storages_load(appconfig_t* config, const json_token_t* token_storages) {
    if (token_storages == NULL) return 1;
    if (!json_is_object(token_storages)) {
        log_error("__module_loader_storages_load: storages must be object\n");
        return 0;
    }

    int result = 0;
    storage_t* last_storage = NULL;
    for (json_it_t it = json_init_it(token_storages); !json_end_it(&it); json_next_it(&it)) {
        json_token_t* token_object = json_it_value(&it);
        if (!json_is_object(token_object)) {
            log_error("__module_loader_storages_load: storage must be object\n");
            goto failed;
        }

        const char* storage_name = json_it_key(&it);
        if (strlen(storage_name) == 0) {
            log_error("__module_loader_storages_load: storage name must be not empty\n");
            goto failed;
        }

        json_token_t* token_storage_type = json_object_get(token_object, "type");
        if (!json_is_string(token_storage_type)) {
            log_error("Field type must be string in storage %s\n", storage_name);
            goto failed;
        }

        storage_t* storage = NULL;
        const char* storage_type = json_string(token_storage_type);
        if (strcmp(storage_type, "filesystem") == 0)
            storage = __module_loader_storage_fs_load(token_object, storage_name);
        else if (strcmp(storage_type, "s3") == 0)
            storage = __module_loader_storage_s3_load(token_object, storage_name);
        else
            goto failed;

        if (config->storages == NULL)
            config->storages = storage;

        if (last_storage != NULL)
            last_storage->next = storage;

        last_storage = storage;
    }

    result = 1;

    failed:

    if (result == 0) {
        storages_free(config->storages);
        config->storages = NULL;
    }

    return result;
}

int __module_loader_mimetype_load(appconfig_t* config, const json_token_t* token_mimetypes) {
    if (token_mimetypes == NULL) {
        log_error("__module_loader_mimetype_load: mimetypes not found\n");
        return 0;
    }
    if (!json_is_object(token_mimetypes)) {
        log_error("__module_loader_mimetype_load: mimetypes must be object\n");
        return 0;
    }
    if (json_object_size(token_mimetypes) == 0) {
        log_error("__module_loader_mimetype_load: mimetypes must be not empty\n");
        return 0;
    }

    int result = 0;

    config->mimetype = mimetype_create();
    if (config->mimetype == NULL) {
        log_error("__module_loader_mimetype_load: can't alloc mimetype memory, %d\n", errno);
        goto failed;
    }

    for (json_it_t it_object = json_init_it(token_mimetypes); !json_end_it(&it_object); json_next_it(&it_object)) {
        const char* mimetype = json_it_key(&it_object);
        const json_token_t* token_array = json_it_value(&it_object);
        if (!json_is_array(token_array)) {
            log_error("__module_loader_mimetype_load: mimetype item must be array\n");
            goto failed;
        }
        if (json_array_size(token_array) == 0) {
            log_error("__module_loader_mimetype_load: mimetype item must be not empty\n");
            goto failed;
        }

        for (json_it_t it_array = json_init_it(token_array); !json_end_it(&it_array); json_next_it(&it_array)) {
            const int* index = json_it_key(&it_array);
            const json_token_t* token_value = json_it_value(&it_array);
            if (!json_is_string(token_value)) {
                log_error("__module_loader_mimetype_load: mimetype item.value must be string\n");
                goto failed;
            }
            if (json_string_size(token_value) == 0) {
                log_error("__module_loader_mimetype_load: mimetype item.value must be not empty\n");
                goto failed;
            }

            const char* extension = json_string(token_value);
            if (*index == 0)
                if (!mimetype_add(config->mimetype, MIMETYPE_TABLE_TYPE, mimetype, extension))
                    goto failed;

            if (!mimetype_add(config->mimetype, MIMETYPE_TABLE_EXT, extension, mimetype))
                goto failed;
        }
    }

    result = 1;

    failed:

    if (result == 0) {
        mimetype_destroy(config->mimetype);
        config->mimetype = NULL;
    }

    return result;
}

int __module_loader_viewstore_load(appconfig_t* config) {
    config->viewstore = viewstore_create();
    if (config->viewstore == NULL) {
        log_error("__module_loader_viewstore_load: can't create viewstore\n");
        return 0;
    }

    return 1;
}

int __module_loader_sessionconfig_load(appconfig_t* config, const json_token_t* token_sessions) {
    if (token_sessions == NULL) return 1;
    if (!json_is_object(token_sessions)) {
        log_error("__module_loader_sessionconfig_load: sessions must be object\n");
        return 0;
    }

    int result = 0;
    json_token_t* token_driver = json_object_get(token_sessions, "driver");
    if (!json_is_string(token_driver)) {
        log_error("__module_loader_sessionconfig_load: field driver must be string in sessions section\n");
        goto failed;
    }

    const char* driver = json_string(token_driver);
    if (strcmp(driver, "storage") == 0) {
        config->sessionconfig.driver = SESSION_TYPE_FS;

        config->sessionconfig.session = sessionfile_init();
        if (config->sessionconfig.session == NULL) {
            log_error("__module_loader_sessionconfig_load: can't create sessionfile\n");
            goto failed;
        }

        json_token_t* token_storage_name = json_object_get(token_sessions, "storage_name");
        if (!json_is_string(token_storage_name)) {
            log_error("__module_loader_sessionconfig_load: field storage_name must be string in sessions section\n");
            goto failed;
        }

        const char* storage_name = json_string(token_storage_name);
        if (strlen(storage_name) == 0) {
            log_error("__module_loader_sessionconfig_load: field storage_name must be not empty in sessions section\n");
            goto failed;
        }

        strcpy(config->sessionconfig.storage_name, storage_name);
    }
    else if (strcmp(driver, "redis") == 0) {
        config->sessionconfig.driver = SESSION_TYPE_REDIS;

        config->sessionconfig.session = sessionredis_init();
        if (config->sessionconfig.session == NULL) {
            log_error("__module_loader_sessionconfig_load: can't create sessionredis\n");
            goto failed;
        }

        json_token_t* token_host_id = json_object_get(token_sessions, "host_id");
        if (!json_is_string(token_host_id)) {
            log_error("__module_loader_sessionconfig_load: field host_id must be string in sessions section\n");
            goto failed;
        }

        const char* host_id = json_string(token_host_id);
        if (strlen(host_id) == 0) {
            log_error("__module_loader_sessionconfig_load: field host_id must be not empty in sessions section\n");
            goto failed;
        }

        strcpy(config->sessionconfig.host_id, host_id);
    }
    else {
        log_error("__module_loader_sessionconfig_load: field driver not found in sessions section\n");
        goto failed;
    }

    json_token_t* token_lifetime = json_object_get(token_sessions, "lifetime");
    if (token_lifetime == NULL) {
        log_error("__module_loader_sessionconfig_load: field lifetime not found in sessions section\n");
        goto failed;
    }
    if (!json_is_number(token_lifetime)) {
        log_error("__module_loader_sessionconfig_load: field lifetime must be int in sessions section\n");
        goto failed;
    }
    int ok = 0;
    int lifetime = json_int(token_lifetime, &ok);
    if (!ok || lifetime <= 0) {
        log_error("__module_loader_sessionconfig_load: field lifetime must be positive in sessions section\n");
        goto failed;
    }

    config->sessionconfig.lifetime = lifetime;

    result = 1;

    failed:

    if (result == 0)
        sessionconfig_clear(&config->sessionconfig);

    return result;
}

int __module_loader_prepared_queries_load(appconfig_t* config) {
    for (int i = 0; i < pstmt_count(); i++) {
        prepare_stmt_t* stmt = (pstmt_list()[i])();
        if (stmt == NULL) {
            log_error("__module_loader_prepared_queries_load: can't create prepared statement\n");
            return 0;
        }
        array_push_back(config->prepared_queries, array_create_pointer(stmt, array_nocopy, pstmt_free));
    }

    return 1;
}

int __module_loader_http_routes_load(routeloader_lib_t** first_lib, const json_token_t* token_object, route_t** route, map_t* ratelimiter_config) {
    int result = 0;
    route_t* first_route = NULL;
    route_t* last_route = NULL;
    routeloader_lib_t* last_lib = routeloader_get_last(*first_lib);

    if (token_object == NULL) return 1;
    if (!json_is_object(token_object)) {
        log_error("__module_loader_http_routes_load: http.route must be object\n");
        goto failed;
    }
    if (json_object_size(token_object) == 0) return 1;

    for (json_it_t it = json_init_it(token_object); !json_end_it(&it); json_next_it(&it)) {
        const char* route_path = json_it_key(&it);
        if (strlen(route_path) == 0) {
            log_error("__module_loader_http_routes_load: route path is empty\n");
            goto failed;
        }

        route_t* rt = route_create(route_path);
        if (rt == NULL) {
            log_error("__module_loader_http_routes_load: failed to create route\n");
            goto failed;
        }

        if (first_route == NULL)
            first_route = rt;

        if (last_route != NULL)
            last_route->next = rt;

        last_route = rt;

        if (!__module_loader_set_http_route(first_lib, &last_lib, rt, json_it_value(&it), ratelimiter_config)) {
            log_error("__module_loader_http_routes_load: failed to set http route\n");
            goto failed;
        }
    }

    result = 1;

    *route = first_route;

    failed:

    if (result == 0)
        routes_free(first_route);

    return result;
}

int __module_loader_set_http_route(routeloader_lib_t** first_lib, routeloader_lib_t** last_lib, route_t* route, const json_token_t* token_object, map_t* ratelimiter_config) {
    if (token_object == NULL) {
        log_error("__module_loader_set_http_route: http.route item is empty\n");
        return 0;
    }
    if (!json_is_object(token_object)) {
        log_error("__module_loader_set_http_route: http.route item must be object\n");
        return 0;
    }
    for (json_it_t it = json_init_it(token_object); !json_end_it(&it); json_next_it(&it)) {
        const char* method = json_it_key(&it);
        if (strlen(method) == 0) {
            log_error("__module_loader_set_http_route: http.route item.key must be not empty\n");
            return 0;
        }

        json_token_t* token_object = json_it_value(&it);
        if (!json_is_object(token_object)) {
            log_error("__module_loader_set_http_route: http.route item.value must be object\n");
            return 0;
        }

        if (json_object_size(token_object) < 1) {
            log_error("__module_loader_set_http_route: http.route item.value must be object with at least 1 element\n");
            return 0;
        }

        const json_token_t* token_ratelimit = json_object_get(token_object, "ratelimit");
        ratelimiter_t* ratelimiter = NULL;
        if (token_ratelimit != NULL) {
            if (!json_is_string(token_ratelimit)) {
                log_error("__module_loader_set_http_route: http.route item.value.handler must be string\n");
                return 0;
            }
            if (json_string_size(token_ratelimit) == 0) {
                log_error("__module_loader_set_http_route: http.route item.value.handler must be not empty string\n");
                return 0;
            }

            const char* ratelimit_name = json_string(token_ratelimit);
            ratelimiter_config_t* config = map_find(ratelimiter_config, ratelimit_name);
            if (config == NULL) {
                log_error("__module_loader_set_http_route: ratelimiter %s not found\n", ratelimit_name);
                return 0;
            }

            ratelimiter = ratelimiter_init(config);
            if (ratelimiter == NULL) {
                log_error("__module_loader_set_http_route: failed to create ratelimiter %s\n", ratelimit_name);
                return 0;
            }
        }

        const json_token_t* token_static_file = json_object_get(token_object, "static_file");
        if (token_static_file != NULL) {
            if (!json_is_string(token_static_file)) {
                log_error("__module_loader_set_http_route: http.route item.value.static_file must be string\n");
                return 0;
            }
            if (json_string_size(token_static_file) == 0) {
                log_error("__module_loader_set_http_route: http.route item.value.static_file must be not empty string\n");
                return 0;
            }
            const char* static_file = json_string(token_static_file);
            if (!route_set_http_static(route, method, static_file, ratelimiter)) {
                log_error("__module_loader_set_http_route: failed to set static file %s\n", static_file);
                return 0;
            }

            continue;
        }

        const json_token_t* token_file = json_object_get(token_object, "file");
        if (!json_is_string(token_file)) {
            log_error("__module_loader_set_http_route: http.route item.value.route must be string\n");
            return 0;
        }
        if (json_string_size(token_file) == 0) {
            log_error("__module_loader_set_http_route: http.route item.value.route must be not empty string\n");
            return 0;
        }
        const json_token_t* token_function = json_object_get(token_object, "function");
        if (!json_is_string(token_function)) {
            log_error("__module_loader_set_http_route: http.route item.value.handler must be string\n");
            return 0;
        }
        if (json_string_size(token_function) == 0) {
            log_error("__module_loader_set_http_route: http.route item.value.handler must be not empty string\n");
            return 0;
        }

        const char* lib_file = json_string(token_file);
        const char* lib_handler = json_string(token_function);
        if (!routeloader_has_lib(*first_lib, lib_file)) {
            routeloader_lib_t* routeloader_lib = routeloader_load_lib(lib_file);
            if (routeloader_lib == NULL) {
                log_error("__module_loader_set_http_route: failed to load lib %s\n", lib_file);
                return 0;
            }

            if (*first_lib == NULL)
                *first_lib = routeloader_lib;

            if (*last_lib != NULL)
                (*last_lib)->next = routeloader_lib;

            *last_lib = routeloader_lib;
        }

        void(*function)(void*);
        *(void**)(&function) = routeloader_get_handler(*first_lib, lib_file, lib_handler);
        if (function == NULL) {
            log_error("__module_loader_set_http_route: failed to get handler %s.%s\n", lib_file, lib_handler);
            return 0;
        }

        if (!route_set_http_handler(route, method, function, ratelimiter)) {
            log_error("__module_loader_set_http_route: failed to set http handler %s.%s\n", lib_file, lib_handler);
            return 0;
        }

        __module_loader_pass_memory_sharedlib(*first_lib, lib_file);
    }

    return 1;
}

void __module_loader_pass_memory_sharedlib(routeloader_lib_t* first_lib, const char* lib_file) {
    void(*function)(void*);
    *(void**)(&function) = routeloader_get_handler_silent(first_lib, lib_file, "appconfig_set");

    if (function != NULL)
        function(appconfig());
}

int __module_loader_http_redirects_load(const json_token_t* token_object, redirect_t** redirect) {
    int result = 0;
    redirect_t* first_redirect = NULL;
    redirect_t* last_redirect = NULL;

    if (token_object == NULL) return 1;
    if (!json_is_object(token_object)) {
        log_error("__module_loader_http_redirects_load: http.redirects must be object\n");
        goto failed;
    }
    if (json_object_size(token_object) == 0) return 1;

    for (json_it_t it = json_init_it(token_object); !json_end_it(&it); json_next_it(&it)) {
        json_token_t* token_value = json_it_value(&it);
        if (token_value == NULL) {
            log_error("__module_loader_http_redirects_load: http.redirects item.value is empty\n");
            goto failed;
        }
        if (!json_is_string(token_value)) {
            log_error("__module_loader_http_redirects_load: http.redirects item.value must be string\n");
            goto failed;
        }
        if (json_string_size(token_value) == 0) {
            log_error("__module_loader_http_redirects_load: http.redirects item.value is empty\n");
            goto failed;
        }

        const char* redirect_path = json_it_key(&it);
        if (strlen(redirect_path) == 0) {
            log_error("__module_loader_http_redirects_load: http.redirects item.key is empty\n");
            goto failed;
        }

        const char* redirect_target = json_string(token_value);
        redirect_t* redirect = redirect_create(redirect_path, redirect_target);
        if (redirect == NULL) {
            log_error("__module_loader_http_redirects_load: failed to create redirect\n");
            goto failed;
        }

        if (first_redirect == NULL)
            first_redirect = redirect;

        if (last_redirect != NULL)
            last_redirect->next = redirect;

        last_redirect = redirect;
    }

    result = 1;

    *redirect = first_redirect;

    failed:

    if (result == 0)
        redirect_free(first_redirect);

    return result;
}

int __module_loader_middlewares_load(const json_token_t* token_array, middleware_item_t** middleware_item) {
    int result = 0;
    middleware_item_t* first_middleware = NULL;
    middleware_item_t* last_middleware = NULL;

    if (token_array == NULL) return 1;
    if (!json_is_array(token_array)) {
        log_error("__module_loader_middlewares_load: http.middlewares must be array\n");
        goto failed;
    }
    if (json_array_size(token_array) == 0) return 1;

    for (json_it_t it = json_init_it(token_array); !json_end_it(&it); json_next_it(&it)) {
        json_token_t* token_value = json_it_value(&it);
        if (!json_is_string(token_value)) {
            log_error("__module_loader_middlewares_load: http.middlewares item.value must be string\n");
            goto failed;
        }
        if (json_string_size(token_value) == 0) {
            log_error("__module_loader_middlewares_load: http.middlewares item.value is empty\n");
            goto failed;
        }

        const char* middleware_name = json_string(token_value);
        middleware_fn_p fn = middleware_by_name(middleware_name);
        if (fn == NULL) {
            log_error("__module_loader_middlewares_load: failed to find middleware %s\n", middleware_name);
            goto failed;
        }

        middleware_item_t* middleware_item = middleware_create(fn);
        if (middleware_item == NULL) {
            log_error("__module_loader_middlewares_load: failed to create middleware\n");
            goto failed;
        }

        if (first_middleware == NULL)
            first_middleware = middleware_item;

        if (last_middleware != NULL)
            last_middleware->next = middleware_item;

        last_middleware = middleware_item;
    }

    result = 1;

    *middleware_item = first_middleware;

    failed:

    if (result == 0)
        middlewares_free(first_middleware);

    return result;
}

int __module_loader_websockets_default_load(void(**fn)(void*), routeloader_lib_t** first_lib, const json_token_t* token_object, map_t* ratelimiter_config) {
    *fn = (void(*)(void*))websockets_default_handler;

    if (!json_is_object(token_object)) {
        log_error("__module_loader_websockets_default_load: websockets.route item.value must be object\n");
        return 0;
    }
    if (json_object_size(token_object) < 2) {
        log_error("__module_loader_websockets_default_load: websockets.route item.value must be object with at least 2 elements\n");
        return 0;
    }

    const json_token_t* token_file = json_object_get(token_object, "file");
    if (!json_is_string(token_file)) {
        log_error("__module_loader_websockets_default_load: websockets.route item.value.route must be string\n");
        return 0;
    }
    if (json_string_size(token_file) == 0) {
        log_error("__module_loader_websockets_default_load: websockets.route item.value.route must be not empty string\n");
        return 0;
    }
    const json_token_t* token_function = json_object_get(token_object, "function");
    if (!json_is_string(token_function)) {
        log_error("__module_loader_websockets_default_load: websockets.route item.value.handler must be string\n");
        return 0;
    }
    if (json_string_size(token_function) == 0) {
        log_error("__module_loader_websockets_default_load: websockets.route item.value.handler must be not empty string\n");
        return 0;
    }
    const json_token_t* token_ratelimit = json_object_get(token_object, "ratelimit");
    ratelimiter_t* ratelimiter = NULL;
    if (token_ratelimit != NULL) {
        if (!json_is_string(token_ratelimit)) {
            log_error("__module_loader_websockets_default_load: websockets.route item.value.handler must be string\n");
            return 0;
        }
        if (json_string_size(token_ratelimit) == 0) {
            log_error("__module_loader_websockets_default_load: websockets.route item.value.handler must be not empty string\n");
            return 0;
        }

        const char* ratelimit_name = json_string(token_ratelimit);
        ratelimiter_config_t* config = map_find(ratelimiter_config, ratelimit_name);
        if (config == NULL) {
            log_error("__module_loader_websockets_default_load: ratelimiter %s not found\n", ratelimit_name);
            return 0;
        }

        ratelimiter = ratelimiter_init(config);
        if (ratelimiter == NULL) {
            log_error("__module_loader_websockets_default_load: failed to create ratelimiter %s\n", ratelimit_name);
            return 0;
        }
    }

    routeloader_lib_t* last_lib = routeloader_get_last(*first_lib);
    const char* lib_file = json_string(token_file);
    const char* lib_handler = json_string(token_function);
    if (!routeloader_has_lib(*first_lib, lib_file)) {
        routeloader_lib_t* routeloader_lib = routeloader_load_lib(lib_file);
        if (routeloader_lib == NULL) {
            log_error("__module_loader_websockets_default_load: failed to load lib %s\n", lib_file);
            return 0;
        }

        if (*first_lib == NULL)
            *first_lib = routeloader_lib;

        if (last_lib != NULL)
            last_lib->next = routeloader_lib;

        last_lib = routeloader_lib;
    }

    *(void**)(&(*fn)) = routeloader_get_handler(*first_lib, lib_file, lib_handler);

    return 1;
}

int __module_loader_websockets_routes_load(routeloader_lib_t** first_lib, const json_token_t* token_object, route_t** route, map_t* ratelimiter_config) {
    int result = 0;
    route_t* first_route = NULL;
    route_t* last_route = NULL;
    routeloader_lib_t* last_lib = routeloader_get_last(*first_lib);

    if (token_object == NULL) return 1;
    if (!json_is_object(token_object)) {
        log_error("__module_loader_websockets_routes_load: websockets.routes must be object\n");
        goto failed;
    }
    if (json_object_size(token_object) == 0) return 1;

    for (json_it_t it = json_init_it(token_object); !json_end_it(&it); json_next_it(&it)) {
        const char* route_path = json_it_key(&it);
        if (strlen(route_path) == 0) {
            log_error("__module_loader_websockets_routes_load: websockets.route path is empty\n");
            goto failed;
        }

        route_t* rt = route_create(route_path);
        if (rt == NULL) {
            log_error("__module_loader_websockets_routes_load: failed to create route\n");
            goto failed;
        }

        if (first_route == NULL)
            first_route = rt;

        if (last_route != NULL)
            last_route->next = rt;

        last_route = rt;

        if (!__module_loader_set_websockets_route(first_lib, &last_lib, rt, json_it_value(&it), ratelimiter_config)) {
            log_error("__module_loader_websockets_routes_load: failed to set websockets route\n");
            goto failed;
        }
    }

    result = 1;
    
    *route = first_route;

    failed:

    if (result == 0)
        routes_free(first_route);

    return result;
}

int __module_loader_set_websockets_route(routeloader_lib_t** first_lib, routeloader_lib_t** last_lib, route_t* route, const json_token_t* token_object, map_t* ratelimiter_config) {
    if (token_object == NULL) {
        log_error("__module_loader_set_websockets_route: websockets.route item is empty\n");
        return 0;
    }
    if (!json_is_object(token_object)) {
        log_error("__module_loader_set_websockets_route: websockets.route item must be object\n");
        return 0;
    }
    for (json_it_t it = json_init_it(token_object); !json_end_it(&it); json_next_it(&it)) {
        const char* method = json_it_key(&it);
        if (strlen(method) == 0) {
            log_error("__module_loader_set_websockets_route: websockets.route item.key is empty\n");
            return 0;
        }

        json_token_t* token_object = json_it_value(&it);
        if (!json_is_object(token_object)) {
            log_error("__module_loader_set_websockets_route: websockets.route item.value must be object\n");
            return 0;
        }
        if (json_object_size(token_object) < 2) {
            log_error("__module_loader_set_websockets_route: websockets.route item.value must be object with at least 2 elements\n");
            return 0;
        }

        const json_token_t* token_file = json_object_get(token_object, "file");
        if (!json_is_string(token_file)) {
            log_error("__module_loader_set_websockets_route: websockets.route item.value.route must be string\n");
            return 0;
        }
        if (json_string_size(token_file) == 0) {
            log_error("__module_loader_set_websockets_route: websockets.route item.value.route must be not empty string\n");
            return 0;
        }
        const json_token_t* token_function = json_object_get(token_object, "function");
        if (!json_is_string(token_function)) {
            log_error("__module_loader_set_websockets_route: websockets.route item.value.handler must be string\n");
            return 0;
        }
        if (json_string_size(token_function) == 0) {
            log_error("__module_loader_set_websockets_route: websockets.route item.value.handler must be not empty string\n");
            return 0;
        }
        const json_token_t* token_ratelimit = json_object_get(token_object, "ratelimit");
        ratelimiter_t* ratelimiter = NULL;
        if (token_ratelimit != NULL) {
            if (!json_is_string(token_ratelimit)) {
                log_error("__module_loader_set_websockets_route: websockets.route item.value.handler must be string\n");
                return 0;
            }
            if (json_string_size(token_ratelimit) == 0) {
                log_error("__module_loader_set_websockets_route: websockets.route item.value.handler must be not empty string\n");
                return 0;
            }

            const char* ratelimit_name = json_string(token_ratelimit);
            ratelimiter_config_t* config = map_find(ratelimiter_config, ratelimit_name);
            if (config == NULL) {
                log_error("__module_loader_set_websockets_route: ratelimiter %s not found\n", ratelimit_name);
                return 0;
            }

            ratelimiter = ratelimiter_init(config);
            if (ratelimiter == NULL) {
                log_error("__module_loader_set_websockets_route: failed to create ratelimiter %s\n", ratelimit_name);
                return 0;
            }
        }

        const char* lib_file = json_string(token_file);
        const char* lib_handler = json_string(token_function);
        routeloader_lib_t* routeloader_lib = NULL;
        if (!routeloader_has_lib(*first_lib, lib_file)) {
            routeloader_lib = routeloader_load_lib(lib_file);
            if (routeloader_lib == NULL) {
                log_error("__module_loader_set_websockets_route: failed to load lib %s\n", lib_file);
                return 0;
            }

            if (*first_lib == NULL)
                *first_lib = routeloader_lib;

            if (*last_lib != NULL)
                (*last_lib)->next = routeloader_lib;

            *last_lib = routeloader_lib;
        }

        void(*function)(void*);
        *(void**)(&function) = routeloader_get_handler(*first_lib, lib_file, lib_handler);

        if (function == NULL) {
            log_error("__module_loader_set_websockets_route: failed to get handler %s.%s\n", lib_file, lib_handler);
            return 0;
        }

        if (!route_set_websockets_handler(route, method, function, ratelimiter)) {
            log_error("__module_loader_set_websockets_route: failed to set websockets handler\n");
            return 0;
        }

        __module_loader_pass_memory_sharedlib(*first_lib, lib_file);
    }

    return 1;
}

void module_loader_create_config_and_init(void) {
    appconfig_t* newconfig = appconfig_create(appconfig_path());
    if (newconfig == NULL) {
        log_error("appconfig_threads_pause: can't create new config\n");
        return;
    }

    pstmt_registry_clear();
    middleware_registry_clear();
    appconfig_set(newconfig);
    module_loader_init(newconfig);
}

void __module_loader_on_shutdown_cb(void) {
    atomic_store(&appconfig()->shutdown, 1);
    module_loader_wakeup_all_threads();
}

map_t* __module_loader_ratelimits_configs_load(const json_token_t* token_object) {
    if (!json_is_object(token_object)) {
        log_error("__module_loader_ratelimits_config_load: ratelimits must be object\n");
        return NULL;
    }

    map_t* map = map_create_ex(map_compare_string, map_copy_string, free, NULL, free);
    if (map == NULL) {
        log_error("__module_loader_ratelimits_config_load: can't create ratelimits map\n");
        return NULL;
    }

    for (json_it_t it = json_init_it(token_object); !json_end_it(&it); json_next_it(&it)) {
        const char* key = json_it_key(&it);
        json_token_t* token_object = json_it_value(&it);

        if (!json_is_object(token_object)) {
            log_error("__module_loader_ratelimits_config_load: ratelimits.%s must be object\n", key);
            map_free(map);
            return NULL;
        }

        ratelimiter_config_t* config = __module_loader_ratelimits_config_load(token_object);
        if (config == NULL) {
            map_free(map);
            return NULL;
        }

        if (map_insert_or_assign(map, key, config) == -1) {
            log_error("__module_loader_ratelimits_config_load: can't insert ratelimits.%s\n", key);
            free(config);
            map_free(map);
            return NULL;
        }
    }

    return map;
}

ratelimiter_config_t* __module_loader_ratelimits_config_load(const json_token_t* token_object) {
    if (!json_is_object(token_object)) {
        log_error("__module_loader_ratelimits_config_load: ratelimits must be object\n");
        return NULL;
    }

    ratelimiter_config_t* config = malloc(sizeof * config);
    if (config == NULL) {
        log_error("__module_loader_ratelimits_config_load: can't allocate ratelimits config\n");
        return NULL;
    }

    config->time_window_ns = 1000000000ULL; // 1 секунда
    config->cleanup_interval_s = 60; // 5 минут

    const json_token_t* token_burst = json_object_get(token_object, "burst");
    if (!json_is_number(token_burst)) {
        log_error("__module_loader_ratelimits_config_load: ratelimits.burst must be number\n");
        free(config);
        return NULL;
    }

    int ok = 0;
    const int burst = json_int(token_burst, &ok);
    if (!ok) {
        log_error("__module_loader_ratelimits_config_load: ratelimits.burst must be integer\n");
        free(config);
        return NULL;
    }

    config->max_tokens = burst;

    const json_token_t* token_rate = json_object_get(token_object, "rate");
    if (!json_is_number(token_rate)) {
        log_error("__module_loader_ratelimits_config_load: ratelimits.rate must be number\n");
        free(config);
        return NULL;
    }

    const int rate = json_int(token_rate, &ok);
    if (!ok) {
        log_error("__module_loader_ratelimits_config_load: ratelimits.rate must be integer\n");
        free(config);
        return NULL;
    }

    config->refill_rate = rate;

    return config;
}

int __module_loader_http_ratelimit_load(const json_token_t* token_string, ratelimiter_t** ratelimiter, map_t* ratelimits_config) {
    *ratelimiter = NULL;

    if (token_string == NULL) return 1;

    if (!json_is_string(token_string)) {
        log_error("__module_loader_http_ratelimit_load: http.ratelimit must be string\n");
        return 0;
    }

    if (json_string_size(token_string) == 0) {
        log_error("__module_loader_http_ratelimit_load: http.ratelimit must be not empty string\n");
        return 0;
    }

    if (ratelimits_config == NULL) {
        log_error("__module_loader_http_ratelimit_load: ratelimits config not loaded\n");
        return 0;
    }

    const char* ratelimit_name = json_string(token_string);
    ratelimiter_config_t* config = map_find(ratelimits_config, ratelimit_name);
    if (config == NULL) {
        log_error("__module_loader_http_ratelimit_load: ratelimiter %s not found\n", ratelimit_name);
        return 0;
    }

    *ratelimiter = ratelimiter_init(config);
    if (*ratelimiter == NULL) {
        log_error("__module_loader_http_ratelimit_load: failed to create ratelimiter %s\n", ratelimit_name);
        return 0;
    }

    return 1;
}

int __module_loader_websockets_ratelimit_load(const json_token_t* token_string, ratelimiter_t** ratelimiter, map_t* ratelimits_config) {
    *ratelimiter = NULL;

    if (token_string == NULL) return 1;

    if (!json_is_string(token_string)) {
        log_error("__module_loader_websockets_ratelimit_load: websockets.ratelimit must be string\n");
        return 0;
    }

    if (json_string_size(token_string) == 0) {
        log_error("__module_loader_websockets_ratelimit_load: websockets.ratelimit must be not empty string\n");
        return 0;
    }

    if (ratelimits_config == NULL) {
        log_error("__module_loader_websockets_ratelimit_load: ratelimits config not loaded\n");
        return 0;
    }

    const char* ratelimit_name = json_string(token_string);
    ratelimiter_config_t* config = map_find(ratelimits_config, ratelimit_name);
    if (config == NULL) {
        log_error("__module_loader_websockets_ratelimit_load: ratelimiter %s not found\n", ratelimit_name);
        return 0;
    }

    *ratelimiter = ratelimiter_init(config);
    if (*ratelimiter == NULL) {
        log_error("__module_loader_websockets_ratelimit_load: failed to create ratelimiter %s\n", ratelimit_name);
        return 0;
    }

    return 1;
}

void module_loader_signal_lock(void) {
    atomic_store(&__module_loader_wait_signal, 1);
}

int module_loader_signal_locked(void) {
    return atomic_load(&__module_loader_wait_signal);
}

void module_loader_signal_unlock(void) {
    atomic_store(&__module_loader_wait_signal, 0);
}

void module_loader_wakeup_all_threads(void) {
    thread_handlers_wakeup();
}

void* __module_loader_storage_fs_load(const json_token_t* token_object, const char* storage_name) {
    void* result = NULL;

    const char* root = __module_loader_storage_field(storage_name, token_object, "root");
    if (root == NULL) goto failed;

    char root_path[PATH_MAX];
    strcpy(root_path, root);
    size_t root_path_length = strlen(root_path);
    while (root_path_length > 0) {
        root_path_length--;
        if (root_path[root_path_length] == '/')
            root_path[root_path_length] = 0;
        else
            break;
    }

    if (root_path_length == 0) {
        log_error("__module_loader_storage_fs_load: storage %s has empty path\n", storage_name);
        goto failed;
    }

    storagefs_t* storage = storage_create_fs(storage_name, root_path);
    if (storage == NULL) {
        log_error("__module_loader_storage_fs_load: failed to create storage %s\n", storage_name);
        goto failed;
    }

    result = storage;

    failed:

    return result;
}

void* __module_loader_storage_s3_load(const json_token_t* token_object, const char* storage_name) {
    void* result = NULL;

    const char* access_id = __module_loader_storage_field(storage_name, token_object, "access_id");
    if (access_id == NULL) {
        log_error("__module_loader_storage_s3_load: storage %s has empty access_id\n");
        goto failed;
    }

    const char* access_secret = __module_loader_storage_field(storage_name, token_object, "access_secret");
    if (access_secret == NULL) {
        log_error("__module_loader_storage_s3_load: storage %s has empty access_secret\n");
        goto failed;
    }

    const char* protocol = __module_loader_storage_field(storage_name, token_object, "protocol");
    if (protocol == NULL) {
        log_error("__module_loader_storage_s3_load: storage %s has empty protocol\n");
        goto failed;
    }

    const char* host = __module_loader_storage_field(storage_name, token_object, "host");
    if (host == NULL) {
        log_error("__module_loader_storage_s3_load: storage %s has empty host\n");
        goto failed;
    }

    const char* port = __module_loader_storage_field(storage_name, token_object, "port");
    if (port == NULL) {
        log_error("__module_loader_storage_s3_load: storage %s has empty port\n");
        goto failed;
    }

    const char* bucket = __module_loader_storage_field(storage_name, token_object, "bucket");
    if (bucket == NULL) {
        log_error("__module_loader_storage_s3_load: storage %s has empty bucket\n");
        goto failed;
    }

    const char* region = __module_loader_storage_field(storage_name, token_object, "region");
    if (region == NULL) {
        log_error("__module_loader_storage_s3_load: storage %s has empty region\n");
        goto failed;
    }

    storages3_t* storage = storage_create_s3(storage_name, access_id, access_secret, protocol, host, port, bucket, region);
    if (storage == NULL) {
        log_error("__module_loader_storage_s3_load: failed to create storage %s\n", storage_name);
        goto failed;
    }

    result = storage;

    failed:

    return result;
}

const char* __module_loader_storage_field(const char* storage_name, const json_token_t* token_object, const char* key) {
    json_token_t* token_value = json_object_get(token_object, key);
    if (!json_is_string(token_value)) {
        log_error("__module_loader_storage_field: field %s must be string in storage %s\n", key, storage_name);
        return NULL;
    }

    const char* value = json_string(token_value);
    if (json_string_size(token_value) == 0) {
        log_error("__module_loader_storage_field: field %s is empty in storage %s\n", key, storage_name);
        return NULL;
    }

    return value;
}

openssl_t* __module_loader_tls_load(const json_token_t* token_object) {
    if (token_object == NULL) {
        log_error("__module_loader_tls_load: openssl not found\n");
        return NULL;
    }
    if (!json_is_object(token_object)) {
        log_error("__module_loader_tls_load: openssl must be object\n");
        return NULL;
    }

    openssl_t* result = NULL;
    openssl_t* openssl = openssl_create();
    if (openssl == NULL) {
        log_error("__module_loader_tls_load: failed to create openssl\n");
        return NULL;
    }

    enum fields { FULLCHAIN = 0, PRIVATE, CIPHERS, FIELDS_COUNT };
    char* finded_fields_str[FIELDS_COUNT] = {"fullchain", "private", "ciphers"};
    int finded_fields[FIELDS_COUNT] = {0};
    for (json_it_t it = json_init_it(token_object); !json_end_it(&it); json_next_it(&it)) {
        const char* key = json_it_key(&it);
        if (strlen(key) == 0) {
            log_error("__module_loader_tls_load: tls key is empty\n");
            goto failed;
        }

        const json_token_t* token_value = json_it_value(&it);
        if (token_value == NULL) {
            log_error("__module_loader_tls_load: tls value is empty\n");
            goto failed;
        }

        if (strcmp(key, "fullchain") == 0) {
            if (!json_is_string(token_value)) {
                log_error("__module_loader_tls_load: field fullchain must be string type\n");
                goto failed;
            }
            if (json_string_size(token_value) == 0) {
                log_error("__module_loader_tls_load: field fullchain is empty\n");
                goto failed;
            }

            finded_fields[FULLCHAIN] = 1;

            openssl->fullchain = malloc(json_string_size(token_value) + 1);
            if (openssl->fullchain == NULL) {
                log_error("__module_loader_tls_load: failed to allocate memory for fullchain\n");
                goto failed;
            }

            strcpy(openssl->fullchain, json_string(token_value));
        }
        else if (strcmp(key, "private") == 0) {
            if (!json_is_string(token_value)) {
                log_error("Openssl field private must be string type\n");
                goto failed;
            }
            if (json_string_size(token_value) == 0) {
                log_error("__module_loader_tls_load: field private is empty\n");
                goto failed;
            }

            finded_fields[PRIVATE] = 1;

            openssl->private = malloc(json_string_size(token_value) + 1);
            if (openssl->private == NULL) {
                log_error("__module_loader_tls_load: failed to allocate memory for private\n");
                goto failed;
            }

            strcpy(openssl->private, json_string(token_value));
        }
        else if (strcmp(key, "ciphers") == 0) {
            if (!json_is_string(token_value)) {
                log_error("Openssl field ciphers must be string type\n");
                goto failed;
            }
            if (json_string_size(token_value) == 0) {
                log_error("__module_loader_tls_load: field ciphers is empty\n");
                goto failed;
            }

            finded_fields[CIPHERS] = 1;

            openssl->ciphers = malloc(json_string_size(token_value) + 1);
            if (openssl->ciphers == NULL) {
                log_error("__module_loader_tls_load: failed to allocate memory for ciphers\n");
                goto failed;
            }

            strcpy(openssl->ciphers, json_string(token_value));
        }
    }

    for (int i = 0; i < FIELDS_COUNT; i++) {
        if (finded_fields[i] == 0) {
            log_error("__module_loader_tls_load: field %s not found in tls\n", finded_fields_str[i]);
            goto failed;
        }
    }

    if (!openssl_init(openssl))
        goto failed;

    result = openssl;

    failed:

    if (result == NULL)
        openssl_free(openssl);

    return result;
}

int __module_loader_check_unique_domainport(server_t* first_server) {
    for (server_t* current_server = first_server; current_server; current_server = current_server->next) {
        unsigned short int current_port = current_server->port;
        for (domain_t* current_domain = current_server->domain; current_domain; current_domain = current_domain->next) {

            for (server_t* server = first_server; server; server = server->next) {
                unsigned short int port = server->port;
                for (domain_t* domain = server->domain; domain; domain = domain->next) {
                    if (current_domain == domain) continue;

                    if (strcmp(current_domain->template, domain->template) == 0 && current_port == port) {
                        log_error("__module_loader_check_unique_domainport: domains with ports must be unique. %s %d\n", domain->template, port);
                        return 0;
                    }
                }
            }
        }
    }

    return 1;
}

int __module_loader_thread_taskmanager_load(appconfig_t* config) {
    return taskmanager_create_threads(config);
}

int __module_loader_thread_workers_load(appconfig_t* config) {
    const int count = config->env.main.workers;
    if (count <= 0) {
        log_error("__module_loader_thread_workers_load: set the number of workers\n");
        return 0;
    }

    thread_worker_set_threads_shutdown_cb(__module_loader_on_shutdown_cb);

    return thread_worker_run(config, count);
}

int __module_loader_thread_handlers_load(appconfig_t* config) {
    const int count = config->env.main.threads;
    if (count <= 0) {
        log_error("__module_loader_thread_handlers_load: set the number of threads\n");
        return 0;
    }

    return thread_handler_run(config, count);
}

int __module_loader_taskmanager_init(appconfig_t* config, json_token_t* token_taskmanager) {
    if (token_taskmanager == NULL)
        return 1;

    if (!json_is_object(token_taskmanager)) {
        log_error("__module_loader_taskmanager_init: task_manager must be object\n");
        return 0;
    }

    taskmanager_t* manager = taskmanager_init();
    if (manager == NULL) {
        log_error("__module_loader_taskmanager_init: failed to initialize taskmanager\n");
        return 0;
    }

    config->taskmanager = manager;

    if (!__module_loader_taskmanager_load(config, manager, token_taskmanager)) {
        log_error("__module_loader_taskmanager_init: failed to load scheduled tasks\n");
        return 0;
    }

    return 1;
}

int __module_loader_translations_load(appconfig_t* config, json_token_t* translations) {
    // translations is optional
    if (translations == NULL) {
        config->translations = NULL;
        return 1;
    }

    if (!json_is_array(translations)) {
        log_error("__module_loader_translations_load: translations must be array\n");
        return 0;
    }

    config->translations = map_create_ex(
        map_compare_string,
        map_copy_string,  // key_copy
        free,             // key_free
        NULL,             // value_copy
        (map_free_fn)i18n_free  // value_free
    );
    if (config->translations == NULL) {
        log_error("__module_loader_translations_load: failed to create translations map\n");
        return 0;
    }

    // Load each translation domain
    // Format: [{ "domain": "identity", "path": "/path/to/locale" }, ...]
    json_it_t it = json_init_it(translations);
    while (!json_end_it(&it)) {
        json_token_t* item = json_it_value(&it);

        if (!json_is_object(item)) {
            log_error("__module_loader_translations_load: translation item must be object\n");
            it = json_next_it(&it);
            continue;
        }

        const char* domain = json_string(json_object_get(item, "domain"));
        if (domain == NULL || *domain == '\0') {
            log_error("__module_loader_translations_load: domain is required\n");
            it = json_next_it(&it);
            continue;
        }

        const char* locale_dir = json_string(json_object_get(item, "path"));
        if (locale_dir == NULL || *locale_dir == '\0') {
            log_error("__module_loader_translations_load: path is required\n");
            it = json_next_it(&it);
            continue;
        }

        i18n_t* i18n = i18n_create(locale_dir, domain, "en");
        if (i18n == NULL) {
            log_error("__module_loader_translations_load: failed to create i18n for domain %s\n", domain);
            it = json_next_it(&it);
            continue;
        }

        if (map_insert(config->translations, domain, i18n) == -1) {
            log_error("__module_loader_translations_load: failed to insert i18n for domain %s\n", domain);
            it = json_next_it(&it);
            continue;
        }

        it = json_next_it(&it);
    }

    return 1;
}

static int __module_loader_taskmanager_load(appconfig_t* config, taskmanager_t* manager, const json_token_t* token_taskmanager) {
    const json_token_t* token_schedule = json_object_get(token_taskmanager, "schedule");

    if (token_schedule == NULL) {
        return 1;
    }

    if (!json_is_array(token_schedule)) {
        log_error("__module_loader_taskmanager_load: schedule must be array\n");
        return 0;
    }

    routeloader_lib_t* last_lib = routeloader_get_last(config->taskmanager_loader);

    for (int i = 0; i < json_array_size(token_schedule); i++) {
        const json_token_t* token_task = json_array_get(token_schedule, i);

        if (!json_is_object(token_task)) {
            log_error("__module_loader_taskmanager_load: task item must be object\n");
            return 0;
        }

        const json_token_t* token_name = json_object_get(token_task, "name");
        if (token_name == NULL || !json_is_string(token_name)) {
            log_error("__module_loader_taskmanager_load: task name is required and must be string\n");
            return 0;
        }
        const char* name = json_string(token_name);

        const json_token_t* token_type = json_object_get(token_task, "type");
        if (token_type == NULL || !json_is_string(token_type)) {
            log_error("__module_loader_taskmanager_load: task type is required and must be string\n");
            return 0;
        }
        const char* type = json_string(token_type);

        const json_token_t* token_file = json_object_get(token_task, "file");
        if (token_file == NULL || !json_is_string(token_file)) {
            log_error("__module_loader_taskmanager_load: task file is required and must be string\n");
            return 0;
        }
        const char* lib_file = json_string(token_file);

        const json_token_t* token_function = json_object_get(token_task, "function");
        if (token_function == NULL || !json_is_string(token_function)) {
            log_error("__module_loader_taskmanager_load: task function is required and must be string\n");
            return 0;
        }
        const char* function_name = json_string(token_function);

        if (!routeloader_has_lib(config->taskmanager_loader, lib_file)) {
            routeloader_lib_t* lib = routeloader_load_lib(lib_file);
            if (lib == NULL) {
                log_error("__module_loader_taskmanager_load: failed to load library %s\n", lib_file);
                return 0;
            }

            if (config->taskmanager_loader == NULL) {
                config->taskmanager_loader = lib;
            } else {
                last_lib->next = lib;
            }
            last_lib = lib;
        }

        void(*handler)(void*);
        *(void**)(&handler) = routeloader_get_handler(config->taskmanager_loader, lib_file, function_name);
        if (handler == NULL) {
            log_error("__module_loader_taskmanager_load: function %s not found in %s\n", function_name, lib_file);
            return 0;
        }

        if (strcmp(type, "interval") == 0) {
            const json_token_t* token_interval = json_object_get(token_task, "interval");
            if (token_interval == NULL || !json_is_number(token_interval)) {
                log_error("__module_loader_taskmanager_load: interval is required for interval type\n");
                return 0;
            }
            int ok = 0;
            int interval = json_int(token_interval, &ok);
            if (!ok || interval < 1) {
                log_error("__module_loader_taskmanager_load: interval must be >= 1\n");
                return 0;
            }

            if (!taskmanager_schedule(manager, name, interval, handler)) {
                log_error("__module_loader_taskmanager_load: failed to schedule task %s\n", name);
                return 0;
            }

            log_info("taskmanager: loaded scheduled task '%s' (interval: %d sec)\n", name, interval);
        }
        else if (strcmp(type, "daily") == 0) {
            const json_token_t* token_hour = json_object_get(token_task, "hour");
            if (token_hour == NULL || !json_is_number(token_hour)) {
                log_error("__module_loader_taskmanager_load: hour is required for daily type\n");
                return 0;
            }
            int ok = 0;
            int hour = json_int(token_hour, &ok);
            if (!ok || hour < 0 || hour > 23) {
                log_error("__module_loader_taskmanager_load: hour must be 0-23\n");
                return 0;
            }

            const json_token_t* token_minute = json_object_get(token_task, "minute");
            if (token_minute == NULL || !json_is_number(token_minute)) {
                log_error("__module_loader_taskmanager_load: minute is required for daily type\n");
                return 0;
            }
            ok = 0;
            int minute = json_int(token_minute, &ok);
            if (!ok || minute < 0 || minute > 59) {
                log_error("__module_loader_taskmanager_load: minute must be 0-59\n");
                return 0;
            }

            if (!taskmanager_schedule_daily(manager, name, hour, minute, handler)) {
                log_error("__module_loader_taskmanager_load: failed to schedule daily task %s\n", name);
                return 0;
            }

            log_info("taskmanager: loaded scheduled task '%s' (daily at %02d:%02d)\n", name, hour, minute);
        }
        else if (strcmp(type, "weekly") == 0) {
            const json_token_t* token_weekday = json_object_get(token_task, "weekday");
            if (token_weekday == NULL || !json_is_string(token_weekday)) {
                log_error("__module_loader_taskmanager_load: weekday is required for weekly type\n");
                return 0;
            }
            const char* weekday_str = json_string(token_weekday);

            weekday_e weekday;
            if (strcmp(weekday_str, "sunday") == 0)          weekday = SUNDAY;
            else if (strcmp(weekday_str, "monday") == 0)     weekday = MONDAY;
            else if (strcmp(weekday_str, "tuesday") == 0)    weekday = TUESDAY;
            else if (strcmp(weekday_str, "wednesday") == 0)  weekday = WEDNESDAY;
            else if (strcmp(weekday_str, "thursday") == 0)   weekday = THURSDAY;
            else if (strcmp(weekday_str, "friday") == 0)     weekday = FRIDAY;
            else if (strcmp(weekday_str, "saturday") == 0)   weekday = SATURDAY;
            else {
                log_error("__module_loader_taskmanager_load: invalid weekday '%s'\n", weekday_str);
                return 0;
            }

            const json_token_t* token_hour = json_object_get(token_task, "hour");
            if (token_hour == NULL || !json_is_number(token_hour)) {
                log_error("__module_loader_taskmanager_load: hour is required for weekly type\n");
                return 0;
            }
            int ok = 0;
            int hour = json_int(token_hour, &ok);
            if (!ok || hour < 0 || hour > 23) {
                log_error("__module_loader_taskmanager_load: hour must be 0-23\n");
                return 0;
            }

            const json_token_t* token_minute = json_object_get(token_task, "minute");
            if (token_minute == NULL || !json_is_number(token_minute)) {
                log_error("__module_loader_taskmanager_load: minute is required for weekly type\n");
                return 0;
            }
            ok = 0;
            int minute = json_int(token_minute, &ok);
            if (!ok || minute < 0 || minute > 59) {
                log_error("__module_loader_taskmanager_load: minute must be 0-59\n");
                return 0;
            }

            if (!taskmanager_schedule_weekly(manager, name, weekday, hour, minute, handler)) {
                log_error("__module_loader_taskmanager_load: failed to schedule weekly task %s\n", name);
                return 0;
            }

            log_info("taskmanager: loaded scheduled task '%s' (weekly: %s at %02d:%02d)\n", name, weekday_str, hour, minute);
        }
        else if (strcmp(type, "monthly") == 0) {
            const json_token_t* token_day = json_object_get(token_task, "day");
            if (token_day == NULL || !json_is_number(token_day)) {
                log_error("__module_loader_taskmanager_load: day is required for monthly type\n");
                return 0;
            }
            int ok = 0;
            int day = json_int(token_day, &ok);
            if (!ok || day < 1 || day > 31) {
                log_error("__module_loader_taskmanager_load: day must be 1-31\n");
                return 0;
            }

            const json_token_t* token_hour = json_object_get(token_task, "hour");
            if (token_hour == NULL || !json_is_number(token_hour)) {
                log_error("__module_loader_taskmanager_load: hour is required for monthly type\n");
                return 0;
            }
            ok = 0;
            int hour = json_int(token_hour, &ok);
            if (!ok || hour < 0 || hour > 23) {
                log_error("__module_loader_taskmanager_load: hour must be 0-23\n");
                return 0;
            }

            const json_token_t* token_minute = json_object_get(token_task, "minute");
            if (token_minute == NULL || !json_is_number(token_minute)) {
                log_error("__module_loader_taskmanager_load: minute is required for monthly type\n");
                return 0;
            }
            ok = 0;
            int minute = json_int(token_minute, &ok);
            if (!ok || minute < 0 || minute > 59) {
                log_error("__module_loader_taskmanager_load: minute must be 0-59\n");
                return 0;
            }

            if (!taskmanager_schedule_monthly(manager, name, day, hour, minute, handler)) {
                log_error("__module_loader_taskmanager_load: failed to schedule monthly task %s\n", name);
                return 0;
            }

            log_info("taskmanager: loaded scheduled task '%s' (monthly: day %d at %02d:%02d)\n", name, day, hour, minute);
        }
        else {
            log_error("__module_loader_taskmanager_load: unknown task type '%s'\n", type);
            return 0;
        }
    }

    return 1;
}

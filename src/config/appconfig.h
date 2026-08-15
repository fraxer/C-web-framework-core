#ifndef __APPCONFIG__
#define __APPCONFIG__

#include <stdbool.h>

#include "array.h"
#include "map.h"
#include "json.h"
#include "server.h"
#include "storage.h"
#include "database.h"
#include "viewstore.h"
#include "mimetype.h"
#include "session.h"
#include "routeloader.h"

typedef struct taskmanager taskmanager_t;

typedef struct env_gzip_str {
    char* mimetype;
    struct env_gzip_str* next;
} env_gzip_str_t;

typedef enum {
    APPCONFIG_RELOAD_SOFT = 0,
    APPCONFIG_RELOAD_HARD
} appconfig_reload_state_e;

typedef struct env_log {
    bool enabled;
    int level;
} env_log_t;

typedef struct i18n i18n_t;

typedef struct env_main {
    appconfig_reload_state_e reload;
    unsigned int workers;
    unsigned int threads;
    unsigned int client_max_body_size;
    char* tmp;
    env_gzip_str_t* gzip;
    env_log_t log;
} env_main_t;

typedef struct env_mail {
    char* dkim_private;
    char* dkim_selector;
    char* host;
} env_mail_t;

typedef struct env {
    env_main_t main;
    env_mail_t mail;
    json_doc_t* custom_store;
} env_t;

typedef struct appconfig {
    atomic_bool shutdown;
    atomic_int threads_count;
    env_t env;
    map_t* sessionconfigs;
    char* path;
    mimetype_t* mimetype;
    array_t* databases;
    storage_t* storages;
    viewstore_t* viewstore;
    server_chain_t* server_chain;
    routeloader_lib_t* taskmanager_loader;
    taskmanager_t* taskmanager;
    map_t* translations;  // map: domain -> i18n_t*
} appconfig_t;

int appconfig_init(int argc, char* argv[]);

/* Whether -f was given: keep the process in the foreground instead of
 * daemonising. Meaningful only to the executables, which is why it is a
 * question about the command line and not a field of the configuration. */
int appconfig_foreground(void);
appconfig_t* appconfig_create(const char* path);
appconfig_t* appconfig(void);
env_t* env(void);
void appconfig_set(appconfig_t* config);
void appconfig_clear(appconfig_t* config);
void appconfig_free(appconfig_t* config);
char* appconfig_path(void);
void appconfg_threads_increment(appconfig_t* config);
void appconfg_threads_decrement(appconfig_t* config);

/* How many worker/handler/task threads are still running, tracked in a
 * process-lifetime counter rather than in the config — the last thread out frees
 * the config, so config->threads_count cannot be safely polled from outside.
 * Used by the shutdown drain to tell when the workers have finished. */
int appconfig_threads_alive(void);

/* The process is terminating, as opposed to reloading.
 *
 * Both raise appconfig_t::shutdown, and until this existed the two were
 * indistinguishable -- which mattered in exactly one place. A *hard reload*
 * deliberately leaves the listening sockets alone: signal_USR1 shuts them down
 * itself and the replacement configuration takes them over. Terminate does
 * neither, so under `reload: hard` the listeners stayed open, the worker's
 * drain never reached zero connections, and every shutdown ran out its grace
 * window with the workers still going.
 *
 * A file-static rather than a field on appconfig_t: the struct is shared with
 * application handlers through libcwfr_framework.so, and a flag is not worth an
 * ABI question. Same pattern as the thread counter above. */
void appconfig_set_terminating(void);
int  appconfig_terminating(void);

const char* env_get_string(const char* key, const char* default_value);
/* 1 = present and valid, 0 = absent, -1 = present with the wrong type/range. */
int env_get_string_checked(const char* key, const char** value);
int env_get_llong_checked(const char* key, long long* value);
int env_get_bool_checked(const char* key, bool* value);
int env_config_get_string_checked(const env_t* source, const char* key, const char** value);
int env_config_get_llong_checked(const env_t* source, const char* key, long long* value);
int env_config_get_bool_checked(const env_t* source, const char* key, bool* value);
int env_get_int(const char* key, int default_value);
long long env_get_llong(const char* key, long long default_value);
int env_get_bool(const char* key, int default_value);
double env_get_double(const char* key, double default_value);
long double env_get_ldouble(const char* key, long double default_value);

#endif

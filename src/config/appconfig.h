#ifndef __APPCONFIG__
#define __APPCONFIG__

#include <stdbool.h>

#include "array.h"
#include "json.h"
#include "server.h"
#include "storage.h"
#include "database.h"
#include "viewstore.h"
#include "mimetype.h"
#include "session.h"
#include "routeloader.h"

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

typedef struct env_migrations {
    char* source_directory;
} env_migrations_t;

typedef struct {
    env_main_t main;
    env_mail_t mail;
    env_migrations_t migrations;
    json_doc_t* custom_store;
} env_t;

typedef struct appconfig {
    atomic_bool shutdown;
    atomic_int threads_count;
    env_t env;
    sessionconfig_t sessionconfig;
    char* path;
    mimetype_t* mimetype;
    array_t* databases;
    storage_t* storages;
    viewstore_t* viewstore;
    server_chain_t* server_chain;
    array_t* prepared_queries; // prepare_stmt_t
    routeloader_lib_t* taskmanager_loader;
} appconfig_t;

int appconfig_init(int argc, char* argv[]);
appconfig_t* appconfig_create(const char* path);
appconfig_t* appconfig(void);
env_t* env(void);
void appconfig_set(appconfig_t* config);
void appconfig_clear(appconfig_t* config);
void appconfig_free(appconfig_t* config);
char* appconfig_path(void);
void appconfg_threads_increment(appconfig_t* config);
void appconfg_threads_decrement(appconfig_t* config);

const char* env_get_string(const char* key);
int env_get_int(const char* key, int default_value);
long long env_get_llong(const char* key, long long default_value);
int env_get_bool(const char* key, int default_value);
double env_get_double(const char* key, double default_value);
long double env_get_ldouble(const char* key, long double default_value);

#endif
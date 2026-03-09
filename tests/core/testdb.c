#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <dlfcn.h>

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include "database.h"
#include "moduleloader.h"
#include "statement_registry.h"
#include "middleware_registry.h"

#ifdef PostgreSQL_FOUND
    #include "postgresql.h"
#endif
#ifdef MySQL_FOUND
    #include "mysql.h"
#endif

static char __temp_name[128] = {0};
static const char* __dbid = NULL;
static testdb_driver_e __driver = TESTDB_DRIVER_NONE;
static appconfig_t* __appconfig = NULL;
static json_doc_t* __document = NULL;
static int __teardown_registered = 0;

static int sort_asc(const struct dirent **a, const struct dirent **b) {
    return strcoll((*a)->d_name, (*b)->d_name);
}

static int run_migrations(const char* dbid, const char* migrations_dir) {
    struct dirent **namelist = NULL;
    const int count = scandir(migrations_dir, &namelist, NULL, sort_asc);

    if (count == -1) {
        fprintf(stderr, "testdb: cannot open migrations directory: %s\n", migrations_dir);
        return 0;
    }

    int result = 1;
    const int reg_file = 8;

    for (int i = 0; i < count; i++) {
        if (namelist[i]->d_type != reg_file) {
            free(namelist[i]);
            namelist[i] = NULL;
            continue;
        }

        size_t path_len = strlen(migrations_dir) + 1 + strlen(namelist[i]->d_name) + 1;
        char* filepath = malloc(path_len);
        if (filepath == NULL) {
            fprintf(stderr, "testdb: out of memory\n");
            result = 0;
            break;
        }

        snprintf(filepath, path_len, "%s/%s", migrations_dir, namelist[i]->d_name);

        void* dl = dlopen(filepath, RTLD_LAZY);
        if (dl == NULL) {
            fprintf(stderr, "testdb: cannot load migration %s: %s\n", filepath, dlerror());
            free(filepath);
            result = 0;
            break;
        }

        int(*fn_up)(const char*) = NULL;
        *(void**)(&fn_up) = dlsym(dl, "up");

        if (fn_up == NULL) {
            fprintf(stderr, "testdb: no up() in %s\n", filepath);
            dlclose(dl);
            free(filepath);
            result = 0;
            break;
        }

        if (!fn_up(dbid)) {
            fprintf(stderr, "testdb: migration failed: %s\n", namelist[i]->d_name);
            dlclose(dl);
            free(filepath);
            result = 0;
            break;
        }

        printf("testdb: migration ok: %s\n", namelist[i]->d_name);

        dlclose(dl);
        free(filepath);
        free(namelist[i]);
        namelist[i] = NULL;
    }

    for (int i = 0; i < count; i++) {
        if (namelist[i]) free(namelist[i]);
    }
    free(namelist);

    return result;
}

int testdb_setup(const char* dbid, const char* config_path, const char* migrations_dir) {
    /* Generate temp name */
    snprintf(__temp_name, sizeof(__temp_name), "test_%d_%ld", getpid(), (long)time(NULL));
    __dbid = dbid;

    /* Detect driver */
    if (strncmp(dbid, "postgresql", 10) == 0) {
#ifdef PostgreSQL_FOUND
        __driver = TESTDB_DRIVER_POSTGRESQL;
#else
        fprintf(stderr, "testdb: PostgreSQL support not compiled\n");
        return 0;
#endif
    } else if (strncmp(dbid, "mysql", 5) == 0) {
#ifdef MySQL_FOUND
        __driver = TESTDB_DRIVER_MYSQL;
#else
        fprintf(stderr, "testdb: MySQL support not compiled\n");
        return 0;
#endif
    } else {
        fprintf(stderr, "testdb: unknown database driver in dbid: %s\n", dbid);
        return 0;
    }

    /* Initialize framework (same pattern as migrate/main.c) */
    __appconfig = appconfig_create(config_path);
    if (__appconfig == NULL) {
        fprintf(stderr, "testdb: cannot create appconfig from %s\n", config_path);
        return 0;
    }
    appconfig_set(__appconfig);

    if (!prepare_statements_init()) {
        fprintf(stderr, "testdb: failed to initialize prepared statements\n");
        return 0;
    }
    if (!middlewares_init()) {
        fprintf(stderr, "testdb: failed to initialize middlewares\n");
        return 0;
    }
    if (!module_loader_load_json_config(config_path, &__document)) {
        fprintf(stderr, "testdb: cannot load json from %s\n", config_path);
        return 0;
    }
    if (!module_loader_config_load(__appconfig, __document)) {
        fprintf(stderr, "testdb: cannot parse config %s\n", config_path);
        return 0;
    }

    /* Create temporary space */
    dbresult_t* result = NULL;

#ifdef PostgreSQL_FOUND
    if (__driver == TESTDB_DRIVER_POSTGRESQL) {
        postgresqlhost_t* host = (postgresqlhost_t*)dbhost(dbid);
        if (host == NULL) {
            fprintf(stderr, "testdb: cannot find host for %s\n", dbid);
            return 0;
        }

        /* Update schema to temp name */
        if (host->schema) free(host->schema);
        host->schema = strdup(__temp_name);

        /* Create temporary schema */
        result = dbqueryf(dbid, "CREATE SCHEMA %s", __temp_name);
        if (!dbresult_ok(result)) {
            fprintf(stderr, "testdb: failed to create schema %s\n", __temp_name);
            dbresult_free(result);
            return 0;
        }
        dbresult_free(result);

        /* Set search_path for unqualified table names */
        result = dbqueryf(dbid, "SET search_path TO %s", __temp_name);
        if (!dbresult_ok(result)) {
            fprintf(stderr, "testdb: failed to set search_path\n");
            dbresult_free(result);
            return 0;
        }
        dbresult_free(result);

        printf("testdb: created PostgreSQL schema: %s\n", __temp_name);
    }
#endif

#ifdef MySQL_FOUND
    if (__driver == TESTDB_DRIVER_MYSQL) {
        myhost_t* host = (myhost_t*)dbhost(dbid);
        if (host == NULL) {
            fprintf(stderr, "testdb: cannot find host for %s\n", dbid);
            return 0;
        }

        /* Create temporary database */
        result = dbqueryf(dbid, "CREATE DATABASE %s", __temp_name);
        if (!dbresult_ok(result)) {
            fprintf(stderr, "testdb: failed to create database %s\n", __temp_name);
            dbresult_free(result);
            return 0;
        }
        dbresult_free(result);

        /* Switch to temporary database */
        result = dbqueryf(dbid, "USE %s", __temp_name);
        if (!dbresult_ok(result)) {
            fprintf(stderr, "testdb: failed to switch to database %s\n", __temp_name);
            dbresult_free(result);
            return 0;
        }
        dbresult_free(result);

        /* Update host dbname for potential reconnects */
        if (host->dbname) free(host->dbname);
        host->dbname = strdup(__temp_name);

        printf("testdb: created MySQL database: %s\n", __temp_name);
    }
#endif

    /* Register cleanup on exit */
    if (!__teardown_registered) {
        atexit(testdb_teardown);
        __teardown_registered = 1;
    }

    /* Run migrations */
    if (!run_migrations(dbid, migrations_dir)) {
        fprintf(stderr, "testdb: migrations failed, cleaning up\n");
        testdb_teardown();
        return 0;
    }

    printf("testdb: setup complete\n");
    return 1;
}

void testdb_teardown(void) {
    if (__driver == TESTDB_DRIVER_NONE)
        return;

    if (__temp_name[0] == '\0')
        return;

    dbresult_t* result = NULL;

#ifdef PostgreSQL_FOUND
    if (__driver == TESTDB_DRIVER_POSTGRESQL) {
        result = dbqueryf(__dbid, "DROP SCHEMA IF EXISTS %s CASCADE", __temp_name);
        if (result) {
            if (dbresult_ok(result))
                printf("testdb: dropped schema %s\n", __temp_name);
            dbresult_free(result);
        }
    }
#endif

#ifdef MySQL_FOUND
    if (__driver == TESTDB_DRIVER_MYSQL) {
        result = dbqueryf(__dbid, "DROP DATABASE IF EXISTS %s", __temp_name);
        if (result) {
            if (dbresult_ok(result))
                printf("testdb: dropped database %s\n", __temp_name);
            dbresult_free(result);
        }
    }
#endif

    __temp_name[0] = '\0';
    __driver = TESTDB_DRIVER_NONE;

    if (__document) {
        json_free(__document);
        __document = NULL;
    }

    if (__appconfig) {
        appconfig_free(__appconfig);
        __appconfig = NULL;
    }
}

void testdb_begin_test(void) {
    dbresult_t* r;

    r = dbqueryf(__dbid, "BEGIN");
    if (r) dbresult_free(r);

    r = dbqueryf(__dbid, "SAVEPOINT test_sp");
    if (r) dbresult_free(r);
}

void testdb_rollback_test(void) {
    dbresult_t* r;

    r = dbqueryf(__dbid, "ROLLBACK TO SAVEPOINT test_sp");
    if (r) dbresult_free(r);

    r = dbqueryf(__dbid, "COMMIT");
    if (r) dbresult_free(r);
}

const char* testdb_name(void) {
    return __temp_name;
}

const char* testdb_dbid(void) {
    return __dbid;
}

testdb_driver_e testdb_driver(void) {
    return __driver;
}

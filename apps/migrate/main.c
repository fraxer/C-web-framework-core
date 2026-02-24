#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <time.h>
#include <stdlib.h>

#include "json.h"
#include "dbquery.h"
#include "dbresult.h"
#include "model.h"
#include "database.h"
#include "moduleloader.h"
#include "statement_registry.h"
#include "middleware_registry.h"
#ifdef MySQL_FOUND
    #include "mysql.h"
#endif
#ifdef PostgreSQL_FOUND
    #include "postgresql.h"
#endif
#ifdef Redis_FOUND
    #include "redis.h"
#endif


typedef enum mgactions {
    NONE = 0,
    CREATE,
    UP
} mgactions_e;

// migrate create <migration_name> <config_path> <target_dir>
// migrate create create_users_table config.json ./migrations/s1

// migrate up <config_path> <db_host> <server_id>
// migrate up config.json postgresql.p1 s1
// migrate up <number|all> <config_path> <db_host> <server_id>
// migrate up 2 config.json postgresql.p1 s1
// migrate up all config.json postgresql.p1 s1

typedef struct mgconfig {
    int ok;
    char* database_driver;
    char* server;
    mgactions_e action;
    char* migration_name;
    char* target_directory;
    int count_migrations;
    int count_applied_migrations;
    appconfig_t* appconfig;
} mgconfig_t;

void mg_config_free(mgconfig_t* config) {
    config->ok = 0;
    config->action = NONE;
    config->count_migrations = 0;
    config->count_applied_migrations = 0;

    appconfig_free(config->appconfig);

    if (config->server) free(config->server);
    if (config->database_driver) free(config->database_driver);
    if (config->migration_name) free(config->migration_name);
    if (config->target_directory) free(config->target_directory);
}

int mg_parse_action_create(mgconfig_t* config, int argc, char* argv[]) {
    if (argc != 5) {
        printf("Error: command incorrect\n");
        printf("Example: migrate create <migration name> <config path> <target directory>\n");
        return -1;
    }

    config->ok = 1;
    config->migration_name = strdup(argv[2]);
    config->appconfig = appconfig_create(argv[3]);
    config->target_directory = strdup(argv[4]);

    return 0;
}

int mg_parse_action_up(mgconfig_t* config, int argc, char* argv[]) {
    if (argc == 5) {
        // migrate up <config_path> <db_host> <server_id>
        config->count_migrations = 1;
        config->ok = 1;
        config->appconfig = appconfig_create(argv[2]);
        config->database_driver = strdup(argv[3]);
        config->server = strdup(argv[4]);
        return 0;
    }

    if (argc == 6) {
        // migrate up <number|all> <config_path> <db_host> <server_id>
        if (strspn(argv[2], "0123456789") == strlen(argv[2])) {
            config->count_migrations = atoi(argv[2]);
        }
        else if (strcmp(argv[2], "all") == 0) {
            config->count_migrations = 0;
        }
        else {
            printf("Error: command incorrect\n");
            printf("Example: migrate up [number|all] <config path> <db host> <server id>\n");
            return -1;
        }

        config->ok = 1;
        config->appconfig = appconfig_create(argv[3]);
        config->database_driver = strdup(argv[4]);
        config->server = strdup(argv[5]);
        return 0;
    }

    printf("Error: command incorrect\n");
    printf("Example: migrate up [number|all] <config path> <db host> <server id>\n");
    return -1;
}

mgconfig_t mg_args_parse(int argc, char* argv[]) {
    mgconfig_t config = {
        .ok = 0,
        .database_driver = NULL,
        .server = NULL,
        .action = NONE,
        .migration_name = NULL,
        .target_directory = NULL,
        .count_migrations = 1,
        .count_applied_migrations = 0,
        .appconfig = NULL,
    };

    if (argc < 2) {
        printf("Error: command incorrect\n");
        printf("Example: migrate <action> ...\n");
        return config;
    }

    if (strcmp(argv[1], "create") == 0) {
        config.action = CREATE;
        if (mg_parse_action_create(&config, argc, argv) == -1) return config;
    }
    else if (strcmp(argv[1], "up") == 0) {
        config.action = UP;
        if (mg_parse_action_up(&config, argc, argv) == -1) return config;
    }
    else {
        printf("Error: command incorrect\n");
        return config;
    }

    return config;
}

int mg_sort_asc(const struct dirent **a, const struct dirent **b) {
    return strcoll((*a)->d_name, (*b)->d_name);
}

int mg_sort_desc(const struct dirent **a, const struct dirent **b) {
    return strcoll((*b)->d_name, (*a)->d_name);
}

int mg_migration_table_exist(const char* dbid) {
    dbresult_t* result = dbtable_exist(dbid, "migration");

    if (!dbresult_ok(result)) {
        printf("%s\n", "query error");
        dbresult_free(result);
        return 0;
    }

    int rows = dbresult_query_rows(result);

    dbresult_free(result);

    return rows > 0;
}

int mg_migration_table_create(const char* dbid) {
    dbresult_t* result = dbtable_migration_create(dbid, "migration");

    if (!dbresult_ok(result)) {
        printf("%s\n", "query error");
        dbresult_free(result);
        return 0;
    }
    dbresult_free(result);

    return 1;
}

int mg_migration_exist(const char* dbid, const char* filename) {
    array_t* params = array_create();
    if (params == NULL)
        return 0;

    mparams_fill_array(params,
        mparam_text(version, filename)
    )
    array_t* column_arr = array_create_strings("1");

    dbresult_t* result = dbselect(dbid, "migration", column_arr, params);
    array_free(column_arr);
    array_free(params);

    if (!dbresult_ok(result)) {
        printf("%s\n", "query error");
        dbresult_free(result);
        return 0;
    }

    int rows = dbresult_query_rows(result);

    dbresult_free(result);

    return rows > 0;
}

int mg_migration_commit(const char* dbid, const char* filename) {
    array_t* params = array_create();
    if (params == NULL)
        return 0;

    mparams_fill_array(params,
        mparam_text(version, filename),
        mparam_bigint(apply_time, time(0))
    )

    dbresult_t* result = dbinsert(dbid, "migration", params);
    array_free(params);

    if (!dbresult_ok(result)) {
        printf("%s\n", "query error");
        dbresult_free(result);
        return 0;
    }

    dbresult_free(result);

    return 1;
}

int mg_migrate_run(mgconfig_t* config, const char* filename, const char* path) {
    int result = -1;
    void* dlpointer = dlopen(path, RTLD_LAZY);

    if (dlpointer == NULL) {
        printf("Error: can't open file %s\n", path);
        return result;
    }

    int make_increment = 0;
    const char* dbid = config->database_driver;
    int(*function_up)(const char*) = NULL;

    *(void**)(&function_up) = dlsym(dlpointer, "up");
    if (function_up == NULL) {
        printf("Error: not found function up in %s\n", path);
        goto failed;
    }

    
    if (dbid == NULL) {
        printf("Error: not found database in %s\n", path);
        goto failed;
    }
    
    if (!mg_migration_table_exist(dbid))
        if (!mg_migration_table_create(dbid))
            goto failed;

    if (config->action == UP) {
        if (!mg_migration_exist(dbid, filename) && function_up(dbid)) {
            mg_migration_commit(dbid, filename);
            printf("Success up %s in %s\n", path, config->database_driver);
            make_increment = 1;
        }
    }

    result = 0;

    if (make_increment) config->count_applied_migrations++;

    failed:

    dlclose(dlpointer);

    return result;
}

int mg_migrations_process(mgconfig_t* config) {
    int result = 0;
    const char* migrations_dir = "./migrations/";
    size_t path_length = strlen(migrations_dir) + strlen(config->server);
    char* path = malloc(path_length + 1);
    if (path == NULL) {
        printf("Error: out of memory\n");
        return result;
    }

    strcpy(path, migrations_dir);
    strcat(path, config->server);

    struct dirent **namelist;
    const int count_files = scandir(path, &namelist, NULL, config->action == UP ? mg_sort_asc : mg_sort_desc);
    if (count_files == -1) {
        printf("Error: no such directory\n");
        goto failed;
    }

    const int reg_file = 8;
    for (int i = 0; i < count_files; i++) {
        if (namelist[i]->d_type == reg_file) {
            if (config->count_migrations > 0 &&
                config->count_applied_migrations == config->count_migrations) {
                break;
            }
            size_t length = strlen(path) + 1 + strlen(namelist[i]->d_name) + 1; // "/" + '\0'
            char* filepath = malloc(length);

            if (filepath == NULL) {
                printf("Error: out of memory\n");
                goto failed;
            }

            strcpy(filepath, path);
            strcat(filepath, "/");
            strcat(filepath, namelist[i]->d_name);

            if (mg_migrate_run(config, namelist[i]->d_name, filepath) == -1) {
                printf("Error: can't attach file %s\n", filepath);
                free(filepath);
                goto failed;
            }
            free(filepath);
        }
    }

    result = 1;

    failed:

    for (int i = 0; i < count_files; i++) {
        free(namelist[i]);
    }
    free(namelist);
    free(path);

    return result;
}

int mg_make_directory(const char* target_directory) {
    char tmp[PATH_MAX] = {0};

    strcpy(tmp, target_directory);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }
    }

    mkdir(tmp, S_IRWXU);

    struct stat st = {0};

    if (stat(&tmp[0], &st) == 0 && S_ISDIR(st.st_mode)) return 1;

    printf("Error: can't create directory %s", &tmp[0]);

    return 0;
}

int mg_create_template(const char* target_directory, mgconfig_t* config) {
    char tmp[512] = {0};
    strcpy(&tmp[0], target_directory);

    size_t len = strlen(tmp);

    if (tmp[len - 1] != '/')
        strcat(&tmp[0], "/");

    time_t t = time(0);
    struct tm tm = *localtime(&t);
    sprintf(&tmp[strlen(tmp)], "%d-%02d-%02d_%02d-%02d-%02d_", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    strcat(&tmp[0], config->migration_name);
    strcat(&tmp[0], ".c");

    const char* data =
        "#include <stdlib.h>\n\n"
        "#include \"dbquery.h\"\n"
        "#include \"dbresult.h\"\n\n"

        "int up(const char* dbid) {\n"
        "    dbresult_t* result = dbqueryf(dbid, \"\");\n\n"

        "    int res = dbresult_ok(result);\n\n"

        "    dbresult_free(result);\n\n"

        "    return res;\n"
        "}\n"
    ;

    int fd = open(&tmp[0], O_RDWR | O_CREAT, S_IRWXU);
    if (fd < 0) {
        printf("Error: can't create migration %s", &tmp[0]);
        return 0;
    }

    int r = write(fd, data, strlen(data));
    if (r <= 0)
        printf("Error: can't write tot file %s", &tmp[0]);

    close(fd);

    return 1;
}

int mg_migration_create(mgconfig_t* config) {
    if (mg_make_directory(config->target_directory) == -1) return 0;
    if (mg_create_template(config->target_directory, config) == -1) return 0;

    return 1;
}

int main(int argc, char* argv[]) {
    json_doc_t* document = NULL;
    mgconfig_t config = mg_args_parse(argc, argv);
    if (!config.ok) goto failed;

    appconfig_set(config.appconfig);

    if (!prepare_statements_init()) {
        printf("module_loader_init: failed to initialize prepared statements\n");
        goto failed;
    }
    if (!middlewares_init()) {
        printf("Error: failed to initialize middlewares\n");
        goto failed;
    }
    if (!module_loader_load_json_config(config.appconfig->path, &document)) {
        printf("Error: can't load config %s\n", config.appconfig->path);
        goto failed;
    }
    if (!module_loader_config_load(config.appconfig, document)) {
        printf("Error: can't load config %s\n", config.appconfig->path);
        goto failed;
    }

    if (config.action == CREATE) {
        if (mg_migration_create(&config) == -1) goto failed;
    }
    else if (mg_migrations_process(&config) == -1) goto failed;

    failed:

    mg_config_free(&config);
    json_free(document);

    return EXIT_SUCCESS;
}
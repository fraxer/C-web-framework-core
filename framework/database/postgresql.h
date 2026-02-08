#ifndef __POSTGRESQL__
#define __POSTGRESQL__

#include <postgresql/libpq-fe.h>
#include <postgresql/pg_config.h>

#include "json.h"
#include "database.h"

typedef struct postgresqlhost {
    dbhost_t base;
    char* dbname;
    char* user;
    char* password;
    char* schema;
    int connection_timeout;
} postgresqlhost_t;

typedef struct postgresqlconnection {
    dbconnection_t base;
    PGconn* connection;
} postgresqlconnection_t;

db_t* postgresql_load(const char* database_id, const json_token_t* token_array);

#endif
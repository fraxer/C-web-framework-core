#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "log.h"
#include "array.h"
#include "str.h"
#include "map.h"
#include "model.h"
#include "dbresult.h"
#include "dbquery.h"
#include "postgresql.h"

typedef struct {
    array_t* param_order;
    int* param_index;
} pg_sql_processor_data_t;

typedef struct {
    void* connection;
    array_t* param_order;
    str_t* stmt_name;
} pg_prepared_stmt_t;

static postgresqlhost_t* __host_create(void);
static void __host_free(void*);
static void* __connection_create(void* host);
static void __connection_free(void* connection);
static dbresult_t* __query(void* connection, const char* sql);
static dbresult_t* __process_result(void* connection, dbresult_t* result);
static PGconn* __connect(void* host);
static int __is_active(void* connection);
static int __reconnect(void* host, void* connection);
static dbresult_t* __begin(void* connection, transaction_level_e level);
static char* __compile_table_exist(dbconnection_t* connection, const char* table);
static char* __compile_table_migration_create(dbconnection_t* connection, const char* table);
static str_t* __escape_identifier_part(PGconn* pg_conn, const char* start, size_t len);
static str_t* __escape_identifier(void* connection, const char* str);
static str_t* __escape_string(void* connection, const char* str);
static str_t* __escape_internal(void* connection, const char* str, char*(fn)(PGconn* conn, const char* str, size_t len));
static int __build_query_processor(void* connection, char parameter_type, const char* param_name, mfield_t* field, str_t* result_sql, void* user_data);
static str_t* __build_query(void* connection, str_t* sql, array_t* params, array_t* param_order);
static void __prepared_stmt_free(void* data);
static int __prepare(void* connection, str_t* stmt_name, str_t* sql, array_t* params);
static dbresult_t* __execute_prepared(void* connection, const char* stmt_name, array_t* params);
static char* __compile_insert(void* connection, const char* table, array_t* params);
static char* __compile_select(void* connection, const char* table, array_t* columns, array_t* where);
static char* __compile_update(void* connection, const char* table, array_t* set, array_t* where);
static char* __compile_delete(void* connection, const char* table, array_t* where);
static int __is_raw_sql(const char* str);

postgresqlhost_t* __host_create(void) {
    postgresqlhost_t* host = malloc(sizeof * host);
    if (host == NULL) return NULL;

    host->base.free = __host_free;
    host->base.port = 0;
    host->base.ip = NULL;
    host->base.id = NULL;
    host->base.connection_create = __connection_create;
    host->base.connections = array_create();
    host->base.connections_locked = 0;
    host->base.grammar.compile_table_exist = __compile_table_exist;
    host->base.grammar.compile_table_migration_create = __compile_table_migration_create;
    host->base.grammar.compile_insert = __compile_insert;
    host->base.grammar.compile_select = __compile_select;
    host->base.grammar.compile_update = __compile_update;
    host->base.grammar.compile_delete = __compile_delete;
    host->dbname = NULL;
    host->user = NULL;
    host->password = NULL;
    host->schema = NULL;
    host->connection_timeout = 0;

    return host;
}

void __host_free(void* arg) {
    if (arg == NULL) return;

    postgresqlhost_t* host = arg;

    if (host->base.id) free(host->base.id);
    if (host->base.ip) free(host->base.ip);
    if (host->dbname) free(host->dbname);
    if (host->user) free(host->user);
    if (host->password) free(host->password);
    if (host->schema) free(host->schema);

    array_free(host->base.connections);
    free(host);
}

void* __connection_create(void* host) {
    postgresqlconnection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection->base.thread_id = gettid();
    connection->base.prepare_statements = map_create_ex(map_compare_string, map_copy_string, free, NULL, __prepared_stmt_free);
    connection->base.free = __connection_free;
    connection->base.query = __query;
    connection->base.escape_identifier = __escape_identifier;
    connection->base.escape_string = __escape_string;
    connection->base.is_active = __is_active;
    connection->base.reconnect = __reconnect;
    connection->base.prepare = __prepare;
    connection->base.execute_prepared = __execute_prepared;
    connection->base.begin = __begin;
    connection->base.host = host;
    connection->connection = __connect(host);

    if (connection->connection == NULL) {
        connection->base.free(connection);
        connection = NULL;
    }

    return connection;
}

char* __compile_table_exist(dbconnection_t* connection, const char* table) {
    str_t* quoted_table = connection->escape_string(connection, table);
    if (quoted_table == NULL)
        return NULL;

    char tmp[512] = {0};

    ssize_t written = snprintf(
        tmp,
        sizeof(tmp),
        "SELECT "
            "1 "
        "FROM "
            "\"information_schema\".\"tables\" "
        "WHERE "
            "table_name = %s AND "
            "table_type = 'BASE TABLE'",
        str_get(quoted_table)
    );

    str_free(quoted_table);

    if (written < 0 || written >= (ssize_t)sizeof(tmp)) {
        log_error("__compile_table_exist: buffer overflow prevented\n");
        return NULL;
    }

    return strdup(tmp);
}

char* __compile_table_migration_create(dbconnection_t* connection, const char* table) {
    str_t* quoted_table = connection->escape_identifier(connection, table);
    if (quoted_table == NULL)
        return NULL;

    char tmp[512] = {0};

    postgresqlhost_t* host = connection->host;

    ssize_t written = snprintf(
        tmp,
        sizeof(tmp),
        "CREATE TABLE %s.%s "
        "("
            "version     varchar(180)  NOT NULL PRIMARY KEY,"
            "apply_time  integer       NOT NULL DEFAULT 0"
        ")",
        host->schema,
        str_get(quoted_table)
    );

    str_free(quoted_table);

    if (written < 0 || written >= (ssize_t)sizeof(tmp)) {
        log_error("__compile_table_migration_create: buffer overflow prevented\n");
        return NULL;
    }

    return strdup(tmp);
}

void __connection_free(void* connection) {
    if (connection == NULL) return;

    postgresqlconnection_t* conn = connection;

    if (conn->base.prepare_statements != NULL)
        map_free(conn->base.prepare_statements);

    PQfinish(conn->connection);
    free(conn);
}

dbresult_t* __query(void* connection, const char* sql) {
    postgresqlconnection_t* pgconnection = connection;

    dbresult_t* result = dbresult_create();
    if (result == NULL) return NULL;

    if (!PQsendQuery(pgconnection->connection, sql)) {
        log_error("PQsendQuery error: %s", PQerrorMessage(pgconnection->connection));
        return result;
    }

    return __process_result(pgconnection, result);
}

dbresult_t* __process_result(void* connection, dbresult_t* result) {
    postgresqlconnection_t* pgconnection = connection;

    result->ok = 1;

    PGresult* res = NULL;
    dbresultquery_t* query_last = NULL;

    while ((res = PQgetResult(pgconnection->connection))) {
        ExecStatusType status = PQresultStatus(res);

        switch (status) {
        case PGRES_COMMAND_OK:
        case PGRES_TUPLES_OK:
        case PGRES_SINGLE_TUPLE: {
            int cols = PQnfields(res);
            int rows = PQntuples(res);

            dbresultquery_t* query = dbresult_query_create(rows, cols);
            if (query == NULL) {
                result->ok = 0;
                log_error("Postgresql error: Out of memory\n");
                goto clear;
            }

            if (query_last)
                query_last->next = query;

            query_last = query;

            if (result->query == NULL) {
                result->query = query;
                result->current = query;
            }

            for (int col = 0; col < cols; col++)
                dbresult_query_field_insert(query, PQfname(res, col), col);

            for (int row = 0; row < rows; row++) {
                for (int col = 0; col < cols; col++) {
                    size_t length = PQgetlength(res, row, col);
                    const char* value = PQgetvalue(res, row, col);

                    dbresult_query_value_insert(query, value, length, row, col);
                }
            }

            break;
        }
        case PGRES_FATAL_ERROR:
        case PGRES_NONFATAL_ERROR:
        case PGRES_EMPTY_QUERY:
        case PGRES_BAD_RESPONSE:
        case PGRES_PIPELINE_ABORTED: {
            log_error("Postgresql error: %s", PQresultErrorMessage(res));
            result->ok = 0;
            break;
        }
        default:
            break;
        }

        clear:

        PQclear(res);
    }

    return result;
}

size_t postgresql_connection_string(char* buffer, size_t size, postgresqlhost_t* host) {
    return snprintf(buffer, size,
        "host=%s "
        "port=%d "
        "dbname=%s "
        "user=%s "
        "password=%s "
        "connect_timeout=%d ",
        host->base.ip,
        host->base.port,
        host->dbname,
        host->user,
        host->password,
        host->connection_timeout
    );
}

PGconn* __connect(void* arg) {
    postgresqlhost_t* host = arg;

    size_t string_length = postgresql_connection_string(NULL, 0, host);
    char* string = malloc(string_length + 1);
    if (string == NULL) return NULL;

    postgresql_connection_string(string, string_length, host);

    PGconn* connection = PQconnectdb(string);

    free(string);

    return connection;
}

int __is_active(void* connection) {
    postgresqlconnection_t* conn = connection;
    if (conn == NULL) return 0;

    return PQstatus(conn->connection) == CONNECTION_OK;
}

int __reconnect(void* host, void* connection) {
    postgresqlconnection_t* conn = connection;

    if (!__is_active(conn)) {
        PQfinish(conn->connection);

        conn->connection = __connect(host);

        if (!__is_active(conn)) {
            PQfinish(conn->connection);
            conn->connection = NULL;
            return 0;
        }
    }

    return 1;
}

const char* __postgresql_isolation_level_to_string(transaction_level_e level) {
    switch (level) {
        case READ_UNCOMMITTED:
            // PostgreSQL treats READ_UNCOMMITTED as READ_COMMITTED
            return "READ COMMITTED";
        case READ_COMMITTED:
            return "READ COMMITTED";
        case REPEATABLE_READ:
            return "REPEATABLE READ";
        case SERIALIZABLE:
            return "SERIALIZABLE";
        default:
            return "READ COMMITTED";
    }
}

dbresult_t* __begin(void* connection, transaction_level_e level) {
    postgresqlconnection_t* pgconnection = connection;
    if (pgconnection == NULL) return NULL;

    const char* level_str = __postgresql_isolation_level_to_string(level);

    str_t query;
    str_init(&query, 64);
    if (!str_appendf(&query, "BEGIN ISOLATION LEVEL %s", level_str)) {
        str_clear(&query);
        return NULL;
    }

    dbresult_t* result = __query(connection, str_get(&query));

    str_clear(&query);

    return result;
}

str_t* __escape_identifier_part(PGconn* pg_conn, const char* start, size_t len) {
    if (len == 0)
        return NULL;

    int is_quoted = (start[0] == '"' && start[len - 1] == '"' && len >= 2);

    if (is_quoted) {
        // Extract content between quotes and unescape "" -> "
        size_t content_len = len - 2;
        if (content_len == 0)
            return NULL;

        char* unquoted = malloc(content_len + 1);
        if (unquoted == NULL)
            return NULL;

        size_t j = 0;
        for (size_t i = 0; i < content_len; i++) {
            char c = start[1 + i];
            unquoted[j++] = c;
            // Skip second quote in "" sequence
            if (c == '"' && i + 1 < content_len && start[1 + i + 1] == '"')
                i++;
        }
        unquoted[j] = '\0';

        char* escaped = PQescapeIdentifier(pg_conn, unquoted, j);
        free(unquoted);

        if (escaped == NULL)
            return NULL;

        str_t* result = str_create(escaped);
        PQfreemem(escaped);
        return result;
    } else {
        char* escaped = PQescapeIdentifier(pg_conn, start, len);
        if (escaped == NULL)
            return NULL;

        str_t* result = str_create(escaped);
        PQfreemem(escaped);
        return result;
    }
}

str_t* __escape_identifier(void* connection, const char* str) {
    if (str == NULL || str[0] == '\0')
        return NULL;

    postgresqlconnection_t* conn = connection;
    str_t* result = str_create_empty(256);
    if (result == NULL)
        return NULL;

    const char* p = str;
    const char* part_start = str;
    int in_quotes = 0;
    int first_part = 1;

    while (1) {
        char c = *p;

        if (c == '"') {
            // Handle escaped quotes "" inside quoted identifier
            if (in_quotes && *(p + 1) == '"') {
                p += 2;
                continue;
            }
            in_quotes = !in_quotes;
            p++;
            continue;
        }

        if ((c == '.' && !in_quotes) || c == '\0') {
            // Check for unclosed quote at end of string
            if (c == '\0' && in_quotes) {
                str_free(result);
                return NULL;
            }

            size_t part_len = p - part_start;

            if (part_len == 0) {
                str_free(result);
                return NULL;
            }

            if (!first_part) {
                str_append(result, ".", 1);
            }

            str_t* escaped_part = __escape_identifier_part(conn->connection, part_start, part_len);
            if (escaped_part == NULL) {
                str_free(result);
                return NULL;
            }

            str_append(result, str_get(escaped_part), str_size(escaped_part));
            str_free(escaped_part);

            first_part = 0;

            if (c == '\0')
                break;

            part_start = p + 1;
        }

        p++;
    }

    return result;
}

str_t* __escape_string(void* connection, const char* str) {
    return __escape_internal(connection, str, PQescapeLiteral);
}

str_t* __escape_internal(void* connection, const char* str, char*(fn)(PGconn* conn, const char* str, size_t len)) {
    postgresqlconnection_t* conn = connection;
    const size_t str_len = strlen(str);

    char* quoted = fn(conn->connection, str, str_len);
    if (quoted == NULL) return NULL;

    str_t* string = str_create_empty(256);
    if (string == NULL) {
        free(quoted);
        return NULL;
    }

    str_append(string, quoted, strlen(quoted));

    free(quoted);

    return string;
}

int __is_raw_sql(const char* str) {
    if (str == NULL || str[0] == '\0') return 0;

    // Wildcard
    if (strcmp(str, "*") == 0) return 1;

    // NULL
    if (strcasecmp(str, "NULL") == 0) return 1;

    // Boolean
    if (strcasecmp(str, "true") == 0 || strcasecmp(str, "false") == 0) return 1;

    // Числа: 123, -45, 3.14, -0.5
    const char* p = str;
    if (*p == '-' || *p == '+') p++;
    if (*p != '\0') {
        int has_digit = 0;
        int has_dot = 0;
        while (*p) {
            if (isdigit((unsigned char)*p)) {
                has_digit = 1;
            } else if (*p == '.' && !has_dot) {
                has_dot = 1;
            } else {
                break;
            }
            p++;
        }
        if (*p == '\0' && has_digit) return 1;
    }

    // Функции: name(...) — ищем pattern "identifier("
    p = str;
    if (isalpha((unsigned char)*p) || *p == '_') {
        while (*p && (isalnum((unsigned char)*p) || *p == '_')) p++;
        if (*p == '(') return 1;
    }

    // Выражения с операторами: +, -, *, /, ||, ::
    for (p = str; *p; p++) {
        if (*p == '+' || *p == '/' || *p == '|' || *p == ':') return 1;
        // * только если не в начале (иначе это wildcard, уже проверили)
        if (*p == '*' && p != str) return 1;
        // - только если не в начале (иначе это отрицательное число)
        if (*p == '-' && p != str) return 1;
    }

    // CASE выражения
    if (strncasecmp(str, "CASE ", 5) == 0) return 1;

    // Подзапросы
    if (str[0] == '(') return 1;

    // Строковые литералы в кавычках
    if (str[0] == '\'') return 1;

    return 0;
}

int __build_query_processor(void* connection, char parameter_type, const char* param_name, mfield_t* field, str_t* result_sql, void* user_data) {
    pg_sql_processor_data_t* data = user_data;
    array_t* param_order = data->param_order;
    int* param_index = data->param_index;

    if (parameter_type == '@') {
        str_t* field_value = model_field_to_string(field);
        if (field_value == NULL) return 0;

        if (!process_value(connection, parameter_type, result_sql, field_value)) {
            log_error("__build_query_processor: process_value failed\n");
            return 0;
        }
    }
    else if (parameter_type == ':') {
        // Replace :param with $N
        str_appendf(result_sql, "$%d", *param_index);
        array_push_back_str(param_order, param_name);
        (*param_index)++;
    }
    else {
        log_error("__build_query_processor: unknown parameter type: %c\n", parameter_type);
        return 0;
    }

    return 1;
}

str_t* __build_query(void* connection, str_t* sql, array_t* params, array_t* param_order) {
    const char* query = str_get(sql);
    const size_t query_size = str_size(sql);

    // Prepare data for callback
    int param_index = 1;  // Counter for $1, $2, ...
    pg_sql_processor_data_t processor_data = {
        .param_order = param_order,
        .param_index = &param_index
    };

    return parse_sql_parameters(connection, query, query_size, params, __build_query_processor, &processor_data);
}

void __prepared_stmt_free(void* data) {
    if (data == NULL) return;

    pg_prepared_stmt_t* stmt_data = data;

    if (stmt_data->connection != NULL && stmt_data->stmt_name != NULL) {
        postgresqlconnection_t* pgconnection = stmt_data->connection;

        #ifdef PG_MAJORVERSION_NUM
            #if PG_MAJORVERSION_NUM > 16
                PQsendClosePrepared(pgconnection->connection, str_get(stmt_data->stmt_name));
            #else
                str_t str;
                str_init(&str, 64);
                str_appendf(&str, "DEALLOCATE %s", str_get(stmt_data->stmt_name));

                PQclear(PQexec(pgconnection->connection, str_get(&str)));
                str_clear(&str);
            #endif
        #endif
    }

    if (stmt_data->param_order != NULL)
        array_free(stmt_data->param_order);

    if (stmt_data->stmt_name != NULL)
        str_free(stmt_data->stmt_name);

    free(stmt_data);
}

int __prepare(void* connection, str_t* stmt_name, str_t* sql, array_t* params) {
    postgresqlconnection_t* pgconnection = connection;

    // Массив с упорядоченными параметрами
    array_t* param_order = array_create();
    if (param_order == NULL)
        return 0;

    // Обрабатываем SQL-строку
    str_t* processed_sql = __build_query(connection, sql, params, param_order);
    if (processed_sql == NULL) {
        array_free(param_order);
        return 0;
    }

    // Подготавливаем statement
    PGresult* res = PQprepare(pgconnection->connection, str_get(stmt_name), str_get(processed_sql), array_size(param_order), NULL);
    if (res == NULL) {
        log_error("PQprepare failed: out of memory\n");
        str_free(processed_sql);
        array_free(param_order);
        return 0;
    }

    pg_prepared_stmt_t* stmt_data = malloc(sizeof * stmt_data);
    if (stmt_data == NULL) {
        log_error("__prepare: memory allocation failed for stmt_data\n");
        str_free(processed_sql);
        array_free(param_order);
        return 0;
    }

    stmt_data->connection = connection;
    stmt_data->param_order = param_order;
    stmt_data->stmt_name = str_createn(str_get(stmt_name), str_size(stmt_name));
    if (stmt_data->stmt_name == NULL) {
        log_error("__prepare: memory allocation failed for stmt_name\n");
        str_free(processed_sql);
        __prepared_stmt_free(stmt_data);
        return 0;
    }

    ExecStatusType status = PQresultStatus(res);
    PQclear(res);

    if (status != PGRES_COMMAND_OK) {
        log_error("PQprepare error: %s\nSQL: %s\n", PQerrorMessage(pgconnection->connection), str_get(processed_sql));
        str_free(processed_sql);
        __prepared_stmt_free(stmt_data);
        return 0;
    }

    str_free(processed_sql);

    // Сохраняем порядок параметров в prepare_statements. Даже пустой.
    const int r = map_insert_or_assign(pgconnection->base.prepare_statements, str_get(stmt_name), stmt_data);
    if (r == -1) {
        __prepared_stmt_free(stmt_data);
        return 0;
    }

    return 1;
}

dbresult_t* __execute_prepared(void* connection, const char* stmt_name, array_t* params) {
    postgresqlconnection_t* pgconnection = connection;

    int res = 0;
    dbresult_t* result = dbresult_create();
    if (result == NULL) return NULL;

    // Получаем порядок параметров из prepare_statements
    pg_prepared_stmt_t* stmt_data = map_find(pgconnection->base.prepare_statements, stmt_name);
    if (stmt_data == NULL) {
        log_error("__execute_prepared: prepared statement %s not found\n", stmt_name);
        return result;
    }

    array_t* param_order = stmt_data->param_order;
    // Определяем количество параметров
    const int n_params = array_size(param_order);
    // Подготавливаем массивы параметров
    const char** param_values = NULL;
    int* param_lengths = NULL;

    if (n_params > 0) {
        param_values = malloc(sizeof(char*) * n_params);
        if (param_values == NULL) {
            log_error("__execute_prepared: memory allocation failed\n");
            goto failed;
        }

        param_lengths = malloc(sizeof(int) * n_params);
        if (param_lengths == NULL) {
            log_error("__execute_prepared: memory allocation failed\n");
            goto failed;
        }

        for (size_t i = 0; i < array_size(param_order); i++) {
            int finded = 0;
            const char* param_order_str = array_get_string(param_order, i);
            if (param_order_str == NULL) {
                log_error("__execute_prepared: param_order_str is NULL\n");
                goto failed;
            }

            for (size_t j = 0; j < array_size(params); j++) {
                mfield_t* field = array_get(params, j);

                if (field != NULL && strcmp(param_order_str, field->name) == 0) {
                    str_t* str = model_field_to_string(field);
                    if (str == NULL) {
                        log_error("__execute_prepared: model_field_to_string failed\n");
                        goto failed;
                    }
                    param_values[i] = str_get(str);
                    if (param_values[i] == NULL) {
                        log_error("__execute_prepared: memory allocation failed for param_strings\n");
                        goto failed;
                    }
                    param_lengths[i] = (int)str_size(str);
                    if (param_lengths[i] < 0) {
                        log_error("__execute_prepared: param_lengths is less than 0\n");
                        goto failed;
                    }
                    finded = 1;
                    break;
                }
            }

            if (!finded) {
                log_error("__execute_prepared: param %s not found in params array\n", param_order_str);
                goto failed;
            }
        }
    }

    if (!PQsendQueryPrepared(pgconnection->connection, stmt_name, n_params, param_values, param_lengths, 0, 0)) {
        log_error("PQsendQueryPrepared failed: %s\n", PQerrorMessage(pgconnection->connection));
        goto failed;
    }

    res = 1;

    failed:

    if (param_values != NULL) free(param_values);
    if (param_lengths != NULL) free(param_lengths);

    if (!res) {
        result->ok = 0;
        return result;
    }

    return __process_result(pgconnection, result);
}

db_t* postgresql_load(const char* database_id, const json_token_t* token_array) {
    db_t* result = NULL;
    db_t* database = db_create(database_id);
    if (database == NULL) {
        log_error("postgresql_load: can't create database\n");
        return NULL;
    }

    enum fields { HOST_ID = 0, PORT, IP, DBNAME, USER, PASSWORD, CONNECTION_TIMEOUT, FIELDS_COUNT };
    enum reqired_fields { R_HOST_ID = 0, R_PORT, R_IP, R_DBNAME, R_USER, R_PASSWORD, R_CONNECTION_TIMEOUT, R_FIELDS_COUNT };
    char* field_names[FIELDS_COUNT] = {"host_id", "port", "ip", "dbname", "user", "password", "connection_timeout"};

    for (json_it_t it_array = json_init_it(token_array); !json_end_it(&it_array); json_next_it(&it_array)) {
        json_token_t* token_object = json_it_value(&it_array);
        int lresult = 0;
        int finded_fields[FIELDS_COUNT] = {0};
        postgresqlhost_t* host = __host_create();
        if (host == NULL) {
            log_error("postgresql_load: can't create host\n");
            goto failed;
        }

        for (json_it_t it_object = json_init_it(token_object); !json_end_it(&it_object); json_next_it(&it_object)) {
            const char* key = json_it_key(&it_object);
            json_token_t* token_value = json_it_value(&it_object);

            if (strcmp(key, "host_id") == 0) {
                if (finded_fields[HOST_ID]) {
                    log_error("postgresql_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("postgresql_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[HOST_ID] = 1;

                if (host->base.id != NULL) free(host->base.id);

                host->base.id = malloc(json_string_size(token_value) + 1);
                if (host->base.id == NULL) {
                    log_error("postgresql_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->base.id, json_string(token_value));
            }
            else if (strcmp(key, "port") == 0) {
                if (finded_fields[PORT]) {
                    log_error("postgresql_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_number(token_value)) {
                    log_error("postgresql_load: field %s must be int\n", key);
                    goto host_failed;
                }

                finded_fields[PORT] = 1;

                int ok = 0;
                host->base.port = json_int(token_value, &ok);
                if (!ok) {
                    log_error("postgresql_load: field %s must be int\n", key);
                    goto host_failed;
                }
            }
            else if (strcmp(key, "ip") == 0) {
                if (finded_fields[IP]) {
                    log_error("postgresql_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("postgresql_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[IP] = 1;

                if (host->base.ip != NULL) free(host->base.ip);

                host->base.ip = malloc(json_string_size(token_value) + 1);
                if (host->base.ip == NULL) {
                    log_error("postgresql_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->base.ip, json_string(token_value));
            }
            else if (strcmp(key, "dbname") == 0) {
                if (finded_fields[DBNAME]) {
                    log_error("postgresql_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("postgresql_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[DBNAME] = 1;

                if (host->dbname != NULL) free(host->dbname);

                host->dbname = malloc(json_string_size(token_value) + 1);
                if (host->dbname == NULL) {
                    log_error("postgresql_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->dbname, json_string(token_value));
            }
            else if (strcmp(key, "user") == 0) {
                if (finded_fields[USER]) {
                    log_error("postgresql_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("postgresql_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[USER] = 1;

                if (host->user != NULL) free(host->user);

                host->user = malloc(json_string_size(token_value) + 1);
                if (host->user == NULL) {
                    log_error("postgresql_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->user, json_string(token_value));
            }
            else if (strcmp(key, "password") == 0) {
                if (finded_fields[PASSWORD]) {
                    log_error("postgresql_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("postgresql_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[PASSWORD] = 1;

                if (host->password != NULL) free(host->password);

                host->password = malloc(json_string_size(token_value) + 1);
                if (host->password == NULL) {
                    log_error("postgresql_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->password, json_string(token_value));
            }
            else if (strcmp(key, "connection_timeout") == 0) {
                if (finded_fields[CONNECTION_TIMEOUT]) {
                    log_error("postgresql_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_number(token_value)) {
                    log_error("postgresql_load: field %s must be int\n", key);
                    goto host_failed;
                }

                finded_fields[CONNECTION_TIMEOUT] = 1;

                int ok = 0;
                host->connection_timeout = json_int(token_value, &ok);
                if (!ok) {
                    log_error("postgresql_load: field %s must be int\n", key);
                    goto host_failed;
                }
            }
            else if (strcmp(key, "schema") == 0) {
                if (!json_is_string(token_value)) {
                    log_error("postgresql_load: field %s must be string\n", key);
                    goto host_failed;
                }

                size_t schema_size = json_string_size(token_value);
                if (schema_size > 0) {
                    host->schema = malloc(schema_size + 1);
                    if (host->schema == NULL) {
                        log_error("postgresql_load: alloc memory for %s failed\n", key);
                        goto host_failed;
                    }
                    strcpy(host->schema, json_string(token_value));
                } else {
                    host->schema = NULL;
                }
            }
            else {
                log_error("postgresql_load: unknown field: %s\n", key);
                goto host_failed;
            }
        }

        array_push_back(database->hosts, array_create_pointer(host, array_nocopy, host->base.free));

        for (int i = 0; i < R_FIELDS_COUNT; i++) {
            if (finded_fields[i] == 0) {
                log_error("postgresql_load: required field %s not found\n", field_names[i]);
                goto host_failed;
            }
        }

        lresult = 1;

        host_failed:

        if (lresult == 0) {
            host->base.free(host);
            goto failed;
        }
    }

    result = database;

    failed:

    if (result == NULL)
        db_free(database);

    return result;
}

char* __compile_insert(void* connection, const char* table, array_t* params) {
    if (connection == NULL) return NULL;
    if (table == NULL) return NULL;
    if (params == NULL) return NULL;
    if (array_size(params) == 0) return NULL;

    dbconnection_t* conn = connection;
    char* buffer = NULL;

    // Экранируем название таблицы
    str_t* escaped_table = conn->escape_identifier(conn, table);
    if (escaped_table == NULL)
        return NULL;

    str_t* fields = str_create_empty(256);
    if (fields == NULL) {
        str_free(escaped_table);
        return NULL;
    }

    str_t* values = str_create_empty(256);
    if (values == NULL)
        goto failed;

    for (size_t i = 0; i < array_size(params); i++) {
        mfield_t* field = array_get(params, i);
        if (field == NULL)
            goto failed;

        if (i > 0) {
            str_appendc(fields, ',');
            str_appendc(values, ',');
        }

        str_t* escaped_field = conn->escape_identifier(conn, field->name);
        if (escaped_field == NULL)
            goto failed;

        str_append(fields, str_get(escaped_field), str_size(escaped_field));
        str_free(escaped_field);

        str_t* value = model_field_to_string(field);
        if (value == NULL)
            goto failed;

        const char* value_str = str_get(value);
        if (field->use_raw_sql) {
            str_append(values, value_str, str_size(value));
        } else {
            str_t* quoted_str = conn->escape_string(conn, value_str);
            if (quoted_str == NULL)
                goto failed;

            str_append(values, str_get(quoted_str), str_size(quoted_str));
            str_free(quoted_str);
        }
    }

    const char* format = "INSERT INTO %s (%s) VALUES (%s)";
    const size_t buffer_size = strlen(format) + str_size(escaped_table) + str_size(fields) + str_size(values) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL)
        goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(escaped_table),
        str_get(fields),
        str_get(values)
    );

    failed:

    str_free(escaped_table);
    str_free(fields);
    str_free(values);

    return buffer;
}

char* __compile_select(void* connection, const char* table, array_t* columns, array_t* where) {
    if (connection == NULL) return NULL;
    if (table == NULL) return NULL;

    dbconnection_t* conn = connection;
    char* buffer = NULL;

    str_t* escaped_table = conn->escape_identifier(conn, table);
    if (escaped_table == NULL)
        return NULL;

    str_t* columns_str = str_create_empty(256);
    if (columns_str == NULL) {
        str_free(escaped_table);
        return NULL;
    }

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL)
        goto failed;

    // Обрабатываем колонки
    for (size_t i = 0; i < array_size(columns); i++) {
        const char* column_name = array_get(columns, i);
        if (column_name == NULL)
            goto failed;

        if (i > 0)
            str_appendc(columns_str, ',');

        // Литералы, функции и выражения вставляем как есть
        if (__is_raw_sql(column_name)) {
            str_append(columns_str, column_name, strlen(column_name));
        } else {
            // Идентификаторы экранируем
            str_t* escaped_col = conn->escape_identifier(conn, column_name);
            if (escaped_col == NULL)
                goto failed;

            str_append(columns_str, str_get(escaped_col), str_size(escaped_col));
            str_free(escaped_col);
        }
    }

    // Экранируем имена полей в WHERE
    for (size_t i = 0; i < array_size(where); i++) {
        mfield_t* field = array_get(where, i);
        if (field == NULL)
            goto failed;

        if (i > 0)
            str_append(where_str, " AND ", 5);

        str_t* escaped_field = conn->escape_identifier(conn, field->name);
        if (escaped_field == NULL)
            goto failed;

        str_append(where_str, str_get(escaped_field), str_size(escaped_field));
        str_free(escaped_field);

        str_appendc(where_str, '=');

        str_t* value = model_field_to_string(field);
        if (value == NULL)
            goto failed;

        str_t* quoted_str = conn->escape_string(conn, str_get(value));
        if (quoted_str == NULL)
            goto failed;

        str_append(where_str, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    const char* format = "SELECT %s FROM %s WHERE %s";
    const size_t buffer_size = strlen(format) + str_size(escaped_table) + str_size(columns_str) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL)
        goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(columns_str),
        str_get(escaped_table),
        str_get(where_str)
    );

    failed:

    str_free(escaped_table);
    str_free(columns_str);
    str_free(where_str);

    return buffer;
}

char* __compile_update(void* connection, const char* table, array_t* set, array_t* where) {
    if (connection == NULL) return NULL;
    if (table == NULL) return NULL;
    if (set == NULL) return NULL;

    dbconnection_t* conn = connection;
    char* buffer = NULL;

    str_t* escaped_table = conn->escape_identifier(conn, table);
    if (escaped_table == NULL)
        return NULL;

    str_t* set_str = str_create_empty(256);
    if (set_str == NULL) {
        str_free(escaped_table);
        return NULL;
    }

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL)
        goto failed;

    if (where == NULL || array_size(where) == 0)
        str_append(where_str, "true", 4);

    // Экранируем имена полей в SET
    for (size_t i = 0; i < array_size(set); i++) {
        mfield_t* field = array_get(set, i);
        if (field == NULL)
            goto failed;

        if (i > 0)
            str_appendc(set_str, ',');

        str_t* escaped_field = conn->escape_identifier(conn, field->name);
        if (escaped_field == NULL)
            goto failed;

        str_append(set_str, str_get(escaped_field), str_size(escaped_field));
        str_free(escaped_field);

        str_appendc(set_str, '=');

        str_t* value = model_field_to_string(field);
        if (value == NULL)
            goto failed;

        str_t* quoted_str = conn->escape_string(conn, str_get(value));
        if (quoted_str == NULL)
            goto failed;

        str_append(set_str, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    // Экранируем имена полей в WHERE
    for (size_t i = 0; i < array_size(where); i++) {
        mfield_t* field = array_get(where, i);
        if (field == NULL)
            goto failed;

        if (i > 0)
            str_append(where_str, " AND ", 5);

        str_t* escaped_field = conn->escape_identifier(conn, field->name);
        if (escaped_field == NULL)
            goto failed;

        str_append(where_str, str_get(escaped_field), str_size(escaped_field));
        str_free(escaped_field);

        str_appendc(where_str, '=');

        str_t* value = model_field_to_string(field);
        if (value == NULL)
            goto failed;

        str_t* quoted_str = conn->escape_string(conn, str_get(value));
        if (quoted_str == NULL)
            goto failed;

        str_append(where_str, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    const char* format = "UPDATE %s SET %s WHERE %s";
    const size_t buffer_size = strlen(format) + str_size(escaped_table) + str_size(set_str) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL)
        goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(escaped_table),
        str_get(set_str),
        str_get(where_str)
    );

    failed:

    str_free(escaped_table);
    str_free(set_str);
    str_free(where_str);

    return buffer;
}

char* __compile_delete(void* connection, const char* table, array_t* where) {
    if (connection == NULL) return NULL;
    if (table == NULL) return NULL;

    dbconnection_t* conn = connection;
    char* buffer = NULL;

    str_t* escaped_table = conn->escape_identifier(conn, table);
    if (escaped_table == NULL)
        return NULL;

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL) {
        str_free(escaped_table);
        return NULL;
    }

    if (where == NULL || array_size(where) == 0)
        str_append(where_str, "true", 4);

    // Экранируем имена полей в WHERE
    for (size_t i = 0; i < array_size(where); i++) {
        mfield_t* field = array_get(where, i);
        if (field == NULL)
            goto failed;

        if (i > 0)
            str_append(where_str, " AND ", 5);

        str_t* escaped_field = conn->escape_identifier(conn, field->name);
        if (escaped_field == NULL)
            goto failed;

        str_append(where_str, str_get(escaped_field), str_size(escaped_field));
        str_free(escaped_field);

        str_appendc(where_str, '=');

        str_t* value = model_field_to_string(field);
        if (value == NULL)
            goto failed;

        str_t* quoted_str = conn->escape_string(conn, str_get(value));
        if (quoted_str == NULL)
            goto failed;

        str_append(where_str, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    const char* format = "DELETE FROM %s WHERE %s";
    const size_t buffer_size = strlen(format) + str_size(escaped_table) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL)
        goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(escaped_table),
        str_get(where_str)
    );

    failed:

    str_free(escaped_table);
    str_free(where_str);

    return buffer;
}

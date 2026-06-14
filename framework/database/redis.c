#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "log.h"
#include "array.h"
#include "str.h"
#include "model.h"
#include "dbresult.h"
#include "redis.h"

static redishost_t* __host_create(void);
static void __host_free(void* arg);
static void* __connection_create(void* host);
static void __connection_free(void* connection);
static dbresult_t* __query(void* connection, const char* sql);
static dbresult_t* __execute_params(void* connection, const char* sql, array_t* params);
static int __redis_fill_result(redisReply* reply, dbresult_t* result);
int redis_auth(redisContext*, const char*, const char*);
int redis_selectdb(redisContext*, const int);
static redisContext* __connect(void* host);
static int __is_active(void* connection);
static int __reconnect(void* host, void* connection);
static str_t* __escape_identifier(void* connection, const char* str);
static str_t* __escape_string(void* connection, const char* str);
static char* __compile_insert(void* connection, const char* table, array_t* params);
static char* __compile_select(void* connection, const char* table, array_t* columns, array_t* where);
static char* __compile_update(void* connection, const char* table, array_t* set, array_t* where);
static char* __compile_delete(void* connection, const char* table, array_t* where);


redishost_t* __host_create(void) {
    redishost_t* host = malloc(sizeof * host);
    if (host == NULL) return NULL;

    host->base.connections = array_create();
    if (host->base.connections == NULL) {
        free(host);
        return NULL;
    }

    host->base.free = __host_free;
    host->base.port = 0;
    host->base.ip = NULL;
    host->base.id = NULL;
    host->base.connection_create = __connection_create;
    host->base.connections_locked = 0;
    host->base.grammar.compile_table_exist = NULL;
    host->base.grammar.compile_table_migration_create = NULL;
    host->base.grammar.compile_insert = __compile_insert;
    host->base.grammar.compile_select = __compile_select;
    host->base.grammar.compile_update = __compile_update;
    host->base.grammar.compile_delete = __compile_delete;
    host->dbindex = 0;
    host->user = NULL;
    host->password = NULL;

    return host;
}

void __host_free(void* arg) {
    if (arg == NULL) return;

    redishost_t* host = arg;

    if (host->base.id) free(host->base.id);
    if (host->base.ip) free(host->base.ip);
    if (host->user) free(host->user);
    if (host->password) free(host->password);

    array_free(host->base.connections);
    free(host);
}

static const char* __type_cast(int field_type) {
    (void)field_type;
    return "";
}

void* __connection_create(void* host) {
    redisconnection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection->base.thread_id = gettid();
    connection->base.prepare_statements = NULL;
    connection->base.free = __connection_free;
    connection->base.query = __query;
    connection->base.escape_identifier = __escape_identifier;
    connection->base.escape_string = __escape_string;
    connection->base.is_active = __is_active;
    connection->base.reconnect = __reconnect;
    connection->base.prepare = NULL;
    connection->base.execute_prepared = NULL;
    connection->base.execute_params = __execute_params;
    connection->base.type_cast = __type_cast;
    connection->base.host = host;
    connection->connection = __connect(host);

    if (!__is_active(connection)) {
        log_error("redis connection not created by host %s\n", ((redishost_t*)host)->base.id);
        connection->base.free(connection);
        connection = NULL;
    }

    return connection;
}

void __connection_free(void* connection) {
    if (connection == NULL) return;

    redisconnection_t* conn = connection;

    redisFree(conn->connection);
    free(conn);
}

// Map a successful redisReply into `result`: a single unnamed column, one row
// per array element (REDIS_REPLY_ARRAY) or a single row otherwise. Returns 1 on
// success, 0 on allocation failure. Shared by __query and __execute_params.
static int __redis_fill_result(redisReply* reply, dbresult_t* result) {
    int rows = reply->type == REDIS_REPLY_ARRAY ? reply->elements : 1;
    int cols = 1;
    int col = 0;
    dbresultquery_t* query = dbresult_query_create(rows, cols);

    if (query == NULL) {
        log_error("Out of memory\n");
        return 0;
    }

    result->query = query;
    result->current = query;

    dbresult_query_field_insert(query, "", col);

    for (int row = 0; row < rows; row++) {
        size_t length = reply->len;
        const char* value = reply->str;

        if (rows > 1) {
            length = reply->element[row]->len;
            value = reply->element[row]->str;
        }

        dbresult_query_value_insert(query, value, length, row, col);
    }

    return 1;
}

dbresult_t* __query(void* connection, const char* sql) {
    redisconnection_t* redisconnection = connection;

    log_debug("DB query: %s\n", sql);

    dbresult_t* result = dbresult_create();
    if (result == NULL) return NULL;

    // hiredis трактует строку как printf-формат: экранируем '%' -> '%%',
    // иначе '%' в данных ломает команду и читает мусор из va_args
    redisReply* reply = NULL;
    if (strchr(sql, '%') == NULL) {
        reply = redisCommand(redisconnection->connection, sql);
    } else {
        str_t escaped;
        str_init(&escaped, 256);
        for (const char* p = sql; *p != '\0'; p++) {
            str_appendc(&escaped, *p);
            if (*p == '%')
                str_appendc(&escaped, '%');
        }
        reply = redisCommand(redisconnection->connection, str_get(&escaped));
        str_clear(&escaped);
    }

    if (reply == NULL || redisconnection->connection->err != 0) {
        log_error("Redis error: %s\n", redisconnection->connection->errstr);
        goto failed;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        log_error("Redis error: %s\n", reply->str);
        goto failed;
    }

    if (!__redis_fill_result(reply, result))
        goto failed;

    result->ok = 1;

    failed:

    freeReplyObject(reply);

    return result;
}

/* Parameterized execution (universal named-parameter path).
 *
 * `sql` arrives from the shared builder (__build_query) carrying positional
 * placeholders $1..$N (Redis type_cast is "", so a placeholder token is exactly
 * "$N"); `params` is the ordered array of mfield_t* to bind. We tokenize the
 * command on whitespace and pass it to redisCommandArgv as an argument vector:
 * each "$N" token becomes a single, binary-safe argv element holding the bound
 * value, every other token is forwarded verbatim. Because values are discrete
 * argv elements they can never split into extra command words — this is the
 * binding guarantee Redis lacks via the printf path.
 *
 * v1 scope: scalar `:name` only. `:list__` (comma-joined "$1,$2") and `@name`
 * identifiers are not supported for Redis.
 */
static dbresult_t* __execute_params(void* connection, const char* sql, array_t* params) {
    redisconnection_t* redisconnection = connection;

    log_debug("DB params query: %s\n", sql);

    dbresult_t* result = dbresult_create();
    if (result == NULL) return NULL;

    const int n_params = params != NULL ? (int)array_size(params) : 0;

    char* buf = NULL;
    const char** argv = NULL;
    size_t* argvlen = NULL;
    redisReply* reply = NULL;

    buf = strdup(sql);
    if (buf == NULL) {
        log_error("redis execute_params: out of memory\n");
        goto failed;
    }

    // Count whitespace-separated tokens to size the argv vector.
    size_t argc = 0;
    for (const char* p = sql; *p != '\0'; ) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == '\0') break;
        argc++;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    }

    if (argc == 0) {
        log_error("redis execute_params: empty command\n");
        goto failed;
    }

    argv = malloc(sizeof(char*) * argc);
    argvlen = malloc(sizeof(size_t) * argc);
    if (argv == NULL || argvlen == NULL) {
        log_error("redis execute_params: out of memory\n");
        goto failed;
    }

    size_t ai = 0;
    for (char* p = buf; *p != '\0'; ) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == '\0') break;

        char* start = p;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        if (*p != '\0') { *p = '\0'; p++; }

        // A "$<digits>" token is a positional placeholder: bind params[N-1].
        int is_placeholder = start[0] == '$' && start[1] != '\0';
        for (const char* d = start + 1; is_placeholder && *d != '\0'; d++)
            if (*d < '0' || *d > '9') is_placeholder = 0;

        if (is_placeholder) {
            const int pidx = atoi(start + 1);
            if (pidx < 1 || pidx > n_params) {
                log_error("redis execute_params: placeholder $%d out of range (have %d params)\n", pidx, n_params);
                goto failed;
            }

            mfield_t* field = array_get(params, pidx - 1);
            if (field == NULL) {
                log_error("redis execute_params: param %d is NULL\n", pidx);
                goto failed;
            }

            if (field->is_null) {
                argv[ai] = "";
                argvlen[ai] = 0;
            } else {
                str_t* value = model_field_to_string(field);
                if (value == NULL) {
                    log_error("redis execute_params: model_field_to_string failed for %s\n", field->name);
                    goto failed;
                }
                argv[ai] = str_get(value);
                argvlen[ai] = str_size(value);
            }
        } else {
            argv[ai] = start;
            argvlen[ai] = strlen(start);
        }

        ai++;
    }

    reply = redisCommandArgv(redisconnection->connection, (int)ai, argv, argvlen);

    if (reply == NULL || redisconnection->connection->err != 0) {
        log_error("Redis error: %s\n", redisconnection->connection->errstr);
        goto failed;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        log_error("Redis error: %s\n", reply->str);
        goto failed;
    }

    if (!__redis_fill_result(reply, result))
        goto failed;

    result->ok = 1;

    failed:

    freeReplyObject(reply);
    free(argv);
    free(argvlen);
    free(buf);

    return result;
}

// Проверяет ответ Redis: ошибка протокола или REDIS_REPLY_ERROR -> 0
static int __redis_check_reply(redisReply* reply) {
    if (reply == NULL) return 0;

    int ok = 1;
    if (reply->type == REDIS_REPLY_ERROR) {
        log_error("Redis error: %s\n", reply->str);
        ok = 0;
    }

    freeReplyObject(reply);

    return ok;
}

int redis_auth(redisContext* connection, const char* user, const char* password) {
    if (password == NULL || password[0] == '\0') return 1;

    // Формат-аргументы hiredis бинарно-безопасны: пробелы и '%' в
    // user/password не ломают команду. Без user — legacy AUTH с одним
    // аргументом
    redisReply* reply = (user == NULL || user[0] == '\0')
        ? redisCommand(connection, "AUTH %s", password)
        : redisCommand(connection, "AUTH %s %s", user, password);

    return __redis_check_reply(reply);
}

int redis_selectdb(redisContext* connection, const int index) {
    return __redis_check_reply(redisCommand(connection, "SELECT %d", index));
}

redisContext* __connect(void* arg) {
    redishost_t* host = arg;

    redisContext* connection = redisConnect(host->base.ip, host->base.port);
    if (connection == NULL || connection->err != 0) {
        log_error("Redis error: %s\n", connection != NULL ? connection->errstr : "can't allocate redis context");
        redisFree(connection);
        return NULL;
    }

    if (!redis_auth(connection, host->user, host->password)) {
        log_error("Redis error: %s\n", connection->errstr);
        redisFree(connection);
        return NULL;
    }

    if (!redis_selectdb(connection, host->dbindex)) {
        log_error("Redis error: %s\n", connection->errstr);
        redisFree(connection);
        return NULL;
    }

    redisEnableKeepAlive(connection);

    return connection;
}

int __is_active(void* connection) {
    redisconnection_t* conn = connection;
    if (conn == NULL) return 0;

    if (conn->connection == NULL) return 0;

    redisReply* reply = redisCommand(conn->connection, "PING");
    if (reply == NULL) {
        log_error("Redis error: connection lost\n");
        return 0;
    }

    int is_alive = 0;
    if (reply->type == REDIS_REPLY_STRING && strcmp(reply->str, "PONG") == 0)
        is_alive = 1;
    else if (reply->type == REDIS_REPLY_STATUS && strcmp(reply->str, "PONG") == 0)
        is_alive = 1;

    freeReplyObject(reply);

    return is_alive;
}

int __reconnect(void* host, void* connection) {
    redisconnection_t* conn = connection;

    if (!__is_active(conn)) {
        redisFree(conn->connection);

        conn->connection = __connect(host);

        if (!__is_active(conn)) {
            redisFree(conn->connection);
            conn->connection = NULL;
            return 0;
        }
    }

    return 1;
}

str_t* __escape_identifier(void* connection, const char* str) {
    return __escape_string(connection, str);
}

str_t* __escape_string(void* connection, const char* str) {
    (void)connection;
    str_t* quoted_str = str_create_empty(256);
    if (quoted_str == NULL) return NULL;

    str_appendc(quoted_str, '"');
    const size_t str_len = strlen(str);
    for (size_t i = 0; i < str_len; i++) {
        char ch = str[i];
        if (ch == '"' || ch == '\\' || ch == '\'')
            str_appendc(quoted_str, '\\');

        str_appendc(quoted_str, ch);
    }
    str_appendc(quoted_str, '"');

    return quoted_str;
}

db_t* redis_load(const char* database_id, const json_token_t* token_array) {
    db_t* result = NULL;
    db_t* database = db_create(database_id);
    if (database == NULL) return NULL;

    enum fields { HOST_ID = 0, PORT, IP, DBINDEX, USER, PASSWORD, FIELDS_COUNT };
    enum required_fields { R_HOST_ID = 0, R_PORT, R_IP, R_DBINDEX, R_FIELDS_COUNT };
    char* field_names[FIELDS_COUNT] = {"host_id", "port", "ip", "dbindex", "user", "password"};

    for (json_it_t it_array = json_init_it(token_array); !json_end_it(&it_array); json_next_it(&it_array)) {
        json_token_t* token_object = json_it_value(&it_array);
        int lresult = 0;
        int finded_fields[FIELDS_COUNT] = {0};
        redishost_t* host = __host_create();
        if (host == NULL) {
            log_error("redis_load: can't create host\n");
            goto failed;
        }

        for (json_it_t it_object = json_init_it(token_object); !json_end_it(&it_object); json_next_it(&it_object)) {
            const char* key = json_it_key(&it_object);
            json_token_t* token_value = json_it_value(&it_object);

            if (strcmp(key, "host_id") == 0) {
                if (finded_fields[HOST_ID]) {
                    log_error("redis_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("redis_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[HOST_ID] = 1;

                if (host->base.id != NULL) free(host->base.id);

                host->base.id = malloc(json_string_size(token_value) + 1);
                if (host->base.id == NULL) {
                    log_error("redis_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->base.id, json_string(token_value));
            }
            else if (strcmp(key, "port") == 0) {
                if (finded_fields[PORT]) {
                    log_error("redis_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_number(token_value)) {
                    log_error("redis_load: field %s must be int\n", key);
                    goto host_failed;
                }

                finded_fields[PORT] = 1;

                int ok = 0;
                host->base.port = json_int(token_value, &ok);
                if (!ok) {
                    log_error("redis_load: field %s must be int\n", key);
                    goto host_failed;
                }
            }
            else if (strcmp(key, "ip") == 0) {
                if (finded_fields[IP]) {
                    log_error("redis_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("redis_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[IP] = 1;

                if (host->base.ip != NULL) free(host->base.ip);

                host->base.ip = malloc(json_string_size(token_value) + 1);
                if (host->base.ip == NULL) {
                    log_error("redis_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->base.ip, json_string(token_value));
            }
            else if (strcmp(key, "dbindex") == 0) {
                if (finded_fields[DBINDEX]) {
                    log_error("redis_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_number(token_value)) {
                    log_error("redis_load: field %s must be int\n", key);
                    goto host_failed;
                }

                finded_fields[DBINDEX] = 1;

                int ok = 0;
                host->dbindex = json_int(token_value, &ok);
                // Базы Redis по умолчанию: 0..15
                if (!ok || host->dbindex < 0 || host->dbindex > 15) {
                    log_error("redis_load: dbindex must be in range 0..15\n");
                    goto host_failed;
                }
            }
            else if (strcmp(key, "user") == 0) {
                if (finded_fields[USER]) {
                    log_error("redis_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("redis_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[USER] = 1;

                if (host->user != NULL) free(host->user);

                host->user = malloc(json_string_size(token_value) + 1);
                if (host->user == NULL) {
                    log_error("redis_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->user, json_string(token_value));
            }
            else if (strcmp(key, "password") == 0) {
                if (finded_fields[PASSWORD]) {
                    log_error("redis_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("redis_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[PASSWORD] = 1;

                if (host->password != NULL) free(host->password);

                host->password = malloc(json_string_size(token_value) + 1);
                if (host->password == NULL) {
                    log_error("redis_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->password, json_string(token_value));
            }
            else {
                log_error("redis_load: unknown field: %s\n", key);
                goto host_failed;
            }
        }

        if (finded_fields[USER] == 0) {
            if (host->user == NULL)
                host->user = malloc(1);

            if (host->user == NULL) {
                log_error("redis_load: can't alloc memory for user\n");
                goto host_failed;
            }
            strcpy(host->user, "");
        }

        if (finded_fields[PASSWORD] == 0) {
            if (host->password == NULL)
                host->password = malloc(1);

            if (host->password == NULL) {
                log_error("redis_load: can't alloc memory for password\n");
                goto host_failed;
            }
            strcpy(host->password, "");
        }

        for (int i = 0; i < R_FIELDS_COUNT; i++) {
            if (finded_fields[i] == 0) {
                log_error("redis_load: required field %s not found\n", field_names[i]);
                goto host_failed;
            }
        }

        // Добавляем host в массив только после всех проверок: элемент массива
        // владеет host (освобождается через db_free), ручной free после
        // push привёл бы к двойному освобождению
        array_push_back(database->hosts, array_create_pointer(host, array_nocopy, host->base.free));

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
    (void)connection;
    (void)table;
    (void)params;
    return NULL;
}

char* __compile_select(void* connection, const char* table, array_t* columns, array_t* where) {
    (void)connection;
    (void)table;
    (void)columns;
    (void)where;
    return NULL;
}

char* __compile_update(void* connection, const char* table, array_t* set, array_t* where) {
    (void)connection;
    (void)table;
    (void)set;
    (void)where;
    return NULL;
}

char* __compile_delete(void* connection, const char* table, array_t* where) {
    (void)connection;
    (void)table;
    (void)where;
    return NULL;
}

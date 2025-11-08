#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "log.h"
#include "array.h"
#include "str.h"
#include "model.h"
#include "dbresult.h"
#include "dbquery.h"
#include "mysql.h"

// Помощник функция для очистки bind_result (используется при ошибках)
// Определяем макрос для очистки
#define CLEANUP_BIND_RESULT() \
    for (int col = 0; col < cols; col++) { \
        if (bind_result[col].buffer) free(bind_result[col].buffer); \
        if (bind_result[col].length) free(bind_result[col].length); \
        if (bind_result[col].is_null) free(bind_result[col].is_null); \
        if (bind_result[col].error) free(bind_result[col].error); \
    } \
    free(bind_result); \

typedef struct {
    array_t* param_order;
} my_sql_processor_data_t;

typedef struct {
    MYSQL_STMT* stmt;
    array_t* param_order;
    MYSQL_BIND* write_binds;
    bool* null_indicators;  // Массив индикаторов NULL для каждого параметра
} mysql_prepared_stmt_t;

static myhost_t* __host_create(void);
static void __host_free(void*);
static void* __connection_create(void* host);
static void __connection_free(void* connection);
static dbresult_t* __query(void* connection, const char* sql);
static dbresult_t* __process_result(void* connection, dbresult_t* result);
static dbresult_t* __process_prepared_result(void* connection, MYSQL_STMT* stmt, dbresult_t* result);
static MYSQL* __connect(void* host);
static int __is_active(void* connection);
static int __reconnect(void* host, void* connection);
static char* __compile_table_exist(dbconnection_t* connection, const char* table);
static char* __compile_table_migration_create(dbconnection_t* connection, const char* table);
static str_t* __escape_identifier(void* connection, const char* str);
static str_t* __escape_string(void* connection, const char* str);
static str_t* __escape_internal(void* connection, const char* str, char quote);
static int __build_query_processor(void* connection, char parameter_type, const char* param_name, mfield_t* field, str_t* result_sql, void* user_data);
static str_t* __build_query(void* connection, str_t* sql, array_t* params, array_t* param_order);
static void __prepared_stmt_free(void* data);
static int __prepare(void* connection, str_t* stmt_name, str_t* sql, array_t* params);
static dbresult_t* __execute_prepared(void* connection, const char* stmt_name, array_t* params);
static int __deallocate(void* connection, str_t* stmt_name);
static char* __compile_insert(void* connection, const char* table, array_t* params);
static char* __compile_select(void* connection, const char* table, array_t* columns, array_t* where);
static char* __compile_update(void* connection, const char* table, array_t* set, array_t* where);
static char* __compile_delete(void* connection, const char* table, array_t* where);
static enum_field_types __convert_model_type_to_mysql(mtype_e model_type);
static int __bind_field_value(MYSQL_BIND* bind, mfield_t* field, bool* is_null_indicator);


myhost_t* __host_create(void) {
    myhost_t* host = malloc(sizeof * host);
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

    return host;
}

void __host_free(void* arg) {
    if (arg == NULL) return;

    myhost_t* host = arg;

    if (host->base.id) free(host->base.id);
    if (host->base.ip) free(host->base.ip);
    if (host->dbname) free(host->dbname);
    if (host->user) free(host->user);
    if (host->password) free(host->password);

    array_free(host->base.connections);
    free(host);
}

void* __connection_create(void* host) {
    myconnection_t* connection = malloc(sizeof * connection);
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
    connection->base.deallocate = __deallocate;
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
        "SHOW TABLES LIKE %s",
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

    ssize_t written = snprintf(
        tmp,
        sizeof(tmp),
        "CREATE TABLE %s "
        "("
            "version     varchar(180)  NOT NULL PRIMARY KEY,"
            "apply_time  integer       NOT NULL DEFAULT 0"
        ")",
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

    myconnection_t* conn = connection;

    mysql_close(conn->connection);
    free(conn);
}

dbresult_t* __query(void* connection, const char* sql) {
    myconnection_t* myconnection = connection;

    dbresult_t* result = dbresult_create();
    if (result == NULL) return NULL;

    if (mysql_query(myconnection->connection, sql) != 0) {
        log_error("Mysql error: %s\n", mysql_error(myconnection->connection));
        return result;
    }

    return __process_result(myconnection, result);
}

dbresult_t* __process_result(void* connection, dbresult_t* result) {
    myconnection_t* myconnection = connection;

    result->ok = 1;

    int status = 0;
    dbresultquery_t* query_last = NULL;

    do {
        MYSQL_RES* res = NULL;

        if ((res = mysql_store_result(myconnection->connection))) {
            int cols = mysql_num_fields(res);
            int rows = mysql_num_rows(res);

            dbresultquery_t* query = dbresult_query_create(rows, cols);
            if (query == NULL) {
                result->ok = 0;
                log_error("Mysql error: Out of memory\n");
                goto clear;
            }

            if (query_last != NULL)
                query_last->next = query;

            query_last = query;

            if (result->query == NULL) {
                result->query = query;
                result->current = query;
            }

            MYSQL_FIELD* fields = mysql_fetch_fields(res);

            for (int col = 0; col < cols; col++)
                dbresult_query_field_insert(query, fields[col].name, col);

            MYSQL_ROW myrow;
            int row = 0;

            while ((myrow = mysql_fetch_row(res))) {
                unsigned long* lengths = mysql_fetch_lengths(res);

                for (int col = 0; col < cols; col++) {
                    size_t length = lengths[col];
                    const char* value = myrow[col];

                    dbresult_query_value_insert(query, value, length, row, col);
                }

                row++;
            }

            clear:

            mysql_free_result(res);
        }
        else if (mysql_field_count(myconnection->connection) != 0) {
            log_error("Mysql error: %s\n", mysql_error(myconnection->connection));
            result->ok = 0;
            break;
        }

        if ((status = mysql_next_result(myconnection->connection)) > 0) {
            log_error("Mysql error: %s\n", mysql_error(myconnection->connection));
            result->ok = 0;
        }

    } while (status == 0);

    return result;
}

dbresult_t* __process_prepared_result(void* connection, MYSQL_STMT* stmt, dbresult_t* result) {
    myconnection_t* myconnection = connection;

    result->ok = 1;
    dbresultquery_t* query_last = NULL;

    do {
        // Получаем метаданные результата
        MYSQL_RES* res = mysql_stmt_result_metadata(stmt);
        if (res == NULL && mysql_stmt_field_count(stmt) > 0) {
            log_error("__process_prepared_result: mysql_stmt_result_metadata failed: %s\n", mysql_stmt_error(stmt));
            return result;
        }

        if (res != NULL) {
            int cols = mysql_num_fields(res);

            // Сохраняем результаты в буфер statement'а
            if (mysql_stmt_store_result(stmt)) {
                log_error("__process_prepared_result: mysql_stmt_store_result failed: %s\n", mysql_stmt_error(stmt));
                mysql_free_result(res);
                return result;
            }

            unsigned long num_rows = mysql_stmt_num_rows(stmt);

            // Создаём query с правильным количеством строк
            dbresultquery_t* query = dbresult_query_create(num_rows, cols);
            if (query == NULL) {
                log_error("__process_prepared_result: Out of memory\n");
                mysql_free_result(res);
                result->ok = 0;
                return result;
            }

            // ДОБАВЛЯЕМ QUERY В RESULT СРАЗУ ПОСЛЕ СОЗДАНИЯ
            // чтобы гарантировать что она не будет потеряна при ошибках
            if (query_last != NULL)
                query_last->next = query;

            query_last = query;

            if (result->query == NULL) {
                result->query = query;
                result->current = query;
            }

            // Вставляем информацию о полях
            MYSQL_FIELD* fields = mysql_fetch_fields(res);
            MYSQL_BIND* bind_result = calloc(cols, sizeof(MYSQL_BIND));
            if (bind_result == NULL) {
                log_error("__process_prepared_result: memory allocation failed for bind_result\n");
                mysql_free_result(res);
                result->ok = 0;
                return result;
            }

            // Инициализируем буферы для каждого столбца на основе max_length
            int alloc_failed = 0;
            for (int col = 0; col < cols; col++) {
                MYSQL_FIELD field = fields[col];

                dbresult_query_field_insert(query, field.name, col);

                // Вычисляем размер буфера
                // ВАЖНО: field.max_length всегда 0 для prepared statements, используем field.length
                // field.length — это максимальная длина по схеме таблицы
                // Защита от integer overflow: проверяем ПЕРЕД добавлением 1
                unsigned long buffer_length;
                const unsigned long MAX_FIELD_SIZE = 1024 * 1024 * 100;  // 100 MB на поле

                if (field.length >= MAX_FIELD_SIZE) {
                    buffer_length = MAX_FIELD_SIZE;
                    log_error("Field '%s' has excessive length %lu, limiting to 100MB\n", field.name, field.length);
                } else if (field.length > 0) {
                    // Безопасно добавляем 1 для null-терминатора
                    buffer_length = field.length + 1;
                } else {
                    buffer_length = 4096;
                }

                char* buffer = malloc(buffer_length);
                if (buffer == NULL) {
                    alloc_failed = 1;
                    break;
                }

                unsigned long* length = malloc(sizeof(unsigned long));
                if (length == NULL) {
                    alloc_failed = 1;
                    free(buffer);
                    break;
                }

                bool* is_null = malloc(sizeof(bool));
                if (is_null == NULL) {
                    alloc_failed = 1;
                    free(buffer);
                    free(length);
                    break;
                }

                // Добавляем поле error для детекции усечения
                bool* error = malloc(sizeof(bool));
                if (error == NULL) {
                    alloc_failed = 1;
                    free(buffer);
                    free(length);
                    free(is_null);
                    break;
                }

                *length = 0;
                *is_null = 0;
                *error = 0;  // Инициализируем флаг ошибки

                bind_result[col].buffer_type = MYSQL_TYPE_STRING;
                bind_result[col].buffer = buffer;
                bind_result[col].buffer_length = buffer_length;
                bind_result[col].length = length;
                bind_result[col].is_null = is_null;
                bind_result[col].error = error;  // Устанавливаем указатель на флаг ошибки
            }

            mysql_free_result(res);

            if (alloc_failed) {
                // Освобождаем ВСЕ уже выделенные буферы перед выходом
                CLEANUP_BIND_RESULT();
                result->ok = 0;
                return result;
            }

            // Привязываем буферы к результатам
            if (mysql_stmt_bind_result(stmt, bind_result)) {
                log_error("__process_prepared_result: mysql_stmt_bind_result failed: %s\n", mysql_stmt_error(stmt));
                CLEANUP_BIND_RESULT();
                result->ok = 0;
                return result;
            }

            // Получаем строки
            int row = 0;
            int fetch_status;
            while ((fetch_status = mysql_stmt_fetch(stmt)) == 0) {
                for (int col = 0; col < cols; col++) {
                    // ИСПРАВЛЕНИЕ: Используем указатель вместо копии структуры
                    // Это избегает ненужного копирования и потенциальных race conditions
                    MYSQL_BIND* bind = &bind_result[col];

                    if (*bind->is_null) {
                        dbresult_query_value_insert(query, NULL, 0, row, col);
                    } else {
                        // ИСПРАВЛЕНИЕ: Улучшена логика проверки buffer overread
                        // Всегда используем минимум из двух значений для безопасности
                        unsigned long safe_length;

                        if (*bind->error) {
                            // Данные были усечены
                            log_error("Data truncated in column %d at row %d. Buffer size: %lu, Actual data length: %lu\n",
                                    col, row, bind->buffer_length, *bind->length);
                            result->ok = 0;

                            // При усечении: берем меньшее значение, но не больше buffer_length
                            safe_length = (*bind->length < bind->buffer_length)
                                ? *bind->length
                                : bind->buffer_length;
                        } else {
                            // Нет усечения, но проверяем на переполнение буфера
                            // *bind->length должно быть <= buffer_length, но проверяем для безопасности
                            if (*bind->length > bind->buffer_length) {
                                log_error("Buffer overread detected in column %d at row %d: length %lu > buffer_length %lu\n",
                                        col, row, *bind->length, bind->buffer_length);
                                safe_length = bind->buffer_length;
                                result->ok = 0;
                            } else {
                                safe_length = *bind->length;
                            }
                        }

                        // Дополнительная проверка: исключаем null-терминатор из длины
                        if (safe_length > 0 && bind->buffer_type == MYSQL_TYPE_STRING) {
                            safe_length = (safe_length > bind->buffer_length) ? bind->buffer_length : safe_length;
                        }

                        dbresult_query_value_insert(query, bind->buffer, safe_length, row, col);
                    }
                }
                row++;
            }

            // Проверяем результат fetch
            if (fetch_status != MYSQL_NO_DATA) {
                log_error("__process_prepared_result: mysql_stmt_fetch error: %s\n", mysql_stmt_error(stmt));
                result->ok = 0;
            }

            // Освобождаем буферы ПОСЛЕ обработки всех строк
            CLEANUP_BIND_RESULT();
            mysql_stmt_free_result(stmt);
        }
        else if (mysql_stmt_field_count(stmt) != 0) {
            log_error("__process_prepared_result: error getting result: %s\n", mysql_stmt_error(stmt));
            result->ok = 0;
            break;
        }

        // Пытаемся получить следующий результат на уровне соединения
        int status = mysql_stmt_next_result(stmt);
        if (status > 0) {
            log_error("__process_prepared_result: mysql_stmt_next_result error: %s\n", mysql_stmt_error(stmt));
            result->ok = 0;
        } else if (status < 0) {
            // status == -1 означает нет больше результатов
            break;
        }
        // status == 0 означает есть еще результаты

    } while (1);

    return result;
}

MYSQL* __connect(void* arg) {
    myhost_t* host = arg;

    MYSQL* connection = mysql_init(NULL);
    if (connection == NULL) return NULL;

    connection = mysql_real_connect(
        connection,
        host->base.ip,
        host->user,
        host->password,
        host->dbname,
        host->base.port,
        NULL,
        CLIENT_MULTI_STATEMENTS
    );

    return connection;
}

int __is_active(void* connection) {
    myconnection_t* conn = connection;
    if (conn == NULL) return 0;

    return mysql_ping(conn->connection) == 0;
}

int __reconnect(void* host, void* connection) {
    myconnection_t* conn = connection;

    if (__is_active(conn)) {
        mysql_close(conn->connection);

        conn->connection = __connect(host);

        if (!__is_active(conn)) {
            mysql_close(conn->connection);
            conn->connection = NULL;
            return 0;
        }
    }

    return 1;
}

str_t* __escape_identifier(void* connection, const char* str) {
    return __escape_internal(connection, str, '`');
}

str_t* __escape_string(void* connection, const char* str) {
    return __escape_internal(connection, str, '\'');
}

str_t* __escape_internal(void* connection, const char* str, char quote) {
    myconnection_t* conn = connection;

    const size_t str_len = strlen(str);

    char* escaped = malloc(str_len * 2 + 1);
    if (escaped == NULL) return NULL;

    unsigned long len = mysql_real_escape_string(conn->connection, escaped, str, str_len);
    if (len == (unsigned long)-1) {
        free(escaped);
        return NULL;
    }

    str_t* string = str_create_empty(256);
    if (string == NULL) {
        free(escaped);
        return NULL;
    }

    str_appendc(string, quote);
    str_append(string, escaped, len);
    str_appendc(string, quote);

    free(escaped);

    return string;
}

db_t* my_load(const char* database_id, const json_token_t* token_array) {
    db_t* result = NULL;
    db_t* database = db_create(database_id);
    if (database == NULL) {
        log_error("my_load: can't create database\n");
        return NULL;
    }

    enum fields { HOST_ID = 0, PORT, IP, DBNAME, USER, PASSWORD, MIGRATION, FIELDS_COUNT };
    enum required_fields { R_HOST_ID = 0, R_PORT, R_IP, R_DBNAME, R_USER, R_PASSWORD, R_FIELDS_COUNT };
    char* field_names[FIELDS_COUNT] = {"host_id", "port", "ip", "dbname", "user", "password"};

    for (json_it_t it_array = json_init_it(token_array); !json_end_it(&it_array); json_next_it(&it_array)) {
        json_token_t* token_object = json_it_value(&it_array);
        int lresult = 0;
        int finded_fields[FIELDS_COUNT] = {0};
        myhost_t* host = __host_create();
        if (host == NULL) {
            log_error("my_load: can't create host\n");
            goto failed;
        }

        for (json_it_t it_object = json_init_it(token_object); !json_end_it(&it_object); json_next_it(&it_object)) {
            const char* key = json_it_key(&it_object);
            json_token_t* token_value = json_it_value(&it_object);

            if (strcmp(key, "host_id") == 0) {
                if (finded_fields[HOST_ID]) {
                    log_error("my_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("my_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[HOST_ID] = 1;

                if (host->base.id != NULL) free(host->base.id);

                host->base.id = malloc(json_string_size(token_value) + 1);
                if (host->base.id == NULL) {
                    log_error("my_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->base.id, json_string(token_value));
            }
            else if (strcmp(key, "port") == 0) {
                if (finded_fields[PORT]) {
                    log_error("my_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_number(token_value)) {
                    log_error("my_load: field %s must be int\n", key);
                    goto host_failed;
                }

                finded_fields[PORT] = 1;

                int ok = 0;
                host->base.port = json_int(token_value, &ok);
                if (!ok) {
                    log_error("my_load: field %s must be int\n", key);
                    goto host_failed;
                }
            }
            else if (strcmp(key, "ip") == 0) {
                if (finded_fields[IP]) {
                    log_error("my_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("my_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[IP] = 1;

                if (host->base.ip != NULL) free(host->base.ip);

                host->base.ip = malloc(json_string_size(token_value) + 1);
                if (host->base.ip == NULL) {
                    log_error("my_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->base.ip, json_string(token_value));
            }
            else if (strcmp(key, "dbname") == 0) {
                if (finded_fields[DBNAME]) {
                    log_error("my_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("my_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[DBNAME] = 1;

                if (host->dbname != NULL) free(host->dbname);

                host->dbname = malloc(json_string_size(token_value) + 1);
                if (host->dbname == NULL) {
                    log_error("my_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->dbname, json_string(token_value));
            }
            else if (strcmp(key, "user") == 0) {
                if (finded_fields[USER]) {
                    log_error("my_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("my_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[USER] = 1;

                if (host->user != NULL) free(host->user);

                host->user = malloc(json_string_size(token_value) + 1);
                if (host->user == NULL) {
                    log_error("my_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->user, json_string(token_value));
            }
            else if (strcmp(key, "password") == 0) {
                if (finded_fields[PASSWORD]) {
                    log_error("my_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("my_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[PASSWORD] = 1;

                if (host->password != NULL) free(host->password);

                host->password = malloc(json_string_size(token_value) + 1);
                if (host->password == NULL) {
                    log_error("my_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->password, json_string(token_value));
            }
            else {
                log_error("my_load: unknown field: %s\n", key);
                goto host_failed;
            }
        }

        array_push_back(database->hosts, array_create_pointer(host, array_nocopy, host->base.free));

        for (int i = 0; i < R_FIELDS_COUNT; i++) {
            if (finded_fields[i] == 0) {
                log_error("my_load: required field %s not found\n", field_names[i]);
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

int __build_query_processor(void* connection, char parameter_type, const char* param_name, mfield_t* field, str_t* result_sql, void* user_data) {
    my_sql_processor_data_t* data = user_data;
    array_t* param_order = data->param_order;

    if (parameter_type == '@') {
        str_t* field_value = model_field_to_string(field);
        if (field_value == NULL) return 0;

        if (!process_value(connection, parameter_type, result_sql, field_value)) {
            log_error("__build_query_processor: process_value failed\n");
            return 0;
        }
    }
    else if (parameter_type == ':') {
        // Replace :param with ?
        str_appendc(result_sql, '?');
        array_push_back_str(param_order, param_name);
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
    my_sql_processor_data_t processor_data = {
        .param_order = param_order,
    };

    return parse_sql_parameters(connection, query, query_size, params, __build_query_processor, &processor_data);
}

void __prepared_stmt_free(void* data) {
    if (data == NULL) return;

    mysql_prepared_stmt_t* stmt_data = data;

    if (stmt_data->stmt != NULL)
        mysql_stmt_close(stmt_data->stmt);

    if (stmt_data->param_order != NULL)
        array_free(stmt_data->param_order);

    if (stmt_data->write_binds != NULL)
        free(stmt_data->write_binds);

    if (stmt_data->null_indicators != NULL)
        free(stmt_data->null_indicators);

    free(stmt_data);
}

int __prepare(void* connection, str_t* stmt_name, str_t* sql, array_t* params) {
    myconnection_t* myconnection = connection;

    // Массив с упорядоченными параметрами
    array_t* param_order = array_create();
    if (param_order == NULL)
        return 0;

    // Обрабатываем SQL-строку (заменяем :param на ?)
    str_t* processed_sql = __build_query(connection, sql, params, param_order);
    if (processed_sql == NULL) {
        array_free(param_order);
        return 0;
    }

    // Инициализируем prepared statement
    MYSQL_STMT* stmt = mysql_stmt_init(myconnection->connection);
    if (stmt == NULL) {
        log_error("mysql_stmt_init failed: out of memory\n");
        str_free(processed_sql);
        array_free(param_order);
        return 0;
    }

    // Подготавливаем statement
    if (mysql_stmt_prepare(stmt, str_get(processed_sql), str_size(processed_sql))) {
        log_error("mysql_stmt_prepare error: %s\nSQL: %s\n", mysql_stmt_error(stmt), str_get(processed_sql));
        str_free(processed_sql);
        array_free(param_order);
        mysql_stmt_close(stmt);
        return 0;
    }

    str_free(processed_sql);

    // Создаём структуру для хранения statement
    mysql_prepared_stmt_t* stmt_data = malloc(sizeof * stmt_data);
    if (stmt_data == NULL) {
        log_error("__prepare: memory allocation failed for stmt_data\n");
        array_free(param_order);
        mysql_stmt_close(stmt);
        return 0;
    }

    stmt_data->stmt = stmt;
    stmt_data->param_order = param_order;

    // Предвыделяем write_binds и lengths для переиспользования в execute_prepared
    const int n_params = array_size(param_order);
    if (n_params > 0) {
        stmt_data->write_binds = calloc(n_params, sizeof(MYSQL_BIND));
        if (stmt_data->write_binds == NULL) {
            log_error("__prepare: memory allocation failed for write_binds\n");
            array_free(param_order);
            mysql_stmt_close(stmt);
            free(stmt_data);
            return 0;
        }

        stmt_data->null_indicators = calloc(n_params, sizeof(bool));
        if (stmt_data->null_indicators == NULL) {
            log_error("__prepare: memory allocation failed for null_indicators\n");
            array_free(param_order);
            mysql_stmt_close(stmt);
            free(stmt_data->write_binds);
            free(stmt_data);
            return 0;
        }

        // Инициализируем структуры MYSQL_BIND один раз
        for (int i = 0; i < n_params; i++) {
            int finded = 0;
            const char* param_name = array_get(param_order, i);
            if (param_name == NULL) {
                log_error("__prepare: param_name is NULL at index %d\n", i);
                array_free(param_order);
                mysql_stmt_close(stmt);
                free(stmt_data->write_binds);
                free(stmt_data->null_indicators);
                free(stmt_data);
                return 0;
            }

            for (size_t j = 0; j < array_size(params); j++) {
                mfield_t* field = array_get(params, j);
                if (field == NULL || field->name == NULL)
                    continue;

                if (strcmp(param_name, field->name) == 0) {
                    stmt_data->write_binds[i].buffer_type = __convert_model_type_to_mysql(field->type);
                    finded = 1;
                    break;
                }
            }

            if (!finded) {
                log_error("__prepare: param %s not found in params\n", param_name);
                array_free(param_order);
                mysql_stmt_close(stmt);
                free(stmt_data->write_binds);
                free(stmt_data->null_indicators);
                free(stmt_data);
                return 0;
            }
        }
    } else {
        stmt_data->write_binds = NULL;
        stmt_data->null_indicators = NULL;
    }

    // Сохраняем statement с функцией освобождения
    const int r = map_insert_or_assign(myconnection->base.prepare_statements, str_get(stmt_name), stmt_data);
    if (r == -1) {
        __prepared_stmt_free(stmt_data);
        return 0;
    }

    return 1;
}

dbresult_t* __execute_prepared(void* connection, const char* stmt_name, array_t* params) {
    myconnection_t* myconnection = connection;

    dbresult_t* result = dbresult_create();
    if (result == NULL) return NULL;

    // Получаем подготовленный statement
    mysql_prepared_stmt_t* stmt_data = map_find(myconnection->base.prepare_statements, stmt_name);
    if (stmt_data == NULL) {
        log_error("__execute_prepared: prepared statement %s not found\n", stmt_name);
        return result;
    }

    array_t* param_order = stmt_data->param_order;
    MYSQL_STMT* stmt = stmt_data->stmt;
    MYSQL_BIND* write_binds = stmt_data->write_binds;
    bool* null_indicators = stmt_data->null_indicators;

    const int n_params = array_size(param_order);

    // Инициализируем массив null_indicators перед выполнением
    if (null_indicators != NULL)
        for (int i = 0; i < n_params; i++)
            null_indicators[i] = false;

    // Заполняем параметры (привязка выполнена в __prepare)
    if (n_params > 0) {
        for (int i = 0; i < n_params; i++) {
            int finded = 0;
            const char* param_name = array_get_string(param_order, i);
            if (param_name == NULL) {
                log_error("__execute_prepared: param_order_str is NULL\n");
                return result;
            }

            // Ищем параметр в массиве params
            for (size_t j = 0; j < array_size(params); j++) {
                mfield_t* field = array_get(params, j);

                // Проверка на NULL для field и field->name
                if (field != NULL && field->name != NULL && strcmp(param_name, field->name) == 0) {
                    if (!__bind_field_value(&write_binds[i], field, &null_indicators[i])) {
                        log_error("__execute_prepared: failed to bind field %s\n", param_name);
                        return result;
                    }

                    finded = 1;
                    break;
                }
            }

            if (!finded) {
                log_error("__execute_prepared: param %s not found in params array\n", param_name);
                return result;
            }
        }

        if (mysql_stmt_bind_param(stmt, stmt_data->write_binds)) {
            log_error("__prepare: mysql_stmt_bind_param failed: %s\n", mysql_stmt_error(stmt));
            return result;
        }
    }

    // Выполняем statement
    if (mysql_stmt_execute(stmt)) {
        log_error("__execute_prepared: mysql_stmt_execute failed: %s\n", mysql_stmt_error(stmt));
        return result;
    }

    return __process_prepared_result(myconnection, stmt, result);
}

int __deallocate(void* connection, str_t* stmt_name) {
    myconnection_t* myconnection = connection;

    // Удаляем из map - функция __prepared_stmt_free будет вызвана автоматически
    // и освободит stmt и param_order
    const int result = map_erase(myconnection->base.prepare_statements, str_get(stmt_name));
    if (result == 0)
        return 0;

    return 1;
}

char* __compile_insert(void* connection, const char* table, array_t* params) {
    if (connection == NULL) return NULL;
    if (table == NULL) return NULL;
    if (params == NULL) return NULL;
    if (array_size(params) == 0) return NULL;

    char* buffer = NULL;

    str_t* fields = str_create_empty(256);
    if (fields == NULL) return NULL;

    str_t* values = str_create_empty(256);
    if (values == NULL) goto failed;

    for (size_t i = 0; i < array_size(params); i++) {
        mfield_t* field = array_get(params, i);

        if (i > 0) {
            str_appendc(fields, ',');
            str_appendc(values, ',');
        }

        str_append(fields, field->name, strlen(field->name));

        str_t* value = model_field_to_string(field);
        if (value == NULL) goto failed;

        str_t* quoted_str = __escape_string(connection, str_get(value));
        if (quoted_str == NULL) goto failed;

        str_append(values, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    const char* format = "INSERT INTO %s (%s) VALUES (%s)";
    const size_t buffer_size = strlen(format) + strlen(table) + str_size(fields) + str_size(values) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL) goto failed;

    snprintf(buffer, buffer_size,
        format,
        table,
        str_get(fields),
        str_get(values)
    );

    failed:

    str_free(fields);
    str_free(values);

    return buffer;
}

char* __compile_select(void* connection, const char* table, array_t* columns, array_t* where) {
    if (connection == NULL) return 0;
    if (table == NULL) return 0;

    char* buffer = NULL;

    str_t* columns_str = str_create_empty(256);
    if (columns_str == NULL) return 0;

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL) goto failed;

    for (size_t i = 0; i < array_size(columns); i++) {
        const char* column_name = array_get(columns, i);

        if (i > 0)
            str_appendc(columns_str, ',');

        str_append(columns_str, column_name, strlen(column_name));
    }

    for (size_t i = 0; i < array_size(where); i++) {
        mfield_t* field = array_get(where, i);

        if (i > 0)
            str_append(where_str, " AND ", 5);

        str_append(where_str, field->name, strlen(field->name));
        str_appendc(where_str, '=');

        str_t* value = model_field_to_string(field);
        if (value == NULL) goto failed;

        str_t* quoted_str = __escape_string(connection, str_get(value));
        if (quoted_str == NULL) goto failed;

        str_append(where_str, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    const char* format = "SELECT %s FROM %s WHERE %s";
    const size_t buffer_size = strlen(format) + strlen(table) + str_size(columns_str) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL) goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(columns_str),
        table,
        str_get(where_str)
    );

    failed:

    str_free(columns_str);
    str_free(where_str);

    return buffer;
}

char* __compile_update(void* connection, const char* table, array_t* set, array_t* where) {
    if (connection == NULL) return 0;
    if (table == NULL) return 0;
    if (set == NULL) return 0;

    char* buffer = NULL;

    str_t* set_str = str_create_empty(256);
    if (set_str == NULL) return 0;

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL) goto failed;

    if (where == NULL || array_size(where) == 0)
        str_append(where_str, "true", 4);

    for (size_t i = 0; i < array_size(set); i++) {
        mfield_t* field = array_get(set, i);

        if (i > 0)
            str_appendc(set_str, ',');

        str_append(set_str, field->name, strlen(field->name));
        str_appendc(set_str, '=');

        str_t* value = model_field_to_string(field);
        if (value == NULL) goto failed;

        str_t* quoted_str = __escape_string(connection, str_get(value));
        if (quoted_str == NULL) goto failed;

        str_append(set_str, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    for (size_t i = 0; i < array_size(where); i++) {
        mfield_t* field = array_get(where, i);

        if (i > 0)
            str_append(where_str, " AND ", 5);

        str_append(where_str, field->name, strlen(field->name));
        str_appendc(where_str, '=');

        str_t* value = model_field_to_string(field);
        if (value == NULL) goto failed;

        str_t* quoted_str = __escape_string(connection, str_get(value));
        if (quoted_str == NULL) goto failed;

        str_append(where_str, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    const char* format = "UPDATE %s SET %s WHERE %s";
    const size_t buffer_size = strlen(format) + strlen(table) + str_size(set_str) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL) goto failed;

    snprintf(buffer, buffer_size,
        format,
        table,
        str_get(set_str),
        str_get(where_str)
    );

    failed:

    str_free(set_str);
    str_free(where_str);

    return buffer;
}

char* __compile_delete(void* connection, const char* table, array_t* where) {
    if (connection == NULL) return 0;
    if (table == NULL) return 0;

    char* buffer = NULL;

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL) goto failed;

    if (where == NULL || array_size(where) == 0)
        str_append(where_str, "true", 4);

    for (size_t i = 0; i < array_size(where); i++) {
        mfield_t* field = array_get(where, i);

        if (i > 0)
            str_append(where_str, " AND ", 5);

        str_append(where_str, field->name, strlen(field->name));
        str_appendc(where_str, '=');

        str_t* value = model_field_to_string(field);
        if (value == NULL) goto failed;

        str_t* quoted_str = __escape_string(connection, str_get(value));
        if (quoted_str == NULL) goto failed;

        str_append(where_str, str_get(quoted_str), str_size(quoted_str));
        str_free(quoted_str);
    }

    const char* format = "DELETE FROM %s WHERE %s";
    const size_t buffer_size = strlen(format) + strlen(table) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL) goto failed;

    snprintf(buffer, buffer_size,
        format,
        table,
        str_get(where_str)
    );

    failed:

    str_free(where_str);

    return buffer;
}

enum_field_types __convert_model_type_to_mysql(mtype_e model_type) {
    switch (model_type) {
        // Логические и целые типы
        case MODEL_BOOL:
            return MYSQL_TYPE_TINY;        // TINYINT
        case MODEL_SMALLINT:
            return MYSQL_TYPE_SHORT;       // SMALLINT
        case MODEL_INT:
            return MYSQL_TYPE_LONG;        // INT
        case MODEL_BIGINT:
            return MYSQL_TYPE_LONGLONG;    // BIGINT

        // Вещественные типы
        case MODEL_FLOAT:
            return MYSQL_TYPE_FLOAT;       // FLOAT
        case MODEL_DOUBLE:
            return MYSQL_TYPE_DOUBLE;      // DOUBLE
        case MODEL_DECIMAL:
            return MYSQL_TYPE_NEWDECIMAL;  // DECIMAL
        case MODEL_MONEY:
            return MYSQL_TYPE_NEWDECIMAL;  // DECIMAL

        // Типы даты и времени
        case MODEL_DATE:
            return MYSQL_TYPE_DATE;        // DATE
        case MODEL_TIME:
            return MYSQL_TYPE_TIME;        // TIME
        case MODEL_TIMETZ:
            return MYSQL_TYPE_TIME;        // TIME (без поддержки часового пояса в MySQL)
        case MODEL_TIMESTAMP:
            return MYSQL_TYPE_TIMESTAMP;   // TIMESTAMP
        case MODEL_TIMESTAMPTZ:
            return MYSQL_TYPE_DATETIME;    // DATETIME (без поддержки часового пояса)

        // Типы данных JSON
        case MODEL_JSON:
            return MYSQL_TYPE_JSON;        // JSON

        // Строковые типы
        case MODEL_BINARY:
            return MYSQL_TYPE_BLOB;        // BLOB (для бинарных данных)
        case MODEL_VARCHAR:
            return MYSQL_TYPE_VARCHAR;     // VARCHAR
        case MODEL_CHAR:
            return MYSQL_TYPE_STRING;      // CHAR
        case MODEL_TEXT:
            return MYSQL_TYPE_STRING;      // LONGBLOB/TEXT
        case MODEL_ENUM:
            return MYSQL_TYPE_STRING;      // VARCHAR (enum хранится как строка)
        case MODEL_ARRAY:
            return MYSQL_TYPE_JSON;        // JSON (массив как JSON)

        default:
            return MYSQL_TYPE_STRING;      // Значение по умолчанию
    }
}

int __bind_field_value(MYSQL_BIND* bind, mfield_t* field, bool* is_null_indicator) {
    if (bind == NULL || field == NULL || is_null_indicator == NULL) return 0;

    // Инициализируем NULL индикатор для этого параметра
    *is_null_indicator = false;

    switch (field->type) {
        case MODEL_BOOL:
        case MODEL_SMALLINT: {
            bind->buffer = &field->value._short;
            bind->buffer_length = sizeof(short);
            break;
        }
        case MODEL_INT: {
            bind->buffer = &field->value._int;
            bind->buffer_length = sizeof(int);
            break;
        }
        case MODEL_BIGINT: {
            bind->buffer = &field->value._bigint;
            bind->buffer_length = sizeof(long long);
            break;
        }
        case MODEL_FLOAT: {
            bind->buffer = &field->value._float;
            bind->buffer_length = sizeof(float);
            break;
        }
        case MODEL_DOUBLE:
        case MODEL_MONEY: {
            bind->buffer = &field->value._double;
            bind->buffer_length = sizeof(double);
            break;
        }
        case MODEL_DECIMAL: {
            bind->buffer = &field->value._ldouble;
            bind->buffer_length = sizeof(long double);
            break;
        }
        case MODEL_DATE:
        case MODEL_TIME:
        case MODEL_TIMETZ:
        case MODEL_TIMESTAMP:
        case MODEL_TIMESTAMPTZ: {
            // Преобразуем дату/время в строку
            str_t* str_value = model_field_to_string(field);
            if (str_value == NULL) {
                bind->buffer = NULL;
                bind->buffer_length = 0;
                bind->is_null = is_null_indicator;
                *is_null_indicator = true;
            } else {
                char* str = str_get(str_value);
                // Дополнительная проверка на NULL после str_get
                if (str == NULL) {
                    bind->buffer = NULL;
                    bind->buffer_length = 0;
                    bind->is_null = is_null_indicator;
                    *is_null_indicator = true;
                } else {
                    const size_t len = str_size(str_value);
                    bind->buffer = str;
                    bind->buffer_length = len;
                    bind->is_null = is_null_indicator;
                }
                // Примечание: str_value должна оставаться в памяти во время выполнения запроса
                // В этом случае нужно управлять жизненным циклом отдельно
            }
            break;
        }
        case MODEL_JSON:
        case MODEL_ARRAY: {
            // JSON и ARRAY преобразуем в строку
            str_t* str_value = model_field_to_string(field);
            if (str_value == NULL) {
                bind->buffer = NULL;
                bind->buffer_length = 0;
                bind->is_null = is_null_indicator;
                *is_null_indicator = true;
            } else {
                char* str = str_get(str_value);
                // Дополнительная проверка на NULL после str_get
                if (str == NULL) {
                    bind->buffer = NULL;
                    bind->buffer_length = 0;
                    bind->is_null = is_null_indicator;
                    *is_null_indicator = true;
                } else {
                    const size_t len = str_size(str_value);
                    bind->buffer = str;
                    bind->buffer_length = len;
                    bind->is_null = is_null_indicator;
                }
            }
            break;
        }
        case MODEL_BINARY:
        case MODEL_VARCHAR:
        case MODEL_CHAR:
        case MODEL_TEXT:
        case MODEL_ENUM: {
            // Строковые типы
            // Проверка на NULL для field->value._string перед использованием
            if (field->value._string == NULL) {
                bind->buffer = NULL;
                bind->buffer_length = 0;
                bind->is_null = is_null_indicator;
                *is_null_indicator = true;
            } else {
                char* str = str_get(field->value._string);
                if (str != NULL) {
                    const size_t len = str_size(field->value._string);
                    bind->buffer = str;
                    bind->buffer_length = len;
                    bind->is_null = is_null_indicator;
                } else {
                    bind->buffer = NULL;
                    bind->buffer_length = 0;
                    bind->is_null = is_null_indicator;
                    *is_null_indicator = true;
                }
            }
            break;
        }
        default: {
            log_error("__bind_field_value: unknown field type: %d\n", field->type);
            return 0;
        }
    }

    return 1;
}

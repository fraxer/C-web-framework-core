#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>

#include "appconfig.h"
#include "str.h"
#include "log.h"
#include "dbquery.h"
#include "model.h"
#include "dbresult.h"
#include "statement_registry.h"

/**
 * SQL parser state for tracking strings, comments, and context
 */
typedef struct {
    int in_string;          // 1 if inside a string literal
    char quote_char;        // The quote character (' or ") that started the string
    int in_line_comment;    // 1 if inside a line comment (--)
    int in_block_comment;   // 1 if inside a block comment (/* */)
} sql_parse_state_t;

static int __update_sql_parse_state(const char* query, size_t query_size, size_t* i, sql_parse_state_t* state);

static dbhost_t* __get_host(const char* identificator);
static str_t* __build_query(dbconnection_t* connection, const char* query, array_t* params);

/**
 * Update SQL parser state based on the current character
 * This function processes string literals and SQL comments (line and block)
 * to ensure parameters are not parsed inside these contexts.
 *
 * param query The SQL query string
 * param query_size The size of the query
 * param i Current position in the query (will be incremented by this function if needed)
 * param state The parser state to update
 * return 1 if the caller should continue to next iteration, 0 otherwise
 *
 * Security note: This function safely handles backslash-escaped quotes and doubled quotes
 */
int __update_sql_parse_state(const char* query, size_t query_size, size_t* i, sql_parse_state_t* state) {
    if (query == NULL || state == NULL || i == NULL) {
        return 0;
    }

    size_t pos = *i;
    if (pos >= query_size) {
        return 0;
    }

    // Handle string literals
    if (!state->in_line_comment && !state->in_block_comment) {
        if ((query[pos] == '\'' || query[pos] == '"') && (pos == 0 || query[pos-1] != '\\')) {
            if (!state->in_string) {
                state->in_string = 1;
                state->quote_char = query[pos];
            } else if (query[pos] == state->quote_char) {
                // Check for doubled quotes (SQL escaping)
                if (pos + 1 < query_size && query[pos + 1] == state->quote_char) {
                    (*i)++; // Skip second quote
                } else {
                    state->in_string = 0;
                }
            }
        }
    }

    // Handle comments (only if not in string)
    if (!state->in_string) {
        // Line comment start
        if (!state->in_block_comment && pos + 1 < query_size && query[pos] == '-' && query[pos+1] == '-') {
            state->in_line_comment = 1;
            (*i)++; // Skip second dash
            return 1;
        }

        // Line comment end
        if (state->in_line_comment && query[pos] == '\n') {
            state->in_line_comment = 0;
            return 1;
        }

        // Block comment start
        if (!state->in_line_comment && pos + 1 < query_size && query[pos] == '/' && query[pos+1] == '*') {
            state->in_block_comment = 1;
            (*i)++; // Skip asterisk
            return 1;
        }

        // Block comment end
        if (state->in_block_comment && pos > 0 && query[pos-1] == '*' && query[pos] == '/') {
            state->in_block_comment = 0;
            return 1;
        }
    }

    return 0;
}

dbinstance_t* dbinstance(const char* identificator) {
    dbhost_t* host = __get_host(identificator);
    if (host == NULL) {
        log_error("db host not found\n");
        return NULL;
    }

    dbinstance_t* inst = malloc(sizeof * inst);
    if (inst == NULL) return NULL;

    host_connections_lock(host);
    dbconnection_t* connection = db_connection_find(host->connections);
    host_connections_unlock(host);

    int result = 0;
    if (connection == NULL) {
        connection = host->connection_create(host);

        if (connection == NULL) {
            log_error("db connection not found\n");
            goto exit;
        }

        host_connections_lock(host);
        array_push_back(host->connections, array_create_pointer(connection, array_nocopy, connection->free));
        host_connections_unlock(host);
    }

    if (!connection->is_active(connection)) {
        if (!connection->reconnect(host, connection)) {
            log_error("db reconnect error\n");
            goto exit;
        }
    }

    inst->grammar = &host->grammar;
    inst->connection = connection;

    result = 1;

    exit:

    if (result == 0) {
        dbinstance_free(inst);
        inst = NULL;
    }

    return inst;
}

void dbinstance_free(dbinstance_t* instance) {
    free(instance);
}

dbresult_t* dbqueryf(const char* dbid, const char* format, ...) {
    dbinstance_t* instance = dbinstance(dbid);
    if (instance == NULL) return NULL;

    va_list args;
    va_start(args, format);
    size_t string_length = vsnprintf(NULL, 0, format, args);
    va_end(args);

    char* string = malloc(string_length + 1);
    if (string == NULL) return NULL;

    va_start(args, format);
    vsnprintf(string, string_length + 1, format, args);
    va_end(args);

    dbconnection_t* connection = instance->connection;
    dbinstance_free(instance);

    dbresult_t* result = connection->query(connection, string);

    free(string);

    return result;
}

dbresult_t* dbquery(const char* dbid, const char* format, array_t* params) {
    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) return NULL;

    dbconnection_t* connection = dbinst->connection;
    dbinstance_free(dbinst);

    str_t* result_query = __build_query(connection, format, params);
    if (result_query == NULL) return NULL;

    dbresult_t* result = connection->query(connection, str_get(result_query));
    
    str_free(result_query);

    return result;
}

dbresult_t* dbprepared_query(const char* dbid, const char* stmt_name, array_t* params) {
    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) return NULL;

    dbconnection_t* connection = dbinst->connection;

    dbinstance_free(dbinst);

    if (connection->prepare_statements == NULL)
        return NULL;

    void* stmt = map_find(connection->prepare_statements, stmt_name);
    if (stmt == NULL) {
        array_t* prepared_queries = appconfig()->prepared_queries;
        for (size_t i = 0; i < array_size(prepared_queries); i++) {
            prepare_stmt_t* stmt = array_get(prepared_queries, i);
            if (str_cmpc(stmt->name, stmt_name) != 0) continue;

            if (!connection->prepare(connection, stmt->name, stmt->query, stmt->params))
                return NULL;

            break;
        }
    }

    return connection->execute_prepared(connection, stmt_name, params);
}

dbresult_t* dbtable_exist(const char* dbid, const char* table) {
    dbinstance_t* instance = dbinstance(dbid);
    if (instance == NULL) return NULL;

    dbconnection_t* connection = instance->connection;

    char* sql = instance->grammar->compile_table_exist(connection, table);
    dbinstance_free(instance);

    if (sql == NULL) return NULL;

    dbresult_t* result = connection->query(connection, sql);

    free(sql);

    return result;
}

dbresult_t* dbtable_migration_create(const char* dbid, const char* table) {
    dbinstance_t* instance = dbinstance(dbid);
    if (instance == NULL) return NULL;

    dbconnection_t* connection = instance->connection;

    char* sql = instance->grammar->compile_table_migration_create(connection, table);
    dbinstance_free(instance);

    if (sql == NULL) return NULL;

    dbresult_t* result = connection->query(connection, sql);

    free(sql);

    return result;
}

dbresult_t* dbbegin(const char* dbid, transaction_level_e level) {
    (void)level;
    return dbqueryf(dbid, "level");
}

dbresult_t* dbcommit(const char* dbid) {
    return dbqueryf(dbid, "commit");
}

dbresult_t* dbrollback(const char* dbid) {
    return dbqueryf(dbid, "rollback");
}

dbresult_t* dbinsert(const char* dbid, const char* table, array_t* params) {
    dbinstance_t* instance = dbinstance(dbid);
    if (instance == NULL) return NULL;

    dbconnection_t* connection = instance->connection;

    char* sql = instance->grammar->compile_insert(connection, table, params);
    dbinstance_free(instance);

    if (sql == NULL) return NULL;

    dbresult_t* result = connection->query(connection, sql);

    free(sql);

    return result;
}

dbresult_t* dbupdate(const char* dbid, const char* table, array_t* set, array_t* where) {
    dbinstance_t* instance = dbinstance(dbid);
    if (instance == NULL) return NULL;

    dbconnection_t* connection = instance->connection;

    char* sql = instance->grammar->compile_update(connection, table, set, where);
    dbinstance_free(instance);

    if (sql == NULL) return NULL;

    dbresult_t* result = connection->query(connection, sql);

    free(sql);

    return result;
}

dbresult_t* dbdelete(const char* dbid, const char* table, array_t* where) {
    dbinstance_t* instance = dbinstance(dbid);
    if (instance == NULL) return NULL;

    dbconnection_t* connection = instance->connection;

    char* sql = instance->grammar->compile_delete(connection, table, where);
    dbinstance_free(instance);

    if (sql == NULL) return NULL;

    dbresult_t* result = connection->query(connection, sql);

    free(sql);

    return result;
}

dbresult_t* dbselect(const char* dbid, const char* table, array_t* columns, array_t* where) {
    dbinstance_t* instance = dbinstance(dbid);
    if (instance == NULL) return NULL;

    dbconnection_t* connection = instance->connection;

    char* sql = instance->grammar->compile_select(connection, table, columns, where);
    dbinstance_free(instance);

    if (sql == NULL) return NULL;

    dbresult_t* result = connection->query(connection, sql);

    free(sql);

    return result;
}

int dbexec(const char* dbid, const char* format, array_t* params) {
    int res = 0;

    dbresult_t* result = dbquery(dbid, format, params);
    if (!dbresult_ok(result))
        goto failed;

    res = 1;

    failed:

    dbresult_free(result);

    return res;
}

int dbprepared_exec(const char* dbid, const char* stmt_name, array_t* params) {
    int res = 0;

    dbresult_t* result = dbprepared_query(dbid, stmt_name, params);
    if (!dbresult_ok(result))
        goto failed;

    res = 1;

    failed:

    dbresult_free(result);

    return res;
}

dbhost_t* __get_host(const char* identificator) {
    if (identificator == NULL) return NULL;

    const char* p = identificator;
    while (*p != '.' && *p != 0) p++;

    if (p - identificator == 0) return NULL;

    char* driver = strndup(identificator, p - identificator);
    if (driver == NULL) return NULL;

    const char* host_id = NULL;
    if (*p != 0 && strlen(p + 1) > 0)
        host_id = p + 1;

    dbhost_t* host = NULL;
    array_t* dbs = appconfig()->databases;
    for (size_t i = 0; i < array_size(dbs); i++) {
        db_t* db = array_get(dbs, i);
        if (strcmp(db->id, driver) == 0) {
            host = db_host_find(db, host_id);
            break;
        }
    }

    free(driver);

    return host;
}

/**
 * Common SQL parameter parsing function
 * Parses SQL string and calls processor callback for each found parameter
 * Handles string literals, comments, and parameter detection
 */
str_t* parse_sql_parameters(void* connection, const char* query, size_t query_size, array_t* params, sql_param_processor_t processor, void* user_data) {
    #define MAX_PARAM_NAME 256
    int param_start = -1;
    char param_name[MAX_PARAM_NAME] = {0};
    str_t* result_query = str_create_empty(512);
    if (result_query == NULL) return NULL;

    typedef struct {
        size_t position;
        size_t offset;
    } point_t;

    point_t point = {0, 0};

    // Track string literals and comments to skip parameter parsing inside them
    sql_parse_state_t parse_state = {0, 0, 0, 0};

    for (size_t i = 0; i < query_size; i++) {
        // Update parser state based on current character
        if (__update_sql_parse_state(query, query_size, &i, &parse_state)) {
            continue;
        }

        // Skip parameter processing inside strings and comments
        if (parse_state.in_string || parse_state.in_line_comment || parse_state.in_block_comment) {
            continue;
        }

        if (query[i] == ':' || query[i] == '@') {
            if (param_start != -1) {
                log_error("parse_sql_parameters: error param concats\n");
                goto failed;
            }

            param_start = i;
            point.offset = i;
            continue;
        }

        // Check parameter end
        const int string_end = i == query_size - 1;
        // Cast to unsigned char to safely handle non-ASCII bytes and avoid undefined behavior with ctype functions
        const int is_spec_symbol = ispunct_custom((unsigned char)query[i]) ||
                                   iscntrl((unsigned char)query[i]) ||
                                   isspace((unsigned char)query[i]);
        if (param_start != -1 && (is_spec_symbol || string_end)) {
            const size_t param_end = (string_end && !is_spec_symbol) ? i + 1 : i;
            const char parameter_type = query[param_start];

            size_t name_size = param_end - param_start - 1;
            if (name_size > 0 && name_size < MAX_PARAM_NAME) {
                // Safe copy with buffer size consideration
                size_t copy_size = (name_size < MAX_PARAM_NAME - 1) ? name_size : MAX_PARAM_NAME - 1;
                memcpy(param_name, query + param_start + 1, copy_size);
                param_name[copy_size] = 0;

                int param_finded = 0;
                int is_in = 0;
                const char* param_name_p = param_name;

                if (starts_with_substr(param_name, "list__")) {
                    param_name_p += 6;
                    is_in = 1;
                }

                for (size_t j = 0; j < array_size(params); j++) {
                    mfield_t* field = array_get(params, j);
                    if (field != NULL && strcmp(param_name_p, field->name) == 0) {
                        str_append(result_query, query + point.position, point.offset - point.position);

                        if (is_in) {
                            // Process list__ parameter
                            if (field->type != MODEL_ARRAY) {
                                log_error("__build_query_processor: param @list__ requires array type <%s>\n", param_name);
                                return 0;
                            }

                            array_t* array = model_array(field);
                            const size_t size = array_size(array);
                            if (size == 0) {
                                log_error("__build_query_processor: empty array for list__ <%s>\n", param_name);
                                return 0;
                            }

                            // Add array items separated by comma
                            for (size_t k = 0; k < size; k++) {
                                str_t* str = array_item_to_string(array, k);
                                if (str == NULL) return 0;

                                if (k > 0)
                                    str_appendc(result_query, ',');

                                if (!process_value(connection, parameter_type, result_query, str)) {
                                    log_error("__build_query_processor: process_value failed\n");
                                    str_free(str);
                                    return 0;
                                }

                                str_free(str);
                            }
                        } else {
                            // Call processor callback to handle the parameter
                            if (!processor(connection, parameter_type, param_name_p, field, result_query, user_data)) {
                                log_error("parse_sql_parameters: processor callback failed for param <%s>\n", param_name_p);
                                goto failed;
                            }
                        }

                        point.position = param_end;
                        point.offset = param_end;
                        param_finded = 1;
                        break;
                    }
                }

                if (!param_finded) {
                    log_error("parse_sql_parameters: param not found in params array <%s>\n", param_name_p);
                    goto failed;
                }
            }
            param_start = -1;
        }

        if (param_start == -1 && string_end)
            str_append(result_query, query + point.position, (i + 1) - point.position);
    }

    return result_query;

    failed:

    str_free(result_query);
    return NULL;
}

/**
 * Callback function for __build_query
 * Directly substitutes parameter values into SQL string
 * Handles both single values and array lists
 */
static int __build_query_processor(
    void* connection,
    char parameter_type,
    const char* param_name,
    mfield_t* field,
    str_t* result_sql,
    void* user_data
) {
    (void)param_name;  // Not used in this processor
    (void)user_data;  // Not used in this processor

    str_t* field_value = model_field_to_string(field);
    if (field_value == NULL) return 0;

    if (!process_value(connection, parameter_type, result_sql, field_value)) {
        log_error("__build_query_processor: process_value failed\n");
        return 0;
    }

    return 1;
}

str_t* __build_query(dbconnection_t* connection, const char* query, array_t* params) {
    const size_t query_size = strlen(query);
    void* processor_data = NULL;

    return parse_sql_parameters(connection, query, query_size, params, __build_query_processor, processor_data);
}


int starts_with_substr(const char* string, const char* substring) {
    if (string == NULL || substring == NULL)
        return 0;

    const size_t start_length = strlen(string);
    const size_t substring_length = strlen(substring);

    if (substring_length > start_length)
        return 0;

    for (size_t i = 0; i < substring_length; i++)
        if (string[i] != substring[i])
            return 0;

    return 1;
}

int process_value(dbconnection_t* connection, char parameter_type, str_t* string, str_t* value) {
    str_t* quoted_str = NULL;

    if (parameter_type == '@')
        quoted_str = connection->escape_identifier(connection, str_get(value));
    else
        quoted_str = connection->escape_string(connection, str_get(value));

    if (quoted_str == NULL) return 0;

    str_append(string, str_get(quoted_str), str_size(quoted_str));
    str_free(quoted_str);

    return 1;
}

int ispunct_custom(int c) {
    unsigned char uc = (unsigned char)c;

    if (uc >= 32 && uc <= 126) {
        if ((uc >= '0' && uc <= '9') ||
            (uc >= 'A' && uc <= 'Z') ||
            (uc >= 'a' && uc <= 'z') ||
            (uc == ' ')) {
            return 0;
        }

        if (uc == '_') return 0;

        return 1;
    }

    return 0;
}

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <sqlite3.h>

#include "log.h"
#include "array.h"
#include "str.h"
#include "model.h"
#include "dbresult.h"
#include "dbquery.h"
#include "sqlite.h"

static sqlitehost_t* __host_create(void);
static void __host_free(void* arg);
static void* __connection_create(void* host);
static void __connection_free(void* connection);
static sqlite3* __connect(void* host);
static void __exec_pragma(sqlite3* db, const char* sql);
static int __is_active(void* connection);
static int __reconnect(void* host, void* connection);
static dbresult_t* __query(void* connection, const char* sql);
static dbresult_t* __execute_params(void* connection, const char* sql, array_t* params);
static int __fill_result(sqlite3* db, sqlite3_stmt* stmt, dbresult_t* result);
static int __bind_field(sqlite3_stmt* stmt, int idx, mfield_t* field);
static dbresult_t* __begin(void* connection, transaction_level_e level);
static const char* __type_cast(int field_type);
static str_t* __escape_identifier(void* connection, const char* str);
static str_t* __escape_string(void* connection, const char* str);
static str_t* __compile_table_ref(dbconnection_t* conn, const char* table);
static char* __compile_table_exist(dbconnection_t* connection, const char* table);
static char* __compile_table_migration_create(dbconnection_t* connection, const char* table);
static char* __compile_insert(void* connection, const char* table, array_t* params);
static char* __compile_select(void* connection, const char* table, array_t* columns, array_t* where);
static char* __compile_update(void* connection, const char* table, array_t* set, array_t* where);
static char* __compile_delete(void* connection, const char* table, array_t* where);
static int __is_raw_sql(const char* str);


sqlitehost_t* __host_create(void) {
    sqlitehost_t* host = malloc(sizeof * host);
    if (host == NULL) return NULL;

    host->base.connections = array_create();
    if (host->base.connections == NULL) {
        free(host);
        return NULL;
    }

    host->base.free = __host_free;
    host->base.port = 0;          // not used (file-based)
    host->base.ip = NULL;
    host->base.id = NULL;
    host->base.connection_create = __connection_create;
    host->base.connections_locked = 0;
    host->base.grammar.compile_table_exist = __compile_table_exist;
    host->base.grammar.compile_table_migration_create = __compile_table_migration_create;
    host->base.grammar.compile_insert = __compile_insert;
    host->base.grammar.compile_select = __compile_select;
    host->base.grammar.compile_update = __compile_update;
    host->base.grammar.compile_delete = __compile_delete;
    host->path = NULL;
    host->journal_mode = NULL;
    host->busy_timeout = 0;

    return host;
}

void __host_free(void* arg) {
    if (arg == NULL) return;

    sqlitehost_t* host = arg;

    if (host->base.id) free(host->base.id);
    if (host->base.ip) free(host->base.ip);
    if (host->path) free(host->path);
    if (host->journal_mode) free(host->journal_mode);

    array_free(host->base.connections);
    free(host);
}

static const char* __type_cast(int field_type) {
    (void)field_type;
    // SQLite is dynamically typed — no cast suffix on positional placeholders.
    return "";
}

void* __connection_create(void* host) {
    sqliteconnection_t* connection = malloc(sizeof * connection);
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
    connection->base.begin = __begin;
    connection->base.type_cast = __type_cast;
    // INSERT ... RETURNING arrived in SQLite 3.35. Gate it at compile time
    // against the headers we're built with: on older builds the model layer
    // transparently falls back to the out-of-band insert_id
    // (sqlite3_last_insert_rowid), which the driver always sets, so both
    // branches are correct regardless of the runtime library version.
#if defined(SQLITE_VERSION_NUMBER) && SQLITE_VERSION_NUMBER >= 3035000
    connection->base.uses_returning = 1;
#else
    connection->base.uses_returning = 0;
#endif
    connection->base.host = host;
    connection->connection = __connect(host);

    if (!__is_active(connection)) {
        log_error("sqlite connection not created by host %s\n", ((sqlitehost_t*)host)->base.id);
        connection->base.free(connection);
        connection = NULL;
    }

    return connection;
}

void __connection_free(void* connection) {
    if (connection == NULL) return;

    sqliteconnection_t* conn = connection;

    if (conn->connection != NULL)
        sqlite3_close_v2(conn->connection);

    free(conn);
}

static void __exec_pragma(sqlite3* db, const char* sql) {
    char* err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        log_warning("sqlite pragma failed (%s): %s\n", sql, err ? err : "?");
        sqlite3_free(err);
    }
}

sqlite3* __connect(void* arg) {
    sqlitehost_t* host = arg;
    sqlite3* db = NULL;

    // SQLITE_OPEN_NOMUTEX is safe: the framework hands each worker thread its
    // own sqlite3* (per-thread pool via db_connection_find), so no handle is
    // shared across threads.
    if (sqlite3_open_v2(host->path, &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        log_error("sqlite connect: %s\n", db ? sqlite3_errmsg(db) : "can't allocate sqlite handle");
        if (db) sqlite3_close_v2(db);
        return NULL;
    }

    // Recommended for multi-threaded server use: bound write-lock waits, durable
    // journaling, and FK enforcement. These are no-ops on some stores (e.g.
    // journal_mode on ":memory:") and report via log_warning, never fatal.
    char pragma[128];
    snprintf(pragma, sizeof(pragma), "PRAGMA busy_timeout = %d", host->busy_timeout);
    __exec_pragma(db, pragma);

    if (host->journal_mode != NULL && host->journal_mode[0] != '\0') {
        char jm[160];
        snprintf(jm, sizeof(jm), "PRAGMA journal_mode = %s", host->journal_mode);
        __exec_pragma(db, jm);
    }

    __exec_pragma(db, "PRAGMA foreign_keys = ON");

    return db;
}

int __is_active(void* connection) {
    sqliteconnection_t* conn = connection;
    // SQLite is an in-process file store — the handle can't "drop" like a
    // network socket. A NULL check is sufficient; a gone/unopenable file
    // surfaces as an error result on the next query.
    return conn != NULL && conn->connection != NULL;
}

int __reconnect(void* host, void* connection) {
    sqliteconnection_t* conn = connection;

    if (!__is_active(conn)) {
        if (conn->connection != NULL)
            sqlite3_close_v2(conn->connection);

        conn->connection = __connect(host);

        return __is_active(conn);
    }

    return 1;
}

// Quote an identifier: "name", doubling any embedded double quotes. This is
// SQLite's standard identifier-quoting form (also accepted for string literals
// when single quotes aren't used, but we reserve it for identifiers).
str_t* __escape_identifier(void* connection, const char* str) {
    (void)connection;

    str_t* quoted = str_create_empty(256);
    if (quoted == NULL) return NULL;

    str_appendc(quoted, '"');
    for (const char* p = str; *p != '\0'; p++) {
        if (*p == '"')
            str_appendc(quoted, '"');
        str_appendc(quoted, *p);
    }
    str_appendc(quoted, '"');

    return quoted;
}

// Quote a string literal: 'text', doubling any embedded single quotes. SQLite
// treats backslash literally by default, so only the quote needs escaping.
str_t* __escape_string(void* connection, const char* str) {
    (void)connection;

    str_t* quoted = str_create_empty(256);
    if (quoted == NULL) return NULL;

    str_appendc(quoted, '\'');
    for (const char* p = str; *p != '\0'; p++) {
        if (*p == '\'')
            str_appendc(quoted, '\'');
        str_appendc(quoted, *p);
    }
    str_appendc(quoted, '\'');

    return quoted;
}

// Materialize a stepped statement into result->query. SQLite exposes rows
// through a forward-only cursor, so the row count is unknown until done — but
// dbresult_query_create preallocates a rows*cols matrix. We therefore buffer
// rows into a temporary array first, then build the matrix (values are copied
// by dbresult_query_value_insert, so the buffer is freed afterwards). Returns
// 1 on success, 0 on error (driver message stored on the result).
static int __fill_result(sqlite3* db, sqlite3_stmt* stmt, dbresult_t* result) {
    const int cols = sqlite3_column_count(stmt);
    if (cols <= 0) {
        // No result set (DDL / INSERT without RETURNING / UPDATE / DELETE): a
        // prepared statement only takes effect when stepped, so run it to
        // completion. Without this, CREATE TABLE would silently do nothing.
        int rc = sqlite3_step(stmt);
        while (rc == SQLITE_ROW)
            rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            dbresult_set_error(result, sqlite3_errmsg(db));
            return 0;
        }
        return 1;
    }

    int cap = 16;
    int n = 0;
    db_table_cell_t** rowptrs = malloc((size_t)cap * sizeof * rowptrs);
    if (rowptrs == NULL) {
        dbresult_set_error(result, sqlite3_errmsg(db));
        return 0;
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        db_table_cell_t* cells = calloc((size_t)cols, sizeof * cells);
        if (cells == NULL)
            goto failed;

        for (int c = 0; c < cols; c++) {
            // Read as text + length: like the postgresql/mysql drivers (which
            // surface every value as a string), this renders integers/reals in
            // their text form. column_bytes is then called on the same column,
            // as required, to get the length. NULL SQL values yield ptr=NULL.
            const void* ptr = sqlite3_column_text(stmt, c);
            int len = sqlite3_column_bytes(stmt, c);
            if (len < 0) len = 0;
            dbresult_cell_create(&cells[c], (const char*)ptr, (size_t)len);
        }

        if (n == cap) {
            cap *= 2;
            db_table_cell_t** tmp = realloc(rowptrs, (size_t)cap * sizeof * tmp);
            if (tmp == NULL) {
                for (int c = 0; c < cols; c++)
                    db_cell_free(&cells[c]);
                free(cells);
                goto failed;
            }
            rowptrs = tmp;
        }

        rowptrs[n++] = cells;
    }

    if (rc != SQLITE_DONE)
        goto failed;

    {
        dbresultquery_t* query = dbresult_query_create(n, cols);
        if (query == NULL)
            goto failed;

        for (int c = 0; c < cols; c++)
            dbresult_query_field_insert(query, sqlite3_column_name(stmt, c), c);

        for (int r = 0; r < n; r++) {
            db_table_cell_t* cells = rowptrs[r];
            for (int c = 0; c < cols; c++)
                dbresult_query_value_insert(query, cells[c].value, cells[c].length, r, c);
        }

        result->query = query;
        result->current = query;
    }

    for (int r = 0; r < n; r++) {
        db_table_cell_t* cells = rowptrs[r];
        for (int c = 0; c < cols; c++)
            db_cell_free(&cells[c]);
        free(cells);
    }
    free(rowptrs);
    return 1;

failed:
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        dbresult_set_error(result, sqlite3_errmsg(db));

    for (int r = 0; r < n; r++) {
        db_table_cell_t* cells = rowptrs[r];
        for (int c = 0; c < cols; c++)
            db_cell_free(&cells[c]);
        free(cells);
    }
    free(rowptrs);
    return 0;
}

// Bind one mfield_t at the 1-based positional index. `$1..$N` placeholders
// produced by the shared builder map directly to these indices; SQLite accepts
// that placeholder syntax natively (no MySQL-style rewrite). Returns SQLITE_OK
// on success.
static int __bind_field(sqlite3_stmt* stmt, int idx, mfield_t* field) {
    if (field == NULL || field->is_null)
        return sqlite3_bind_null(stmt, idx);

    switch ((mtype_e)field->type) {
        case MODEL_BOOL:
        case MODEL_SMALLINT:
            return sqlite3_bind_int(stmt, idx, field->value._short);

        case MODEL_INT:
            return sqlite3_bind_int(stmt, idx, field->value._int);

        case MODEL_BIGINT:
            return sqlite3_bind_int64(stmt, idx, field->value._bigint);

        case MODEL_FLOAT:
            return sqlite3_bind_double(stmt, idx, field->value._float);

        case MODEL_DOUBLE:
        case MODEL_MONEY:
            return sqlite3_bind_double(stmt, idx, field->value._double);

        case MODEL_VARCHAR:
        case MODEL_CHAR:
        case MODEL_TEXT:
        case MODEL_ENUM:
        case MODEL_BINARY:
            if (field->value._string == NULL)
                return sqlite3_bind_null(stmt, idx);
            return sqlite3_bind_text(stmt, idx, str_get(field->value._string),
                (int)str_size(field->value._string), SQLITE_TRANSIENT);

        // Types without a native numeric mapping: serialize and bind as text.
        // SQLITE_TRANSIENT makes SQLite copy the bytes, so the temp str_t can be
        // freed immediately afterwards.
        case MODEL_DECIMAL:
        case MODEL_DATE:
        case MODEL_TIME:
        case MODEL_TIMETZ:
        case MODEL_TIMESTAMP:
        case MODEL_TIMESTAMPTZ:
        case MODEL_JSON:
        case MODEL_ARRAY:
        default: {
            str_t* s = model_field_to_string(field);
            if (s == NULL)
                return sqlite3_bind_null(stmt, idx);
            int r = sqlite3_bind_text(stmt, idx, str_get(s), (int)str_size(s), SQLITE_TRANSIENT);
            str_free(s);
            return r;
        }
    }
}

dbresult_t* __query(void* connection, const char* sql) {
    sqliteconnection_t* conn = connection;

    log_debug("DB query: %s\n", sql);

    dbresult_t* result = dbresult_create();
    if (result == NULL) return NULL;

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(conn->connection, sql, -1, &stmt, NULL) != SQLITE_OK) {
        dbresult_set_error(result, sqlite3_errmsg(conn->connection));
        log_error("sqlite query prepare: %s\n", sqlite3_errmsg(conn->connection));
        return result;
    }

    if (__fill_result(conn->connection, stmt, result)) {
        result->insert_id = sqlite3_last_insert_rowid(conn->connection);
        result->ok = 1;
    }

    sqlite3_finalize(stmt);
    return result;
}

// Parameterized execution (universal named-parameter path). `sql` arrives from
// the shared builder with positional placeholders $1..$N; SQLite parses those
// natively, and we bind each mfield_t by index. SELECT / RETURNING rows are
// materialized via __fill_result; the last insert row id is reported for
// inserts.
dbresult_t* __execute_params(void* connection, const char* sql, array_t* params) {
    sqliteconnection_t* conn = connection;

    log_debug("DB params query: %s\n", sql);

    dbresult_t* result = dbresult_create();
    if (result == NULL) return NULL;

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(conn->connection, sql, -1, &stmt, NULL) != SQLITE_OK) {
        dbresult_set_error(result, sqlite3_errmsg(conn->connection));
        log_error("sqlite execute_params prepare: %s\n", sqlite3_errmsg(conn->connection));
        return result;
    }

    const int n_params = params != NULL ? (int)array_size(params) : 0;
    for (int i = 0; i < n_params; i++) {
        mfield_t* field = array_get(params, i);
        if (__bind_field(stmt, i + 1, field) != SQLITE_OK) {
            dbresult_set_error(result, sqlite3_errmsg(conn->connection));
            log_error("sqlite execute_params bind $%d failed: %s\n", i + 1, sqlite3_errmsg(conn->connection));
            sqlite3_finalize(stmt);
            return result;
        }
    }

    if (__fill_result(conn->connection, stmt, result)) {
        result->insert_id = sqlite3_last_insert_rowid(conn->connection);
        result->ok = 1;
    }

    sqlite3_finalize(stmt);
    return result;
}

dbresult_t* __begin(void* connection, transaction_level_e level) {
    // SQLite is effectively serializable; BEGIN IMMEDIATE acquires the write
    // lock up front (instead of on first write) to surface contention as a
    // bounded wait under busy_timeout rather than SQLITE_BUSY mid-statement.
    const char* sql = (level == SERIALIZABLE) ? "BEGIN IMMEDIATE" : "BEGIN";
    return __query(connection, sql);
}

static str_t* __compile_table_ref(dbconnection_t* conn, const char* table) {
    // SQLite has no schema-qualified refs in this driver; just quote the name.
    return conn->escape_identifier(conn, table);
}

char* __compile_table_exist(dbconnection_t* connection, const char* table) {
    str_t* quoted_table = connection->escape_string(connection, table);
    if (quoted_table == NULL)
        return NULL;

    char tmp[512] = {0};
    ssize_t written = snprintf(
        tmp,
        sizeof(tmp),
        "SELECT 1 FROM \"sqlite_master\" WHERE \"type\" = 'table' AND \"name\" = %s",
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
    str_t* table_ref = __compile_table_ref(connection, table);
    if (table_ref == NULL)
        return NULL;

    char tmp[512] = {0};
    ssize_t written = snprintf(
        tmp,
        sizeof(tmp),
        "CREATE TABLE IF NOT EXISTS %s ("
            "\"version\"    TEXT    NOT NULL PRIMARY KEY,"
            "\"apply_time\" INTEGER NOT NULL DEFAULT 0"
        ")",
        str_get(table_ref)
    );

    str_free(table_ref);

    if (written < 0 || written >= (ssize_t)sizeof(tmp)) {
        log_error("__compile_table_migration_create: buffer overflow prevented\n");
        return NULL;
    }

    return strdup(tmp);
}

char* __compile_insert(void* connection, const char* table, array_t* params) {
    if (connection == NULL) return NULL;
    if (table == NULL) return NULL;
    if (params == NULL) return NULL;
    if (array_size(params) == 0) return NULL;

    dbconnection_t* conn = connection;
    char* buffer = NULL;

    str_t* table_ref = __compile_table_ref(conn, table);
    if (table_ref == NULL)
        return NULL;

    str_t* fields = str_create_empty(256);
    if (fields == NULL) {
        str_free(table_ref);
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
    const size_t buffer_size = strlen(format) + str_size(table_ref) + str_size(fields) + str_size(values) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL)
        goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(table_ref),
        str_get(fields),
        str_get(values)
    );

    failed:

    str_free(table_ref);
    str_free(fields);
    str_free(values);

    return buffer;
}

char* __compile_select(void* connection, const char* table, array_t* columns, array_t* where) {
    if (connection == NULL) return NULL;
    if (table == NULL) return NULL;

    dbconnection_t* conn = connection;
    char* buffer = NULL;

    str_t* table_ref = __compile_table_ref(conn, table);
    if (table_ref == NULL)
        return NULL;

    str_t* columns_str = str_create_empty(256);
    if (columns_str == NULL) {
        str_free(table_ref);
        return NULL;
    }

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL)
        goto failed;

    for (size_t i = 0; i < array_size(columns); i++) {
        const char* column_name = array_get(columns, i);
        if (column_name == NULL)
            goto failed;

        if (i > 0)
            str_appendc(columns_str, ',');

        if (__is_raw_sql(column_name)) {
            str_append(columns_str, column_name, strlen(column_name));
        } else {
            str_t* escaped_col = conn->escape_identifier(conn, column_name);
            if (escaped_col == NULL)
                goto failed;

            str_append(columns_str, str_get(escaped_col), str_size(escaped_col));
            str_free(escaped_col);
        }
    }

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

        if (field->use_raw_sql) {
            str_append(where_str, str_get(value), str_size(value));
        } else {
            str_t* quoted_str = conn->escape_string(conn, str_get(value));
            if (quoted_str == NULL)
                goto failed;

            str_append(where_str, str_get(quoted_str), str_size(quoted_str));
            str_free(quoted_str);
        }
    }

    const char* format = "SELECT %s FROM %s WHERE %s";
    const size_t buffer_size = strlen(format) + str_size(table_ref) + str_size(columns_str) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL)
        goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(columns_str),
        str_get(table_ref),
        str_get(where_str)
    );

    failed:

    str_free(table_ref);
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

    str_t* table_ref = __compile_table_ref(conn, table);
    if (table_ref == NULL)
        return NULL;

    str_t* set_str = str_create_empty(256);
    if (set_str == NULL) {
        str_free(table_ref);
        return NULL;
    }

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL)
        goto failed;

    if (where == NULL || array_size(where) == 0)
        str_append(where_str, "1", 1);

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

        if (field->use_raw_sql) {
            str_append(set_str, str_get(value), str_size(value));
        } else {
            str_t* quoted_str = conn->escape_string(conn, str_get(value));
            if (quoted_str == NULL)
                goto failed;

            str_append(set_str, str_get(quoted_str), str_size(quoted_str));
            str_free(quoted_str);
        }
    }

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

        if (field->use_raw_sql) {
            str_append(where_str, str_get(value), str_size(value));
        } else {
            str_t* quoted_str = conn->escape_string(conn, str_get(value));
            if (quoted_str == NULL)
                goto failed;

            str_append(where_str, str_get(quoted_str), str_size(quoted_str));
            str_free(quoted_str);
        }
    }

    const char* format = "UPDATE %s SET %s WHERE %s";
    const size_t buffer_size = strlen(format) + str_size(table_ref) + str_size(set_str) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL)
        goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(table_ref),
        str_get(set_str),
        str_get(where_str)
    );

    failed:

    str_free(table_ref);
    str_free(set_str);
    str_free(where_str);

    return buffer;
}

char* __compile_delete(void* connection, const char* table, array_t* where) {
    if (connection == NULL) return NULL;
    if (table == NULL) return NULL;

    dbconnection_t* conn = connection;
    char* buffer = NULL;

    str_t* table_ref = __compile_table_ref(conn, table);
    if (table_ref == NULL)
        return NULL;

    str_t* where_str = str_create_empty(256);
    if (where_str == NULL) {
        str_free(table_ref);
        return NULL;
    }

    if (where == NULL || array_size(where) == 0)
        str_append(where_str, "1", 1);

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

        if (field->use_raw_sql) {
            str_append(where_str, str_get(value), str_size(value));
        } else {
            str_t* quoted_str = conn->escape_string(conn, str_get(value));
            if (quoted_str == NULL)
                goto failed;

            str_append(where_str, str_get(quoted_str), str_size(quoted_str));
            str_free(quoted_str);
        }
    }

    const char* format = "DELETE FROM %s WHERE %s";
    const size_t buffer_size = strlen(format) + str_size(table_ref) + str_size(where_str) + 1;
    buffer = malloc(buffer_size);
    if (buffer == NULL)
        goto failed;

    snprintf(buffer, buffer_size,
        format,
        str_get(table_ref),
        str_get(where_str)
    );

    failed:

    str_free(table_ref);
    str_free(where_str);

    return buffer;
}

int __is_raw_sql(const char* str) {
    if (str == NULL || str[0] == '\0') return 0;

    if (strcmp(str, "*") == 0) return 1;

    if (strcasecmp(str, "NULL") == 0) return 1;

    if (strcasecmp(str, "true") == 0 || strcasecmp(str, "false") == 0) return 1;

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

    p = str;
    if (isalpha((unsigned char)*p) || *p == '_') {
        while (*p && (isalnum((unsigned char)*p) || *p == '_')) p++;
        if (*p == '(') return 1;
    }

    for (p = str; *p; p++) {
        if (*p == '+' || *p == '/' || *p == '|' || *p == ':') return 1;
        if (*p == '*' && p != str) return 1;
        if (*p == '-' && p != str) return 1;
    }

    if (strncasecmp(str, "CASE ", 5) == 0) return 1;

    if (str[0] == '(') return 1;

    if (str[0] == '\'') return 1;

    return 0;
}

db_t* sqlite_load(const char* database_id, const json_token_t* token_array) {
    db_t* result = NULL;
    db_t* database = db_create(database_id);
    if (database == NULL) {
        log_error("sqlite_load: can't create database\n");
        return NULL;
    }

    enum fields { HOST_ID = 0, PATH, JOURNAL_MODE, BUSY_TIMEOUT, FIELDS_COUNT };
    enum required_fields { R_HOST_ID = 0, R_PATH, R_FIELDS_COUNT };
    char* field_names[FIELDS_COUNT] = {"host_id", "path", "journal_mode", "busy_timeout"};

    for (json_it_t it_array = json_init_it(token_array); !json_end_it(&it_array); json_next_it(&it_array)) {
        json_token_t* token_object = json_it_value(&it_array);
        int lresult = 0;
        int finded_fields[FIELDS_COUNT] = {0};
        sqlitehost_t* host = __host_create();
        if (host == NULL) {
            log_error("sqlite_load: can't create host\n");
            goto failed;
        }

        for (json_it_t it_object = json_init_it(token_object); !json_end_it(&it_object); json_next_it(&it_object)) {
            const char* key = json_it_key(&it_object);
            json_token_t* token_value = json_it_value(&it_object);

            if (strcmp(key, "host_id") == 0) {
                if (finded_fields[HOST_ID]) {
                    log_error("sqlite_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("sqlite_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[HOST_ID] = 1;

                if (host->base.id != NULL) free(host->base.id);

                host->base.id = malloc(json_string_size(token_value) + 1);
                if (host->base.id == NULL) {
                    log_error("sqlite_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->base.id, json_string(token_value));
            }
            else if (strcmp(key, "path") == 0) {
                if (finded_fields[PATH]) {
                    log_error("sqlite_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("sqlite_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[PATH] = 1;

                if (host->path != NULL) free(host->path);

                host->path = malloc(json_string_size(token_value) + 1);
                if (host->path == NULL) {
                    log_error("sqlite_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->path, json_string(token_value));
            }
            else if (strcmp(key, "journal_mode") == 0) {
                if (finded_fields[JOURNAL_MODE]) {
                    log_error("sqlite_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_string(token_value)) {
                    log_error("sqlite_load: field %s must be string\n", key);
                    goto host_failed;
                }

                finded_fields[JOURNAL_MODE] = 1;

                if (host->journal_mode != NULL) free(host->journal_mode);

                host->journal_mode = malloc(json_string_size(token_value) + 1);
                if (host->journal_mode == NULL) {
                    log_error("sqlite_load: alloc memory for %s failed\n", key);
                    goto host_failed;
                }

                strcpy(host->journal_mode, json_string(token_value));
            }
            else if (strcmp(key, "busy_timeout") == 0) {
                if (finded_fields[BUSY_TIMEOUT]) {
                    log_error("sqlite_load: field %s must be unique\n", key);
                    goto host_failed;
                }
                if (!json_is_number(token_value)) {
                    log_error("sqlite_load: field %s must be int\n", key);
                    goto host_failed;
                }

                finded_fields[BUSY_TIMEOUT] = 1;

                int ok = 0;
                int value = json_int(token_value, &ok);
                if (!ok || value < 0) {
                    log_error("sqlite_load: field %s must be non-negative int\n", key);
                    goto host_failed;
                }

                host->busy_timeout = value;
            }
            else {
                log_error("sqlite_load: unknown field: %s\n", key);
                goto host_failed;
            }
        }

        // Defaults for optional fields.
        if (finded_fields[JOURNAL_MODE] == 0) {
            if (host->journal_mode != NULL) free(host->journal_mode);
            host->journal_mode = strdup("WAL");
            if (host->journal_mode == NULL) {
                log_error("sqlite_load: alloc memory for journal_mode failed\n");
                goto host_failed;
            }
        }

        if (finded_fields[BUSY_TIMEOUT] == 0) {
            host->busy_timeout = 5000;
        }

        for (int i = 0; i < R_FIELDS_COUNT; i++) {
            if (finded_fields[i] == 0) {
                log_error("sqlite_load: required field %s not found\n", field_names[i]);
                goto host_failed;
            }
        }

        // Push host only after all checks: the array element owns it (freed via
        // db_free), so a manual free after push would double-free.
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

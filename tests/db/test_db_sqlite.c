// SQLite tests for the universal named-parameter path (dbquery against a SQLite
// host). These exercise the sqlite driver's execute_params: :name values are
// bound positionally ($1..$N passed through to sqlite3_bind_*), never
// interpolated into SQL.
//
// Like the Redis tests these do not use TEST_DB (no transaction wrap); each test
// builds and tears down its own table. They are skipped gracefully when no
// SQLite host is configured/reachable (dbquery returns NULL). The host in
// test_config.json points at ":memory:", which is process-private and shared
// across calls because the single-threaded runner reuses one cached connection
// per thread (db_connection_find by thread_id).

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include "database.h"
#include "model.h"
#include "str.h"
#include "array.h"
#include <string.h>

#define SQLITE_DBID "sqlite.test"

// Run a parameter-less statement (DDL/DML). Returns 1 on success.
static int __sqlite_exec(const char* sql) {
    dbresult_t* r = dbquery(SQLITE_DBID, sql, NULL);
    int ok = dbresult_ok(r);
    dbresult_free(r);
    return ok;
}

// Probe whether a SQLite host is configured and reachable; tests no-op otherwise.
static int __sqlite_available(void) {
    return __sqlite_exec("SELECT 1");
}

// Recreate the scratch table; returns 1 on success.
static int __sqlite_setup_table(void) {
    if (!__sqlite_exec("DROP TABLE IF EXISTS cwfr_sqlite_test")) return 0;
    return __sqlite_exec(
        "CREATE TABLE cwfr_sqlite_test ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT NOT NULL, "
            "age INTEGER"
        ")");
}

// Insert a row with bound text + int parameters; returns the assigned rowid, or
// 0 on failure.
static long long __sqlite_insert_person(const char* name, int age) {
    array_t* params = array_create();
    if (params == NULL) return 0;

    mparams_fill_array(params,
        mparam_text(name, name),
        mparam_int(age, age)
    );

    dbresult_t* r = dbquery(SQLITE_DBID,
        "INSERT INTO cwfr_sqlite_test (name, age) VALUES (:name, :age)", params);
    array_free(params);

    long long id = dbresult_ok(r) ? dbresult_insert_id(r) : 0;
    dbresult_free(r);
    return id;
}

// Select a row by id; caller frees the result.
static dbresult_t* __sqlite_select_by_id(long long id) {
    array_t* params = array_create();
    if (params == NULL) return NULL;

    mparams_fill_array(params, mparam_bigint(id, id));

    dbresult_t* r = dbquery(SQLITE_DBID,
        "SELECT name, age FROM cwfr_sqlite_test WHERE id = :id", params);
    array_free(params);
    return r;
}

TEST(test_sqlite_insert_select_roundtrip) {
    TEST_SUITE("sqlite dbquery");
    TEST_CASE("INSERT with bound params reads back via SELECT");

    if (!__sqlite_available()) return;

    TEST_ASSERT(__sqlite_setup_table(), "table setup should succeed");

    long long id = __sqlite_insert_person("alice", 30);
    TEST_ASSERT(id == 1, "first insert should get rowid 1");

    dbresult_t* r = __sqlite_select_by_id(id);
    TEST_ASSERT(dbresult_ok(r), "SELECT should succeed");
    if (dbresult_ok(r)) {
        TEST_ASSERT_EQUAL(1, dbresult_query_rows(r), "one row expected");

        db_table_cell_t* name_cell = dbresult_field(r, "name");
        db_table_cell_t* age_cell = dbresult_field(r, "age");
        TEST_ASSERT_NOT_NULL(name_cell, "name cell should exist");
        TEST_ASSERT_NOT_NULL(age_cell, "age cell should exist");

        if (name_cell != NULL && name_cell->length > 0)
            TEST_ASSERT_STR_EQUAL("alice", name_cell->value, "name round-trips verbatim");
        // Integers are surfaced as text (like the postgresql/mysql drivers).
        if (age_cell != NULL && age_cell->length > 0)
            TEST_ASSERT_STR_EQUAL("30", age_cell->value, "age bound as int reads back as text");
    }
    dbresult_free(r);
}

TEST(test_sqlite_returning) {
    TEST_SUITE("sqlite dbquery");
    TEST_CASE("INSERT ... RETURNING reads back the inserted row");

    if (!__sqlite_available()) return;

    TEST_ASSERT(__sqlite_setup_table(), "table setup should succeed");

    array_t* params = array_create();
    if (params == NULL) return;
    mparams_fill_array(params,
        mparam_text(name, "bob"),
        mparam_int(age, 25)
    );

    dbresult_t* r = dbquery(SQLITE_DBID,
        "INSERT INTO cwfr_sqlite_test (name, age) VALUES (:name, :age) "
        "RETURNING id, name", params);
    array_free(params);

    TEST_ASSERT(dbresult_ok(r), "RETURNING insert should succeed");
    if (dbresult_ok(r)) {
        TEST_ASSERT_EQUAL(1, dbresult_query_rows(r), "RETURNING should yield one row");

        db_table_cell_t* name_cell = dbresult_field(r, "name");
        TEST_ASSERT_NOT_NULL(name_cell, "name cell from RETURNING should exist");
        if (name_cell != NULL && name_cell->length > 0)
            TEST_ASSERT_STR_EQUAL("bob", name_cell->value, "RETURNING name must match inserted value");
    }
    dbresult_free(r);
}

TEST(test_sqlite_binding_safe) {
    TEST_SUITE("sqlite dbquery");
    TEST_CASE("a value containing a quote is bound, not interpolated");

    if (!__sqlite_available()) return;

    TEST_ASSERT(__sqlite_setup_table(), "table setup should succeed");

    long long id = __sqlite_insert_person("O'Brien", 41);
    TEST_ASSERT(id > 0, "insert with a quote in the value should succeed");

    dbresult_t* r = __sqlite_select_by_id(id);
    TEST_ASSERT(dbresult_ok(r), "SELECT should succeed");
    if (dbresult_ok(r)) {
        db_table_cell_t* name_cell = dbresult_field(r, "name");
        TEST_ASSERT_NOT_NULL(name_cell, "name cell should exist");
        if (name_cell != NULL && name_cell->length > 0)
            TEST_ASSERT_STR_EQUAL("O'Brien", name_cell->value, "quote must round-trip verbatim (no injection)");
    }
    dbresult_free(r);
}

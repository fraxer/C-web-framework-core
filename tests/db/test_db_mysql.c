// MySQL tests for the universal named-parameter path (dbquery against a MySQL
// host). They exercise the driver improvements that bring it to parity with the
// PostgreSQL driver on the shared dbquery API:
//
//   * Phase 1: utility/DDL statements with no bound params (CREATE TABLE, SET,
//     BEGIN/COMMIT) route through the simple protocol (mysql_query) instead of
//     the prepared protocol, which rejects them.
//   * Bound :name values go through the prepared protocol and are never
//     interpolated into the SQL text (injection-safe, stored verbatim).
//   * Phase 3: dbresult_insert_id() reports the generated AUTO_INCREMENT key.
//
// Like the Redis tests they run against a separate "mysql.test" dbid (no global
// TEST_DB transaction wraps them; MySQL auto-commits DDL anyway) and are skipped
// gracefully when no MySQL host is configured/reachable. Each test creates and
// drops its own table so a failure cannot leak state into the next test.

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include "database.h"
#include "model.h"
#include "str.h"
#include "array.h"
#include <string.h>
#include <stdlib.h>

#define MYSQL_DBID "mysql.test"

// Probe whether a MySQL host is configured and reachable; tests no-op otherwise.
// "SELECT 1" carries no params, so this also exercises the simple-protocol path.
static int __mysql_available(void) {
    dbresult_t* r = dbquery(MYSQL_DBID, "SELECT 1", NULL);
    int ok = dbresult_ok(r);
    dbresult_free(r);
    return ok;
}

// Run a parameterless statement (DDL/utility), return 1 on success.
static int __mysql_exec(const char* sql) {
    dbresult_t* r = dbquery(MYSQL_DBID, sql, NULL);
    int ok = dbresult_ok(r);
    dbresult_free(r);
    return ok;
}

TEST(test_mysql_ddl_simple_protocol) {
    TEST_SUITE("mysql dbquery");
    TEST_CASE("parameterless DDL/utility statements run via simple protocol");

    if (!__mysql_available()) return;

    // CREATE TABLE has no bind params: before Phase 1 this hit mysql_stmt_prepare
    // and failed; now it goes through mysql_query.
    __mysql_exec("DROP TABLE IF EXISTS cwfr_mysql_ddl");
    TEST_ASSERT(
        __mysql_exec(
            "CREATE TABLE cwfr_mysql_ddl ("
            "id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255))"),
        "CREATE TABLE should succeed via simple protocol");

    // SET and transaction-control statements likewise carry no params.
    TEST_ASSERT(__mysql_exec("SET @cwfr_x := 1"), "SET should succeed");
    TEST_ASSERT(__mysql_exec("BEGIN"), "BEGIN should succeed");
    TEST_ASSERT(__mysql_exec("COMMIT"), "COMMIT should succeed");

    __mysql_exec("DROP TABLE IF EXISTS cwfr_mysql_ddl");
}

TEST(test_mysql_crud_and_insert_id) {
    TEST_SUITE("mysql dbquery");
    TEST_CASE("bound INSERT reports insert_id and SELECT round-trips values");

    if (!__mysql_available()) return;

    __mysql_exec("DROP TABLE IF EXISTS cwfr_mysql_crud");
    TEST_ASSERT(
        __mysql_exec(
            "CREATE TABLE cwfr_mysql_crud ("
            "id INT AUTO_INCREMENT PRIMARY KEY,"
            "name VARCHAR(255) NOT NULL,"
            "val INT NOT NULL)"),
        "CREATE TABLE should succeed");

    // Bound INSERT → prepared protocol; values bound, not interpolated.
    array_t* params = array_create();
    TEST_ASSERT_NOT_NULL(params, "params array");
    mparams_fill_array(params,
        mparam_text(name, "Alpha"),
        mparam_int(val, 42)
    );
    dbresult_t* ins = dbquery(MYSQL_DBID,
        "INSERT INTO cwfr_mysql_crud (name, val) VALUES (:name, :val)", params);
    array_free(params);

    TEST_ASSERT(dbresult_ok(ins), "INSERT should succeed");
    long long id = dbresult_insert_id(ins);
    TEST_ASSERT(id > 0, "dbresult_insert_id should report the generated key");
    dbresult_free(ins);

    // SELECT the row back by the generated id; verify both columns.
    array_t* sel_params = array_create();
    TEST_ASSERT_NOT_NULL(sel_params, "select params array");
    mparams_fill_array(sel_params, mparam_bigint(id, id));
    dbresult_t* sel = dbquery(MYSQL_DBID,
        "SELECT name, val FROM cwfr_mysql_crud WHERE id = :id", sel_params);
    array_free(sel_params);

    TEST_ASSERT(dbresult_ok(sel), "SELECT should succeed");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(sel), "exactly one row expected");
    if (dbresult_query_rows(sel) == 1) {
        const db_table_cell_t* name_cell = dbresult_field(sel, "name");
        const db_table_cell_t* val_cell = dbresult_field(sel, "val");
        TEST_ASSERT_NOT_NULL(name_cell, "name cell");
        TEST_ASSERT_NOT_NULL(val_cell, "val cell");
        if (name_cell != NULL)
            TEST_ASSERT_STR_EQUAL("Alpha", name_cell->value, "name must round-trip");
        if (val_cell != NULL)
            TEST_ASSERT_STR_EQUAL("42", val_cell->value, "val must round-trip");
    }
    dbresult_free(sel);

    __mysql_exec("DROP TABLE IF EXISTS cwfr_mysql_crud");
}

TEST(test_mysql_value_binding_verbatim) {
    TEST_SUITE("mysql dbquery");
    TEST_CASE("a value with quotes/semicolons is stored verbatim, cannot inject");

    if (!__mysql_available()) return;

    __mysql_exec("DROP TABLE IF EXISTS cwfr_mysql_inject");
    TEST_ASSERT(
        __mysql_exec(
            "CREATE TABLE cwfr_mysql_inject ("
            "id INT AUTO_INCREMENT PRIMARY KEY, payload TEXT)"),
        "CREATE TABLE should succeed");

    // A hostile value: quotes, a statement terminator and a comment. Bound as a
    // parameter it is a single opaque value; interpolated it could break out.
    const char* payload = "x'; DROP TABLE cwfr_mysql_inject; -- \"end";

    array_t* params = array_create();
    TEST_ASSERT_NOT_NULL(params, "params array");
    mparams_fill_array(params, mparam_text(payload, payload));
    dbresult_t* ins = dbquery(MYSQL_DBID,
        "INSERT INTO cwfr_mysql_inject (payload) VALUES (:payload)", params);
    array_free(params);

    TEST_ASSERT(dbresult_ok(ins), "INSERT with hostile value should succeed");
    dbresult_free(ins);

    // The table must still exist (the embedded DROP never ran) and hold the
    // value verbatim.
    dbresult_t* sel = dbquery(MYSQL_DBID,
        "SELECT payload FROM cwfr_mysql_inject", NULL);
    TEST_ASSERT(dbresult_ok(sel), "SELECT should succeed (table not dropped)");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(sel), "exactly one row expected");
    if (dbresult_query_rows(sel) == 1) {
        const db_table_cell_t* cell = dbresult_field(sel, "payload");
        TEST_ASSERT_NOT_NULL(cell, "payload cell");
        if (cell != NULL)
            TEST_ASSERT_STR_EQUAL(payload, cell->value, "value must be stored verbatim");
    }
    dbresult_free(sel);

    __mysql_exec("DROP TABLE IF EXISTS cwfr_mysql_inject");
}

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"

TEST_DB(test_db_insert_and_select) {
    TEST_SUITE("Database: Basic Operations");
    TEST_CASE("Insert and retrieve a row");

    const char* dbid = testdb_dbid();

    dbresult_t* r = dbqueryf(dbid,
        "INSERT INTO user_entity (id, email, email_constraint, enabled) "
        "VALUES ('test-uuid-1', 'test@example.com', 'test@example.com', TRUE)");
    TEST_ASSERT(dbresult_ok(r), "Insert should succeed");
    dbresult_free(r);

    r = dbqueryf(dbid, "SELECT id, email FROM user_entity WHERE id = 'test-uuid-1'");
    TEST_ASSERT(dbresult_ok(r), "Select should succeed");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(r), "Should find 1 row");

    db_table_cell_t* cell = dbresult_field(r, "email");
    TEST_ASSERT_NOT_NULL(cell, "Email field should exist");
    if (cell)
        TEST_ASSERT_STR_EQUAL("test@example.com", cell->value, "Email should match");

    dbresult_free(r);
}

TEST_DB(test_db_rollback_isolation) {
    TEST_SUITE("Database: Isolation");
    TEST_CASE("Previous test data should not persist after rollback");

    const char* dbid = testdb_dbid();

    dbresult_t* r = dbqueryf(dbid,
        "SELECT * FROM user_entity WHERE id = 'test-uuid-1'");
    TEST_ASSERT(dbresult_ok(r), "Query should succeed");
    TEST_ASSERT_EQUAL(0, dbresult_query_rows(r), "No data from previous test");
    dbresult_free(r);
}

TEST_DB(test_db_transaction_support) {
    TEST_SUITE("Database: Transactions");
    TEST_CASE("Multiple inserts within a test are rolled back");

    const char* dbid = testdb_dbid();

    for (int i = 0; i < 5; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "INSERT INTO user_entity (id, email, email_constraint, enabled) "
            "VALUES ('batch-%d', 'user%d@test.com', 'user%d@test.com', TRUE)",
            i, i, i);
        dbresult_t* r = dbqueryf(dbid, "%s", sql);
        TEST_ASSERT(dbresult_ok(r), "Batch insert should succeed");
        dbresult_free(r);
    }

    dbresult_t* r = dbqueryf(dbid, "SELECT COUNT(*) FROM user_entity");
    TEST_ASSERT(dbresult_ok(r), "Count query should succeed");
    dbresult_free(r);
}

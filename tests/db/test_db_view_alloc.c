/* Namespaced view/driver copies in the existing DB runner. Only wrapper
 * allocations are intercepted; framework, models and libpq use real allocators.
 */
#undef malloc
#undef calloc
#undef strdup
#include <stdlib.h>
#include <string.h>

static long remaining = -1;
static int failed;
static int allocations;
static int should_fail(void) {
    allocations++;
    if (remaining < 0) return 0;
    if (remaining-- == 0) { failed = 1; return 1; }
    return 0;
}
void* cwfr_test_pg_malloc(size_t size) {
    return should_fail() ? NULL : malloc(size);
}
void* cwfr_test_view_calloc(size_t count, size_t size) {
    return should_fail() ? NULL : calloc(count, size);
}
char* cwfr_test_view_strdup(const char* text) {
    return should_fail() ? NULL : strdup(text);
}

#include "testdb.h"
#include "dbquery.h"
#include "postgresql.h"
#include "postgresql_view_internal.h"

TEST(test_pg_view_driver_allocation_failures) {
    TEST_SUITE("postgresql read-only view allocations");
    TEST_CASE("Bind and metadata OOM drain the connection and discard partial PGresult owners");
    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;
    dbinstance_t* instance = dbinstance(testdb_dbid());
    TEST_REQUIRE_NOT_NULL(instance, "connection");
    postgresqlconnection_t* pg = instance->connection;
    dbinstance_free(instance);
    array_t* params = array_create();
    TEST_REQUIRE_NOT_NULL(params, "params");
    mparams_fill_array(params, mparam_int(n, 20));
    int completed = 0;
    for (long site = 0; site < 10; site++) {
        dbresult_view_t* view = dbresult_view_create();
        TEST_REQUIRE_NOT_NULL(view, "empty view");
        remaining = site;
        failed = 0;
        postgresql_execute_params_view(&pg->base, "SELECT $1::int", params, view);
        remaining = -1;
        if (failed) {
            TEST_ASSERT(!dbresult_view_ok(view), "failed allocation rejects view");
            TEST_ASSERT_NOT_NULL(dbresult_view_error(view), "OOM error");
            TEST_ASSERT_EQUAL(0, dbresult_view_rows(view), "no partial result");
        } else {
            TEST_ASSERT(dbresult_view_ok(view), "eventually all allocations succeed");
            completed = 1;
        }
        dbresult_view_free(view);
        view = dbresult_view_create();
        TEST_REQUIRE_NOT_NULL(view, "recovery view");
        postgresql_execute_params_view(&pg->base, "SELECT 42", NULL, view);
        TEST_ASSERT(dbresult_view_ok(view), "success after allocation failure");
        dbresult_view_free(view);
        if (completed) break;
    }
    TEST_ASSERT(completed, "all bind/result allocation sites covered");
    array_free(params);
    dbresult_view_t* view = dbresult_view_create();
    TEST_REQUIRE_NOT_NULL(view, "chain view");
    TEST_REQUIRE(PQsendQuery(pg->connection, "SELECT 'first'; SELECT 'second'; SELECT 'third'"), "chain sent");
    remaining = 1; /* First owner succeeds; second owner's metadata fails. */
    failed = 0;
    postgresql_process_result_view(&pg->base, view);
    remaining = -1;
    TEST_ASSERT(failed && !dbresult_view_ok(view), "second owner failed");
    TEST_ASSERT_EQUAL(0, dbresult_view_rows(view), "first owner discarded");
    dbresult_view_free(view);
    view = dbresult_view_create();
    TEST_REQUIRE_NOT_NULL(view, "recovery view");
    postgresql_execute_params_view(&pg->base, "SELECT 43", NULL, view);
    TEST_ASSERT(dbresult_view_ok(view), "all remaining chain results drained");
    dbresult_view_free(view);
}

TEST(test_pg_view_no_cell_allocations) {
    TEST_SUITE("postgresql read-only view allocations");
    TEST_CASE("A 20 by 5 result allocates only the view and one owner node");
    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;
    dbinstance_t* instance = dbinstance(testdb_dbid());
    TEST_REQUIRE_NOT_NULL(instance, "connection");
    dbconnection_t* connection = instance->connection;
    dbinstance_free(instance);
    allocations = 0;
    dbresult_view_t* view = dbresult_view_create();
    TEST_REQUIRE_NOT_NULL(view, "view");
    postgresql_execute_params_view(connection,
        "SELECT i AS id, 42 AS category, 'item'::text AS name, 123 AS price, true AS active "
        "FROM generate_series(1,20) i", NULL, view);
    TEST_REQUIRE(dbresult_view_ok(view), "fixture shape");
    TEST_ASSERT_EQUAL(20, dbresult_view_rows(view), "twenty rows");
    TEST_ASSERT_EQUAL(5, dbresult_view_cols(view), "five columns");
    for (int col = 0; col < 5; col++) {
        TEST_ASSERT_NOT_NULL(dbresult_view_col_name(view, col), "name");
        for (int row = 0; row < 20; row++) {
            const char* value;
            size_t length;
            TEST_ASSERT(dbresult_view_cell(view, row, col, &value, &length), "value");
            TEST_ASSERT(value && length, "nonempty fixture value");
        }
    }
    TEST_ASSERT_EQUAL(2, allocations, "only view and result-node allocations; libpq is not intercepted");
    dbresult_view_free(view);
}

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include <pthread.h>

#ifdef PostgreSQL_FOUND
#include "postgresql.h"
#include "postgresql_view_internal.h"

static void expect_cell(dbresult_view_t* view, int row, int col,
                        const char* expected, size_t expected_length) {
    const char* value = NULL;
    size_t length = 99;
    TEST_ASSERT(dbresult_view_cell(view, row, col, &value, &length), "cell exists");
    TEST_ASSERT_EQUAL_SIZE(expected_length, length, "driver byte length");
    if (!expected) TEST_ASSERT_NULL(value, "SQL NULL");
    else TEST_ASSERT(value && !memcmp(value, expected, length), "exact bytes");
}

TEST(test_pg_view_values_and_shapes) {
    TEST_SUITE("postgresql read-only views");
    TEST_CASE("NULL, empty, UTF-8, long text and text bytea preserve bytes and dimensions");
    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;
    array_t* params = array_create();
    TEST_REQUIRE_NOT_NULL(params, "params allocated");
    mparams_fill_array(params, mparam_text(v, "é雪😀"), mparam_int(n, 20));
    dbresult_view_t* view = dbquery_params_view(testdb_dbid(),
        "SELECT NULL::text AS nil, ''::text AS empty, $1::text AS utf8, "
        "repeat('x',65536) AS long, decode('610062','hex') AS bytes "
        "FROM generate_series(1,$2::int)", params);
    array_free(params);
    TEST_REQUIRE(dbresult_view_ok(view), "bound query succeeded");
    TEST_ASSERT_EQUAL(20, dbresult_view_rows(view), "all twenty rows");
    TEST_ASSERT_EQUAL(5, dbresult_view_cols(view), "all five fields");
    const char* names[] = {"nil", "empty", "utf8", "long", "bytes"};
    for (int col = 0; col < 5; col++)
        TEST_ASSERT_STR_EQUAL(names[col], dbresult_view_col_name(view, col), "name retained");
    for (int row = 0; row < 20; row++) {
        expect_cell(view, row, 0, NULL, 0);
        expect_cell(view, row, 1, "", 0);
        expect_cell(view, row, 2, "é雪😀", strlen("é雪😀"));
        const char* value;
        size_t length;
        TEST_ASSERT(dbresult_view_cell(view, row, 3, &value, &length), "long value exists");
        TEST_ASSERT_EQUAL_SIZE(65536, length, "long byte length");
        TEST_ASSERT(value && strspn(value, "x") == length, "long bytes preserved");
        expect_cell(view, row, 4, "\\x610062", 8);
    }
    const char* value = "sentinel";
    size_t length = 9;
    TEST_ASSERT(!dbresult_view_cell(view, -1, 0, &value, &length), "negative row refused");
    TEST_ASSERT(value == NULL && length == 0, "outputs reset");
    TEST_ASSERT(!dbresult_view_cell(view, 20, 0, &value, &length), "row beyond end");
    TEST_ASSERT(!dbresult_view_cell(view, 0, 5, &value, &length), "col beyond end");
    TEST_ASSERT_NULL(dbresult_view_col_name(view, -1), "negative column");
    TEST_ASSERT_NULL(dbresult_view_col_name(view, 5), "column beyond end");
    dbresult_view_free(view);
    view = dbquery_params_view(testdb_dbid(), "SELECT 1 AS known WHERE false", NULL);
    TEST_REQUIRE(dbresult_view_ok(view), "empty SELECT succeeded");
    TEST_ASSERT_EQUAL(0, dbresult_view_rows(view), "zero rows");
    TEST_ASSERT_EQUAL(1, dbresult_view_cols(view), "known column");
    TEST_ASSERT_STR_EQUAL("known", dbresult_view_col_name(view, 0), "empty header retained");
    dbresult_view_free(view);
    view = dbquery_params_view(testdb_dbid(), "SET application_name TO 'view-tests'", NULL);
    TEST_REQUIRE(dbresult_view_ok(view), "command succeeded");
    TEST_ASSERT_EQUAL(0, dbresult_view_rows(view), "command has no rows");
    TEST_ASSERT_EQUAL(0, dbresult_view_cols(view), "command has no fields");
    dbresult_view_free(view);
}

TEST(test_pg_view_lifetime_and_json) {
    TEST_SUITE("postgresql read-only views");
    TEST_CASE("Views survive a second query, reconnect and connection closure; JSON owns its copy");
    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;
    dbresult_view_t* first = dbquery_params_view(testdb_dbid(), "SELECT 'é雪😀'::text AS value", NULL);
    TEST_REQUIRE(dbresult_view_ok(first), "first query");
    const char* saved;
    size_t length;
    TEST_REQUIRE(dbresult_view_cell(first, 0, 0, &saved, &length), "first value");
    dbresult_view_t* second = dbquery_params_view(testdb_dbid(), "SELECT 'second'::text", NULL);
    TEST_REQUIRE(dbresult_view_ok(second), "second query");
    expect_cell(first, 0, 0, "é雪😀", strlen("é雪😀"));
    dbresult_view_free(second); /* Reverse order. */
    dbinstance_t* instance = dbinstance(testdb_dbid());
    TEST_REQUIRE_NOT_NULL(instance, "cached connection");
    postgresqlconnection_t* pg = instance->connection;
    dbinstance_free(instance);
    PQfinish(pg->connection);
    pg->connection = NULL;
    expect_cell(first, 0, 0, "é雪😀", length);
    second = dbquery_params_view(testdb_dbid(), "SELECT 'reconnected'::text", NULL);
    TEST_REQUIRE(dbresult_view_ok(second), "automatic reconnect");
    expect_cell(first, 0, 0, "é雪😀", length);
    json_doc_t* doc = json_root_create_object();
    TEST_REQUIRE_NOT_NULL(doc, "JSON document");
    TEST_REQUIRE(json_object_set(json_root(doc), "value", json_create_string(saved)), "JSON string copied");
    dbresult_view_free(first);
    dbresult_view_free(second);
    TEST_ASSERT_STR_EQUAL("é雪😀", json_string(json_object_get(json_root(doc), "value")), "JSON survives free");
    TEST_ASSERT_NOT_NULL(json_stringify(doc), "normal serializer succeeds");
    json_free(doc);
}

TEST(test_pg_view_errors_and_protocol) {
    TEST_SUITE("postgresql read-only views");
    TEST_CASE("SQL errors drain results, chains retain ownership and unsupported COPY reconnects");
    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;
    const char* failures[] = {"SELECT 1/0", "SELECT 1; SELECT 2", ""};
    for (size_t i = 0; i < sizeof failures / sizeof failures[0]; i++) {
        dbresult_view_t* failed = dbquery_params_view(testdb_dbid(), failures[i], NULL);
        TEST_REQUIRE_NOT_NULL(failed, "failed view returned");
        TEST_ASSERT(!dbresult_view_ok(failed), "SQL rejected");
        TEST_ASSERT_NOT_NULL(dbresult_view_error(failed), "owned error");
        TEST_ASSERT_EQUAL(0, dbresult_view_rows(failed), "no partial rows");
        char* error = strdup(dbresult_view_error(failed));
        TEST_REQUIRE_NOT_NULL(error, "error snapshot");
        dbresult_view_t* next = dbquery_params_view(testdb_dbid(), "SELECT 42", NULL);
        TEST_REQUIRE(dbresult_view_ok(next), "success after error");
        expect_cell(next, 0, 0, "42", 2);
        TEST_ASSERT_STR_EQUAL(error, dbresult_view_error(failed), "error survives next query");
        free(error);
        dbresult_view_free(failed);
        dbresult_view_free(next);
    }
    dbinstance_t* instance = dbinstance(testdb_dbid());
    TEST_REQUIRE_NOT_NULL(instance, "connection");
    postgresqlconnection_t* pg = instance->connection;
    dbinstance_free(instance);
    dbresult_view_t* chain = dbresult_view_create();
    TEST_REQUIRE_NOT_NULL(chain, "chain view");
    TEST_REQUIRE(PQsendQuery(pg->connection, "SELECT 'first'; SELECT 'second'"), "simple protocol chain");
    postgresql_process_result_view(&pg->base, chain);
    TEST_REQUIRE(dbresult_view_ok(chain), "chain collected");
    const char* saved;
    size_t length;
    TEST_REQUIRE(dbresult_view_cell(chain, 0, 0, &saved, &length), "first pointer");
    TEST_ASSERT(dbresult_view_query_next(chain), "second result");
    expect_cell(chain, 0, 0, "second", 6);
    TEST_ASSERT_STR_EQUAL("first", saved, "first still alive");
    TEST_ASSERT(!dbresult_view_query_next(chain), "fully drained");
    TEST_ASSERT(dbresult_view_query_first(chain), "first again");
    dbresult_view_free(chain);
    chain = dbresult_view_create();
    TEST_REQUIRE_NOT_NULL(chain, "failed chain view");
    TEST_REQUIRE(PQsendQuery(pg->connection, "SELECT 'partial'; SELECT 1/0; SELECT 'unreachable'"), "error chain");
    postgresql_process_result_view(&pg->base, chain);
    TEST_ASSERT(!dbresult_view_ok(chain), "error in chain");
    TEST_ASSERT_EQUAL(0, dbresult_view_rows(chain), "prior successful owner discarded");
    dbresult_view_free(chain);
    const char* copies[] = {"COPY (SELECT 1) TO STDOUT", "COPY pg_temp.view_copy FROM STDIN"};
    dbresult_t* setup = dbquery(testdb_dbid(), "CREATE TEMP TABLE view_copy(v integer)", NULL);
    TEST_REQUIRE(dbresult_ok(setup), "temporary COPY table");
    dbresult_free(setup);
    for (size_t i = 0; i < sizeof copies / sizeof copies[0]; i++) {
        /* Recreate the temporary table after each reconnect if needed. */
        if (i) {
            setup = dbquery(testdb_dbid(), "CREATE TEMP TABLE view_copy(v integer)", NULL);
            TEST_REQUIRE(dbresult_ok(setup), "COPY table after reconnect");
            dbresult_free(setup);
        }
        chain = dbquery_params_view(testdb_dbid(), copies[i], NULL);
        TEST_ASSERT(!dbresult_view_ok(chain), "COPY refused");
        TEST_ASSERT_STR_EQUAL("Unsupported PostgreSQL result status", dbresult_view_error(chain), "explicit protocol error");
        TEST_ASSERT_NULL(pg->connection, "busy connection closed");
        dbresult_view_free(chain);
        chain = dbquery_params_view(testdb_dbid(), "SELECT 7", NULL);
        TEST_REQUIRE(dbresult_view_ok(chain), "success after COPY reconnect");
        dbresult_view_free(chain);
    }
    chain = dbquery_params_view(testdb_dbid(), "SELECT pg_terminate_backend(pg_backend_pid())", NULL);
    TEST_ASSERT(!dbresult_view_ok(chain), "lost connection rejected");
    TEST_ASSERT_NOT_NULL(dbresult_view_error(chain), "disconnect error copied");
    dbresult_view_free(chain);
    chain = dbquery_params_view(testdb_dbid(), "SELECT 8", NULL);
    TEST_REQUIRE(dbresult_view_ok(chain), "success after backend termination");
    dbresult_view_free(chain);
    TEST_REQUIRE(PQenterPipelineMode(pg->connection), "pipeline mode entered for refusal test");
    chain = dbquery_params_view(testdb_dbid(), "SELECT 9", NULL);
    TEST_ASSERT(!dbresult_view_ok(chain), "pipeline refused before sending");
    TEST_ASSERT_STR_EQUAL("PostgreSQL pipeline mode is not supported by result views",
                          dbresult_view_error(chain), "pipeline refusal explicit");
    TEST_ASSERT_NULL(pg->connection, "unsupported protocol connection closed");
    dbresult_view_free(chain);
    chain = dbquery_params_view(testdb_dbid(), "SELECT 10", NULL);
    TEST_REQUIRE(dbresult_view_ok(chain), "success after pipeline reconnect");
    dbresult_view_free(chain);
}

typedef struct { int number; int ok; dbresult_view_t* view; } view_thread_t;
static void* query_thread(void* data) {
    view_thread_t* job = data;
    array_t* params = array_create();
    if (!params) return NULL;
    mparams_fill_array(params, mparam_int(n, job->number));
    job->view = dbquery_params_view(testdb_dbid(), "SELECT $1::int AS thread", params);
    array_free(params);
    job->ok = dbresult_view_ok(job->view);
    return NULL;
}

TEST(test_pg_view_thread_connections) {
    TEST_SUITE("postgresql read-only views");
    TEST_CASE("Eight independent thread connections can transfer completed views to the caller");
    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;
    pthread_t threads[8];
    view_thread_t jobs[8] = {0};
    int started = 0;
    for (int i = 0; i < 8; i++) {
        jobs[i].number = i;
        if (pthread_create(&threads[i], NULL, query_thread, &jobs[i])) break;
        started++;
    }
    for (int i = 0; i < started; i++) pthread_join(threads[i], NULL);
    TEST_ASSERT_EQUAL(8, started, "eight threads started");
    for (int i = 0; i < started; i++) {
        TEST_ASSERT(jobs[i].ok, "thread query succeeded");
        char expected[16];
        snprintf(expected, sizeof expected, "%d", i);
        expect_cell(jobs[i].view, 0, 0, expected, strlen(expected));
        dbresult_view_free(jobs[i].view);
    }
}
#endif

TEST(test_db_view_other_drivers) {
    TEST_SUITE("read-only view driver compatibility");
    TEST_CASE("Other drivers explicitly reject views and remain usable through the old API");
    const char* ids[] = {
#ifdef MySQL_FOUND
        "mysql.test",
#endif
#ifdef SQLite_FOUND
        "sqlite.test",
#endif
#ifdef Redis_FOUND
        "redis.test",
#endif
        NULL
    };
    for (int i = 0; ids[i]; i++) {
        dbresult_view_t* view = dbquery_params_view(ids[i], "SELECT 1", NULL);
        TEST_REQUIRE_NOT_NULL(view, "failed view returned");
        TEST_ASSERT(!dbresult_view_ok(view), "unsupported driver");
        TEST_ASSERT_STR_EQUAL("Read-only result views are not supported by this database driver",
                              dbresult_view_error(view), "explicit refusal");
        dbresult_view_free(view);
        dbresult_t* old = dbquery(ids[i], !strcmp(ids[i], "redis.test") ? "PING" : "SELECT 1", NULL);
        TEST_ASSERT(dbresult_ok(old), "old API works after refusal");
        dbresult_free(old);
    }
    dbresult_view_t* invalid = dbquery_params_view(NULL, "SELECT 1", NULL);
    TEST_ASSERT(!dbresult_view_ok(invalid), "missing database ID");
    TEST_ASSERT_NOT_NULL(dbresult_view_error(invalid), "invalid input error");
    dbresult_view_free(invalid);
}

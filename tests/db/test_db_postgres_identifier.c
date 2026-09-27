// PostgreSQL identifier escaping (postgresql.c __escape_identifier): the
// hand-written split of "schema.table" into parts, with quoted parts and
// doubled quotes, ahead of PQescapeIdentifier. It needs a live connection --
// PQescapeIdentifier takes one -- so the db_query fuzz target cannot reach it
// on SQLite; this is where it is held to the same rule: an identifier is
// quoted part by part or refused, never spliced (FUZZING_PLAN_3.md, stage 24).

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include "model.h"
#include <string.h>

static dbresult_t* __alias(const char* identifier) {
    array_t* params = array_create();
    mparams_fill_array(params, mparam_text(n, identifier));
    dbresult_t* r = dbquery(testdb_dbid(), "SELECT 1 AS @n", params);
    array_free(params);
    return r;
}

TEST_DB(test_pg_identifier_quoted) {
    TEST_SUITE("postgresql identifier");
    TEST_CASE("a single part is quoted whatever it holds");

    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;

    static const char* const names[][2] = {
        { "plain", "plain" },
        { "x\" AS y, 2 AS \"z", "x\" AS y, 2 AS \"z" },
        { "\"a.b\"", "a.b" },
        { "\"a\"\"b\"", "a\"b" },
        { "Mixed Case", "Mixed Case" },
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        dbresult_t* r = __alias(names[i][0]);
        TEST_ASSERT(dbresult_ok(r), names[i][0]);
        if (dbresult_ok(r)) {
            TEST_ASSERT_EQUAL(1, dbresult_query_cols(r), "one column");
            TEST_ASSERT_STR_EQUAL(names[i][1], dbresult_col_name(r, 0), names[i][0]);
        }
        dbresult_free(r);
    }
}

TEST_DB(test_pg_identifier_refused) {
    TEST_SUITE("postgresql identifier");
    TEST_CASE("an empty part or an unclosed quote is refused before the database");

    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;

    /* A lone quote opens a quoted part that never closes: refused, where
     * SQLite's escaper doubles it -- either is safe, neither splices. */
    static const char* const names[] = { "", ".", "a..b", "a.", ".a", "\"a", "a.\"b", "a\"b" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        dbresult_t* r = __alias(names[i]);
        TEST_ASSERT_NULL(r, names[i]);
        dbresult_free(r);
    }
}

TEST_DB(test_pg_identifier_qualified) {
    TEST_SUITE("postgresql identifier");
    TEST_CASE("a dotted name is a qualified reference, each part quoted");

    if (testdb_driver() != TESTDB_DRIVER_POSTGRESQL) return;

    array_t* params = array_create();
    mparams_fill_array(params, mparam_text(c, "t.v; DROP"));
    dbresult_t* r = dbquery(testdb_dbid(), "SELECT @c FROM (SELECT 7 AS \"v; DROP\") AS t", params);
    array_free(params);
    TEST_ASSERT(dbresult_ok(r), "t.\"v; DROP\" resolves");
    if (dbresult_ok(r))
        TEST_ASSERT_STR_EQUAL("7", dbresult_cell(r, 0, 0)->value, "to the column");
    dbresult_free(r);
}

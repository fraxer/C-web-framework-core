// dbquery / dbresult on SQLite ":memory:" (dbid sqlite.test): how a template and
// its parameters become SQL and bound values, and how a result is walked. No
// server needed, so these run wherever the runner does; they no-op when the
// SQLite host is not configured, like test_db_sqlite.c.
//
// The invariants are the ones the db_query fuzz target holds the builder to
// (FUZZING_PLAN_3.md, stage 24): a value comes back byte for byte whatever it
// contains, a template without parameters reaches the database unchanged, a
// list gives exactly as many placeholders as elements, and every refusal is a
// NULL result rather than a half-built query.

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include "database.h"
#include "model.h"
#include "mparams.h"
#include "str.h"
#include "array.h"
#include <string.h>

#define QUERY_DBID "sqlite.test"

static int __query_available(void) {
    dbresult_t* r = dbquery(QUERY_DBID, "SELECT 1", NULL);
    const int ok = dbresult_ok(r);
    dbresult_free(r);
    return ok;
}

TEST(test_db_query_decimal_param) {
    TEST_SUITE("dbquery (sqlite)");
    TEST_CASE("a DECIMAL parameter is bound and freed once");

    /* __bind_field serialized types without a native SQLite mapping through
     * model_field_to_string and freed the result -- but that string belongs to
     * the field (field->value._string), so the bound clone was freed twice. */
    if (!__query_available()) return;

    array_t* params = array_create();
    mparams_fill_array(params, mparam_decimal(d, 1.5L));

    dbresult_t* r = dbquery(QUERY_DBID, "SELECT :d AS d", params);
    array_free(params);

    TEST_ASSERT(dbresult_ok(r), "the query succeeds");
    db_table_cell_t* cell = dbresult_ok(r) ? dbresult_field(r, "d") : NULL;
    TEST_ASSERT_NOT_NULL(cell, "one value comes back");
    if (cell != NULL)
        TEST_ASSERT_STR_EQUAL("1.500000000000", cell->value, "in the text form the model writes");

    dbresult_free(r);
}

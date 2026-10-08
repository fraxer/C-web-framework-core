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

static dbresult_t* __query1(const char* sql, void* field) {
    array_t* params = array_create();
    if (field != NULL)
        array_push_back(params, array_create_pointer(field, NULL, model_param_free));
    dbresult_t* r = dbquery(QUERY_DBID, sql, params);
    array_free(params);
    return r;
}

TEST(test_db_query_list_refusals) {
    TEST_SUITE("dbquery (sqlite)");
    TEST_CASE("an empty list, a list__ that is not an array and an unknown name are refused");

    /* The first two returned from the middle of the builder without freeing
     * the half-built query: a leak per refusal, visible under LeakSanitizer. */
    if (!__query_available()) return;

    dbresult_t* r = __query1("SELECT :list__ids", mparam_array(ids, array_create()));
    TEST_ASSERT_NULL(r, "an empty list is refused");
    dbresult_free(r);

    r = __query1("SELECT :list__ids", mparam_int(ids, 1));
    TEST_ASSERT_NULL(r, "a list__ over a scalar is refused");
    dbresult_free(r);

    r = __query1("SELECT :missing", mparam_int(ids, 1));
    TEST_ASSERT_NULL(r, "an unknown parameter is refused");
    dbresult_free(r);
}

TEST(test_db_query_list_expands) {
    TEST_SUITE("dbquery (sqlite)");
    TEST_CASE("a list of N gives exactly N bound values, in order");

    if (!__query_available()) return;

    array_t* ids = array_create();
    array_push_back(ids, array_create_int(7));
    array_push_back(ids, array_create_string("x'y"));
    array_push_back(ids, array_create_int(-1));

    dbresult_t* r = __query1("SELECT :list__ids", mparam_array(ids, ids));
    TEST_ASSERT(dbresult_ok(r), "the query succeeds");
    if (dbresult_ok(r)) {
        TEST_ASSERT_EQUAL(3, dbresult_query_cols(r), "three columns");
        TEST_ASSERT_STR_EQUAL("7", dbresult_cell(r, 0, 0)->value, "first");
        TEST_ASSERT_STR_EQUAL("x'y", dbresult_cell(r, 0, 1)->value, "second, quote and all");
        TEST_ASSERT_STR_EQUAL("-1", dbresult_cell(r, 0, 2)->value, "third");
    }
    dbresult_free(r);
}

TEST(test_db_query_value_roundtrip) {
    TEST_SUITE("dbquery (sqlite)");
    TEST_CASE("a text value comes back byte for byte, whatever SQL it looks like");

    if (!__query_available()) return;

    static const char* const values[] = {
        "", "'", "''", "\"", "\\", "\\'", "x'; DROP TABLE t; --", "/* :v */", "@v", ":v",
        "\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82", "$1", "?", "--",
    };
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        dbresult_t* r = __query1("SELECT :v AS v", mparam_text(v, values[i]));
        TEST_ASSERT(dbresult_ok(r), "the query succeeds");
        db_table_cell_t* cell = dbresult_ok(r) ? dbresult_field(r, "v") : NULL;
        TEST_ASSERT_NOT_NULL(cell, "the value comes back");
        if (cell != NULL) {
            TEST_ASSERT_EQUAL(strlen(values[i]), cell->length, "same length");
            TEST_ASSERT(memcmp(cell->value, values[i], cell->length) == 0, "same bytes");
        }
        dbresult_free(r);
    }

    /* 64 KiB of quotes. */
    char* big = malloc(65537);
    TEST_REQUIRE_NOT_NULL(big, "64 KiB buffer");
    memset(big, '\'', 65536);
    big[65536] = '\0';
    dbresult_t* r = __query1("SELECT :v AS v", mparam_text(v, big));
    db_table_cell_t* cell = dbresult_ok(r) ? dbresult_field(r, "v") : NULL;
    TEST_ASSERT(cell != NULL && cell->length == 65536 && memcmp(cell->value, big, 65536) == 0, "64 KiB of quotes round-trip");
    dbresult_free(r);
    free(big);
}

TEST(test_db_query_identifier_escaped) {
    TEST_SUITE("dbquery (sqlite)");
    TEST_CASE("an @identifier with a quote in it is quoted, not spliced");

    if (!__query_available()) return;

    dbresult_t* r = __query1("SELECT 1 AS @name", mparam_text(name, "a\" AS b, 2 AS \"c"));
    TEST_ASSERT(dbresult_ok(r), "the query succeeds");
    if (dbresult_ok(r)) {
        TEST_ASSERT_EQUAL(1, dbresult_query_cols(r), "one column, not three");
        TEST_ASSERT_STR_EQUAL("a\" AS b, 2 AS \"c", dbresult_col_name(r, 0), "named exactly as given");
    }
    dbresult_free(r);
}

TEST(test_db_query_template_unchanged) {
    TEST_SUITE("dbquery (sqlite)");
    TEST_CASE("names inside literals and comments are not parameters");

    if (!__query_available()) return;

    dbresult_t* r = __query1("SELECT ':v' AS a, 'it''s :v' AS b, \"x\" AS \"@v\" /* :v */ -- :v\n", NULL);
    TEST_ASSERT(dbresult_ok(r), "the query succeeds without parameters");
    if (dbresult_ok(r)) {
        TEST_ASSERT_STR_EQUAL(":v", dbresult_field(r, "a")->value, "literal kept");
        TEST_ASSERT_STR_EQUAL("it's :v", dbresult_field(r, "b")->value, "doubled quote kept");
        TEST_ASSERT_STR_EQUAL("@v", dbresult_col_name(r, 2), "quoted identifier kept");
    }
    dbresult_free(r);
}

/* The builder on its own, with a processor that writes <name> for a value
 * and {name} for an identifier: what comes out is the template with exactly
 * those substitutions and nothing else. No database involved. */
static int __marker_processor(void* connection, char type, const char* name, mfield_t* field, str_t* sql, void* user_data) {
    (void)connection; (void)field; (void)user_data;
    str_appendc(sql, type == ':' ? '<' : '{');
    str_append(sql, name, strlen(name));
    str_appendc(sql, type == ':' ? '>' : '}');
    return 1;
}

static void __assert_built(const char* template, const char* expected) {
    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(v, 1), mparam_int(w, 2));
    str_t* built = parse_sql_parameters(NULL, template, strlen(template), params, __marker_processor, NULL);
    array_free(params);

    if (expected == NULL) {
        TEST_ASSERT_NULL(built, template);
    } else {
        TEST_ASSERT_NOT_NULL(built, template);
        if (built != NULL)
            TEST_ASSERT_STR_EQUAL(expected, str_get(built), template);
    }
    str_free(built);
}

TEST(test_db_query_builder_tail) {
    TEST_SUITE("dbquery builder");
    TEST_CASE("a template ending in a comment or a literal keeps its tail");

    /* The tail was appended on the last iteration of the scan, and a last
     * character inside a comment or a literal skipped the iteration: the
     * whole template became "" (sqlite: "not an error"). */
    __assert_built("SELECT 1", "SELECT 1");
    __assert_built("SELECT 1 /* c */", "SELECT 1 /* c */");
    __assert_built("SELECT 1 -- c", "SELECT 1 -- c");
    __assert_built("SELECT 1 -- c\n", "SELECT 1 -- c\n");
    __assert_built("SELECT 'a", "SELECT 'a");
    __assert_built("SELECT :v /* c */", "SELECT <v> /* c */");
    __assert_built("SELECT ':v', \"@w\", 'it''s :v'", "SELECT ':v', \"@w\", 'it''s :v'");
}

TEST(test_db_query_builder_block_comment) {
    TEST_SUITE("dbquery builder");
    TEST_CASE("a block comment ends at the first */ after its own /*");

    /* Found by fuzz_db_query: the opening test ran inside a comment too, so
     * the '/' of a "*" "/" that a '*' follows reopened it and the comment ran
     * on; and the star of the opener counted as the star of "*" "/", so a
     * comment starting with '/' closed at once. Either way, parameters were
     * substituted inside the comment or not substituted outside it. */
    __assert_built("SELECT 1 /* a */*:v", "SELECT 1 /* a */*<v>");
    __assert_built("SELECT /*/ :v */ 1", "SELECT /*/ :v */ 1");
    __assert_built("SELECT /**/ :v", "SELECT /**/ <v>");
    __assert_built("SELECT /* /* :v */ :w", "SELECT /* /* :v */ <w>");
}

TEST(test_db_query_builder_param_boundary) {
    TEST_SUITE("dbquery builder");
    TEST_CASE("a parameter ends at a comment, a quote or a cast");

    /* The comment and quote tests ran before the end-of-name test, so the
     * name was never closed: the parameter and the rest of the template were
     * dropped. */
    __assert_built("SELECT :v--c", "SELECT <v>--c");
    __assert_built("SELECT :v/*c*/", "SELECT <v>/*c*/");
    __assert_built("SELECT :v'x'", "SELECT <v>'x'");
    __assert_built("SELECT :v::int", "SELECT <v>::int");
    __assert_built("SELECT :v,@w", "SELECT <v>,{w}");
    __assert_built("SELECT :v", "SELECT <v>");
    __assert_built("SELECT @w", "SELECT {w}");
    __assert_built("SELECT :v:w", NULL);
    __assert_built("SELECT :x", NULL);
}

TEST(test_db_query_real_exact) {
    TEST_SUITE("dbquery (sqlite)");
    TEST_CASE("a REAL reads back as text that parses to the same double");

    /* The driver surfaces every value as text, and sqlite3_column_text renders
     * a REAL with 15 significant digits: 0.1 + 0.2 came back as 0.3 (found
     * by fuzz_db_model through model_double). Short values stay short. */
    if (!__query_available()) return;

    static const double values[] = { 0.1 + 0.2, 2.4626032915729627e-14, 1e300 / 3, 0.1, 19.99, -0.0, 5e-324 };
    static const char* const texts[] = { NULL, NULL, NULL, "0.1", "19.99", NULL, NULL };
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        dbresult_t* r = __query1("SELECT :d AS d", mparam_double(d, values[i]));
        db_table_cell_t* cell = dbresult_ok(r) ? dbresult_field(r, "d") : NULL;
        TEST_ASSERT_NOT_NULL(cell, "a value comes back");
        if (cell != NULL) {
            TEST_ASSERT(strtod(cell->value, NULL) == values[i], cell->value);
            if (texts[i] != NULL)
                TEST_ASSERT_STR_EQUAL(texts[i], cell->value, "in its shortest form");
        }
        dbresult_free(r);
    }
}

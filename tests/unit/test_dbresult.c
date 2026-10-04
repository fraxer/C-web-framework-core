#include "framework.h"

#include "dbresult.h"

/* framework/database/dbresult.c -- walking a result set, without a database.
 *
 * The cursor functions are the part of the API every driver shares, and the
 * db_query fuzz target walks results of any shape with them. What they must
 * never do, whatever the shape or the index: read outside the table, or claim
 * a position that is not there. */

static dbresult_t* __result(int rows, int cols) {
    dbresult_t* result = dbresult_create();
    dbresultquery_t* query = dbresult_query_create(rows, cols);
    for (int c = 0; c < cols; c++)
        dbresult_query_field_insert(query, c == 0 ? "a" : "b", c);
    for (int r = 0; r < rows; r++)
        for (int c = 0; c < cols; c++)
            dbresult_query_value_insert(query, "v", 1, r, c);
    result->query = query;
    result->current = query;
    result->ok = 1;
    return result;
}

TEST(test_dbresult_row_next_stops) {
    TEST_CASE("row_next and col_next stop on the last position");

    dbresult_t* r = __result(3, 2);
    TEST_ASSERT_EQUAL(1, dbresult_row_next(r), "to row 1");
    TEST_ASSERT_EQUAL(1, dbresult_row_next(r), "to row 2");
    TEST_ASSERT_EQUAL(0, dbresult_row_next(r), "no row 3");
    TEST_ASSERT_EQUAL(2, r->current->current_row, "still on row 2");
    TEST_ASSERT_EQUAL(1, dbresult_col_next(r), "to col 1");
    TEST_ASSERT_EQUAL(0, dbresult_col_next(r), "no col 2");
    dbresult_free(r);
}

TEST(test_dbresult_empty_result) {
    TEST_CASE("a result with no rows has no next row");

    /* row_next compared current_row + 1 with rows for equality: with no
     * rows it never matched, and a do { } while (dbresult_row_next(r)) over
     * an empty SELECT never ended. */
    dbresult_t* r = __result(0, 2);
    TEST_ASSERT_EQUAL(0, dbresult_row_next(r), "no row 1");
    TEST_ASSERT_EQUAL(0, r->current->current_row, "cursor not moved");
    TEST_ASSERT_NULL(dbresult_field(r, "a"), "no value on a row that does not exist");
    TEST_ASSERT_NULL(dbresult_field(r, NULL), "nor at the cursor");
    dbresult_free(r);

    r = __result(2, 0);
    TEST_ASSERT_EQUAL(0, dbresult_col_next(r), "no col 1 without columns");
    dbresult_free(r);
}

TEST(test_dbresult_set_bounds) {
    TEST_CASE("row_set and col_set accept exactly the positions that exist");

    /* They refused the last position and accepted every other number,
     * negative and past the end included -- and dbresult_cell then indexed
     * the table with it. */
    dbresult_t* r = __result(3, 2);
    TEST_ASSERT_EQUAL(1, dbresult_row_set(r, 2), "the last row");
    TEST_ASSERT_EQUAL(2, r->current->current_row, "is set");
    TEST_ASSERT_EQUAL(1, dbresult_row_set(r, 0), "the first row");
    TEST_ASSERT_EQUAL(0, dbresult_row_set(r, 3), "past the end");
    TEST_ASSERT_EQUAL(0, dbresult_row_set(r, -1), "negative");
    TEST_ASSERT_EQUAL(0, r->current->current_row, "refusals leave the cursor");
    TEST_ASSERT_EQUAL(1, dbresult_col_set(r, 1), "the last column");
    TEST_ASSERT_EQUAL(0, dbresult_col_set(r, 2), "past the end");
    TEST_ASSERT_EQUAL(0, dbresult_col_set(r, -1), "negative");
    dbresult_free(r);
}

TEST(test_dbresult_cell_bounds) {
    TEST_CASE("dbresult_cell refuses any index outside the table");

    dbresult_t* r = __result(2, 2);
    TEST_ASSERT_NOT_NULL(dbresult_cell(r, 1, 1), "inside");
    TEST_ASSERT_NULL(dbresult_cell(r, 2, 0), "row past the end");
    TEST_ASSERT_NULL(dbresult_cell(r, 0, 2), "col past the end");
    TEST_ASSERT_NULL(dbresult_cell(r, -1, 0), "negative row");
    TEST_ASSERT_NULL(dbresult_cell(r, 0, -1), "negative col");
    TEST_ASSERT_NULL(dbresult_field(r, "missing"), "no such column");
    dbresult_free(r);
}

TEST(test_dbresult_no_result_set) {
    TEST_CASE("a result without a result set, or none at all, is walked safely");

    /* An INSERT without RETURNING has no query; NULL is what a refused
     * dbquery returns. Both used to be dereferenced. */
    dbresult_t* r = dbresult_create();
    r->ok = 1;
    TEST_ASSERT_EQUAL(0, dbresult_row_next(r), "row_next");
    TEST_ASSERT_EQUAL(0, dbresult_col_next(r), "col_next");
    TEST_ASSERT_EQUAL(0, dbresult_query_cols(r), "cols");
    TEST_ASSERT_NULL(dbresult_field(r, NULL), "field at the cursor");
    TEST_ASSERT_NULL(dbresult_field(r, "a"), "field by name");
    TEST_ASSERT_NULL(dbresult_query_next(r), "query_next");
    dbresult_free(r);

    TEST_ASSERT_EQUAL(0, dbresult_ok(NULL), "ok");
    TEST_ASSERT_EQUAL(0, dbresult_row_next(NULL), "row_next(NULL)");
    TEST_ASSERT_EQUAL(0, dbresult_col_next(NULL), "col_next(NULL)");
    TEST_ASSERT_EQUAL(0, dbresult_row_set(NULL, 0), "row_set(NULL)");
    TEST_ASSERT_EQUAL(0, dbresult_col_set(NULL, 0), "col_set(NULL)");
    TEST_ASSERT_EQUAL(0, dbresult_query_rows(NULL), "rows(NULL)");
    TEST_ASSERT_EQUAL(0, dbresult_query_cols(NULL), "cols(NULL)");
    TEST_ASSERT_NULL(dbresult_field(NULL, "a"), "field(NULL)");
    TEST_ASSERT_NULL(dbresult_cell(NULL, 0, 0), "cell(NULL)");
    TEST_ASSERT_NULL(dbresult_query_next(NULL), "query_next(NULL)");
    TEST_ASSERT_NULL(dbresult_col_name(NULL, 0), "col_name(NULL)");
}

TEST(test_dbresult_materialized_ownership) {
    TEST_CASE("Legacy cells own mutable copies, distinguish NULL and preserve byte lengths");
    dbresult_t* result = dbresult_create();
    TEST_REQUIRE_NOT_NULL(result, "allocated");
    dbresultquery_t* query = dbresult_query_create(3, 1);
    TEST_REQUIRE_NOT_NULL(query, "table allocated");
    result->query = result->current = query;
    result->ok = 1;
    char name[] = "value";
    char bytes[] = {'a', 0, 'b'};
    dbresult_query_field_insert(query, name, 0);
    dbresult_query_value_insert(query, NULL, 0, 0, 0);
    dbresult_query_value_insert(query, "", 0, 1, 0);
    dbresult_query_value_insert(query, bytes, sizeof bytes, 2, 0);
    name[0] = 'x';
    bytes[0] = 'x';
    TEST_ASSERT_STR_EQUAL("value", dbresult_col_name(result, 0), "name is independent copy");
    db_table_cell_t* cell = dbresult_cell(result, 0, 0);
    TEST_ASSERT(cell && !cell->value && cell->length == 0, "SQL NULL");
    cell = dbresult_cell(result, 1, 0);
    TEST_ASSERT(cell && cell->value && cell->length == 0, "empty differs from NULL");
    cell = dbresult_cell(result, 2, 0);
    TEST_REQUIRE_NOT_NULL(cell, "byte cell");
    TEST_ASSERT(cell->value != bytes && cell->length == 3, "independent byte buffer");
    TEST_ASSERT(!memcmp(cell->value, "a\0b", 3), "embedded NUL preserved");
    cell->value[0] = 'z';
    TEST_ASSERT(dbresult_cell(result, 2, 0)->value[0] == 'z', "legacy cell remains writable");
    db_cell_free(cell);
    TEST_ASSERT(cell->value == NULL && cell->length == 0, "independent cell cleanup remains supported");
    dbresult_free(result);
}

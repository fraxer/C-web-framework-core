#ifdef TEST_DB_VIEW_ALLOC_FAILURES
#undef calloc
#undef strdup
#include <stdlib.h>
#include <string.h>
static int fail_view_alloc;
void* cwfr_test_view_calloc(size_t count, size_t size) {
    return fail_view_alloc ? NULL : calloc(count, size);
}
char* cwfr_test_view_strdup(const char* text) {
    return fail_view_alloc ? NULL : strdup(text);
}
#define calloc cwfr_test_view_calloc
#define strdup cwfr_test_view_strdup
#endif

#include "framework.h"
#include "dbresult_view_internal.h"

/* A driver-shaped owner with bytes that aren't C strings. No server is needed
 * to exercise ownership, invalid indices, chain traversal or NULL semantics.
 */
typedef struct {
    int frees;
    int reads;
    const char* name;
    const char* values[3];
    size_t lengths[3];
} view_owner_t;

static const char* view_name(const void* data, int col) {
    (void)col;
    return ((const view_owner_t*)data)->name;
}

static void view_cell(const void* data, int row, int col, const char** value, size_t* length) {
    (void)col;
    view_owner_t* owner = (view_owner_t*)data;
    owner->reads++;
    *value = owner->values[row];
    *length = owner->lengths[row];
}

static void view_free(void* data) {
    ((view_owner_t*)data)->frees++;
}

static const dbresult_view_ops_t view_ops = {view_name, view_cell, view_free};

TEST(test_dbresult_view_bytes_and_lifetime) {
    TEST_CASE("Read-only cells borrow exact bytes and owners survive cursor changes");
    const char bytes[] = {'a', 0, 'b'};
    view_owner_t first = {.name = "value", .values = {NULL, "", bytes}, .lengths = {0, 0, 3}};
    view_owner_t second = {.name = "empty"};
    view_owner_t command = {0};
    dbresult_view_t* view = dbresult_view_create();
    TEST_REQUIRE_NOT_NULL(view, "view allocated");
    TEST_ASSERT(dbresult_view_append(view, &first, &view_ops, 3, 1), "first owner transferred");
    TEST_ASSERT(dbresult_view_append(view, &second, &view_ops, 0, 1), "empty SELECT transferred");
    TEST_ASSERT(dbresult_view_append(view, &command, &view_ops, 0, 0), "command transferred");
    dbresult_view_set_ok(view);
    TEST_ASSERT(dbresult_view_ok(view), "successful result");
    TEST_ASSERT_NULL(dbresult_view_error(view), "no error");
    TEST_ASSERT(dbresult_view_col_name(view, 0) == first.name, "name borrowed");
    const char* value = bytes;
    size_t length = 99;
    TEST_ASSERT(dbresult_view_cell(view, 0, 0, &value, &length), "SQL NULL is a valid cell");
    TEST_ASSERT(value == NULL && length == 0, "SQL NULL distinguished");
    TEST_ASSERT(dbresult_view_cell(view, 1, 0, &value, &length), "empty string valid");
    TEST_ASSERT(value != NULL && length == 0, "empty is not NULL");
    TEST_ASSERT(dbresult_view_cell(view, 2, 0, &value, &length), "binary-safe cell");
    TEST_ASSERT(value == bytes && length == 3, "no copy or strlen");
    const char* saved = value;
    TEST_ASSERT(dbresult_view_query_next(view), "empty SELECT");
    TEST_ASSERT_EQUAL(0, dbresult_view_rows(view), "zero rows");
    TEST_ASSERT_EQUAL(1, dbresult_view_cols(view), "column retained");
    TEST_ASSERT(!dbresult_view_cell(view, 0, 0, &value, &length), "no empty row");
    TEST_ASSERT(saved == bytes && saved[2] == 'b' && first.frees == 0, "previous pointer alive");
    TEST_ASSERT(dbresult_view_query_next(view), "command result");
    TEST_ASSERT_EQUAL(0, dbresult_view_cols(view), "command has no columns");
    TEST_ASSERT(!dbresult_view_query_next(view), "chain exhausted");
    TEST_ASSERT(dbresult_view_query_first(view), "return to first");
    TEST_ASSERT_EQUAL(3, dbresult_view_rows(view), "first dimensions restored");
    dbresult_view_free(view);
    TEST_ASSERT(first.frees == 1 && second.frees == 1 && command.frees == 1, "each owner freed exactly once");
}

TEST(test_dbresult_view_refusals_and_errors) {
    TEST_CASE("Invalid reads are refused before driver callbacks; errors own their text");
    view_owner_t owner = {.name = "v", .values = {"v"}, .lengths = {1}};
    dbresult_view_t* view = dbresult_view_create();
    TEST_REQUIRE_NOT_NULL(view, "allocated");
    TEST_ASSERT(!dbresult_view_ok(view), "empty initialization unsuccessful");
    TEST_ASSERT(!dbresult_view_query_first(view), "no first result");
    TEST_ASSERT(!dbresult_view_append(view, &owner, &view_ops, -1, 1), "negative dimensions refused");
    TEST_ASSERT_EQUAL(0, owner.frees, "refusal does not take ownership");
    TEST_ASSERT(dbresult_view_append(view, &owner, &view_ops, 1, 1), "owner transferred");
    const int indices[][2] = {{-1, 0}, {0, -1}, {1, 0}, {0, 1}};
    for (size_t i = 0; i < sizeof indices / sizeof indices[0]; i++) {
        const char* value = "sentinel";
        size_t length = 42;
        TEST_ASSERT(!dbresult_view_cell(view, indices[i][0], indices[i][1], &value, &length), "out of bounds");
        TEST_ASSERT(value == NULL && length == 0, "outputs reset");
    }
    TEST_ASSERT_NULL(dbresult_view_col_name(view, -1), "negative column");
    TEST_ASSERT_NULL(dbresult_view_col_name(view, 1), "past last column");
    size_t length = 42;
    TEST_ASSERT(!dbresult_view_cell(view, 0, 0, NULL, &length), "missing output refused");
    TEST_ASSERT_EQUAL(0, owner.reads, "invalid reads never invoke driver");
    char error[] = "original SQL error";
    dbresult_view_set_error(view, error);
    memset(error, 'x', sizeof error - 1);
    dbresult_view_set_error(view, "later error");
    dbresult_view_set_ok(view);
    TEST_ASSERT(!dbresult_view_ok(view), "failure sticky");
    TEST_ASSERT_STR_EQUAL("original SQL error", dbresult_view_error(view), "first error copied");
    dbresult_view_free(view);
    TEST_ASSERT_EQUAL(1, owner.frees, "failed view releases owner");
    TEST_ASSERT(!dbresult_view_ok(NULL), "NULL not successful");
    TEST_ASSERT_NULL(dbresult_view_error(NULL), "NULL error");
    TEST_ASSERT_NULL(dbresult_view_col_name(NULL, 0), "NULL column");
    TEST_ASSERT_EQUAL(0, dbresult_view_rows(NULL), "NULL rows");
    TEST_ASSERT_EQUAL(0, dbresult_view_cols(NULL), "NULL columns");
    TEST_ASSERT(!dbresult_view_query_next(NULL), "NULL traversal");
    TEST_ASSERT(!dbresult_view_cell(NULL, 0, 0, NULL, NULL), "NULL read");
    dbresult_view_free(NULL);
}

#ifdef TEST_DB_VIEW_ALLOC_FAILURES
TEST(test_dbresult_view_allocation_failures) {
    TEST_CASE("Metadata allocation failures do not transfer ownership or lose prior owners");
    fail_view_alloc = 1;
    dbresult_view_t* view = dbresult_view_create();
    fail_view_alloc = 0;
    TEST_ASSERT_NULL(view, "failed empty allocation");
    view = dbresult_view_create();
    TEST_REQUIRE_NOT_NULL(view, "allocated");
    view_owner_t first = {0}, rejected = {0};
    TEST_ASSERT(dbresult_view_append(view, &first, &view_ops, 0, 0), "first owner");
    fail_view_alloc = 1;
    int appended = dbresult_view_append(view, &rejected, &view_ops, 0, 0);
    dbresult_view_set_error(view, "metadata allocation failed");
    fail_view_alloc = 0;
    TEST_ASSERT(!appended, "second allocation refused");
    TEST_ASSERT(!dbresult_view_ok(view), "allocation failure unsuccessful");
    TEST_ASSERT_STR_EQUAL("Out of memory", dbresult_view_error(view), "fallback when copying error fails");
    dbresult_view_free(view);
    TEST_ASSERT_EQUAL(1, first.frees, "prior owner freed once");
    TEST_ASSERT_EQUAL(0, rejected.frees, "rejected owner still belongs to driver");
    view_free(&rejected);
    TEST_ASSERT_EQUAL(1, rejected.frees, "driver frees rejected owner once");
}
#endif

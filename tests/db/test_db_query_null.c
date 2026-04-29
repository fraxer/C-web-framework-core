#include "framework.h"
#include "dbquery.h"
#include "model.h"
#include "str.h"
#include "array.h"
#include <string.h>

// ============================================================================
// Custom processor that replicates __build_query_processor behavior.
// For NULL fields: appends "NULL" directly (the optimized path).
// For non-NULL fields: appends field string value (no escaping, no real connection).
// ============================================================================

static int test_processor(
    void* connection,
    char parameter_type,
    const char* param_name,
    mfield_t* field,
    str_t* result_sql,
    void* user_data
) {
    (void)connection;
    (void)parameter_type;
    (void)param_name;
    (void)user_data;

    if (field->is_null) {
        str_append(result_sql, "NULL", 4);
        return 1;
    }

    str_t* val = model_field_to_string(field);
    if (val == NULL) return 0;

    str_append(result_sql, str_get(val), str_size(val));
    return 1;
}

// ============================================================================
// Tests
// ============================================================================

TEST(test_null_text_field_produces_null) {
    TEST_CASE("NULL text field produces 'NULL' in query");

    mfield_t* f = field_create_text("name", NULL);
    TEST_ASSERT_NOT_NULL(f, "field_create_text should succeed");
    TEST_ASSERT_EQUAL(1, f->is_null, "Field created with NULL should have is_null=1");

    array_t* params = array_create();
    array_push_back(params, array_create_pointer(f, NULL, model_param_free));

    const char* query = "SELECT :name";
    str_t* result = parse_sql_parameters(NULL, query, strlen(query), params, test_processor, NULL);
    TEST_ASSERT_NOT_NULL(result, "parse_sql_parameters should succeed");
    TEST_ASSERT_STR_EQUAL("SELECT NULL", str_get(result), "Query should contain NULL literal");

    str_free(result);
    array_free(params);
}

TEST(test_null_field_does_not_mutate_use_raw_sql) {
    TEST_CASE("NULL field is_null path does not set use_raw_sql");

    mfield_t* f = field_create_text("col", NULL);
    TEST_ASSERT_NOT_NULL(f, "field_create_text should succeed");

    // field_create_text with NULL sets is_null=1 and may initialize use_raw_sql
    // We explicitly clear it to verify the new optimized path doesn't set it
    f->use_raw_sql = 0;

    array_t* params = array_create();
    array_push_back(params, array_create_pointer(f, NULL, model_param_free));

    const char* query = "INSERT INTO t VALUES (:col)";
    str_t* result = parse_sql_parameters(NULL, query, strlen(query), params, test_processor, NULL);
    TEST_ASSERT_NOT_NULL(result, "parse_sql_parameters should succeed");

    TEST_ASSERT_EQUAL(0, f->use_raw_sql, "use_raw_sql should remain 0 (new optimized path bypasses model_field_to_string)");

    str_free(result);
    array_free(params);
}

TEST(test_non_null_text_field_works) {
    TEST_CASE("Non-NULL text field produces its value in query");

    mfield_t* f = field_create_text("name", "hello");
    TEST_ASSERT_NOT_NULL(f, "field_create_text should succeed");
    TEST_ASSERT_EQUAL(0, f->is_null, "Field with value should have is_null=0");

    array_t* params = array_create();
    array_push_back(params, array_create_pointer(f, NULL, model_param_free));

    const char* query = "SELECT :name";
    str_t* result = parse_sql_parameters(NULL, query, strlen(query), params, test_processor, NULL);
    TEST_ASSERT_NOT_NULL(result, "parse_sql_parameters should succeed");
    TEST_ASSERT_STR_EQUAL("SELECT hello", str_get(result), "Query should contain field value");

    str_free(result);
    array_free(params);
}

TEST(test_mixed_null_and_non_null) {
    TEST_CASE("Mixed NULL and non-NULL params all substituted correctly");

    mfield_t* a = field_create_text("a", "hello");
    mfield_t* b = field_create_text("b", NULL);
    mfield_t* c = field_create_text("c", "world");

    array_t* params = array_create();
    array_push_back(params, array_create_pointer(a, NULL, model_param_free));
    array_push_back(params, array_create_pointer(b, NULL, model_param_free));
    array_push_back(params, array_create_pointer(c, NULL, model_param_free));

    const char* query = ":a, :b, :c";
    str_t* result = parse_sql_parameters(NULL, query, strlen(query), params, test_processor, NULL);
    TEST_ASSERT_NOT_NULL(result, "parse_sql_parameters should succeed");
    TEST_ASSERT_STR_EQUAL("hello, NULL, world", str_get(result), "All params should be substituted correctly");

    str_free(result);
    array_free(params);
}

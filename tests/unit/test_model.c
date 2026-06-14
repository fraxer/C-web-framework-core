#define _GNU_SOURCE
#include "framework.h"
#include "model.h"
#include "model_internal.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

// ============================================================================
// field_create_bool
// ============================================================================

TEST(test_field_create_bool_basic) {
    TEST_CASE("Create bool field with true value");

    mfield_t* field = field_create_bool("active", 1);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_BOOL, field->type, "Type should be MODEL_BOOL");
    TEST_ASSERT_EQUAL(1, field->value._short, "Value should be 1");
    TEST_ASSERT_EQUAL(0, field->dirty, "Should not be dirty");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");
    TEST_ASSERT_STR_EQUAL("active", field->name, "Name should be 'active'");

    model_param_free(field);
}

TEST(test_field_create_bool_false) {
    TEST_CASE("Create bool field with false value");

    mfield_t* field = field_create_bool("active", 0);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(0, field->value._short, "Value should be 0");

    model_param_free(field);
}

// ============================================================================
// field_create_smallint
// ============================================================================

TEST(test_field_create_smallint) {
    TEST_CASE("Create smallint field");

    mfield_t* field = field_create_smallint("age", 42);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_SMALLINT, field->type, "Type should be MODEL_SMALLINT");
    TEST_ASSERT_EQUAL(42, field->value._short, "Value should be 42");

    model_param_free(field);
}

TEST(test_field_create_smallint_negative) {
    TEST_CASE("Create smallint field with negative value");

    mfield_t* field = field_create_smallint("delta", -100);
    TEST_ASSERT_EQUAL(-100, field->value._short, "Value should be -100");

    model_param_free(field);
}

// ============================================================================
// field_create_int
// ============================================================================

TEST(test_field_create_int) {
    TEST_CASE("Create int field");

    mfield_t* field = field_create_int("count", 12345);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_INT, field->type, "Type should be MODEL_INT");
    TEST_ASSERT_EQUAL(12345, field->value._int, "Value should be 12345");

    model_param_free(field);
}

TEST(test_field_create_int_zero) {
    TEST_CASE("Create int field with zero");

    mfield_t* field = field_create_int("zero", 0);
    TEST_ASSERT_EQUAL(0, field->value._int, "Value should be 0");

    model_param_free(field);
}

TEST(test_field_create_int_negative) {
    TEST_CASE("Create int field with negative value");

    mfield_t* field = field_create_int("neg", -99999);
    TEST_ASSERT_EQUAL(-99999, field->value._int, "Value should be -99999");

    model_param_free(field);
}

// ============================================================================
// field_create_bigint
// ============================================================================

TEST(test_field_create_bigint) {
    TEST_CASE("Create bigint field");

    mfield_t* field = field_create_bigint("id", 9223372036854775807LL);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_BIGINT, field->type, "Type should be MODEL_BIGINT");
    TEST_ASSERT_EQUAL(9223372036854775807LL, field->value._bigint, "Value should be INT64_MAX");

    model_param_free(field);
}

TEST(test_field_create_bigint_negative) {
    TEST_CASE("Create bigint field with negative value");

    mfield_t* field = field_create_bigint("big_id", -9223372036854775807LL);
    TEST_ASSERT_EQUAL(-9223372036854775807LL, field->value._bigint, "Value should match");

    model_param_free(field);
}

// ============================================================================
// field_create_float
// ============================================================================

TEST(test_field_create_float) {
    TEST_CASE("Create float field");

    mfield_t* field = field_create_float("ratio", 3.14f);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_FLOAT, field->type, "Type should be MODEL_FLOAT");
    TEST_ASSERT_EQUAL(1, fabsf(field->value._float - 3.14f) < 0.001f, "Value should be ~3.14");

    model_param_free(field);
}

// ============================================================================
// field_create_double
// ============================================================================

TEST(test_field_create_double) {
    TEST_CASE("Create double field");

    mfield_t* field = field_create_double("price", 99.99);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_DOUBLE, field->type, "Type should be MODEL_DOUBLE");
    TEST_ASSERT_EQUAL(1, fabs(field->value._double - 99.99) < 0.001, "Value should be ~99.99");

    model_param_free(field);
}

// ============================================================================
// field_create_decimal
// ============================================================================

TEST(test_field_create_decimal) {
    TEST_CASE("Create decimal field");

    mfield_t* field = field_create_decimal("amount", 12345.6789L);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_DECIMAL, field->type, "Type should be MODEL_DECIMAL");
    TEST_ASSERT_EQUAL(1, fabsl(field->value._ldouble - 12345.6789L) < 0.001L, "Value should match");

    model_param_free(field);
}

// ============================================================================
// field_create_money
// ============================================================================

TEST(test_field_create_money) {
    TEST_CASE("Create money field");

    mfield_t* field = field_create_money("salary", 50000.50);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_MONEY, field->type, "Type should be MODEL_MONEY");
    TEST_ASSERT_EQUAL(1, fabs(field->value._double - 50000.50) < 0.01, "Value should match");

    model_param_free(field);
}

// ============================================================================
// field_create_date
// ============================================================================

TEST(test_field_create_date_with_value) {
    TEST_CASE("Create date field with value");

    tm_t val = {0};
    val.tm_year = 125; val.tm_mon = 4; val.tm_mday = 14;
    mfield_t* field = field_create_date("birthday", &val);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_DATE, field->type, "Type should be MODEL_DATE");
    TEST_ASSERT_EQUAL(125, field->value._tm.tm_year, "Year should be 125");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");
    TEST_ASSERT_EQUAL(0, field->use_raw_sql, "use_raw_sql should be 0");

    model_param_free(field);
}

TEST(test_field_create_date_null) {
    TEST_CASE("Create date field with NULL value");

    mfield_t* field = field_create_date("birthday", NULL);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1 for NULL date");

    model_param_free(field);
}

// ============================================================================
// field_create_time
// ============================================================================

TEST(test_field_create_time_with_value) {
    TEST_CASE("Create time field with value");

    tm_t val = {0};
    val.tm_hour = 14; val.tm_min = 30; val.tm_sec = 0;
    mfield_t* field = field_create_time("start_time", &val);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_TIME, field->type, "Type should be MODEL_TIME");
    TEST_ASSERT_EQUAL(14, field->value._tm.tm_hour, "Hour should be 14");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");

    model_param_free(field);
}

TEST(test_field_create_time_null) {
    TEST_CASE("Create time field with NULL");

    mfield_t* field = field_create_time("start_time", NULL);
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

// ============================================================================
// field_create_varchar / binary / char / text
// ============================================================================

TEST(test_field_create_varchar_with_value) {
    TEST_CASE("Create varchar field with value");

    mfield_t* field = field_create_varchar("name", "hello");
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_VARCHAR, field->type, "Type should be MODEL_VARCHAR");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");
    TEST_ASSERT_STR_EQUAL("hello", str_get(field->value._string), "Value should be 'hello'");

    model_param_free(field);
}

TEST(test_field_create_varchar_null) {
    TEST_CASE("Create varchar field with NULL");

    mfield_t* field = field_create_varchar("name", NULL);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

TEST(test_field_create_text_with_value) {
    TEST_CASE("Create text field with value");

    mfield_t* field = field_create_text("body", "some long text");
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_TEXT, field->type, "Type should be MODEL_TEXT");
    TEST_ASSERT_STR_EQUAL("some long text", str_get(field->value._string), "Value should match");

    model_param_free(field);
}

TEST(test_field_create_text_null) {
    TEST_CASE("Create text field with NULL");

    mfield_t* field = field_create_text("body", NULL);
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

TEST(test_field_create_binary_with_value) {
    TEST_CASE("Create binary field with value");

    mfield_t* field = field_create_binary("data", "rawdata");
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_BINARY, field->type, "Type should be MODEL_BINARY");
    TEST_ASSERT_STR_EQUAL("rawdata", str_get(field->value._string), "Value should match");

    model_param_free(field);
}

TEST(test_field_create_binary_null) {
    TEST_CASE("Create binary field with NULL");

    mfield_t* field = field_create_binary("data", NULL);
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

TEST(test_field_create_char_with_value) {
    TEST_CASE("Create char field with value");

    mfield_t* field = field_create_char("code", "A");
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_CHAR, field->type, "Type should be MODEL_CHAR");
    TEST_ASSERT_STR_EQUAL("A", str_get(field->value._string), "Value should be 'A'");

    model_param_free(field);
}

TEST(test_field_create_char_null) {
    TEST_CASE("Create char field with NULL");

    mfield_t* field = field_create_char("code", NULL);
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

// ============================================================================
// field_create_json
// ============================================================================

TEST(test_field_create_json_null) {
    TEST_CASE("Create json field with NULL");

    mfield_t* field = field_create_json("meta", NULL);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_JSON, field->type, "Type should be MODEL_JSON");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

// ============================================================================
// field_create_enum
// ============================================================================

TEST(test_field_create_enum_with_value) {
    TEST_CASE("Create enum field with default value");

    char* values[] = {"active", "inactive", "deleted"};
    mfield_t* field = field_create_enum("status", "active", values, 3);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_ENUM, field->type, "Type should be MODEL_ENUM");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");
    TEST_ASSERT_STR_EQUAL("active", str_get(field->value._string), "Value should be 'active'");

    model_param_free(field);
}

TEST(test_field_create_enum_null_default) {
    TEST_CASE("Create enum field with NULL default");

    char* values[] = {"a", "b"};
    mfield_t* field = field_create_enum("status", NULL, values, 2);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

// ============================================================================
// field_create_array
// ============================================================================

TEST(test_field_create_array_with_value) {
    TEST_CASE("Create array field with value");

    array_t* arr = array_create();
    array_push_back(arr, array_create_string("item1"));
    mfield_t* field = field_create_array("tags", arr);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(MODEL_ARRAY, field->type, "Type should be MODEL_ARRAY");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");

    model_param_free(field);
}

TEST(test_field_create_array_null) {
    TEST_CASE("Create array field with NULL");

    mfield_t* field = field_create_array("tags", NULL);
    TEST_ASSERT_NOT_NULL(field, "Field should not be NULL");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

// ============================================================================
// model_set_bool / model_bool
// ============================================================================

TEST(test_model_set_bool_and_get) {
    TEST_CASE("Set and get bool value");

    mfield_t* field = field_create_bool("flag", 0);
    TEST_ASSERT_EQUAL(0, model_bool(field), "Initial should be 0");

    int res = model_set_bool(field, 1);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(1, model_bool(field), "Should be 1 after set");
    TEST_ASSERT_EQUAL(1, field->dirty, "Should be dirty");
    TEST_ASSERT_EQUAL(0, field->oldvalue._short, "Old value should be 0");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");
    TEST_ASSERT_EQUAL(0, field->use_raw_sql, "use_raw_sql should be 0");

    model_param_free(field);
}

TEST(test_model_set_bool_null_field) {
    TEST_CASE("Set bool on NULL field returns 0");

    int res = model_set_bool(NULL, 1);
    TEST_ASSERT_EQUAL(0, res, "Should return 0");
}

TEST(test_model_set_bool_wrong_type) {
    TEST_CASE("Set bool on wrong type field returns 0");

    mfield_t* field = field_create_int("num", 5);
    int res = model_set_bool(field, 1);
    TEST_ASSERT_EQUAL(0, res, "Should return 0 for wrong type");

    model_param_free(field);
}

TEST(test_model_bool_null_field) {
    TEST_CASE("Get bool from NULL field returns 0");

    TEST_ASSERT_EQUAL(0, model_bool(NULL), "Should return 0");
}

TEST(test_model_bool_wrong_type) {
    TEST_CASE("Get bool from wrong type field returns 0");

    mfield_t* field = field_create_int("num", 42);
    TEST_ASSERT_EQUAL(0, model_bool(field), "Should return 0 for wrong type");

    model_param_free(field);
}

TEST(test_model_set_bool_twice_preserves_first_oldvalue) {
    TEST_CASE("Setting bool twice keeps original oldvalue");

    mfield_t* field = field_create_bool("flag", 0);
    model_set_bool(field, 1);
    model_set_bool(field, 0);

    TEST_ASSERT_EQUAL(0, field->oldvalue._short, "Old value should still be initial 0");
    TEST_ASSERT_EQUAL(0, model_bool(field), "Current value should be 0");
    TEST_ASSERT_EQUAL(1, field->dirty, "Should still be dirty");

    model_param_free(field);
}

// ============================================================================
// model_set_int / model_int
// ============================================================================

TEST(test_model_set_int_and_get) {
    TEST_CASE("Set and get int value");

    mfield_t* field = field_create_int("count", 0);
    int res = model_set_int(field, 42);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(42, model_int(field), "Should be 42");
    TEST_ASSERT_EQUAL(1, field->dirty, "Should be dirty");
    TEST_ASSERT_EQUAL(0, field->oldvalue._int, "Old value should be 0");

    model_param_free(field);
}

TEST(test_model_int_null_field) {
    TEST_CASE("Get int from NULL field returns 0");
    TEST_ASSERT_EQUAL(0, model_int(NULL), "Should return 0");
}

TEST(test_model_set_int_wrong_type) {
    TEST_CASE("Set int on wrong type returns 0");

    mfield_t* field = field_create_bool("flag", 1);
    TEST_ASSERT_EQUAL(0, model_set_int(field, 5), "Should return 0");

    model_param_free(field);
}

// ============================================================================
// model_set_bigint / model_bigint
// ============================================================================

TEST(test_model_set_bigint_and_get) {
    TEST_CASE("Set and get bigint value");

    mfield_t* field = field_create_bigint("id", 0);
    int res = model_set_bigint(field, 123456789012LL);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(123456789012LL, model_bigint(field), "Should match");
    TEST_ASSERT_EQUAL(1, field->dirty, "Should be dirty");

    model_param_free(field);
}

TEST(test_model_bigint_null_field) {
    TEST_CASE("Get bigint from NULL field returns 0");
    TEST_ASSERT_EQUAL(0, model_bigint(NULL), "Should return 0");
}

// ============================================================================
// model_set_smallint / model_smallint
// ============================================================================

TEST(test_model_set_smallint_and_get) {
    TEST_CASE("Set and get smallint value");

    mfield_t* field = field_create_smallint("val", 0);
    int res = model_set_smallint(field, 100);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(100, model_smallint(field), "Should be 100");

    model_param_free(field);
}

// ============================================================================
// model_set_float / model_float
// ============================================================================

TEST(test_model_set_float_and_get) {
    TEST_CASE("Set and get float value");

    mfield_t* field = field_create_float("ratio", 0.0f);
    int res = model_set_float(field, 2.5f);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(1, fabsf(model_float(field) - 2.5f) < 0.001f, "Should be ~2.5");

    model_param_free(field);
}

TEST(test_model_float_null_field) {
    TEST_CASE("Get float from NULL field returns 0.0");
    TEST_ASSERT_EQUAL(1, model_float(NULL) == 0.0f, "Should return 0.0");
}

// ============================================================================
// model_set_double / model_double
// ============================================================================

TEST(test_model_set_double_and_get) {
    TEST_CASE("Set and get double value");

    mfield_t* field = field_create_double("price", 0.0);
    int res = model_set_double(field, 99.99);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(1, fabs(model_double(field) - 99.99) < 0.001, "Should be ~99.99");

    model_param_free(field);
}

// ============================================================================
// model_set_decimal / model_decimal
// ============================================================================

TEST(test_model_set_decimal_and_get) {
    TEST_CASE("Set and get decimal value");

    mfield_t* field = field_create_decimal("amount", 0.0L);
    int res = model_set_decimal(field, 123.456L);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(1, fabsl(model_decimal(field) - 123.456L) < 0.001L, "Should match");

    model_param_free(field);
}

// ============================================================================
// model_set_money / model_money
// ============================================================================

TEST(test_model_set_money_and_get) {
    TEST_CASE("Set and get money value");

    mfield_t* field = field_create_money("salary", 0.0);
    int res = model_set_money(field, 75000.50);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(1, fabs(model_money(field) - 75000.50) < 0.01, "Should match");

    model_param_free(field);
}

// ============================================================================
// model_set_varchar / model_varchar
// ============================================================================

TEST(test_model_set_varchar_and_get) {
    TEST_CASE("Set and get varchar value");

    mfield_t* field = field_create_varchar("name", "old");
    int res = model_set_varchar(field, "new");
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_STR_EQUAL("new", str_get(model_varchar(field)), "Should be 'new'");
    TEST_ASSERT_EQUAL(1, field->dirty, "Should be dirty");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");
    TEST_ASSERT_EQUAL(0, field->use_raw_sql, "use_raw_sql should be 0");

    model_param_free(field);
}

TEST(test_model_set_varchar_null) {
    TEST_CASE("Set varchar to NULL value");

    mfield_t* field = field_create_varchar("name", "old");
    int res = model_set_varchar(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");
    TEST_ASSERT_EQUAL(0, field->use_raw_sql, "use_raw_sql should be 0");

    model_param_free(field);
}

TEST(test_model_varchar_null_field) {
    TEST_CASE("Get varchar from NULL field returns NULL");
    TEST_ASSERT_NULL(model_varchar(NULL), "Should return NULL");
}

TEST(test_model_varchar_wrong_type) {
    TEST_CASE("Get varchar from wrong type returns NULL");

    mfield_t* field = field_create_int("num", 5);
    TEST_ASSERT_NULL(model_varchar(field), "Should return NULL for wrong type");

    model_param_free(field);
}

// ============================================================================
// model_set_text / model_text
// ============================================================================

TEST(test_model_set_text_and_get) {
    TEST_CASE("Set and get text value");

    mfield_t* field = field_create_text("body", "old text");
    int res = model_set_text(field, "new text");
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_STR_EQUAL("new text", str_get(model_text(field)), "Should be 'new text'");

    model_param_free(field);
}

// ============================================================================
// model_set_char / model_char
// ============================================================================

TEST(test_model_set_char_and_get) {
    TEST_CASE("Set and get char value");

    mfield_t* field = field_create_char("code", "A");
    int res = model_set_char(field, "B");
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_STR_EQUAL("B", str_get(model_char(field)), "Should be 'B'");

    model_param_free(field);
}

// ============================================================================
// model_set_binary / model_binary
// ============================================================================

TEST(test_model_set_binary_and_get) {
    TEST_CASE("Set and get binary value");

    mfield_t* field = field_create_binary("data", "");
    int res = model_set_binary(field, "payload", 7);
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_EQUAL(7, str_size(model_binary(field)), "Size should be 7");

    model_param_free(field);
}

// ============================================================================
// model_set_enum / model_enum
// ============================================================================

TEST(test_model_set_enum_and_get) {
    TEST_CASE("Set and get enum value");

    char* values[] = {"pending", "active", "done"};
    mfield_t* field = field_create_enum("status", "pending", values, 3);
    int res = model_set_enum(field, "active");
    TEST_ASSERT_EQUAL(1, res, "Set should succeed");
    TEST_ASSERT_STR_EQUAL("active", str_get(model_enum(field)), "Should be 'active'");

    model_param_free(field);
}

TEST(test_model_set_enum_invalid) {
    TEST_CASE("Set enum to invalid value returns 0");

    char* values[] = {"a", "b"};
    mfield_t* field = field_create_enum("st", "a", values, 2);
    int res = model_set_enum(field, "invalid");
    TEST_ASSERT_EQUAL(0, res, "Should return 0 for invalid enum value");

    model_param_free(field);
}

TEST(test_model_set_enum_null) {
    TEST_CASE("Set enum to NULL value (zero-length)");

    char* values[] = {"a", "b"};
    mfield_t* field = field_create_enum("st", "a", values, 2);
    int res = model_set_enum(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed with NULL (size=0)");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

// ============================================================================
// model_set_bool_from_str
// ============================================================================

TEST(test_model_set_bool_from_str_true_values) {
    TEST_CASE("Parse bool from '1', 'true', 't'");

    const char* true_vals[] = {"1", "true", "t"};
    for (int i = 0; i < 3; i++) {
        mfield_t* field = field_create_bool("b", 0);
        int res = model_set_bool_from_str(field, true_vals[i]);
        TEST_ASSERT_EQUAL(1, res, "Should succeed");
        TEST_ASSERT_EQUAL(1, model_bool(field), "Should be true");

        model_param_free(field);
    }
}

TEST(test_model_set_bool_from_str_false_values) {
    TEST_CASE("Parse bool from '0', 'false', 'f'");

    const char* false_vals[] = {"0", "false", "f"};
    for (int i = 0; i < 3; i++) {
        mfield_t* field = field_create_bool("b", 1);
        int res = model_set_bool_from_str(field, false_vals[i]);
        TEST_ASSERT_EQUAL(1, res, "Should succeed");
        TEST_ASSERT_EQUAL(0, model_bool(field), "Should be false");

        model_param_free(field);
    }
}

TEST(test_model_set_bool_from_str_null) {
    TEST_CASE("Parse bool from NULL sets is_null");

    mfield_t* field = field_create_bool("b", 0);
    int res = model_set_bool_from_str(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_bool_from_str_null_field) {
    TEST_CASE("Parse bool from NULL field returns 0");

    TEST_ASSERT_EQUAL(0, model_set_bool_from_str(NULL, "1"), "Should return 0");
}

TEST(test_model_set_bool_from_str_invalid) {
    TEST_CASE("Parse bool from invalid string returns 0");

    mfield_t* field = field_create_bool("b", 0);
    TEST_ASSERT_EQUAL(0, model_set_bool_from_str(field, "yes"), "Should fail for 'yes'");
    TEST_ASSERT_EQUAL(0, model_set_bool_from_str(field, "2"), "Should fail for '2'");

    model_param_free(field);
}

// ============================================================================
// model_set_int_from_str / model_set_smallint_from_str
// ============================================================================

TEST(test_model_set_int_from_str) {
    TEST_CASE("Parse int from string");

    mfield_t* field = field_create_int("n", 0);
    int res = model_set_int_from_str(field, "42");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(42, model_int(field), "Should be 42");

    model_param_free(field);
}

TEST(test_model_set_int_from_str_null) {
    TEST_CASE("Parse int from NULL sets is_null");

    mfield_t* field = field_create_int("n", 0);
    int res = model_set_int_from_str(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_int_from_str_null_field) {
    TEST_CASE("Parse int from NULL field returns 0");
    TEST_ASSERT_EQUAL(0, model_set_int_from_str(NULL, "5"), "Should return 0");
}

TEST(test_model_set_smallint_from_str) {
    TEST_CASE("Parse smallint from string");

    mfield_t* field = field_create_smallint("n", 0);
    int res = model_set_smallint_from_str(field, "-10");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(-10, model_smallint(field), "Should be -10");

    model_param_free(field);
}

// ============================================================================
// model_set_bigint_from_str
// ============================================================================

TEST(test_model_set_bigint_from_str) {
    TEST_CASE("Parse bigint from string");

    mfield_t* field = field_create_bigint("id", 0);
    int res = model_set_bigint_from_str(field, "9999999999");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(9999999999LL, model_bigint(field), "Should match");

    model_param_free(field);
}

TEST(test_model_set_bigint_from_str_null) {
    TEST_CASE("Parse bigint from NULL sets is_null");

    mfield_t* field = field_create_bigint("id", 0);
    int res = model_set_bigint_from_str(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

// ============================================================================
// model_set_float_from_str / model_set_double_from_str
// ============================================================================

TEST(test_model_set_float_from_str) {
    TEST_CASE("Parse float from string");

    mfield_t* field = field_create_float("r", 0.0f);
    int res = model_set_float_from_str(field, "3.14");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, fabsf(model_float(field) - 3.14f) < 0.01f, "Should be ~3.14");

    model_param_free(field);
}

TEST(test_model_set_double_from_str) {
    TEST_CASE("Parse double from string");

    mfield_t* field = field_create_double("d", 0.0);
    int res = model_set_double_from_str(field, "99.99");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, fabs(model_double(field) - 99.99) < 0.01, "Should be ~99.99");

    model_param_free(field);
}

// ============================================================================
// model_set_decimal_from_str / model_set_money_from_str
// ============================================================================

TEST(test_model_set_decimal_from_str) {
    TEST_CASE("Parse decimal from string");

    mfield_t* field = field_create_decimal("amt", 0.0L);
    int res = model_set_decimal_from_str(field, "123.456");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, fabsl(model_decimal(field) - 123.456L) < 0.01L, "Should match");

    model_param_free(field);
}

TEST(test_model_set_money_from_str) {
    TEST_CASE("Parse money from string");

    mfield_t* field = field_create_money("sal", 0.0);
    int res = model_set_money_from_str(field, "50000.50");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, fabs(model_money(field) - 50000.50) < 0.01, "Should match");

    model_param_free(field);
}

TEST(test_model_set_decimal_from_str_null) {
    TEST_CASE("Parse decimal from NULL sets is_null");

    mfield_t* field = field_create_decimal("d", 0.0L);
    int res = model_set_decimal_from_str(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

// ============================================================================
// model_set_date_from_str
// ============================================================================

TEST(test_model_set_date_from_str) {
    TEST_CASE("Parse date from string");

    mfield_t* field = field_create_date("d", NULL);
    int res = model_set_date_from_str(field, "2025-05-14 00:00:00");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(125, field->value._tm.tm_year, "Year should be 125");
    TEST_ASSERT_EQUAL(4, field->value._tm.tm_mon, "Month should be 4 (May)");
    TEST_ASSERT_EQUAL(14, field->value._tm.tm_mday, "Day should be 14");

    model_param_free(field);
}

TEST(test_model_set_date_from_str_null) {
    TEST_CASE("Parse date from NULL sets is_null");

    mfield_t* field = field_create_date("d", NULL);
    int res = model_set_date_from_str(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_date_from_str_wrong_type) {
    TEST_CASE("Parse date on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_date_from_str(field, "2025-05-14 00:00:00"), "Should fail");

    model_param_free(field);
}

TEST(test_model_set_date_from_str_empty) {
    TEST_CASE("Parse date from empty string succeeds (zeroed tm)");

    mfield_t* field = field_create_date("d", NULL);
    int res = model_set_date_from_str(field, "");
    TEST_ASSERT_EQUAL(1, res, "Empty string should succeed");

    model_param_free(field);
}

// ============================================================================
// model_set_json_from_str
// ============================================================================

TEST(test_model_set_json_from_str) {
    TEST_CASE("Parse JSON from string");

    mfield_t* field = field_create_json("meta", NULL);
    int res = model_set_json_from_str(field, "{\"key\":\"value\"}");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");
    TEST_ASSERT_NOT_NULL(field->value._jsondoc, "JSON doc should not be NULL");

    model_param_free(field);
}

TEST(test_model_set_json_from_str_null) {
    TEST_CASE("Parse JSON from NULL sets is_null");

    mfield_t* field = field_create_json("meta", NULL);
    int res = model_set_json_from_str(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_json_from_str_invalid) {
    TEST_CASE("Parse JSON from invalid string returns 0");

    mfield_t* field = field_create_json("meta", NULL);
    int res = model_set_json_from_str(field, "not json");
    TEST_ASSERT_EQUAL(0, res, "Should fail for invalid JSON");

    model_param_free(field);
}

TEST(test_model_set_json_from_str_wrong_type) {
    TEST_CASE("Parse JSON on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_json_from_str(field, "{}"), "Should fail");

    model_param_free(field);
}

// ============================================================================
// model_set_binary_from_str (regression: NULL value removed from handler)
// ============================================================================

TEST(test_model_set_binary_from_str) {
    TEST_CASE("Set binary from string");

    mfield_t* field = field_create_binary("data", "");
    int res = model_set_binary_from_str(field, "hello", 5);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(5, str_size(model_binary(field)), "Size should be 5");
    TEST_ASSERT_STR_EQUAL("hello", str_get(model_binary(field)), "Value should match");

    model_param_free(field);
}

TEST(test_model_set_binary_from_str_null_value) {
    TEST_CASE("Set binary from NULL value - delegates to __model_set_binary");

    mfield_t* field = field_create_binary("data", "old");
    int res = model_set_binary_from_str(field, NULL, 0);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_binary_from_str_wrong_type) {
    TEST_CASE("Set binary from string on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_binary_from_str(field, "x", 1), "Should fail");

    model_param_free(field);
}

// ============================================================================
// model_set_varchar_from_str (regression: NULL value removed)
// ============================================================================

TEST(test_model_set_varchar_from_str) {
    TEST_CASE("Set varchar from string with size");

    mfield_t* field = field_create_varchar("name", "");
    int res = model_set_varchar_from_str(field, "test", 4);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_STR_EQUAL("test", str_get(model_varchar(field)), "Should be 'test'");

    model_param_free(field);
}

TEST(test_model_set_varchar_from_str_null_value) {
    TEST_CASE("Set varchar from NULL value - delegates to __model_set_binary");

    mfield_t* field = field_create_varchar("name", "old");
    int res = model_set_varchar_from_str(field, NULL, 0);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_varchar_from_str_wrong_type) {
    TEST_CASE("Set varchar from string on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_varchar_from_str(field, "x", 1), "Should fail");

    model_param_free(field);
}

// ============================================================================
// model_set_char_from_str (regression: NULL value removed)
// ============================================================================

TEST(test_model_set_char_from_str) {
    TEST_CASE("Set char from string with size");

    mfield_t* field = field_create_char("code", "");
    int res = model_set_char_from_str(field, "A", 1);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_STR_EQUAL("A", str_get(model_char(field)), "Should be 'A'");

    model_param_free(field);
}

TEST(test_model_set_char_from_str_null_value) {
    TEST_CASE("Set char from NULL value - delegates to __model_set_binary");

    mfield_t* field = field_create_char("code", "old");
    int res = model_set_char_from_str(field, NULL, 0);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

// ============================================================================
// model_set_text_from_str (regression: NULL value removed)
// ============================================================================

TEST(test_model_set_text_from_str) {
    TEST_CASE("Set text from string with size");

    mfield_t* field = field_create_text("body", "");
    int res = model_set_text_from_str(field, "hello world", 11);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_STR_EQUAL("hello world", str_get(model_text(field)), "Should match");

    model_param_free(field);
}

TEST(test_model_set_text_from_str_null_value) {
    TEST_CASE("Set text from NULL value - delegates to __model_set_binary");

    mfield_t* field = field_create_text("body", "old");
    int res = model_set_text_from_str(field, NULL, 0);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_text_from_str_wrong_type) {
    TEST_CASE("Set text from string on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_text_from_str(field, "x", 1), "Should fail");

    model_param_free(field);
}

// ============================================================================
// model_set_enum_from_str (regression: NULL value removed)
// ============================================================================

TEST(test_model_set_enum_from_str) {
    TEST_CASE("Set enum from valid string");

    char* values[] = {"a", "b", "c"};
    mfield_t* field = field_create_enum("st", "a", values, 3);
    int res = model_set_enum_from_str(field, "b", 1);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_STR_EQUAL("b", str_get(model_enum(field)), "Should be 'b'");

    model_param_free(field);
}

TEST(test_model_set_enum_from_str_invalid) {
    TEST_CASE("Set enum from invalid string returns 0");

    char* values[] = {"a", "b"};
    mfield_t* field = field_create_enum("st", "a", values, 2);
    int res = model_set_enum_from_str(field, "z", 1);
    TEST_ASSERT_EQUAL(0, res, "Should fail for invalid enum value");

    model_param_free(field);
}

TEST(test_model_set_enum_from_str_empty) {
    TEST_CASE("Set enum from empty string (size=0) delegates to __model_set_binary");

    char* values[] = {"a", "b"};
    mfield_t* field = field_create_enum("st", "a", values, 2);
    int res = model_set_enum_from_str(field, "", 0);
    TEST_ASSERT_EQUAL(1, res, "Should succeed with size=0");

    model_param_free(field);
}

// ============================================================================
// model_set_array_from_str
// ============================================================================

TEST(test_model_set_array_from_str) {
    TEST_CASE("Set array from JSON array string");

    mfield_t* field = field_create_array("tags", NULL);
    int res = model_set_array_from_str(field, "[\"a\",\"b\",\"c\"]");
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_NOT_NULL(field->value._array, "Array should not be NULL");

    model_param_free(field);
}

TEST(test_model_set_array_from_str_null) {
    TEST_CASE("Set array from NULL sets is_null");

    mfield_t* field = field_create_array("tags", NULL);
    int res = model_set_array_from_str(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_array_from_str_not_array) {
    TEST_CASE("Set array from non-array JSON returns 0");

    mfield_t* field = field_create_array("tags", NULL);
    int res = model_set_array_from_str(field, "{\"key\":\"val\"}");
    TEST_ASSERT_EQUAL(0, res, "Should fail for non-array JSON");

    model_param_free(field);
}

TEST(test_model_set_array_from_str_null_field) {
    TEST_CASE("Set array from NULL field returns 0");

    TEST_ASSERT_EQUAL(0, model_set_array_from_str(NULL, "[]"), "Should return 0");
}

// ============================================================================
// model_set_timestamp / model_set_timestamp_now
// ============================================================================

TEST(test_model_set_timestamp) {
    TEST_CASE("Set timestamp from tm_t");

    mfield_t* field = field_create_timestamp("ts", NULL);
    tm_t val = {0};
    val.tm_year = 125; val.tm_mon = 4; val.tm_mday = 14;
    val.tm_hour = 10; val.tm_min = 30; val.tm_sec = 0;

    int res = model_set_timestamp(field, &val);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(125, field->value._tm.tm_year, "Year should match");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");
    TEST_ASSERT_EQUAL(0, field->use_raw_sql, "use_raw_sql should be 0");
    TEST_ASSERT_EQUAL(1, field->dirty, "Should be dirty");

    model_param_free(field);
}

TEST(test_model_set_timestamp_null_value) {
    TEST_CASE("Set timestamp to NULL value");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int res = model_set_timestamp(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_timestamp_now) {
    TEST_CASE("Set timestamp NOW() sets raw SQL");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int res = model_set_timestamp_now(field);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");
    TEST_ASSERT_EQUAL(0, field->use_default, "use_default should be 0");
    TEST_ASSERT_NOT_NULL(field->value._string, "String should not be NULL");
    TEST_ASSERT_STR_EQUAL("NOW()", str_get(field->value._string), "Should be 'NOW()'");

    model_param_free(field);
}

TEST(test_model_set_timestamp_now_wrong_type) {
    TEST_CASE("Set timestamp NOW() on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_timestamp_now(field), "Should return 0");

    model_param_free(field);
}

// ============================================================================
// model_set_timestamptz / model_set_timestamptz_now
// ============================================================================

TEST(test_model_set_timestamptz_now) {
    TEST_CASE("Set timestamptz NOW() sets raw SQL");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int res = model_set_timestamptz_now(field);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");
    TEST_ASSERT_STR_EQUAL("NOW()", str_get(field->value._string), "Should be 'NOW()'");

    model_param_free(field);
}

TEST(test_model_set_timestamptz_now_wrong_type) {
    TEST_CASE("Set timestamptz NOW() on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_timestamptz_now(field), "Should return 0");

    model_param_free(field);
}

// ============================================================================
// model_set_json
// ============================================================================

TEST(test_model_set_json_null_value) {
    TEST_CASE("Set JSON to NULL value");

    mfield_t* field = field_create_json("meta", NULL);
    json_doc_t* doc = json_parse("{}");
    model_set_json(field, doc);
    json_free(doc);

    // Now set to NULL
    int res = model_set_json(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_json_wrong_type) {
    TEST_CASE("Set JSON on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_json(field, NULL), "Should return 0");

    model_param_free(field);
}

// ============================================================================
// model_set_array
// ============================================================================

TEST(test_model_set_array_null_value) {
    TEST_CASE("Set array to NULL value");

    mfield_t* field = field_create_array("tags", NULL);
    array_t* arr = array_create();
    model_set_array(field, arr);
    // model_set_array takes ownership, do not free arr manually

    int res = model_set_array(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

TEST(test_model_set_array_wrong_type) {
    TEST_CASE("Set array on wrong type returns 0");

    mfield_t* field = field_create_int("n", 0);
    TEST_ASSERT_EQUAL(0, model_set_array(field, NULL), "Should return 0");

    model_param_free(field);
}

// ============================================================================
// model_field_to_string (dispatch)
// ============================================================================

TEST(test_model_field_to_string_null) {
    TEST_CASE("field_to_string on NULL field returns NULL");
    TEST_ASSERT_NULL(model_field_to_string(NULL), "Should return NULL");
}

TEST(test_model_field_to_string_bool) {
    TEST_CASE("field_to_string dispatches bool");

    mfield_t* field = field_create_bool("b", 1);
    str_t* result = model_field_to_string(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("1", str_get(result), "Bool true should be '1'");

    model_param_free(field);
}

TEST(test_model_field_to_string_int) {
    TEST_CASE("field_to_string dispatches int");

    mfield_t* field = field_create_int("n", 42);
    str_t* result = model_field_to_string(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("42", str_get(result), "Should be '42'");

    model_param_free(field);
}

TEST(test_model_field_to_string_bigint) {
    TEST_CASE("field_to_string dispatches bigint");

    mfield_t* field = field_create_bigint("id", 123456789012LL);
    str_t* result = model_field_to_string(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("123456789012", str_get(result), "Should match");

    model_param_free(field);
}

TEST(test_model_field_to_string_varchar) {
    TEST_CASE("field_to_string dispatches varchar");

    mfield_t* field = field_create_varchar("name", "hello");
    str_t* result = model_field_to_string(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello", str_get(result), "Should be 'hello'");

    model_param_free(field);
}

TEST(test_model_field_to_string_null_field) {
    TEST_CASE("field_to_string on null is_null field returns 'NULL' raw SQL");

    mfield_t* field = field_create_varchar("name", NULL);
    // is_null=1 triggers "NULL" raw SQL
    str_t* result = model_field_to_string(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("NULL", str_get(result), "Should be 'NULL'");
    TEST_ASSERT_EQUAL(1, field->use_raw_sql, "use_raw_sql should be 1");

    model_param_free(field);
}

// ============================================================================
// model_bool_to_str / model_int_to_str / etc.
// ============================================================================

TEST(test_model_bool_to_str) {
    TEST_CASE("Bool to string");

    mfield_t* field = field_create_bool("b", 1);
    str_t* result = model_bool_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("1", str_get(result), "Should be '1'");

    model_param_free(field);
}

TEST(test_model_bool_to_str_false) {
    TEST_CASE("Bool false to string");

    mfield_t* field = field_create_bool("b", 0);
    str_t* result = model_bool_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("0", str_get(result), "Should be '0'");

    model_param_free(field);
}

TEST(test_model_int_to_str) {
    TEST_CASE("Int to string");

    mfield_t* field = field_create_int("n", 42);
    str_t* result = model_int_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("42", str_get(result), "Should be '42'");

    model_param_free(field);
}

TEST(test_model_int_to_str_negative) {
    TEST_CASE("Negative int to string");

    mfield_t* field = field_create_int("n", -123);
    str_t* result = model_int_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("-123", str_get(result), "Should be '-123'");

    model_param_free(field);
}

TEST(test_model_bigint_to_str) {
    TEST_CASE("Bigint to string");

    mfield_t* field = field_create_bigint("id", 9999999999LL);
    str_t* result = model_bigint_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("9999999999", str_get(result), "Should match");

    model_param_free(field);
}

TEST(test_model_float_to_str) {
    TEST_CASE("Float to string");

    mfield_t* field = field_create_float("r", 3.14f);
    str_t* result = model_float_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "3.14") != NULL, "Should contain 3.14");

    model_param_free(field);
}

TEST(test_model_double_to_str) {
    TEST_CASE("Double to string");

    mfield_t* field = field_create_double("d", 99.99);
    str_t* result = model_double_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "99.99") != NULL, "Should contain 99.99");

    model_param_free(field);
}

TEST(test_model_decimal_to_str) {
    TEST_CASE("Decimal to string");

    mfield_t* field = field_create_decimal("amt", 123.456L);
    str_t* result = model_decimal_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "123") != NULL, "Should contain 123");

    model_param_free(field);
}

TEST(test_model_money_to_str) {
    TEST_CASE("Money to string");

    mfield_t* field = field_create_money("sal", 50000.50);
    str_t* result = model_money_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "50000") != NULL, "Should contain 50000");

    model_param_free(field);
}

TEST(test_model_smallint_to_str) {
    TEST_CASE("Smallint to string");

    mfield_t* field = field_create_smallint("s", 42);
    str_t* result = model_smallint_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("42", str_get(result), "Should be '42'");

    model_param_free(field);
}

TEST(test_model_to_str_null_field) {
    TEST_CASE("Int to_str on NULL field returns NULL");
    TEST_ASSERT_NULL(model_int_to_str(NULL), "Should return NULL");
}

TEST(test_model_to_str_wrong_type) {
    TEST_CASE("Int to_str on wrong type returns NULL");

    mfield_t* field = field_create_bool("b", 1);
    TEST_ASSERT_NULL(model_int_to_str(field), "Should return NULL");

    model_param_free(field);
}

// ============================================================================
// model_date_to_str / model_time_to_str / model_timetz_to_str
// ============================================================================

TEST(test_model_date_to_str) {
    TEST_CASE("Date to string");

    mfield_t* field = field_create_date("d", NULL);
    model_set_date_from_str(field, "2025-05-14 00:00:00");
    str_t* result = model_date_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "2025-05-14") != NULL, "Should contain date");

    model_param_free(field);
}

TEST(test_model_time_to_str) {
    TEST_CASE("Time to string");

    mfield_t* field = field_create_time("t", NULL);
    model_set_time_from_str(field, "15:30:45");
    str_t* result = model_time_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "15:30:45") != NULL, "Should contain time");

    model_param_free(field);
}

TEST(test_model_time_to_str_with_usec) {
    TEST_CASE("Time with microseconds to string");

    mfield_t* field = field_create_time("t", NULL);
    model_set_time_from_str(field, "15:30:45.123456");
    str_t* result = model_time_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), ".123456") != NULL, "Should contain usec");

    model_param_free(field);
}

TEST(test_model_timetz_to_str) {
    TEST_CASE("Timetz to string");

    mfield_t* field = field_create_timetz("tz", NULL);
    model_set_timetz_from_str(field, "15:30:45.123456+03:00");
    str_t* result = model_timetz_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "15:30:45") != NULL, "Should contain time");

    model_param_free(field);
}

// ============================================================================
// model_json_to_str
// ============================================================================

TEST(test_model_json_to_str) {
    TEST_CASE("JSON to string");

    mfield_t* field = field_create_json("meta", NULL);
    model_set_json_from_str(field, "{\"key\":\"val\"}");
    str_t* result = model_json_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "key") != NULL, "Should contain 'key'");

    model_param_free(field);
}

// ============================================================================
// model_array_to_str
// ============================================================================

TEST(test_model_array_to_str) {
    TEST_CASE("Array to string");

    mfield_t* field = field_create_array("tags", NULL);
    model_set_array_from_str(field, "[\"a\",\"b\"]");
    str_t* result = model_array_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "a") != NULL, "Should contain 'a'");
    TEST_ASSERT_EQUAL(1, strstr(str_get(result), "b") != NULL, "Should contain 'b'");

    model_param_free(field);
}

TEST(test_model_array_to_str_null_field) {
    TEST_CASE("Array to string on NULL field returns NULL");
    TEST_ASSERT_NULL(model_array_to_str(NULL), "Should return NULL");
}

// ============================================================================
// model_param_clear / model_param_free
// ============================================================================

TEST(test_model_param_clear) {
    TEST_CASE("Clear param frees internal values");

    mfield_t* field = field_create_varchar("name", "test");
    model_param_clear(field);
    // After clear, value._string should be NULL (explicit_bzero)
    TEST_ASSERT_NULL(field->value._string, "String should be NULL after clear");

    free(field);
}

// ============================================================================
// model_set_time / model_time
// ============================================================================

TEST(test_model_set_time) {
    TEST_CASE("Set time from tm_t");

    mfield_t* field = field_create_time("t", NULL);
    tm_t val = {0};
    val.tm_hour = 10; val.tm_min = 30; val.tm_sec = 45;
    int res = model_set_time(field, &val);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(10, model_time(field).tm_hour, "Hour should be 10");
    TEST_ASSERT_EQUAL(0, field->is_null, "Should not be null");

    model_param_free(field);
}

TEST(test_model_set_time_null_value) {
    TEST_CASE("Set time to NULL");

    mfield_t* field = field_create_time("t", NULL);
    int res = model_set_time(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

// ============================================================================
// model_set_timetz / model_timetz
// ============================================================================

TEST(test_model_set_timetz) {
    TEST_CASE("Set timetz from tm_t");

    mfield_t* field = field_create_timetz("tz", NULL);
    tm_t val = {0};
    val.tm_hour = 10; val.tm_min = 30; val.tm_sec = 45; val.tm_gmtoff = 10800;
    int res = model_set_timetz(field, &val);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(10, model_timetz(field).tm_hour, "Hour should be 10");
    TEST_ASSERT_EQUAL(10800, model_timetz(field).tm_gmtoff, "Offset should be 10800");

    model_param_free(field);
}

TEST(test_model_set_timetz_null) {
    TEST_CASE("Set timetz to NULL");

    mfield_t* field = field_create_timetz("tz", NULL);
    int res = model_set_timetz(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

// ============================================================================
// model_set_date / model_date
// ============================================================================

TEST(test_model_set_date) {
    TEST_CASE("Set date from tm_t");

    mfield_t* field = field_create_date("d", NULL);
    tm_t val = {0};
    val.tm_year = 125; val.tm_mon = 4; val.tm_mday = 14;
    int res = model_set_date(field, &val);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(14, model_date(field).tm_mday, "Day should be 14");

    model_param_free(field);
}

TEST(test_model_set_date_null) {
    TEST_CASE("Set date to NULL");

    mfield_t* field = field_create_date("d", NULL);
    int res = model_set_date(field, NULL);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Should be null");

    model_param_free(field);
}

// ============================================================================
// Getters for NULL field / wrong type (exhaustive)
// ============================================================================

TEST(test_model_getters_null_field) {
    TEST_CASE("All getters return zero/NULL for NULL field");

    TEST_ASSERT_EQUAL(0, model_smallint(NULL), "smallint NULL => 0");
    TEST_ASSERT_EQUAL(0, model_bigint(NULL), "bigint NULL => 0");
    TEST_ASSERT_EQUAL(1, model_float(NULL) == 0.0f, "float NULL => 0.0");
    TEST_ASSERT_EQUAL(1, model_double(NULL) == 0.0, "double NULL => 0.0");
    TEST_ASSERT_EQUAL(1, model_decimal(NULL) == 0.0L, "decimal NULL => 0.0");
    TEST_ASSERT_EQUAL(1, model_money(NULL) == 0.0, "money NULL => 0.0");
    TEST_ASSERT_NULL(model_json(NULL), "json NULL => NULL");
    TEST_ASSERT_NULL(model_binary(NULL), "binary NULL => NULL");
    TEST_ASSERT_NULL(model_text(NULL), "text NULL => NULL");
    TEST_ASSERT_NULL(model_enum(NULL), "enum NULL => NULL");
    TEST_ASSERT_NULL(model_array(NULL), "array NULL => NULL");
}

TEST(test_model_timestamp_null_field) {
    TEST_CASE("Timestamp getters return zero tm_t for NULL field");

    tm_t ts = model_timestamp(NULL);
    TEST_ASSERT_EQUAL(0, ts.tm_year, "Year should be 0");

    tm_t tsz = model_timestamptz(NULL);
    TEST_ASSERT_EQUAL(0, tsz.tm_year, "Year should be 0");

    tm_t d = model_date(NULL);
    TEST_ASSERT_EQUAL(0, d.tm_year, "Year should be 0");

    tm_t t = model_time(NULL);
    TEST_ASSERT_EQUAL(0, t.tm_hour, "Hour should be 0");

    tm_t tz = model_timetz(NULL);
    TEST_ASSERT_EQUAL(0, tz.tm_hour, "Hour should be 0");
}

TEST(test_model_getters_wrong_type) {
    TEST_CASE("Getters return zero/NULL for wrong type");

    mfield_t* field = field_create_bool("b", 1);

    TEST_ASSERT_EQUAL(0, model_int(field), "int on bool => 0");
    TEST_ASSERT_EQUAL(0, model_bigint(field), "bigint on bool => 0");
    TEST_ASSERT_EQUAL(1, model_float(field) == 0.0f, "float on bool => 0.0");
    TEST_ASSERT_EQUAL(1, model_double(field) == 0.0, "double on bool => 0.0");
    TEST_ASSERT_EQUAL(1, model_decimal(field) == 0.0L, "decimal on bool => 0.0");
    TEST_ASSERT_EQUAL(1, model_money(field) == 0.0, "money on bool => 0.0");
    TEST_ASSERT_NULL(model_json(field), "json on bool => NULL");
    TEST_ASSERT_NULL(model_binary(field), "binary on bool => NULL");
    TEST_ASSERT_NULL(model_varchar(field), "varchar on bool => NULL");
    TEST_ASSERT_NULL(model_char(field), "char on bool => NULL");
    TEST_ASSERT_NULL(model_text(field), "text on bool => NULL");
    TEST_ASSERT_NULL(model_enum(field), "enum on bool => NULL");
    TEST_ASSERT_NULL(model_array(field), "array on bool => NULL");

    model_param_free(field);
}

TEST(test_model_date_getters_wrong_type) {
    TEST_CASE("Date/time getters return zero for wrong type");

    mfield_t* field = field_create_int("n", 0);

    tm_t ts = model_timestamp(field);
    TEST_ASSERT_EQUAL(0, ts.tm_year, "timestamp on int => 0");

    tm_t tsz = model_timestamptz(field);
    TEST_ASSERT_EQUAL(0, tsz.tm_year, "timestamptz on int => 0");

    tm_t d = model_date(field);
    TEST_ASSERT_EQUAL(0, d.tm_year, "date on int => 0");

    tm_t t = model_time(field);
    TEST_ASSERT_EQUAL(0, t.tm_hour, "time on int => 0");

    tm_t tz = model_timetz(field);
    TEST_ASSERT_EQUAL(0, tz.tm_hour, "timetz on int => 0");

    model_param_free(field);
}

// ============================================================================
// Setters for NULL field (exhaustive)
// ============================================================================

TEST(test_model_setters_null_field) {
    TEST_CASE("All setters return 0 for NULL field");

    TEST_ASSERT_EQUAL(0, model_set_smallint(NULL, 1), "smallint NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_int(NULL, 1), "int NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_bigint(NULL, 1), "bigint NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_float(NULL, 1.0f), "float NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_double(NULL, 1.0), "double NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_decimal(NULL, 1.0L), "decimal NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_money(NULL, 1.0), "money NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_timestamp(NULL, NULL), "timestamp NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_timestamptz(NULL, NULL), "timestamptz NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_date(NULL, NULL), "date NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_time(NULL, NULL), "time NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_timetz(NULL, NULL), "timetz NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_json(NULL, NULL), "json NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_binary(NULL, "x", 1), "binary NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_varchar(NULL, "x"), "varchar NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_char(NULL, "x"), "char NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_text(NULL, "x"), "text NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_enum(NULL, "x"), "enum NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_array(NULL, NULL), "array NULL => 0");
}

// ============================================================================
// model_set_*_from_str NULL field
// ============================================================================

TEST(test_model_set_from_str_null_field) {
    TEST_CASE("All *_from_str return 0 for NULL field");

    TEST_ASSERT_EQUAL(0, model_set_smallint_from_str(NULL, "1"), "smallint NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_int_from_str(NULL, "1"), "int NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_bigint_from_str(NULL, "1"), "bigint NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_float_from_str(NULL, "1.0"), "float NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_double_from_str(NULL, "1.0"), "double NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_decimal_from_str(NULL, "1.0"), "decimal NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_money_from_str(NULL, "1.0"), "money NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_timestamp_from_str(NULL, "2025-01-01 00:00:00"), "timestamp NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_timestamptz_from_str(NULL, "2025-01-01T00:00:00Z"), "timestamptz NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_date_from_str(NULL, "2025-01-01 00:00:00"), "date NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_time_from_str(NULL, "00:00:00"), "time NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_timetz_from_str(NULL, "00:00:00Z"), "timetz NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_json_from_str(NULL, "{}"), "json NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_binary_from_str(NULL, "x", 1), "binary NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_varchar_from_str(NULL, "x", 1), "varchar NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_char_from_str(NULL, "x", 1), "char NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_text_from_str(NULL, "x", 1), "text NULL => 0");
    TEST_ASSERT_EQUAL(0, model_set_enum_from_str(NULL, "x", 1), "enum NULL => 0");
}

// ============================================================================
// __model_set_date dirty tracking
// ============================================================================

TEST(test_model_set_date_twice_keeps_first_oldvalue) {
    TEST_CASE("Setting date twice: second set does not update oldvalue (dirty already 1)");

    mfield_t* field = field_create_date("d", NULL);
    tm_t val1 = {0}; val1.tm_year = 120; val1.tm_mon = 0; val1.tm_mday = 1;
    tm_t val2 = {0}; val2.tm_year = 125; val2.tm_mon = 4; val2.tm_mday = 14;

    model_set_date(field, &val1);
    // First set saves oldvalue (zeroed from create) and sets dirty=1
    TEST_ASSERT_EQUAL(1, field->dirty, "Should be dirty after first set");
    model_set_date(field, &val2);
    // Second set: dirty=1, so oldvalue is NOT updated again
    TEST_ASSERT_EQUAL(125, field->value._tm.tm_year, "Current year should be 125");
    TEST_ASSERT_EQUAL(1, field->dirty, "Should still be dirty");

    model_param_free(field);
}

TEST(test_model_set_timestamp_twice_keeps_first_oldvalue) {
    TEST_CASE("Setting timestamp twice: second set does not update oldvalue (dirty already 1)");

    mfield_t* field = field_create_timestamp("ts", NULL);
    tm_t val1 = {0}; val1.tm_year = 120;
    tm_t val2 = {0}; val2.tm_year = 125;

    model_set_timestamp(field, &val1);
    TEST_ASSERT_EQUAL(1, field->dirty, "Should be dirty after first set");
    model_set_timestamp(field, &val2);

    TEST_ASSERT_EQUAL(125, field->value._tm.tm_year, "Current year should be 125");
    TEST_ASSERT_EQUAL(1, field->dirty, "Should still be dirty");

    model_param_free(field);
}

// ============================================================================
// model_set_json copy semantics
// ============================================================================

TEST(test_model_set_json_copies_document) {
    TEST_CASE("set_json makes a copy of the document");

    mfield_t* field = field_create_json("meta", NULL);
    json_doc_t* doc = json_parse("{\"x\":1}");
    int res = model_set_json(field, doc);
    TEST_ASSERT_EQUAL(1, res, "Should succeed");

    // Freeing original should not affect the field
    json_free(doc);

    str_t* str = model_json_to_str(field);
    TEST_ASSERT_NOT_NULL(str, "Should still be valid after freeing original");
    TEST_ASSERT_EQUAL(1, strstr(str_get(str), "x") != NULL, "Should contain 'x'");

    model_param_free(field);
}

// ============================================================================
// model_set_timestamp_from_str with NOW() raw SQL path
// ============================================================================

TEST(test_model_timestamp_to_str_now_raw_sql) {
    TEST_CASE("timestamp_to_str returns NOW() when set via set_timestamp_now");

    mfield_t* field = field_create_timestamp("ts", NULL);
    model_set_timestamp_now(field);
    str_t* result = model_timestamp_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("NOW()", str_get(result), "Should be 'NOW()'");

    model_param_free(field);
}

TEST(test_model_timestamptz_to_str_now_raw_sql) {
    TEST_CASE("timestamptz_to_str returns NOW() when set via set_timestamptz_now");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    model_set_timestamptz_now(field);
    str_t* result = model_timestamptz_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Should not be NULL");
    TEST_ASSERT_STR_EQUAL("NOW()", str_get(result), "Should be 'NOW()'");

    model_param_free(field);
}

// ============================================================================
// R6: rich JSON serialization (model_stringify with JSON/ARRAY columns)
// ============================================================================

enum r6_item_column {
    R6_COL_ID = 0,
    R6_COL_META,
    R6_COL_TAGS,
    R6_COLUMNS_COUNT
};

static const mcolumn_t __r6_columns[R6_COLUMNS_COUNT] = {
    [R6_COL_ID]   = { .name = "id",   .type = MODEL_INT, .is_primary = 1 },
    [R6_COL_META] = { .name = "meta", .type = MODEL_JSON, .nullable = 1 },
    [R6_COL_TAGS] = { .name = "tags", .type = MODEL_ARRAY, .nullable = 1 },
};

static const int __r6_primary_keys[] = { R6_COL_ID };

static const mschema_t __r6_schema = {
    .table = "r6_items",
    .columns = __r6_columns,
    .columns_count = R6_COLUMNS_COUNT,
    .primary_keys = __r6_primary_keys,
    .primary_keys_count = 1,
};

static model_t* __r6_record_create(void) {
    model_t* record = calloc(1, sizeof * record);
    if (record == NULL) return NULL;
    if (!model_init(record, &__r6_schema)) {
        free(record);
        return NULL;
    }
    return record;
}

TEST(test_model_stringify_json_nested_object) {
    TEST_CASE("JSON column serialized as nested object, not a string");

    model_t* record = __r6_record_create();
    TEST_ASSERT_NOT_NULL(record, "Record should not be NULL");

    model_set_int(model_field(record, R6_COL_ID), 7);
    TEST_ASSERT_EQUAL(1, model_set_json_from_str(model_field(record, R6_COL_META),
        "{\"a\":1,\"b\":[2,3]}"), "set json should succeed");
    TEST_ASSERT_EQUAL(1, model_set_array_from_str(model_field(record, R6_COL_TAGS),
        "[1,2,3]"), "set array should succeed");

    char* json = model_stringify(record, NULL);
    TEST_ASSERT_NOT_NULL(json, "stringify should not be NULL");
    TEST_ASSERT_STR_EQUAL("{\"id\":7,\"meta\":{\"a\":1,\"b\":[2,3]},\"tags\":[1,2,3]}",
        json, "JSON/array should be nested natively");

    free(json);
    model_free(record);
}

TEST(test_model_stringify_array_string_elements) {
    TEST_CASE("ARRAY of strings keeps quotes, numbers do not");

    model_t* record = __r6_record_create();
    TEST_ASSERT_NOT_NULL(record, "Record should not be NULL");

    model_set_int(model_field(record, R6_COL_ID), 1);
    model_field(record, R6_COL_META)->is_null = 1;
    TEST_ASSERT_EQUAL(1, model_set_array_from_str(model_field(record, R6_COL_TAGS),
        "[\"a\",\"b\"]"), "set array should succeed");

    char* json = model_stringify(record, NULL);
    TEST_ASSERT_NOT_NULL(json, "stringify should not be NULL");
    TEST_ASSERT_STR_EQUAL("{\"id\":1,\"meta\":null,\"tags\":[\"a\",\"b\"]}",
        json, "string array elements stay quoted, null meta stays null");

    free(json);
    model_free(record);
}

TEST(test_model_stringify_json_deeply_nested) {
    TEST_CASE("Deeply nested JSON column clones recursively");

    model_t* record = __r6_record_create();
    TEST_ASSERT_NOT_NULL(record, "Record should not be NULL");

    model_set_int(model_field(record, R6_COL_ID), 2);
    TEST_ASSERT_EQUAL(1, model_set_json_from_str(model_field(record, R6_COL_META),
        "{\"x\":{\"y\":{\"z\":[true,false,null,\"s\"]}}}"), "set json should succeed");
    model_field(record, R6_COL_TAGS)->is_null = 1;

    char* json = model_stringify(record, NULL);
    TEST_ASSERT_NOT_NULL(json, "stringify should not be NULL");
    TEST_ASSERT_STR_EQUAL("{\"id\":2,\"meta\":{\"x\":{\"y\":{\"z\":[true,false,null,\"s\"]}}},\"tags\":null}",
        json, "nested structure should be preserved");

    free(json);
    model_free(record);
}

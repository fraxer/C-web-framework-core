#define _GNU_SOURCE
#include "framework.h"
#include "form/form.h"
#include <float.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define TEXT(value) { .kind = FORM_INPUT_TEXT, .data.text = (value) }

static char* strip_spaces(char* value, int flags) {
    (void)flags;
    if (value == NULL) return NULL;
    while (*value == ' ') value++;
    size_t length = strlen(value);
    while (length > 0 && value[length - 1] == ' ')
        value[--length] = 0;
    return value;
}

static int adult(const form_value_t* value, void* context) {
    (void)context;
    return value->kind == FORM_VALUE_INTEGER && value->data.integer >= 18;
}

static int digits_only(const form_value_t* value, void* context) {
    (void)context;
    if (value->kind != FORM_VALUE_TEXT) return 0;
    for (const char* p = value->data.text; *p != 0; p++)
        if (*p < '0' || *p > '9') return 0;
    return 1;
}

static const form_validator_t age_validators[] = {
    { .check = adult, .message = "too young" }
};

static const form_validator_t code_validators[] = {
    { .check = digits_only, .message = "digits required" }
};

static const form_field_spec_t fields[] = {
    { .kind = FORM_FIELD_TEXT, .text = {
        .common = { .name = "name", .required = 1,
                    .required_message = "name required" },
        .min_length = 2, .max_length = 3,
        .min_length_message = "name too short",
        .max_length_message = "name too long" } },
    { .kind = FORM_FIELD_INTEGER, .integer = {
        .common = { .name = "age", .required = 1,
                    .validators = age_validators, .validators_count = 1,
                    .invalid_message = "invalid age" } } },
    { .kind = FORM_FIELD_TEXT, .text = {
        .common = { .name = "code", .validators = code_validators,
                    .validators_count = 1, .invalid_message = "invalid code" } } },
    { .kind = FORM_FIELD_BOOLEAN, .boolean = {
        .common = { .name = "consent", .required = 1,
                    .invalid_message = "invalid consent" } } }
};

static void validate_form(form_t* form, void* context) {
    (void)context;
    const form_value_t* name = form_field_value(form, 0);
    const form_value_t* code = form_field_value(form, 2);
    if (name == NULL || code == NULL || code->kind == FORM_VALUE_EMPTY)
        return;
    if (strcmp(name->data.text, "Ada") == 0 &&
        strcmp(code->data.text, "000") == 0)
        form_add_error(form, 2, FORM_INVALID, "reserved code");
    if (strcmp(code->data.text, "999") == 0)
        form_add_non_field_error(form, "combination rejected");
}

static const form_schema_t schema = {
    .fields = fields, .fields_count = 4,
    .clean = strip_spaces, .length = strlen,
    .validate = validate_form
};

static int destroyed = 0;

static void destroy_object(void* object) {
    destroyed++;
    free(object);
}

static int parse_owned_object(const form_input_t* input, form_value_t* value,
                              void* context) {
    if (input->kind != FORM_INPUT_TEXT) return 0;
    int* parsed = malloc(sizeof *parsed);
    if (parsed == NULL) return 0;
    *parsed = atoi(input->data.text);
    *value = (form_value_t){
        .kind = FORM_VALUE_OBJECT, .data.object = parsed,
        .destroy = destroy_object
    };
    return context == NULL;
}

// ============================================================================
// Валидация формы целиком
// ============================================================================

TEST(test_form_valid_input) {
    TEST_SUITE("form");
    TEST_CASE("Valid input: cleaned data appears only after validation");

    form_input_t valid_values[] = {
        TEXT(strdup("  Ada ")), TEXT(strdup("21")),
        TEXT(strdup("   ")), TEXT(strdup("true"))
    };
    form_t* valid = form_create(&schema, valid_values);
    TEST_REQUIRE_NOT_NULL(valid, "Form should be created");
    TEST_ASSERT_EQUAL_SIZE(4, form_fields_count(valid), "Form should expose 4 fields");
    TEST_ASSERT_NULL(form_cleaned_data(valid, 0), "Cleaned data should be unavailable before validation");
    TEST_REQUIRE_GOTO(form_is_valid(valid), "Form should be valid", cleanup);
    TEST_ASSERT_EQUAL(FORM_VALUE_TEXT, form_cleaned_data(valid, 0)->kind, "Name should be a text value");
    TEST_ASSERT_STR_EQUAL("Ada", form_cleaned_data(valid, 0)->data.text, "Name should be trimmed by the cleaner");
    TEST_ASSERT_EQUAL(21, form_cleaned_data(valid, 1)->data.integer, "Age should be 21");
    TEST_ASSERT_EQUAL(FORM_VALUE_EMPTY, form_cleaned_data(valid, 2)->kind, "Blank optional code should be empty");
    TEST_ASSERT_EQUAL(1, form_cleaned_data(valid, 3)->data.boolean, "Consent should be true");
    // The second call must return the cached verdict rather than revalidate.
    TEST_ASSERT(form_is_valid(valid), "Repeated validation should return the cached result");

cleanup:
    form_free(valid);
}

TEST(test_form_invalid_input) {
    TEST_SUITE("form");
    TEST_CASE("Invalid input: error code and message of every bad value");

    form_input_t invalid_values[] = {
        TEXT(strdup(" A ")), TEXT(strdup("oops")),
        TEXT(strdup("x")), TEXT(strdup("maybe"))
    };
    form_t* invalid = form_create(&schema, invalid_values);
    TEST_REQUIRE_NOT_NULL(invalid, "Form should be created");
    TEST_ASSERT(!form_is_valid(invalid), "Form should be invalid");
    TEST_ASSERT_EQUAL(FORM_MIN_LENGTH, form_error_code(invalid, 0), "Name should fail the minimum length");
    TEST_ASSERT_EQUAL(FORM_INVALID, form_error_code(invalid, 1), "Age should fail to parse");
    TEST_ASSERT_EQUAL(FORM_INVALID, form_error_code(invalid, 2), "Code should fail its validator");
    TEST_ASSERT_EQUAL(FORM_INVALID, form_error_code(invalid, 3), "Consent should fail to parse");
    TEST_ASSERT_STR_EQUAL("name too short", form_error_message(invalid, 0), "Name message should come from the field");
    TEST_ASSERT_STR_EQUAL("digits required", form_error_message(invalid, 2), "Code message should come from the validator");
    TEST_ASSERT_NULL(form_cleaned_data(invalid, 0), "Cleaned data should stay unavailable on an invalid form");

    form_free(invalid);
}

TEST(test_form_validator_rejects) {
    TEST_SUITE("form");
    TEST_CASE("Field validator rejects an underage value");

    form_input_t young_values[] = {
        TEXT(strdup("Bob")), TEXT(strdup("17")),
        TEXT(NULL), TEXT(strdup("0"))
    };
    form_t* young = form_create(&schema, young_values);
    TEST_REQUIRE_NOT_NULL(young, "Form should be created");
    TEST_ASSERT(!form_is_valid(young), "Form should be invalid");
    TEST_ASSERT_STR_EQUAL("too young", form_error_message(young, 1), "Validator message should be reported");

    form_free(young);
}

TEST(test_form_cross_field_error) {
    TEST_SUITE("form");
    TEST_CASE("Schema validate adds a field error for a reserved code");

    form_input_t cross_values[] = {
        TEXT(strdup("Ada")), TEXT(strdup("21")),
        TEXT(strdup("000")), TEXT(strdup("1"))
    };
    form_t* cross = form_create(&schema, cross_values);
    TEST_REQUIRE_NOT_NULL(cross, "Form should be created");
    TEST_ASSERT(!form_is_valid(cross), "Form should be invalid");
    TEST_ASSERT_STR_EQUAL("reserved code", form_error_message(cross, 2), "Cross-field message should be reported");
    TEST_ASSERT_NULL(form_field_value(cross, 2), "A field failed by the schema should drop its value");

    form_free(cross);
}

TEST(test_form_non_field_error) {
    TEST_SUITE("form");
    TEST_CASE("Schema validate adds a non-field error");

    form_input_t global_values[] = {
        TEXT(strdup("Bob")), TEXT(strdup("21")),
        TEXT(strdup("999")), TEXT(strdup("1"))
    };
    form_t* global = form_create(&schema, global_values);
    TEST_REQUIRE_NOT_NULL(global, "Form should be created");
    TEST_ASSERT(!form_is_valid(global), "Form should be invalid");
    TEST_ASSERT_STR_EQUAL("combination rejected", form_non_field_error(global), "Non-field message should be reported");
    TEST_ASSERT_NOT_NULL(form_field_value(global, 0), "A global error preserves valid field values");
    TEST_ASSERT_NULL(form_cleaned_data(global, 0), "A global error hides all cleaned data");

    form_free(global);
}

TEST(test_form_required_missing) {
    TEST_SUITE("form");
    TEST_CASE("Missing required field reports FORM_REQUIRED");

    form_input_t missing_values[] = {
        TEXT(NULL), TEXT(strdup("21")), TEXT(NULL), TEXT(strdup("1"))
    };
    form_t* missing = form_create(&schema, missing_values);
    TEST_REQUIRE_NOT_NULL(missing, "Form should be created");
    TEST_ASSERT(!form_is_valid(missing), "Form should be invalid");
    TEST_ASSERT_EQUAL(FORM_REQUIRED, form_error_code(missing, 0), "Missing name should report FORM_REQUIRED");

    form_free(missing);
}

TEST(test_form_integer_overflow) {
    TEST_SUITE("form");
    TEST_CASE("Integer beyond INT64_MAX is rejected as invalid");

    form_input_t overflow_values[] = {
        TEXT(strdup("Bob")), TEXT(strdup("9223372036854775808")),
        TEXT(NULL), TEXT(strdup("1"))
    };
    form_t* overflow = form_create(&schema, overflow_values);
    TEST_REQUIRE_NOT_NULL(overflow, "Form should be created");
    TEST_ASSERT(!form_is_valid(overflow), "Form should be invalid");
    TEST_ASSERT_STR_EQUAL("invalid age", form_error_message(overflow, 1), "Overflowing age should use the invalid message");

    form_free(overflow);
}

// ============================================================================
// Владение объектами
// ============================================================================

TEST(test_form_object_ownership) {
    TEST_SUITE("form");
    TEST_CASE("Object input is owned by the form and destroyed exactly once");

    // Constructor order between test files is unspecified, so the shared
    // counter is rebased here instead of being read as a running total.
    destroyed = 0;

    int* payload = malloc(sizeof *payload);
    TEST_REQUIRE_NOT_NULL(payload, "Payload should be allocated");
    *payload = 42;
    const form_field_spec_t object_fields[] = {
        { .kind = FORM_FIELD_OBJECT, .object = {
            .common = { .name = "upload", .required = 1 } } }
    };
    const form_schema_t object_schema = { .fields = object_fields, .fields_count = 1 };
    form_input_t object_values[] = {
        { .kind = FORM_INPUT_OBJECT, .data.object = payload,
          .destroy = destroy_object }
    };
    form_t* object = form_create(&object_schema, object_values);
    TEST_REQUIRE_NOT_NULL(object, "Object form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(object), "Object form should be valid", free_object);
    TEST_ASSERT_EQUAL(FORM_VALUE_OBJECT, form_cleaned_data(object, 0)->kind, "Value should be an object");
    TEST_ASSERT_EQUAL(42, *(int*)form_cleaned_data(object, 0)->data.object, "Object should carry the payload");

free_object:
    form_free(object);
    TEST_ASSERT_EQUAL(1, destroyed, "Freeing the form should destroy the object once");

    int* invalid_payload = malloc(sizeof *invalid_payload);
    TEST_REQUIRE_NOT_NULL(invalid_payload, "Rejected payload should be allocated");
    const form_field_spec_t invalid_fields[] = {
        { .kind = FORM_FIELD_TEXT, .text = {
            .common = { .name = "upload" }, .min_length = 1 } }
    };
    const form_schema_t invalid_schema = {
        .fields = invalid_fields, .fields_count = 1, .length = strlen
    };
    form_input_t invalid_object_values[] = {
        { .kind = FORM_INPUT_OBJECT, .data.object = invalid_payload,
          .destroy = destroy_object }
    };
    form_t* rejected = form_create(&invalid_schema, invalid_object_values);
    TEST_REQUIRE_NOT_NULL(rejected, "A valid schema should accept input for later validation");
    TEST_ASSERT(!form_is_valid(rejected), "A text field should reject an object input during validation");
    TEST_ASSERT_EQUAL(FORM_INVALID, form_error_code(rejected, 0), "Wrong input kind should be invalid");
    TEST_ASSERT_EQUAL(1, destroyed, "Rejected input should remain owned until form_free");
    form_free(rejected);
    TEST_ASSERT_EQUAL(2, destroyed, "A rejected input should still be destroyed");
}

TEST(test_form_custom_parser) {
    TEST_SUITE("form");
    TEST_CASE("Custom parse hook owns the value it produces, on success and on failure");

    // Constructor order between test files is unspecified, so the shared
    // counter is rebased here instead of being read as a running total.
    destroyed = 0;

    const form_field_spec_t parsed_fields[] = {
        { .kind = FORM_FIELD_CUSTOM, .custom = {
            .common = { .name = "number" }, .parse = parse_owned_object } }
    };
    const form_schema_t parsed_schema = {
        .fields = parsed_fields, .fields_count = 1
    };
    form_input_t parsed_inputs[] = { TEXT(strdup("42")) };
    form_t* parsed = form_create(&parsed_schema, parsed_inputs);
    TEST_REQUIRE_NOT_NULL(parsed, "Parsed form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(parsed), "Parsed form should be valid", free_parsed);
    TEST_ASSERT_EQUAL(42, *(int*)form_cleaned_data(parsed, 0)->data.object, "Parser should produce the parsed number");

free_parsed:
    form_free(parsed);
    TEST_ASSERT_EQUAL(1, destroyed, "Freeing the form should destroy the parsed object");

    const form_field_spec_t failing_parser_fields[] = {
        { .kind = FORM_FIELD_CUSTOM, .custom = {
            .common = { .name = "number", .context = &destroyed,
                        .invalid_message = "parse failed" },
            .parse = parse_owned_object } }
    };
    const form_schema_t failing_parser_schema = {
        .fields = failing_parser_fields, .fields_count = 1
    };
    form_input_t failing_parser_inputs[] = { TEXT(strdup("42")) };
    form_t* failing_parser = form_create(&failing_parser_schema,
                                         failing_parser_inputs);
    TEST_REQUIRE_NOT_NULL(failing_parser, "Failing parser form should be created");
    TEST_ASSERT(!form_is_valid(failing_parser), "Failing parser should invalidate the form");
    TEST_ASSERT_STR_EQUAL("parse failed", form_error_message(failing_parser, 0), "Field invalid message should be reported");
    // The object a failing parser produced is released during validation.
    TEST_ASSERT_EQUAL(2, destroyed, "A failed parse should destroy its half-built object");

    form_free(failing_parser);
    TEST_ASSERT_EQUAL(2, destroyed, "Freeing a failed parse must not destroy its object again");
}

// ============================================================================
// Значения по умолчанию
// ============================================================================

TEST(test_form_defaults) {
    TEST_SUITE("form");
    TEST_CASE("Defaults fill missing input and are validated like real values");

    const form_field_spec_t default_fields[] = {
        { .kind = FORM_FIELD_INTEGER, .integer = {
            .common = { .name = "age", .validators = age_validators,
                        .validators_count = 1 },
            .has_default = 1, .default_value = 21 } }
    };
    const form_schema_t default_schema = {
        .fields = default_fields, .fields_count = 1
    };
    form_input_t default_inputs[] = { TEXT(NULL) };
    form_t* with_default = form_create(&default_schema, default_inputs);
    TEST_REQUIRE_NOT_NULL(with_default, "Default form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(with_default), "Default form should be valid", free_default);
    TEST_ASSERT_EQUAL(21, form_cleaned_data(with_default, 0)->data.integer, "Default value should be used");

free_default:
    form_free(with_default);

    const form_field_spec_t bad_default_fields[] = {
        { .kind = FORM_FIELD_INTEGER, .integer = {
            .common = { .name = "age", .validators = age_validators,
                        .validators_count = 1 },
            .has_default = 1, .default_value = 17 } }
    };
    const form_schema_t bad_default_schema = {
        .fields = bad_default_fields, .fields_count = 1
    };
    form_input_t bad_default_inputs[] = { TEXT(NULL) };
    form_t* with_bad_default = form_create(&bad_default_schema,
                                           bad_default_inputs);
    TEST_REQUIRE_NOT_NULL(with_bad_default, "Bad default form should be created");
    TEST_ASSERT(!form_is_valid(with_bad_default), "A default failing a validator should invalidate the form");
    TEST_ASSERT_STR_EQUAL("too young", form_error_message(with_bad_default, 0), "Validator message should be reported for the default");

    form_free(with_bad_default);

    const form_field_spec_t long_default_fields[] = {
        { .kind = FORM_FIELD_TEXT, .text = {
            .common = { .name = "name" }, .default_value = "four",
            .max_length = 3, .max_length_message = "default too long" } }
    };
    const form_schema_t long_default_schema = {
        .fields = long_default_fields, .fields_count = 1, .length = strlen
    };
    form_input_t long_default_inputs[] = { TEXT(NULL) };
    form_t* with_long_default = form_create(&long_default_schema,
                                            long_default_inputs);
    TEST_REQUIRE_NOT_NULL(with_long_default, "Long default form should be created");
    TEST_ASSERT(!form_is_valid(with_long_default), "A default exceeding max_length should invalidate the form");
    TEST_ASSERT_STR_EQUAL("default too long", form_error_message(with_long_default, 0), "Max length message should be reported for the default");

    form_free(with_long_default);
}

// ============================================================================
// Числовые границы
// ============================================================================

TEST(test_form_numeric_bounds) {
    TEST_SUITE("form");
    TEST_CASE("Integer and decimal bounds: boundary, below, above, non-finite, inverted");

    const form_field_spec_t typed_fields[] = {
        { .kind = FORM_FIELD_INTEGER, .integer = {
            .common = { .name = "count" },
            .has_min_value = 1, .min_value = 0,
            .has_max_value = 1, .max_value = 10,
            .min_value_message = "count too small",
            .max_value_message = "count too large" } },
        { .kind = FORM_FIELD_DECIMAL, .decimal = {
            .common = { .name = "rate" },
            .has_min_value = 1, .min_value = 0.5,
            .has_max_value = 1, .max_value = 1.5,
            .min_value_message = "rate too small",
            .max_value_message = "rate too large" } },
        { .kind = FORM_FIELD_BOOLEAN, .boolean = {
            .common = { .name = "approved", .required = 1,
                        .required_message = "approval required" } } }
    };
    const form_schema_t typed_schema = {
        .fields = typed_fields, .fields_count = 3
    };
    form_input_t boundary_inputs[] = {
        TEXT(strdup("0")), TEXT(strdup("1.5")), TEXT(strdup("true"))
    };
    form_t* boundary = form_create(&typed_schema, boundary_inputs);
    TEST_REQUIRE_NOT_NULL(boundary, "Boundary form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(boundary), "Values on the boundary should be accepted", free_boundary);
    TEST_ASSERT_EQUAL(0, form_cleaned_data(boundary, 0)->data.integer, "Count should be the minimum");
    TEST_ASSERT(form_cleaned_data(boundary, 1)->data.decimal == 1.5, "Rate should be the maximum");

free_boundary:
    form_free(boundary);

    form_input_t below_inputs[] = {
        TEXT(strdup("-1")), TEXT(strdup("0.4")), TEXT(strdup("false"))
    };
    form_t* below = form_create(&typed_schema, below_inputs);
    TEST_REQUIRE_NOT_NULL(below, "Below form should be created");
    TEST_ASSERT(!form_is_valid(below), "Values below the minimum should be rejected");
    TEST_ASSERT_EQUAL(FORM_MIN_VALUE, form_error_code(below, 0), "Count should report FORM_MIN_VALUE");
    TEST_ASSERT_EQUAL(FORM_MIN_VALUE, form_error_code(below, 1), "Rate should report FORM_MIN_VALUE");
    TEST_ASSERT_EQUAL(FORM_REQUIRED, form_error_code(below, 2), "A false boolean should not satisfy required");
    TEST_ASSERT_STR_EQUAL("count too small", form_error_message(below, 0), "Count min message should be reported");
    TEST_ASSERT_STR_EQUAL("rate too small", form_error_message(below, 1), "Decimal min message should be reported");
    TEST_ASSERT_STR_EQUAL("approval required", form_error_message(below, 2), "Approval required message should be reported");

    form_free(below);

    form_input_t above_inputs[] = {
        TEXT(strdup("11")), TEXT(strdup("1.6")), TEXT(strdup("1"))
    };
    form_t* above = form_create(&typed_schema, above_inputs);
    TEST_REQUIRE_NOT_NULL(above, "Above form should be created");
    TEST_ASSERT(!form_is_valid(above), "Values above the maximum should be rejected");
    TEST_ASSERT_EQUAL(FORM_MAX_VALUE, form_error_code(above, 0), "Count should report FORM_MAX_VALUE");
    TEST_ASSERT_EQUAL(FORM_MAX_VALUE, form_error_code(above, 1), "Rate should report FORM_MAX_VALUE");
    TEST_ASSERT_STR_EQUAL("count too large", form_error_message(above, 0), "Integer max message should be reported");
    TEST_ASSERT_STR_EQUAL("rate too large", form_error_message(above, 1), "Decimal max message should be reported");

    form_free(above);

    form_input_t nonfinite_inputs[] = {
        TEXT(strdup("0")), TEXT(strdup("NaN")), TEXT(strdup("true"))
    };
    form_t* nonfinite = form_create(&typed_schema, nonfinite_inputs);
    TEST_REQUIRE_NOT_NULL(nonfinite, "Non-finite form should be created");
    TEST_ASSERT(!form_is_valid(nonfinite), "A non-finite decimal should be rejected");
    TEST_ASSERT_EQUAL(FORM_INVALID, form_error_code(nonfinite, 1), "NaN should report FORM_INVALID");

    form_free(nonfinite);

    const form_field_spec_t inverted_fields[] = {
        { .kind = FORM_FIELD_INTEGER, .integer = {
            .common = { .name = "count" },
            .has_min_value = 1, .min_value = 2,
            .has_max_value = 1, .max_value = 1 } }
    };
    const form_schema_t inverted_schema = {
        .fields = inverted_fields, .fields_count = 1
    };
    form_input_t inverted_inputs[] = { TEXT(strdup("1")) };
    form_t* rejected = form_create(&inverted_schema, inverted_inputs);
    TEST_ASSERT_NULL(rejected, "min_value above max_value should be refused at create time");
    form_free(rejected);

    const form_field_spec_t bounded_default_fields[] = {
        { .kind = FORM_FIELD_INTEGER, .integer = {
            .common = { .name = "count" },
            .has_default = 1, .default_value = 3,
            .has_max_value = 1, .max_value = 2,
            .max_value_message = "default too large" } }
    };
    const form_schema_t bounded_default_schema = {
        .fields = bounded_default_fields, .fields_count = 1
    };
    form_input_t bounded_default_inputs[] = { TEXT(NULL) };
    form_t* bounded_default = form_create(&bounded_default_schema,
                                          bounded_default_inputs);
    TEST_REQUIRE_NOT_NULL(bounded_default, "Bounded default form should be created");
    TEST_ASSERT(!form_is_valid(bounded_default), "A default outside the bounds should invalidate the form");
    TEST_ASSERT_EQUAL(FORM_MAX_VALUE, form_error_code(bounded_default, 0), "Default should report FORM_MAX_VALUE");
    TEST_ASSERT_STR_EQUAL("default too large", form_error_message(bounded_default, 0), "Max value message should be reported for the default");

    form_free(bounded_default);
}

// ============================================================================
// Описание полей
// ============================================================================

TEST(test_form_unspecified_kind) {
    TEST_SUITE("form");
    TEST_CASE("FORM_FIELD_UNSPECIFIED is refused at create time");

    const form_field_spec_t unspecified_fields[] = { { .kind = FORM_FIELD_UNSPECIFIED } };
    const form_schema_t unspecified_schema = {
        .fields = unspecified_fields, .fields_count = 1
    };
    form_input_t unspecified_inputs[] = { TEXT(strdup("value")) };
    form_t* rejected = form_create(&unspecified_schema, unspecified_inputs);
    TEST_ASSERT_NULL(rejected, "A field without a kind should be refused");
    form_free(rejected);
}

TEST(test_form_boolean_default) {
    TEST_SUITE("form");
    TEST_CASE("Optional boolean: explicit false and defaulted false");

    const form_field_spec_t optional_boolean_fields[] = {
        { .kind = FORM_FIELD_BOOLEAN, .boolean = {
            .common = { .name = "approved" },
            .has_default = 1, .default_value = 0 } }
    };
    const form_schema_t optional_boolean_schema = {
        .fields = optional_boolean_fields, .fields_count = 1
    };
    form_input_t false_inputs[] = { TEXT(strdup("false")) };
    form_t* optional_false = form_create(&optional_boolean_schema, false_inputs);
    TEST_REQUIRE_NOT_NULL(optional_false, "Explicit false form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(optional_false), "An optional false should be valid", free_false);
    TEST_ASSERT_EQUAL(0, form_cleaned_data(optional_false, 0)->data.boolean, "Explicit false should be kept");

free_false:
    form_free(optional_false);

    form_input_t default_false_inputs[] = { TEXT(NULL) };
    form_t* default_false = form_create(&optional_boolean_schema,
                                        default_false_inputs);
    TEST_REQUIRE_NOT_NULL(default_false, "Defaulted false form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(default_false), "A defaulted false should be valid", free_default_false);
    TEST_ASSERT_EQUAL(FORM_VALUE_BOOLEAN, form_cleaned_data(default_false, 0)->kind, "Default should produce a boolean value");
    TEST_ASSERT_EQUAL(0, form_cleaned_data(default_false, 0)->data.boolean, "Default should be false");

free_default_false:
    form_free(default_false);
}

TEST(test_form_decimal_default) {
    TEST_SUITE("form");
    TEST_CASE("Decimal default and long double parsing precision");

    const form_field_spec_t decimal_default_fields[] = {
        { .kind = FORM_FIELD_DECIMAL, .decimal = {
            .common = { .name = "rate" },
            .has_default = 1, .default_value = 1.25 } }
    };
    const form_schema_t decimal_default_schema = {
        .fields = decimal_default_fields, .fields_count = 1
    };
    form_input_t decimal_default_inputs[] = { TEXT(NULL) };
    form_t* decimal_default = form_create(&decimal_default_schema,
                                          decimal_default_inputs);
    TEST_REQUIRE_NOT_NULL(decimal_default, "Decimal default form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(decimal_default), "Decimal default form should be valid", free_decimal);
    TEST_ASSERT(form_cleaned_data(decimal_default, 0)->data.decimal == 1.25, "Decimal default should be 1.25");

free_decimal:
    form_free(decimal_default);

#if LDBL_MANT_DIG > DBL_MANT_DIG
    form_input_t precise_input = TEXT(strdup("1.000000000000000001"));
    form_value_t precise_value = {0};
    TEST_ASSERT(form_parse_decimal(&precise_input, &precise_value, NULL), "Precise decimal should parse");
    TEST_ASSERT(precise_value.data.decimal > 1.0L, "Parsing should keep long double precision");
    free(precise_input.data.text);
#endif
}

// ============================================================================
// Регулярные выражения
// ============================================================================

TEST(test_form_regex) {
    TEST_SUITE("form");
    TEST_CASE("Text regex: matching, non-matching, empty, default and malformed pattern");

    const form_field_spec_t regex_fields[] = {
        { .kind = FORM_FIELD_TEXT, .text = {
            .common = { .name = "letters" },
            .regex = "\\A\\p{L}+\\z",
            .regex_message = "letters only" } }
    };
    const form_schema_t regex_schema = {
        .fields = regex_fields, .fields_count = 1,
        .clean = strip_spaces
    };
    form_input_t regex_valid_inputs[] = { TEXT(strdup(" Иван ")) };
    form_t* regex_valid = form_create(&regex_schema, regex_valid_inputs);
    TEST_REQUIRE_NOT_NULL(regex_valid, "Matching regex form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(regex_valid), "Matching value should be valid", free_regex_valid);
    TEST_ASSERT_STR_EQUAL("Иван", form_cleaned_data(regex_valid, 0)->data.text, "Value should be trimmed before matching");

free_regex_valid:
    form_free(regex_valid);

    form_input_t regex_invalid_inputs[] = { TEXT(strdup("Иван1")) };
    form_t* regex_invalid = form_create(&regex_schema, regex_invalid_inputs);
    TEST_REQUIRE_NOT_NULL(regex_invalid, "Non-matching regex form should be created");
    TEST_ASSERT(!form_is_valid(regex_invalid), "Non-matching value should be rejected");
    TEST_ASSERT_EQUAL(FORM_REGEX, form_error_code(regex_invalid, 0), "Non-matching value should report FORM_REGEX");
    TEST_ASSERT_STR_EQUAL("letters only", form_error_message(regex_invalid, 0), "Regex message should be reported");

    form_free(regex_invalid);

    form_input_t regex_empty_inputs[] = { TEXT(NULL) };
    form_t* regex_empty = form_create(&regex_schema, regex_empty_inputs);
    TEST_REQUIRE_NOT_NULL(regex_empty, "Empty regex form should be created");
    TEST_ASSERT(form_is_valid(regex_empty), "An optional empty value should skip the regex");

    form_free(regex_empty);

    const form_field_spec_t regex_default_fields[] = {
        { .kind = FORM_FIELD_TEXT, .text = {
            .common = { .name = "letters" },
            .default_value = "abc1", .regex = "\\A[a-z]+\\z",
            .regex_message = "letters only" } }
    };
    const form_schema_t regex_default_schema = {
        .fields = regex_default_fields, .fields_count = 1
    };
    form_input_t regex_default_inputs[] = { TEXT(NULL) };
    form_t* regex_default = form_create(&regex_default_schema,
                                        regex_default_inputs);
    TEST_REQUIRE_NOT_NULL(regex_default, "Regex default form should be created");
    TEST_ASSERT(!form_is_valid(regex_default), "A default violating the regex should invalidate the form");
    TEST_ASSERT_EQUAL(FORM_REGEX, form_error_code(regex_default, 0), "Default should report FORM_REGEX");

    form_free(regex_default);

    const form_field_spec_t bad_regex_fields[] = {
        { .kind = FORM_FIELD_TEXT, .text = {
            .common = { .name = "good" }, .regex = "^ok$" } },
        { .kind = FORM_FIELD_TEXT, .text = {
            .common = { .name = "broken" }, .regex = "[" } }
    };
    const form_schema_t bad_regex_schema = {
        .fields = bad_regex_fields, .fields_count = 2
    };
    form_input_t bad_regex_inputs[] = {
        TEXT(strdup("ok")), TEXT(strdup("value"))
    };
    form_t* rejected = form_create(&bad_regex_schema, bad_regex_inputs);
    TEST_ASSERT_NULL(rejected, "A malformed pattern should be refused at create time");
    form_free(rejected);
}

TEST(test_form_parser_boundaries) {
    TEST_SUITE("form");
    TEST_CASE("Built-in parsers preserve endpoints and reject malformed numbers");

    const struct { const char* text; int64_t expected; } integers[] = {
        { "-9223372036854775808", INT64_MIN }, { "9223372036854775807", INT64_MAX },
        { "0", 0 }, { "+42", 42 }, { "-1", -1 }
    };
    for (size_t i = 0; i < sizeof integers / sizeof *integers; i++) {
        form_input_t input = TEXT((char*)integers[i].text);
        form_value_t value = {0};
        TEST_ASSERT(form_parse_integer(&input, &value, NULL), integers[i].text);
        TEST_ASSERT_EQUAL(FORM_VALUE_INTEGER, value.kind, "Integer kind");
        TEST_ASSERT_EQUAL(integers[i].expected, value.data.integer, integers[i].text);
    }
    const char* invalid_integers[] = {
        "9223372036854775808", "-9223372036854775809", "", " ", "+", "1x", "1.0", "0x10"
    };
    const char* invalid_decimals[] = {
        "", " ", ".", "1.2x", "NaN", "inf", "-inf", "1e99999", "1e-99999"
    };
    const char* invalid_booleans[] = { "", "True", "FALSE", "yes", "2", "true " };
    const form_parse_fn parsers[] = { form_parse_integer, form_parse_decimal, form_parse_boolean };
    const char* const* invalid[] = { invalid_integers, invalid_decimals, invalid_booleans };
    const size_t counts[] = {
        sizeof invalid_integers / sizeof *invalid_integers,
        sizeof invalid_decimals / sizeof *invalid_decimals,
        sizeof invalid_booleans / sizeof *invalid_booleans
    };
    for (size_t p = 0; p < 3; p++) {
        form_value_t value = {0};
        form_input_t missing = TEXT(NULL);
        form_input_t object = { .kind = FORM_INPUT_OBJECT, .data.object = &value };
        TEST_ASSERT(!parsers[p](NULL, &value, NULL), "NULL input is rejected");
        TEST_ASSERT(!parsers[p](&missing, &value, NULL), "NULL text is rejected");
        TEST_ASSERT(!parsers[p](&object, &value, NULL), "Objects are rejected");
        form_input_t present = TEXT("1");
        TEST_ASSERT(!parsers[p](&present, NULL, NULL), "NULL output is rejected");
        for (size_t i = 0; i < counts[p]; i++) {
            form_input_t input = TEXT((char*)invalid[p][i]);
            TEST_ASSERT(!parsers[p](&input, &value, NULL), invalid[p][i]);
        }
    }
    const char* booleans[] = { "false", "true", "0", "1" };
    for (size_t i = 0; i < 4; i++) {
        form_input_t input = TEXT((char*)booleans[i]);
        form_value_t value = {0};
        TEST_ASSERT(form_parse_boolean(&input, &value, NULL), booleans[i]);
        TEST_ASSERT_EQUAL(FORM_VALUE_BOOLEAN, value.kind, "Boolean kind");
        TEST_ASSERT_EQUAL(i % 2, value.data.boolean, booleans[i]);
    }
    form_input_t decimal = TEXT("-1.25e2");
    form_value_t value = {0};
    TEST_ASSERT(form_parse_decimal(&decimal, &value, NULL), "Signed exponent parses");
    TEST_ASSERT_EQUAL(FORM_VALUE_DECIMAL, value.kind, "Decimal kind");
    TEST_ASSERT(value.data.decimal == -125.0L, "Exponent is applied");
}

TEST(test_form_invalid_schemas_consume_inputs) {
    TEST_SUITE("form");
    TEST_CASE("Invalid schemas consume all inputs, including those after the bad field");
    const form_validator_t no_check = {0};
    const form_field_spec_t bad[] = {
        { .kind = FORM_FIELD_TEXT }, /* Missing name. */
        { .kind = FORM_FIELD_TEXT, .text = { .common = { .name = "x", .validators_count = 1 } } },
        { .kind = FORM_FIELD_TEXT, .text = { .common = { .name = "x", .validators = &no_check, .validators_count = 1 } } },
        { .kind = FORM_FIELD_TEXT, .text = { .common = { .name = "x" }, .min_length = 1 } }, /* No length hook. */
        { .kind = FORM_FIELD_DECIMAL, .decimal = { .common = { .name = "x" }, .has_min_value = 1, .min_value = 2, .has_max_value = 1, .max_value = 1 } },
        { .kind = FORM_FIELD_DECIMAL, .decimal = { .common = { .name = "x" }, .has_default = 1, .default_value = NAN } },
        { .kind = FORM_FIELD_DECIMAL, .decimal = { .common = { .name = "x" }, .has_min_value = 1, .min_value = -INFINITY } },
        { .kind = FORM_FIELD_DECIMAL, .decimal = { .common = { .name = "x" }, .has_max_value = 1, .max_value = INFINITY } },
        { .kind = FORM_FIELD_BOOLEAN, .boolean = { .common = { .name = "x" }, .has_default = 1, .default_value = 2 } },
        { .kind = FORM_FIELD_CUSTOM, .custom = { .common = { .name = "x" } } },
        { .kind = FORM_FIELD_TEXT, .text = { .common = { .name = "x" }, .regex = "[" } },
        { .kind = (form_field_kind_t)-1 }
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        form_field_spec_t specs[] = {
            bad[i], { .kind = FORM_FIELD_OBJECT, .object = { .common = { .name = "tail" } } }
        };
        const form_schema_t local = { .fields = specs, .fields_count = 2 };
        int* payload = malloc(sizeof *payload);
        TEST_REQUIRE_NOT_NULL(payload, "Owned input should allocate");
        form_input_t inputs[] = {
            TEXT(strdup("bad")), { .kind = FORM_INPUT_OBJECT, .data.object = payload, .destroy = destroy_object }
        };
        destroyed = 0;
        form_t* form = form_create(&local, inputs);
        TEST_ASSERT_NULL(form, "Invalid schema must fail at construction");
        TEST_ASSERT_EQUAL(1, destroyed, "Construction failure must consume the trailing object");
        form_free(form);
    }
    const form_field_spec_t inverted = { .kind = FORM_FIELD_TEXT, .text = {
        .common = { .name = "x" }, .min_length = 3, .max_length = 2 } };
    const form_schema_t local = { .fields = &inverted, .fields_count = 1, .length = strlen };
    form_input_t input = TEXT(strdup("xx"));
    form_t* form = form_create(&local, &input);
    TEST_ASSERT_NULL(form, "Inverted lengths fail even with a length hook");
    form_free(form);
}

typedef struct {
    int field_calls;
    int schema_calls;
    int reject;
} validation_probe_t;

static int count_validation(const form_value_t* value, void* context) {
    validation_probe_t* probe = context;
    probe->field_calls++;
    TEST_ASSERT_EQUAL(FORM_VALUE_INTEGER, value->kind, "Validator receives parsed data");
    return 1;
}

static void probe_validation(form_t* form, void* context) {
    validation_probe_t* probe = context;
    probe->schema_calls++;
    TEST_ASSERT_NOT_NULL(form_field_value(form, 0), "Field data is visible inside schema validation");
    TEST_ASSERT_NULL(form_cleaned_data(form, 0), "Cleaned data waits for schema validation");
    TEST_ASSERT(!form_is_valid(form), "Recursive validation must not recurse");
    TEST_ASSERT(!form_add_error(form, 1, FORM_INVALID, "out of bounds"), "Invalid index cannot add an error");
    TEST_ASSERT(!form_add_error(form, 0, FORM_VALID, "valid"), "FORM_VALID is not an error");
    TEST_ASSERT(!form_add_non_field_error(form, NULL), "NULL is not a non-field error");
    if (probe->reject) {
        TEST_ASSERT(form_add_error(form, 0, FORM_INVALID, "first"), "First field error is accepted");
        TEST_ASSERT(!form_add_error(form, 0, FORM_REQUIRED, "second"), "Second field error is ignored");
        TEST_ASSERT(form_add_non_field_error(form, "global first"), "First global error is accepted");
        TEST_ASSERT(!form_add_non_field_error(form, "global second"), "Second global error is ignored");
    }
}

TEST(test_form_validation_lifecycle) {
    TEST_SUITE("form");
    TEST_CASE("Validation executes once, preserves first errors and gates accessors");
    for (int reject = 0; reject <= 1; reject++) {
        validation_probe_t probe = { .reject = reject };
        const form_validator_t validator = { .check = count_validation, .context = &probe };
        const form_field_spec_t field = { .kind = FORM_FIELD_INTEGER, .integer = {
            .common = { .name = "number", .validators = &validator, .validators_count = 1 } } };
        const form_schema_t local = { .fields = &field, .fields_count = 1,
            .validate = probe_validation, .context = &probe };
        form_input_t input = TEXT(strdup("42"));
        form_t* form = form_create(&local, &input);
        TEST_REQUIRE_NOT_NULL(form, "Lifecycle form should build");
        TEST_ASSERT_STR_EQUAL("number", form_field_name(form, 0), "Field name is available immediately");
        TEST_ASSERT_NULL(form_field_value(form, 0), "Field value is hidden before validation");
        TEST_ASSERT_NULL(form_error_message(form, 0), "No errors before validation");
        TEST_ASSERT(!form_add_error(form, 0, FORM_INVALID, "early"), "Errors cannot be added before validation");
        TEST_ASSERT(!form_add_non_field_error(form, "early"), "Global errors cannot be added early");
        TEST_ASSERT_EQUAL(!reject, form_is_valid(form), "First verdict");
        TEST_ASSERT_EQUAL(!reject, form_is_valid(form), "Cached verdict");
        TEST_ASSERT_EQUAL(1, probe.field_calls, "Field validator executes exactly once");
        TEST_ASSERT_EQUAL(1, probe.schema_calls, "Schema validator executes exactly once");
        TEST_ASSERT(!form_add_error(form, 0, FORM_INVALID, "late"), "Errors cannot be added after validation");
        TEST_ASSERT(!form_add_non_field_error(form, "late"), "Global errors cannot be added late");
        if (reject) {
            TEST_ASSERT_EQUAL(FORM_INVALID, form_error_code(form, 0), "First code wins");
            TEST_ASSERT_STR_EQUAL("first", form_error_message(form, 0), "First message wins");
            TEST_ASSERT_STR_EQUAL("global first", form_non_field_error(form), "First global message wins");
            TEST_ASSERT_NULL(form_cleaned_data(form, 0), "Rejected form hides cleaned data");
        } else {
            TEST_ASSERT_NOT_NULL(form_cleaned_data(form, 0), "Valid form exposes cleaned data");
            TEST_ASSERT_EQUAL(FORM_VALID, form_error_code(form, 0), "Valid field has no error");
            TEST_ASSERT_NULL(form_non_field_error(form), "Valid form has no global error");
        }
        TEST_ASSERT_NULL(form_field_value(form, 1), "Out-of-range field is hidden");
        TEST_ASSERT_NULL(form_cleaned_data(form, 1), "Out-of-range cleaned data is hidden");
        TEST_ASSERT_NULL(form_field_name(form, 1), "Out-of-range name is NULL");
        TEST_ASSERT_NULL(form_error_message(form, 1), "Out-of-range error is NULL");
        form_free(form);
    }
    TEST_ASSERT(!form_is_valid(NULL), "NULL form is invalid");
    TEST_ASSERT_EQUAL_SIZE(0, form_fields_count(NULL), "NULL form has no fields");
    TEST_ASSERT_NULL(form_field_name(NULL, 0), "NULL form has no name");
    TEST_ASSERT_NULL(form_field_value(NULL, 0), "NULL form has no value");
    TEST_ASSERT_NULL(form_cleaned_data(NULL, 0), "NULL form has no cleaned data");
    TEST_ASSERT_NULL(form_error_message(NULL, 0), "NULL form has no message");
    TEST_ASSERT_NULL(form_non_field_error(NULL), "NULL form has no global error");
    TEST_ASSERT_EQUAL(FORM_VALID, form_error_code(NULL, 0), "NULL form has no field error");
    TEST_ASSERT(!form_add_error(NULL, 0, FORM_INVALID, "x"), "NULL form cannot receive an error");
    TEST_ASSERT(!form_add_non_field_error(NULL, "x"), "NULL form cannot receive a global error");
    form_free(NULL);
}

TEST(test_form_required_precedes_default) {
    TEST_SUITE("form");
    TEST_CASE("Required empty inputs do not use defaults, including after cleaning");
    const form_field_spec_t field = { .kind = FORM_FIELD_TEXT, .text = {
        .common = { .name = "name", .required = 1, .required_message = "required" },
        .default_value = "fallback" } };
    const form_schema_t local = { .fields = &field, .fields_count = 1, .clean = strip_spaces };
    const char* empty[] = { NULL, "", "   " };
    for (size_t i = 0; i < 3; i++) {
        form_input_t input = TEXT(empty[i] ? strdup(empty[i]) : NULL);
        form_t* form = form_create(&local, &input);
        TEST_REQUIRE_NOT_NULL(form, "Required form should build");
        TEST_ASSERT(!form_is_valid(form), "Empty required field is invalid despite its default");
        TEST_ASSERT_EQUAL(FORM_REQUIRED, form_error_code(form, 0), "Required check precedes default");
        TEST_ASSERT_STR_EQUAL("required", form_error_message(form, 0), "Required message is selected");
        form_free(form);
    }
}

TEST(test_form_borrowed_defaults) {
    TEST_SUITE("form");
    TEST_CASE("Object and custom defaults are borrowed");
    int payload = 42;
    const form_value_t default_value = {
        .kind = FORM_VALUE_OBJECT, .data.object = &payload, .destroy = destroy_object
    };
    const form_field_spec_t specs[] = {
        { .kind = FORM_FIELD_OBJECT, .object = { .common = { .name = "object" }, .default_value = &payload } },
        { .kind = FORM_FIELD_CUSTOM, .custom = { .common = { .name = "custom" },
            .default_value = &default_value, .parse = parse_owned_object } }
    };
    const form_schema_t local = { .fields = specs, .fields_count = 2 };
    form_input_t inputs[] = { { .kind = FORM_INPUT_OBJECT }, TEXT(NULL) };
    destroyed = 0;
    form_t* form = form_create(&local, inputs);
    TEST_REQUIRE_NOT_NULL(form, "Default form should build");
    TEST_REQUIRE_GOTO(form_is_valid(form), "Borrowed defaults validate", cleanup);
    for (size_t i = 0; i < 2; i++) {
        const form_value_t* value = form_cleaned_data(form, i);
        TEST_REQUIRE_GOTO(value != NULL && value->kind == FORM_VALUE_OBJECT, "Object default kind", cleanup);
        TEST_ASSERT(value->data.object == &payload, "Default pointer is borrowed");
        TEST_ASSERT(value->destroy == NULL, "Default must not retain a destructor");
    }
cleanup:
    form_free(form);
    TEST_ASSERT_EQUAL(0, destroyed, "Borrowed defaults are never destroyed by the form");
}

static int reject_counted(const form_value_t* value, void* context) {
    (void)value;
    (*(int*)context)++;
    return 0;
}

TEST(test_form_validator_order) {
    TEST_SUITE("form");
    TEST_CASE("Validators stop at first rejection, skip empty/invalid input and use message fallback");
    int calls[] = {0, 0};
    form_validator_t validators[] = {
        { .check = reject_counted, .context = &calls[0] },
        { .check = reject_counted, .context = &calls[1], .message = "second" }
    };
    const form_field_spec_t field = { .kind = FORM_FIELD_INTEGER, .integer = {
        .common = { .name = "x", .validators = validators, .validators_count = 2, .invalid_message = "fallback" } } };
    const form_schema_t local = { .fields = &field, .fields_count = 1 };
    const char* texts[] = { NULL, "invalid", "42" };
    for (size_t i = 0; i < 3; i++) {
        form_input_t input = TEXT(texts[i] ? strdup(texts[i]) : NULL);
        form_t* form = form_create(&local, &input);
        TEST_REQUIRE_NOT_NULL(form, "Validator form should build");
        TEST_ASSERT_EQUAL(i == 0, form_is_valid(form), "Only optional empty input is valid");
        TEST_ASSERT_EQUAL(i == 2, calls[0], "First validator runs only on parsed nonempty input");
        TEST_ASSERT_EQUAL(0, calls[1], "Second validator never runs after rejection");
        if (i != 0)
            TEST_ASSERT_STR_EQUAL("fallback", form_error_message(form, 0), "Missing validator message uses field message");
        form_free(form);
    }
}

TEST(test_form_optional_kinds) {
    TEST_SUITE("form");
    TEST_CASE("Missing optional inputs stay empty without defaults");
    const form_field_spec_t specs[] = {
        { .kind = FORM_FIELD_INTEGER, .integer = { .common = { .name = "integer" } } },
        { .kind = FORM_FIELD_DECIMAL, .decimal = { .common = { .name = "decimal" } } },
        { .kind = FORM_FIELD_BOOLEAN, .boolean = { .common = { .name = "boolean" } } },
        { .kind = FORM_FIELD_OBJECT, .object = { .common = { .name = "object" } } },
        { .kind = FORM_FIELD_CUSTOM, .custom = { .common = { .name = "custom" }, .parse = parse_owned_object } }
    };
    const form_schema_t local = { .fields = specs, .fields_count = 5 };
    form_input_t inputs[5] = {0};
    form_t* form = form_create(&local, inputs);
    TEST_REQUIRE_NOT_NULL(form, "Optional form should build");
    TEST_REQUIRE_GOTO(form_is_valid(form), "Missing optional values validate", cleanup_optional);
    for (size_t i = 0; i < 5; i++) {
        const form_value_t* value = form_cleaned_data(form, i);
        TEST_REQUIRE_NOT_NULL_GOTO(value, "Empty values are accessible", cleanup_optional);
        TEST_ASSERT_EQUAL(FORM_VALUE_EMPTY, value->kind, "Missing values do not become zero or false");
    }
cleanup_optional:
    form_free(form);
}

TEST(test_form_free_before_validation) {
    TEST_SUITE("form");
    TEST_CASE("Owned inputs are destroyed even when validation never runs");
    const form_field_spec_t field = { .kind = FORM_FIELD_OBJECT, .object = { .common = { .name = "object" } } };
    const form_schema_t local = { .fields = &field, .fields_count = 1 };
    int* payload = malloc(sizeof *payload);
    TEST_REQUIRE_NOT_NULL(payload, "Payload should allocate");
    form_input_t input = { .kind = FORM_INPUT_OBJECT, .data.object = payload, .destroy = destroy_object };
    destroyed = 0;
    form_t* form = form_create(&local, &input);
    TEST_REQUIRE_NOT_NULL(form, "Owned form should build");
    TEST_ASSERT_EQUAL(0, destroyed, "Input is alive after construction");
    form_free(form);
    TEST_ASSERT_EQUAL(1, destroyed, "Unvalidated input is destroyed exactly once");
}

TEST(test_form_invalid_utf8_regex) {
    TEST_SUITE("form");
    TEST_CASE("Invalid UTF-8 reports FORM_INVALID, not a regular expression mismatch");
    const form_field_spec_t field = { .kind = FORM_FIELD_TEXT, .text = {
        .common = { .name = "text" }, .regex = "." } };
    const form_schema_t local = { .fields = &field, .fields_count = 1 };
    form_input_t input = TEXT(strdup("\xff"));
    form_t* form = form_create(&local, &input);
    TEST_REQUIRE_NOT_NULL(form, "Regex form should build");
    TEST_ASSERT(!form_is_valid(form), "Invalid UTF-8 must fail");
    TEST_ASSERT_EQUAL(FORM_INVALID, form_error_code(form, 0), "Encoding error differs from no match");
    form_free(form);
}

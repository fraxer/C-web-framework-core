#include "framework.h"
#include "formdataparser.h"
#include <string.h>
#include <stdlib.h>

// Helper: parse a Content-Disposition value string and return parser
static formdataparser_t parse_fd(const char* input, int*ok) {
    formdataparser_t parser;
    size_t len = strlen(input);
    formdataparser_init(&parser, "form-data");
    int res = formdataparser_parse(&parser, input, len);
    if (ok != NULL)
        *ok = res;

    return parser;
}

// Helper: check disposition_type matches expected string
static int dt_equals(formdataparser_t* p, const char* expected) {
    if (!p->disposition_type || !expected) return p->disposition_type == NULL && expected == NULL;
    return strcmp(p->disposition_type, expected) == 0;
}

// Helper: get field value as C string
static const char* field_value(formdatafield_t* f) {
    return f ? str_get(&f->value) : "";
}

// Helper: get field key as C string
static const char* field_key(formdatafield_t* f) {
    return f ? str_get(&f->key) : "";
}

// Helper: get field value length
static size_t field_value_len(formdatafield_t* f) {
    return f ? str_size(&f->value) : 0;
}

// ============================================================================
// Test Suite 1: Type only
// ============================================================================

TEST(test_fdp_type_only) {
    TEST_SUITE("FormDataParser - Type Only");
    TEST_CASE("Parse type without any key=value pairs");

    int ok;
    formdataparser_t parser = parse_fd("form-data", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT(dt_equals(&parser, "form-data"), "disposition_type should match 'form-data'");
    TEST_ASSERT_NULL(parser.field, "No fields expected");

    formdataparser_clear(&parser);
}

TEST(test_fdp_type_with_trailing_semicolon) {
    TEST_CASE("Type with trailing semicolon but no key=value");

    int ok;
    formdataparser_t parser = parse_fd("form-data;", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT(dt_equals(&parser, "form-data"), "disposition_type should match 'form-data'");
    TEST_ASSERT_NULL(parser.field, "No fields — semicolon without key=value is safely ignored");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 2: Basic key=value — name only
// ============================================================================

TEST(test_fdp_name_quoted) {
    TEST_SUITE("FormDataParser - Name Field");
    TEST_CASE("Parse name=\"field1\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"field1\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have a field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Field key should be 'name'");
    TEST_ASSERT_STR_EQUAL("field1", field_value(parser.field), "Field value should be 'field1'");
    TEST_ASSERT_EQUAL_SIZE(6, field_value_len(parser.field), "Value size should be 6 for 'field1'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_name_unquoted) {
    TEST_CASE("Parse name=field1 (no quotes)");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=field1", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have a field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Field key should be 'name'");
    TEST_ASSERT_STR_EQUAL("field1", field_value(parser.field), "Field value should be 'field1'");
    TEST_ASSERT_EQUAL_SIZE(6, field_value_len(parser.field), "Value size should be 6 for 'field1'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 3: name + filename
// ============================================================================

TEST(test_fdp_name_and_filename) {
    TEST_SUITE("FormDataParser - Name and Filename");
    TEST_CASE("Parse name and filename");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"upload\"; filename=\"doc.pdf\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have first field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "First key");
    TEST_ASSERT_STR_EQUAL("upload", field_value(parser.field), "First value");
    TEST_ASSERT_EQUAL_SIZE(6, field_value_len(parser.field), "First value size for 'upload'");

    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have second field");
    TEST_ASSERT_STR_EQUAL("filename", field_key(parser.field->next), "Second key");
    TEST_ASSERT_STR_EQUAL("doc.pdf", field_value(parser.field->next), "Second value");
    TEST_ASSERT_EQUAL_SIZE(7, field_value_len(parser.field->next), "Second value size for 'doc.pdf'");
    TEST_ASSERT_NULL(parser.field->next->next, "Should have exactly two fields");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 4: Multiple fields (3+)
// ============================================================================

TEST(test_fdp_three_fields) {
    TEST_SUITE("FormDataParser - Multiple Fields");
    TEST_CASE("Parse three key=value pairs");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"file\"; filename=\"test.txt\"; extra=\"val\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    formdatafield_t* f = parser.field;

    TEST_ASSERT_NOT_NULL(f, "First field");
    TEST_ASSERT_STR_EQUAL("name", field_key(f), "First key");

    TEST_ASSERT_NOT_NULL(f->next, "Second field");
    TEST_ASSERT_STR_EQUAL("filename", field_key(f->next), "Second key");

    TEST_ASSERT_NOT_NULL(f->next->next, "Third field");
    TEST_ASSERT_STR_EQUAL("extra", field_key(f->next->next), "Third key");
    TEST_ASSERT_STR_EQUAL("val", field_value(f->next->next), "Third value");
    TEST_ASSERT_EQUAL_SIZE(3, field_value_len(f->next->next), "Third value size for 'val'");

    TEST_ASSERT_NULL(f->next->next->next, "Should have exactly three fields");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 5: Empty values
// ============================================================================

TEST(test_fdp_empty_quoted_value) {
    TEST_SUITE("FormDataParser - Empty Values");
    TEST_CASE("Key with empty quoted value: name=\"\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Key is 'name'");
    TEST_ASSERT_EQUAL_SIZE(0, field_value_len(parser.field), "Value size should be 0");

    formdataparser_clear(&parser);
}

TEST(test_fdp_empty_unquoted_value_after_equals) {
    TEST_CASE("Key with equals but no value before semicolon: name=; filename=\"f\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=; filename=\"f\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have first field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "First key is 'name'");

    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have second field");
    TEST_ASSERT_STR_EQUAL("filename", field_key(parser.field->next), "Second key is 'filename'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 6: Escaped quotes
// ============================================================================

TEST(test_fdp_escaped_quote_in_value) {
    TEST_SUITE("FormDataParser - Escaped Quotes");
    TEST_CASE("Value with backslash-escaped quote: name=\"a\\\"b\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a\\\"b\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Key is 'name'");

    // Parser: when seeing \" inside quote, backslash is overwritten by the quote char
    // So "a\"b" → buffer receives: a, \, then " overwrites \ → a" then b → "a\"b" (3 chars)
    TEST_ASSERT_STR_EQUAL("a\"b", field_value(parser.field), "Value should be 'a\"b'");
    TEST_ASSERT_EQUAL_SIZE(3, field_value_len(parser.field), "Value size should be 3 for 'a\"b'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_multiple_escaped_quotes) {
    TEST_CASE("Value with multiple escaped quotes: name=\"a\\\"b\\\"c\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a\\\"b\\\"c\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    // a \" b \" c: each \" → backslash overwritten by quote char → a"b"c = 5 chars
    TEST_ASSERT_STR_EQUAL("a\"b\"c", field_value(parser.field), "Value should be 'a\"b\"c'");
    TEST_ASSERT_EQUAL_SIZE(5, field_value_len(parser.field), "Value size for 'a\"b\"c'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 7: Spaces handling
// ============================================================================

TEST(test_fdp_space_in_quoted_value) {
    TEST_SUITE("FormDataParser - Spaces");
    TEST_CASE("Spaces inside quotes are preserved");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"hello world\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_EQUAL_SIZE(11, field_value_len(parser.field), "Value size for 'hello world'");
    TEST_ASSERT_STR_EQUAL("hello world", field_value(parser.field), "Value is 'hello world'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_leading_spaces_before_type) {
    TEST_CASE("Leading spaces before type cause mismatch");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    const char* input = "   form-data";
    int result = formdataparser_parse(&parser, input, strlen(input));
    TEST_ASSERT_EQUAL(0, result, "Should fail — leading spaces don't match 'form-data'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_multiple_spaces_between_parts) {
    TEST_CASE("Multiple spaces between semicolons and keys");

    int ok;
    formdataparser_t parser = parse_fd("form-data;    name=\"x\"   ;   filename=\"y\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have first field");
    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have second field");

    formdataparser_clear(&parser);
}

TEST(test_fdp_multiple_spaces_in_value) {
    TEST_CASE("Multiple spaces in value");

    int ok;
    formdataparser_t parser = parse_fd("form-data;    name= \"x\"; filename = \"y\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have first field");
    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have second field");

    formdataparser_clear(&parser);
}

TEST(test_fdp_parameters_without_semicolon) {
    TEST_CASE("Parameters without semicolon");

    int ok;
    formdataparser_t parser = parse_fd("form-data;    name= \"x\"filename = \"y\"", &ok);
    TEST_ASSERT_EQUAL(0, ok, "Parse should succeed");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 8: Special characters in values
// ============================================================================

TEST(test_fdp_special_chars_in_value) {
    TEST_SUITE("FormDataParser - Special Characters");
    TEST_CASE("Value with special chars: name=\"a+b=c@d\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a+b=c@d\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("a+b=c@d", field_value(parser.field), "Value is 'a+b=c@d'");
    TEST_ASSERT_EQUAL_SIZE(7, field_value_len(parser.field), "Value size for 'a+b=c@d'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_semicolon_in_quoted_value) {
    TEST_CASE("Semicolon inside quotes is literal");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a;b\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("a;b", field_value(parser.field), "Value is 'a;b'");
    TEST_ASSERT_EQUAL_SIZE(3, field_value_len(parser.field), "Value size for 'a;b'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_equals_in_quoted_value) {
    TEST_CASE("Equals inside quotes is literal");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"x=y\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("x=y", field_value(parser.field), "Value is 'x=y'");
    TEST_ASSERT_EQUAL_SIZE(3, field_value_len(parser.field), "Value size for 'x=y'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 9: formdataparser_find_field lookup
// ============================================================================

TEST(test_fdp_field_lookup_found) {
    TEST_SUITE("FormDataParser - Field Lookup");
    TEST_CASE("Lookup existing field");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"field1\"; filename=\"doc.txt\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    const char* val = formdataparser_find_field(&parser, "filename");

    TEST_ASSERT_NOT_NULL(val, "Should find 'filename'");
    TEST_ASSERT_STR_EQUAL("doc.txt", val, "Value should be 'doc.txt'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_field_lookup_not_found) {
    TEST_CASE("Lookup non-existent field");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"field1\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    const char* val = formdataparser_find_field(&parser, "nonexistent");

    TEST_ASSERT_NULL(val, "Should not find 'nonexistent'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_field_lookup_first_field) {
    TEST_CASE("Lookup first field by name");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"field1\"; filename=\"f.txt\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    const char* val = formdataparser_find_field(&parser, "name");

    TEST_ASSERT_NOT_NULL(val, "Should find 'name'");
    TEST_ASSERT_STR_EQUAL("field1", val, "Value should be 'field1'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 10: formdataparser_first_field list
// ============================================================================

TEST(test_fdp_fields_list) {
    TEST_SUITE("FormDataParser - Fields List");
    TEST_CASE("Get full fields list");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"x\"; filename=\"y\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    formdatafield_t* fields = formdataparser_first_field(&parser);

    TEST_ASSERT_NOT_NULL(fields, "Fields list should not be NULL");
    TEST_ASSERT_STR_EQUAL("name", field_key(fields), "First field key");
    TEST_ASSERT_NOT_NULL(fields->next, "Second field exists");
    TEST_ASSERT_STR_EQUAL("filename", field_key(fields->next), "Second field key");

    formdataparser_clear(&parser);
}

TEST(test_fdp_fields_empty) {
    TEST_CASE("No fields (type only)");

    int ok;
    formdataparser_t parser = parse_fd("form-data", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    formdatafield_t* fields = formdataparser_first_field(&parser);

    TEST_ASSERT_NULL(fields, "Fields list should be NULL for type-only input");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 11: Empty input
// ============================================================================

TEST(test_fdp_empty_input) {
    TEST_SUITE("FormDataParser - Empty Input");
    TEST_CASE("Empty string input");

    formdataparser_t parser;
    int result = formdataparser_init(&parser, "form-data");
    TEST_ASSERT_EQUAL(1, result, "Init should succeed");
    result = formdataparser_parse(&parser, "", 0);
    TEST_ASSERT_EQUAL(0, result, "Parse should fail on empty buffer");

    formdataparser_clear(&parser);
}

TEST(test_fdp_zero_buffer_size_nonzero_payload) {
    TEST_CASE("Buffer size 0 with non-zero payload size");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    formdataparser_parse(&parser, "form-data", 0);

    TEST_ASSERT_NULL(parser.field, "No fields when buffer_size=0");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 12: Single call parse
// ============================================================================

TEST(test_fdp_single_call_parse) {
    TEST_SUITE("FormDataParser - Single Call Parse");
    TEST_CASE("Parse full input in one call");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    const char input[] = "form-data; name=\"field1\"";
    size_t len = sizeof(input) - 1;
    int result = formdataparser_parse(&parser, input, len);

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Key is 'name'");
    TEST_ASSERT_STR_EQUAL("field1", field_value(parser.field), "Value is 'field1'");
    TEST_ASSERT_EQUAL_SIZE(6, field_value_len(parser.field), "Value size for 'field1'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 13: Buffer overflow protection
// ============================================================================

TEST(test_fdp_type_exceeds_buffer) {
    TEST_SUITE("FormDataParser - Buffer Overflow");
    TEST_CASE("Type string > FORMDATABUFSIZ should fail gracefully");

    char input[1100];
    memset(input, 'A', 1025);
    input[1025] = '\0';

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, input, 1025);
    TEST_ASSERT_EQUAL(0, result, "Should fail — type doesn't match 'form-data'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_key_exceeds_buffer) {
    TEST_CASE("Key string fills entire buffer should fail gracefully");

    char input[1100];
    size_t pos = 0;

    memcpy(input, "form-data; ", 11);
    pos += 11;

    size_t fill = FORMDATABUFSIZ + 10;
    memset(input + pos, 'A', fill);
    pos += fill;

    input[pos++] = '=';
    input[pos++] = '1';

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, input, pos);
    TEST_ASSERT_EQUAL(0, result, "Should fail — buffer too big");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 14: Unclosed quotes
// ============================================================================

TEST(test_fdp_unclosed_quote) {
    TEST_SUITE("FormDataParser - Unclosed Quotes");
    TEST_CASE("Value with unclosed quote: name=\"field1");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"field1", &ok);
    // Parser returns 0 (unclosed quote), but field was already allocated by save_key
    TEST_ASSERT_EQUAL(0, ok, "Parse should fail — unclosed quote");
    // field exists but value is empty (save_value was not called)
    TEST_ASSERT_NOT_NULL(parser.field, "Field allocated but value not saved");

    formdataparser_clear(&parser);
}

TEST(test_fdp_unclosed_quote_with_semicolon) {
    TEST_CASE("Semicolon inside unclosed quotes is literal");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"field1; extra", &ok);
    TEST_ASSERT_EQUAL(0, ok, "Parse should fail — unclosed quote");
    TEST_ASSERT_NOT_NULL(parser.field, "Field allocated but value not saved");
    TEST_ASSERT_NULL(parser.field->next, "No second field — semicolon was inside quotes");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 15: Malformed input
// ============================================================================

TEST(test_fdp_no_equals_just_key) {
    TEST_SUITE("FormDataParser - Malformed Input");
    TEST_CASE("Key without equals: form-data; name; other=\"val\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name; other=\"val\"", &ok);
    // "name" read as key, then ';' in FORMDATA_KEY returns 0
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed — key without value");
    TEST_ASSERT(dt_equals(&parser, "form-data"), "disposition_type should be set");

    const char* val_name = formdataparser_find_field(&parser, "name");
    TEST_ASSERT_NOT_NULL(val_name, "Should find 'name'");
    TEST_ASSERT_STR_EQUAL("", val_name, "Value should be empty");

    const char* val_other = formdataparser_find_field(&parser, "other");
    TEST_ASSERT_NOT_NULL(val_other, "Should find 'other'");
    TEST_ASSERT_STR_EQUAL("val", val_other, "Value should be 'val'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_equals_without_key) {
    TEST_CASE("Equals without key before it: =\"value\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; =\"value\"", &ok);
    // '=' in FORMDATA_SKIP is not alpha/'-'/'*'/' ' — returns 0
    TEST_ASSERT_EQUAL(0, ok, "Parse should fail — unexpected '='");
    TEST_ASSERT_NULL(parser.field, "Should not have field");

    formdataparser_clear(&parser);
}

TEST(test_fdp_equals_at_end) {
    TEST_CASE("Trailing equals with no value: name=");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed — empty value at end");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Key is 'name'");
    TEST_ASSERT_EQUAL_SIZE(0, field_value_len(parser.field), "Value size should be 0");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 16: Double equals
// ============================================================================

TEST(test_fdp_double_equals) {
    TEST_SUITE("FormDataParser - Double Equals");
    TEST_CASE("Key with double equals: name==\"val\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name==\"val\"; filename==\"val2", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Key is 'name'");
    // Second '=' is in VALUE stage, treated as literal char
    TEST_ASSERT_STR_EQUAL("=\"val\"", field_value(parser.field), "Value includes second =");

    TEST_ASSERT_STR_EQUAL("filename", field_key(parser.last_field), "Key is 'filename'");
    // Second '=' is in VALUE stage, treated as literal char
    TEST_ASSERT_STR_EQUAL("=\"val2", field_value(parser.last_field), "Value includes second =");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 17: Payload size mismatch
// ============================================================================

TEST(test_fdp_payload_size_smaller_than_actual) {
    TEST_CASE("payload_size smaller than buffer_size");

    const char input[] = "form-data; name=\"field1\"; filename=\"f.txt\"";
    size_t real_len = sizeof(input) - 5;

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, input, real_len);

    TEST_ASSERT_EQUAL(0, result, "Parse should failed");
    TEST_ASSERT(1, "Parser should not crash on payload size mismatch");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 18: Degenerate input
// ============================================================================

TEST(test_fdp_only_semicolons) {
    TEST_SUITE("FormDataParser - Degenerate Input");
    TEST_CASE("Input is just semicolons: ;;;");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, ";;;", 3);
    TEST_ASSERT_EQUAL(0, result, "Should fail — doesn't match 'form-data'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_only_equals) {
    TEST_CASE("Input is just equals: ===");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, "===", 3);
    TEST_ASSERT_EQUAL(0, result, "Should fail — doesn't match 'form-data'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_only_spaces) {
    TEST_CASE("Input is just spaces: '   '");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, "   ", 3);
    TEST_ASSERT_EQUAL(0, result, "Should fail — doesn't match 'form-data'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 19: Backslash handling
// ============================================================================

TEST(test_fdp_backslash_not_before_quote) {
    TEST_SUITE("FormDataParser - Backslash Handling");
    TEST_CASE("Backslash not before closing quote: name=\"a\\b\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a\\b\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    // 'a' '\' 'b' — backslash is literal since next char is not '"'
    TEST_ASSERT_STR_EQUAL("a\\b", field_value(parser.field), "Key is 'a\\b'");
    TEST_ASSERT_EQUAL_SIZE(3, field_value_len(parser.field), "Value size for 'a\\b'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_double_backslash_before_quote) {
    TEST_CASE("Double backslash before quote: name=\"a\\\\\\\"\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a\\\\\\\"\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    // a(1) \(2) \(3) "(4) — second \ before " means escape: backslash overwritten by "
    // So value is: a \ " = 3 chars
    TEST_ASSERT_STR_EQUAL("a\\\"", field_value(parser.field), "Key is 'a\\\"'");
    TEST_ASSERT_EQUAL_SIZE(3, field_value_len(parser.field), "Value size for 'a\\\"'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 20: Quote inside unquoted value
// ============================================================================

TEST(test_fdp_quote_in_unquoted_value) {
    TEST_SUITE("FormDataParser - Quote Edge Cases");
    TEST_CASE("Opening quote inside unquoted value: name=abc\"def\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=abc\"def\"", &ok);
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("abc\"def\"", field_value(parser.field), "Key is 'abc\"def\"'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 21: Real-world Content-Disposition values
// ============================================================================

TEST(test_fdp_real_world_form_data) {
    TEST_SUITE("FormDataParser - Real World");
    TEST_CASE("Typical form-data with name and filename");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"file\"; filename=\"document.pdf\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have name field");
    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have filename field");

    const char* name_val = formdataparser_find_field(&parser, "name");
    TEST_ASSERT_NOT_NULL(name_val, "name found");
    TEST_ASSERT_STR_EQUAL("file", name_val, "name value");

    const char* fn_val = formdataparser_find_field(&parser, "filename");
    TEST_ASSERT_NOT_NULL(fn_val, "filename found");
    TEST_ASSERT_STR_EQUAL("document.pdf", fn_val, "filename value");

    formdataparser_clear(&parser);
}

TEST(test_fdp_real_world_attachment) {
    TEST_CASE("Attachment type");

    formdataparser_t parser;
    formdataparser_init(&parser, "attachment");
    const char input[] = "attachment; filename=\"report.xlsx\"";
    int result = formdataparser_parse(&parser, input, strlen(input));

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT(dt_equals(&parser, "attachment"), "disposition_type is 'attachment'");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("filename", field_key(parser.field), "Key is 'filename'");
    TEST_ASSERT_STR_EQUAL("report.xlsx", field_value(parser.field), "Value is 'report.xlsx'");
    TEST_ASSERT_EQUAL_SIZE(11, field_value_len(parser.field), "Value size for 'report.xlsx'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_real_world_unicode_filename) {
    TEST_CASE("UTF-8 filename");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"file\"; filename=\"\xd0\xb4\xd0\xbe\xd0\xba\xd1\x83\xd0\xbc\xd0\xb5\xd0\xbd\xd1\x82.pdf\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have name field");
    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have filename field");
    TEST_ASSERT_STR_EQUAL("filename", field_key(parser.field->next), "Filename key");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 22: Reuse safety
// ============================================================================

TEST(test_fdp_init_reuse) {
    TEST_SUITE("FormDataParser - Reuse Safety");
    TEST_CASE("Re-initializing parser after free");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"x\"", &ok);
    formdataparser_clear(&parser);

    formdataparser_init(&parser, "attachment");
    formdataparser_parse(&parser, "attachment; fn=\"a\"", 18);

    TEST_ASSERT(dt_equals(&parser, "attachment"), "disposition_type is 'attachment'");

    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("fn", field_key(parser.field), "Key is 'fn'");
    TEST_ASSERT_STR_EQUAL("a", field_value(parser.field), "Value is 'a'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 23: Equals after value
// ============================================================================

TEST(test_fdp_equals_after_value) {
    TEST_SUITE("FormDataParser - Equals After Value");
    TEST_CASE("name=\"val\"=extra");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"val\"=extra", &ok);
    // After closing quote, '=' is in FORMDATA_SEMICOLON stage — not ';'/space/alpha → returns 0
    TEST_ASSERT_EQUAL(0, ok, "Parse should fail — '=' after closing quote");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 24: Near buffer limit
// ============================================================================

TEST(test_fdp_value_near_buffer_limit) {
    TEST_SUITE("FormDataParser - Near Buffer Limit");
    TEST_CASE("Value with 250 chars (within FORMDATABUFSIZ)");

    char input[1200];
    size_t pos = 0;

    memcpy(input, "form-data; name=\"", 17);
    pos += 17;

    memset(input + pos, 'X', 250);
    pos += 250;

    input[pos++] = '"';

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, input, pos);
    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Key is 'name'");
    TEST_ASSERT_EQUAL_SIZE(250, field_value_len(parser.field), "Value size should be 250");

    formdataparser_clear(&parser);
}

TEST(test_fdp_value_at_255) {
    TEST_CASE("Value at exactly 255 chars");

    char input[512];
    size_t pos = 0;

    memcpy(input, "form-data; name=\"", 17);
    pos += 17;

    memset(input + pos, 'Z', 255);
    pos += 255;

    input[pos++] = '"';

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, input, pos);
    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field at 255 chars");
    TEST_ASSERT_EQUAL_SIZE(255, field_value_len(parser.field), "Value size should be 255");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 25: Disposition type validation
// ============================================================================

TEST(test_disposition_type_with_equals) {
    TEST_SUITE("FormDataParser - Disposition Type Validation");
    TEST_CASE("Type with '=' in it: form-data=data");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, "form-data=data", 14);
    TEST_ASSERT_EQUAL(0, result, "Should fail — '=' doesn't match disposition type");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 26: No-space after semicolons
// ============================================================================

TEST(test_no_space_after_semicolon) {
    TEST_SUITE("FormDataParser - Compact Format");
    TEST_CASE("No space after semicolon: form-data;name=\"a\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data;name=\"a\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Key is 'name'");
    TEST_ASSERT_STR_EQUAL("a", field_value(parser.field), "Value is 'a'");

    formdataparser_clear(&parser);
}

TEST(test_no_space_after_semicolon_without_quotes) {
    TEST_SUITE("FormDataParser - Compact Format");
    TEST_CASE("No space after semicolon and without quotes: form-data;name=a ");

    int ok;
    formdataparser_t parser = parse_fd("form-data;name=a ", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("name", field_key(parser.field), "Key is 'name'");
    TEST_ASSERT_STR_EQUAL("a", field_value(parser.field), "Value is 'a'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 27: attachment disposition type
// ============================================================================

TEST(test_attachment_type) {
    TEST_SUITE("FormDataParser - Attachment Type");
    TEST_CASE("attachment; filename=\"file.pdf\"");

    formdataparser_t parser;
    formdataparser_init(&parser, "attachment");
    const char input[] = "attachment; filename=\"file.pdf\"";
    int result = formdataparser_parse(&parser, input, strlen(input));
    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT(dt_equals(&parser, "attachment"), "disposition_type is 'attachment'");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("filename", field_key(parser.field), "Key is 'filename'");
    TEST_ASSERT_STR_EQUAL("file.pdf", field_value(parser.field), "Value is 'file.pdf'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 28: creation-date and filename* fields
// ============================================================================

TEST(test_hyphenated_field_names) {
    TEST_SUITE("FormDataParser - Hyphenated Fields");
    TEST_CASE("Fields with hyphens: creation-date");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; creation-date=\"2024-01-01\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have name field");
    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have creation-date field");
    TEST_ASSERT_STR_EQUAL("creation-date", field_key(parser.field->next), "Key with hyphen");

    formdataparser_clear(&parser);
}

TEST(test_star_field_name) {
    TEST_CASE("Field with asterisk: filename*");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=\"utf-8''test.pdf\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have name field");
    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have filename* field");
    TEST_ASSERT_STR_EQUAL("filename*", field_key(parser.field->next), "Key with asterisk");
    TEST_ASSERT_STR_EQUAL("test.pdf", field_value(parser.field->next), "Value should be percent-decoded");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_utf8_encoded) {
    TEST_SUITE("FormDataParser - RFC 5987");
    TEST_CASE("filename* with UTF-8 percent-encoded Cyrillic");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=UTF-8''%D0%B4%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82.pdf", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field->next, "Should have filename* field");
    TEST_ASSERT_STR_EQUAL("filename*", field_key(parser.field->next), "Key is filename*");
    // %D0%B4%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82 = "документ" in UTF-8
    TEST_ASSERT_STR_EQUAL("\xd0\xb4\xd0\xbe\xd0\xba\xd1\x83\xd0\xbc\xd0\xb5\xd0\xbd\xd1\x82.pdf",
                          field_value(parser.field->next), "Value should be decoded to UTF-8");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_with_language) {
    TEST_CASE("filename* with charset and language tag");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=UTF-8'ru'%D1%84%D0%B0%D0%B9%D0%BB.txt", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("\xd1\x84\xd0\xb0\xd0\xb9\xd0\xbb.txt",
                          field_value(parser.field->next), "Value should decode with language tag ignored");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_ascii_only) {
    TEST_CASE("filename* with ASCII-only value (no percent encoding)");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=UTF-8''simple.txt", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("simple.txt", field_value(parser.field->next), "Plain ASCII decoded as-is");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_mixed_encoding) {
    TEST_CASE("filename* with mix of encoded and plain characters");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=UTF-8''hello%20world.txt", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("hello world.txt", field_value(parser.field->next), "Percent-encoded space decoded");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_empty_value) {
    TEST_CASE("filename* with empty encoded value");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=UTF-8''", &ok);
    TEST_ASSERT_EQUAL(0, ok, "Parse should fail — empty value after second quote");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_failed_value) {
    TEST_CASE("filename* with failed encoded value");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=UTF-8'", &ok);
    TEST_ASSERT_EQUAL(0, ok, "Parse should fail — empty value after first quote");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_incomplete_percent) {
    TEST_CASE("filename* with incomplete percent sequence at end");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=UTF-8''test%2", &ok);
    TEST_ASSERT_EQUAL(0, ok, "Parse should fail — incomplete percent sequence");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_invalid_hex) {
    TEST_CASE("filename* with invalid hex digit in percent sequence");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"f\"; filename*=UTF-8''test%2G", &ok);
    TEST_ASSERT_EQUAL(0, ok, "Parse should fail — invalid hex digit");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_star_priority) {
    TEST_SUITE("FormDataParser - RFC 5987 Priority");
    TEST_CASE("filename* takes priority over filename in find_field");

    int ok;
    formdataparser_t parser = parse_fd(
        "form-data; name=\"f\"; filename=\"fallback.txt\"; filename*=UTF-8''%D1%84%D0%B0%D0%B9%D0%BB.txt",
        &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");

    // find_field("filename") should return the decoded filename* value, not fallback
    const char* val = formdataparser_find_field(&parser, "filename");
    TEST_ASSERT_NOT_NULL(val, "Should find filename");
    TEST_ASSERT_STR_EQUAL("\xd1\x84\xd0\xb0\xd0\xb9\xd0\xbb.txt", val,
                          "Should return decoded filename* value, not fallback.txt");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_no_star_fallback) {
    TEST_CASE("find_field returns filename when filename* is absent");

    int ok;
    formdataparser_t parser = parse_fd(
        "form-data; name=\"f\"; filename=\"fallback.txt\"",
        &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");

    const char* val = formdataparser_find_field(&parser, "filename");
    TEST_ASSERT_NOT_NULL(val, "Should find filename");
    TEST_ASSERT_STR_EQUAL("fallback.txt", val, "Should return plain filename value");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 29: OWS around '='
// ============================================================================

TEST(test_fdp_space_before_equals_only) {
    TEST_SUITE("FormDataParser - OWS around '='");
    TEST_CASE("Space before equals: filename =\"y\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; filename =\"y\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("y", formdataparser_find_field(&parser, "filename"), "Value is 'y'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_space_after_equals_only) {
    TEST_CASE("Space after equals: name= \"x\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name= \"x\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("x", formdataparser_find_field(&parser, "name"), "Value is 'x'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 30: Additional error cases
// ============================================================================

TEST(test_fdp_err_key_space_eof) {
    TEST_SUITE("FormDataParser - Key Without Value Errors");
    TEST_CASE("Key followed by space then EOF: name ");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, "form-data; name ", 16);
    TEST_ASSERT_EQUAL(0, result, "Should fail — key without value (space then EOF)");

    formdataparser_clear(&parser);
}

TEST(test_fdp_key_equals_empty_value_with_space) {
    TEST_CASE("Key with space before equals and empty value: name =");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name =", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed — empty value is valid");
    const char* val = formdataparser_find_field(&parser, "name");
    TEST_ASSERT_NOT_NULL(val, "Should find 'name'");
    TEST_ASSERT_STR_EQUAL("", val, "Value should be empty");

    formdataparser_clear(&parser);
}

TEST(test_fdp_key_equals_empty_value_no_space) {
    TEST_CASE("Key with equals and empty value: name=");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed — empty value is valid");
    const char* val = formdataparser_find_field(&parser, "name");
    TEST_ASSERT_NOT_NULL(val, "Should find 'name'");
    TEST_ASSERT_STR_EQUAL("", val, "Value should be empty");

    formdataparser_clear(&parser);
}

TEST(test_fdp_err_letter_after_quoted_value) {
    TEST_CASE("Letter right after closing quote without semicolon: name=\"x\"filename=\"y\"");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, "form-data; name=\"x\"filename=\"y\"", 35);
    TEST_ASSERT_EQUAL(0, result, "Should fail — no semicolon between fields");

    formdataparser_clear(&parser);
}

TEST(test_fdp_err_garbage_after_quoted_value) {
    TEST_CASE("Garbage character after closing quote: name=\"x\"@");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, "form-data; name=\"x\"@", 22);
    TEST_ASSERT_EQUAL(0, result, "Should fail — garbage after closing quote");

    formdataparser_clear(&parser);
}

TEST(test_fdp_err_bad_char_in_key) {
    TEST_CASE("Invalid character in key name: na@me=\"x\"");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, "form-data; na@me=\"x\"", 21);
    TEST_ASSERT_EQUAL(0, result, "Should fail — '@' is not valid in key name");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 31: Additional backslash edge cases
// ============================================================================

TEST(test_fdp_trailing_escaped_backslash) {
    TEST_SUITE("FormDataParser - Backslash Edge Cases");
    TEST_CASE("Trailing escaped backslash: name=\"a\\\\\"\" -> a\\");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a\\\\\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("a\\", field_value(parser.field), "Value should be 'a\\'");
    TEST_ASSERT_EQUAL_SIZE(2, field_value_len(parser.field), "Value size for 'a\\'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_backslash_before_normal_char) {
    TEST_CASE("Backslash before normal char: name=\"C:\\temp\" -> C:\\temp");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"C:\\temp\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("C:\\temp", field_value(parser.field), "Value should be 'C:\\temp'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_value_ends_with_escaped_quote) {
    TEST_CASE("Value ending with escaped quote: name=\"a\\\"\"\" -> a\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a\\\"\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(parser.field, "Should have field");
    TEST_ASSERT_STR_EQUAL("a\"", field_value(parser.field), "Value should be 'a\"'");

    formdataparser_clear(&parser);
}

TEST(test_fdp_quoted_value_with_semicolon_and_next_field) {
    TEST_CASE("Semicolon in quoted value with second field: name=\"a;b\"; filename=\"c\"");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name=\"a;b\"; filename=\"c\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("a;b", formdataparser_find_field(&parser, "name"), "Name value is 'a;b'");
    TEST_ASSERT_STR_EQUAL("c", formdataparser_find_field(&parser, "filename"), "Filename value is 'c'");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 32: RFC 5987 additional cases
// ============================================================================

TEST(test_rfc5987_lowercase_hex) {
    TEST_SUITE("FormDataParser - RFC 5987 Additional");
    TEST_CASE("Lowercase hex in percent encoding: %c3%a9 -> é");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name*=UTF-8''%c3%a9", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("\xc3\xa9", formdataparser_find_field(&parser, "name"), "Value should be 'é'");

    formdataparser_clear(&parser);
}

TEST(test_rfc5987_star_priority_reordered) {
    TEST_CASE("name* appears before name — order should not matter");

    int ok;
    formdataparser_t parser = parse_fd("form-data; name*=UTF-8''%41; name=\"plain\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("A", formdataparser_find_field(&parser, "name"),
                          "Should return decoded name* value regardless of order");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 33: Field order preserved
// ============================================================================

TEST(test_fdp_field_order_preserved) {
    TEST_SUITE("FormDataParser - Field Order");
    TEST_CASE("Three fields should preserve order: a=1, b=2, c=3");

    int ok;
    formdataparser_t parser = parse_fd("form-data; a=\"1\"; b=\"2\"; c=\"3\"", &ok);
    TEST_ASSERT_EQUAL(1, ok, "Parse should succeed");

    formdatafield_t* f = formdataparser_first_field(&parser);
    TEST_ASSERT_NOT_NULL(f, "First field");
    TEST_ASSERT_STR_EQUAL("a", str_get(&f->key), "First key is 'a'");
    TEST_ASSERT_STR_EQUAL("1", str_get(&f->value), "First value is '1'");

    f = f->next;
    TEST_ASSERT_NOT_NULL(f, "Second field");
    TEST_ASSERT_STR_EQUAL("b", str_get(&f->key), "Second key is 'b'");
    TEST_ASSERT_STR_EQUAL("2", str_get(&f->value), "Second value is '2'");

    f = f->next;
    TEST_ASSERT_NOT_NULL(f, "Third field");
    TEST_ASSERT_STR_EQUAL("c", str_get(&f->key), "Third key is 'c'");
    TEST_ASSERT_STR_EQUAL("3", str_get(&f->value), "Third value is '3'");
    TEST_ASSERT_NULL(f->next, "Should have exactly three fields");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 34: Reuse safety — full lifecycle test
// ============================================================================

TEST(test_fdp_reuse_after_clear) {
    TEST_SUITE("FormDataParser - Reuse After Clear");
    TEST_CASE("Parse, clear, re-init, parse again — no state leaks");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    const char input1[] = "form-data; name=\"first\"";
    int ok = formdataparser_parse(&parser, input1, sizeof(input1) - 1);
    TEST_ASSERT_EQUAL(1, ok, "First parse should succeed");
    TEST_ASSERT_STR_EQUAL("first", formdataparser_find_field(&parser, "name"), "First value is 'first'");

    formdataparser_clear(&parser);
    // Double clear should be safe (no double-free)
    formdataparser_clear(&parser);

    formdataparser_init(&parser, "form-data");
    const char input2[] = "form-data; name=\"second\"";
    ok = formdataparser_parse(&parser, input2, sizeof(input2) - 1);
    TEST_ASSERT_EQUAL(1, ok, "Second parse should succeed");
    TEST_ASSERT_STR_EQUAL("second", formdataparser_find_field(&parser, "name"), "Second value is 'second'");

    // First parse result should not leak into second parse
    formdatafield_t* f = formdataparser_first_field(&parser);
    TEST_ASSERT_NOT_NULL(f, "Should have one field");
    TEST_ASSERT_NULL(f->next, "Should have exactly one field — no leak from first parse");

    formdataparser_clear(&parser);
}

// ============================================================================
// Test Suite 35: Error — key without equals sign
// ============================================================================

TEST(test_fdp_err_key_without_value) {
    TEST_SUITE("FormDataParser - Key Without Equals");
    TEST_CASE("Key followed by EOF without equals: form-data; name");

    formdataparser_t parser;
    formdataparser_init(&parser, "form-data");
    int result = formdataparser_parse(&parser, "form-data; name", 15);
    TEST_ASSERT_EQUAL(0, result, "Should fail — key without value (no equals)");

    formdataparser_clear(&parser);
}

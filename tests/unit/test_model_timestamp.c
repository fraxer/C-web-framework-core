#define _GNU_SOURCE
#include "framework.h"
#include "model.h"
#include "model_internal.h"
#include <string.h>
#include <stdlib.h>

// ============================================================================
// model_set_timestamptz_from_str
// ============================================================================

TEST(test_timestamptz_postgres_with_usec) {
    TEST_CASE("Parse PostgreSQL timestamptz with microseconds");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2025-01-09 15:04:23.338335+00");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(125, field->value._tm.tm_year, "Year should be 125 (2025 - 1900)");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_mon, "Month should be 0 (January)");
    TEST_ASSERT_EQUAL(9, field->value._tm.tm_mday, "Day should be 9");
    TEST_ASSERT_EQUAL(15, field->value._tm.tm_hour, "Hour should be 15");
    TEST_ASSERT_EQUAL(4, field->value._tm.tm_min, "Min should be 4");
    TEST_ASSERT_EQUAL(23, field->value._tm.tm_sec, "Sec should be 23");
    TEST_ASSERT_EQUAL(338335, field->value._tm.tm_usec, "Microseconds should be 338335");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_gmtoff, "UTC offset should be 0");

    model_param_free(field);
}

TEST(test_timestamptz_iso8601_utc) {
    TEST_CASE("Parse ISO 8601 UTC with microseconds");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2024-04-21T15:30:45.123456Z");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(124, field->value._tm.tm_year, "Year should be 124 (2024 - 1900)");
    TEST_ASSERT_EQUAL(3, field->value._tm.tm_mon, "Month should be 3 (April)");
    TEST_ASSERT_EQUAL(21, field->value._tm.tm_mday, "Day should be 21");
    TEST_ASSERT_EQUAL(15, field->value._tm.tm_hour, "Hour should be 15");
    TEST_ASSERT_EQUAL(30, field->value._tm.tm_min, "Min should be 30");
    TEST_ASSERT_EQUAL(45, field->value._tm.tm_sec, "Sec should be 45");
    TEST_ASSERT_EQUAL(123456, field->value._tm.tm_usec, "Microseconds should be 123456");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_gmtoff, "UTC offset should be 0");

    model_param_free(field);
}

TEST(test_timestamptz_iso8601_with_tz) {
    TEST_CASE("Parse ISO 8601 with +03:00 timezone");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2024-04-21T15:30:45.123456+03:00");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(123456, field->value._tm.tm_usec, "Microseconds should be 123456");
    TEST_ASSERT_EQUAL(10800, field->value._tm.tm_gmtoff, "Offset should be +10800 (+03:00)");

    model_param_free(field);
}

TEST(test_timestamptz_space_no_usec) {
    TEST_CASE("Parse space-separated timestamptz without microseconds");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2025-01-09 15:04:23+03");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_usec, "Microseconds should be 0");
    TEST_ASSERT_EQUAL(10800, field->value._tm.tm_gmtoff, "UTC offset should be 10800 (+03)");

    model_param_free(field);
}

TEST(test_timestamptz_t_no_usec) {
    TEST_CASE("Parse T-separated timestamptz without microseconds");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2024-04-21T15:30:45Z");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_usec, "Microseconds should be 0");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_gmtoff, "UTC offset should be 0");

    model_param_free(field);
}

TEST(test_timestamptz_frac1_digit) {
    TEST_CASE("Parse timestamptz with 1 fractional digit");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2024-04-21T15:30:45.1+03:00");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(100000, field->value._tm.tm_usec, "0.1 sec = 100000 usec");

    model_param_free(field);
}

TEST(test_timestamptz_frac3_digits) {
    TEST_CASE("Parse timestamptz with 3 fractional digits");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2024-04-21T15:30:45.123Z");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(123000, field->value._tm.tm_usec, "0.123 sec = 123000 usec");

    model_param_free(field);
}

TEST(test_timestamptz_null_value) {
    TEST_CASE("NULL value sets is_null");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, NULL);

    TEST_ASSERT_EQUAL(1, result, "NULL should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Field should be null");

    model_param_free(field);
}

TEST(test_timestamptz_wrong_type) {
    TEST_CASE("Wrong field type returns 0");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    field->type = MODEL_INT;
    int result = model_set_timestamptz_from_str(field, "2025-01-09 15:04:23+00");

    TEST_ASSERT_EQUAL(0, result, "Wrong type should fail");

    model_param_free(field);
}

TEST(test_timestamptz_null_field) {
    TEST_CASE("NULL field returns 0");

    int result = model_set_timestamptz_from_str(NULL, "2025-01-09 15:04:23+00");

    TEST_ASSERT_EQUAL(0, result, "NULL field should fail");
}

// ============================================================================
// model_set_timestamp_from_str
// ============================================================================

TEST(test_timestamp_space_with_usec) {
    TEST_CASE("Parse timestamp with space and microseconds");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int result = model_set_timestamp_from_str(field, "2025-01-09 15:04:23.338335");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(125, field->value._tm.tm_year, "Year should be 125");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_mon, "Month should be 0");
    TEST_ASSERT_EQUAL(9, field->value._tm.tm_mday, "Day should be 9");
    TEST_ASSERT_EQUAL(15, field->value._tm.tm_hour, "Hour should be 15");
    TEST_ASSERT_EQUAL(4, field->value._tm.tm_min, "Min should be 4");
    TEST_ASSERT_EQUAL(23, field->value._tm.tm_sec, "Sec should be 23");
    TEST_ASSERT_EQUAL(338335, field->value._tm.tm_usec, "Microseconds should be 338335");

    model_param_free(field);
}

TEST(test_timestamp_t_separator) {
    TEST_CASE("Parse timestamp with T separator");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int result = model_set_timestamp_from_str(field, "2024-04-21T15:30:45.123456");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(123456, field->value._tm.tm_usec, "Microseconds should be 123456");

    model_param_free(field);
}

TEST(test_timestamp_no_usec) {
    TEST_CASE("Parse timestamp without microseconds");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int result = model_set_timestamp_from_str(field, "2025-01-09 15:04:23");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_usec, "Microseconds should be 0");

    model_param_free(field);
}

TEST(test_timestamp_null) {
    TEST_CASE("NULL value sets is_null");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int result = model_set_timestamp_from_str(field, NULL);

    TEST_ASSERT_EQUAL(1, result, "NULL should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Field should be null");

    model_param_free(field);
}

// ============================================================================
// model_set_timetz_from_str
// ============================================================================

TEST(test_timetz_with_usec_and_tz) {
    TEST_CASE("Parse timetz with microseconds and timezone");

    mfield_t* field = field_create_timetz("tz", NULL);
    int result = model_set_timetz_from_str(field, "15:30:45.123456+03:00");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(15, field->value._tm.tm_hour, "Hour should be 15");
    TEST_ASSERT_EQUAL(30, field->value._tm.tm_min, "Min should be 30");
    TEST_ASSERT_EQUAL(45, field->value._tm.tm_sec, "Sec should be 45");
    TEST_ASSERT_EQUAL(123456, field->value._tm.tm_usec, "Microseconds should be 123456");
    TEST_ASSERT_EQUAL(10800, field->value._tm.tm_gmtoff, "Offset should be +10800");

    model_param_free(field);
}

TEST(test_timetz_no_usec) {
    TEST_CASE("Parse timetz without microseconds");

    mfield_t* field = field_create_timetz("tz", NULL);
    int result = model_set_timetz_from_str(field, "15:30:45+03:00");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_usec, "Microseconds should be 0");
    TEST_ASSERT_EQUAL(10800, field->value._tm.tm_gmtoff, "Offset should be +10800");

    model_param_free(field);
}

TEST(test_timetz_z_timezone) {
    TEST_CASE("Parse timetz with Z timezone and 1 fractional digit");

    mfield_t* field = field_create_timetz("tz", NULL);
    int result = model_set_timetz_from_str(field, "15:30:45.5Z");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(500000, field->value._tm.tm_usec, "0.5 sec = 500000 usec");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_gmtoff, "UTC offset should be 0");

    model_param_free(field);
}

TEST(test_timetz_null) {
    TEST_CASE("NULL value sets is_null");

    mfield_t* field = field_create_timetz("tz", NULL);
    int result = model_set_timetz_from_str(field, NULL);

    TEST_ASSERT_EQUAL(1, result, "NULL should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Field should be null");

    model_param_free(field);
}

// ============================================================================
// model_set_time_from_str
// ============================================================================

TEST(test_time_with_usec) {
    TEST_CASE("Parse time with microseconds");

    mfield_t* field = field_create_time("t", NULL);
    int result = model_set_time_from_str(field, "15:30:45.123456");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(15, field->value._tm.tm_hour, "Hour should be 15");
    TEST_ASSERT_EQUAL(30, field->value._tm.tm_min, "Min should be 30");
    TEST_ASSERT_EQUAL(45, field->value._tm.tm_sec, "Sec should be 45");
    TEST_ASSERT_EQUAL(123456, field->value._tm.tm_usec, "Microseconds should be 123456");

    model_param_free(field);
}

TEST(test_time_no_usec) {
    TEST_CASE("Parse time without microseconds");

    mfield_t* field = field_create_time("t", NULL);
    int result = model_set_time_from_str(field, "15:30:45");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_usec, "Microseconds should be 0");

    model_param_free(field);
}

TEST(test_time_null) {
    TEST_CASE("NULL value sets is_null");

    mfield_t* field = field_create_time("t", NULL);
    int result = model_set_time_from_str(field, NULL);

    TEST_ASSERT_EQUAL(1, result, "NULL should succeed");
    TEST_ASSERT_EQUAL(1, field->is_null, "Field should be null");

    model_param_free(field);
}

// ============================================================================
// model_timestamptz_to_str
// ============================================================================

TEST(test_timestamptz_to_str_with_usec) {
    TEST_CASE("Format timestamptz with microseconds includes .NNNNNN");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    model_set_timestamptz_from_str(field, "2024-04-21T15:30:45.123456+03:00");

    str_t* result = model_timestamptz_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");

    const char* str = str_get(result);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str, ".123456") != NULL, "Should contain .123456");
    TEST_ASSERT_EQUAL(1, strstr(str, "+0300") != NULL, "Should contain timezone");

    model_param_free(field);
}

TEST(test_timestamptz_to_str_no_usec) {
    TEST_CASE("Format timestamptz without microseconds has no fractional part");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    model_set_timestamptz_from_str(field, "2024-04-21T15:30:45Z");

    str_t* result = model_timestamptz_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");

    const char* str = str_get(result);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    TEST_ASSERT_EQUAL(0, strstr(str, ".") != NULL, "Should not contain fractional part");
    TEST_ASSERT_EQUAL(1, strstr(str, "+0000") != NULL, "Should contain timezone");

    model_param_free(field);
}

// ============================================================================
// model_timestamp_to_str
// ============================================================================

TEST(test_timestamp_to_str_with_usec) {
    TEST_CASE("Format timestamp with microseconds includes .NNNNNN");

    mfield_t* field = field_create_timestamp("ts", NULL);
    model_set_timestamp_from_str(field, "2024-04-21T15:30:45.123456");

    str_t* result = model_timestamp_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");

    const char* str = str_get(result);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    TEST_ASSERT_EQUAL(1, strstr(str, ".123456") != NULL, "Should contain .123456");

    model_param_free(field);
}

TEST(test_timestamp_to_str_no_usec) {
    TEST_CASE("Format timestamp without microseconds has no fractional part");

    mfield_t* field = field_create_timestamp("ts", NULL);
    model_set_timestamp_from_str(field, "2024-04-21 15:30:45");

    str_t* result = model_timestamp_to_str(field);
    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");

    const char* str = str_get(result);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    TEST_ASSERT_EQUAL(0, strstr(str, ".") != NULL, "Should not contain fractional part");

    model_param_free(field);
}

// ============================================================================
// Некорректные входные данные
// ============================================================================

TEST(test_timestamptz_empty_string) {
    TEST_CASE("Empty string returns 0");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "");

    TEST_ASSERT_EQUAL(0, result, "Empty string should fail");

    model_param_free(field);
}

TEST(test_timestamptz_garbage) {
    TEST_CASE("Garbage string returns 0");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "abcxyz");

    TEST_ASSERT_EQUAL(0, result, "Garbage should fail");

    model_param_free(field);
}

TEST(test_timestamptz_incomplete_date) {
    TEST_CASE("Incomplete date returns 0");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2025-01");

    TEST_ASSERT_EQUAL(0, result, "Incomplete date should fail");

    model_param_free(field);
}

TEST(test_timestamptz_time_only) {
    TEST_CASE("Time-only string returns 0 for timestamptz");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "15:30:45");

    TEST_ASSERT_EQUAL(0, result, "Time-only should fail for timestamptz");

    model_param_free(field);
}

TEST(test_timestamptz_date_only) {
    TEST_CASE("Date-only string returns 0");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2025-01-09");

    TEST_ASSERT_EQUAL(0, result, "Date-only should fail for timestamptz");

    model_param_free(field);
}

TEST(test_timestamptz_tz_without_time) {
    TEST_CASE("Timezone without full time returns 0");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2025-01-09+03:00");

    TEST_ASSERT_EQUAL(0, result, "Timezone without time should fail");

    model_param_free(field);
}

TEST(test_timestamptz_alpha_after_dot) {
    TEST_CASE("Non-numeric chars after dot should give 0 usec");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    int result = model_set_timestamptz_from_str(field, "2025-01-09 15:04:23.abcdef+00");

    TEST_ASSERT_EQUAL(1, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(0, field->value._tm.tm_usec, "Non-numeric fraction should give 0 usec");

    model_param_free(field);
}

TEST(test_timestamp_empty_string) {
    TEST_CASE("Empty string returns 0");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int result = model_set_timestamp_from_str(field, "");

    TEST_ASSERT_EQUAL(0, result, "Empty string should fail");

    model_param_free(field);
}

TEST(test_timestamp_garbage) {
    TEST_CASE("Garbage string returns 0");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int result = model_set_timestamp_from_str(field, "abcxyz");

    TEST_ASSERT_EQUAL(0, result, "Garbage should fail");

    model_param_free(field);
}

TEST(test_timestamp_incomplete_time) {
    TEST_CASE("Incomplete time returns 0");

    mfield_t* field = field_create_timestamp("ts", NULL);
    int result = model_set_timestamp_from_str(field, "2025-01-09 15:30");

    TEST_ASSERT_EQUAL(0, result, "Incomplete time should fail");

    model_param_free(field);
}

TEST(test_timetz_incomplete_time) {
    TEST_CASE("Incomplete time returns 0 for timetz");

    mfield_t* field = field_create_timetz("tz", NULL);
    int result = model_set_timetz_from_str(field, "15:30");

    TEST_ASSERT_EQUAL(0, result, "Incomplete time should fail");

    model_param_free(field);
}

TEST(test_timetz_garbage) {
    TEST_CASE("Garbage string returns 0 for timetz");

    mfield_t* field = field_create_timetz("tz", NULL);
    int result = model_set_timetz_from_str(field, "abcxyz");

    TEST_ASSERT_EQUAL(0, result, "Garbage should fail");

    model_param_free(field);
}

TEST(test_time_incomplete) {
    TEST_CASE("Incomplete time returns 0 for time");

    mfield_t* field = field_create_time("t", NULL);
    int result = model_set_time_from_str(field, "15:30");

    TEST_ASSERT_EQUAL(0, result, "Incomplete time should fail");

    model_param_free(field);
}

TEST(test_time_garbage) {
    TEST_CASE("Garbage string returns 0 for time");

    mfield_t* field = field_create_time("t", NULL);
    int result = model_set_time_from_str(field, "abcxyz");

    TEST_ASSERT_EQUAL(0, result, "Garbage should fail");

    model_param_free(field);
}

// ============================================================================
// Round-trip: parse → format → verify
// ============================================================================

TEST(test_timestamptz_roundtrip_with_usec) {
    TEST_CASE("Round-trip: parse and format timestamptz with microseconds");

    mfield_t* field = field_create_timestamptz("ts", NULL);
    model_set_timestamptz_from_str(field, "2024-04-21T15:30:45.123456+03:00");

    tm_t parsed = model_timestamptz(field);
    TEST_ASSERT_EQUAL(123456, parsed.tm_usec, "Parsed usec should match");

    str_t* formatted = model_timestamptz_to_str(field);
    TEST_ASSERT_NOT_NULL(formatted, "Formatted string should not be NULL");

    const char* str = str_get(formatted);
    TEST_ASSERT_EQUAL(1, strstr(str, ".123456") != NULL, "Formatted should contain .123456");
    TEST_ASSERT_EQUAL(1, strstr(str, "+0300") != NULL, "Formatted should contain +0300");

    model_param_free(field);
}

TEST(test_timestamp_roundtrip_no_usec) {
    TEST_CASE("Round-trip: parse and format timestamp without microseconds");

    mfield_t* field = field_create_timestamp("ts", NULL);
    model_set_timestamp_from_str(field, "2024-04-21 15:30:45");

    str_t* formatted = model_timestamp_to_str(field);
    TEST_ASSERT_NOT_NULL(formatted, "Formatted string should not be NULL");

    const char* str = str_get(formatted);
    TEST_ASSERT_EQUAL(1, strstr(str, "2024-04-21") != NULL, "Should contain date");
    TEST_ASSERT_EQUAL(1, strstr(str, "15:30:45") != NULL, "Should contain time");
    TEST_ASSERT_EQUAL(0, strstr(str, ".") != NULL, "Should not contain fractional part");

    model_param_free(field);
}

// ============================================================================
// parse_usec
// ============================================================================

TEST(test_parse_usec_6_digits) {
    TEST_CASE("Parse 6 fractional digits");

    const char* input = "123456+00";
    const char* end = NULL;
    int result = parse_usec(input, &end);

    TEST_ASSERT_EQUAL(123456, result, "Should parse 123456");
    TEST_ASSERT_EQUAL(1, end == input + 6, "end should point past 6 digits");
}

TEST(test_parse_usec_1_digit) {
    TEST_CASE("Parse 1 fractional digit padded to 6");

    const char* input = "1+00";
    const char* end = NULL;
    int result = parse_usec(input, &end);

    TEST_ASSERT_EQUAL(100000, result, "0.1 = 100000 usec");
    TEST_ASSERT_EQUAL(1, end == input + 1, "end should point past 1 digit");
}

TEST(test_parse_usec_3_digits) {
    TEST_CASE("Parse 3 fractional digits padded to 6");

    const char* input = "456Z";
    const char* end = NULL;
    int result = parse_usec(input, &end);

    TEST_ASSERT_EQUAL(456000, result, "0.456 = 456000 usec");
    TEST_ASSERT_EQUAL(1, end == input + 3, "end should point past 3 digits");
}

TEST(test_parse_usec_null_end) {
    TEST_CASE("Parse with end=NULL does not crash");

    int result = parse_usec("999999", NULL);

    TEST_ASSERT_EQUAL(999999, result, "Should parse 999999");
}

TEST(test_parse_usec_trailing_alpha) {
    TEST_CASE("Non-digit chars stop parsing");

    const char* input = "12abc";
    const char* end = NULL;
    int result = parse_usec(input, &end);

    TEST_ASSERT_EQUAL(120000, result, "0.12 = 120000 usec");
    TEST_ASSERT_EQUAL(1, end == input + 2, "end should point to 'a'");
}

TEST(test_parse_usec_zero) {
    TEST_CASE("Parse all zeros");

    const char* input = "000000";
    const char* end = NULL;
    int result = parse_usec(input, &end);

    TEST_ASSERT_EQUAL(0, result, "Should be 0");
}

// ============================================================================
// parse_tz_offset
// ============================================================================

TEST(test_parse_tz_offset_z) {
    TEST_CASE("Parse Z as UTC");

    long gmtoff = -1;
    int result = parse_tz_offset("Z", &gmtoff);

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT_EQUAL(0, gmtoff, "Z = 0 offset");
}

TEST(test_parse_tz_offset_positive) {
    TEST_CASE("Parse +03:00");

    long gmtoff = -1;
    int result = parse_tz_offset("+03:00", &gmtoff);

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT_EQUAL(10800, gmtoff, "+03:00 = 10800 sec");
}

TEST(test_parse_tz_offset_negative) {
    TEST_CASE("Parse -05:30");

    long gmtoff = -1;
    int result = parse_tz_offset("-05:30", &gmtoff);

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT_EQUAL(-19800, gmtoff, "-05:30 = -19800 sec");
}

TEST(test_parse_tz_offset_no_colon) {
    TEST_CASE("Parse +03 without colon");

    long gmtoff = -1;
    int result = parse_tz_offset("+03", &gmtoff);

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT_EQUAL(10800, gmtoff, "+03 = 10800 sec");
}

TEST(test_parse_tz_offset_hours_only_with_colon) {
    TEST_CASE("Parse +05:00");

    long gmtoff = -1;
    int result = parse_tz_offset("+05:00", &gmtoff);

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT_EQUAL(18000, gmtoff, "+05:00 = 18000 sec");
}

TEST(test_parse_tz_offset_invalid) {
    TEST_CASE("Invalid char returns 0");

    long gmtoff = -1;
    int result = parse_tz_offset("X", &gmtoff);

    TEST_ASSERT_EQUAL(0, result, "Should fail");
}

TEST(test_parse_tz_offset_negative_zero) {
    TEST_CASE("Parse -00:00");

    long gmtoff = -1;
    int result = parse_tz_offset("-00:00", &gmtoff);

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT_EQUAL(0, gmtoff, "-00:00 = 0 sec");
}

// ============================================================================
// strptime_flex
// ============================================================================

TEST(test_strptime_flex_space) {
    TEST_CASE("Parse with space separator");

    struct tm stm = {0};
    const char* rest = strptime_flex("2024-04-21 15:30:45", &stm);

    TEST_ASSERT_NOT_NULL(rest, "Should parse");
    TEST_ASSERT_EQUAL(124, stm.tm_year, "Year should be 124");
    TEST_ASSERT_EQUAL(3, stm.tm_mon, "Month should be 3");
    TEST_ASSERT_EQUAL(21, stm.tm_mday, "Day should be 21");
    TEST_ASSERT_EQUAL(15, stm.tm_hour, "Hour should be 15");
    TEST_ASSERT_EQUAL(30, stm.tm_min, "Min should be 30");
    TEST_ASSERT_EQUAL(45, stm.tm_sec, "Sec should be 45");
}

TEST(test_strptime_flex_t) {
    TEST_CASE("Parse with T separator");

    struct tm stm = {0};
    const char* rest = strptime_flex("2024-04-21T15:30:45", &stm);

    TEST_ASSERT_NOT_NULL(rest, "Should parse");
    TEST_ASSERT_EQUAL(15, stm.tm_hour, "Hour should be 15");
    TEST_ASSERT_EQUAL(30, stm.tm_min, "Min should be 30");
    TEST_ASSERT_EQUAL(45, stm.tm_sec, "Sec should be 45");
}

TEST(test_strptime_flex_invalid) {
    TEST_CASE("Invalid string returns NULL");

    struct tm stm = {0};
    const char* rest = strptime_flex("abc", &stm);

    TEST_ASSERT_NULL(rest, "Should fail");
}

TEST(test_strptime_flex_t_fallback) {
    TEST_CASE("T format is tried when space format fails");

    struct tm stm = {0};
    const char* rest = strptime_flex("2024-04-21T00:00:00", &stm);

    TEST_ASSERT_NOT_NULL(rest, "Should parse via T fallback");
    TEST_ASSERT_EQUAL(0, stm.tm_hour, "Hour should be 0");
}

// ============================================================================
// tm_to_strtm / strtm_to_tm
// ============================================================================

TEST(test_tm_to_strtm_roundtrip) {
    TEST_CASE("tm_t -> struct tm preserves fields");

    tm_t src = {0};
    src.tm_sec = 45;
    src.tm_min = 30;
    src.tm_hour = 15;
    src.tm_mday = 21;
    src.tm_mon = 3;
    src.tm_year = 124;
    src.tm_isdst = 0;
    src.tm_gmtoff = 10800;
    src.tm_usec = 123456;

    struct tm dst = tm_to_strtm(&src);

    TEST_ASSERT_EQUAL(45, dst.tm_sec, "sec should match");
    TEST_ASSERT_EQUAL(30, dst.tm_min, "min should match");
    TEST_ASSERT_EQUAL(15, dst.tm_hour, "hour should match");
    TEST_ASSERT_EQUAL(21, dst.tm_mday, "mday should match");
    TEST_ASSERT_EQUAL(3, dst.tm_mon, "mon should match");
    TEST_ASSERT_EQUAL(124, dst.tm_year, "year should match");
    TEST_ASSERT_EQUAL(10800, dst.tm_gmtoff, "gmtoff should match");
}

TEST(test_strtm_to_tm_sets_usec_zero) {
    TEST_CASE("strtm_to_tm initializes tm_usec to 0");

    struct tm src = {0};
    src.tm_sec = 45;
    src.tm_min = 30;
    src.tm_hour = 15;
    src.tm_mday = 21;
    src.tm_mon = 3;
    src.tm_year = 124;
    src.tm_gmtoff = -3600;

    tm_t dst;
    strtm_to_tm(&src, &dst);

    TEST_ASSERT_EQUAL(45, dst.tm_sec, "sec should match");
    TEST_ASSERT_EQUAL(15, dst.tm_hour, "hour should match");
    TEST_ASSERT_EQUAL(0, dst.tm_usec, "tm_usec should be 0");
    TEST_ASSERT_EQUAL(-3600, dst.tm_gmtoff, "gmtoff should match");
}

TEST(test_tm_strtm_roundtrip) {
    TEST_CASE("tm_t -> struct tm -> tm_t roundtrip preserves standard fields");

    tm_t original = {0};
    original.tm_sec = 59;
    original.tm_min = 59;
    original.tm_hour = 23;
    original.tm_mday = 31;
    original.tm_mon = 11;
    original.tm_year = 124;
    original.tm_isdst = -1;
    original.tm_gmtoff = 7200;
    original.tm_usec = 999999;

    struct tm mid = tm_to_strtm(&original);
    tm_t result;
    strtm_to_tm(&mid, &result);

    TEST_ASSERT_EQUAL(original.tm_sec, result.tm_sec, "sec should match");
    TEST_ASSERT_EQUAL(original.tm_min, result.tm_min, "min should match");
    TEST_ASSERT_EQUAL(original.tm_hour, result.tm_hour, "hour should match");
    TEST_ASSERT_EQUAL(original.tm_mday, result.tm_mday, "mday should match");
    TEST_ASSERT_EQUAL(original.tm_mon, result.tm_mon, "mon should match");
    TEST_ASSERT_EQUAL(original.tm_year, result.tm_year, "year should match");
    TEST_ASSERT_EQUAL(original.tm_gmtoff, result.tm_gmtoff, "gmtoff should match");
    TEST_ASSERT_EQUAL(0, result.tm_usec, "tm_usec should be reset to 0");
}

// ============================================================================
// parse_datetime_rest
// ============================================================================

TEST(test_parse_datetime_rest_with_usec) {
    TEST_CASE("Extract microseconds from rest string");

    tm_t tm = {0};
    const char* rest = parse_datetime_rest(".338335+00", &tm);

    TEST_ASSERT_EQUAL(338335, tm.tm_usec, "Should parse 338335 usec");
    TEST_ASSERT_EQUAL('+', *rest, "rest should point to '+'");
}

TEST(test_parse_datetime_rest_no_dot) {
    TEST_CASE("No dot leaves usec at 0 and skips to tz");

    tm_t tm = {0};
    const char* rest = parse_datetime_rest("+03:00", &tm);

    TEST_ASSERT_EQUAL(0, tm.tm_usec, "usec should be 0");
    TEST_ASSERT_EQUAL('+', *rest, "rest should point to '+'");
}

TEST(test_parse_datetime_rest_usec_then_z) {
    TEST_CASE("Microseconds followed by Z");

    tm_t tm = {0};
    const char* rest = parse_datetime_rest(".123Z", &tm);

    TEST_ASSERT_EQUAL(123000, tm.tm_usec, "Should parse 123000 usec");
    TEST_ASSERT_EQUAL('Z', *rest, "rest should point to 'Z'");
}

TEST(test_parse_datetime_rest_empty_after_dot) {
    TEST_CASE("Dot with no digits after it");

    tm_t tm = {0};
    parse_datetime_rest(".", &tm);

    TEST_ASSERT_EQUAL(0, tm.tm_usec, "No digits = 0 usec");
}

TEST(test_parse_datetime_rest_preserves_existing_usec) {
    TEST_CASE("Does not zero usec if no dot found");

    tm_t tm = {0};
    tm.tm_usec = 500000;
    parse_datetime_rest("+00", &tm);

    TEST_ASSERT_EQUAL(500000, tm.tm_usec, "Existing usec preserved");
}

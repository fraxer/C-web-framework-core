#include "framework.h"
#include "str.h"
#include <string.h>

// ============================================================================
// Тесты создания строк
// ============================================================================

TEST(test_str_create_from_string) {
    TEST_CASE("Create string from C string");

    str_t* str = str_create("Hello, World!");
    TEST_ASSERT_NOT_NULL(str, "String should be created");
    TEST_ASSERT_EQUAL_SIZE(13, str_size(str), "String size should be 13");
    TEST_ASSERT_STR_EQUAL("Hello, World!", str_get(str), "String content should match");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Short string should use SSO");

    str_free(str);
}

TEST(test_str_create_from_null) {
    TEST_CASE("Create string from NULL pointer");

    str_t* str = str_create(NULL);
    TEST_ASSERT_NOT_NULL(str, "String should be created");
    TEST_ASSERT_EQUAL_SIZE(0, str_size(str), "String size should be 0");
    TEST_ASSERT_STR_EQUAL("", str_get(str), "String should be empty");

    str_free(str);
}

TEST(test_str_createn_with_size) {
    TEST_CASE("Create string with explicit size");

    const char* text = "Test123";
    str_t* str = str_createn(text, 4);  // Only take "Test"
    TEST_ASSERT_NOT_NULL(str, "String should be created");
    TEST_ASSERT_EQUAL_SIZE(4, str_size(str), "String size should be 4");

    char result[5];
    memcpy(result, str_get(str), 4);
    result[4] = '\0';
    TEST_ASSERT_STR_EQUAL("Test", result, "String should contain first 4 chars");

    str_free(str);
}

TEST(test_str_create_empty) {
    TEST_CASE("Create empty string");

    str_t* str = str_create_empty(0);
    TEST_ASSERT_NOT_NULL(str, "Empty string should be created");
    TEST_ASSERT_EQUAL_SIZE(0, str_size(str), "Size should be 0");
    TEST_ASSERT_STR_EQUAL("", str_get(str), "String should be empty");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Empty string should use SSO");

    str_free(str);
}

TEST(test_str_create_empty_with_capacity) {
    TEST_CASE("Create empty string with initial capacity");

    str_t* str = str_create_empty(100);
    TEST_ASSERT_NOT_NULL(str, "String should be created");
    TEST_ASSERT_EQUAL_SIZE(0, str_size(str), "Size should be 0");
    TEST_ASSERT_EQUAL(100, str->init_capacity, "Init capacity should be 100");

    str_free(str);
}

// ============================================================================
// Тесты SSO (Small String Optimization)
// ============================================================================

TEST(test_str_sso_mode_small_string) {
    TEST_CASE("SSO mode for small strings");

    str_t* str = str_create("Short");
    TEST_ASSERT_NOT_NULL(str, "String should be created");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should be in SSO mode");
    TEST_ASSERT_EQUAL_SIZE(5, str_size(str), "Size should be 5");
    TEST_ASSERT_STR_EQUAL("Short", str_get(str), "Content should match");
    TEST_ASSERT_NULL(str->dynamic_buffer, "Dynamic buffer should be NULL");

    str_free(str);
}

TEST(test_str_sso_mode_max_size) {
    TEST_CASE("SSO mode at maximum capacity");

    // Create string just under SSO_SIZE (31 chars + null terminator)
    char test_str[32];
    memset(test_str, 'A', 31);
    test_str[31] = '\0';

    str_t* str = str_create(test_str);
    TEST_ASSERT_NOT_NULL(str, "String should be created");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should still be in SSO mode");
    TEST_ASSERT_EQUAL_SIZE(31, str_size(str), "Size should be 31");

    str_free(str);
}

TEST(test_str_sso_to_dynamic_transition) {
    TEST_CASE("Transition from SSO to dynamic mode");

    str_t* str = str_create("Small");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should start in SSO mode");

    // Append enough data to trigger transition to dynamic mode
    const char* long_suffix = " but now it becomes a very long string that exceeds SSO capacity";
    str_append(str, long_suffix, strlen(long_suffix));

    TEST_ASSERT_EQUAL_UINT(1, str->is_dynamic, "Should switch to dynamic mode");
    TEST_ASSERT_NOT_NULL(str->dynamic_buffer, "Dynamic buffer should be allocated");
    TEST_ASSERT(str->capacity > STR_SSO_SIZE, "Capacity should exceed SSO size");

    // Verify content integrity
    TEST_ASSERT(strstr(str_get(str), "Small") != NULL, "Should contain original text");
    TEST_ASSERT(strstr(str_get(str), "very long string") != NULL, "Should contain appended text");

    str_free(str);
}

// ============================================================================
// Тесты динамического режима
// ============================================================================

TEST(test_str_dynamic_mode_large_string) {
    TEST_CASE("Dynamic mode for large strings");

    // Create string larger than SSO_SIZE
    char large_str[100];
    memset(large_str, 'X', 99);
    large_str[99] = '\0';

    str_t* str = str_create(large_str);
    TEST_ASSERT_NOT_NULL(str, "String should be created");
    TEST_ASSERT_EQUAL_UINT(1, str->is_dynamic, "Should be in dynamic mode");
    TEST_ASSERT_NOT_NULL(str->dynamic_buffer, "Dynamic buffer should be allocated");
    TEST_ASSERT_EQUAL_SIZE(99, str_size(str), "Size should be 99");
    TEST_ASSERT(str->capacity >= 99, "Capacity should be at least 99");

    str_free(str);
}

TEST(test_str_dynamic_reallocation) {
    TEST_CASE("Dynamic buffer reallocation on growth");

    str_t* str = str_create_empty(0);

    // Add data that triggers multiple reallocations
    for (int i = 0; i < 100; i++) {
        str_appendc(str, 'A' + (i % 26));
    }

    TEST_ASSERT_EQUAL_UINT(1, str->is_dynamic, "Should be in dynamic mode");
    TEST_ASSERT_EQUAL_SIZE(100, str_size(str), "Size should be 100");
    TEST_ASSERT(str->capacity >= 100, "Capacity should accommodate all data");

    str_free(str);
}

// ============================================================================
// Тесты резервирования памяти
// ============================================================================

TEST(test_str_reserve_within_sso) {
    TEST_CASE("Reserve capacity within SSO range");

    str_t* str = str_create_empty(0);
    int result = str_reserve(str, 20);

    TEST_ASSERT_EQUAL(1, result, "Reserve should succeed");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should remain in SSO mode");

    str_free(str);
}

TEST(test_str_reserve_force_dynamic) {
    TEST_CASE("Reserve capacity beyond SSO forces dynamic mode");

    str_t* str = str_create("Small");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should start in SSO mode");

    int result = str_reserve(str, 100);
    TEST_ASSERT_EQUAL(1, result, "Reserve should succeed");
    TEST_ASSERT_EQUAL_UINT(1, str->is_dynamic, "Should switch to dynamic mode");
    TEST_ASSERT(str->capacity >= 100, "Capacity should be at least 100");

    // Verify content preserved
    TEST_ASSERT_STR_EQUAL("Small", str_get(str), "Content should be preserved");

    str_free(str);
}

TEST(test_str_reserve_expand_dynamic) {
    TEST_CASE("Reserve expands existing dynamic buffer");

    char large_str[100];
    memset(large_str, 'Y', 99);
    large_str[99] = '\0';

    str_t* str = str_create(large_str);
    size_t old_capacity = str->capacity;

    int result = str_reserve(str, old_capacity + 100);
    TEST_ASSERT_EQUAL(1, result, "Reserve should succeed");
    TEST_ASSERT(str->capacity >= old_capacity + 100, "Capacity should be expanded");

    str_free(str);
}

// ============================================================================
// Тесты операций с символами
// ============================================================================

TEST(test_str_appendc) {
    TEST_CASE("Append single character");

    str_t* str = str_create("Hello");
    int result = str_appendc(str, '!');

    TEST_ASSERT_EQUAL(1, result, "Append should succeed");
    TEST_ASSERT_EQUAL_SIZE(6, str_size(str), "Size should be 6");
    TEST_ASSERT_STR_EQUAL("Hello!", str_get(str), "Content should match");

    str_free(str);
}

TEST(test_str_prependc) {
    TEST_CASE("Prepend single character");

    str_t* str = str_create("ello");
    int result = str_prependc(str, 'H');

    TEST_ASSERT_EQUAL(1, result, "Prepend should succeed");
    TEST_ASSERT_EQUAL_SIZE(5, str_size(str), "Size should be 5");
    TEST_ASSERT_STR_EQUAL("Hello", str_get(str), "Content should match");

    str_free(str);
}

TEST(test_str_insertc_middle) {
    TEST_CASE("Insert character in the middle");

    str_t* str = str_create("Helo");
    int result = str_insertc(str, 'l', 3);

    TEST_ASSERT_EQUAL(1, result, "Insert should succeed");
    TEST_ASSERT_EQUAL_SIZE(5, str_size(str), "Size should be 5");
    TEST_ASSERT_STR_EQUAL("Hello", str_get(str), "Content should match");

    str_free(str);
}

TEST(test_str_insertc_at_boundaries) {
    TEST_CASE("Insert character at boundaries");

    str_t* str = str_create("Middle");

    // Insert at beginning
    str_insertc(str, '[', 0);
    TEST_ASSERT_STR_EQUAL("[Middle", str_get(str), "Insert at start should work");

    // Insert at end
    str_insertc(str, ']', str_size(str));
    TEST_ASSERT_STR_EQUAL("[Middle]", str_get(str), "Insert at end should work");

    str_free(str);
}

TEST(test_str_insertc_invalid_position) {
    TEST_CASE("Insert character at invalid position");

    str_t* str = str_create("Test");
    int result = str_insertc(str, 'X', 100);  // Position beyond size

    TEST_ASSERT_EQUAL(0, result, "Insert should fail");
    TEST_ASSERT_STR_EQUAL("Test", str_get(str), "Content should be unchanged");

    str_free(str);
}

// ============================================================================
// Тесты операций со строками
// ============================================================================

TEST(test_str_append) {
    TEST_CASE("Append string");

    str_t* str = str_create("Hello");
    int result = str_append(str, ", World!", 8);

    TEST_ASSERT_EQUAL(1, result, "Append should succeed");
    TEST_ASSERT_EQUAL_SIZE(13, str_size(str), "Size should be 13");
    TEST_ASSERT_STR_EQUAL("Hello, World!", str_get(str), "Content should match");

    str_free(str);
}

TEST(test_str_prepend) {
    TEST_CASE("Prepend string");

    str_t* str = str_create("World");
    int result = str_prepend(str, "Hello, ", 7);

    TEST_ASSERT_EQUAL(1, result, "Prepend should succeed");
    TEST_ASSERT_EQUAL_SIZE(12, str_size(str), "Size should be 12");
    TEST_ASSERT_STR_EQUAL("Hello, World", str_get(str), "Content should match");

    str_free(str);
}

TEST(test_str_insert_middle) {
    TEST_CASE("Insert string in the middle");

    str_t* str = str_create("HelloWorld");
    int result = str_insert(str, ", ", 2, 5);

    TEST_ASSERT_EQUAL(1, result, "Insert should succeed");
    TEST_ASSERT_EQUAL_SIZE(12, str_size(str), "Size should be 12");
    TEST_ASSERT_STR_EQUAL("Hello, World", str_get(str), "Content should match");

    str_free(str);
}

TEST(test_str_append_empty_string) {
    TEST_CASE("Append to empty string");

    str_t* str = str_create_empty(0);
    str_append(str, "First", 5);

    TEST_ASSERT_EQUAL_SIZE(5, str_size(str), "Size should be 5");
    TEST_ASSERT_STR_EQUAL("First", str_get(str), "Content should match");

    str_append(str, " Second", 7);
    TEST_ASSERT_STR_EQUAL("First Second", str_get(str), "Multiple appends should work");

    str_free(str);
}

TEST(test_str_append_null_handling) {
    TEST_CASE("Append NULL string handling");

    str_t* str = str_create("Test");
    int result = str_append(str, NULL, 5);

    TEST_ASSERT_EQUAL(0, result, "Append NULL should fail");
    TEST_ASSERT_STR_EQUAL("Test", str_get(str), "Content should be unchanged");

    str_free(str);
}

// ============================================================================
// Тесты форматированного добавления
// ============================================================================

TEST(test_str_appendf_simple) {
    TEST_CASE("Formatted append - simple");

    str_t* str = str_create("Value: ");
    int result = str_appendf(str, "%d", 42);

    TEST_ASSERT_EQUAL(1, result, "Appendf should succeed");
    TEST_ASSERT_STR_EQUAL("Value: 42", str_get(str), "Content should match");

    str_free(str);
}

TEST(test_str_appendf_multiple_args) {
    TEST_CASE("Formatted append - multiple arguments");

    str_t* str = str_create("Data: ");
    int result = str_appendf(str, "x=%d, y=%d, name=%s", 10, 20, "test");

    TEST_ASSERT_EQUAL(1, result, "Appendf should succeed");
    TEST_ASSERT_STR_EQUAL("Data: x=10, y=20, name=test", str_get(str), "Content should match");

    str_free(str);
}

TEST(test_str_appendf_float) {
    TEST_CASE("Formatted append - float");

    str_t* str = str_create("Pi: ");
    str_appendf(str, "%.2f", 3.14159);

    TEST_ASSERT_STR_EQUAL("Pi: 3.14", str_get(str), "Float formatting should work");

    str_free(str);
}

TEST(test_str_appendf_large_output) {
    TEST_CASE("Formatted append - large output");

    str_t* str = str_create_empty(0);
    char large_text[200];
    memset(large_text, 'X', 199);
    large_text[199] = '\0';

    int result = str_appendf(str, "Text: %s", large_text);

    TEST_ASSERT_EQUAL(1, result, "Appendf should succeed");
    TEST_ASSERT(str_size(str) > 100, "Should handle large formatted output");

    str_free(str);
}

// ============================================================================
// Тесты присвоения
// ============================================================================

TEST(test_str_assign) {
    TEST_CASE("Assign new value");

    str_t* str = str_create("Old value");
    int result = str_assign(str, "New value", 9);

    TEST_ASSERT_EQUAL(1, result, "Assign should succeed");
    TEST_ASSERT_EQUAL_SIZE(9, str_size(str), "Size should be 9");
    TEST_ASSERT_STR_EQUAL("New value", str_get(str), "Content should be replaced");

    str_free(str);
}

TEST(test_str_assign_shorter) {
    TEST_CASE("Assign shorter string");

    str_t* str = str_create("Very long string");
    str_assign(str, "Short", 5);

    TEST_ASSERT_EQUAL_SIZE(5, str_size(str), "Size should be reduced");
    TEST_ASSERT_STR_EQUAL("Short", str_get(str), "Content should be replaced");

    str_free(str);
}

TEST(test_str_assign_longer) {
    TEST_CASE("Assign longer string");

    str_t* str = str_create("Short");
    str_assign(str, "Much longer string now", 22);

    TEST_ASSERT_EQUAL_SIZE(22, str_size(str), "Size should be increased");
    TEST_ASSERT_STR_EQUAL("Much longer string now", str_get(str), "Content should be replaced");

    str_free(str);
}

// ============================================================================
// Тесты перемещения
// ============================================================================

TEST(test_str_move_sso_to_sso) {
    TEST_CASE("Move SSO string to SSO string");

    str_t* src = str_create("Source");
    str_t* dst = str_create("Destination");

    int result = str_move(src, dst);

    TEST_ASSERT_EQUAL(1, result, "Move should succeed");
    TEST_ASSERT_STR_EQUAL("Source", str_get(dst), "Destination should have source content");
    TEST_ASSERT_EQUAL_SIZE(6, str_size(dst), "Destination size should match");
    TEST_ASSERT_EQUAL_SIZE(0, str_size(src), "Source should be empty");

    str_free(src);
    str_free(dst);
}

TEST(test_str_move_dynamic_to_sso) {
    TEST_CASE("Move dynamic string to SSO string");

    char large_str[100];
    memset(large_str, 'A', 99);
    large_str[99] = '\0';

    str_t* src = str_create(large_str);
    str_t* dst = str_create("Small");

    TEST_ASSERT_EQUAL_UINT(1, src->is_dynamic, "Source should be dynamic");

    void* old_buffer = src->dynamic_buffer;
    int result = str_move(src, dst);

    TEST_ASSERT_EQUAL(1, result, "Move should succeed");
    TEST_ASSERT_EQUAL_UINT(1, dst->is_dynamic, "Destination should become dynamic");
    TEST_ASSERT_EQUAL(old_buffer, dst->dynamic_buffer, "Buffer should be moved");
    TEST_ASSERT_EQUAL_SIZE(99, str_size(dst), "Destination size should match");
    TEST_ASSERT_EQUAL_SIZE(0, str_size(src), "Source should be empty");

    str_free(src);
    str_free(dst);
}

TEST(test_str_move_null_handling) {
    TEST_CASE("Move with NULL pointers");

    str_t* str = str_create("Test");

    int result1 = str_move(NULL, str);
    TEST_ASSERT_EQUAL(0, result1, "Move from NULL should fail");

    int result2 = str_move(str, NULL);
    TEST_ASSERT_EQUAL(0, result2, "Move to NULL should fail");

    str_free(str);
}

// ============================================================================
// Тесты сравнения
// ============================================================================

TEST(test_str_cmp_equal) {
    TEST_CASE("Compare equal strings");

    str_t* str1 = str_create("Equal");
    str_t* str2 = str_create("Equal");

    int result = str_cmp(str1, str2);
    TEST_ASSERT_EQUAL(0, result, "Equal strings should return 0");

    str_free(str1);
    str_free(str2);
}

TEST(test_str_cmp_different) {
    TEST_CASE("Compare different strings");

    str_t* str1 = str_create("Apple");
    str_t* str2 = str_create("Banana");

    int result = str_cmp(str1, str2);
    TEST_ASSERT(result < 0, "Apple should be less than Banana");

    str_free(str1);
    str_free(str2);
}

TEST(test_str_cmpc) {
    TEST_CASE("Compare str_t with C string");

    str_t* str = str_create("Test");

    TEST_ASSERT_EQUAL(0, str_cmpc(str, "Test"), "Should match");
    TEST_ASSERT(str_cmpc(str, "Zest") < 0, "Test < Zest");
    TEST_ASSERT(str_cmpc(str, "Best") > 0, "Test > Best");

    str_free(str);
}

// ============================================================================
// Тесты получения данных
// ============================================================================

TEST(test_str_get) {
    TEST_CASE("Get string pointer");

    str_t* str = str_create("Content");
    char* ptr = str_get(str);

    TEST_ASSERT_NOT_NULL(ptr, "Pointer should not be NULL");
    TEST_ASSERT_STR_EQUAL("Content", ptr, "Content should match");

    str_free(str);
}

TEST(test_str_get_empty) {
    TEST_CASE("Get empty string");

    str_t* str = str_create_empty(0);
    char* ptr = str_get(str);

    TEST_ASSERT_NOT_NULL(ptr, "Pointer should not be NULL");
    TEST_ASSERT_STR_EQUAL("", ptr, "Should return empty string");

    str_free(str);
}

TEST(test_str_get_null) {
    TEST_CASE("Get from NULL string");

    char* ptr = str_get(NULL);
    TEST_ASSERT_NULL(ptr, "Should return NULL for NULL input");
}

TEST(test_str_copy) {
    TEST_CASE("Copy string content");

    str_t* str = str_create("Original");
    char* copy = str_copy(str);

    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_STR_EQUAL("Original", copy, "Copy should match original");
    TEST_ASSERT(copy != str_get(str), "Copy should be different pointer");

    // Modify original
    str_append(str, " modified", 9);
    TEST_ASSERT_STR_EQUAL("Original", copy, "Copy should be independent");

    free(copy);
    str_free(str);
}

TEST(test_str_copy_null) {
    TEST_CASE("Copy NULL string");

    char* copy = str_copy(NULL);
    TEST_ASSERT_NULL(copy, "Copy of NULL should return NULL");
}

// ============================================================================
// Тесты сброса и очистки
// ============================================================================

TEST(test_str_reset) {
    TEST_CASE("Reset string");

    str_t* str = str_create("Content");
    str->init_capacity = 50;

    int result = str_reset(str);

    TEST_ASSERT_EQUAL(1, result, "Reset should succeed");
    TEST_ASSERT_EQUAL_SIZE(0, str_size(str), "Size should be 0");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should be in SSO mode");
    TEST_ASSERT_EQUAL(50, str->init_capacity, "Init capacity should be preserved");

    str_free(str);
}

TEST(test_str_clear) {
    TEST_CASE("Clear string");

    str_t* str = str_create("Content");
    str_clear(str);

    TEST_ASSERT_EQUAL_SIZE(0, str_size(str), "Size should be 0");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should be in SSO mode");
    TEST_ASSERT_STR_EQUAL("", str_get(str), "String should be empty");

    str_free(str);
}

TEST(test_str_clear_dynamic) {
    TEST_CASE("Clear dynamic string");

    char large_str[100];
    memset(large_str, 'Z', 99);
    large_str[99] = '\0';

    str_t* str = str_create(large_str);
    TEST_ASSERT_EQUAL_UINT(1, str->is_dynamic, "Should be dynamic");

    str_clear(str);

    TEST_ASSERT_EQUAL_SIZE(0, str_size(str), "Size should be 0");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should reset to SSO mode");

    str_free(str);
}

// ============================================================================
// Тесты производительности и граничных случаев
// ============================================================================

TEST(test_str_large_string_operations) {
    TEST_CASE("Operations on very large string");

    str_t* str = str_create_empty(1000);

    // Build large string
    for (int i = 0; i < 500; i++) {
        str_append(str, "AB", 2);
    }

    TEST_ASSERT_EQUAL_SIZE(1000, str_size(str), "Size should be 1000");
    TEST_ASSERT_EQUAL_UINT(1, str->is_dynamic, "Should be in dynamic mode");

    // Verify content
    char* content = str_get(str);
    TEST_ASSERT_EQUAL('A', content[0], "First char should be A");
    TEST_ASSERT_EQUAL('B', content[1], "Second char should be B");
    TEST_ASSERT_EQUAL('B', content[999], "Last char should be B");

    str_free(str);
}

TEST(test_str_multiple_transitions) {
    TEST_CASE("Multiple SSO to dynamic transitions");

    str_t* str = str_create("Start");
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should start in SSO");

    // First transition
    for (int i = 0; i < 30; i++) {
        str_appendc(str, 'X');
    }
    TEST_ASSERT_EQUAL_UINT(1, str->is_dynamic, "Should be dynamic");

    // Clear and reset to SSO
    str_clear(str);
    TEST_ASSERT_EQUAL_UINT(0, str->is_dynamic, "Should be back in SSO");

    // Second transition
    str_append(str, "Another long string that exceeds SSO capacity", 46);
    TEST_ASSERT_EQUAL_UINT(1, str->is_dynamic, "Should be dynamic again");

    str_free(str);
}

TEST(test_str_size_function) {
    TEST_CASE("Size function accuracy");

    str_t* str = str_create_empty(0);
    TEST_ASSERT_EQUAL_SIZE(0, str_size(str), "Empty string size should be 0");

    str_appendc(str, 'A');
    TEST_ASSERT_EQUAL_SIZE(1, str_size(str), "Size should be 1");

    str_append(str, "BCDEF", 5);
    TEST_ASSERT_EQUAL_SIZE(6, str_size(str), "Size should be 6");

    TEST_ASSERT_EQUAL_SIZE(0, str_size(NULL), "NULL string size should be 0");

    str_free(str);
}

TEST(test_str_boundary_positions) {
    TEST_CASE("Insert at boundary positions");

    str_t* str = str_create("Middle");

    // Insert at position 0
    str_insert(str, "Start", 5, 0);
    TEST_ASSERT_STR_EQUAL("StartMiddle", str_get(str), "Insert at 0 should work");

    // Insert at current end
    size_t end_pos = str_size(str);
    str_insert(str, "End", 3, end_pos);
    TEST_ASSERT_STR_EQUAL("StartMiddleEnd", str_get(str), "Insert at end should work");

    str_free(str);
}

TEST(test_str_empty_operations) {
    TEST_CASE("Operations on empty string");

    str_t* str = str_create_empty(0);

    // Append to empty
    str_appendc(str, 'A');
    TEST_ASSERT_STR_EQUAL("A", str_get(str), "Append to empty should work");

    str_clear(str);

    // Prepend to empty
    str_prependc(str, 'B');
    TEST_ASSERT_STR_EQUAL("B", str_get(str), "Prepend to empty should work");

    str_free(str);
}

TEST(test_str_consecutive_operations) {
    TEST_CASE("Multiple consecutive operations");

    str_t* str = str_create_empty(0);

    str_append(str, "Hello", 5);
    str_appendc(str, ' ');
    str_append(str, "World", 5);
    str_appendc(str, '!');
    str_prepend(str, ">> ", 3);

    TEST_ASSERT_STR_EQUAL(">> Hello World!", str_get(str), "Consecutive operations should work");
    TEST_ASSERT_EQUAL_SIZE(15, str_size(str), "Size should be correct");

    str_free(str);
}

// ============================================================================
// Тесты целостности памяти
// ============================================================================

TEST(test_str_memory_integrity_after_operations) {
    TEST_CASE("Memory integrity after multiple operations");

    str_t* str = str_create("Initial");

    // Perform various operations
    str_append(str, " text", 5);
    str_prependc(str, '[');
    str_appendc(str, ']');
    str_insert(str, " inserted", 9, 8);

    // Content should be valid
    char* content = str_get(str);
    TEST_ASSERT_NOT_NULL(content, "Content should not be NULL");
    TEST_ASSERT(strlen(content) == str_size(str), "String length should match size");

    str_free(str);
}

TEST(test_str_null_termination) {
    TEST_CASE("Null termination consistency");

    str_t* str = str_create("Test");

    // After append
    str_appendc(str, '!');
    char* ptr = str_get(str);
    TEST_ASSERT_EQUAL('\0', ptr[str_size(str)], "Should be null-terminated after append");

    // After insert
    str_insertc(str, 'X', 2);
    ptr = str_get(str);
    TEST_ASSERT_EQUAL('\0', ptr[str_size(str)], "Should be null-terminated after insert");

    // After prepend
    str_prependc(str, 'Y');
    ptr = str_get(str);
    TEST_ASSERT_EQUAL('\0', ptr[str_size(str)], "Should be null-terminated after prepend");

    str_free(str);
}

// ============================================================================
// Тесты специальных символов
// ============================================================================

TEST(test_str_special_characters) {
    TEST_CASE("Handle special characters");

    str_t* str = str_create("Line1\nLine2\tTabbed\r\nWindows");

    TEST_ASSERT(str_size(str) > 0, "Should handle newlines and tabs");
    TEST_ASSERT(strstr(str_get(str), "\n") != NULL, "Should contain newline");
    TEST_ASSERT(strstr(str_get(str), "\t") != NULL, "Should contain tab");

    str_free(str);
}

TEST(test_str_null_byte_in_content) {
    TEST_CASE("Handle explicit size with null bytes");

    char data[] = {'A', 'B', '\0', 'C', 'D'};
    str_t* str = str_createn(data, 5);

    TEST_ASSERT_EQUAL_SIZE(5, str_size(str), "Size should include null byte");

    char* content = str_get(str);
    TEST_ASSERT_EQUAL('A', content[0], "First char should be A");
    TEST_ASSERT_EQUAL('\0', content[2], "Third char should be null");
    TEST_ASSERT_EQUAL('D', content[4], "Fifth char should be D");

    str_free(str);
}

// ============================================================================
// Тесты init_capacity
// ============================================================================

TEST(test_str_init_capacity_limit) {
    TEST_CASE("Init capacity should be limited to 16384");

    str_t* str = str_create_empty(20000);
    TEST_ASSERT_EQUAL(16384, str->init_capacity, "Init capacity should be capped at 16384");

    str_free(str);
}

TEST(test_str_init_capacity_preserved) {
    TEST_CASE("Init capacity preserved through operations");

    str_t* str = str_create_empty(100);
    TEST_ASSERT_EQUAL(100, str->init_capacity, "Init capacity should be set");

    str_append(str, "Some text", 9);
    TEST_ASSERT_EQUAL(100, str->init_capacity, "Init capacity should be preserved");

    str_clear(str);
    TEST_ASSERT_EQUAL(100, str->init_capacity, "Init capacity should survive clear");

    str_free(str);
}

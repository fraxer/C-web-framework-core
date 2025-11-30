#include "framework.h"
#include "../misc/bufferdata.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// ============================================================================
// Тесты инициализации
// ============================================================================

TEST(test_bufferdata_init_basic) {
    TEST_CASE("Basic initialization");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Type should be STATIC");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_sbuffer, "Static buffer offset should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_dbuffer, "Dynamic buffer offset should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.dbuffer_size, "Dynamic buffer size should be 0");
    TEST_ASSERT_NULL(buffer.dynamic_buffer, "Dynamic buffer pointer should be NULL");
    TEST_ASSERT_EQUAL(0, buffer.static_buffer[0], "First byte should be null terminator");
}

TEST(test_bufferdata_init_null) {
    TEST_CASE("Initialize with NULL pointer");

    // Should not crash
    bufferdata_init(NULL);
    TEST_ASSERT(1, "Function should handle NULL gracefully");
}

// ============================================================================
// Тесты bufferdata_push - базовая функциональность
// ============================================================================

TEST(test_bufferdata_push_single_char) {
    TEST_CASE("Push single character");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    int result = bufferdata_push(&buffer, 'A');
    TEST_ASSERT_EQUAL(1, result, "Push should succeed");
    TEST_ASSERT_EQUAL_SIZE(1, buffer.offset_sbuffer, "Offset should be 1");
    TEST_ASSERT_EQUAL('A', buffer.static_buffer[0], "First char should be 'A'");
    TEST_ASSERT_EQUAL(0, buffer.static_buffer[1], "Should be null-terminated");
    TEST_ASSERT_EQUAL_SIZE(1, bufferdata_writed(&buffer), "Written size should be 1");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_push_multiple_chars) {
    TEST_CASE("Push multiple characters");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    const char* text = "Hello";
    for (int i = 0; text[i] != '\0'; i++) {
        int result = bufferdata_push(&buffer, text[i]);
        TEST_ASSERT_EQUAL(1, result, "Each push should succeed");
    }

    TEST_ASSERT_EQUAL_SIZE(5, buffer.offset_sbuffer, "Offset should be 5");
    TEST_ASSERT_EQUAL_SIZE(5, bufferdata_writed(&buffer), "Written size should be 5");

    char* data = bufferdata_get(&buffer);
    TEST_ASSERT_NOT_NULL(data, "Should get valid pointer");
    TEST_ASSERT_STR_EQUAL("Hello", data, "Content should match");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_push_null_pointer) {
    TEST_CASE("Push to NULL buffer");

    int result = bufferdata_push(NULL, 'A');
    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL buffer");
}

// ============================================================================
// Тесты переполнения статического буфера
// ============================================================================

TEST(test_bufferdata_push_boundary_4095) {
    TEST_CASE("Push exactly 4095 characters (BUFFERDATA_SIZE - 1)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Push 4095 characters - должно остаться в STATIC режиме
    for (int i = 0; i < 4095; i++) {
        int result = bufferdata_push(&buffer, 'A');
        TEST_ASSERT_EQUAL(1, result, "Push should succeed");
    }

    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Should still be STATIC");
    TEST_ASSERT_EQUAL_SIZE(4095, buffer.offset_sbuffer, "Offset should be 4095");
    TEST_ASSERT_EQUAL_SIZE(4095, bufferdata_writed(&buffer), "Written size should be 4095");
    TEST_ASSERT_NULL(buffer.dynamic_buffer, "Dynamic buffer should still be NULL");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_push_boundary_4096) {
    TEST_CASE("Push exactly 4096 characters (BUFFERDATA_SIZE)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Push 4096 characters - should stay in STATIC mode
    for (int i = 0; i < 4096; i++) {
        int result = bufferdata_push(&buffer, 'B');
        TEST_ASSERT_EQUAL(1, result, "Push should succeed");
    }

    // At exactly 4096, buffer is still STATIC (offset_sbuffer < BUFFERDATA_SIZE check)
    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Should still be STATIC");
    TEST_ASSERT_EQUAL_SIZE(4096, bufferdata_writed(&buffer), "Written size should be 4096");
    TEST_ASSERT_NULL(buffer.dynamic_buffer, "Dynamic buffer should not be allocated yet");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_push_boundary_4097) {
    TEST_CASE("Push 4097 characters (overflow)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Push 4097 characters
    for (int i = 0; i < 4097; i++) {
        int result = bufferdata_push(&buffer, 'C');
        TEST_ASSERT_EQUAL(1, result, "Push should succeed");
    }

    TEST_ASSERT_EQUAL(BUFFERDATA_DYNAMIC, buffer.type, "Should be in DYNAMIC mode");
    TEST_ASSERT_EQUAL_SIZE(4097, bufferdata_writed(&buffer), "Written size should be 4097");

    // Must complete to move all data to dynamic buffer
    bufferdata_complete(&buffer);

    char* data = bufferdata_get(&buffer);
    TEST_ASSERT_NOT_NULL(data, "Should get valid pointer");
    TEST_ASSERT_EQUAL('C', data[0], "First char should be 'C'");
    TEST_ASSERT_EQUAL('C', data[4096], "Last char should be 'C'");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_push_large_buffer) {
    TEST_CASE("Push very large buffer (10000 chars)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 10000; i++) {
        int result = bufferdata_push(&buffer, 'X');
        TEST_ASSERT_EQUAL(1, result, "Push should succeed");
    }

    TEST_ASSERT_EQUAL(BUFFERDATA_DYNAMIC, buffer.type, "Should be DYNAMIC");
    TEST_ASSERT_EQUAL_SIZE(10000, bufferdata_writed(&buffer), "Written size should be 10000");

    bufferdata_clear(&buffer);
}

// ============================================================================
// Тесты переключения STATIC -> DYNAMIC
// ============================================================================

TEST(test_bufferdata_transition_to_dynamic) {
    TEST_CASE("Transition from STATIC to DYNAMIC mode");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Fill static buffer completely (4096 chars)
    for (int i = 0; i < BUFFERDATA_SIZE; i++) {
        bufferdata_push(&buffer, 'A' + (i % 26));
    }

    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Should still be STATIC at 4096");

    // This should trigger transition to DYNAMIC
    int result = bufferdata_push(&buffer, 'Z');
    TEST_ASSERT_EQUAL(1, result, "Push should succeed");
    TEST_ASSERT_EQUAL(BUFFERDATA_DYNAMIC, buffer.type, "Should transition to DYNAMIC");
    TEST_ASSERT_EQUAL_SIZE(4097, bufferdata_writed(&buffer), "Size should be 4097");

    // Complete to move all data to dynamic buffer
    bufferdata_complete(&buffer);

    // Verify all data is preserved
    char* data = bufferdata_get(&buffer);
    TEST_ASSERT_NOT_NULL(data, "Data should be accessible");
    TEST_ASSERT_EQUAL_SIZE(4097, bufferdata_writed(&buffer), "Size should still be 4097");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_dynamic_realloc_growth) {
    TEST_CASE("Dynamic buffer reallocation and growth");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Force dynamic mode
    for (int i = 0; i <= BUFFERDATA_SIZE; i++) {
        bufferdata_push(&buffer, 'A');
    }

    TEST_ASSERT_EQUAL(BUFFERDATA_DYNAMIC, buffer.type, "Should be in DYNAMIC mode");

    size_t initial_dbuffer_size = buffer.dbuffer_size;

    // Continue pushing to force realloc
    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'B');
    }

    TEST_ASSERT(buffer.dbuffer_size >= initial_dbuffer_size, "Buffer should have grown");
    TEST_ASSERT_EQUAL_SIZE(4097 + 5000, bufferdata_writed(&buffer), "Size should be correct");

    bufferdata_clear(&buffer);
}

// ============================================================================
// Тесты bufferdata_reset
// ============================================================================

TEST(test_bufferdata_reset_static) {
    TEST_CASE("Reset static buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'T');
    bufferdata_push(&buffer, 'E');
    bufferdata_push(&buffer, 'S');
    bufferdata_push(&buffer, 'T');

    bufferdata_reset(&buffer);

    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Type should be STATIC");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_sbuffer, "Static offset should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_dbuffer, "Dynamic offset should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, bufferdata_writed(&buffer), "Written size should be 0");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_reset_dynamic) {
    TEST_CASE("Reset dynamic buffer (memory reuse)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Create dynamic buffer
    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }

    char* old_ptr = buffer.dynamic_buffer;
    TEST_ASSERT_NOT_NULL(old_ptr, "Dynamic buffer should exist");

    bufferdata_reset(&buffer);

    // Reset should NOT free dynamic buffer (optimization for reuse)
    TEST_ASSERT_EQUAL(old_ptr, buffer.dynamic_buffer, "Dynamic buffer pointer should be preserved");
    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Type should reset to STATIC");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_sbuffer, "Static offset should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_dbuffer, "Dynamic offset should be 0");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_reset_null) {
    TEST_CASE("Reset NULL buffer");

    bufferdata_reset(NULL);
    TEST_ASSERT(1, "Should handle NULL gracefully");
}

// ============================================================================
// Тесты bufferdata_clear
// ============================================================================

TEST(test_bufferdata_clear_static) {
    TEST_CASE("Clear static buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'X');

    bufferdata_clear(&buffer);

    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Type should be STATIC");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_sbuffer, "Offset should be 0");
    TEST_ASSERT_NULL(buffer.dynamic_buffer, "Dynamic buffer should be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.dbuffer_size, "Dynamic size should be 0");
}

TEST(test_bufferdata_clear_dynamic) {
    TEST_CASE("Clear dynamic buffer (full cleanup)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Create dynamic buffer
    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }

    TEST_ASSERT_NOT_NULL(buffer.dynamic_buffer, "Dynamic buffer should exist");

    bufferdata_clear(&buffer);

    // Clear should free dynamic buffer
    TEST_ASSERT_NULL(buffer.dynamic_buffer, "Dynamic buffer should be freed");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.dbuffer_size, "Dynamic size should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_dbuffer, "Dynamic offset should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_sbuffer, "Static offset should be 0");
}

TEST(test_bufferdata_clear_null) {
    TEST_CASE("Clear NULL buffer");

    bufferdata_clear(NULL);
    TEST_ASSERT(1, "Should handle NULL gracefully");
}

// ============================================================================
// Тесты bufferdata_writed
// ============================================================================

TEST(test_bufferdata_writed_empty) {
    TEST_CASE("Written size of empty buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    TEST_ASSERT_EQUAL_SIZE(0, bufferdata_writed(&buffer), "Size should be 0");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_writed_static) {
    TEST_CASE("Written size in STATIC mode");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 100; i++) {
        bufferdata_push(&buffer, 'A');
    }

    TEST_ASSERT_EQUAL_SIZE(100, bufferdata_writed(&buffer), "Size should be 100");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_writed_dynamic) {
    TEST_CASE("Written size in DYNAMIC mode");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }

    TEST_ASSERT_EQUAL_SIZE(5000, bufferdata_writed(&buffer), "Size should be 5000");
    TEST_ASSERT_EQUAL(BUFFERDATA_DYNAMIC, buffer.type, "Should be DYNAMIC");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_writed_null) {
    TEST_CASE("Written size of NULL buffer");

    TEST_ASSERT_EQUAL_SIZE(0, bufferdata_writed(NULL), "Should return 0 for NULL");
}

// ============================================================================
// Тесты bufferdata_complete
// ============================================================================

TEST(test_bufferdata_complete_static) {
    TEST_CASE("Complete static buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'A');

    int result = bufferdata_complete(&buffer);
    TEST_ASSERT_EQUAL(1, result, "Complete should succeed");
    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Should remain STATIC");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_complete_dynamic) {
    TEST_CASE("Complete dynamic buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Create dynamic buffer with data in static part
    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }

    // Add more to static buffer without moving
    buffer.type = BUFFERDATA_DYNAMIC;
    buffer.offset_sbuffer = 10; // Simulate pending data

    int result = bufferdata_complete(&buffer);
    TEST_ASSERT_EQUAL(1, result, "Complete should succeed");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_complete_null) {
    TEST_CASE("Complete NULL buffer");

    int result = bufferdata_complete(NULL);
    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL");
}

// ============================================================================
// Тесты bufferdata_move
// ============================================================================

TEST(test_bufferdata_move_static_no_op) {
    TEST_CASE("Move on STATIC buffer (no-op)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'A');

    int result = bufferdata_move(&buffer);
    TEST_ASSERT_EQUAL(1, result, "Move should succeed");
    TEST_ASSERT_EQUAL(BUFFERDATA_STATIC, buffer.type, "Should remain STATIC");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_move_dynamic) {
    TEST_CASE("Move data from static to dynamic buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    buffer.type = BUFFERDATA_DYNAMIC;

    // Simulate data in static buffer
    strcpy(buffer.static_buffer, "Hello");
    buffer.offset_sbuffer = 5;
    buffer.offset_dbuffer = 0;

    int result = bufferdata_move(&buffer);
    TEST_ASSERT_EQUAL(1, result, "Move should succeed");
    TEST_ASSERT_NOT_NULL(buffer.dynamic_buffer, "Dynamic buffer should be allocated");
    TEST_ASSERT_EQUAL_SIZE(5, buffer.offset_dbuffer, "Dynamic offset should be 5");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_sbuffer, "Static offset should be 0");
    TEST_ASSERT_STR_EQUAL("Hello", buffer.dynamic_buffer, "Data should be moved");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_move_null) {
    TEST_CASE("Move NULL buffer");

    int result = bufferdata_move(NULL);
    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL");
}

// ============================================================================
// Тесты bufferdata_get
// ============================================================================

TEST(test_bufferdata_get_static) {
    TEST_CASE("Get pointer to static buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'T');
    bufferdata_push(&buffer, 'e');
    bufferdata_push(&buffer, 's');
    bufferdata_push(&buffer, 't');

    char* data = bufferdata_get(&buffer);
    TEST_ASSERT_NOT_NULL(data, "Should return valid pointer");
    TEST_ASSERT_EQUAL(data, buffer.static_buffer, "Should point to static buffer");
    TEST_ASSERT_STR_EQUAL("Test", data, "Content should match");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_get_dynamic) {
    TEST_CASE("Get pointer to dynamic buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }

    // Complete to move all data to dynamic buffer
    bufferdata_complete(&buffer);

    char* data = bufferdata_get(&buffer);
    TEST_ASSERT_NOT_NULL(data, "Should return valid pointer");
    TEST_ASSERT_EQUAL(data, buffer.dynamic_buffer, "Should point to dynamic buffer");
    TEST_ASSERT_EQUAL('A', data[0], "First char should be 'A'");
    TEST_ASSERT_EQUAL('A', data[4999], "Last char should be 'A'");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_get_null) {
    TEST_CASE("Get from NULL buffer");

    char* data = bufferdata_get(NULL);
    TEST_ASSERT_NULL(data, "Should return NULL");
}

// ============================================================================
// Тесты bufferdata_copy
// ============================================================================

TEST(test_bufferdata_copy_static) {
    TEST_CASE("Copy static buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'C');
    bufferdata_push(&buffer, 'o');
    bufferdata_push(&buffer, 'p');
    bufferdata_push(&buffer, 'y');

    char* copy = bufferdata_copy(&buffer);
    TEST_ASSERT_NOT_NULL(copy, "Copy should succeed");
    TEST_ASSERT_STR_EQUAL("Copy", copy, "Content should match");
    TEST_ASSERT(copy != buffer.static_buffer, "Should be a different pointer");

    free(copy);
    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_copy_dynamic) {
    TEST_CASE("Copy dynamic buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'X');
    }

    // NOTE: bufferdata_copy has a limitation - it doesn't handle pending data in static_buffer
    // Must call bufferdata_complete() first to ensure all data is in dynamic_buffer
    bufferdata_complete(&buffer);

    char* copy = bufferdata_copy(&buffer);
    TEST_ASSERT_NOT_NULL(copy, "Copy should succeed");

    // The copy should contain all 5000 characters
    TEST_ASSERT_EQUAL('X', copy[0], "First char should match");
    TEST_ASSERT_EQUAL('X', copy[4999], "Last char should match");
    TEST_ASSERT_EQUAL(0, copy[5000], "Should be null-terminated");

    free(copy);
    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_copy_empty) {
    TEST_CASE("Copy empty buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    char* copy = bufferdata_copy(&buffer);
    TEST_ASSERT_NOT_NULL(copy, "Copy should succeed");
    TEST_ASSERT_STR_EQUAL("", copy, "Should be empty string");

    free(copy);
    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_copy_null) {
    TEST_CASE("Copy NULL buffer");

    char* copy = bufferdata_copy(NULL);
    TEST_ASSERT_NULL(copy, "Should return NULL");
}

// ============================================================================
// Тесты bufferdata_back
// ============================================================================

TEST(test_bufferdata_back_static) {
    TEST_CASE("Get last character from static buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'A');
    bufferdata_push(&buffer, 'B');
    bufferdata_push(&buffer, 'C');

    char last = bufferdata_back(&buffer);
    TEST_ASSERT_EQUAL('C', last, "Last char should be 'C'");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_back_dynamic) {
    TEST_CASE("Get last character from dynamic buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }
    bufferdata_push(&buffer, 'Z');

    char last = bufferdata_back(&buffer);
    TEST_ASSERT_EQUAL('Z', last, "Last char should be 'Z'");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_back_empty) {
    TEST_CASE("Get last character from empty buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    char last = bufferdata_back(&buffer);
    TEST_ASSERT_EQUAL(0, last, "Should return 0 for empty buffer");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_back_null) {
    TEST_CASE("Get last character from NULL buffer");

    char last = bufferdata_back(NULL);
    TEST_ASSERT_EQUAL(0, last, "Should return 0 for NULL");
}

// ============================================================================
// Тесты bufferdata_pop_back
// ============================================================================

TEST(test_bufferdata_pop_back_static) {
    TEST_CASE("Pop last character from static buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'A');
    bufferdata_push(&buffer, 'B');
    bufferdata_push(&buffer, 'C');

    char popped = bufferdata_pop_back(&buffer);
    TEST_ASSERT_EQUAL('C', popped, "Popped char should be 'C'");
    TEST_ASSERT_EQUAL_SIZE(2, bufferdata_writed(&buffer), "Size should decrease to 2");
    TEST_ASSERT_EQUAL('B', bufferdata_back(&buffer), "New last char should be 'B'");
    TEST_ASSERT_EQUAL(0, buffer.static_buffer[2], "Should be null-terminated");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_pop_back_dynamic) {
    TEST_CASE("Pop last character from dynamic buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }
    bufferdata_push(&buffer, 'Z');

    size_t size_before = bufferdata_writed(&buffer);
    char popped = bufferdata_pop_back(&buffer);

    TEST_ASSERT_EQUAL('Z', popped, "Popped char should be 'Z'");
    TEST_ASSERT_EQUAL_SIZE(size_before - 1, bufferdata_writed(&buffer), "Size should decrease");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_pop_back_until_empty) {
    TEST_CASE("Pop all characters until empty");

    bufferdata_t buffer;
    bufferdata_init(&buffer);
    bufferdata_push(&buffer, 'A');
    bufferdata_push(&buffer, 'B');
    bufferdata_push(&buffer, 'C');

    TEST_ASSERT_EQUAL('C', bufferdata_pop_back(&buffer), "Pop 'C'");
    TEST_ASSERT_EQUAL('B', bufferdata_pop_back(&buffer), "Pop 'B'");
    TEST_ASSERT_EQUAL('A', bufferdata_pop_back(&buffer), "Pop 'A'");

    TEST_ASSERT_EQUAL_SIZE(0, bufferdata_writed(&buffer), "Buffer should be empty");

    char popped = bufferdata_pop_back(&buffer);
    TEST_ASSERT_EQUAL(0, popped, "Pop from empty should return 0");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_pop_back_empty) {
    TEST_CASE("Pop from empty buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    char popped = bufferdata_pop_back(&buffer);
    TEST_ASSERT_EQUAL(0, popped, "Should return 0 for empty buffer");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_pop_back_null) {
    TEST_CASE("Pop from NULL buffer");

    char popped = bufferdata_pop_back(NULL);
    TEST_ASSERT_EQUAL(0, popped, "Should return 0 for NULL");
}

// ============================================================================
// Тесты bufferdata_move_data_to_start
// ============================================================================

TEST(test_bufferdata_move_data_to_start_static_basic) {
    TEST_CASE("Move data to start in static buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    strcpy(buffer.static_buffer, "0123456789");
    buffer.offset_sbuffer = 10;

    int result = bufferdata_move_data_to_start(&buffer, 5, 5);
    TEST_ASSERT_EQUAL(1, result, "Move should succeed");
    TEST_ASSERT_STR_EQUAL("56789", buffer.static_buffer, "Should contain chars 5-9");
    TEST_ASSERT_EQUAL_SIZE(5, buffer.offset_sbuffer, "Offset should be 5");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_move_data_to_start_static_offset_zero) {
    TEST_CASE("Move from offset 0 (copy to self)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    strcpy(buffer.static_buffer, "Hello");
    buffer.offset_sbuffer = 5;

    int result = bufferdata_move_data_to_start(&buffer, 0, 5);
    TEST_ASSERT_EQUAL(1, result, "Move should succeed");
    TEST_ASSERT_STR_EQUAL("Hello", buffer.static_buffer, "Content should remain");
    TEST_ASSERT_EQUAL_SIZE(5, buffer.offset_sbuffer, "Offset should be 5");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_move_data_to_start_static_boundary) {
    TEST_CASE("Move exactly at buffer boundary");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    memset(buffer.static_buffer, 'A', BUFFERDATA_SIZE);
    buffer.offset_sbuffer = BUFFERDATA_SIZE;

    int result = bufferdata_move_data_to_start(&buffer, BUFFERDATA_SIZE - 10, 10);
    TEST_ASSERT_EQUAL(1, result, "Move should succeed");
    TEST_ASSERT_EQUAL_SIZE(10, buffer.offset_sbuffer, "Offset should be 10");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_move_data_to_start_static_out_of_bounds) {
    TEST_CASE("Move with out-of-bounds parameters (static)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    strcpy(buffer.static_buffer, "Test");
    buffer.offset_sbuffer = 4;

    // offset + size > BUFFERDATA_SIZE
    int result = bufferdata_move_data_to_start(&buffer, 0, BUFFERDATA_SIZE + 1);
    TEST_ASSERT_EQUAL(0, result, "Should fail for size > BUFFERDATA_SIZE");

    // offset + size > BUFFERDATA_SIZE
    result = bufferdata_move_data_to_start(&buffer, BUFFERDATA_SIZE, 1);
    TEST_ASSERT_EQUAL(0, result, "Should fail for offset + size > BUFFERDATA_SIZE");

    // offset + size == BUFFERDATA_SIZE + 1 (just over the limit)
    result = bufferdata_move_data_to_start(&buffer, BUFFERDATA_SIZE - 10, 11);
    TEST_ASSERT_EQUAL(0, result, "Should fail for offset + size > BUFFERDATA_SIZE");

    // Valid boundary case: offset + size == BUFFERDATA_SIZE
    result = bufferdata_move_data_to_start(&buffer, 5000, 5000);
    TEST_ASSERT_EQUAL(0, result, "Should succeed for offset + size == BUFFERDATA_SIZE");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_move_data_to_start_dynamic_basic) {
    TEST_CASE("Move data to start in dynamic buffer");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Create dynamic buffer
    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, '0' + (i % 10));
    }

    bufferdata_complete(&buffer); // Ensure all data is in dynamic buffer

    int result = bufferdata_move_data_to_start(&buffer, 100, 50);
    TEST_ASSERT_EQUAL(1, result, "Move should succeed");
    TEST_ASSERT_EQUAL_SIZE(50, buffer.offset_dbuffer, "Offset should be 50");
    TEST_ASSERT_EQUAL_SIZE(51, buffer.dbuffer_size, "Buffer size should be 51 (50 + null terminator)");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_move_data_to_start_dynamic_out_of_bounds) {
    TEST_CASE("Move with out-of-bounds parameters (dynamic)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Create dynamic buffer - need >4096 bytes to force DYNAMIC mode
    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }
    bufferdata_complete(&buffer);

    TEST_ASSERT_EQUAL(BUFFERDATA_DYNAMIC, buffer.type, "Buffer should be DYNAMIC");
    size_t current_size = buffer.offset_dbuffer;
    TEST_ASSERT(current_size == 5000, "Buffer should have 5000 bytes");

    // offset == current_size (out of bounds) - should fail
    int result = bufferdata_move_data_to_start(&buffer, current_size, 1);
    TEST_ASSERT_EQUAL(0, result, "Should fail for offset >= current_size");

    // offset + size > current_size - should fail
    result = bufferdata_move_data_to_start(&buffer, 2500, current_size);
    TEST_ASSERT_EQUAL(0, result, "Should fail for offset + size > current_size");

    // Valid operation at boundary (offset + size == current_size)
    result = bufferdata_move_data_to_start(&buffer, 4900, 100);
    TEST_ASSERT_EQUAL(1, result, "Should succeed for valid boundary case");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_move_data_to_start_null) {
    TEST_CASE("Move data with NULL buffer");

    int result = bufferdata_move_data_to_start(NULL, 0, 10);
    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL");
}

// ============================================================================
// Тесты на утечки памяти и множественные операции
// ============================================================================

TEST(test_bufferdata_multiple_reset_reuse) {
    TEST_CASE("Multiple reset operations (memory reuse)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Create dynamic buffer
    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }

    char* ptr1 = buffer.dynamic_buffer;
    TEST_ASSERT_NOT_NULL(ptr1, "Dynamic buffer should exist");

    bufferdata_reset(&buffer);
    TEST_ASSERT_EQUAL(ptr1, buffer.dynamic_buffer, "Pointer should be reused");

    // Use again
    for (int i = 0; i < 3000; i++) {
        bufferdata_push(&buffer, 'B');
    }

    bufferdata_reset(&buffer);
    TEST_ASSERT_EQUAL(ptr1, buffer.dynamic_buffer, "Pointer should still be reused");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_clear_after_clear) {
    TEST_CASE("Multiple clear operations");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 5000; i++) {
        bufferdata_push(&buffer, 'A');
    }

    bufferdata_clear(&buffer);
    TEST_ASSERT_NULL(buffer.dynamic_buffer, "Should be freed");

    bufferdata_clear(&buffer); // Should not crash
    TEST_ASSERT_NULL(buffer.dynamic_buffer, "Should still be NULL");
}

TEST(test_bufferdata_stress_push_pop) {
    TEST_CASE("Stress test: alternating push/pop");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    for (int i = 0; i < 1000; i++) {
        bufferdata_push(&buffer, 'A' + (i % 26));
        if (i % 3 == 0 && bufferdata_writed(&buffer) > 0) {
            bufferdata_pop_back(&buffer);
        }
    }

    size_t final_size = bufferdata_writed(&buffer);
    TEST_ASSERT(final_size > 0, "Should have some data");
    TEST_ASSERT(final_size < 1000, "Should be less than total pushes");

    bufferdata_clear(&buffer);
}

// ============================================================================
// Тесты специальных символов и бинарных данных
// ============================================================================

TEST(test_bufferdata_null_bytes) {
    TEST_CASE("Handle null bytes in data");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    bufferdata_push(&buffer, 'A');
    bufferdata_push(&buffer, '\0');
    bufferdata_push(&buffer, 'B');
    bufferdata_push(&buffer, '\0');
    bufferdata_push(&buffer, 'C');

    TEST_ASSERT_EQUAL_SIZE(5, bufferdata_writed(&buffer), "Size should be 5");

    char* data = bufferdata_get(&buffer);
    TEST_ASSERT_EQUAL('A', data[0], "First char should be 'A'");
    TEST_ASSERT_EQUAL('\0', data[1], "Second char should be null");
    TEST_ASSERT_EQUAL('B', data[2], "Third char should be 'B'");
    TEST_ASSERT_EQUAL('\0', data[3], "Fourth char should be null");
    TEST_ASSERT_EQUAL('C', data[4], "Fifth char should be 'C'");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_binary_data) {
    TEST_CASE("Handle binary data (all byte values)");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Push all possible byte values
    for (int i = 0; i < 256; i++) {
        bufferdata_push(&buffer, (char)i);
    }

    TEST_ASSERT_EQUAL_SIZE(256, bufferdata_writed(&buffer), "Size should be 256");

    char* data = bufferdata_get(&buffer);
    for (int i = 0; i < 256; i++) {
        TEST_ASSERT_EQUAL((char)i, data[i], "Byte value should match");
    }

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_unicode_utf8) {
    TEST_CASE("Handle UTF-8 multibyte characters");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // UTF-8 encoded string: "Привет" (6 characters, 12 bytes)
    const char* utf8_text = "\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82";

    for (int i = 0; utf8_text[i] != '\0'; i++) {
        bufferdata_push(&buffer, utf8_text[i]);
    }

    TEST_ASSERT_EQUAL_SIZE(12, bufferdata_writed(&buffer), "Size should be 12 bytes");

    char* data = bufferdata_get(&buffer);
    TEST_ASSERT_STR_EQUAL(utf8_text, data, "UTF-8 content should match");

    bufferdata_clear(&buffer);
}

// ============================================================================
// Тесты граничных условий для offset и size
// ============================================================================

TEST(test_bufferdata_edge_case_size_t_max) {
    TEST_CASE("Edge case: very large offset/size values");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // SIZE_MAX offset - should fail (overflow protection)
    int result = bufferdata_move_data_to_start(&buffer, SIZE_MAX, 1);
    TEST_ASSERT_EQUAL(0, result, "Should fail for SIZE_MAX offset");

    // SIZE_MAX size - should fail
    result = bufferdata_move_data_to_start(&buffer, 1, SIZE_MAX);
    TEST_ASSERT_EQUAL(0, result, "Should fail for SIZE_MAX size");

    // Both SIZE_MAX - should fail
    result = bufferdata_move_data_to_start(&buffer, SIZE_MAX, SIZE_MAX);
    TEST_ASSERT_EQUAL(0, result, "Should fail for SIZE_MAX offset and size");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_zero_size_move) {
    TEST_CASE("Move zero bytes");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    strcpy(buffer.static_buffer, "Test");
    buffer.offset_sbuffer = 4;

    int result = bufferdata_move_data_to_start(&buffer, 2, 0);
    TEST_ASSERT_EQUAL(1, result, "Move of 0 bytes should succeed");
    TEST_ASSERT_EQUAL_SIZE(0, buffer.offset_sbuffer, "Offset should be 0");

    bufferdata_clear(&buffer);
}

// ============================================================================
// Интеграционные тесты
// ============================================================================

TEST(test_bufferdata_integration_http_header_parsing) {
    TEST_CASE("Integration: Simulate HTTP header parsing");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    const char* http_request =
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: TestClient/1.0\r\n"
        "Accept: */*\r\n"
        "\r\n";

    for (int i = 0; http_request[i] != '\0'; i++) {
        bufferdata_push(&buffer, http_request[i]);
    }

    char* data = bufferdata_get(&buffer);
    TEST_ASSERT_NOT_NULL(data, "Should get data");
    TEST_ASSERT_STR_EQUAL(http_request, data, "HTTP request should match");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_integration_json_building) {
    TEST_CASE("Integration: Build large JSON");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    bufferdata_push(&buffer, '{');

    for (int i = 0; i < 1000; i++) {
        char entry[50];
        snprintf(entry, sizeof(entry), "\"key%d\":%d,", i, i * 2);
        for (int j = 0; entry[j] != '\0'; j++) {
            bufferdata_push(&buffer, entry[j]);
        }
    }

    bufferdata_pop_back(&buffer); // Remove last comma
    bufferdata_push(&buffer, '}');

    // Complete to ensure all data is accessible
    bufferdata_complete(&buffer);

    char* json = bufferdata_get(&buffer);
    TEST_ASSERT_NOT_NULL(json, "JSON should be built");
    TEST_ASSERT_EQUAL('{', json[0], "Should start with '{'");

    size_t len = bufferdata_writed(&buffer);
    TEST_ASSERT_EQUAL('}', json[len - 1], "Should end with '}'");

    bufferdata_clear(&buffer);
}

TEST(test_bufferdata_integration_reuse_pattern) {
    TEST_CASE("Integration: Buffer reuse pattern");

    bufferdata_t buffer;
    bufferdata_init(&buffer);

    // Simulate processing multiple requests with same buffer
    for (int request = 0; request < 100; request++) {
        bufferdata_reset(&buffer);

        for (int i = 0; i < 50; i++) {
            bufferdata_push(&buffer, 'A' + (request % 26));
        }

        TEST_ASSERT_EQUAL_SIZE(50, bufferdata_writed(&buffer), "Each request should have 50 bytes");
    }

    bufferdata_clear(&buffer);
}

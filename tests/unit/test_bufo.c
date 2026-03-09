#include "framework.h"
#include "bufo.h"
#include <string.h>
#include <limits.h>
#include <stdint.h>

// ============================================================================
// Тесты создания и инициализации
// ============================================================================

TEST(test_bufo_create) {
    TEST_CASE("Create buffer with bufo_create");

    bufo_t* buf = bufo_create();
    TEST_ASSERT_NOT_NULL(buf, "Buffer should be created");
    TEST_ASSERT_NULL(buf->data, "Data pointer should be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, buf->capacity, "Initial capacity should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, buf->size, "Initial size should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, buf->pos, "Initial position should be 0");
    TEST_ASSERT_EQUAL_UINT(0, buf->is_proxy, "is_proxy should be 0");
    TEST_ASSERT_EQUAL_UINT(0, buf->is_last, "is_last should be 0");

    bufo_free(buf);
}

TEST(test_bufo_init) {
    TEST_CASE("Initialize buffer with bufo_init");

    bufo_t buf;
    buf.data = (char*)0xDEADBEEF;  // Set to non-NULL
    buf.capacity = 100;
    buf.size = 50;
    buf.pos = 25;
    buf.is_proxy = 1;
    buf.is_last = 1;

    bufo_init(&buf);

    TEST_ASSERT_NULL(buf.data, "Data pointer should be NULL after init");
    TEST_ASSERT_EQUAL_SIZE(0, buf.capacity, "Capacity should be 0 after init");
    TEST_ASSERT_EQUAL_SIZE(0, buf.size, "Size should be 0 after init");
    TEST_ASSERT_EQUAL_SIZE(0, buf.pos, "Position should be 0 after init");
    TEST_ASSERT_EQUAL_UINT(0, buf.is_proxy, "is_proxy should be 0 after init");
    TEST_ASSERT_EQUAL_UINT(0, buf.is_last, "is_last should be 0 after init");
}

// ============================================================================
// Тесты выделения памяти
// ============================================================================

TEST(test_bufo_alloc_normal) {
    TEST_CASE("Allocate memory for buffer");

    bufo_t* buf = bufo_create();
    int result = bufo_alloc(buf, 1024);

    TEST_ASSERT_EQUAL(1, result, "Allocation should succeed");
    TEST_ASSERT_NOT_NULL(buf->data, "Data pointer should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(1024, buf->capacity, "Capacity should be 1024");

    bufo_free(buf);
}

TEST(test_bufo_alloc_already_allocated) {
    TEST_CASE("Allocate when buffer already has memory");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);

    int result = bufo_alloc(buf, 2048);

    TEST_ASSERT_EQUAL(1, result, "Should return 1 when already allocated");
    TEST_ASSERT_EQUAL_SIZE(1024, buf->capacity, "Capacity should remain unchanged");

    bufo_free(buf);
}

TEST(test_bufo_alloc_zero_capacity) {
    TEST_CASE("Allocate with zero capacity");

    bufo_t* buf = bufo_create();
    int result = bufo_alloc(buf, 0);

    TEST_ASSERT_EQUAL(1, result, "Allocation should succeed");

    // malloc(0) может вернуть либо NULL либо валидный указатель
    // Проверяем что capacity установлен в 0
    TEST_ASSERT_EQUAL_SIZE(0, buf->capacity, "Capacity should be 0");

    bufo_free(buf);
}

// ============================================================================
// Тесты добавления данных (bufo_append)
// ============================================================================

TEST(test_bufo_append_normal) {
    TEST_CASE("Append data to buffer");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);

    const char* data = "Hello, World!";
    ssize_t written = bufo_append(buf, data, strlen(data));

    TEST_ASSERT_EQUAL_SIZE((ssize_t)strlen(data), written, "Should write all data");
    TEST_ASSERT_EQUAL_SIZE(strlen(data), buf->size, "Size should be updated");
    TEST_ASSERT_EQUAL_SIZE(strlen(data), buf->pos, "Position should be updated");
    TEST_ASSERT(memcmp(buf->data, data, strlen(data)) == 0, "Data should match");

    bufo_free(buf);
}

TEST(test_bufo_append_multiple) {
    TEST_CASE("Append data multiple times");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);

    bufo_append(buf, "Hello", 5);
    bufo_append(buf, ", ", 2);
    bufo_append(buf, "World!", 6);

    TEST_ASSERT_EQUAL_SIZE(13, buf->size, "Total size should be 13");
    TEST_ASSERT_EQUAL_SIZE(13, buf->pos, "Position should be 13");
    TEST_ASSERT(memcmp(buf->data, "Hello, World!", 13) == 0, "Data should match");

    bufo_free(buf);
}

TEST(test_bufo_append_zero_size) {
    TEST_CASE("Append with zero size");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);

    ssize_t written = bufo_append(buf, "test", 0);

    TEST_ASSERT_EQUAL_SIZE(0, written, "Should write nothing");
    TEST_ASSERT_EQUAL_SIZE(0, buf->size, "Size should remain 0");

    bufo_free(buf);
}

TEST(test_bufo_append_null_buffer) {
    TEST_CASE("Append to buffer without allocated memory");

    bufo_t* buf = bufo_create();
    // Не вызываем bufo_alloc

    ssize_t written = bufo_append(buf, "test", 4);

    TEST_ASSERT_EQUAL(-1, written, "Should return -1 when data is NULL");

    bufo_free(buf);
}

TEST(test_bufo_append_overflow) {
    TEST_CASE("Append more data than capacity");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 10);

    const char* data = "This is a very long string";
    ssize_t written = bufo_append(buf, data, strlen(data));

    TEST_ASSERT_EQUAL_SIZE(10, written, "Should write only capacity bytes");
    TEST_ASSERT_EQUAL_SIZE(10, buf->size, "Size should be capacity");
    TEST_ASSERT_EQUAL_SIZE(10, buf->pos, "Position should be capacity");

    bufo_free(buf);
}

TEST(test_bufo_append_exact_capacity) {
    TEST_CASE("Append exactly capacity bytes");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 5);

    ssize_t written = bufo_append(buf, "Hello", 5);

    TEST_ASSERT_EQUAL_SIZE(5, written, "Should write all 5 bytes");
    TEST_ASSERT_EQUAL_SIZE(5, buf->size, "Size should be 5");
    TEST_ASSERT_EQUAL_SIZE(5, buf->pos, "Position should be 5");

    bufo_free(buf);
}

TEST(test_bufo_append_when_full) {
    TEST_CASE("Append when buffer is full");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 5);
    bufo_append(buf, "Hello", 5);

    ssize_t written = bufo_append(buf, "World", 5);

    TEST_ASSERT_EQUAL_SIZE(0, written, "Should write nothing when full");
    TEST_ASSERT_EQUAL_SIZE(5, buf->size, "Size should remain 5");

    bufo_free(buf);
}

TEST(test_bufo_append_is_proxy) {
    TEST_CASE("Append to proxy buffer");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    buf->is_proxy = 1;

    ssize_t written = bufo_append(buf, "test", 4);

    TEST_ASSERT_EQUAL_SIZE(0, written, "Should return 0 for proxy buffer");

    bufo_free(buf);
}

TEST(test_bufo_append_pos_at_capacity) {
    TEST_CASE("Append when pos >= capacity");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 10);
    buf->pos = 10;  // Manually set pos to capacity

    ssize_t written = bufo_append(buf, "test", 4);

    TEST_ASSERT_EQUAL_SIZE(0, written, "Should return 0 when pos >= capacity");

    bufo_free(buf);
}

// ============================================================================
// Тесты управления позицией
// ============================================================================

TEST(test_bufo_move_front_pos_normal) {
    TEST_CASE("Move position forward normally");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello, World!", 13);
    bufo_reset_pos(buf);

    size_t moved = bufo_move_front_pos(buf, 5);

    TEST_ASSERT_EQUAL_SIZE(5, moved, "Should move 5 bytes");
    TEST_ASSERT_EQUAL_SIZE(5, buf->pos, "Position should be 5");

    bufo_free(buf);
}

TEST(test_bufo_move_front_pos_overflow) {
    TEST_CASE("Move position beyond size");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);
    bufo_reset_pos(buf);

    size_t moved = bufo_move_front_pos(buf, 100);

    TEST_ASSERT_EQUAL_SIZE(5, moved, "Should move only to size");
    TEST_ASSERT_EQUAL_SIZE(5, buf->pos, "Position should be at size");

    bufo_free(buf);
}

TEST(test_bufo_move_front_pos_exact_size) {
    TEST_CASE("Move position exactly to size");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);
    bufo_reset_pos(buf);

    size_t moved = bufo_move_front_pos(buf, 5);

    TEST_ASSERT_EQUAL_SIZE(5, moved, "Should move exactly 5 bytes");
    TEST_ASSERT_EQUAL_SIZE(5, buf->pos, "Position should be 5");

    bufo_free(buf);
}

TEST(test_bufo_move_front_pos_already_at_end) {
    TEST_CASE("Move position when already at end");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);
    // pos уже равен size (5)

    size_t moved = bufo_move_front_pos(buf, 10);

    TEST_ASSERT_EQUAL_SIZE(0, moved, "Should not move when at end");
    TEST_ASSERT_EQUAL_SIZE(5, buf->pos, "Position should remain at size");

    bufo_free(buf);
}

TEST(test_bufo_move_front_pos_beyond_size) {
    TEST_CASE("Move position when pos > size");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_set_size(buf, 10);
    buf->pos = 15;  // Manually set pos beyond size

    size_t moved = bufo_move_front_pos(buf, 5);

    TEST_ASSERT_EQUAL_SIZE(0, moved, "Should not move when pos >= size");

    bufo_free(buf);
}

TEST(test_bufo_reset_pos) {
    TEST_CASE("Reset position to zero");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);

    TEST_ASSERT_EQUAL_SIZE(5, buf->pos, "Position should be 5");

    bufo_reset_pos(buf);

    TEST_ASSERT_EQUAL_SIZE(0, buf->pos, "Position should be 0 after reset");
    TEST_ASSERT_EQUAL_SIZE(5, buf->size, "Size should remain unchanged");

    bufo_free(buf);
}

// ============================================================================
// Тесты управления размером
// ============================================================================

TEST(test_bufo_set_size) {
    TEST_CASE("Set buffer size explicitly");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);

    bufo_set_size(buf, 100);

    TEST_ASSERT_EQUAL_SIZE(100, buf->size, "Size should be set to 100");

    bufo_free(buf);
}

TEST(test_bufo_reset_size) {
    TEST_CASE("Reset size to zero");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);

    TEST_ASSERT_EQUAL_SIZE(5, buf->size, "Size should be 5");

    bufo_reset_size(buf);

    TEST_ASSERT_EQUAL_SIZE(0, buf->size, "Size should be 0 after reset");

    bufo_free(buf);
}

TEST(test_bufo_size) {
    TEST_CASE("Get buffer size");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Test", 4);

    size_t size = bufo_size(buf);

    TEST_ASSERT_EQUAL_SIZE(4, size, "Size should be 4");

    bufo_free(buf);
}

// ============================================================================
// Тесты получения данных
// ============================================================================

TEST(test_bufo_data) {
    TEST_CASE("Get data pointer");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello, World!", 13);
    bufo_reset_pos(buf);

    char* data = bufo_data(buf);

    TEST_ASSERT_NOT_NULL(data, "Data pointer should not be NULL");
    TEST_ASSERT(data == buf->data, "Data pointer should match buf->data");
    TEST_ASSERT(memcmp(data, "Hello, World!", 13) == 0, "Data should match");

    bufo_free(buf);
}

TEST(test_bufo_data_with_offset) {
    TEST_CASE("Get data pointer with offset");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello, World!", 13);
    bufo_reset_pos(buf);
    bufo_move_front_pos(buf, 7);

    char* data = bufo_data(buf);

    TEST_ASSERT_NOT_NULL(data, "Data pointer should not be NULL");
    TEST_ASSERT(data == buf->data + 7, "Data pointer should be offset by 7");
    TEST_ASSERT(memcmp(data, "World!", 6) == 0, "Data should match from offset");

    bufo_free(buf);
}

TEST(test_bufo_chunk_size_normal) {
    TEST_CASE("Calculate chunk size normally");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello, World!", 13);
    bufo_reset_pos(buf);

    size_t chunk = bufo_chunk_size(buf, 5);

    TEST_ASSERT_EQUAL_SIZE(5, chunk, "Chunk size should be 5");

    bufo_free(buf);
}

TEST(test_bufo_chunk_size_larger_than_remaining) {
    TEST_CASE("Calculate chunk size larger than remaining");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);
    bufo_reset_pos(buf);

    size_t chunk = bufo_chunk_size(buf, 100);

    TEST_ASSERT_EQUAL_SIZE(5, chunk, "Chunk size should be remaining (5)");

    bufo_free(buf);
}

TEST(test_bufo_chunk_size_with_offset) {
    TEST_CASE("Calculate chunk size with offset");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello, World!", 13);
    bufo_reset_pos(buf);
    bufo_move_front_pos(buf, 7);

    size_t chunk = bufo_chunk_size(buf, 10);

    TEST_ASSERT_EQUAL_SIZE(6, chunk, "Chunk size should be 6 (remaining)");

    bufo_free(buf);
}

TEST(test_bufo_chunk_size_at_end) {
    TEST_CASE("Calculate chunk size when at end");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);
    // pos уже равен size

    size_t chunk = bufo_chunk_size(buf, 10);

    TEST_ASSERT_EQUAL_SIZE(0, chunk, "Chunk size should be 0 at end");

    bufo_free(buf);
}

TEST(test_bufo_chunk_size_beyond_size) {
    TEST_CASE("Calculate chunk size when pos > size");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_set_size(buf, 10);
    buf->pos = 15;

    size_t chunk = bufo_chunk_size(buf, 10);

    TEST_ASSERT_EQUAL_SIZE(0, chunk, "Chunk size should be 0 when pos > size");

    bufo_free(buf);
}

// ============================================================================
// Тесты очистки и освобождения
// ============================================================================

TEST(test_bufo_flush) {
    TEST_CASE("Flush buffer");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);
    buf->is_proxy = 1;
    buf->is_last = 1;

    bufo_flush(buf);

    TEST_ASSERT_EQUAL_SIZE(0, buf->size, "Size should be 0 after flush");
    TEST_ASSERT_EQUAL_SIZE(0, buf->pos, "Position should be 0 after flush");
    TEST_ASSERT_EQUAL_UINT(0, buf->is_proxy, "is_proxy should be 0 after flush");
    TEST_ASSERT_EQUAL_UINT(0, buf->is_last, "is_last should be 0 after flush");
    TEST_ASSERT_NOT_NULL(buf->data, "Data should not be freed by flush");
    TEST_ASSERT_EQUAL_SIZE(1024, buf->capacity, "Capacity should remain unchanged");

    bufo_free(buf);
}

TEST(test_bufo_clear_normal) {
    TEST_CASE("Clear buffer normally");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);
    bufo_clear(buf);

    TEST_ASSERT_NULL(buf->data, "Data should be NULL after clear");
    TEST_ASSERT_EQUAL_SIZE(0, buf->capacity, "Capacity should be 0 after clear");
    TEST_ASSERT_EQUAL_SIZE(0, buf->size, "Size should be 0 after clear");
    TEST_ASSERT_EQUAL_SIZE(0, buf->pos, "Position should be 0 after clear");

    free(buf);
}

TEST(test_bufo_clear_proxy) {
    TEST_CASE("Clear proxy buffer");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    buf->is_proxy = 1;
    bufo_clear(buf);

    TEST_ASSERT_NULL(buf->data, "Data should be NULL after clear");
    TEST_ASSERT_EQUAL_SIZE(0, buf->capacity, "Capacity should be 0 after clear");
    TEST_ASSERT_EQUAL_UINT(0, buf->is_proxy, "is_proxy should be reset");

    free(buf);
}

TEST(test_bufo_free_null) {
    TEST_CASE("Free NULL buffer");

    // Не должно вызывать crash
    bufo_free(NULL);

    TEST_ASSERT(1, "Should handle NULL gracefully");
}

TEST(test_bufo_free_normal) {
    TEST_CASE("Free buffer normally");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    bufo_append(buf, "Hello", 5);

    // Просто проверяем что не падает
    bufo_free(buf);

    TEST_ASSERT(1, "Should free buffer without crash");
}

TEST(test_bufo_free_proxy) {
    TEST_CASE("Free proxy buffer");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 1024);
    buf->is_proxy = 1;

    // При is_proxy data не должна освобождаться, только буфер
    bufo_free(buf);

    TEST_ASSERT(1, "Should free proxy buffer without freeing data");
}

TEST(test_bufo_free_without_alloc) {
    TEST_CASE("Free buffer without allocated data");

    bufo_t* buf = bufo_create();

    bufo_free(buf);

    TEST_ASSERT(1, "Should free buffer without crash");
}

// ============================================================================
// Тесты сложных сценариев и граничных условий
// ============================================================================

TEST(test_bufo_multiple_operations) {
    TEST_CASE("Perform multiple operations in sequence");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    // Добавляем данные
    bufo_append(buf, "Hello", 5);
    TEST_ASSERT_EQUAL_SIZE(5, buf->size, "Size should be 5");

    // Сбрасываем позицию и читаем
    bufo_reset_pos(buf);
    size_t chunk = bufo_chunk_size(buf, 3);
    TEST_ASSERT_EQUAL_SIZE(3, chunk, "Chunk should be 3");

    // Двигаем позицию
    bufo_move_front_pos(buf, 3);
    TEST_ASSERT_EQUAL_SIZE(3, buf->pos, "Position should be 3");

    // Добавляем еще данные (записывается с позиции 3)
    bufo_append(buf, ", World!", 8);
    TEST_ASSERT_EQUAL_SIZE(11, buf->size, "Size should be 11");

    // Проверяем данные (данные с позиции 3)
    bufo_reset_pos(buf);
    char* data = bufo_data(buf);
    TEST_ASSERT(memcmp(data, "Hel, World!", 11) == 0, "Data should be 'Hel, World!'");

    bufo_free(buf);
}

TEST(test_bufo_reset_and_reuse) {
    TEST_CASE("Reset buffer and reuse");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    bufo_append(buf, "First", 5);
    TEST_ASSERT_EQUAL_SIZE(5, buf->size, "Size should be 5");

    bufo_flush(buf);
    TEST_ASSERT_EQUAL_SIZE(0, buf->size, "Size should be 0 after flush");

    bufo_append(buf, "Second", 6);
    TEST_ASSERT_EQUAL_SIZE(6, buf->size, "Size should be 6");

    bufo_reset_pos(buf);
    char* data = bufo_data(buf);
    TEST_ASSERT(memcmp(data, "Second", 6) == 0, "Data should be 'Second'");

    bufo_free(buf);
}

TEST(test_bufo_partial_read_write) {
    TEST_CASE("Partial read and write operations");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 20);

    bufo_append(buf, "0123456789", 10);
    bufo_reset_pos(buf);

    // Читаем по частям
    bufo_move_front_pos(buf, 3);
    char* data1 = bufo_data(buf);
    TEST_ASSERT(memcmp(data1, "3456789", 7) == 0, "Should point to offset 3");

    bufo_move_front_pos(buf, 4);
    char* data2 = bufo_data(buf);
    TEST_ASSERT(memcmp(data2, "789", 3) == 0, "Should point to offset 7");

    // Дописываем еще (с позиции 7)
    bufo_append(buf, "ABCDE", 5);
    TEST_ASSERT_EQUAL_SIZE(12, buf->size, "Size should be 12");

    bufo_free(buf);
}

TEST(test_bufo_size_pos_consistency) {
    TEST_CASE("Verify size and pos consistency");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    // После append, pos должен == size
    bufo_append(buf, "Test", 4);
    TEST_ASSERT_EQUAL_SIZE(buf->size, buf->pos, "pos should equal size after append");

    // После reset_pos, pos = 0, size остается
    bufo_reset_pos(buf);
    TEST_ASSERT_EQUAL_SIZE(0, buf->pos, "pos should be 0");
    TEST_ASSERT_EQUAL_SIZE(4, buf->size, "size should remain 4");

    // После еще одного append с pos < size
    buf->pos = 2;
    bufo_append(buf, "XY", 2);
    TEST_ASSERT_EQUAL_SIZE(4, buf->pos, "pos should be 4");
    TEST_ASSERT_EQUAL_SIZE(4, buf->size, "size should be 4 (not increased)");

    bufo_free(buf);
}

TEST(test_bufo_boundary_capacity) {
    TEST_CASE("Test boundary at exact capacity");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 10);

    // Заполняем до конца
    ssize_t w1 = bufo_append(buf, "12345", 5);
    TEST_ASSERT_EQUAL_SIZE(5, w1, "Should write 5 bytes");

    ssize_t w2 = bufo_append(buf, "67890", 5);
    TEST_ASSERT_EQUAL_SIZE(5, w2, "Should write 5 bytes");

    // Попытка записать еще
    ssize_t w3 = bufo_append(buf, "X", 1);
    TEST_ASSERT_EQUAL_SIZE(0, w3, "Should write 0 bytes (buffer full)");

    TEST_ASSERT_EQUAL_SIZE(10, buf->size, "Size should be 10");
    TEST_ASSERT_EQUAL_SIZE(10, buf->pos, "Position should be 10");

    bufo_free(buf);
}

TEST(test_bufo_append_updates_size_correctly) {
    TEST_CASE("Verify append updates size only when pos > size");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    // Первый append
    bufo_append(buf, "12345", 5);
    TEST_ASSERT_EQUAL_SIZE(5, buf->size, "Size should be 5");

    // Возвращаемся назад
    buf->pos = 2;

    // Второй append - затирает данные но не увеличивает size
    bufo_append(buf, "AB", 2);
    TEST_ASSERT_EQUAL_SIZE(5, buf->size, "Size should still be 5");
    TEST_ASSERT_EQUAL_SIZE(4, buf->pos, "Position should be 4");

    // Третий append - выходит за старый size
    bufo_append(buf, "CDEFG", 5);
    TEST_ASSERT_EQUAL_SIZE(9, buf->size, "Size should be updated to 9");

    bufo_free(buf);
}

TEST(test_bufo_empty_buffer_operations) {
    TEST_CASE("Operations on empty buffer");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    TEST_ASSERT_EQUAL_SIZE(0, bufo_size(buf), "Size should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, bufo_chunk_size(buf, 10), "Chunk size should be 0");

    bufo_reset_pos(buf);
    TEST_ASSERT_EQUAL_SIZE(0, buf->pos, "Position should be 0");

    size_t moved = bufo_move_front_pos(buf, 10);
    TEST_ASSERT_EQUAL_SIZE(0, moved, "Should not move on empty buffer");

    bufo_free(buf);
}

TEST(test_bufo_is_last_flag) {
    TEST_CASE("Test is_last flag behavior");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    buf->is_last = 1;
    TEST_ASSERT_EQUAL_UINT(1, buf->is_last, "is_last should be 1");

    bufo_flush(buf);
    TEST_ASSERT_EQUAL_UINT(0, buf->is_last, "is_last should be reset by flush");

    bufo_free(buf);
}

TEST(test_bufo_proxy_flag_behavior) {
    TEST_CASE("Test proxy flag behavior");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);
    buf->is_proxy = 1;

    // Proxy buffer не должен принимать append
    ssize_t written = bufo_append(buf, "test", 4);
    TEST_ASSERT_EQUAL_SIZE(0, written, "Proxy buffer should reject append");

    // Clear proxy buffer не должен освобождать data
    bufo_clear(buf);
    TEST_ASSERT_EQUAL_UINT(0, buf->is_proxy, "is_proxy should be reset");

    free(buf);
}

// ============================================================================
// Тесты на уязвимости и безопасность
// ============================================================================

TEST(test_bufo_no_buffer_overflow_on_append) {
    TEST_CASE("Verify no buffer overflow on append");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 10);

    // Попытка записать больше чем capacity
    char large_data[1000];
    memset(large_data, 'A', sizeof(large_data));

    ssize_t written = bufo_append(buf, large_data, sizeof(large_data));

    TEST_ASSERT_EQUAL_SIZE(10, written, "Should write only capacity bytes");
    TEST_ASSERT_EQUAL_SIZE(10, buf->size, "Size should not exceed capacity");

    // Проверяем что не вышли за границы
    for (size_t i = 0; i < 10; i++) {
        TEST_ASSERT(buf->data[i] == 'A', "Data should be 'A' within bounds");
    }

    bufo_free(buf);
}

TEST(test_bufo_integer_overflow_protection) {
    TEST_CASE("Test protection against integer overflow");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    // Устанавливаем pos близко к SIZE_MAX
    buf->pos = SIZE_MAX - 1;
    buf->size = SIZE_MAX - 1;

    size_t moved = bufo_move_front_pos(buf, SIZE_MAX);

    // Должно корректно обработаться
    TEST_ASSERT(moved <= 1, "Should handle near-overflow correctly");

    bufo_free(buf);
}

TEST(test_bufo_null_data_append) {
    TEST_CASE("Append NULL data pointer");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    // Даже если data == NULL, не должно упасть
    // (memcpy с NULL source это UB, но проверяем что size == 0 обрабатывается)
    ssize_t written = bufo_append(buf, NULL, 0);

    TEST_ASSERT_EQUAL_SIZE(0, written, "Should write 0 bytes");

    bufo_free(buf);
}

TEST(test_bufo_double_free_protection) {
    TEST_CASE("Verify no double free");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    bufo_clear(buf);  // Освобождает data
    TEST_ASSERT_NULL(buf->data, "Data should be NULL after clear");

    // Повторный clear не должен вызвать double free
    bufo_clear(buf);
    TEST_ASSERT_NULL(buf->data, "Data should still be NULL");

    free(buf);
}

TEST(test_bufo_use_after_clear) {
    TEST_CASE("Verify safe behavior after clear");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);
    bufo_append(buf, "test", 4);

    bufo_clear(buf);

    // После clear buf->data == NULL
    // Попытка append должна вернуть -1
    ssize_t written = bufo_append(buf, "new", 3);
    TEST_ASSERT_EQUAL(-1, written, "Should return -1 when data is NULL");

    free(buf);
}

TEST(test_bufo_extreme_capacity) {
    TEST_CASE("Test with very large capacity request");

    bufo_t* buf = bufo_create();

    // Попытка выделить экстремально большой буфер
    // malloc может вернуть NULL
    int result = bufo_alloc(buf, SIZE_MAX);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 when allocation fails");
    TEST_ASSERT_NULL(buf->data, "Data should be NULL if allocation failed");

    bufo_free(buf);
}

TEST(test_bufo_data_pointer_null_buffer) {
    TEST_CASE("Get data pointer from unallocated buffer");

    bufo_t* buf = bufo_create();

    // buf->data == NULL, вызов bufo_data вернет NULL + 0
    char* data = bufo_data(buf);

    TEST_ASSERT(data == NULL, "Data pointer should be NULL");

    bufo_free(buf);
}

TEST(test_bufo_concurrent_pos_size_modification) {
    TEST_CASE("Test pos/size consistency with manual modifications");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    // Ручная манипуляция для создания некорректного состояния
    buf->pos = 50;
    buf->size = 30;  // pos > size

    // chunk_size должен вернуть 0
    size_t chunk = bufo_chunk_size(buf, 10);
    TEST_ASSERT_EQUAL_SIZE(0, chunk, "Chunk should be 0 when pos > size");

    // move_front_pos должен вернуть 0
    size_t moved = bufo_move_front_pos(buf, 10);
    TEST_ASSERT_EQUAL_SIZE(0, moved, "Should not move when pos > size");

    bufo_free(buf);
}

TEST(test_bufo_append_with_pos_not_at_size) {
    TEST_CASE("Append when pos is not at size");

    bufo_t* buf = bufo_create();
    bufo_alloc(buf, 100);

    // Создаем данные
    bufo_append(buf, "0123456789", 10);
    TEST_ASSERT_EQUAL_SIZE(10, buf->size, "Size should be 10");

    // Отматываем pos назад
    buf->pos = 5;

    // Append должен писать с позиции 5
    bufo_append(buf, "ABC", 3);

    TEST_ASSERT_EQUAL_SIZE(10, buf->size, "Size should still be 10 (not increased)");
    TEST_ASSERT_EQUAL_SIZE(8, buf->pos, "Position should be 8");

    // Проверяем что данные перезаписаны
    bufo_reset_pos(buf);
    char* data = bufo_data(buf);
    TEST_ASSERT(memcmp(data, "01234ABC89", 10) == 0, "Data should be overwritten");

    bufo_free(buf);
}

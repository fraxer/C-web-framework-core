#include "framework.h"
#include "cqueue.h"
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>

// ============================================================================
// Helper functions and structures
// ============================================================================

static int free_callback_count = 0;

static void test_free_callback(void* data) {
    free_callback_count++;
    free(data);
}

static void reset_free_callback_count(void) {
    free_callback_count = 0;
}

// ============================================================================
// Тесты создания и инициализации
// ============================================================================

TEST(test_cqueue_create) {
    TEST_CASE("Create queue with cqueue_create");

    cqueue_t* queue = cqueue_create();

    TEST_ASSERT_NOT_NULL(queue, "Queue should be created");
    TEST_ASSERT_NULL(queue->item, "First item should be NULL");
    TEST_ASSERT_NULL(queue->last_item, "Last item should be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Initial size should be 0");
    TEST_ASSERT_EQUAL(0, atomic_load(&queue->locked), "Queue should not be locked");

    cqueue_free(queue);
}

TEST(test_cqueue_init) {
    TEST_CASE("Initialize queue with cqueue_init");

    cqueue_t queue;
    // Set to non-NULL values
    queue.item = (cqueue_item_t*)0xDEADBEEF;
    queue.last_item = (cqueue_item_t*)0xDEADBEEF;
    queue.size = 100;
    atomic_store(&queue.locked, 5);

    cqueue_init(&queue);

    TEST_ASSERT_NULL(queue.item, "First item should be NULL after init");
    TEST_ASSERT_NULL(queue.last_item, "Last item should be NULL after init");
    TEST_ASSERT_EQUAL_SIZE(0, queue.size, "Size should be 0 after init");
    TEST_ASSERT_EQUAL(0, atomic_load(&queue.locked), "Queue should not be locked after init");
}

TEST(test_cqueue_init_null) {
    TEST_CASE("Initialize NULL queue");

    // Should not crash
    cqueue_init(NULL);

    TEST_ASSERT(1, "Should handle NULL gracefully");
}

// ============================================================================
// Тесты добавления элементов (append)
// ============================================================================

TEST(test_cqueue_append_normal) {
    TEST_CASE("Append data to queue");

    cqueue_t* queue = cqueue_create();
    char* data = strdup("test");

    int result = cqueue_append(queue, data);

    TEST_ASSERT_EQUAL(1, result, "Append should succeed");
    TEST_ASSERT_NOT_NULL(queue->item, "First item should not be NULL");
    TEST_ASSERT_NOT_NULL(queue->last_item, "Last item should not be NULL");
    TEST_ASSERT(queue->item == queue->last_item, "First and last should be same for single item");
    TEST_ASSERT_EQUAL_SIZE(1, queue->size, "Size should be 1");
    TEST_ASSERT(queue->item->data == data, "Item data should match");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_append_multiple) {
    TEST_CASE("Append multiple items");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");
    char* data3 = strdup("third");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);
    cqueue_append(queue, data3);

    TEST_ASSERT_EQUAL_SIZE(3, queue->size, "Size should be 3");
    TEST_ASSERT(queue->item->data == data1, "First item should be data1");
    TEST_ASSERT(queue->last_item->data == data3, "Last item should be data3");

    // Check chain
    TEST_ASSERT(queue->item->next->data == data2, "Second item should be data2");
    TEST_ASSERT(queue->item->next->next->data == data3, "Third item should be data3");
    TEST_ASSERT_NULL(queue->last_item->next, "Last item next should be NULL");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_append_null_queue) {
    TEST_CASE("Append to NULL queue");

    int result = cqueue_append(NULL, (void*)0x123);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL queue");
}

TEST(test_cqueue_append_null_data) {
    TEST_CASE("Append NULL data");

    cqueue_t* queue = cqueue_create();
    int result = cqueue_append(queue, NULL);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL data");
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should remain 0");
    TEST_ASSERT_NULL(queue->item, "First item should remain NULL");

    cqueue_free(queue);
}

// ============================================================================
// Тесты добавления в начало (prepend)
// ============================================================================

TEST(test_cqueue_prepend_normal) {
    TEST_CASE("Prepend data to queue");

    cqueue_t* queue = cqueue_create();
    char* data = strdup("test");

    int result = cqueue_prepend(queue, data);

    TEST_ASSERT_EQUAL(1, result, "Prepend should succeed");
    TEST_ASSERT_NOT_NULL(queue->item, "First item should not be NULL");
    TEST_ASSERT_NOT_NULL(queue->last_item, "Last item should not be NULL");
    TEST_ASSERT(queue->item == queue->last_item, "First and last should be same for single item");
    TEST_ASSERT_EQUAL_SIZE(1, queue->size, "Size should be 1");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_prepend_multiple) {
    TEST_CASE("Prepend multiple items");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");
    char* data3 = strdup("third");

    cqueue_prepend(queue, data1);
    cqueue_prepend(queue, data2);
    cqueue_prepend(queue, data3);

    TEST_ASSERT_EQUAL_SIZE(3, queue->size, "Size should be 3");
    TEST_ASSERT(queue->item->data == data3, "First item should be data3 (last prepended)");
    TEST_ASSERT(queue->last_item->data == data1, "Last item should be data1 (first prepended)");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_prepend_null_queue) {
    TEST_CASE("Prepend to NULL queue");

    int result = cqueue_prepend(NULL, (void*)0x123);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL queue");
}

TEST(test_cqueue_prepend_null_data) {
    TEST_CASE("Prepend NULL data");

    cqueue_t* queue = cqueue_create();
    int result = cqueue_prepend(queue, NULL);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL data");
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should remain 0");

    cqueue_free(queue);
}

TEST(test_cqueue_mixed_append_prepend) {
    TEST_CASE("Mix append and prepend operations");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("1");
    char* data2 = strdup("2");
    char* data3 = strdup("3");
    char* data4 = strdup("4");

    cqueue_append(queue, data1);   // [1]
    cqueue_prepend(queue, data2);  // [2, 1]
    cqueue_append(queue, data3);   // [2, 1, 3]
    cqueue_prepend(queue, data4);  // [4, 2, 1, 3]

    TEST_ASSERT_EQUAL_SIZE(4, queue->size, "Size should be 4");
    TEST_ASSERT(queue->item->data == data4, "First should be 4");
    TEST_ASSERT(queue->last_item->data == data3, "Last should be 3");

    cqueue_freecb(queue, free);
}

// ============================================================================
// Тесты удаления элементов (pop)
// ============================================================================

TEST(test_cqueue_pop_single) {
    TEST_CASE("Pop single item from queue");

    cqueue_t* queue = cqueue_create();
    char* data = strdup("test");
    cqueue_append(queue, data);

    void* popped = cqueue_pop(queue);

    TEST_ASSERT(popped == data, "Popped data should match");
    TEST_ASSERT_NULL(queue->item, "First item should be NULL after pop");
    TEST_ASSERT_NULL(queue->last_item, "Last item should be NULL after pop");
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should be 0 after pop");

    free(data);
    cqueue_free(queue);
}

TEST(test_cqueue_pop_multiple) {
    TEST_CASE("Pop multiple items");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");
    char* data3 = strdup("third");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);
    cqueue_append(queue, data3);

    void* pop1 = cqueue_pop(queue);
    TEST_ASSERT(pop1 == data1, "First pop should return data1");
    TEST_ASSERT_EQUAL_SIZE(2, queue->size, "Size should be 2");

    void* pop2 = cqueue_pop(queue);
    TEST_ASSERT(pop2 == data2, "Second pop should return data2");
    TEST_ASSERT_EQUAL_SIZE(1, queue->size, "Size should be 1");

    void* pop3 = cqueue_pop(queue);
    TEST_ASSERT(pop3 == data3, "Third pop should return data3");
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should be 0");
    TEST_ASSERT_NULL(queue->item, "Queue should be empty");
    TEST_ASSERT_NULL(queue->last_item, "Last item should be NULL");

    free(data1);
    free(data2);
    free(data3);
    cqueue_free(queue);
}

TEST(test_cqueue_pop_empty) {
    TEST_CASE("Pop from empty queue");

    cqueue_t* queue = cqueue_create();
    void* popped = cqueue_pop(queue);

    TEST_ASSERT_NULL(popped, "Popping from empty queue should return NULL");
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should remain 0");

    cqueue_free(queue);
}

TEST(test_cqueue_pop_null_queue) {
    TEST_CASE("Pop from NULL queue");

    void* popped = cqueue_pop(NULL);

    TEST_ASSERT_NULL(popped, "Popping from NULL queue should return NULL");
}

TEST(test_cqueue_pop_all_then_append) {
    TEST_CASE("Pop all items then append new ones");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");

    cqueue_append(queue, data1);
    cqueue_pop(queue);
    free(data1);

    // Queue should be properly reset
    cqueue_append(queue, data2);
    TEST_ASSERT_EQUAL_SIZE(1, queue->size, "Size should be 1");
    TEST_ASSERT(queue->item->data == data2, "Item should be data2");
    TEST_ASSERT(queue->last_item->data == data2, "Last item should be data2");

    cqueue_freecb(queue, free);
}

// ============================================================================
// Тесты доступа к элементам
// ============================================================================

TEST(test_cqueue_first) {
    TEST_CASE("Get first item from queue");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);

    cqueue_item_t* first = cqueue_first(queue);
    TEST_ASSERT_NOT_NULL(first, "First item should not be NULL");
    TEST_ASSERT(first->data == data1, "First item data should match");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_first_empty) {
    TEST_CASE("Get first item from empty queue");

    cqueue_t* queue = cqueue_create();
    cqueue_item_t* first = cqueue_first(queue);

    TEST_ASSERT_NULL(first, "First item should be NULL for empty queue");

    cqueue_free(queue);
}

TEST(test_cqueue_first_null_queue) {
    TEST_CASE("Get first item from NULL queue");

    cqueue_item_t* first = cqueue_first(NULL);

    TEST_ASSERT_NULL(first, "Should return NULL for NULL queue");
}

TEST(test_cqueue_last) {
    TEST_CASE("Get last item from queue");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);

    cqueue_item_t* last = cqueue_last(queue);
    TEST_ASSERT_NOT_NULL(last, "Last item should not be NULL");
    TEST_ASSERT(last->data == data2, "Last item data should match");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_last_empty) {
    TEST_CASE("Get last item from empty queue");

    cqueue_t* queue = cqueue_create();
    cqueue_item_t* last = cqueue_last(queue);

    TEST_ASSERT_NULL(last, "Last item should be NULL for empty queue");

    cqueue_free(queue);
}

TEST(test_cqueue_last_null_queue) {
    TEST_CASE("Get last item from NULL queue");

    cqueue_item_t* last = cqueue_last(NULL);

    TEST_ASSERT_NULL(last, "Should return NULL for NULL queue");
}

TEST(test_cqueue_empty) {
    TEST_CASE("Check if queue is empty");

    cqueue_t* queue = cqueue_create();

    TEST_ASSERT_EQUAL(1, cqueue_empty(queue), "New queue should be empty");

    char* data = strdup("test");
    cqueue_append(queue, data);
    TEST_ASSERT_EQUAL(0, cqueue_empty(queue), "Queue with item should not be empty");

    cqueue_pop(queue);
    free(data);
    TEST_ASSERT_EQUAL(1, cqueue_empty(queue), "Queue after pop should be empty");

    cqueue_free(queue);
}

TEST(test_cqueue_empty_null_queue) {
    TEST_CASE("Check if NULL queue is empty");

    int result = cqueue_empty(NULL);

    TEST_ASSERT_EQUAL(1, result, "NULL queue should be considered empty");
}

TEST(test_cqueue_size) {
    TEST_CASE("Get queue size");

    cqueue_t* queue = cqueue_create();

    TEST_ASSERT_EQUAL(0, cqueue_size(queue), "Initial size should be 0");

    char* data1 = strdup("1");
    char* data2 = strdup("2");
    char* data3 = strdup("3");

    cqueue_append(queue, data1);
    TEST_ASSERT_EQUAL(1, cqueue_size(queue), "Size should be 1");

    cqueue_append(queue, data2);
    TEST_ASSERT_EQUAL(2, cqueue_size(queue), "Size should be 2");

    cqueue_append(queue, data3);
    TEST_ASSERT_EQUAL(3, cqueue_size(queue), "Size should be 3");

    cqueue_pop(queue);
    free(data1);
    TEST_ASSERT_EQUAL(2, cqueue_size(queue), "Size should be 2 after pop");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_size_null_queue) {
    TEST_CASE("Get size of NULL queue");

    int size = cqueue_size(NULL);

    TEST_ASSERT_EQUAL(0, size, "NULL queue size should be 0");
}

// ============================================================================
// Тесты блокировок
// ============================================================================

TEST(test_cqueue_lock) {
    TEST_CASE("Lock queue");

    cqueue_t* queue = cqueue_create();

    int result = cqueue_lock(queue);

    TEST_ASSERT_EQUAL(1, result, "Lock should succeed");
    TEST_ASSERT_EQUAL(1, atomic_load(&queue->locked), "Queue should be locked");

    cqueue_unlock(queue);
    cqueue_free(queue);
}

TEST(test_cqueue_lock_null_queue) {
    TEST_CASE("Lock NULL queue");

    int result = cqueue_lock(NULL);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL queue");
}

TEST(test_cqueue_unlock) {
    TEST_CASE("Unlock queue");

    cqueue_t* queue = cqueue_create();
    cqueue_lock(queue);

    int result = cqueue_unlock(queue);

    TEST_ASSERT_EQUAL(1, result, "Unlock should succeed");
    TEST_ASSERT_EQUAL(0, atomic_load(&queue->locked), "Queue should be unlocked");

    cqueue_free(queue);
}

TEST(test_cqueue_unlock_null_queue) {
    TEST_CASE("Unlock NULL queue");

    int result = cqueue_unlock(NULL);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL queue");
}

TEST(test_cqueue_incrementlock) {
    TEST_CASE("Increment lock counter");

    cqueue_t* queue = cqueue_create();

    cqueue_incrementlock(queue);
    TEST_ASSERT_EQUAL(1, atomic_load(&queue->locked), "Lock counter should be 1");

    cqueue_incrementlock(queue);
    TEST_ASSERT_EQUAL(2, atomic_load(&queue->locked), "Lock counter should be 2");

    cqueue_incrementlock(queue);
    TEST_ASSERT_EQUAL(3, atomic_load(&queue->locked), "Lock counter should be 3");

    cqueue_free(queue);
}

TEST(test_cqueue_incrementlock_null_queue) {
    TEST_CASE("Increment lock on NULL queue");

    int result = cqueue_incrementlock(NULL);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL queue");
}

TEST(test_cqueue_lock_unlock_sequence) {
    TEST_CASE("Lock and unlock sequence");

    cqueue_t* queue = cqueue_create();

    cqueue_incrementlock(queue);
    cqueue_incrementlock(queue);
    cqueue_incrementlock(queue);
    TEST_ASSERT_EQUAL(3, atomic_load(&queue->locked), "Lock counter should be 3");

    cqueue_unlock(queue);
    TEST_ASSERT_EQUAL(2, atomic_load(&queue->locked), "Lock counter should be 2");

    cqueue_unlock(queue);
    TEST_ASSERT_EQUAL(1, atomic_load(&queue->locked), "Lock counter should be 1");

    cqueue_unlock(queue);
    TEST_ASSERT_EQUAL(0, atomic_load(&queue->locked), "Lock counter should be 0");

    cqueue_free(queue);
}

// ============================================================================
// Тесты очистки
// ============================================================================

TEST(test_cqueue_clear) {
    TEST_CASE("Clear queue");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);

    cqueue_clear(queue);

    // After clear, queue structure should be reset
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should be 0 after clear");

    // Note: current implementation doesn't reset item/last_item after clear
    // This is a potential bug - testing actual behavior

    free(data1);
    free(data2);
    free(queue);
}

TEST(test_cqueue_clear_empty) {
    TEST_CASE("Clear empty queue");

    cqueue_t* queue = cqueue_create();

    cqueue_clear(queue);

    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should remain 0");

    free(queue);
}

TEST(test_cqueue_clear_null_queue) {
    TEST_CASE("Clear NULL queue");

    // Should not crash
    cqueue_clear(NULL);

    TEST_ASSERT(1, "Should handle NULL gracefully");
}

TEST(test_cqueue_clearcb_with_callback) {
    TEST_CASE("Clear queue with callback");

    reset_free_callback_count();
    cqueue_t* queue = cqueue_create();

    char* data1 = malloc(10);
    char* data2 = malloc(10);
    char* data3 = malloc(10);

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);
    cqueue_append(queue, data3);

    cqueue_clearcb(queue, test_free_callback);

    TEST_ASSERT_EQUAL(3, free_callback_count, "Callback should be called 3 times");
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should be 0");

    free(queue);
}

TEST(test_cqueue_clearcb_null_callback) {
    TEST_CASE("Clear queue with NULL callback");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("test1");
    char* data2 = strdup("test2");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);

    cqueue_clearcb(queue, NULL);

    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should be 0");

    // Data is not freed, need to free manually
    free(data1);
    free(data2);
    free(queue);
}

TEST(test_cqueue_free_normal) {
    TEST_CASE("Free queue normally");

    cqueue_t* queue = cqueue_create();
    char* data = strdup("test");
    cqueue_append(queue, data);

    // Should not crash
    cqueue_free(queue);
    free(data);

    TEST_ASSERT(1, "Should free without crash");
}

TEST(test_cqueue_freecb_with_callback) {
    TEST_CASE("Free queue with callback");

    reset_free_callback_count();
    cqueue_t* queue = cqueue_create();

    char* data1 = malloc(10);
    char* data2 = malloc(10);

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);

    cqueue_freecb(queue, test_free_callback);

    TEST_ASSERT_EQUAL(2, free_callback_count, "Callback should be called for all items");
}

// ============================================================================
// Тесты элементов очереди
// ============================================================================

TEST(test_cqueue_item_create) {
    TEST_CASE("Create queue item");

    char* data = strdup("test");
    cqueue_item_t* item = cqueue_item_create(data);

    TEST_ASSERT_NOT_NULL(item, "Item should be created");
    TEST_ASSERT(item->data == data, "Item data should match");
    TEST_ASSERT_NULL(item->next, "Item next should be NULL");

    cqueue_item_free(item);
    free(data);
}

TEST(test_cqueue_item_free_null) {
    TEST_CASE("Free NULL item");

    // Should not crash
    cqueue_item_free(NULL);

    TEST_ASSERT(1, "Should handle NULL gracefully");
}

// ============================================================================
// Тесты граничных условий и потенциальных багов
// ============================================================================

TEST(test_cqueue_size_consistency) {
    TEST_CASE("Verify size consistency through operations");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("1");
    char* data2 = strdup("2");
    char* data3 = strdup("3");

    cqueue_append(queue, data1);
    TEST_ASSERT_EQUAL_SIZE(1, queue->size, "Size should be 1");

    cqueue_prepend(queue, data2);
    TEST_ASSERT_EQUAL_SIZE(2, queue->size, "Size should be 2");

    cqueue_append(queue, data3);
    TEST_ASSERT_EQUAL_SIZE(3, queue->size, "Size should be 3");

    cqueue_pop(queue);
    free(data2);
    TEST_ASSERT_EQUAL_SIZE(2, queue->size, "Size should be 2 after pop");

    cqueue_pop(queue);
    free(data1);
    TEST_ASSERT_EQUAL_SIZE(1, queue->size, "Size should be 1 after pop");

    cqueue_pop(queue);
    free(data3);
    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should be 0 after final pop");

    cqueue_free(queue);
}

TEST(test_cqueue_chain_integrity) {
    TEST_CASE("Verify linked list chain integrity");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("1");
    char* data2 = strdup("2");
    char* data3 = strdup("3");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);
    cqueue_append(queue, data3);

    // Walk the chain
    cqueue_item_t* current = queue->item;
    int count = 0;
    while (current != NULL) {
        count++;
        if (count > 10) break; // Prevent infinite loop
        current = current->next;
    }

    TEST_ASSERT_EQUAL(3, count, "Chain should have 3 items");
    TEST_ASSERT(current == NULL, "Chain should end with NULL");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_prepend_to_non_empty) {
    TEST_CASE("Prepend to non-empty queue maintains last_item");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");

    cqueue_append(queue, data1);
    cqueue_item_t* original_last = queue->last_item;

    cqueue_prepend(queue, data2);

    TEST_ASSERT(queue->last_item == original_last, "Last item should not change on prepend");
    TEST_ASSERT(queue->last_item->data == data1, "Last item should still be data1");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_append_to_non_empty) {
    TEST_CASE("Append to non-empty queue maintains first item");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");

    cqueue_append(queue, data1);
    cqueue_item_t* original_first = queue->item;

    cqueue_append(queue, data2);

    TEST_ASSERT(queue->item == original_first, "First item should not change on append");
    TEST_ASSERT(queue->item->data == data1, "First item should still be data1");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_alternating_operations) {
    TEST_CASE("Alternating push and pop operations");

    cqueue_t* queue = cqueue_create();

    for (int i = 0; i < 100; i++) {
        char* data = malloc(10);
        snprintf(data, 10, "%d", i);
        cqueue_append(queue, data);

        if (i % 2 == 1) {
            void* popped = cqueue_pop(queue);
            free(popped);
        }
    }

    // Should have 50 items left
    int expected_size = 50;
    TEST_ASSERT_EQUAL_SIZE(expected_size, queue->size, "Size should be 50");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_large_queue) {
    TEST_CASE("Create large queue");

    cqueue_t* queue = cqueue_create();
    const int count = 10000;

    // Add many items
    for (int i = 0; i < count; i++) {
        char* data = malloc(20);
        snprintf(data, 20, "item_%d", i);
        cqueue_append(queue, data);
    }

    TEST_ASSERT_EQUAL_SIZE(count, queue->size, "Size should match count");

    // Pop all items
    for (int i = 0; i < count; i++) {
        void* data = cqueue_pop(queue);
        TEST_ASSERT_NOT_NULL(data, "Popped data should not be NULL");
        free(data);
    }

    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should be 0 after popping all");
    TEST_ASSERT_NULL(queue->item, "Queue should be empty");

    cqueue_free(queue);
}

// ============================================================================
// Тесты на уязвимости и безопасность
// ============================================================================

TEST(test_cqueue_no_use_after_free) {
    TEST_CASE("Verify no use-after-free on pop");

    cqueue_t* queue = cqueue_create();
    char* data = strdup("test");
    cqueue_append(queue, data);

    void* popped_data = cqueue_pop(queue);

    // item is freed, accessing it would be use-after-free
    // We can't really test this without memory tools, but we verify the queue state
    TEST_ASSERT(popped_data == data, "Popped data should be valid");
    TEST_ASSERT_NULL(queue->item, "Queue item should be NULL");

    free(data);
    cqueue_free(queue);
}

TEST(test_cqueue_clear_state_after_clear) {
    TEST_CASE("Verify queue state after clear");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("1");
    char* data2 = strdup("2");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);

    cqueue_clear(queue);

    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Size should be 0");
    TEST_ASSERT_NULL(queue->item, "item should be NULL after clear");
    TEST_ASSERT_NULL(queue->last_item, "last_item should be NULL after clear");

    free(data1);
    free(data2);
    free(queue);
}

TEST(test_cqueue_append_after_clear) {
    TEST_CASE("Append after clear should work");

    cqueue_t* queue = cqueue_create();
    char* data1 = strdup("first");
    char* data2 = strdup("second");

    cqueue_append(queue, data1);
    cqueue_clear(queue);
    free(data1);

    cqueue_append(queue, data2);
    TEST_ASSERT_EQUAL_SIZE(1, queue->size, "Size should be 1");
    TEST_ASSERT(queue->item->data == data2, "Item should be data2");

    cqueue_freecb(queue, free);
}

TEST(test_cqueue_double_free_protection) {
    TEST_CASE("Verify protection against double free");

    reset_free_callback_count();
    cqueue_t* queue = cqueue_create();
    char* data = malloc(10);

    cqueue_append(queue, data);

    cqueue_clearcb(queue, test_free_callback);
    TEST_ASSERT_EQUAL(1, free_callback_count, "Callback called once");

    // Queue is already cleared, calling again should be safe
    cqueue_clearcb(queue, test_free_callback);
    TEST_ASSERT_EQUAL(1, free_callback_count, "Callback should not be called again");

    free(queue);
}

TEST(test_cqueue_null_pointer_dereference_safety) {
    TEST_CASE("Test safety against NULL pointer dereferences");

    // All these should return safely without crashing
    TEST_ASSERT_EQUAL(0, cqueue_append(NULL, (void*)0x123), "NULL queue append");
    TEST_ASSERT_EQUAL(0, cqueue_prepend(NULL, (void*)0x123), "NULL queue prepend");
    TEST_ASSERT_NULL(cqueue_pop(NULL), "NULL queue pop");
    TEST_ASSERT_EQUAL(1, cqueue_empty(NULL), "NULL queue empty");
    TEST_ASSERT_EQUAL(0, cqueue_size(NULL), "NULL queue size");
    TEST_ASSERT_NULL(cqueue_first(NULL), "NULL queue first");
    TEST_ASSERT_NULL(cqueue_last(NULL), "NULL queue last");
    TEST_ASSERT_EQUAL(0, cqueue_lock(NULL), "NULL queue lock");
    TEST_ASSERT_EQUAL(0, cqueue_unlock(NULL), "NULL queue unlock");

    TEST_ASSERT(1, "All NULL checks passed");
}

TEST(test_cqueue_memory_leak_on_free_without_callback) {
    TEST_CASE("Document potential memory leak without callback");

    cqueue_t* queue = cqueue_create();

    // This creates a memory leak - data is allocated but not freed
    char* data1 = strdup("leak1");
    char* data2 = strdup("leak2");

    cqueue_append(queue, data1);
    cqueue_append(queue, data2);

    // Free queue without callback - data is leaked
    // For this test, we'll clean up manually
    cqueue_pop(queue);
    free(data1);
    cqueue_pop(queue);
    free(data2);

    cqueue_free(queue);

    TEST_ASSERT(1, "Memory leak scenario documented");
}

// ============================================================================
// Многопоточные тесты (базовые)
// ============================================================================

typedef struct {
    cqueue_t* queue;
    int count;
} thread_data_t;

static void* producer_thread(void* arg) {
    thread_data_t* tdata = (thread_data_t*)arg;

    for (int i = 0; i < tdata->count; i++) {
        char* data = malloc(20);
        snprintf(data, 20, "item_%d", i);

        cqueue_lock(tdata->queue);
        cqueue_append(tdata->queue, data);
        cqueue_unlock(tdata->queue);

        usleep(1); // Small delay
    }

    return NULL;
}

static void* consumer_thread(void* arg) {
    thread_data_t* tdata = (thread_data_t*)arg;
    int consumed = 0;

    while (consumed < tdata->count) {
        cqueue_lock(tdata->queue);
        if (!cqueue_empty(tdata->queue)) {
            void* data = cqueue_pop(tdata->queue);
            if (data != NULL) {
                free(data);
                consumed++;
            }
        }
        cqueue_unlock(tdata->queue);

        usleep(1);
    }

    return NULL;
}

TEST(test_cqueue_basic_thread_safety) {
    TEST_CASE("Basic thread safety with lock/unlock");

    cqueue_t* queue = cqueue_create();
    pthread_t prod_thread, cons_thread;

    thread_data_t tdata = {queue, 100};

    pthread_create(&prod_thread, NULL, producer_thread, &tdata);
    pthread_create(&cons_thread, NULL, consumer_thread, &tdata);

    pthread_join(prod_thread, NULL);
    pthread_join(cons_thread, NULL);

    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Queue should be empty after consumption");

    cqueue_free(queue);
}

// ============================================================================
// Сложные сценарии
// ============================================================================

TEST(test_cqueue_fifo_order) {
    TEST_CASE("Verify FIFO order");

    cqueue_t* queue = cqueue_create();
    const int count = 100;

    // Enqueue
    for (int i = 0; i < count; i++) {
        char* data = malloc(20);
        snprintf(data, 20, "%d", i);
        cqueue_append(queue, data);
    }

    // Dequeue and verify order
    for (int i = 0; i < count; i++) {
        char* data = (char*)cqueue_pop(queue);
        TEST_ASSERT_NOT_NULL(data, "Data should not be NULL");

        int value = atoi(data);
        TEST_ASSERT_EQUAL(i, value, "Order should be FIFO");

        free(data);
    }

    cqueue_free(queue);
}

TEST(test_cqueue_lifo_order_with_prepend) {
    TEST_CASE("Verify LIFO order with prepend");

    cqueue_t* queue = cqueue_create();
    const int count = 100;

    // Prepend (acts like stack)
    for (int i = 0; i < count; i++) {
        char* data = malloc(20);
        snprintf(data, 20, "%d", i);
        cqueue_prepend(queue, data);
    }

    // Pop should give LIFO order
    for (int i = count - 1; i >= 0; i--) {
        char* data = (char*)cqueue_pop(queue);
        TEST_ASSERT_NOT_NULL(data, "Data should not be NULL");

        int value = atoi(data);
        TEST_ASSERT_EQUAL(i, value, "Order should be LIFO for prepend");

        free(data);
    }

    cqueue_free(queue);
}

TEST(test_cqueue_stress_test) {
    TEST_CASE("Stress test with many operations");

    cqueue_t* queue = cqueue_create();
    const int iterations = 1000;

    for (int i = 0; i < iterations; i++) {
        // Mix of operations
        char* data1 = malloc(20);
        char* data2 = malloc(20);
        snprintf(data1, 20, "a_%d", i);
        snprintf(data2, 20, "b_%d", i);

        cqueue_append(queue, data1);
        cqueue_prepend(queue, data2);

        if (i % 3 == 0 && !cqueue_empty(queue)) {
            void* popped = cqueue_pop(queue);
            free(popped);
        }
    }

    // Clean up
    while (!cqueue_empty(queue)) {
        void* data = cqueue_pop(queue);
        free(data);
    }

    TEST_ASSERT_EQUAL_SIZE(0, queue->size, "Queue should be empty");

    cqueue_free(queue);
}

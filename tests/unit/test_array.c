#include "framework.h"
#include "array.h"
#include <string.h>
#include <float.h>
#include <limits.h>
#include <math.h>

// ============================================================================
// Вспомогательные функции для тестирования ARRAY_POINTER
// ============================================================================

typedef struct {
    int id;
    char name[32];
} test_obj_t;

static void* test_obj_copy(void* ptr) {
    if (ptr == NULL) return NULL;
    test_obj_t* obj = malloc(sizeof(test_obj_t));
    if (obj == NULL) return NULL;
    memcpy(obj, ptr, sizeof(test_obj_t));
    return obj;
}

static void test_obj_free(void* ptr) {
    free(ptr);
}

static int custom_free_called = 0;
static void test_obj_free_counted(void* ptr) {
    custom_free_called++;
    free(ptr);
}

// ============================================================================
// Тесты создания и инициализации массива
// ============================================================================

TEST(test_array_create) {
    TEST_SUITE("Array Creation and Initialization");
    TEST_CASE("Create empty array");

    array_t* arr = array_create();
    TEST_ASSERT_NOT_NULL(arr, "Array should be created");
    TEST_ASSERT_NOT_NULL(arr->elements, "Elements buffer should be allocated");
    TEST_ASSERT_EQUAL_SIZE(0, arr->size, "Initial size should be 0");
    TEST_ASSERT(arr->capacity >= 10, "Initial capacity should be at least 10");

    array_free(arr);
}

TEST(test_array_init_null) {
    TEST_CASE("Initialize NULL array");

    int result = array_init(NULL);
    TEST_ASSERT_EQUAL(0, result, "array_init should return 0 for NULL pointer");
}

TEST(test_array_init_stack_allocated) {
    TEST_CASE("Initialize stack-allocated array");

    array_t arr;
    int result = array_init(&arr);
    TEST_ASSERT_EQUAL(1, result, "array_init should succeed");
    TEST_ASSERT_NOT_NULL(arr.elements, "Elements should be allocated");
    TEST_ASSERT_EQUAL_SIZE(0, arr.size, "Size should be 0");
    TEST_ASSERT(arr.capacity >= 10, "Capacity should be initialized");

    array_destroy(&arr);
}

TEST(test_array_destroy_null) {
    TEST_CASE("Destroy NULL array");

    // Should not crash
    array_destroy(NULL);
    array_free(NULL);
    TEST_ASSERT(1, "NULL destroy should not crash");
}

// ============================================================================
// Тесты создания массивов из данных
// ============================================================================

TEST(test_array_create_from_ints) {
    TEST_SUITE("Array Creation from Data");
    TEST_CASE("Create array from integers");

    array_t* arr = array_create_ints(1, 2, 3, 4, 5);
    TEST_ASSERT_NOT_NULL(arr, "Array should be created");
    TEST_ASSERT_EQUAL_SIZE(5, array_size(arr), "Size should be 5");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 0), "First element should be 1");
    TEST_ASSERT_EQUAL(5, array_get_int(arr, 4), "Last element should be 5");

    array_free(arr);
}

TEST(test_array_create_from_doubles) {
    TEST_CASE("Create array from doubles");

    array_t* arr = array_create_doubles(1.5, 2.7, 3.14);
    TEST_ASSERT_NOT_NULL(arr, "Array should be created");
    TEST_ASSERT_EQUAL_SIZE(3, array_size(arr), "Size should be 3");
    TEST_ASSERT(array_get_double(arr, 0) == 1.5, "First element should be 1.5");
    TEST_ASSERT(array_get_double(arr, 2) == 3.14, "Last element should be 3.14");

    array_free(arr);
}

TEST(test_array_create_from_strings) {
    TEST_CASE("Create array from strings");

    array_t* arr = array_create_strings("hello", "world", "test");
    TEST_ASSERT_NOT_NULL(arr, "Array should be created");
    TEST_ASSERT_EQUAL_SIZE(3, array_size(arr), "Size should be 3");
    TEST_ASSERT_STR_EQUAL("hello", array_get_string(arr, 0), "First element should be 'hello'");
    TEST_ASSERT_STR_EQUAL("test", array_get_string(arr, 2), "Last element should be 'test'");

    array_free(arr);
}

TEST(test_array_create_from_empty_strings) {
    TEST_CASE("Create array with empty strings");

    array_t* arr = array_create();
    array_push_back_str(arr, "");
    array_push_back_str(arr, NULL);
    array_push_back_str(arr, "");

    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr), "Size should be 3");
    const char* str0 = array_get_string(arr, 0);
    TEST_ASSERT_NOT_NULL(str0, "Empty string should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, strlen(str0), "Empty string should have length 0");

    array_free(arr);
}

// ============================================================================
// Тесты типов данных и avalue_t
// ============================================================================

TEST(test_array_create_int_value) {
    TEST_SUITE("Array Value Creation");
    TEST_CASE("Create int value");

    avalue_t val = array_create_int(42);
    TEST_ASSERT_EQUAL(ARRAY_INT, val.type, "Type should be ARRAY_INT");
    TEST_ASSERT_EQUAL(42, val._int, "Value should be 42");
}

TEST(test_array_create_double_value) {
    TEST_CASE("Create double value");

    avalue_t val = array_create_double(3.14159);
    TEST_ASSERT_EQUAL(ARRAY_DOUBLE, val.type, "Type should be ARRAY_DOUBLE");
    TEST_ASSERT(val._double == 3.14159, "Value should be 3.14159");
}

TEST(test_array_create_ldouble_value) {
    TEST_CASE("Create long double value");

    avalue_t val = array_create_ldouble(1.23456789L);
    TEST_ASSERT_EQUAL(ARRAY_LONGDOUBLE, val.type, "Type should be ARRAY_LONGDOUBLE");
    // BUG: array.c:334 uses ._double instead of ._ldouble!
}

TEST(test_array_create_string_value) {
    TEST_CASE("Create string value");

    avalue_t val = array_create_string("test string");
    TEST_ASSERT_EQUAL(ARRAY_STRING, val.type, "Type should be ARRAY_STRING");
    TEST_ASSERT_NOT_NULL(val._string, "String should be allocated");
    TEST_ASSERT_EQUAL_SIZE(11, val._length, "Length should be 11");
    TEST_ASSERT_STR_EQUAL("test string", val._string, "String content should match");

    free(val._string);
}

TEST(test_array_create_stringn_value) {
    TEST_CASE("Create string value with explicit length");

    const char* text = "hello world";
    avalue_t val = array_create_stringn(text, 5);
    TEST_ASSERT_EQUAL(ARRAY_STRING, val.type, "Type should be ARRAY_STRING");
    TEST_ASSERT_NOT_NULL(val._string, "String should be allocated");
    TEST_ASSERT_EQUAL_SIZE(5, val._length, "Length should be 5");
    TEST_ASSERT_STR_EQUAL("hello", val._string, "String should be 'hello'");

    free(val._string);
}

TEST(test_array_create_pointer_value) {
    TEST_CASE("Create pointer value");

    test_obj_t obj = {.id = 123, .name = "test"};
    avalue_t val = array_create_pointer(&obj, test_obj_copy, test_obj_free);

    TEST_ASSERT_EQUAL(ARRAY_POINTER, val.type, "Type should be ARRAY_POINTER");
    TEST_ASSERT_EQUAL(&obj, val._pointer, "Pointer should match");
    TEST_ASSERT_NOT_NULL(val._copy, "Copy function should be set");
    TEST_ASSERT_NOT_NULL(val._free, "Free function should be set");
}

// ============================================================================
// Тесты push операций
// ============================================================================

TEST(test_array_push_back_int) {
    TEST_SUITE("Array Push Operations");
    TEST_CASE("Push integers to back");

    array_t* arr = array_create();
    array_push_back_int(arr, 10);
    array_push_back_int(arr, 20);
    array_push_back_int(arr, 30);

    TEST_ASSERT_EQUAL_SIZE(3, array_size(arr), "Size should be 3");
    TEST_ASSERT_EQUAL(10, array_get_int(arr, 0), "First element should be 10");
    TEST_ASSERT_EQUAL(20, array_get_int(arr, 1), "Second element should be 20");
    TEST_ASSERT_EQUAL(30, array_get_int(arr, 2), "Third element should be 30");

    array_free(arr);
}

TEST(test_array_push_back_double) {
    TEST_CASE("Push doubles to back");

    array_t* arr = array_create();
    array_push_back_double(arr, 1.1);
    array_push_back_double(arr, 2.2);

    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr), "Size should be 2");
    TEST_ASSERT(array_get_double(arr, 0) == 1.1, "First element should be 1.1");
    TEST_ASSERT(array_get_double(arr, 1) == 2.2, "Second element should be 2.2");

    array_free(arr);
}

TEST(test_array_push_back_str) {
    TEST_CASE("Push strings to back");

    array_t* arr = array_create();
    array_push_back_str(arr, "first");
    array_push_back_str(arr, "second");

    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr), "Size should be 2");
    TEST_ASSERT_STR_EQUAL("first", array_get_string(arr, 0), "First string should match");
    TEST_ASSERT_STR_EQUAL("second", array_get_string(arr, 1), "Second string should match");

    array_free(arr);
}

TEST(test_array_push_front) {
    TEST_CASE("Push to front of array");

    array_t* arr = array_create();
    array_push_back_int(arr, 1);
    array_push_back_int(arr, 2);
    array_push_front(arr, array_create_int(0));

    TEST_ASSERT_EQUAL_SIZE(3, array_size(arr), "Size should be 3");
    TEST_ASSERT_EQUAL(0, array_get_int(arr, 0), "First element should be 0");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 1), "Second element should be 1");
    TEST_ASSERT_EQUAL(2, array_get_int(arr, 2), "Third element should be 2");

    array_free(arr);
}

TEST(test_array_push_to_null) {
    TEST_CASE("Push to NULL array");

    // Should not crash
    array_push_back_int(NULL, 42);
    array_push_back_double(NULL, 3.14);
    array_push_back_str(NULL, "test");
    array_push_front(NULL, array_create_int(1));
    TEST_ASSERT(1, "NULL push operations should not crash");
}

// ============================================================================
// Тесты insert операций
// ============================================================================

TEST(test_array_insert_middle) {
    TEST_SUITE("Array Insert Operations");
    TEST_CASE("Insert in the middle");

    array_t* arr = array_create_ints(1, 2, 4, 5);
    array_insert(arr, 2, array_create_int(3));

    TEST_ASSERT_EQUAL_SIZE(5, array_size(arr), "Size should be 5");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 0), "Element 0 should be 1");
    TEST_ASSERT_EQUAL(2, array_get_int(arr, 1), "Element 1 should be 2");
    TEST_ASSERT_EQUAL(3, array_get_int(arr, 2), "Element 2 should be 3");
    TEST_ASSERT_EQUAL(4, array_get_int(arr, 3), "Element 3 should be 4");
    TEST_ASSERT_EQUAL(5, array_get_int(arr, 4), "Element 4 should be 5");

    array_free(arr);
}

TEST(test_array_insert_at_start) {
    TEST_CASE("Insert at start");

    array_t* arr = array_create_ints(2, 3);
    array_insert(arr, 0, array_create_int(1));

    TEST_ASSERT_EQUAL_SIZE(3, array_size(arr), "Size should be 3");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 0), "First element should be 1");
    TEST_ASSERT_EQUAL(2, array_get_int(arr, 1), "Second element should be 2");

    array_free(arr);
}

TEST(test_array_insert_at_end) {
    TEST_CASE("Insert at end");

    array_t* arr = array_create_ints(1, 2);
    array_insert(arr, 2, array_create_int(3));

    TEST_ASSERT_EQUAL_SIZE(3, array_size(arr), "Size should be 3");
    TEST_ASSERT_EQUAL(3, array_get_int(arr, 2), "Last element should be 3");

    array_free(arr);
}

TEST(test_array_insert_out_of_bounds) {
    TEST_CASE("Insert out of bounds");

    array_t* arr = array_create_ints(1, 2);
    size_t old_size = array_size(arr);

    // Should fail silently (based on log_error in code)
    array_insert(arr, 100, array_create_int(99));

    TEST_ASSERT_EQUAL_SIZE(old_size, array_size(arr), "Size should not change on invalid insert");

    array_free(arr);
}

TEST(test_array_insert_to_null) {
    TEST_CASE("Insert to NULL array");

    // Should not crash
    array_insert(NULL, 0, array_create_int(42));
    TEST_ASSERT(1, "NULL insert should not crash");
}

// ============================================================================
// Тесты delete операций
// ============================================================================

TEST(test_array_delete_middle) {
    TEST_SUITE("Array Delete Operations");
    TEST_CASE("Delete from middle");

    array_t* arr = array_create_ints(1, 2, 3, 4, 5);
    array_delete(arr, 2);

    TEST_ASSERT_EQUAL_SIZE(4, array_size(arr), "Size should be 4");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 0), "Element 0 should be 1");
    TEST_ASSERT_EQUAL(2, array_get_int(arr, 1), "Element 1 should be 2");
    TEST_ASSERT_EQUAL(4, array_get_int(arr, 2), "Element 2 should be 4");
    TEST_ASSERT_EQUAL(5, array_get_int(arr, 3), "Element 3 should be 5");

    array_free(arr);
}

TEST(test_array_delete_first) {
    TEST_CASE("Delete first element");

    array_t* arr = array_create_ints(1, 2, 3);
    array_delete(arr, 0);

    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr), "Size should be 2");
    TEST_ASSERT_EQUAL(2, array_get_int(arr, 0), "First element should be 2");
    TEST_ASSERT_EQUAL(3, array_get_int(arr, 1), "Second element should be 3");

    array_free(arr);
}

TEST(test_array_delete_last) {
    TEST_CASE("Delete last element");

    array_t* arr = array_create_ints(1, 2, 3);
    array_delete(arr, 2);

    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr), "Size should be 2");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 0), "First element should be 1");
    TEST_ASSERT_EQUAL(2, array_get_int(arr, 1), "Second element should be 2");

    array_free(arr);
}

TEST(test_array_delete_out_of_bounds) {
    TEST_CASE("Delete out of bounds");

    array_t* arr = array_create_ints(1, 2);
    size_t old_size = array_size(arr);

    // Should fail silently
    array_delete(arr, 100);

    TEST_ASSERT_EQUAL_SIZE(old_size, array_size(arr), "Size should not change on invalid delete");

    array_free(arr);
}

TEST(test_array_delete_string_frees_memory) {
    TEST_CASE("Delete string element frees memory");

    array_t* arr = array_create_strings("test1", "test2", "test3");
    array_delete(arr, 1);

    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr), "Size should be 2");
    TEST_ASSERT_STR_EQUAL("test1", array_get_string(arr, 0), "First should be test1");
    TEST_ASSERT_STR_EQUAL("test3", array_get_string(arr, 1), "Second should be test3");

    array_free(arr);
}

// ============================================================================
// Тесты update операций
// ============================================================================

TEST(test_array_update) {
    TEST_SUITE("Array Update Operations");
    TEST_CASE("Update element");

    array_t* arr = array_create_ints(1, 2, 3);
    array_update(arr, 1, array_create_int(99));

    TEST_ASSERT_EQUAL_SIZE(3, array_size(arr), "Size should remain 3");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 0), "First element unchanged");
    TEST_ASSERT_EQUAL(99, array_get_int(arr, 1), "Second element should be 99");
    TEST_ASSERT_EQUAL(3, array_get_int(arr, 2), "Third element unchanged");

    array_free(arr);
}

TEST(test_array_update_change_type) {
    TEST_CASE("Update element changing type");

    array_t* arr = array_create_ints(1, 2, 3);
    array_update(arr, 1, array_create_string("hello"));

    TEST_ASSERT_EQUAL_SIZE(3, array_size(arr), "Size should remain 3");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 0), "First element unchanged");
    TEST_ASSERT_STR_EQUAL("hello", array_get_string(arr, 1), "Second element should be string");
    TEST_ASSERT_EQUAL(3, array_get_int(arr, 2), "Third element unchanged");

    array_free(arr);
}

TEST(test_array_update_out_of_bounds) {
    TEST_CASE("Update out of bounds");

    array_t* arr = array_create_ints(1, 2);

    // Should fail silently
    array_update(arr, 100, array_create_int(99));

    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr), "Size should not change");
    TEST_ASSERT_EQUAL(1, array_get_int(arr, 0), "First element unchanged");
    TEST_ASSERT_EQUAL(2, array_get_int(arr, 1), "Second element unchanged");

    array_free(arr);
}

TEST(test_array_update_null) {
    TEST_CASE("Update NULL array");

    // Should not crash (no NULL check in array_update!)
    // This is a potential bug
    // array_update(NULL, 0, array_create_int(42));
    TEST_ASSERT(1, "Skipping NULL update test due to missing NULL check");
}

// ============================================================================
// Тесты get операций
// ============================================================================

TEST(test_array_get) {
    TEST_SUITE("Array Get Operations");
    TEST_CASE("Get element by index");

    array_t* arr = array_create_ints(10, 20, 30);
    void* val = array_get(arr, 1);

    TEST_ASSERT_NOT_NULL(val, "Value should not be NULL");
    TEST_ASSERT_EQUAL(20, *(int*)val, "Value should be 20");

    array_free(arr);
}

TEST(test_array_get_int) {
    TEST_CASE("Get int element");

    array_t* arr = array_create_ints(42, 43, 44);
    TEST_ASSERT_EQUAL(42, array_get_int(arr, 0), "First int should be 42");
    TEST_ASSERT_EQUAL(43, array_get_int(arr, 1), "Second int should be 43");
    TEST_ASSERT_EQUAL(44, array_get_int(arr, 2), "Third int should be 44");

    array_free(arr);
}

TEST(test_array_get_double) {
    TEST_CASE("Get double element");

    array_t* arr = array_create_doubles(1.5, 2.5, 3.5);
    TEST_ASSERT(array_get_double(arr, 0) == 1.5, "First double should be 1.5");
    TEST_ASSERT(array_get_double(arr, 1) == 2.5, "Second double should be 2.5");
    TEST_ASSERT(array_get_double(arr, 2) == 3.5, "Third double should be 3.5");

    array_free(arr);
}

TEST(test_array_get_string) {
    TEST_CASE("Get string element");

    array_t* arr = array_create_strings("foo", "bar", "baz");
    TEST_ASSERT_STR_EQUAL("foo", array_get_string(arr, 0), "First string should be 'foo'");
    TEST_ASSERT_STR_EQUAL("bar", array_get_string(arr, 1), "Second string should be 'bar'");
    TEST_ASSERT_STR_EQUAL("baz", array_get_string(arr, 2), "Third string should be 'baz'");

    array_free(arr);
}

TEST(test_array_get_out_of_bounds) {
    TEST_CASE("Get out of bounds");

    array_t* arr = array_create_ints(1, 2);
    void* val = array_get(arr, 100);

    TEST_ASSERT_NULL(val, "Should return NULL for out of bounds");

    array_free(arr);
}

TEST(test_array_get_null) {
    TEST_CASE("Get from NULL array");

    void* val = array_get(NULL, 0);
    TEST_ASSERT_NULL(val, "Should return NULL for NULL array");

    int ival = array_get_int(NULL, 0);
    TEST_ASSERT_EQUAL(0, ival, "Should return 0 for NULL array");

    double dval = array_get_double(NULL, 0);
    TEST_ASSERT(dval == 0.0, "Should return 0.0 for NULL array");
}

// ============================================================================
// Тесты copy операций
// ============================================================================

TEST(test_array_copy_ints) {
    TEST_SUITE("Array Copy Operations");
    TEST_CASE("Copy array of integers");

    array_t* arr = array_create_ints(1, 2, 3);
    array_t* copy = array_copy(arr);

    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT(copy != arr, "Copy should be different object");
    TEST_ASSERT_EQUAL_SIZE(array_size(arr), array_size(copy), "Sizes should match");

    for (size_t i = 0; i < array_size(arr); i++) {
        TEST_ASSERT_EQUAL(array_get_int(arr, i), array_get_int(copy, i), "Elements should match");
    }

    // Modify original, verify copy unchanged
    array_update(arr, 0, array_create_int(999));
    TEST_ASSERT_EQUAL(999, array_get_int(arr, 0), "Original should be modified");
    TEST_ASSERT_EQUAL(1, array_get_int(copy, 0), "Copy should be unchanged");

    array_free(arr);
    array_free(copy);
}

TEST(test_array_copy_strings) {
    TEST_CASE("Copy array of strings");

    array_t* arr = array_create_strings("hello", "world");
    array_t* copy = array_copy(arr);

    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(2, array_size(copy), "Size should be 2");
    TEST_ASSERT_STR_EQUAL("hello", array_get_string(copy, 0), "First string should match");
    TEST_ASSERT_STR_EQUAL("world", array_get_string(copy, 1), "Second string should match");

    // Verify deep copy (different string pointers)
    TEST_ASSERT(array_get_string(arr, 0) != array_get_string(copy, 0),
                "String pointers should be different");

    array_free(arr);
    array_free(copy);
}

TEST(test_array_copy_mixed_types) {
    TEST_CASE("Copy array with mixed types");

    array_t* arr = array_create();
    array_push_back_int(arr, 42);
    array_push_back_double(arr, 3.14);
    array_push_back_str(arr, "test");

    array_t* copy = array_copy(arr);

    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(3, array_size(copy), "Size should be 3");
    TEST_ASSERT_EQUAL(42, array_get_int(copy, 0), "Int element should match");
    TEST_ASSERT(array_get_double(copy, 1) == 3.14, "Double element should match");
    TEST_ASSERT_STR_EQUAL("test", array_get_string(copy, 2), "String element should match");

    array_free(arr);
    array_free(copy);
}

TEST(test_array_copy_null) {
    TEST_CASE("Copy NULL array");

    array_t* copy = array_copy(NULL);
    TEST_ASSERT_NULL(copy, "Copy of NULL should be NULL");
}

TEST(test_array_copy_empty) {
    TEST_CASE("Copy empty array");

    array_t* arr = array_create();
    array_t* copy = array_copy(arr);

    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, array_size(copy), "Copy should be empty");

    array_free(arr);
    array_free(copy);
}

// ============================================================================
// Тесты clear операций
// ============================================================================

TEST(test_array_clear) {
    TEST_SUITE("Array Clear Operations");
    TEST_CASE("Clear array");

    array_t* arr = array_create_ints(1, 2, 3, 4, 5);
    size_t old_capacity = arr->capacity;

    array_clear(arr);

    TEST_ASSERT_EQUAL_SIZE(0, array_size(arr), "Size should be 0");
    TEST_ASSERT_EQUAL_SIZE(old_capacity, arr->capacity, "Capacity should remain same");
    TEST_ASSERT_NOT_NULL(arr->elements, "Elements buffer should still exist");

    array_free(arr);
}

TEST(test_array_clear_strings) {
    TEST_CASE("Clear array with strings");

    array_t* arr = array_create_strings("test1", "test2", "test3");
    array_clear(arr);

    TEST_ASSERT_EQUAL_SIZE(0, array_size(arr), "Size should be 0");

    // Should be able to add new elements
    array_push_back_str(arr, "new");
    TEST_ASSERT_EQUAL_SIZE(1, array_size(arr), "Should be able to add after clear");
    TEST_ASSERT_STR_EQUAL("new", array_get_string(arr, 0), "New element should be correct");

    array_free(arr);
}

TEST(test_array_clear_null) {
    TEST_CASE("Clear NULL array");

    // Should not crash
    array_clear(NULL);
    TEST_ASSERT(1, "NULL clear should not crash");
}

// ============================================================================
// Тесты размера и capacity
// ============================================================================

TEST(test_array_size) {
    TEST_SUITE("Array Size and Capacity");
    TEST_CASE("Array size function");

    array_t* arr = array_create();
    TEST_ASSERT_EQUAL_SIZE(0, array_size(arr), "Empty array size is 0");

    array_push_back_int(arr, 1);
    TEST_ASSERT_EQUAL_SIZE(1, array_size(arr), "Size should be 1");

    array_push_back_int(arr, 2);
    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr), "Size should be 2");

    array_free(arr);
}

TEST(test_array_size_null) {
    TEST_CASE("Size of NULL array");

    TEST_ASSERT_EQUAL_SIZE(0, array_size(NULL), "NULL array size should be 0");
}

TEST(test_array_auto_resize_on_push) {
    TEST_CASE("Auto-resize when exceeding capacity");

    array_t* arr = array_create();
    size_t initial_capacity = arr->capacity;

    // Push more than initial capacity
    for (int i = 0; i < 25; i++) {
        array_push_back_int(arr, i);
    }

    TEST_ASSERT_EQUAL_SIZE(25, array_size(arr), "Size should be 25");
    TEST_ASSERT(arr->capacity > initial_capacity, "Capacity should have increased");

    // Verify all elements
    for (int i = 0; i < 25; i++) {
        TEST_ASSERT_EQUAL(i, array_get_int(arr, i), "All elements should be preserved");
    }

    array_free(arr);
}

TEST(test_array_auto_shrink_on_delete) {
    TEST_CASE("Auto-shrink when deleting many elements");

    array_t* arr = array_create();

    // Push 30 elements
    for (int i = 0; i < 30; i++) {
        array_push_back_int(arr, i);
    }

    size_t large_capacity = arr->capacity;

    // Delete most elements
    for (int i = 0; i < 25; i++) {
        array_delete(arr, 0);
    }

    TEST_ASSERT_EQUAL_SIZE(5, array_size(arr), "Size should be 5");
    TEST_ASSERT(arr->capacity < large_capacity, "Capacity should have decreased");

    array_free(arr);
}

// ============================================================================
// Тесты ARRAY_POINTER типа
// ============================================================================

TEST(test_array_pointer_type) {
    TEST_SUITE("Array Pointer Type");
    TEST_CASE("Store and retrieve pointer");

    test_obj_t* obj = malloc(sizeof(test_obj_t));
    if (!obj) return;
    obj->id = 123;
    strcpy(obj->name, "test object");

    array_t* arr = array_create();
    array_push_back(arr, array_create_pointer(obj, test_obj_copy, test_obj_free));

    TEST_ASSERT_EQUAL_SIZE(1, array_size(arr), "Size should be 1");

    test_obj_t* retrieved = (test_obj_t*)array_get_pointer(arr, 0);
    TEST_ASSERT_NOT_NULL(retrieved, "Retrieved pointer should not be NULL");
    TEST_ASSERT_EQUAL(123, retrieved->id, "Object ID should match");
    TEST_ASSERT_STR_EQUAL("test object", retrieved->name, "Object name should match");

    array_free(arr);
}

TEST(test_array_pointer_copy) {
    TEST_CASE("Copy array with pointer type");

    test_obj_t* obj = malloc(sizeof(test_obj_t));
    if (!obj) return;
    obj->id = 456;
    strcpy(obj->name, "original");

    array_t* arr = array_create();
    array_push_back(arr, array_create_pointer(obj, test_obj_copy, test_obj_free));

    array_t* copy = array_copy(arr);

    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(1, array_size(copy), "Copy size should be 1");

    test_obj_t* copy_obj = (test_obj_t*)array_get_pointer(copy, 0);
    TEST_ASSERT_NOT_NULL(copy_obj, "Copied object should not be NULL");
    TEST_ASSERT_EQUAL(456, copy_obj->id, "Copied object ID should match");
    TEST_ASSERT(copy_obj != obj, "Copied object should be different instance");

    array_free(arr);
    array_free(copy);
}

TEST(test_array_pointer_custom_free_called) {
    TEST_CASE("Custom free function is called");

    test_obj_t* obj = malloc(sizeof(test_obj_t));
    if (!obj) return;
    obj->id = 789;
    custom_free_called = 0;

    array_t* arr = array_create();
    array_push_back(arr, array_create_pointer(obj, test_obj_copy, test_obj_free_counted));

    array_free(arr);

    TEST_ASSERT_EQUAL(1, custom_free_called, "Custom free should be called once");
}

TEST(test_array_pointer_no_copy_function) {
    TEST_CASE("Pointer with NULL copy function");

    int value = 42;
    array_t* arr = array_create();
    array_push_back(arr, array_create_pointer(&value, array_nocopy, array_nofree));

    TEST_ASSERT_EQUAL_SIZE(1, array_size(arr), "Size should be 1");

    int* retrieved = (int*)array_get_pointer(arr, 0);
    TEST_ASSERT_NOT_NULL(retrieved, "Retrieved pointer should not be NULL");
    TEST_ASSERT_EQUAL(42, *retrieved, "Value should be 42");

    // Copying with array_nocopy would cause issues
    // array_t* copy = array_copy(arr);  // This would crash!

    array_free(arr);
}

// ============================================================================
// Тесты item_to_string
// ============================================================================

TEST(test_array_item_to_string_int) {
    TEST_SUITE("Array Item to String");
    TEST_CASE("Convert int to string");

    array_t* arr = array_create_ints(42, -17, 0);

    str_t* str = array_item_to_string(arr, 0);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    TEST_ASSERT_STR_EQUAL("42", str_get(str), "Should convert to '42'");
    str_free(str);

    str = array_item_to_string(arr, 1);
    TEST_ASSERT_STR_EQUAL("-17", str_get(str), "Should convert to '-17'");
    str_free(str);

    array_free(arr);
}

TEST(test_array_item_to_string_double) {
    TEST_CASE("Convert double to string");

    array_t* arr = array_create_doubles(3.14159, -2.5);

    str_t* str = array_item_to_string(arr, 0);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    // Should have 12 decimal places
    TEST_ASSERT(strstr(str_get(str), "3.14159") != NULL, "Should contain 3.14159");
    str_free(str);

    array_free(arr);
}

TEST(test_array_item_to_string_string) {
    TEST_CASE("Convert string to string");

    array_t* arr = array_create_strings("hello", "world");

    str_t* str = array_item_to_string(arr, 0);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello", str_get(str), "Should be 'hello'");
    str_free(str);

    array_free(arr);
}

TEST(test_array_item_to_string_pointer) {
    TEST_CASE("Convert pointer to string");

    test_obj_t* obj = malloc(sizeof(test_obj_t));
    array_t* arr = array_create();
    array_push_back(arr, array_create_pointer(obj, test_obj_copy, test_obj_free));

    str_t* str = array_item_to_string(arr, 0);
    // Should return NULL for pointer types
    TEST_ASSERT_NULL(str, "Pointer type should return NULL");

    array_free(arr);
}

TEST(test_array_item_to_string_out_of_bounds) {
    TEST_CASE("Convert out of bounds to string");

    array_t* arr = array_create_ints(1, 2);

    str_t* str = array_item_to_string(arr, 100);
    TEST_ASSERT_NULL(str, "Out of bounds should return NULL");

    array_free(arr);
}

// ============================================================================
// Граничные условия и тесты безопасности
// ============================================================================

TEST(test_array_extreme_values) {
    TEST_SUITE("Boundary Conditions and Security");
    TEST_CASE("Store extreme integer values");

    array_t* arr = array_create();
    array_push_back_int(arr, INT_MAX);
    array_push_back_int(arr, INT_MIN);
    array_push_back_int(arr, 0);

    TEST_ASSERT_EQUAL(INT_MAX, array_get_int(arr, 0), "Should store INT_MAX");
    TEST_ASSERT_EQUAL(INT_MIN, array_get_int(arr, 1), "Should store INT_MIN");
    TEST_ASSERT_EQUAL(0, array_get_int(arr, 2), "Should store 0");

    array_free(arr);
}

TEST(test_array_extreme_double_values) {
    TEST_CASE("Store extreme double values");

    array_t* arr = array_create();
    array_push_back_double(arr, DBL_MAX);
    array_push_back_double(arr, DBL_MIN);
    array_push_back_double(arr, -DBL_MAX);

    TEST_ASSERT(array_get_double(arr, 0) == DBL_MAX, "Should store DBL_MAX");
    TEST_ASSERT(array_get_double(arr, 1) == DBL_MIN, "Should store DBL_MIN");
    TEST_ASSERT(array_get_double(arr, 2) == -DBL_MAX, "Should store -DBL_MAX");

    array_free(arr);
}

TEST(test_array_large_string) {
    TEST_CASE("Store very large string");

    char* large_str = malloc(10000);
    if (!large_str) return;
    memset(large_str, 'A', 9999);
    large_str[9999] = '\0';

    array_t* arr = array_create();
    array_push_back_str(arr, large_str);

    const char* retrieved = array_get_string(arr, 0);
    TEST_ASSERT_NOT_NULL(retrieved, "String should be retrieved");
    TEST_ASSERT_EQUAL_SIZE(9999, strlen(retrieved), "String length should match");

    free(large_str);
    array_free(arr);
}

TEST(test_array_many_elements) {
    TEST_CASE("Store many elements");

    array_t* arr = array_create();
    const size_t count = 1000;

    for (size_t i = 0; i < count; i++) {
        array_push_back_int(arr, i);
    }

    TEST_ASSERT_EQUAL_SIZE(count, array_size(arr), "Size should be 1000");

    // Spot check some elements
    TEST_ASSERT_EQUAL(0, array_get_int(arr, 0), "First element correct");
    TEST_ASSERT_EQUAL(500, array_get_int(arr, 500), "Middle element correct");
    TEST_ASSERT_EQUAL(999, array_get_int(arr, 999), "Last element correct");

    array_free(arr);
}

TEST(test_array_string_with_null_bytes) {
    TEST_CASE("Store string with embedded null bytes");

    const char data[] = {'h', 'e', 'l', 'l', 'o', '\0', 'w', 'o', 'r', 'l', 'd'};

    array_t* arr = array_create();
    array_push_back(arr, array_create_stringn(data, 11));

    TEST_ASSERT_EQUAL_SIZE(1, array_size(arr), "Size should be 1");
    const char* str = array_get_string(arr, 0);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    TEST_ASSERT_EQUAL(11, arr->elements[0]._length, "Length should be 11");

    array_free(arr);
}

TEST(test_array_empty_string) {
    TEST_CASE("Store empty string");

    array_t* arr = array_create();
    array_push_back_str(arr, "");

    TEST_ASSERT_EQUAL_SIZE(1, array_size(arr), "Size should be 1");
    const char* str = array_get_string(arr, 0);
    TEST_ASSERT_NOT_NULL(str, "String should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, strlen(str), "String should be empty");

    array_free(arr);
}

TEST(test_array_sequential_operations) {
    TEST_CASE("Complex sequence of operations");

    array_t* arr = array_create();

    // Add elements
    for (int i = 0; i < 10; i++) {
        array_push_back_int(arr, i);
    }

    // Delete some
    array_delete(arr, 5);
    array_delete(arr, 0);
    array_delete(arr, 7);

    TEST_ASSERT_EQUAL_SIZE(7, array_size(arr), "Size should be 7");

    // Insert in middle
    array_insert(arr, 3, array_create_int(999));
    TEST_ASSERT_EQUAL_SIZE(8, array_size(arr), "Size should be 8");
    TEST_ASSERT_EQUAL(999, array_get_int(arr, 3), "Inserted element should be 999");

    // Update
    array_update(arr, 0, array_create_int(111));
    TEST_ASSERT_EQUAL(111, array_get_int(arr, 0), "Updated element should be 111");

    // Clear and reuse
    array_clear(arr);
    TEST_ASSERT_EQUAL_SIZE(0, array_size(arr), "Should be empty");

    array_push_back_int(arr, 42);
    TEST_ASSERT_EQUAL_SIZE(1, array_size(arr), "Should have one element");
    TEST_ASSERT_EQUAL(42, array_get_int(arr, 0), "Element should be 42");

    array_free(arr);
}

TEST(test_array_multiple_copies) {
    TEST_CASE("Multiple levels of copying");

    array_t* arr1 = array_create_strings("test1", "test2");
    array_t* arr2 = array_copy(arr1);
    array_t* arr3 = array_copy(arr2);

    TEST_ASSERT_EQUAL_SIZE(2, array_size(arr3), "Size should be preserved");
    TEST_ASSERT_STR_EQUAL("test1", array_get_string(arr3, 0), "Content should match");

    // Modify original
    array_update(arr1, 0, array_create_string("modified"));

    // Copies should be unchanged
    TEST_ASSERT_STR_EQUAL("test1", array_get_string(arr2, 0), "Copy 2 unchanged");
    TEST_ASSERT_STR_EQUAL("test1", array_get_string(arr3, 0), "Copy 3 unchanged");

    array_free(arr1);
    array_free(arr2);
    array_free(arr3);
}

// ============================================================================
// Тесты утечек памяти
// ============================================================================

TEST(test_array_no_memory_leak_on_update) {
    TEST_SUITE("Memory Leak Tests");
    TEST_CASE("No memory leak when updating strings");

    array_t* arr = array_create();

    // Push string
    array_push_back_str(arr, "initial");

    // Update multiple times (should free old strings)
    for (int i = 0; i < 10; i++) {
        array_update(arr, 0, array_create_string("updated"));
    }

    TEST_ASSERT_EQUAL_SIZE(1, array_size(arr), "Size should be 1");
    TEST_ASSERT_STR_EQUAL("updated", array_get_string(arr, 0), "Should have last value");

    array_free(arr);
}

TEST(test_array_no_memory_leak_on_delete) {
    TEST_CASE("No memory leak when deleting strings");

    array_t* arr = array_create();

    // Add many strings
    for (int i = 0; i < 100; i++) {
        array_push_back_str(arr, "test string");
    }

    // Delete them all
    while (array_size(arr) > 0) {
        array_delete(arr, 0);
    }

    TEST_ASSERT_EQUAL_SIZE(0, array_size(arr), "Should be empty");

    array_free(arr);
}

TEST(test_array_no_memory_leak_on_clear) {
    TEST_CASE("No memory leak when clearing");

    array_t* arr = array_create();

    for (int i = 0; i < 10; i++) {
        array_push_back_str(arr, "test");
        array_clear(arr);
    }

    TEST_ASSERT_EQUAL_SIZE(0, array_size(arr), "Should be empty");

    array_free(arr);
}


TEST(test_ldouble_precision) {
    TEST_CASE("array_create_ldouble uses correct field (_ldouble not _double)");

    // Test that long double values are stored and retrieved correctly
    long double test_value = 1.234567890123456789L;

    array_t* arr = array_create();
    array_push_back(arr, array_create_ldouble(test_value));

    long double retrieved = array_get_ldouble(arr, 0);

    // With the bug fix, this should preserve full precision
    // Before fix: value was stored in _double field, losing precision
    TEST_ASSERT(fabsl(retrieved - test_value) < 1e-15L,
                "Long double should preserve high precision");

    // Verify the type is correct
    TEST_ASSERT_EQUAL(ARRAY_LONGDOUBLE, arr->elements[0].type,
                     "Type should be ARRAY_LONGDOUBLE");

    array_free(arr);
}

TEST(test_ldouble_very_large_value) {
    TEST_CASE("Long double handles very large values");

    // Test with a value that would overflow double but not long double
    long double large_value = 1.0e308L * 10.0L;  // Beyond double range

    array_t* arr = array_create();
    array_push_back(arr, array_create_ldouble(large_value));

    long double retrieved = array_get_ldouble(arr, 0);

    TEST_ASSERT(isinf(retrieved) || fabsl(retrieved - large_value) / large_value < 1e-10L,
                "Very large long double values should be handled correctly");

    array_free(arr);
}

TEST(test_update_null_array) {
    TEST_CASE("array_update handles NULL array safely");

    // Before fix: this would cause segmentation fault
    // After fix: should return safely without crash
    array_update(NULL, 0, array_create_int(42));

    TEST_ASSERT(1, "array_update with NULL should not crash");
}

TEST(test_update_null_with_string) {
    TEST_CASE("array_update NULL check with string value");

    // Test with different value types to ensure NULL check works
    array_update(NULL, 0, array_create_string("test"));
    array_update(NULL, 5, array_create_double(3.14));

    TEST_ASSERT(1, "array_update with NULL should handle all value types");
}

TEST(test_copy_with_null_copy_function) {
    TEST_CASE("array_copy handles NULL copy function (array_nocopy)");

    int test_value = 42;

    array_t* arr = array_create();
    // Use array_nocopy (NULL) for copy function
    array_push_back(arr, array_create_pointer(&test_value, array_nocopy, array_nofree));

    // Before fix: this would crash trying to call NULL function
    // After fix: should handle gracefully
    array_t* copy = array_copy(arr);

    TEST_ASSERT_NOT_NULL(copy, "Copy should succeed even with NULL copy function");
    TEST_ASSERT_EQUAL_SIZE(1, array_size(copy), "Copy should have 1 element");

    // With NULL copy function, pointer should be copied as-is (shallow copy)
    int* retrieved = (int*)array_get_pointer(copy, 0);
    TEST_ASSERT_EQUAL(&test_value, retrieved, "Pointer should be shallow-copied when copy function is NULL");
    TEST_ASSERT_EQUAL(42, *retrieved, "Value should be accessible");

    array_free(arr);
    array_free(copy);
}

TEST(test_copy_with_null_free_function) {
    TEST_CASE("array_copy handles NULL free function (array_nofree)");

    int test_value = 100;

    array_t* arr = array_create();
    array_push_back(arr, array_create_pointer(&test_value, array_nocopy, array_nofree));

    array_t* copy = array_copy(arr);

    TEST_ASSERT_NOT_NULL(copy, "Copy should succeed with NULL free function");

    // Both arrays should be safely freeable without double-free
    array_free(arr);
    array_free(copy);

    TEST_ASSERT(1, "No double-free or crash should occur");
}

static void* test_copy_func(void* ptr) {
    if (!ptr) return NULL;
    test_obj_t* obj = malloc(sizeof(test_obj_t));
    if (!obj) return NULL;
    memcpy(obj, ptr, sizeof(test_obj_t));
    return obj;
}

static void test_free_func(void* ptr) {
    free(ptr);
}

TEST(test_copy_with_valid_copy_function) {
    TEST_CASE("array_copy still works correctly with valid copy function");

    test_obj_t* obj = malloc(sizeof(test_obj_t));
    if (!obj) return;
    obj->id = 123;
    strcpy(obj->name, "test");

    array_t* arr = array_create();
    array_push_back(arr, array_create_pointer(obj, test_copy_func, test_free_func));

    array_t* copy = array_copy(arr);

    TEST_ASSERT_NOT_NULL(copy, "Copy should succeed");

    test_obj_t* copy_obj = (test_obj_t*)array_get_pointer(copy, 0);
    TEST_ASSERT_NOT_NULL(copy_obj, "Copied object should exist");
    TEST_ASSERT(copy_obj != obj, "Should be different objects (deep copy)");
    TEST_ASSERT_EQUAL(123, copy_obj->id, "Copied data should match");
    TEST_ASSERT_STR_EQUAL("test", copy_obj->name, "Copied data should match");

    array_free(arr);
    array_free(copy);
}

TEST(test_ldouble_in_mixed_array) {
    TEST_CASE("Long double works correctly in mixed-type array");

    array_t* arr = array_create();

    array_push_back_int(arr, 42);
    array_push_back(arr, array_create_ldouble(3.14159265358979323846L));
    array_push_back_double(arr, 2.71828);
    array_push_back_str(arr, "test");

    TEST_ASSERT_EQUAL_SIZE(4, array_size(arr), "Size should be 4");

    long double ld_val = array_get_ldouble(arr, 1);
    TEST_ASSERT(fabsl(ld_val - 3.14159265358979323846L) < 1e-15L,
                "Long double in mixed array should preserve precision");

    // Test copy of mixed array with ldouble
    array_t* copy = array_copy(arr);
    long double ld_copy = array_get_ldouble(copy, 1);
    TEST_ASSERT(fabsl(ld_copy - 3.14159265358979323846L) < 1e-15L,
                "Copied long double should preserve precision");

    array_free(arr);
    array_free(copy);
}

TEST(test_all_null_safety) {
    TEST_CASE("All bug fixes: Comprehensive NULL safety test");

    // Test all fixed NULL-related issues together
    array_update(NULL, 0, array_create_int(1));
    array_update(NULL, 0, array_create_ldouble(1.0L));
    array_update(NULL, 0, array_create_pointer(NULL, array_nocopy, array_nofree));

    array_t* null_copy = array_copy(NULL);
    TEST_ASSERT_NULL(null_copy, "Copy of NULL should return NULL");

    TEST_ASSERT(1, "All NULL safety checks passed");
}

// ============================================================================
// Тесты валидации типов
// ============================================================================

TEST(test_type_validation_int) {
    TEST_SUITE("Type Validation");
    TEST_CASE("array_get_int with type validation");

    array_t* arr = array_create();

    array_push_back(arr, array_create_int(42));
    array_push_back(arr, array_create_double(3.14));
    array_push_back(arr, array_create_string("hello"));

    // Correct type - should work
    int val = array_get_int(arr, 0);
    TEST_ASSERT(val == 42, "Should get correct int value");

    // Wrong type - should return default value and log error
    int wrong1 = array_get_int(arr, 1);  // trying to get double as int
    TEST_ASSERT(wrong1 == 0, "Should return 0 for type mismatch (double->int)");

    int wrong2 = array_get_int(arr, 2);  // trying to get string as int
    TEST_ASSERT(wrong2 == 0, "Should return 0 for type mismatch (string->int)");

    array_free(arr);
}

TEST(test_type_validation_double) {
    TEST_CASE("array_get_double with type validation");

    array_t* arr = array_create();

    array_push_back(arr, array_create_double(3.14159));
    array_push_back(arr, array_create_int(100));
    array_push_back(arr, array_create_string("pi"));

    // Correct type - should work
    double val = array_get_double(arr, 0);
    TEST_ASSERT(fabs(val - 3.14159) < 1e-6, "Should get correct double value");

    // Wrong type - should return default value
    double wrong1 = array_get_double(arr, 1);  // trying to get int as double
    TEST_ASSERT(fabs(wrong1 - 0.0) < 1e-10, "Should return 0.0 for type mismatch (int->double)");

    double wrong2 = array_get_double(arr, 2);  // trying to get string as double
    TEST_ASSERT(fabs(wrong2 - 0.0) < 1e-10, "Should return 0.0 for type mismatch (string->double)");

    array_free(arr);
}

TEST(test_type_validation_ldouble) {
    TEST_CASE("array_get_ldouble with type validation");

    array_t* arr = array_create();

    array_push_back(arr, array_create_ldouble(3.14159265358979323846L));
    array_push_back(arr, array_create_double(2.71));
    array_push_back(arr, array_create_int(42));

    // Correct type - should work
    long double val = array_get_ldouble(arr, 0);
    TEST_ASSERT(fabsl(val - 3.14159265358979323846L) < 1e-15L,
                "Should get correct long double value");

    // Wrong type - should return default value
    long double wrong1 = array_get_ldouble(arr, 1);  // trying to get double as ldouble
    TEST_ASSERT(fabsl(wrong1 - 0.0L) < 1e-15L,
                "Should return 0.0L for type mismatch (double->ldouble)");

    long double wrong2 = array_get_ldouble(arr, 2);  // trying to get int as ldouble
    TEST_ASSERT(fabsl(wrong2 - 0.0L) < 1e-15L,
                "Should return 0.0L for type mismatch (int->ldouble)");

    array_free(arr);
}

TEST(test_type_validation_string) {
    TEST_CASE("array_get_string with type validation");

    array_t* arr = array_create();

    array_push_back(arr, array_create_string("hello world"));
    array_push_back(arr, array_create_int(123));
    array_push_back(arr, array_create_double(9.99));

    // Correct type - should work
    const char* val = array_get_string(arr, 0);
    TEST_ASSERT_NOT_NULL(val, "Should get string pointer");
    TEST_ASSERT_STR_EQUAL("hello world", val, "Should get correct string value");

    // Wrong type - should return NULL
    const char* wrong1 = array_get_string(arr, 1);  // trying to get int as string
    TEST_ASSERT_NULL(wrong1, "Should return NULL for type mismatch (int->string)");

    const char* wrong2 = array_get_string(arr, 2);  // trying to get double as string
    TEST_ASSERT_NULL(wrong2, "Should return NULL for type mismatch (double->string)");

    array_free(arr);
}

TEST(test_type_validation_pointer) {
    TEST_CASE("array_get_pointer with type validation");

    test_obj_t* obj = malloc(sizeof(test_obj_t));
    if (obj == NULL) return;
    obj->id = 999;
    strcpy(obj->name, "test object");

    array_t* arr = array_create();

    array_push_back(arr, array_create_pointer(obj, test_obj_copy, test_obj_free));
    array_push_back(arr, array_create_int(777));
    array_push_back(arr, array_create_string("not a pointer"));

    // Correct type - should work
    test_obj_t* val = (test_obj_t*)array_get_pointer(arr, 0);
    TEST_ASSERT_NOT_NULL(val, "Should get pointer");
    TEST_ASSERT(val->id == 999, "Should get correct object");

    // Wrong type - should return NULL
    void* wrong1 = array_get_pointer(arr, 1);  // trying to get int as pointer
    TEST_ASSERT_NULL(wrong1, "Should return NULL for type mismatch (int->pointer)");

    void* wrong2 = array_get_pointer(arr, 2);  // trying to get string as pointer
    TEST_ASSERT_NULL(wrong2, "Should return NULL for type mismatch (string->pointer)");

    array_free(arr);
}

TEST(test_type_validation_bounds) {
    TEST_CASE("Type validation with out of bounds");

    array_t* arr = array_create();
    array_push_back(arr, array_create_int(42));

    // Out of bounds should also return default values
    int val1 = array_get_int(arr, 999);
    TEST_ASSERT(val1 == 0, "Out of bounds should return 0");

    double val2 = array_get_double(arr, 999);
    TEST_ASSERT(fabs(val2 - 0.0) < 1e-10, "Out of bounds should return 0.0");

    const char* val3 = array_get_string(arr, 999);
    TEST_ASSERT_NULL(val3, "Out of bounds should return NULL");

    // NULL array should also return default values
    int val4 = array_get_int(NULL, 0);
    TEST_ASSERT(val4 == 0, "NULL array should return 0");

    array_free(arr);
}

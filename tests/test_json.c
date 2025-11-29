#include "framework.h"
#include "json.h"
#include <string.h>
#include <math.h>

// ============================================================================
// Тесты парсинга простых типов
// ============================================================================

TEST(test_json_parse_null) {
    TEST_CASE("Parse null value");

    json_doc_t* doc = json_parse("null");
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_null(root), "Token should be null type");

    json_free(doc);
    json_manager_free();
}

TEST(test_json_parse_bool) {
    TEST_CASE("Parse boolean values");

    json_doc_t* doc1 = json_parse("true");
    TEST_ASSERT_NOT_NULL(doc1, "Document for 'true' should be created");

    json_token_t* root1 = json_root(doc1);
    TEST_ASSERT_NOT_NULL(root1, "Root token for 'true' should exist");
    TEST_ASSERT(json_is_bool(root1), "Token should be bool type");
    TEST_ASSERT_EQUAL(1, json_bool(root1), "Bool value should be true");

    json_free(doc1);

    json_doc_t* doc2 = json_parse("false");
    TEST_ASSERT_NOT_NULL(doc2, "Document for 'false' should be created");

    json_token_t* root2 = json_root(doc2);
    TEST_ASSERT_NOT_NULL(root2, "Root token for 'false' should exist");
    TEST_ASSERT(json_is_bool(root2), "Token should be bool type");
    TEST_ASSERT_EQUAL(0, json_bool(root2), "Bool value should be false");

    json_free(doc2);
    json_manager_free();
}

TEST(test_json_parse_number) {
    TEST_CASE("Parse number values");

    // Integer
    json_doc_t* doc1 = json_parse("42");
    TEST_ASSERT_NOT_NULL(doc1, "Document should be created");

    json_token_t* root1 = json_root(doc1);
    TEST_ASSERT_NOT_NULL(root1, "Root token should exist");
    TEST_ASSERT(json_is_number(root1), "Token should be number type");

    int ok = 0;
    int val = json_int(root1, &ok);
    TEST_ASSERT_EQUAL(1, ok, "Integer conversion should succeed");
    TEST_ASSERT_EQUAL(42, val, "Integer value should be 42");

    json_free(doc1);

    // Negative number
    json_doc_t* doc2 = json_parse("-123");
    TEST_ASSERT_NOT_NULL(doc2, "Document for negative number should be created");

    json_token_t* root2 = json_root(doc2);
    ok = 0;
    int val2 = json_int(root2, &ok);
    TEST_ASSERT_EQUAL(1, ok, "Integer conversion should succeed");
    TEST_ASSERT_EQUAL(-123, val2, "Integer value should be -123");

    json_free(doc2);

    // Float
    json_doc_t* doc3 = json_parse("3.14159");
    TEST_ASSERT_NOT_NULL(doc3, "Document for float should be created");

    json_token_t* root3 = json_root(doc3);
    ok = 0;
    double dval = json_double(root3, &ok);
    TEST_ASSERT_EQUAL(1, ok, "Double conversion should succeed");
    TEST_ASSERT(fabs(dval - 3.14159) < 0.00001, "Double value should be approximately 3.14159");

    json_free(doc3);
    json_manager_free();
}

TEST(test_json_parse_string) {
    TEST_CASE("Parse string values");

    json_doc_t* doc = json_parse("\"Hello, World!\"");
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_string(root), "Token should be string type");

    const char* str = json_string(root);
    TEST_ASSERT_NOT_NULL(str, "String value should not be NULL");
    TEST_ASSERT_STR_EQUAL("Hello, World!", str, "String value should match");

    size_t len = json_string_size(root);
    TEST_ASSERT_EQUAL_SIZE(13, len, "String length should be 13");

    json_free(doc);
    json_manager_free();
}

// ============================================================================
// Тесты парсинга объектов
// ============================================================================

TEST(test_json_parse_empty_object) {
    TEST_CASE("Parse empty object");

    json_doc_t* doc = json_parse("{}");
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_object(root), "Token should be object type");
    TEST_ASSERT_EQUAL(0, json_object_size(root), "Object should be empty");

    json_free(doc);
    json_manager_free();
}

TEST(test_json_parse_simple_object) {
    TEST_CASE("Parse simple object");

    json_doc_t* doc = json_parse("{\"name\": \"John\", \"age\": 30}");
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_object(root), "Token should be object type");
    TEST_ASSERT_EQUAL(2, json_object_size(root), "Object should have 2 keys");

    json_token_t* name = json_object_get(root, "name");
    TEST_ASSERT_NOT_NULL(name, "Name key should exist");
    TEST_ASSERT(json_is_string(name), "Name should be string");
    TEST_ASSERT_STR_EQUAL("John", json_string(name), "Name value should be John");

    json_token_t* age = json_object_get(root, "age");
    TEST_ASSERT_NOT_NULL(age, "Age key should exist");
    TEST_ASSERT(json_is_number(age), "Age should be number");

    int ok = 0;
    int age_val = json_int(age, &ok);
    TEST_ASSERT_EQUAL(1, ok, "Integer conversion should succeed");
    TEST_ASSERT_EQUAL(30, age_val, "Age value should be 30");

    json_free(doc);
    json_manager_free();
}

TEST(test_json_parse_nested_object) {
    TEST_CASE("Parse nested object");

    const char* json_str = "{\"person\": {\"name\": \"Alice\", \"age\": 25}}";
    json_doc_t* doc = json_parse(json_str);
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_object(root), "Token should be object type");

    json_token_t* person = json_object_get(root, "person");
    TEST_ASSERT_NOT_NULL(person, "Person key should exist");
    TEST_ASSERT(json_is_object(person), "Person should be object");

    json_token_t* name = json_object_get(person, "name");
    TEST_ASSERT_NOT_NULL(name, "Name key should exist");
    TEST_ASSERT_STR_EQUAL("Alice", json_string(name), "Name should be Alice");

    json_free(doc);
    json_manager_free();
}

// ============================================================================
// Тесты парсинга массивов
// ============================================================================

TEST(test_json_parse_empty_array) {
    TEST_CASE("Parse empty array");

    json_doc_t* doc = json_parse("[]");
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_array(root), "Token should be array type");
    TEST_ASSERT_EQUAL(0, json_array_size(root), "Array should be empty");

    json_free(doc);
    json_manager_free();
}

TEST(test_json_parse_simple_array) {
    TEST_CASE("Parse simple array");

    json_doc_t* doc = json_parse("[1, 2, 3, 4, 5]");
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_array(root), "Token should be array type");
    TEST_ASSERT_EQUAL(5, json_array_size(root), "Array should have 5 elements");

    for (int i = 0; i < 5; i++) {
        json_token_t* elem = json_array_get(root, i);
        TEST_ASSERT_NOT_NULL(elem, "Array element should exist");
        TEST_ASSERT(json_is_number(elem), "Element should be number");

        int ok = 0;
        int val = json_int(elem, &ok);
        TEST_ASSERT_EQUAL(1, ok, "Integer conversion should succeed");
        TEST_ASSERT_EQUAL(i + 1, val, "Element value should match");
    }

    json_free(doc);
    json_manager_free();
}

TEST(test_json_parse_mixed_array) {
    TEST_CASE("Parse array with mixed types");

    json_doc_t* doc = json_parse("[\"hello\", 42, true, null]");
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT_EQUAL(4, json_array_size(root), "Array should have 4 elements");

    json_token_t* elem0 = json_array_get(root, 0);
    TEST_ASSERT(json_is_string(elem0), "First element should be string");
    TEST_ASSERT_STR_EQUAL("hello", json_string(elem0), "String value should match");

    json_token_t* elem1 = json_array_get(root, 1);
    TEST_ASSERT(json_is_number(elem1), "Second element should be number");

    json_token_t* elem2 = json_array_get(root, 2);
    TEST_ASSERT(json_is_bool(elem2), "Third element should be bool");
    TEST_ASSERT_EQUAL(1, json_bool(elem2), "Bool value should be true");

    json_token_t* elem3 = json_array_get(root, 3);
    TEST_ASSERT(json_is_null(elem3), "Fourth element should be null");

    json_free(doc);
    json_manager_free();
}

// ============================================================================
// Тесты создания токенов
// ============================================================================

TEST(test_json_create_primitives) {
    TEST_CASE("Create primitive tokens");

    json_manager_init(json_manager_create());

    json_token_t* tok_null = json_create_null();
    TEST_ASSERT_NOT_NULL(tok_null, "Null token should be created");
    TEST_ASSERT(json_is_null(tok_null), "Token should be null type");

    json_token_t* tok_bool = json_create_bool(1);
    TEST_ASSERT_NOT_NULL(tok_bool, "Bool token should be created");
    TEST_ASSERT(json_is_bool(tok_bool), "Token should be bool type");
    TEST_ASSERT_EQUAL(1, json_bool(tok_bool), "Bool value should be true");

    json_token_t* tok_num = json_create_number(123.45);
    TEST_ASSERT_NOT_NULL(tok_num, "Number token should be created");
    TEST_ASSERT(json_is_number(tok_num), "Token should be number type");

    json_token_t* tok_str = json_create_string("Test");
    TEST_ASSERT_NOT_NULL(tok_str, "String token should be created");
    TEST_ASSERT(json_is_string(tok_str), "Token should be string type");
    TEST_ASSERT_STR_EQUAL("Test", json_string(tok_str), "String value should match");

    json_token_free(tok_null);
    json_token_free(tok_bool);
    json_token_free(tok_num);
    json_token_free(tok_str);

    json_manager_free();
}

TEST(test_json_create_object_from_scratch) {
    TEST_CASE("Create object from scratch");

    json_doc_t* doc = json_root_create_object();
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_object(root), "Token should be object type");
    TEST_ASSERT_EQUAL(0, json_object_size(root), "Object should be empty");

    // Add properties
    json_token_t* name = json_create_string("Bob");
    int result = json_object_set(root, "name", name);
    TEST_ASSERT_EQUAL(1, result, "Setting name should succeed");
    TEST_ASSERT_EQUAL(1, json_object_size(root), "Object should have 1 key");

    json_token_t* age = json_create_number(35);
    result = json_object_set(root, "age", age);
    TEST_ASSERT_EQUAL(1, result, "Setting age should succeed");
    TEST_ASSERT_EQUAL(2, json_object_size(root), "Object should have 2 keys");

    // Verify values
    json_token_t* retrieved_name = json_object_get(root, "name");
    TEST_ASSERT_NOT_NULL(retrieved_name, "Name should be retrievable");
    TEST_ASSERT_STR_EQUAL("Bob", json_string(retrieved_name), "Name value should match");

    json_token_t* retrieved_age = json_object_get(root, "age");
    TEST_ASSERT_NOT_NULL(retrieved_age, "Age should be retrievable");

    json_free(doc);
    json_manager_free();
}

TEST(test_json_create_array_from_scratch) {
    TEST_CASE("Create array from scratch");

    json_doc_t* doc = json_root_create_array();
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT_NOT_NULL(root, "Root token should exist");
    TEST_ASSERT(json_is_array(root), "Token should be array type");
    TEST_ASSERT_EQUAL(0, json_array_size(root), "Array should be empty");

    // Append elements
    json_token_t* elem1 = json_create_number(10);
    int result = json_array_append(root, elem1);
    TEST_ASSERT_EQUAL(1, result, "Append should succeed");
    TEST_ASSERT_EQUAL(1, json_array_size(root), "Array should have 1 element");

    json_token_t* elem2 = json_create_number(20);
    result = json_array_append(root, elem2);
    TEST_ASSERT_EQUAL(1, result, "Append should succeed");
    TEST_ASSERT_EQUAL(2, json_array_size(root), "Array should have 2 elements");

    // Prepend element
    json_token_t* elem0 = json_create_number(5);
    result = json_array_prepend(root, elem0);
    TEST_ASSERT_EQUAL(1, result, "Prepend should succeed");
    TEST_ASSERT_EQUAL(3, json_array_size(root), "Array should have 3 elements");

    // Verify values
    json_token_t* retrieved0 = json_array_get(root, 0);
    TEST_ASSERT_NOT_NULL(retrieved0, "First element should exist");
    int ok = 0;
    int val = json_int(retrieved0, &ok);
    TEST_ASSERT_EQUAL(5, val, "First element should be 5");

    json_free(doc);
    json_manager_free();
}

// ============================================================================
// Тесты работы с объектами
// ============================================================================

TEST(test_json_object_operations) {
    TEST_CASE("Object operations: set, get, remove, clear");

    json_doc_t* doc = json_root_create_object();
    json_token_t* root = json_root(doc);

    // Set multiple keys
    json_object_set(root, "key1", json_create_string("value1"));
    json_object_set(root, "key2", json_create_number(100));
    json_object_set(root, "key3", json_create_bool(0));

    TEST_ASSERT_EQUAL(3, json_object_size(root), "Object should have 3 keys");

    // Get non-existent key
    json_token_t* nonexistent = json_object_get(root, "nonexistent");
    TEST_ASSERT_NULL(nonexistent, "Non-existent key should return NULL");

    // Remove key
    int result = json_object_remove(root, "key2");
    TEST_ASSERT_EQUAL(1, result, "Remove should succeed");
    TEST_ASSERT_EQUAL(2, json_object_size(root), "Object should have 2 keys");

    json_token_t* removed = json_object_get(root, "key2");
    TEST_ASSERT_NULL(removed, "Removed key should not be found");

    // Clear object
    result = json_object_clear(root);
    TEST_ASSERT_EQUAL(1, result, "Clear should succeed");
    TEST_ASSERT_EQUAL(0, json_object_size(root), "Object should be empty");

    json_free(doc);
    json_manager_free();
}

TEST(test_json_object_replace_value) {
    TEST_CASE("Replace value in object");

    json_doc_t* doc = json_root_create_object();
    json_token_t* root = json_root(doc);

    json_object_set(root, "key", json_create_string("old"));

    json_token_t* val = json_object_get(root, "key");
    TEST_ASSERT_STR_EQUAL("old", json_string(val), "Value should be 'old'");

    // Replace with new value
    json_object_set(root, "key", json_create_string("new"));
    TEST_ASSERT_EQUAL(1, json_object_size(root), "Object should still have 1 key");

    json_token_t* new_val = json_object_get(root, "key");
    TEST_ASSERT_STR_EQUAL("new", json_string(new_val), "Value should be 'new'");

    json_free(doc);
    json_manager_free();
}

// ============================================================================
// Тесты работы с массивами
// ============================================================================

TEST(test_json_array_operations) {
    TEST_CASE("Array operations: append, prepend, get, erase, clear");

    json_doc_t* doc = json_root_create_array();
    json_token_t* root = json_root(doc);

    // Append elements
    json_array_append(root, json_create_number(1));
    json_array_append(root, json_create_number(2));
    json_array_append(root, json_create_number(3));

    TEST_ASSERT_EQUAL(3, json_array_size(root), "Array should have 3 elements");

    // Prepend element
    json_array_prepend(root, json_create_number(0));
    TEST_ASSERT_EQUAL(4, json_array_size(root), "Array should have 4 elements");

    // Verify order
    int ok = 0;
    json_token_t* elem = json_array_get(root, 0);
    int val = json_int(elem, &ok);
    TEST_ASSERT_EQUAL(0, val, "First element should be 0");

    elem = json_array_get(root, 3);
    val = json_int(elem, &ok);
    TEST_ASSERT_EQUAL(3, val, "Last element should be 3");

    // Erase element
    int result = json_array_erase(root, 1, 1);
    TEST_ASSERT_EQUAL(1, result, "Erase should succeed");
    TEST_ASSERT_EQUAL(3, json_array_size(root), "Array should have 3 elements");

    // Clear array
    result = json_array_clear(root);
    TEST_ASSERT_EQUAL(1, result, "Clear should succeed");
    TEST_ASSERT_EQUAL(0, json_array_size(root), "Array should be empty");

    json_free(doc);
    json_manager_free();
}

TEST(test_json_array_insert_at) {
    TEST_CASE("Insert element at specific position");

    json_doc_t* doc = json_root_create_array();
    json_token_t* root = json_root(doc);

    json_array_append(root, json_create_number(1));
    json_array_append(root, json_create_number(3));

    // Insert at position 1
    int result = json_array_append_to(root, 1, json_create_number(2));
    TEST_ASSERT_EQUAL(1, result, "Insert should succeed");
    TEST_ASSERT_EQUAL(3, json_array_size(root), "Array should have 3 elements");

    // Verify order
    int ok = 0;
    for (int i = 0; i < 3; i++) {
        json_token_t* elem = json_array_get(root, i);
        int val = json_int(elem, &ok);
        TEST_ASSERT_EQUAL(i + 1, val, "Element order should be correct");
    }

    json_free(doc);
    json_manager_free();
}

// ============================================================================
// Тесты итераторов
// ============================================================================

TEST(test_json_iterator_array) {
    TEST_CASE("Iterate over array");

    json_doc_t* doc = json_parse("[10, 20, 30]");
    json_token_t* root = json_root(doc);

    int count = 0;
    int sum = 0;

    json_it_t it = json_init_it(root);
    while (!json_end_it(&it)) {
        json_token_t* value = json_it_value(&it);
        TEST_ASSERT_NOT_NULL(value, "Iterator value should not be NULL");

        int ok = 0;
        int val = json_int(value, &ok);
        sum += val;
        count++;

        it = json_next_it(&it);
    }

    TEST_ASSERT_EQUAL(3, count, "Should iterate over 3 elements");
    TEST_ASSERT_EQUAL(60, sum, "Sum should be 60");

    json_free(doc);
    json_manager_free();
}

TEST(test_json_iterator_object) {
    TEST_CASE("Iterate over object");

    json_doc_t* doc = json_parse("{\"a\": 1, \"b\": 2, \"c\": 3}");
    json_token_t* root = json_root(doc);

    int count = 0;

    json_it_t it = json_init_it(root);
    while (!json_end_it(&it)) {
        const char* key = (const char*)json_it_key(&it);
        TEST_ASSERT_NOT_NULL(key, "Iterator key should not be NULL");

        json_token_t* value = json_it_value(&it);
        TEST_ASSERT_NOT_NULL(value, "Iterator value should not be NULL");
        TEST_ASSERT(json_is_number(value), "Value should be number");

        count++;
        it = json_next_it(&it);
    }

    TEST_ASSERT_EQUAL(3, count, "Should iterate over 3 keys");

    json_free(doc);
    json_manager_free();
}

// ============================================================================
// Тесты stringify
// ============================================================================

TEST(test_json_stringify_primitives) {
    TEST_CASE("Stringify primitive values");

    json_doc_t* doc1 = json_parse("null");
    const char* str1 = json_stringify(doc1);
    TEST_ASSERT_NOT_NULL(str1, "Stringify should not return NULL");
    TEST_ASSERT_STR_EQUAL("null", str1, "Stringified null should match");
    json_free(doc1);

    json_doc_t* doc2 = json_parse("true");
    const char* str2 = json_stringify(doc2);
    TEST_ASSERT_STR_EQUAL("true", str2, "Stringified bool should match");
    json_free(doc2);

    json_doc_t* doc3 = json_parse("42");
    const char* str3 = json_stringify(doc3);
    TEST_ASSERT_STR_EQUAL("42", str3, "Stringified number should match");
    json_free(doc3);

    json_doc_t* doc4 = json_parse("\"hello\"");
    const char* str4 = json_stringify(doc4);
    TEST_ASSERT_STR_EQUAL("\"hello\"", str4, "Stringified string should match");
    json_free(doc4);
    json_manager_free();
}

TEST(test_json_stringify_object) {
    TEST_CASE("Stringify object");

    json_doc_t* doc = json_root_create_object();
    json_token_t* root = json_root(doc);

    json_object_set(root, "name", json_create_string("Alice"));
    json_object_set(root, "age", json_create_number(30));

    const char* str = json_stringify(doc);
    TEST_ASSERT_NOT_NULL(str, "Stringify should not return NULL");

    // Parse back and verify
    json_doc_t* doc2 = json_parse(str);
    TEST_ASSERT_NOT_NULL(doc2, "Re-parsed document should be valid");

    json_token_t* root2 = json_root(doc2);
    TEST_ASSERT_EQUAL(2, json_object_size(root2), "Object should have 2 keys");

    json_token_t* name = json_object_get(root2, "name");
    TEST_ASSERT_STR_EQUAL("Alice", json_string(name), "Name should match");

    json_free(doc);
    json_free(doc2);
    json_manager_free();
}

TEST(test_json_stringify_array) {
    TEST_CASE("Stringify array");

    json_doc_t* doc = json_root_create_array();
    json_token_t* root = json_root(doc);

    json_array_append(root, json_create_number(1));
    json_array_append(root, json_create_number(2));
    json_array_append(root, json_create_number(3));

    const char* str = json_stringify(doc);
    TEST_ASSERT_NOT_NULL(str, "Stringify should not return NULL");

    // Parse back and verify
    json_doc_t* doc2 = json_parse(str);
    TEST_ASSERT_NOT_NULL(doc2, "Re-parsed document should be valid");

    json_token_t* root2 = json_root(doc2);
    TEST_ASSERT_EQUAL(3, json_array_size(root2), "Array should have 3 elements");

    json_free(doc);
    json_free(doc2);
    json_manager_free();
}

// ============================================================================
// Тесты модификации токенов
// ============================================================================

TEST(test_json_token_set_value) {
    TEST_CASE("Modify token values");

    json_manager_init(json_manager_create());

    json_token_t* token = json_create_null();
    TEST_ASSERT(json_is_null(token), "Token should be null");

    // Change to bool
    json_token_set_bool(token, 1);
    TEST_ASSERT(json_is_bool(token), "Token should be bool");
    TEST_ASSERT_EQUAL(1, json_bool(token), "Bool value should be true");

    // Change to number
    json_token_set_int(token, 42);
    TEST_ASSERT(json_is_number(token), "Token should be number");
    int ok = 0;
    int val = json_int(token, &ok);
    TEST_ASSERT_EQUAL(42, val, "Number value should be 42");

    // Change to string
    json_token_set_string(token, "test");
    TEST_ASSERT(json_is_string(token), "Token should be string");
    TEST_ASSERT_STR_EQUAL("test", json_string(token), "String value should match");

    json_token_free(token);
    json_manager_free();
}

// ============================================================================
// Тесты комплексных структур
// ============================================================================

TEST(test_json_complex_structure) {
    TEST_CASE("Parse and work with complex JSON structure");

    const char* json_str = "{"
        "\"users\": ["
            "{\"name\": \"Alice\", \"age\": 30, \"active\": true},"
            "{\"name\": \"Bob\", \"age\": 25, \"active\": false}"
        "],"
        "\"count\": 2"
    "}";

    json_doc_t* doc = json_parse(json_str);
    TEST_ASSERT_NOT_NULL(doc, "Document should be created");

    json_token_t* root = json_root(doc);
    TEST_ASSERT(json_is_object(root), "Root should be object");

    // Get users array
    json_token_t* users = json_object_get(root, "users");
    TEST_ASSERT_NOT_NULL(users, "Users key should exist");
    TEST_ASSERT(json_is_array(users), "Users should be array");
    TEST_ASSERT_EQUAL(2, json_array_size(users), "Users array should have 2 elements");

    // Get first user
    json_token_t* user0 = json_array_get(users, 0);
    TEST_ASSERT(json_is_object(user0), "First user should be object");

    json_token_t* name0 = json_object_get(user0, "name");
    TEST_ASSERT_STR_EQUAL("Alice", json_string(name0), "First user name should be Alice");

    json_token_t* active0 = json_object_get(user0, "active");
    TEST_ASSERT_EQUAL(1, json_bool(active0), "First user should be active");

    // Get count
    json_token_t* count = json_object_get(root, "count");
    TEST_ASSERT(json_is_number(count), "Count should be number");
    int ok = 0;
    int count_val = json_int(count, &ok);
    TEST_ASSERT_EQUAL(2, count_val, "Count should be 2");

    json_free(doc);
    json_manager_free();
}

// ============================================================================
// Тесты управления памятью
// ============================================================================

TEST(test_json_memory_management) {
    TEST_CASE("Test memory manager operations");

    // Allocate multiple tokens
    json_token_t* tokens[100];
    for (int i = 0; i < 100; i++) {
        tokens[i] = json_token_alloc(JSON_NUMBER);
    }

    // Free half of them
    for (int i = 0; i < 50; i++) {
        json_token_free(tokens[i]);
    }

    // Free remaining tokens
    for (int i = 50; i < 100; i++) {
        json_token_free(tokens[i]);
    }

    // Destroy empty blocks
    json_manager_destroy_empty_blocks();

    json_manager_free();
}

TEST(test_json_document_lifecycle) {
    TEST_CASE("Test document creation and destruction");

    // Create empty document
    json_doc_t* doc = json_create_empty();
    TEST_ASSERT_NOT_NULL(doc, "Empty document should be created");

    // Set root to object
    json_token_t* root = json_create_object();
    json_set_root(doc, root);

    json_token_t* retrieved_root = json_root(doc);
    TEST_ASSERT_EQUAL(root, retrieved_root, "Retrieved root should match");

    // Add some data
    json_object_set(root, "key", json_create_string("value"));

    // Clear and free
    json_clear(doc);
    json_free(doc);
    json_manager_free();
}

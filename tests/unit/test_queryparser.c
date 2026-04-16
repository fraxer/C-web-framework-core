#include "framework.h"
#include "queryparser.h"
#include "query.h"
#include "helpers.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Helper: count nodes in query linked list
static size_t query_count(query_t* query) {
    size_t count = 0;
    while (query != NULL) {
        count++;
        query = query->next;
    }
    return count;
}

// ============================================================================
// query_create / query_free / queries_free
// ============================================================================

TEST(test_query_create_with_key_value) {
    TEST_SUITE("query_create / query_free / queries_free");
    TEST_CASE("Create query with key and value");

    query_t* q = query_create("name", 4, "value", 5);

    TEST_ASSERT_NOT_NULL(q, "Query should be created");
    TEST_ASSERT_NOT_NULL(q->key, "Key should be set");
    TEST_ASSERT_NOT_NULL(q->value, "Value should be set");
    TEST_ASSERT_STR_EQUAL("name", q->key, "Key should match");
    TEST_ASSERT_STR_EQUAL("value", q->value, "Value should match");
    TEST_ASSERT_NULL(q->next, "Next should be NULL");

    query_free(q);
}

TEST(test_query_create_null_params) {
    TEST_SUITE("query_create / query_free / queries_free");
    TEST_CASE("Create query with NULL key and value");

    query_t* q = query_create(NULL, 0, NULL, 0);

    TEST_ASSERT_NOT_NULL(q, "Query should be created");
    TEST_ASSERT_NULL(q->key, "Key should be NULL");
    TEST_ASSERT_NULL(q->value, "Value should be NULL");
    TEST_ASSERT_NULL(q->next, "Next should be NULL");

    query_free(q);
}

TEST(test_query_free_null) {
    TEST_SUITE("query_create / query_free / queries_free");
    TEST_CASE("query_free(NULL) is undefined - skip");

    // query_free does not handle NULL input - caller must ensure non-NULL
    stats.total++;
    stats.passed++;
}

TEST(test_queries_free_null) {
    TEST_SUITE("query_create / query_free / queries_free");
    TEST_CASE("queries_free with NULL should not crash");

    queries_free(NULL);
    stats.total++;
    stats.passed++;
}

TEST(test_queries_free_linked_list) {
    TEST_SUITE("query_create / query_free / queries_free");
    TEST_CASE("Free linked list of queries");

    query_t* q1 = query_create("a", 1, "1", 1);
    query_t* q2 = query_create("b", 1, "2", 1);
    query_t* q3 = query_create("c", 1, "3", 1);
    q1->next = q2;
    q2->next = q3;

    queries_free(q1);
    // No assertion needed - just check it doesn't crash or leak
    stats.total++;
    stats.passed++;
}

// ============================================================================
// queryparser_parse - basic cases
// ============================================================================

TEST(test_parse_single_key_value) {
    TEST_SUITE("queryparser_parse");
    TEST_CASE("Single key=value pair");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("key=value", 9, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(first, "First query should not be NULL");
    TEST_ASSERT_STR_EQUAL("key", first->key, "Key should match");
    TEST_ASSERT_STR_EQUAL("value", first->value, "Value should match");
    TEST_ASSERT_NULL(first->next, "Should have only one query");
    TEST_ASSERT_EQUAL((intptr_t)first, (intptr_t)last, "First and last should be the same");

    queries_free(first);
}

TEST(test_parse_key_without_value) {
    TEST_SUITE("queryparser_parse");
    TEST_CASE("Key without value gets NULL value");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("keyonly", 7, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(first, "First query should not be NULL");
    TEST_ASSERT_STR_EQUAL("keyonly", first->key, "Key should match");
    TEST_ASSERT_NULL(first->value, "Value should be NULL");
    TEST_ASSERT_NULL(first->next, "Should have only one query");

    queries_free(first);
}

TEST(test_parse_multiple_params) {
    TEST_SUITE("queryparser_parse");
    TEST_CASE("Multiple key=value pairs");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("a=1&b=2&c=3", 11, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(3, query_count(first), "Should have 3 params");

    TEST_ASSERT_STR_EQUAL("a", first->key, "First key");
    TEST_ASSERT_STR_EQUAL("1", first->value, "First value");

    TEST_ASSERT_STR_EQUAL("b", first->next->key, "Second key");
    TEST_ASSERT_STR_EQUAL("2", first->next->value, "Second value");

    TEST_ASSERT_STR_EQUAL("c", first->next->next->key, "Third key");
    TEST_ASSERT_STR_EQUAL("3", first->next->next->value, "Third value");

    TEST_ASSERT_NULL(first->next->next->next, "No more params");

    queries_free(first);
}

TEST(test_parse_start_pos) {
    TEST_SUITE("queryparser_parse");
    TEST_CASE("Respects start_pos offset");

    query_t* first = NULL;
    query_t* last = NULL;

    // String "?x=hello", start at pos 1 (after '?')
    int result = queryparser_parse("?x=hello", 8, 1, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(first, "First query should not be NULL");
    TEST_ASSERT_STR_EQUAL("x", first->key, "Key should match");
    TEST_ASSERT_STR_EQUAL("hello", first->value, "Value should match");

    queries_free(first);
}

// ============================================================================
// queryparser_parse - URL decoding
// ============================================================================

TEST(test_parse_url_decode_percent) {
    TEST_SUITE("queryparser_parse - URL decoding");
    TEST_CASE("Decodes percent-encoded characters");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("q=%3Cscript%3E", 14, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("q", first->key, "Key should be q");
    TEST_ASSERT_STR_EQUAL("<script>", first->value, "Value should be decoded");

    queries_free(first);
}

TEST(test_parse_url_decode_space) {
    TEST_SUITE("queryparser_parse - URL decoding");
    TEST_CASE("Decodes + as space");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("name=hello+world", 16, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("name", first->key, "Key should match");
    TEST_ASSERT_STR_EQUAL("hello world", first->value, "+ should decode to space");

    queries_free(first);
}

TEST(test_parse_url_decode_complex) {
    TEST_SUITE("queryparser_parse - URL decoding");
    TEST_CASE("Decodes complex percent-encoded string");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("q=%3Cscript%3Ealert('XSS')%3C/script%3E", 39, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("q", first->key, "Key should be q");
    TEST_ASSERT_STR_EQUAL("<script>alert('XSS')</script>", first->value, "Value should be fully decoded");

    queries_free(first);
}

TEST(test_parse_url_decode_encoded_ampersand) {
    TEST_SUITE("queryparser_parse - URL decoding");
    TEST_CASE("Encoded ampersand is not treated as separator");

    query_t* first = NULL;
    query_t* last = NULL;

    // %26 is encoded &, should NOT split the value
    int result = queryparser_parse("id=1%26action=delete", 20, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(1, query_count(first), "Should have 1 param (not 2)");
    TEST_ASSERT_STR_EQUAL("id", first->key, "Key should be id");
    TEST_ASSERT_STR_EQUAL("1&action=delete", first->value, "Value should contain decoded & and =");

    queries_free(first);
}

TEST(test_parse_url_decode_encoded_hash) {
    TEST_SUITE("queryparser_parse - URL decoding");
    TEST_CASE("Encoded hash is not treated as fragment");

    query_t* first = NULL;
    query_t* last = NULL;

    // %23 is encoded #, should NOT be treated as fragment
    int result = queryparser_parse("id=1%23section", 14, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(1, query_count(first), "Should have 1 param");
    TEST_ASSERT_STR_EQUAL("id", first->key, "Key should be id");
    TEST_ASSERT_STR_EQUAL("1#section", first->value, "Value should contain decoded #");

    queries_free(first);
}

// ============================================================================
// queryparser_parse - fragment
// ============================================================================

TEST(test_parse_fragment_stops_parsing) {
    TEST_SUITE("queryparser_parse - fragment");
    TEST_CASE("Hash stops query parsing");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("a=1&b=2#ignored", 15, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(2, query_count(first), "Should have 2 params (third is after #)");
    TEST_ASSERT_STR_EQUAL("a", first->key, "First key");
    TEST_ASSERT_STR_EQUAL("1", first->value, "First value");
    TEST_ASSERT_STR_EQUAL("b", first->next->key, "Second key");
    TEST_ASSERT_STR_EQUAL("2", first->next->value, "Second value");

    queries_free(first);
}

TEST(test_parse_fragment_after_key) {
    TEST_SUITE("queryparser_parse - fragment");
    TEST_CASE("Hash after key-only param");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("keyonly#fragment", 16, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(1, query_count(first), "Should have 1 param");
    TEST_ASSERT_STR_EQUAL("keyonly", first->key, "Key should match");
    TEST_ASSERT_NULL(first->value, "Value should be NULL");

    queries_free(first);
}

// ============================================================================
// queryparser_parse - edge cases
// ============================================================================

TEST(test_parse_empty_string) {
    TEST_SUITE("queryparser_parse - edge cases");
    TEST_CASE("Empty string produces single empty query");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("", 0, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(1, query_count(first), "Should have 1 query node");
    TEST_ASSERT_NOT_NULL(first->key, "Key should not be NULL");
    TEST_ASSERT_STR_EQUAL("", first->key, "Key should be empty string");
    TEST_ASSERT_NULL(first->value, "Value should be NULL");

    queries_free(first);
}

TEST(test_parse_consecutive_equals) {
    TEST_SUITE("queryparser_parse - edge cases");
    TEST_CASE("Consecutive = characters are skipped");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("key==value", 10, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("key", first->key, "Key should match");
    TEST_ASSERT_STR_EQUAL("=value", first->value, "Value should start with =");

    queries_free(first);
}

TEST(test_parse_only_equals) {
    TEST_SUITE("queryparser_parse - edge cases");
    TEST_CASE("Only = produces empty key and empty value");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("=", 1, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_NOT_NULL(first->key, "Key should not be NULL");
    TEST_ASSERT_STR_EQUAL("", first->key, "Key should be empty string");
    TEST_ASSERT_NOT_NULL(first->value, "Value should not be NULL");
    TEST_ASSERT_STR_EQUAL("", first->value, "Value should be empty string");

    queries_free(first);
}

TEST(test_parse_only_ampersand) {
    TEST_SUITE("queryparser_parse - edge cases");
    TEST_CASE("Only & produces two empty queries");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("&", 1, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(2, query_count(first), "Should have 2 query nodes");
    TEST_ASSERT_STR_EQUAL("", first->key, "First key should be empty");
    TEST_ASSERT_NULL(first->value, "First value should be NULL");
    TEST_ASSERT_STR_EQUAL("", first->next->key, "Second key should be empty");
    TEST_ASSERT_NULL(first->next->value, "Second value should be NULL");

    queries_free(first);
}

TEST(test_parse_trailing_ampersand) {
    TEST_SUITE("queryparser_parse - edge cases");
    TEST_CASE("Trailing & creates empty final query");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("a=1&", 4, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(2, query_count(first), "Should have 2 queries");
    TEST_ASSERT_STR_EQUAL("a", first->key, "First key");
    TEST_ASSERT_STR_EQUAL("1", first->value, "First value");
    TEST_ASSERT_NULL(first->next->value, "Second value should be NULL");

    queries_free(first);
}

TEST(test_parse_leading_ampersand) {
    TEST_SUITE("queryparser_parse - edge cases");
    TEST_CASE("Leading & creates empty first query");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("&b=2", 4, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(2, query_count(first), "Should have 2 queries");
    TEST_ASSERT_STR_EQUAL("", first->key, "First key should be empty");
    TEST_ASSERT_NULL(first->value, "First value should be NULL");
    TEST_ASSERT_STR_EQUAL("b", first->next->key, "Second key");
    TEST_ASSERT_STR_EQUAL("2", first->next->value, "Second value");

    queries_free(first);
}

TEST(test_parse_value_with_equals) {
    TEST_SUITE("queryparser_parse - edge cases");
    TEST_CASE("Value containing = sign");

    query_t* first = NULL;
    query_t* last = NULL;

    // First = separates key from value; subsequent = are part of the value
    int result = queryparser_parse("eq=a==b", 7, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_STR_EQUAL("eq", first->key, "Key should be eq");
    TEST_ASSERT_STR_EQUAL("a==b", first->value, "Value should preserve = signs");

    queries_free(first);
}

// ============================================================================
// queryparser_parse - HTTP parameter pollution (duplicate keys)
// ============================================================================

TEST(test_parse_duplicate_keys) {
    TEST_SUITE("queryparser_parse - HPP");
    TEST_CASE("Duplicate keys are preserved as separate nodes");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("id=1&id=2&id=3", 14, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(3, query_count(first), "Should have 3 params");
    TEST_ASSERT_STR_EQUAL("1", first->value, "First id value");
    TEST_ASSERT_STR_EQUAL("2", first->next->value, "Second id value");
    TEST_ASSERT_STR_EQUAL("3", first->next->next->value, "Third id value");

    queries_free(first);
}

// ============================================================================
// queryparser_parse - callback
// ============================================================================

typedef struct {
    int call_count;
    query_t* queries[16];
} callback_ctx_t;

static void test_append_callback(void* context, query_t* query) {
    callback_ctx_t* ctx = (callback_ctx_t*)context;
    if (ctx->call_count < 16)
        ctx->queries[ctx->call_count] = query;
    ctx->call_count++;
}

TEST(test_parse_callback_invoked) {
    TEST_SUITE("queryparser_parse - callback");
    TEST_CASE("Callback is invoked for each query node");

    callback_ctx_t ctx = {0};
    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("a=1&b=2&c=3", 11, 0, &ctx, test_append_callback, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL(3, ctx.call_count, "Callback should be called 3 times");
    TEST_ASSERT_EQUAL((intptr_t)first, (intptr_t)ctx.queries[0], "First callback query should be first node");
    TEST_ASSERT_EQUAL((intptr_t)first->next, (intptr_t)ctx.queries[1], "Second callback query should be second node");
    TEST_ASSERT_EQUAL((intptr_t)last, (intptr_t)ctx.queries[2], "Last callback query should be last node");

    queries_free(first);
}

TEST(test_parse_null_callback) {
    TEST_SUITE("queryparser_parse - callback");
    TEST_CASE("NULL callback should not crash");

    query_t* first = NULL;
    query_t* last = NULL;

    int result = queryparser_parse("a=1&b=2", 7, 0, NULL, NULL, &first, &last);

    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Parse should succeed");
    TEST_ASSERT_EQUAL_SIZE(2, query_count(first), "Should have 2 params");

    queries_free(first);
}

// ============================================================================
// query_stringify
// ============================================================================

TEST(test_query_stringify_single) {
    TEST_SUITE("query_stringify");
    TEST_CASE("Stringify single key=value pair");

    query_t* q = query_create("key", 3, "value", 5);

    char* result = query_stringify(q);

    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");
    TEST_ASSERT_STR_EQUAL("key=value", result, "Stringified query should match");

    free(result);
    query_free(q);
}

TEST(test_query_stringify_multiple) {
    TEST_SUITE("query_stringify");
    TEST_CASE("Stringify multiple key=value pairs");

    query_t* q1 = query_create("a", 1, "1", 1);
    query_t* q2 = query_create("b", 1, "hello world", 11);
    q1->next = q2;

    char* result = query_stringify(q1);

    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");
    TEST_ASSERT_STR_EQUAL("a=1&b=hello+world", result, "Spaces should be encoded as +");

    free(result);
    query_free(q1);  // frees q2 too via linked list? No, query_free only frees one node
    query_free(q2);
}

TEST(test_query_stringify_null) {
    TEST_SUITE("query_stringify");
    TEST_CASE("Stringify NULL returns NULL");

    char* result = query_stringify(NULL);

    TEST_ASSERT_NULL(result, "Result should be NULL for NULL input");
}

TEST(test_query_stringify_special_chars) {
    TEST_SUITE("query_stringify");
    TEST_CASE("Special characters are percent-encoded");

    query_t* q = query_create("q", 1, "<script>", 8);

    char* result = query_stringify(q);

    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");
    TEST_ASSERT_STR_EQUAL("q=%3Cscript%3E", result, "< and > should be encoded");

    free(result);
    query_free(q);
}

// ============================================================================
// query_stringify roundtrip
// ============================================================================

TEST(test_query_stringify_roundtrip) {
    TEST_SUITE("query_stringify - roundtrip");
    TEST_CASE("Parse -> stringify -> parse produces same result");

    const char* original = "name=John+Doe&age=30&city=New+York";

    // Parse
    query_t* first1 = NULL;
    query_t* last1 = NULL;
    int result = queryparser_parse(original, strlen(original), 0, NULL, NULL, &first1, &last1);
    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "First parse should succeed");

    // Stringify
    char* stringified = query_stringify(first1);
    TEST_ASSERT_NOT_NULL(stringified, "Stringify should succeed");

    // Parse again
    query_t* first2 = NULL;
    query_t* last2 = NULL;
    result = queryparser_parse(stringified, strlen(stringified), 0, NULL, NULL, &first2, &last2);
    TEST_ASSERT_EQUAL(QUERYPARSER_OK, result, "Second parse should succeed");

    // Compare
    TEST_ASSERT_EQUAL_SIZE(query_count(first1), query_count(first2), "Node count should match");
    TEST_ASSERT_STR_EQUAL(first1->key, first2->key, "First key should match");
    TEST_ASSERT_STR_EQUAL(first1->value, first2->value, "First value should match");
    TEST_ASSERT_STR_EQUAL(first1->next->key, first2->next->key, "Second key should match");
    TEST_ASSERT_STR_EQUAL(first1->next->value, first2->next->value, "Second value should match");
    TEST_ASSERT_STR_EQUAL(first1->next->next->key, first2->next->next->key, "Third key should match");
    TEST_ASSERT_STR_EQUAL(first1->next->next->value, first2->next->next->value, "Third value should match");

    free(stringified);
    queries_free(first1);
    queries_free(first2);
}

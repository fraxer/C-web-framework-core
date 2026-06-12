#include "framework.h"
#include "cookieparser.h"
#include "httpcommon.h"
#include "helpers.h"

#include <stdlib.h>
#include <string.h>

// ============================================================================
// Helpers
// ============================================================================

/* Парсит строку через буфер ТОЧНОГО размера без '\0' на конце.
 * Так ASan поймает любое чтение за границами buffer_size. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-use-of-uninitialized-value"
static http_cookie_t* parse(cookieparser_t* parser, const char* src) {
    if (!src) return NULL;

    const size_t len = strlen(src);
    if (len == 0) return NULL;

    char* buffer = malloc(len);
    if (buffer == NULL) return NULL;

    memcpy(buffer, src, len);

    cookieparser_init(parser);
    const int ret = cookieparser_parse(parser, buffer, len);

    free(buffer);
    if (!ret) return NULL;
    return cookieparser_cookie(parser);
}
#pragma GCC diagnostic pop

static size_t list_length(const http_cookie_t* cookie) {
    size_t n = 0;
    for (; cookie != NULL; cookie = cookie->next) n++;
    return n;
}

/* Каждая кука в списке обязана иметь ненулевые key и value
 * и длины, совпадающие со strlen. */
static void check_invariants(const http_cookie_t* cookie) {
    for (; cookie != NULL; cookie = cookie->next) {
        TEST_ASSERT_NOT_NULL(cookie->key, "cookie key should not be NULL");
        TEST_ASSERT_NOT_NULL(cookie->value, "cookie value should not be NULL");
        if (cookie->key != NULL)
            TEST_ASSERT_EQUAL_SIZE(cookie->key_length, strlen(cookie->key),
                                   "cookie key_length should match strlen");
        if (cookie->value != NULL)
            TEST_ASSERT_EQUAL_SIZE(cookie->value_length, strlen(cookie->value),
                                   "cookie value_length should match strlen");
    }
}

// ============================================================================
// Test Suite 1: Basic parsing
// ============================================================================

TEST(test_cookie_single_pair) {
    TEST_SUITE("Cookie Parser - Basic Parsing");
    TEST_CASE("Single key=value pair");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "session=abc123");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("session", c->key, "key should be 'session'");
    TEST_ASSERT_STR_EQUAL("abc123", c->value, "value should be 'abc123'");
    TEST_ASSERT_EQUAL_SIZE(7, c->key_length, "key_length should be 7");
    TEST_ASSERT_EQUAL_SIZE(6, c->value_length, "value_length should be 6");

    http_cookie_free(c);
}

TEST(test_cookie_multiple_pairs) {
    TEST_SUITE("Cookie Parser - Basic Parsing");
    TEST_CASE("Multiple key=value pairs");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "a=1; b=2; c=3");

    TEST_ASSERT_EQUAL(3, list_length(c), "should have 3 cookies");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("a", c->key, "first key should be 'a'");
    TEST_ASSERT_STR_EQUAL("1", c->value, "first value should be '1'");
    TEST_ASSERT_STR_EQUAL("b", c->next->key, "second key should be 'b'");
    TEST_ASSERT_STR_EQUAL("2", c->next->value, "second value should be '2'");
    TEST_ASSERT_STR_EQUAL("c", c->next->next->key, "third key should be 'c'");
    TEST_ASSERT_STR_EQUAL("3", c->next->next->value, "third value should be '3'");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 2: Spacing variations
// ============================================================================

TEST(test_cookie_no_space_after_semicolon) {
    TEST_SUITE("Cookie Parser - Spacing");
    TEST_CASE("No space after semicolon");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "a=1;b=2");

    TEST_ASSERT_EQUAL(2, list_length(c), "should have 2 cookies");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("b", c->next->key, "second key should be 'b'");
    TEST_ASSERT_STR_EQUAL("2", c->next->value, "second value should be '2'");

    http_cookie_free(c);
}

TEST(test_cookie_multiple_spaces) {
    TEST_SUITE("Cookie Parser - Spacing");
    TEST_CASE("Multiple spaces before key");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "a=1;   b=2");

    TEST_ASSERT_EQUAL(2, list_length(c), "should have 2 cookies");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("b", c->next->key, "second key should be 'b'");

    http_cookie_free(c);
}

TEST(test_cookie_leading_spaces) {
    TEST_SUITE("Cookie Parser - Spacing");
    TEST_CASE("Leading spaces before first key");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "  a=1");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("a", c->key, "key should be 'a'");
    TEST_ASSERT_STR_EQUAL("1", c->value, "value should be '1'");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 3: Value edge cases
// ============================================================================

TEST(test_cookie_empty_value) {
    TEST_SUITE("Cookie Parser - Value Edge Cases");
    TEST_CASE("Empty value after equals");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "a=");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("a", c->key, "key should be 'a'");
    TEST_ASSERT_STR_EQUAL("", c->value, "value should be empty");
    TEST_ASSERT_EQUAL_SIZE(0, c->value_length, "value_length should be 0");

    http_cookie_free(c);
}

TEST(test_cookie_value_contains_equals) {
    TEST_SUITE("Cookie Parser - Value Edge Cases");
    TEST_CASE("Value contains '=' characters");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "token=a=b=c");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("token", c->key, "key should be 'token'");
    TEST_ASSERT_STR_EQUAL("a=b=c", c->value, "value should be 'a=b=c'");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 4: Malformed input
// ============================================================================

TEST(test_cookie_token_without_equals_is_skipped) {
    TEST_SUITE("Cookie Parser - Malformed Input");
    TEST_CASE("Token without '=' is skipped, neighbors preserved");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "garbage; a=1; morejunk; b=2");

    TEST_ASSERT_EQUAL(2, list_length(c), "should have 2 valid cookies");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("a", c->key, "first key should be 'a'");
    TEST_ASSERT_STR_EQUAL("1", c->value, "first value should be '1'");
    TEST_ASSERT_STR_EQUAL("b", c->next->key, "second key should be 'b'");
    TEST_ASSERT_STR_EQUAL("2", c->next->value, "second value should be '2'");

    http_cookie_free(c);
}

TEST(test_cookie_only_garbage) {
    TEST_SUITE("Cookie Parser - Malformed Input");
    TEST_CASE("Input with no '=' produces NULL");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "garbage");

    TEST_ASSERT_NULL(c, "garbage input should produce NULL");
}

TEST(test_cookie_empty_key_is_skipped) {
    TEST_SUITE("Cookie Parser - Malformed Input");
    TEST_CASE("Empty key before '=' is skipped");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "=oops; a=1");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("a", c->key, "key should be 'a'");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 5: Trailing semicolons
// ============================================================================

TEST(test_cookie_trailing_semicolon) {
    TEST_SUITE("Cookie Parser - Trailing Semicolons");
    TEST_CASE("Trailing semicolon after pair");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "a=1;");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);

    http_cookie_free(c);
}

TEST(test_cookie_trailing_semicolon_and_space) {
    TEST_SUITE("Cookie Parser - Trailing Semicolons");
    TEST_CASE("Trailing semicolon and space after pair");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "a=1; ");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);

    http_cookie_free(c);
}

TEST(test_cookie_semicolons_only) {
    TEST_SUITE("Cookie Parser - Trailing Semicolons");
    TEST_CASE("Input of only semicolons");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, ";;;");

    TEST_ASSERT_NULL(c, "semicolons only should produce NULL");
}

// ============================================================================
// Test Suite 6: Null and empty inputs
// ============================================================================

TEST(test_cookie_empty_buffer) {
    TEST_SUITE("Cookie Parser - Null/Empty Inputs");
    TEST_CASE("Buffer with zero size");

    cookieparser_t parser;
    char dummy = 'x';

    cookieparser_init(&parser);
    const int ret = cookieparser_parse(&parser, &dummy, 0);

    TEST_ASSERT_EQUAL(1, ret, "empty buffer should return success");
    TEST_ASSERT_NULL(cookieparser_cookie(&parser),
                     "empty buffer should produce NULL cookies");
}

TEST(test_cookie_null_buffer) {
    TEST_SUITE("Cookie Parser - Null/Empty Inputs");
    TEST_CASE("NULL buffer pointer");

    cookieparser_t parser;

    cookieparser_init(&parser);
    const int ret = cookieparser_parse(&parser, NULL, 10);

    TEST_ASSERT_EQUAL(0, ret, "NULL buffer should return 0");
    TEST_ASSERT_NULL(cookieparser_cookie(&parser),
                     "NULL buffer should produce NULL cookies");
}

TEST(test_cookie_null_parser) {
    TEST_SUITE("Cookie Parser - Null/Empty Inputs");
    TEST_CASE("NULL parser does not crash");

    const int ret = cookieparser_parse(NULL, "a=1", 3);
    TEST_ASSERT_EQUAL(0, ret, "NULL parser should return 0");
}

// ============================================================================
// Test Suite 7: Buffer size boundary
// ============================================================================

TEST(test_cookie_buffer_size_cuts_input) {
    TEST_SUITE("Cookie Parser - Buffer Boundary");
    TEST_CASE("buffer_size shorter than actual data");

    cookieparser_t parser;
    const char* src = "a=1; b=2";

    char* buffer = malloc(4);
    if (buffer == NULL) abort();
    memcpy(buffer, src, 4); /* "a=1;" без терминатора */

    cookieparser_init(&parser);
    const int ret = cookieparser_parse(&parser, buffer, 3); /* видит только "a=1" */
    free(buffer);

    TEST_ASSERT_EQUAL(1, ret, "should return success");

    http_cookie_t* c = cookieparser_cookie(&parser);
    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("a", c->key, "key should be 'a'");
    TEST_ASSERT_STR_EQUAL("1", c->value, "value should be '1'");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 8: Large values
// ============================================================================

TEST(test_cookie_long_value) {
    TEST_SUITE("Cookie Parser - Large Values");
    TEST_CASE("64KB value");

    cookieparser_t parser;
    const size_t value_length = 64 * 1024;

    char* src = malloc(value_length + 5);
    if (src == NULL) abort();
    memcpy(src, "big=", 4);
    memset(src + 4, 'x', value_length);
    src[value_length + 4] = '\0';

    http_cookie_t* c = parse(&parser, src);
    free(src);

    if (c == NULL) abort();

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_EQUAL_SIZE(value_length, c->value_length,
                           "value_length should be 64KB");
    TEST_ASSERT(c->value[0] == 'x', "value should start with 'x'");
    TEST_ASSERT(c->value[value_length - 1] == 'x',
                "value should end with 'x'");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 9: Realistic header
// ============================================================================

TEST(test_cookie_realistic_header) {
    TEST_SUITE("Cookie Parser - Realistic Header");
    TEST_CASE("Typical browser Cookie header");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser,
        "_ga=GA1.2.12345; sessionid=eyJhbGciOiJIUzI1NiJ9; csrftoken=Zm9vYmFy; theme=dark");

    TEST_ASSERT_EQUAL(4, list_length(c), "should have 4 cookies");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("_ga", c->key, "first key should be '_ga'");
    TEST_ASSERT_STR_EQUAL("theme", c->next->next->next->key,
                          "last key should be 'theme'");
    TEST_ASSERT_STR_EQUAL("dark", c->next->next->next->value,
                          "last value should be 'dark'");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 10: Linked list integrity
// ============================================================================

TEST(test_cookie_linked_list_order) {
    TEST_SUITE("Cookie Parser - Linked List");
    TEST_CASE("Cookies are linked in order");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "first=1; second=2; third=3");
    if (c == NULL) abort();

    TEST_ASSERT_NOT_NULL(c, "first cookie should not be NULL");
    TEST_ASSERT_STR_EQUAL("first", c->key, "first cookie key");
    TEST_ASSERT_NOT_NULL(c->next, "second cookie should exist");
    TEST_ASSERT_STR_EQUAL("second", c->next->key, "second cookie key");
    TEST_ASSERT_NOT_NULL(c->next->next, "third cookie should exist");
    TEST_ASSERT_STR_EQUAL("third", c->next->next->key, "third cookie key");
    TEST_ASSERT_NULL(c->next->next->next, "no fourth cookie");

    http_cookie_free(c);
}

TEST(test_cookie_last_cookie_tracking) {
    TEST_SUITE("Cookie Parser - Linked List");
    TEST_CASE("last_cookie pointer is correct after parsing");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "a=1; b=2; c=3");
    if (c == NULL) abort();

    http_cookie_t* last = c;
    while (last->next != NULL) last = last->next;

    TEST_ASSERT(last == parser.last_cookie,
                "last_cookie should point to last node");
    TEST_ASSERT_STR_EQUAL("c", parser.last_cookie->key,
                          "last cookie key should be 'c'");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 11: Value with special characters
// ============================================================================

TEST(test_cookie_value_with_spaces) {
    TEST_SUITE("Cookie Parser - Special Characters");
    TEST_CASE("Value containing spaces");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "name=hello world");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("hello world", c->value,
                          "value should preserve spaces");

    http_cookie_free(c);
}

TEST(test_cookie_value_with_semicolon_in_value_via_buffer_size) {
    TEST_SUITE("Cookie Parser - Special Characters");
    TEST_CASE("Value containing ';' controlled by buffer_size");

    /* Парсер разделяет по ';', но мы можем ограничить buffer_size,
     * чтобы ';' попал в значение. */
    cookieparser_t parser;
    const char* src = "a=1;2";
    const size_t len = 5;

    char* buffer = malloc(len);
    if (buffer == NULL) abort();
    memcpy(buffer, src, len);

    cookieparser_init(&parser);
    const int ret = cookieparser_parse(&parser, buffer, 4); /* только "a=1;" → разделит на "a=1" */
    free(buffer);

    TEST_ASSERT_EQUAL(1, ret, "should return success");

    http_cookie_t* c = cookieparser_cookie(&parser);
    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    TEST_ASSERT_STR_EQUAL("1", c->value, "value should be '1'");

    http_cookie_free(c);
}

TEST(test_cookie_value_with_url_encoded) {
    TEST_SUITE("Cookie Parser - Special Characters");
    TEST_CASE("URL-encoded value");

    cookieparser_t parser;
    http_cookie_t* c = parse(&parser, "search=%22hello%22");

    TEST_ASSERT_EQUAL(1, list_length(c), "should have 1 cookie");
    check_invariants(c);
    TEST_ASSERT_STR_EQUAL("%22hello%22", c->value,
                          "value should preserve URL encoding");

    http_cookie_free(c);
}

// ============================================================================
// Test Suite 12: Repeated parsing
// ============================================================================

TEST(test_cookie_reuse_parser) {
    TEST_SUITE("Cookie Parser - Reuse");
    TEST_CASE("Reusing parser after previous parse");

    cookieparser_t parser;

    /* Первый парсинг */
    http_cookie_t* c1 = parse(&parser, "x=1");
    if (c1 == NULL) abort();

    TEST_ASSERT_NOT_NULL(c1, "first parse should produce cookie");
    TEST_ASSERT_STR_EQUAL("x", c1->key, "first parse key");
    http_cookie_free(c1);

    /* Второй парсинг — init сбрасывает состояние */
    http_cookie_t* c2 = parse(&parser, "y=2");
    if (c2 == NULL) abort();

    TEST_ASSERT_NOT_NULL(c2, "second parse should produce cookie");
    TEST_ASSERT_STR_EQUAL("y", c2->key, "second parse key");
    TEST_ASSERT_STR_EQUAL("2", c2->value, "second parse value");

    http_cookie_free(c2);
}

// ============================================================================
// Test Suite 13: cookieparser_cookie accessor
// ============================================================================

TEST(test_cookie_cookie_function) {
    TEST_SUITE("Cookie Parser - Accessor");
    TEST_CASE("cookieparser_cookie returns head of list");

    cookieparser_t parser;
    parse(&parser, "a=1; b=2");

    http_cookie_t* c = cookieparser_cookie(&parser);
    TEST_ASSERT_NOT_NULL(c, "cookieparser_cookie should return non-NULL");
    TEST_ASSERT_STR_EQUAL("a", c->key, "head key should be 'a'");

    http_cookie_free(c);
}

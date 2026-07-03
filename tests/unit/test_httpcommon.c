/*
 * Unit tests for protocols/http/httpcommon.c
 *
 * Covers the shared HTTP building blocks: header create/free/delete,
 * payload part/field, cookie, ranges and the Basic-auth header builder.
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - http_header_create returned a half-built header when copy_cstringn
 *     failed for key or value: the pointer was NULL while the stored length
 *     stayed non-zero, so consumers checking only the header pointer
 *     (multipartparser) went on to dereference NULL. Now it cleans up and
 *     returns NULL, guaranteeing key/value != NULL on success.
 *   - http_header_free(NULL) dereferenced NULL while every other *_free in
 *     the file tolerates NULL; now it is a no-op.
 *   - http_header_delete(list, NULL) called strlen(NULL); now it returns the
 *     list unchanged.
 *
 * Freeing chains under the ASan/LSan-enabled Debug build doubles as the leak
 * check for the *_free functions.
 */

#include "framework.h"
#include "httpcommon.h"
#include "base64.h"

#include <string.h>
#include <stdlib.h>

// ============================================================================
// http_header_create
// ============================================================================

TEST(test_http_header_create_basic) {
    TEST_CASE("http_header_create copies key and value with lengths");

    http_header_t* header = http_header_create("Content-Type", 12, "text/html", 9);
    TEST_REQUIRE_NOT_NULL(header, "header should be created");

    TEST_ASSERT_STR_EQUAL("Content-Type", header->key, "key should be copied");
    TEST_ASSERT_EQUAL_SIZE(12, header->key_length, "key_length should match");
    TEST_ASSERT_STR_EQUAL("text/html", header->value, "value should be copied");
    TEST_ASSERT_EQUAL_SIZE(9, header->value_length, "value_length should match");
    TEST_ASSERT_NULL(header->next, "next should be NULL");

    http_header_free(header);
}

TEST(test_http_header_create_copies_are_independent) {
    TEST_CASE("http_header_create stores independent copies, not the source pointers");

    char key[] = "Host";
    char value[] = "example.com";

    http_header_t* header = http_header_create(key, 4, value, 11);
    TEST_REQUIRE_NOT_NULL(header, "header should be created");

    TEST_ASSERT(header->key != key, "key should be a copy");
    TEST_ASSERT(header->value != value, "value should be a copy");

    key[0] = 'X';
    value[0] = 'X';
    TEST_ASSERT_STR_EQUAL("Host", header->key, "key copy should not follow source mutation");
    TEST_ASSERT_STR_EQUAL("example.com", header->value, "value copy should not follow source mutation");

    http_header_free(header);
}

TEST(test_http_header_create_truncates_by_length) {
    TEST_CASE("http_header_create honors explicit lengths, not NUL terminators");

    http_header_t* header = http_header_create("Content-Length-Extra", 14, "12345garbage", 5);
    TEST_REQUIRE_NOT_NULL(header, "header should be created");

    TEST_ASSERT_STR_EQUAL("Content-Length", header->key, "key should be cut at key_length");
    TEST_ASSERT_STR_EQUAL("12345", header->value, "value should be cut at value_length");

    http_header_free(header);
}

TEST(test_http_header_create_binary_value) {
    TEST_CASE("http_header_create is binary-safe (embedded NUL in value)");

    const char value[] = { 'a', '\0', 'b' };
    http_header_t* header = http_header_create("X-Bin", 5, value, 3);
    TEST_REQUIRE_NOT_NULL(header, "header should be created");

    TEST_ASSERT_EQUAL_SIZE(3, header->value_length, "value_length should be 3");
    TEST_ASSERT(memcmp(header->value, value, 3) == 0, "all 3 bytes should be copied");
    TEST_ASSERT(header->value[3] == '\0', "copy should be NUL-terminated past the data");

    http_header_free(header);
}

TEST(test_http_header_create_empty_value) {
    TEST_CASE("http_header_create with NULL value and zero length yields empty string");

    /* Parser contract: httprequestparser/httpresponseparser create headers as
     * http_header_create(name, len, NULL, 0) and rely on value being a valid
     * empty string, not NULL. */
    http_header_t* header = http_header_create("Accept", 6, NULL, 0);
    TEST_REQUIRE_NOT_NULL(header, "header should be created");

    TEST_ASSERT_NOT_NULL(header->value, "value should be allocated");
    TEST_ASSERT_STR_EQUAL("", header->value, "value should be an empty string");
    TEST_ASSERT_EQUAL_SIZE(0, header->value_length, "value_length should be 0");

    http_header_free(header);
}

TEST(test_http_header_create_preallocation_contract) {
    TEST_CASE("http_header_create with NULL sources preallocates writable buffers");

    /* Parser contract: multipartparser calls
     * http_header_create(NULL, key_size, NULL, value_size) to get buffers it
     * fills in afterwards. Buffers must be non-NULL, writable for the given
     * size and NUL-terminated at [size]. */
    http_header_t* header = http_header_create(NULL, 4, NULL, 6);
    TEST_REQUIRE_NOT_NULL(header, "header should be created");
    TEST_REQUIRE_NOT_NULL(header->key, "key buffer should be allocated");
    TEST_REQUIRE_NOT_NULL(header->value, "value buffer should be allocated");

    TEST_ASSERT(header->key[4] == '\0', "key buffer should be NUL-terminated at key_length");
    TEST_ASSERT(header->value[6] == '\0', "value buffer should be NUL-terminated at value_length");

    memcpy(header->key, "Name", 4);
    memcpy(header->value, "filled", 6);
    TEST_ASSERT_STR_EQUAL("Name", header->key, "key buffer should be writable");
    TEST_ASSERT_STR_EQUAL("filled", header->value, "value buffer should be writable");

    http_header_free(header);
}

// ============================================================================
// http_header_free / http_headers_free
// ============================================================================

TEST(test_http_header_free_null) {
    TEST_CASE("REGRESSION: http_header_free(NULL) is a no-op");

    http_header_free(NULL);
    TEST_ASSERT(1, "should not crash on NULL");
}

TEST(test_http_headers_free_null) {
    TEST_CASE("http_headers_free(NULL) is a no-op");

    http_headers_free(NULL);
    TEST_ASSERT(1, "should not crash on NULL");
}

TEST(test_http_headers_free_chain) {
    TEST_CASE("http_headers_free releases a whole chain (LSan-checked)");

    http_header_t* first = http_header_create("A", 1, "1", 1);
    TEST_REQUIRE_NOT_NULL(first, "first header should be created");
    first->next = http_header_create("B", 1, "2", 1);
    TEST_REQUIRE_NOT_NULL(first->next, "second header should be created");
    first->next->next = http_header_create("C", 1, "3", 1);
    TEST_REQUIRE_NOT_NULL(first->next->next, "third header should be created");

    http_headers_free(first);
    TEST_ASSERT(1, "chain freed without crash");
}

// ============================================================================
// http_header_delete
// ============================================================================

static http_header_t* make_headers3(void) {
    http_header_t* first = http_header_create("Content-Type", 12, "text/html", 9);
    if (first == NULL) return NULL;
    first->next = http_header_create("Host", 4, "example.com", 11);
    if (first->next == NULL) {
        http_headers_free(first);
        return NULL;
    }
    first->next->next = http_header_create("Accept", 6, "*/*", 3);
    if (first->next->next == NULL) {
        http_headers_free(first);
        return NULL;
    }
    return first;
}

TEST(test_http_header_delete_null_list) {
    TEST_CASE("http_header_delete on NULL list returns NULL");

    TEST_ASSERT_NULL(http_header_delete(NULL, "Host"), "NULL list should stay NULL");
}

TEST(test_http_header_delete_null_key) {
    TEST_CASE("REGRESSION: http_header_delete with NULL key returns list unchanged");

    http_header_t* list = make_headers3();
    TEST_REQUIRE_NOT_NULL(list, "test list should be created");

    http_header_t* result = http_header_delete(list, NULL);
    TEST_ASSERT(result == list, "list head should be unchanged");
    TEST_ASSERT_NOT_NULL(result->next, "list should keep its second element");

    http_headers_free(result);
}

TEST(test_http_header_delete_head) {
    TEST_CASE("http_header_delete removes head and returns the new head");

    http_header_t* list = make_headers3();
    TEST_REQUIRE_NOT_NULL(list, "test list should be created");

    http_header_t* result = http_header_delete(list, "Content-Type");
    TEST_REQUIRE_NOT_NULL(result, "list should not be empty after deleting head");

    TEST_ASSERT_STR_EQUAL("Host", result->key, "new head should be the former second element");
    TEST_REQUIRE_NOT_NULL(result->next, "one more element should remain");
    TEST_ASSERT_STR_EQUAL("Accept", result->next->key, "tail should be preserved");
    TEST_ASSERT_NULL(result->next->next, "list should have exactly two elements");

    http_headers_free(result);
}

TEST(test_http_header_delete_middle) {
    TEST_CASE("http_header_delete removes a middle element and relinks the list");

    http_header_t* list = make_headers3();
    TEST_REQUIRE_NOT_NULL(list, "test list should be created");

    http_header_t* result = http_header_delete(list, "Host");
    TEST_ASSERT(result == list, "head should be unchanged");
    TEST_REQUIRE_NOT_NULL(result->next, "tail should remain linked");
    TEST_ASSERT_STR_EQUAL("Accept", result->next->key, "head should now link to the former tail");
    TEST_ASSERT_NULL(result->next->next, "list should have exactly two elements");

    http_headers_free(result);
}

TEST(test_http_header_delete_tail) {
    TEST_CASE("http_header_delete removes the tail element");

    http_header_t* list = make_headers3();
    TEST_REQUIRE_NOT_NULL(list, "test list should be created");

    http_header_t* result = http_header_delete(list, "Accept");
    TEST_ASSERT(result == list, "head should be unchanged");
    TEST_REQUIRE_NOT_NULL(result->next, "second element should remain");
    TEST_ASSERT_STR_EQUAL("Host", result->next->key, "second element should be intact");
    TEST_ASSERT_NULL(result->next->next, "tail should be gone");

    http_headers_free(result);
}

TEST(test_http_header_delete_single_element) {
    TEST_CASE("http_header_delete on a single-element list returns NULL");

    http_header_t* list = http_header_create("Host", 4, "example.com", 11);
    TEST_REQUIRE_NOT_NULL(list, "header should be created");

    TEST_ASSERT_NULL(http_header_delete(list, "Host"), "deleting the only element should yield NULL");
}

TEST(test_http_header_delete_not_found) {
    TEST_CASE("http_header_delete leaves the list intact when key is absent");

    http_header_t* list = make_headers3();
    TEST_REQUIRE_NOT_NULL(list, "test list should be created");

    http_header_t* result = http_header_delete(list, "X-Missing");
    TEST_ASSERT(result == list, "head should be unchanged");
    TEST_REQUIRE_NOT_NULL(result->next, "second element should remain");
    TEST_REQUIRE_NOT_NULL(result->next->next, "third element should remain");
    TEST_ASSERT_NULL(result->next->next->next, "list length should still be three");

    http_headers_free(result);
}

TEST(test_http_header_delete_case_insensitive) {
    TEST_CASE("http_header_delete matches keys case-insensitively");

    http_header_t* list = make_headers3();
    TEST_REQUIRE_NOT_NULL(list, "test list should be created");

    http_header_t* result = http_header_delete(list, "hOsT");
    TEST_ASSERT(result == list, "head should be unchanged");
    TEST_REQUIRE_NOT_NULL(result->next, "tail should remain");
    TEST_ASSERT_STR_EQUAL("Accept", result->next->key, "Host should be removed despite case difference");

    http_headers_free(result);
}

TEST(test_http_header_delete_length_mismatch) {
    TEST_CASE("http_header_delete does not match prefixes or extensions of a key");

    http_header_t* list = make_headers3();
    TEST_REQUIRE_NOT_NULL(list, "test list should be created");

    http_header_t* result = http_header_delete(list, "Hos");
    result = http_header_delete(result, "Hosts");
    TEST_ASSERT(result == list, "head should be unchanged");
    TEST_REQUIRE_NOT_NULL(result->next, "second element should remain");
    TEST_ASSERT_STR_EQUAL("Host", result->next->key, "Host should survive prefix/extension keys");

    http_headers_free(result);
}

TEST(test_http_header_delete_first_duplicate_only) {
    TEST_CASE("http_header_delete removes only the first of duplicate keys");

    http_header_t* first = http_header_create("Set-Cookie", 10, "a=1", 3);
    TEST_REQUIRE_NOT_NULL(first, "first header should be created");
    first->next = http_header_create("Set-Cookie", 10, "b=2", 3);
    TEST_REQUIRE_NOT_NULL_GOTO(first->next, "second header should be created", cleanup);

    http_header_t* result = http_header_delete(first, "Set-Cookie");
    TEST_REQUIRE_NOT_NULL(result, "one duplicate should remain");
    TEST_ASSERT_STR_EQUAL("b=2", result->value, "the remaining header should be the second one");
    TEST_ASSERT_NULL(result->next, "only one element should remain");

    http_headers_free(result);
    return;

cleanup:
    http_headers_free(first);
}

// ============================================================================
// http_payloadpart_create / http_payloadpart_free
// ============================================================================

TEST(test_http_payloadpart_create_defaults) {
    TEST_CASE("http_payloadpart_create zero-initializes all fields");

    http_payloadpart_t* part = http_payloadpart_create();
    TEST_REQUIRE_NOT_NULL(part, "part should be created");

    TEST_ASSERT_NULL(part->field, "field should be NULL");
    TEST_ASSERT_NULL(part->header, "header should be NULL");
    TEST_ASSERT_NULL(part->next, "next should be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, part->offset, "offset should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, part->size, "size should be 0");

    http_payloadpart_free(part);
}

TEST(test_http_payloadpart_free_null) {
    TEST_CASE("http_payloadpart_free(NULL) is a no-op");

    http_payloadpart_free(NULL);
    TEST_ASSERT(1, "should not crash on NULL");
}

TEST(test_http_payloadpart_free_chain_with_contents) {
    TEST_CASE("http_payloadpart_free releases parts with fields and headers (LSan-checked)");

    http_payloadpart_t* first = http_payloadpart_create();
    TEST_REQUIRE_NOT_NULL(first, "first part should be created");

    first->field = http_payloadfield_create();
    TEST_REQUIRE_NOT_NULL_GOTO(first->field, "field should be created", cleanup);
    first->field->key = copy_cstringn("name", 4);
    first->field->key_length = 4;
    first->field->value = copy_cstringn("file.txt", 8);
    first->field->value_length = 8;

    first->header = http_header_create("Content-Disposition", 19, "form-data", 9);
    TEST_REQUIRE_NOT_NULL_GOTO(first->header, "header should be created", cleanup);
    first->header->next = http_header_create("Content-Type", 12, "text/plain", 10);
    TEST_REQUIRE_NOT_NULL_GOTO(first->header->next, "second header should be created", cleanup);

    first->next = http_payloadpart_create();
    TEST_REQUIRE_NOT_NULL_GOTO(first->next, "second part should be created", cleanup);

    http_payloadpart_free(first);
    TEST_ASSERT(1, "chain freed without crash");
    return;

cleanup:
    http_payloadpart_free(first);
}

// ============================================================================
// http_payloadfield_create / http_payloadfield_free
// ============================================================================

TEST(test_http_payloadfield_create_defaults) {
    TEST_CASE("http_payloadfield_create zero-initializes all fields");

    http_payloadfield_t* field = http_payloadfield_create();
    TEST_REQUIRE_NOT_NULL(field, "field should be created");

    TEST_ASSERT_NULL(field->key, "key should be NULL");
    TEST_ASSERT_NULL(field->value, "value should be NULL");
    TEST_ASSERT_NULL(field->next, "next should be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, field->key_length, "key_length should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, field->value_length, "value_length should be 0");

    http_payloadfield_free(field);
}

TEST(test_http_payloadfield_free_null) {
    TEST_CASE("http_payloadfield_free(NULL) is a no-op");

    http_payloadfield_free(NULL);
    TEST_ASSERT(1, "should not crash on NULL");
}

TEST(test_http_payloadfield_free_chain) {
    TEST_CASE("http_payloadfield_free releases a chain incl. NULL keys/values (LSan-checked)");

    http_payloadfield_t* first = http_payloadfield_create();
    TEST_REQUIRE_NOT_NULL(first, "first field should be created");
    first->key = copy_cstringn("a", 1);
    first->value = copy_cstringn("1", 1);

    /* second field keeps key/value NULL: free must tolerate that */
    first->next = http_payloadfield_create();
    TEST_REQUIRE_NOT_NULL_GOTO(first->next, "second field should be created", cleanup);

    http_payloadfield_free(first);
    TEST_ASSERT(1, "chain freed without crash");
    return;

cleanup:
    http_payloadfield_free(first);
}

// ============================================================================
// http_cookie_create / http_cookie_free
// ============================================================================

TEST(test_http_cookie_create_defaults) {
    TEST_CASE("http_cookie_create zero-initializes all fields");

    http_cookie_t* cookie = http_cookie_create();
    TEST_REQUIRE_NOT_NULL(cookie, "cookie should be created");

    TEST_ASSERT_NULL(cookie->key, "key should be NULL");
    TEST_ASSERT_NULL(cookie->value, "value should be NULL");
    TEST_ASSERT_NULL(cookie->next, "next should be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, cookie->key_length, "key_length should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, cookie->value_length, "value_length should be 0");

    http_cookie_free(cookie);
}

TEST(test_http_cookie_free_null) {
    TEST_CASE("http_cookie_free(NULL) is a no-op");

    http_cookie_free(NULL);
    TEST_ASSERT(1, "should not crash on NULL");
}

TEST(test_http_cookie_free_chain) {
    TEST_CASE("http_cookie_free releases a chain (LSan-checked)");

    http_cookie_t* first = http_cookie_create();
    TEST_REQUIRE_NOT_NULL(first, "first cookie should be created");
    first->key = copy_cstringn("session", 7);
    first->key_length = 7;
    first->value = copy_cstringn("abc123", 6);
    first->value_length = 6;

    first->next = http_cookie_create();
    TEST_REQUIRE_NOT_NULL_GOTO(first->next, "second cookie should be created", cleanup);

    http_cookie_free(first);
    TEST_ASSERT(1, "chain freed without crash");
    return;

cleanup:
    http_cookie_free(first);
}

// ============================================================================
// http_ranges_free
// ============================================================================

TEST(test_http_ranges_free_null) {
    TEST_CASE("http_ranges_free(NULL) is a no-op");

    http_ranges_free(NULL);
    TEST_ASSERT(1, "should not crash on NULL");
}

TEST(test_http_ranges_free_chain) {
    TEST_CASE("http_ranges_free releases a chain (LSan-checked)");

    http_ranges_t* first = malloc(sizeof *first);
    TEST_REQUIRE_NOT_NULL(first, "first range should be allocated");
    first->start = 0;
    first->end = 499;
    first->next = malloc(sizeof *first);
    TEST_REQUIRE_NOT_NULL_GOTO(first->next, "second range should be allocated", cleanup);
    first->next->start = 500;
    first->next->end = 999;
    first->next->next = NULL;

    http_ranges_free(first);
    TEST_ASSERT(1, "chain freed without crash");
    return;

cleanup:
    free(first);
}

// ============================================================================
// create_basic_auth_header
// ============================================================================

TEST(test_basic_auth_null_args) {
    TEST_CASE("create_basic_auth_header rejects NULL arguments");

    TEST_ASSERT_NULL(create_basic_auth_header(NULL, "pass"), "NULL first value should yield NULL");
    TEST_ASSERT_NULL(create_basic_auth_header("user", NULL), "NULL second value should yield NULL");
    TEST_ASSERT_NULL(create_basic_auth_header(NULL, NULL), "both NULL should yield NULL");
}

TEST(test_basic_auth_known_vector) {
    TEST_CASE("create_basic_auth_header produces the RFC 7617 example encoding");

    char* result = create_basic_auth_header("user", "pass");
    TEST_REQUIRE_NOT_NULL(result, "result should be created");

    TEST_ASSERT_STR_EQUAL("Basic dXNlcjpwYXNz", result, "should be base64 of 'user:pass' with prefix");
    free(result);
}

TEST(test_basic_auth_empty_values) {
    TEST_CASE("create_basic_auth_header handles empty credentials");

    char* result = create_basic_auth_header("", "");
    TEST_REQUIRE_NOT_NULL(result, "result should be created");

    /* raw string is ":" -> base64 "Og==" */
    TEST_ASSERT_STR_EQUAL("Basic Og==", result, "empty credentials should encode ':'");
    free(result);
}

TEST(test_basic_auth_colon_in_password) {
    TEST_CASE("create_basic_auth_header keeps colons inside the password");

    const char* user = "a";
    const char* pass = "b:c";
    const char* raw = "a:b:c";
    const size_t raw_len = 5;

    char expected[64] = "Basic ";
    base64_encode(expected + 6, raw, (int)raw_len);

    char* result = create_basic_auth_header(user, pass);
    TEST_REQUIRE_NOT_NULL(result, "result should be created");

    TEST_ASSERT_STR_EQUAL(expected, result, "password colons should be encoded as-is");
    free(result);
}

TEST(test_basic_auth_utf8_credentials) {
    TEST_CASE("create_basic_auth_header passes UTF-8 bytes through");

    const char* user = "пользователь";
    const char* pass = "пароль";

    size_t raw_len = strlen(user) + 1 + strlen(pass);
    char raw[128];
    snprintf(raw, sizeof(raw), "%s:%s", user, pass);

    char expected[256] = "Basic ";
    base64_encode(expected + 6, raw, (int)raw_len);

    char* result = create_basic_auth_header(user, pass);
    TEST_REQUIRE_NOT_NULL(result, "result should be created");

    TEST_ASSERT_STR_EQUAL(expected, result, "UTF-8 credentials should round-trip through base64");
    free(result);
}

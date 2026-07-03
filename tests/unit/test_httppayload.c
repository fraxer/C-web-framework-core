/*
 * Unit tests for protocols/http/httppayload.c
 *
 * Covers the typed payload-parameter accessors (payload_param_*) over real
 * urlencoded and multipart payloads. Several cases are regression guards for
 * bugs fixed alongside these tests (each is marked REGRESSION below):
 *
 *   - __prepare_and_get_value took `int** ok` and NULL-checked the address of
 *     the caller's local parameter (never NULL) instead of the user pointer,
 *     so passing ok == NULL to any public function dereferenced NULL.
 *   - get_payloadf returns a heap-allocated copy of the field value; every
 *     numeric/JSON accessor leaked it (payload_param_char now documents that
 *     the caller owns the returned string).
 *
 * env()/appconfig() weak symbols come from test_httprequestparser.c; we only
 * set env()->main.tmp so payload temp files land in a writable directory.
 */

#include "framework.h"
#include "httppayload.h"
#include "httprequest.h"
#include "appconfig.h"
#include "json.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>

// ============================================================================
// Helpers
// ============================================================================

static httprequest_t* make_request(void) {
    httprequest_t* request = httprequest_create(NULL);
    if (request != NULL)
        env()->main.tmp = "/tmp";
    return request;
}

/* Build a urlencoded request with one field. */
static httprequest_t* make_request_field(const char* name, const char* value) {
    httprequest_t* request = make_request();
    if (request == NULL) return NULL;

    if (request->append_urlencoded(request, name, value) == 0) {
        httprequest_free(request);
        return NULL;
    }

    return request;
}

// ============================================================================
// payload_param_char
// ============================================================================

TEST(test_payload_param_char_found) {
    TEST_SUITE("httppayload: char");
    TEST_CASE("existing field is returned with ok=1, caller frees");

    httprequest_t* request = make_request_field("name", "john");
    TEST_REQUIRE_NOT_NULL(request, "request built");

    int ok = -1;
    char* value = payload_param_char(request, "name", &ok);
    TEST_ASSERT_NOT_NULL(value, "value returned");
    if (value) TEST_ASSERT_STR_EQUAL("john", value, "value matches");
    TEST_ASSERT_EQUAL(1, ok, "ok set to 1");
    free(value);

    httprequest_free(request);
}

TEST(test_payload_param_char_missing) {
    TEST_SUITE("httppayload: char");
    TEST_CASE("missing field returns NULL with ok=0");

    httprequest_t* request = make_request_field("name", "john");
    TEST_REQUIRE_NOT_NULL(request, "request built");

    int ok = -1;
    TEST_ASSERT_NULL(payload_param_char(request, "missing", &ok), "missing -> NULL");
    TEST_ASSERT_EQUAL(0, ok, "ok reset to 0");

    httprequest_free(request);
}

TEST(test_payload_param_char_empty_value) {
    TEST_SUITE("httppayload: char");
    TEST_CASE("empty field value is still a successful lookup");

    httprequest_t* request = make_request_field("name", "");
    TEST_REQUIRE_NOT_NULL(request, "request built");

    int ok = -1;
    char* value = payload_param_char(request, "name", &ok);
    TEST_ASSERT_NOT_NULL(value, "value returned");
    if (value) TEST_ASSERT_STR_EQUAL("", value, "empty value");
    TEST_ASSERT_EQUAL(1, ok, "ok set to 1");
    free(value);

    httprequest_free(request);
}

TEST(test_payload_param_null_arguments) {
    TEST_SUITE("httppayload: argument validation");
    TEST_CASE("NULL request / NULL param_name fail with ok=0");

    httprequest_t* request = make_request_field("name", "john");
    TEST_REQUIRE_NOT_NULL(request, "request built");

    int ok = -1;
    TEST_ASSERT_NULL(payload_param_char(NULL, "name", &ok), "NULL request -> NULL");
    TEST_ASSERT_EQUAL(0, ok, "ok reset to 0");

    ok = -1;
    TEST_ASSERT_NULL(payload_param_char(request, NULL, &ok), "NULL param_name -> NULL");
    TEST_ASSERT_EQUAL(0, ok, "ok reset to 0");

    ok = -1;
    TEST_ASSERT_EQUAL(0, payload_param_int(NULL, "name", &ok), "int: NULL request -> 0");
    TEST_ASSERT_EQUAL(0, ok, "ok reset to 0");

    ok = -1;
    TEST_ASSERT_NULL(payload_param_object(NULL, "name", &ok), "object: NULL request -> NULL");
    TEST_ASSERT_EQUAL(0, ok, "ok reset to 0");

    httprequest_free(request);
}

/* REGRESSION: the ok pointer used to be dereferenced without a NULL check
 * (the guard tested the address of a local, which is never NULL). */
TEST(test_payload_param_null_ok_pointer) {
    TEST_SUITE("httppayload: argument validation");
    TEST_CASE("REGRESSION ok == NULL must not crash");

    httprequest_t* request = make_request_field("num", "7");
    TEST_REQUIRE_NOT_NULL(request, "request built");

    char* value = payload_param_char(request, "num", NULL);
    TEST_ASSERT_NOT_NULL(value, "char works without ok");
    if (value) TEST_ASSERT_STR_EQUAL("7", value, "value matches");
    free(value);

    TEST_ASSERT_EQUAL(7, payload_param_int(request, "num", NULL), "int works without ok");
    TEST_ASSERT(payload_param_uint(request, "num", NULL) == 7u, "uint works without ok");
    TEST_ASSERT(payload_param_long(request, "num", NULL) == 7L, "long works without ok");
    TEST_ASSERT(payload_param_ulong(request, "num", NULL) == 7UL, "ulong works without ok");
    TEST_ASSERT(payload_param_float(request, "num", NULL) == 7.0f, "float works without ok");
    TEST_ASSERT(payload_param_double(request, "num", NULL) == 7.0, "double works without ok");
    TEST_ASSERT(payload_param_ldouble(request, "num", NULL) == 7.0L, "ldouble works without ok");
    TEST_ASSERT_NULL(payload_param_array(request, "num", NULL), "array: scalar -> NULL, no crash");
    TEST_ASSERT_NULL(payload_param_object(request, "num", NULL), "object: scalar -> NULL, no crash");
    TEST_ASSERT_NULL(payload_param_char(request, "missing", NULL), "missing field without ok");

    httprequest_free(request);
}

// ============================================================================
// payload_param_int
// ============================================================================

TEST(test_payload_param_int_valid) {
    TEST_SUITE("httppayload: int");
    TEST_CASE("valid integers parse with ok=1");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");
    TEST_ASSERT(request->append_urlencoded(request, "pos", "42") != 0, "append pos");
    TEST_ASSERT(request->append_urlencoded(request, "neg", "-17") != 0, "append neg");
    TEST_ASSERT(request->append_urlencoded(request, "zero", "0") != 0, "append zero");

    int ok = 0;
    TEST_ASSERT_EQUAL(42, payload_param_int(request, "pos", &ok), "positive");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for positive");

    ok = 0;
    TEST_ASSERT_EQUAL(-17, payload_param_int(request, "neg", &ok), "negative");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for negative");

    ok = 0;
    TEST_ASSERT_EQUAL(0, payload_param_int(request, "zero", &ok), "zero");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for zero");

    httprequest_free(request);
}

TEST(test_payload_param_int_invalid) {
    TEST_SUITE("httppayload: int");
    TEST_CASE("non-numeric / overflow values return 0 with ok=0");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");
    TEST_ASSERT(request->append_urlencoded(request, "text", "abc") != 0, "append text");
    TEST_ASSERT(request->append_urlencoded(request, "mixed", "12abc") != 0, "append mixed");
    TEST_ASSERT(request->append_urlencoded(request, "float", "3.14") != 0, "append float");
    TEST_ASSERT(request->append_urlencoded(request, "big", "99999999999999999999") != 0, "append big");
    TEST_ASSERT(request->append_urlencoded(request, "empty", "") != 0, "append empty");

    int ok = 1;
    TEST_ASSERT_EQUAL(0, payload_param_int(request, "text", &ok), "text -> 0");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for text");

    ok = 1;
    TEST_ASSERT_EQUAL(0, payload_param_int(request, "mixed", &ok), "trailing garbage -> 0");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for trailing garbage");

    ok = 1;
    TEST_ASSERT_EQUAL(0, payload_param_int(request, "float", &ok), "float literal -> 0");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for float literal");

    ok = 1;
    TEST_ASSERT_EQUAL(0, payload_param_int(request, "big", &ok), "overflow -> 0");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for overflow");

    ok = 1;
    TEST_ASSERT_EQUAL(0, payload_param_int(request, "empty", &ok), "empty -> 0");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for empty");

    ok = 1;
    TEST_ASSERT_EQUAL(0, payload_param_int(request, "missing", &ok), "missing -> 0");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for missing");

    httprequest_free(request);
}

TEST(test_payload_param_int_limits) {
    TEST_SUITE("httppayload: int");
    TEST_CASE("INT_MIN/INT_MAX parse, values beyond are rejected");

    char buf[64];
    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");

    snprintf(buf, sizeof(buf), "%d", INT_MAX);
    TEST_ASSERT(request->append_urlencoded(request, "max", buf) != 0, "append max");
    snprintf(buf, sizeof(buf), "%d", INT_MIN);
    TEST_ASSERT(request->append_urlencoded(request, "min", buf) != 0, "append min");
    snprintf(buf, sizeof(buf), "%ld", (long)INT_MAX + 1);
    TEST_ASSERT(request->append_urlencoded(request, "over", buf) != 0, "append over");

    int ok = 0;
    TEST_ASSERT_EQUAL(INT_MAX, payload_param_int(request, "max", &ok), "INT_MAX parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for INT_MAX");

    ok = 0;
    TEST_ASSERT_EQUAL(INT_MIN, payload_param_int(request, "min", &ok), "INT_MIN parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for INT_MIN");

    ok = 1;
    TEST_ASSERT_EQUAL(0, payload_param_int(request, "over", &ok), "INT_MAX+1 rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for INT_MAX+1");

    httprequest_free(request);
}

// ============================================================================
// payload_param_uint
// ============================================================================

TEST(test_payload_param_uint) {
    TEST_SUITE("httppayload: uint");
    TEST_CASE("unsigned parsing accepts UINT_MAX, rejects negatives and overflow");

    char buf[64];
    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");

    TEST_ASSERT(request->append_urlencoded(request, "val", "123") != 0, "append val");
    TEST_ASSERT(request->append_urlencoded(request, "neg", "-1") != 0, "append neg");
    snprintf(buf, sizeof(buf), "%u", UINT_MAX);
    TEST_ASSERT(request->append_urlencoded(request, "max", buf) != 0, "append max");
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)UINT_MAX + 1);
    TEST_ASSERT(request->append_urlencoded(request, "over", buf) != 0, "append over");

    int ok = 0;
    TEST_ASSERT(payload_param_uint(request, "val", &ok) == 123u, "123 parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1");

    ok = 1;
    TEST_ASSERT(payload_param_uint(request, "neg", &ok) == 0u, "negative rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for negative");

    ok = 0;
    TEST_ASSERT(payload_param_uint(request, "max", &ok) == UINT_MAX, "UINT_MAX parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for UINT_MAX");

    ok = 1;
    TEST_ASSERT(payload_param_uint(request, "over", &ok) == 0u, "UINT_MAX+1 rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for UINT_MAX+1");

    httprequest_free(request);
}

// ============================================================================
// payload_param_long / payload_param_ulong
// ============================================================================

TEST(test_payload_param_long) {
    TEST_SUITE("httppayload: long");
    TEST_CASE("long parsing handles LONG_MIN/LONG_MAX and rejects overflow");

    char buf[64];
    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");

    snprintf(buf, sizeof(buf), "%ld", LONG_MAX);
    TEST_ASSERT(request->append_urlencoded(request, "max", buf) != 0, "append max");
    snprintf(buf, sizeof(buf), "%ld", LONG_MIN);
    TEST_ASSERT(request->append_urlencoded(request, "min", buf) != 0, "append min");
    TEST_ASSERT(request->append_urlencoded(request, "over", "99999999999999999999999") != 0, "append over");

    int ok = 0;
    TEST_ASSERT(payload_param_long(request, "max", &ok) == LONG_MAX, "LONG_MAX parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for LONG_MAX");

    ok = 0;
    TEST_ASSERT(payload_param_long(request, "min", &ok) == LONG_MIN, "LONG_MIN parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for LONG_MIN");

    ok = 1;
    TEST_ASSERT(payload_param_long(request, "over", &ok) == 0L, "overflow rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for overflow");

    httprequest_free(request);
}

TEST(test_payload_param_ulong) {
    TEST_SUITE("httppayload: ulong");
    TEST_CASE("ulong parsing handles ULONG_MAX and rejects negatives");

    char buf[64];
    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");

    snprintf(buf, sizeof(buf), "%lu", ULONG_MAX);
    TEST_ASSERT(request->append_urlencoded(request, "max", buf) != 0, "append max");
    TEST_ASSERT(request->append_urlencoded(request, "neg", "-5") != 0, "append neg");

    int ok = 0;
    TEST_ASSERT(payload_param_ulong(request, "max", &ok) == ULONG_MAX, "ULONG_MAX parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for ULONG_MAX");

    ok = 1;
    TEST_ASSERT(payload_param_ulong(request, "neg", &ok) == 0UL, "negative rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for negative");

    httprequest_free(request);
}

// ============================================================================
// payload_param_float / double / ldouble
// ============================================================================

TEST(test_payload_param_float) {
    TEST_SUITE("httppayload: float");
    TEST_CASE("float parsing accepts decimals, rejects garbage");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");
    TEST_ASSERT(request->append_urlencoded(request, "pi", "3.14") != 0, "append pi");
    TEST_ASSERT(request->append_urlencoded(request, "neg", "-2.5") != 0, "append neg");
    TEST_ASSERT(request->append_urlencoded(request, "int", "10") != 0, "append int");
    TEST_ASSERT(request->append_urlencoded(request, "bad", "3.14abc") != 0, "append bad");

    int ok = 0;
    float pi = payload_param_float(request, "pi", &ok);
    TEST_ASSERT(pi > 3.13f && pi < 3.15f, "3.14 parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for 3.14");

    ok = 0;
    TEST_ASSERT(payload_param_float(request, "neg", &ok) == -2.5f, "-2.5 parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for -2.5");

    ok = 0;
    TEST_ASSERT(payload_param_float(request, "int", &ok) == 10.0f, "integer literal parses as float");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for integer literal");

    ok = 1;
    TEST_ASSERT(payload_param_float(request, "bad", &ok) == 0.0f, "trailing garbage rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for trailing garbage");

    httprequest_free(request);
}

TEST(test_payload_param_double) {
    TEST_SUITE("httppayload: double");
    TEST_CASE("double parsing accepts decimals and exponents, rejects inf/nan");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");
    TEST_ASSERT(request->append_urlencoded(request, "val", "2.718281828") != 0, "append val");
    TEST_ASSERT(request->append_urlencoded(request, "exp", "1e3") != 0, "append exp");
    TEST_ASSERT(request->append_urlencoded(request, "inf", "inf") != 0, "append inf");
    TEST_ASSERT(request->append_urlencoded(request, "nan", "nan") != 0, "append nan");

    int ok = 0;
    double e = payload_param_double(request, "val", &ok);
    TEST_ASSERT(e > 2.718 && e < 2.719, "2.718281828 parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for decimal");

    ok = 0;
    TEST_ASSERT(payload_param_double(request, "exp", &ok) == 1000.0, "1e3 parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for exponent");

    ok = 1;
    TEST_ASSERT(payload_param_double(request, "inf", &ok) == 0.0, "inf rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for inf");

    ok = 1;
    TEST_ASSERT(payload_param_double(request, "nan", &ok) == 0.0, "nan rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for nan");

    httprequest_free(request);
}

TEST(test_payload_param_ldouble) {
    TEST_SUITE("httppayload: long double");
    TEST_CASE("long double parsing works and rejects garbage");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");
    TEST_ASSERT(request->append_urlencoded(request, "val", "1.5") != 0, "append val");
    TEST_ASSERT(request->append_urlencoded(request, "bad", "abc") != 0, "append bad");

    int ok = 0;
    TEST_ASSERT(payload_param_ldouble(request, "val", &ok) == 1.5L, "1.5 parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for 1.5");

    ok = 1;
    TEST_ASSERT(payload_param_ldouble(request, "bad", &ok) == 0.0L, "garbage rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for garbage");

    httprequest_free(request);
}

// ============================================================================
// payload_param_array / payload_param_object
// ============================================================================

TEST(test_payload_param_array) {
    TEST_SUITE("httppayload: json array");
    TEST_CASE("array field parses; object/scalar/broken json rejected");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");
    TEST_ASSERT(request->append_urlencoded(request, "arr", "[1,2,3]") != 0, "append arr");
    TEST_ASSERT(request->append_urlencoded(request, "obj", "{\"a\":1}") != 0, "append obj");
    TEST_ASSERT(request->append_urlencoded(request, "scalar", "42") != 0, "append scalar");
    TEST_ASSERT(request->append_urlencoded(request, "broken", "[1,2") != 0, "append broken");
    TEST_ASSERT(request->append_urlencoded(request, "empty", "") != 0, "append empty");

    int ok = 0;
    json_doc_t* doc = payload_param_array(request, "arr", &ok);
    TEST_ASSERT_NOT_NULL(doc, "array parsed");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for array");
    if (doc) {
        json_token_t* root = json_root(doc);
        TEST_ASSERT(json_is_array(root), "root is array");
        TEST_ASSERT_EQUAL(3, json_array_size(root), "3 elements");
        json_free(doc);
    }

    ok = 1;
    TEST_ASSERT_NULL(payload_param_array(request, "obj", &ok), "object rejected as array");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for object");

    ok = 1;
    TEST_ASSERT_NULL(payload_param_array(request, "scalar", &ok), "scalar rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for scalar");

    ok = 1;
    TEST_ASSERT_NULL(payload_param_array(request, "broken", &ok), "broken json rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for broken json");

    ok = 1;
    TEST_ASSERT_NULL(payload_param_array(request, "empty", &ok), "empty value rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for empty value");

    ok = 1;
    TEST_ASSERT_NULL(payload_param_array(request, "missing", &ok), "missing field rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for missing field");

    httprequest_free(request);
}

TEST(test_payload_param_object) {
    TEST_SUITE("httppayload: json object");
    TEST_CASE("object field parses; array/scalar/broken json rejected");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");
    TEST_ASSERT(request->append_urlencoded(request, "obj", "{\"a\":1,\"b\":\"x\"}") != 0, "append obj");
    TEST_ASSERT(request->append_urlencoded(request, "arr", "[1,2,3]") != 0, "append arr");
    TEST_ASSERT(request->append_urlencoded(request, "broken", "{\"a\":") != 0, "append broken");

    int ok = 0;
    json_doc_t* doc = payload_param_object(request, "obj", &ok);
    TEST_ASSERT_NOT_NULL(doc, "object parsed");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for object");
    if (doc) {
        json_token_t* root = json_root(doc);
        TEST_ASSERT(json_is_object(root), "root is object");
        json_token_t* a = json_object_get(root, "a");
        TEST_ASSERT_NOT_NULL(a, "field a present");
        int aok = 0;
        if (a) TEST_ASSERT_EQUAL(1, json_int(a, &aok), "a == 1");
        json_free(doc);
    }

    ok = 1;
    TEST_ASSERT_NULL(payload_param_object(request, "arr", &ok), "array rejected as object");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for array");

    ok = 1;
    TEST_ASSERT_NULL(payload_param_object(request, "broken", &ok), "broken json rejected");
    TEST_ASSERT_EQUAL(0, ok, "ok=0 for broken json");

    httprequest_free(request);
}

// ============================================================================
// Multipart payloads go through the same accessors
// ============================================================================

TEST(test_payload_param_multipart) {
    TEST_SUITE("httppayload: multipart");
    TEST_CASE("typed accessors work over multipart fields too");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request built");
    TEST_ASSERT(request->append_formdata_text(request, "name", "alice") != 0, "append name");
    TEST_ASSERT(request->append_formdata_text(request, "age", "33") != 0, "append age");
    TEST_ASSERT(request->append_formdata_text(request, "tags", "[\"a\",\"b\"]") != 0, "append tags");

    int ok = 0;
    char* name = payload_param_char(request, "name", &ok);
    TEST_ASSERT_NOT_NULL(name, "name read");
    if (name) TEST_ASSERT_STR_EQUAL("alice", name, "name value");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for name");
    free(name);

    ok = 0;
    TEST_ASSERT_EQUAL(33, payload_param_int(request, "age", &ok), "age parses");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for age");

    ok = 0;
    json_doc_t* doc = payload_param_array(request, "tags", &ok);
    TEST_ASSERT_NOT_NULL(doc, "tags parse as array");
    TEST_ASSERT_EQUAL(1, ok, "ok=1 for tags");
    if (doc) json_free(doc);

    httprequest_free(request);
}

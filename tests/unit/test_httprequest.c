/*
 * Unit tests for protocols/http/httprequest.c
 *
 * Covers the request-building and payload-reading surface: headers, cookies,
 * method<->string mapping, head serialization, and the plain/urlencoded/
 * multipart payload round-trips. Several cases are regression guards for bugs
 * fixed alongside these tests (each is marked REGRESSION below):
 *
 *   - httprequest_header_del left last_header dangling when the list emptied,
 *     so the next add_header wrote through a freed pointer (heap-UAF).
 *   - httprequest_set_payload_json passed the payload length as a separate
 *     argument evaluated (order-unspecified) possibly before the string was
 *     produced, yielding a zero-length body.
 *   - httprequest_payload_filef read the part/field union as a `part` even for
 *     non-multipart payloads (type confusion -> wild dereference).
 *
 * env()/appconfig()/appconfig_set() are provided as weak symbols by
 * test_httprequestparser.c and shared across the runner; we only read/adjust
 * env()->main.tmp so the payload temp files land in a writable directory.
 */

#include "framework.h"
#include "httprequest.h"
#include "httpcommon.h"
#include "appconfig.h"
#include "json.h"

#include <string.h>
#include <stdlib.h>

/* Non-static functions with external linkage that httprequest.c exposes but
 * does not declare in httprequest.h. */
const char* httprequest_method_string(route_methods_e method);
size_t httprequest_method_length(route_methods_e method);
void httprequest_reset(httprequest_t* request);

// ============================================================================
// Helpers
// ============================================================================

static void use_tmp_dir(void) {
    env()->main.tmp = "/tmp";
}

static httprequest_t* make_request(void) {
    httprequest_t* request = httprequest_create(NULL);
    if (request != NULL)
        use_tmp_dir();
    return request;
}

static char* dup_cstr(const char* s) {
    size_t n = strlen(s);
    char* p = malloc(n + 1);
    if (p == NULL) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

/* Copy the (non NUL-terminated) serialized head into a C string for searching. */
static char* head_to_cstr(const httprequest_head_t* head) {
    char* buf = malloc(head->size + 1);
    if (buf == NULL) return NULL;
    memcpy(buf, head->data, head->size);
    buf[head->size] = 0;
    return buf;
}

// ============================================================================
// Method <-> string mapping
// ============================================================================

TEST(test_httprequest_method_string) {
    TEST_SUITE("httprequest: method string/length");
    TEST_CASE("httprequest_method_string maps every method");

    TEST_ASSERT(httprequest_method_string(ROUTE_NONE) == NULL, "NONE -> NULL");
    TEST_ASSERT_STR_EQUAL("GET", httprequest_method_string(ROUTE_GET), "GET");
    TEST_ASSERT_STR_EQUAL("POST", httprequest_method_string(ROUTE_POST), "POST");
    TEST_ASSERT_STR_EQUAL("PUT", httprequest_method_string(ROUTE_PUT), "PUT");
    TEST_ASSERT_STR_EQUAL("DELETE", httprequest_method_string(ROUTE_DELETE), "DELETE");
    TEST_ASSERT_STR_EQUAL("OPTIONS", httprequest_method_string(ROUTE_OPTIONS), "OPTIONS");
    TEST_ASSERT_STR_EQUAL("PATCH", httprequest_method_string(ROUTE_PATCH), "PATCH");
    TEST_ASSERT_STR_EQUAL("HEAD", httprequest_method_string(ROUTE_HEAD), "HEAD");
}

TEST(test_httprequest_method_length) {
    TEST_SUITE("httprequest: method string/length");
    TEST_CASE("httprequest_method_length matches strlen of the method name");

    TEST_ASSERT_EQUAL_SIZE(0, httprequest_method_length(ROUTE_NONE), "NONE len");
    TEST_ASSERT_EQUAL_SIZE(3, httprequest_method_length(ROUTE_GET), "GET len");
    TEST_ASSERT_EQUAL_SIZE(4, httprequest_method_length(ROUTE_POST), "POST len");
    TEST_ASSERT_EQUAL_SIZE(3, httprequest_method_length(ROUTE_PUT), "PUT len");
    TEST_ASSERT_EQUAL_SIZE(6, httprequest_method_length(ROUTE_DELETE), "DELETE len");
    TEST_ASSERT_EQUAL_SIZE(7, httprequest_method_length(ROUTE_OPTIONS), "OPTIONS len");
    TEST_ASSERT_EQUAL_SIZE(5, httprequest_method_length(ROUTE_PATCH), "PATCH len");
    TEST_ASSERT_EQUAL_SIZE(4, httprequest_method_length(ROUTE_HEAD), "HEAD len");

    /* Every non-NONE method's length must equal strlen of its string form. */
    for (int m = ROUTE_GET; m <= ROUTE_HEAD; m++) {
        const char* s = httprequest_method_string((route_methods_e)m);
        TEST_ASSERT_NOT_NULL(s, "method string present");
        if (s)
            TEST_ASSERT_EQUAL_SIZE(strlen(s), httprequest_method_length((route_methods_e)m), "len == strlen");
    }
}

TEST(test_httprequest_allow_payload) {
    TEST_SUITE("httprequest: allow payload");
    TEST_CASE("only POST/PUT/PATCH may carry a payload");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    request->method = ROUTE_POST;
    TEST_ASSERT(httprequest_allow_payload(request) == 1, "POST allowed");
    request->method = ROUTE_PUT;
    TEST_ASSERT(httprequest_allow_payload(request) == 1, "PUT allowed");
    request->method = ROUTE_PATCH;
    TEST_ASSERT(httprequest_allow_payload(request) == 1, "PATCH allowed");

    request->method = ROUTE_GET;
    TEST_ASSERT(httprequest_allow_payload(request) == 0, "GET not allowed");
    request->method = ROUTE_DELETE;
    TEST_ASSERT(httprequest_allow_payload(request) == 0, "DELETE not allowed");
    request->method = ROUTE_HEAD;
    TEST_ASSERT(httprequest_allow_payload(request) == 0, "HEAD not allowed");
    request->method = ROUTE_NONE;
    TEST_ASSERT(httprequest_allow_payload(request) == 0, "NONE not allowed");

    httprequest_free(request);
}

// ============================================================================
// Headers
// ============================================================================

TEST(test_httprequest_headers_basic) {
    TEST_SUITE("httprequest: headers");
    TEST_CASE("add/get headers, case-insensitive lookup, get_headern");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    TEST_ASSERT_EQUAL(0, request->add_header(request, "Content-Type", "text/plain"), "add ok");
    TEST_ASSERT_EQUAL(0, request->add_header(request, "X-Token", "abc123"), "add ok");

    http_header_t* ct = request->get_header(request, "content-type");
    TEST_ASSERT_NOT_NULL(ct, "case-insensitive lookup");
    if (ct) TEST_ASSERT_STR_EQUAL("text/plain", ct->value, "value");

    http_header_t* upper = request->get_header(request, "CONTENT-TYPE");
    TEST_ASSERT_NOT_NULL(upper, "upper-case lookup finds same header");

    http_header_t* tok = request->get_headern(request, "X-Token-EXTRA", 7); /* only "X-Token" */
    TEST_ASSERT_NOT_NULL(tok, "get_headern honours length");
    if (tok) TEST_ASSERT_STR_EQUAL("abc123", tok->value, "value via headern");

    TEST_ASSERT_NULL(request->get_header(request, "Missing"), "absent header -> NULL");

    httprequest_free(request);
}

TEST(test_httprequest_header_del_middle_and_tail) {
    TEST_SUITE("httprequest: headers");
    TEST_CASE("remove keeps list and last_header consistent");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    request->method = ROUTE_GET;                /* needed for create_head below */
    request->uri = dup_cstr("/");
    request->uri_length = 1;

    request->add_header(request, "A", "1");
    request->add_header(request, "B", "2");
    request->add_header(request, "C", "3");

    /* delete middle */
    request->remove_header(request, "B");
    TEST_ASSERT_NULL(request->get_header(request, "B"), "B removed");
    TEST_ASSERT_NOT_NULL(request->get_header(request, "A"), "A kept");
    TEST_ASSERT_NOT_NULL(request->get_header(request, "C"), "C kept");

    /* delete tail, then append -> exercises last_header rebuild */
    request->remove_header(request, "C");
    request->add_header(request, "D", "4");

    httprequest_head_t head = httprequest_create_head(request);
    TEST_REQUIRE(head.size > 0 && head.data != NULL, "head serialized");
    char* text = head_to_cstr(&head);
    free(head.data);
    TEST_REQUIRE_NOT_NULL(text, "head copied");
    TEST_ASSERT_NOT_NULL(strstr(text, "A: 1\r\n"), "A present");
    TEST_ASSERT_NOT_NULL(strstr(text, "D: 4\r\n"), "D appended after tail delete");
    TEST_ASSERT_NULL(strstr(text, "C: 3\r\n"), "C absent");
    free(text);

    httprequest_free(request);
}

/* REGRESSION: deleting the only header used to leave last_header dangling; the
 * following add_header would write last_header->next into freed memory. Under
 * ASan the bug aborts the runner here; the assertions check the repaired state. */
TEST(test_httprequest_header_del_empties_then_add) {
    TEST_SUITE("httprequest: headers");
    TEST_CASE("REGRESSION delete-only-header then add does not use freed memory");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    request->method = ROUTE_GET;                /* needed for create_head below */
    request->uri = dup_cstr("/");
    request->uri_length = 1;

    request->add_header(request, "Content-Type", "text/plain");
    request->remove_header(request, "Content-Type");           /* list becomes empty */
    TEST_ASSERT_NULL(request->get_header(request, "Content-Type"), "empty after delete");

    request->add_header(request, "X-First", "1");              /* must not touch freed tail */
    request->add_header(request, "X-Second", "2");

    http_header_t* first = request->get_header(request, "X-First");
    http_header_t* second = request->get_header(request, "X-Second");
    TEST_ASSERT_NOT_NULL(first, "X-First present");
    TEST_ASSERT_NOT_NULL(second, "X-Second present");
    if (first) TEST_ASSERT_STR_EQUAL("1", first->value, "X-First value");
    if (second) TEST_ASSERT_STR_EQUAL("2", second->value, "X-Second value");

    /* Order must be X-First then X-Second (last_header was correctly rebuilt). */
    httprequest_head_t head = httprequest_create_head(request);
    TEST_REQUIRE(head.size > 0 && head.data != NULL, "head serialized");
    char* text = head_to_cstr(&head);
    free(head.data);
    TEST_REQUIRE_NOT_NULL(text, "head copied");
    char* p1 = strstr(text, "X-First: 1\r\n");
    char* p2 = strstr(text, "X-Second: 2\r\n");
    TEST_ASSERT_NOT_NULL(p1, "X-First serialized");
    TEST_ASSERT_NOT_NULL(p2, "X-Second serialized");
    if (p1 && p2) TEST_ASSERT(p1 < p2, "insertion order preserved");
    free(text);

    httprequest_free(request);
}

// ============================================================================
// Cookies
// ============================================================================

TEST(test_httprequest_cookie_lookup) {
    TEST_SUITE("httprequest: cookies");
    TEST_CASE("get_cookie is case-insensitive on key and returns value");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    http_cookie_t* c1 = http_cookie_create();
    http_cookie_t* c2 = http_cookie_create();
    TEST_REQUIRE(c1 != NULL && c2 != NULL, "cookies allocated");

    c1->key = dup_cstr("session");
    c1->key_length = strlen("session");
    c1->value = dup_cstr("abc");
    c1->value_length = strlen("abc");
    c1->next = c2;

    c2->key = dup_cstr("theme");
    c2->key_length = strlen("theme");
    c2->value = dup_cstr("dark");
    c2->value_length = strlen("dark");

    request->cookie_ = c1;

    const char* v = request->get_cookie(request, "session");
    TEST_ASSERT_NOT_NULL(v, "session found");
    if (v) TEST_ASSERT_STR_EQUAL("abc", v, "session value");

    const char* v_ci = request->get_cookie(request, "SESSION");
    TEST_ASSERT_NOT_NULL(v_ci, "case-insensitive key");
    if (v_ci) TEST_ASSERT_STR_EQUAL("abc", v_ci, "value via CI key");

    const char* v2 = request->get_cookie(request, "theme");
    TEST_ASSERT_NOT_NULL(v2, "second cookie found");
    if (v2) TEST_ASSERT_STR_EQUAL("dark", v2, "theme value");

    TEST_ASSERT_NULL(request->get_cookie(request, "missing"), "absent cookie -> NULL");

    httprequest_free(request); /* frees the cookie chain */
}

// ============================================================================
// Head serialization
// ============================================================================

TEST(test_httprequest_create_head) {
    TEST_SUITE("httprequest: create_head");
    TEST_CASE("serialized request line + headers + terminator");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    request->method = ROUTE_GET;
    request->uri = dup_cstr("/api");
    request->uri_length = strlen("/api");
    request->add_header(request, "Host", "localhost");

    httprequest_head_t head = httprequest_create_head(request);
    TEST_REQUIRE(head.size > 0 && head.data != NULL, "head serialized");

    char* text = head_to_cstr(&head);
    free(head.data);
    TEST_REQUIRE_NOT_NULL(text, "head copied");

    TEST_ASSERT(strncmp(text, "GET /api HTTP/1.1\r\n", 19) == 0, "request line");
    TEST_ASSERT_NOT_NULL(strstr(text, "Host: localhost\r\n"), "host header");

    size_t len = strlen(text);
    TEST_ASSERT(len >= 4 && strcmp(text + len - 4, "\r\n\r\n") == 0, "blank-line terminator");
    free(text);

    httprequest_free(request);
}

TEST(test_httprequest_create_head_no_method) {
    TEST_SUITE("httprequest: create_head");
    TEST_CASE("method NONE yields empty head, no allocation to leak");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    request->method = ROUTE_NONE;               /* head_size == 0 */
    httprequest_head_t head = httprequest_create_head(request);
    TEST_ASSERT_EQUAL_SIZE(0, head.size, "size 0");
    TEST_ASSERT_NULL(head.data, "no buffer allocated");

    httprequest_free(request);
}

// ============================================================================
// Plain payload
// ============================================================================

TEST(test_httprequest_payload_plain_text) {
    TEST_SUITE("httprequest: plain payload");
    TEST_CASE("set_payload_text round-trips through get_payload");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    TEST_ASSERT(request->set_payload_text(request, "hello world") != 0, "set text");

    char* body = request->get_payload(request);
    TEST_REQUIRE_NOT_NULL(body, "payload read");
    TEST_ASSERT_STR_EQUAL("hello world", body, "body matches");
    TEST_ASSERT_EQUAL(PLAIN, request->payload_.type, "type PLAIN");
    free(body);

    /* a field lookup on a plain payload is meaningless -> NULL */
    TEST_ASSERT_NULL(request->get_payloadf(request, "x"), "plain + field -> NULL");

    httprequest_free(request);
}

TEST(test_httprequest_payload_raw_and_json_parse) {
    TEST_SUITE("httprequest: plain payload");
    TEST_CASE("set_payload_raw with json content, get_payload_json parses it");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    const char* raw = "{\"k\":7}";
    TEST_ASSERT(request->set_payload_raw(request, raw, strlen(raw), "application/json") != 0, "set raw");

    json_doc_t* doc = request->get_payload_json(request);
    TEST_REQUIRE_NOT_NULL(doc, "json parsed");
    json_token_t* root = json_root(doc);
    TEST_REQUIRE_NOT_NULL(root, "root");
    json_token_t* k = json_object_get(root, "k");
    TEST_REQUIRE_NOT_NULL(k, "field k");
    int ok = 0;
    TEST_ASSERT_EQUAL(7, json_int(k, &ok), "k == 7");
    TEST_ASSERT(ok == 1, "k is int");
    json_free(doc);

    httprequest_free(request);
}

/* REGRESSION: set_payload_json used to read the length in a separate argument
 * whose evaluation could precede json_stringify(), producing an empty body. */
TEST(test_httprequest_set_payload_json) {
    TEST_SUITE("httprequest: plain payload");
    TEST_CASE("REGRESSION set_payload_json writes the full document");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    json_doc_t* doc = json_parse("{\"a\":42,\"b\":\"hi\"}");
    TEST_REQUIRE_NOT_NULL(doc, "source doc parsed");

    TEST_ASSERT(request->set_payload_json(request, doc) != 0, "set_payload_json ok");
    json_free(doc);

    char* body = request->get_payload(request);
    TEST_REQUIRE_NOT_NULL(body, "payload read");
    TEST_ASSERT(strlen(body) > 0, "body not empty");
    free(body);

    json_doc_t* got = request->get_payload_json(request);
    TEST_REQUIRE_NOT_NULL(got, "payload re-parsed");
    json_token_t* root = json_root(got);
    TEST_REQUIRE_NOT_NULL(root, "root");
    int ok = 0;
    json_token_t* a = json_object_get(root, "a");
    TEST_REQUIRE_NOT_NULL(a, "field a");
    TEST_ASSERT_EQUAL(42, json_int(a, &ok), "a == 42");
    json_token_t* b = json_object_get(root, "b");
    TEST_REQUIRE_NOT_NULL(b, "field b");
    TEST_ASSERT_STR_EQUAL("hi", json_string(b), "b == hi");
    json_free(got);

    /* Content-Type set to application/json */
    http_header_t* ct = request->get_header(request, "Content-Type");
    TEST_ASSERT_NOT_NULL(ct, "content-type set");
    if (ct) TEST_ASSERT_STR_EQUAL("application/json", ct->value, "json content-type");

    httprequest_free(request);
}

// ============================================================================
// URL-encoded payload
// ============================================================================

TEST(test_httprequest_payload_urlencoded) {
    TEST_SUITE("httprequest: urlencoded payload");
    TEST_CASE("append_urlencoded then read fields back");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    TEST_ASSERT(request->append_urlencoded(request, "name", "john") != 0, "append name");
    TEST_ASSERT(request->append_urlencoded(request, "age", "30") != 0, "append age");

    char* name = request->get_payloadf(request, "name");
    TEST_ASSERT_NOT_NULL(name, "name field");
    if (name) TEST_ASSERT_STR_EQUAL("john", name, "name value");
    free(name);

    char* age = request->get_payloadf(request, "age");
    TEST_ASSERT_NOT_NULL(age, "age field");
    if (age) TEST_ASSERT_STR_EQUAL("30", age, "age value");
    free(age);

    TEST_ASSERT_NULL(request->get_payloadf(request, "missing"), "missing field -> NULL");
    TEST_ASSERT_EQUAL(URLENCODED, request->payload_.type, "type URLENCODED");

    /* get_payload (field == NULL) returns the first field's value */
    char* first = request->get_payload(request);
    TEST_ASSERT_NOT_NULL(first, "first field");
    if (first) TEST_ASSERT_STR_EQUAL("john", first, "first == name value");
    free(first);

    http_header_t* ct = request->get_header(request, "Content-Type");
    TEST_ASSERT_NOT_NULL(ct, "content-type set");
    if (ct) TEST_ASSERT_STR_EQUAL("application/x-www-form-urlencoded", ct->value, "urlencoded ct");

    httprequest_free(request);
}

// ============================================================================
// Multipart payload
// ============================================================================

TEST(test_httprequest_payload_multipart_text) {
    TEST_SUITE("httprequest: multipart payload");
    TEST_CASE("append_formdata_text then read fields back");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    TEST_ASSERT(request->append_formdata_text(request, "name", "John") != 0, "append name");
    TEST_ASSERT(request->append_formdata_text(request, "city", "London") != 0, "append city");

    char* name = request->get_payloadf(request, "name");
    TEST_ASSERT_NOT_NULL(name, "name field");
    if (name) TEST_ASSERT_STR_EQUAL("John", name, "name value");
    free(name);

    char* city = request->get_payloadf(request, "city");
    TEST_ASSERT_NOT_NULL(city, "city field");
    if (city) TEST_ASSERT_STR_EQUAL("London", city, "city value");
    free(city);

    TEST_ASSERT_EQUAL(MULTIPART, request->payload_.type, "type MULTIPART");
    TEST_ASSERT_NULL(request->get_payloadf(request, "nope"), "missing field -> NULL");

    /* get_payload (field == NULL) returns the first part's data */
    char* first = request->get_payload(request);
    TEST_ASSERT_NOT_NULL(first, "first part");
    if (first) TEST_ASSERT_STR_EQUAL("John", first, "first == name value");
    free(first);

    http_header_t* ct = request->get_header(request, "Content-Type");
    TEST_ASSERT_NOT_NULL(ct, "content-type set");
    if (ct) TEST_ASSERT_NOT_NULL(strstr(ct->value, "multipart/form-data; boundary="), "multipart ct");

    httprequest_free(request);
}

TEST(test_httprequest_payload_filef_text_field_not_a_file) {
    TEST_SUITE("httprequest: multipart payload");
    TEST_CASE("get_payload_filef on a non-file field reports ok=0");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    TEST_ASSERT(request->append_formdata_text(request, "name", "John") != 0, "append name");

    file_content_t fc = request->get_payload_filef(request, "name");
    TEST_ASSERT(fc.ok == 0, "text field is not a file -> ok=0");

    httprequest_free(request);
}

/* REGRESSION: get_payload_filef used to read the part/field union as a `part`
 * regardless of type. On a urlencoded payload that reinterprets an
 * http_payloadfield_t* as an http_payloadpart_t* and dereferences garbage. */
TEST(test_httprequest_payload_filef_wrong_type_is_safe) {
    TEST_SUITE("httprequest: multipart payload");
    TEST_CASE("REGRESSION get_payload_filef on urlencoded payload is safe");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    TEST_ASSERT(request->append_urlencoded(request, "a", "1") != 0, "append field");

    file_content_t fc = request->get_payload_filef(request, "a");
    TEST_ASSERT(fc.ok == 0, "non-multipart -> ok=0");
    TEST_ASSERT(fc.fd == -1, "non-multipart -> fd=-1");

    /* get_payload_file (no field) must be equally safe */
    file_content_t fc2 = request->get_payload_file(request);
    TEST_ASSERT(fc2.ok == 0, "no-field non-multipart -> ok=0");

    httprequest_free(request);
}

// ============================================================================
// Reset / lifecycle
// ============================================================================

TEST(test_httprequest_reset_clears_payload) {
    TEST_SUITE("httprequest: lifecycle");
    TEST_CASE("reset drops payload and headers, request is reusable");

    httprequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocated");

    request->add_header(request, "Content-Type", "text/plain");
    TEST_ASSERT(request->set_payload_text(request, "data") != 0, "set text");

    httprequest_reset(request);

    TEST_ASSERT_NULL(request->get_header(request, "Content-Type"), "headers cleared");
    TEST_ASSERT(request->payload_.type == NONE, "payload type reset");
    TEST_ASSERT(request->payload_.file.fd < 0, "payload file closed");

    /* reusable after reset */
    TEST_ASSERT(request->set_payload_text(request, "again") != 0, "set text after reset");
    char* body = request->get_payload(request);
    TEST_ASSERT_NOT_NULL(body, "payload read after reset");
    if (body) TEST_ASSERT_STR_EQUAL("again", body, "new body");
    free(body);

    httprequest_free(request);
}

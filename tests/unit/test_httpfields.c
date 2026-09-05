#include "framework.h"

#include "httpfields.h"
#include "httpcommon.h"
#include "httprequest.h"

#include <string.h>

/* The shared field→request builder (docs/http3/05-http3.md §6.1). The cases are
 * the §4.1/§8.3 violations h2spec probes over TLS, lifted into a unit test so
 * the same rules are pinned for h3 too — the rule fixed in one protocol and
 * forgotten in the other is exactly what this module exists to prevent. */

/* A field backed by string literals. never_indexed is irrelevant on the request
 * side and left 0. */
#define F(n, v) ((httpfields_field_t){(char*)(n), strlen(n), (char*)(v), strlen(v), 0})

static http_fields_status_e build(const httpfields_field_t* fields, size_t n,
                                  http_fields_proto_e proto, httprequest_t** out) {
    *out = httprequest_create(NULL);
    if (*out == NULL) return HTTP_FIELDS_INTERNAL;
    int64_t cl = -1;
    return httpfields_to_request(*out, fields, n, proto, &cl);
}

static int host_is(const httprequest_t* r, const char* want) {
    const http_header_t* h = r->get_headern((httprequest_t*)r, "Host", 4);
    return h != NULL && h->value_length == strlen(want) && memcmp(h->value, want, h->value_length) == 0;
}

TEST(test_httpfields_valid) {
    TEST_SUITE("httpfields");

    TEST_CASE("a well-formed request builds, h2 and h3 identical");
    const httpfields_field_t ok[] = {
        F(":method", "GET"), F(":path", "/"), F(":scheme", "https"),
        F(":authority", "example.com"), F("accept", "text/html"),
        F("user-agent", "test/1.0"),
    };
    for (int p = 0; p < 2; p++) {
        httprequest_t* r = NULL;
        const http_fields_proto_e proto = p == 0 ? HTTP_FIELDS_H2 : HTTP_FIELDS_H3;
        TEST_ASSERT(build(ok, sizeof ok / sizeof ok[0], proto, &r) == HTTP_FIELDS_OK, "ok");
        TEST_ASSERT(r->method == ROUTE_GET, ":method → ROUTE_GET");
        TEST_ASSERT(r->path_length == 1 && memcmp(r->path, "/", 1) == 0, ":path /");
        TEST_ASSERT(host_is(r, "example.com"), ":authority → Host");
        TEST_ASSERT(r->version == HTTP1_VER_1_1, "version 1.1");
        httprequest_free(r);
    }

    TEST_CASE("a cookie header set is accepted (join + parse is cookieparser's job)");
    const httpfields_field_t cookies[] = {
        F(":method", "GET"), F(":path", "/"), F(":scheme", "https"),
        F(":authority", "example.com"),
        F("cookie", "a=1"), F("cookie", "b=2"),
    };
    httprequest_t* r = NULL;
    TEST_ASSERT(build(cookies, sizeof cookies / sizeof cookies[0], HTTP_FIELDS_H2, &r)
                == HTTP_FIELDS_OK, "ok");
    httprequest_free(r);
}

TEST(test_httpfields_content_length) {
    TEST_SUITE("httpfields");

    TEST_CASE("a content-length is reported back to the caller");
    const httpfields_field_t f[] = {
        F(":method", "POST"), F(":path", "/"), F(":scheme", "https"),
        F(":authority", "example.com"), F("content-length", "4242"),
    };
    httprequest_t* r = httprequest_create(NULL);
    int64_t cl = -999;
    TEST_ASSERT(httpfields_to_request(r, f, sizeof f / sizeof f[0], HTTP_FIELDS_H2, &cl)
                == HTTP_FIELDS_OK, "ok");
    TEST_ASSERT(cl == 4242, "content-length reported");
    httprequest_free(r);
}

TEST(test_httpfields_content_length_overflow) {
    TEST_SUITE("httpfields");
    TEST_CASE("content-length cannot overflow the signed body-length sentinel");
    const char* values[] = {"9223372036854775807", "9223372036854775808",
                            "9999999999999999999"};
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        const httpfields_field_t fields[] = {
            F(":method", "POST"), F(":path", "/"), F(":scheme", "https"),
            F(":authority", "example.com"), F("content-length", values[i]),
        };
        for (int p = HTTP_FIELDS_H2; p <= HTTP_FIELDS_H3; p++) {
            httprequest_t* r = httprequest_create(NULL);
            TEST_REQUIRE(r != NULL, "request created");
            int64_t cl = -1;
            const http_fields_status_e st = httpfields_to_request(
                r, fields, sizeof fields / sizeof fields[0], p, &cl);
            TEST_ASSERT(st == (i == 0 ? HTTP_FIELDS_OK : HTTP_FIELDS_MALFORMED),
                        "INT64_MAX accepted, larger lengths rejected");
            if (i == 0) TEST_ASSERT(cl == INT64_MAX, "maximum preserved exactly");
            httprequest_free(r);
        }
    }
}

TEST(test_httpfields_violations) {
    TEST_SUITE("httpfields");

    /* Each of these is one malformed shape from RFC 9113 §8 / RFC 9114 §4. The
     * good four pseudos are reused; one field at a time is the violation. */
#define GOOD3 F(":method", "GET"), F(":path", "/"), F(":scheme", "https"), F(":authority", "e")

    struct { const char* name; const httpfields_field_t* f; size_t n; } cases[] = {
        { "uppercase name",       (const httpfields_field_t[]){ GOOD3, F("Content-Type","text/plain") }, 5 },
        { "CR in value",          (const httpfields_field_t[]){ GOOD3, F("x","a\rb") }, 5 },
        { "pseudo after regular", (const httpfields_field_t[]){ F(":method","GET"), F("a","b"), F(":path","/") }, 3 },
        { "duplicate :method",    (const httpfields_field_t[]){ F(":method","GET"), F(":method","POST"), F(":path","/"), F(":scheme","https"), F(":authority","e") }, 5 },
        { "missing :scheme",      (const httpfields_field_t[]){ F(":method","GET"), F(":path","/"), F(":authority","e") }, 3 },
        { "forbidden connection", (const httpfields_field_t[]){ GOOD3, F("connection","keep-alive") }, 5 },
        { "bad TE",               (const httpfields_field_t[]){ GOOD3, F("te","chunked") }, 5 },
        { "content-length clash", (const httpfields_field_t[]){ GOOD3, F("content-length","1"), F("content-length","2") }, 6 },
        { "asterisk on non-OPTIONS", (const httpfields_field_t[]){ F(":method","GET"), F(":path","*"), F(":scheme","https"), F(":authority","e") }, 4 },
        { "missing :authority",   (const httpfields_field_t[]){ F(":method","GET"), F(":path","/"), F(":scheme","https") }, 3 },
        { "unknown pseudo",       (const httpfields_field_t[]){ F(":method","GET"), F(":path","/"), F(":scheme","https"), F(":authority","e"), F(":foo","x") }, 5 },
        { "value leading space",  (const httpfields_field_t[]){ GOOD3, F("x"," y") }, 5 },
    };

    int all_malformed = 1;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        httprequest_t* r = NULL;
        const http_fields_status_e st = build(cases[i].f, cases[i].n, HTTP_FIELDS_H2, &r);
        if (st != HTTP_FIELDS_MALFORMED) all_malformed = 0;
        httprequest_free(r);
    }
    TEST_ASSERT(all_malformed, "every violation is rejected as malformed");

#undef GOOD3

    TEST_CASE("OPTIONS * is valid (asterisk-form)");
    const httpfields_field_t star[] = {
        F(":method", "OPTIONS"), F(":path", "*"), F(":scheme", "https"), F(":authority", "e"),
    };
    httprequest_t* r = NULL;
    TEST_ASSERT(build(star, sizeof star / sizeof star[0], HTTP_FIELDS_H2, &r) == HTTP_FIELDS_OK,
                "OPTIONS * builds");
    TEST_ASSERT(r->asterisk_form, "asterisk_form set");
    httprequest_free(r);

    TEST_CASE("the forbidden-header helper");
    TEST_ASSERT(httpfields_is_forbidden_header("connection", 10), "connection");
    TEST_ASSERT(httpfields_is_forbidden_header("upgrade", 7), "upgrade");
    TEST_ASSERT(httpfields_is_forbidden_header("transfer-encoding", 17), "transfer-encoding");
    TEST_ASSERT(!httpfields_is_forbidden_header("content-type", 12), "content-type allowed");
    TEST_ASSERT(!httpfields_is_forbidden_header("cookie", 6), "cookie allowed");
}

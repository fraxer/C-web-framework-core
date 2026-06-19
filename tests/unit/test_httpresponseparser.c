#include "framework.h"
#include "httpresponseparser.h"
#include "httpparsercommon.h"
#include "httpresponse.h"
#include "httprequest.h"
#include "connection_c.h"
#include "appconfig.h"
#include "helpers.h"
#include "route.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <zlib.h>

// ============================================================================
// Mock Configuration and Dependencies
// ============================================================================
//
// env()/appconfig()/appconfig_set() are weak-defined in test_httprequestparser.c
// (always linked into the runner). We reuse them here through extern decls so
// the parser's env()->main.client_max_body_size and env()->main.tmp resolve to
// the shared test configuration.

extern appconfig_t* appconfig(void);
extern env_t* env(void);

// Mock client context: the response parser reads ctx->response / ctx->request.
static connection_client_ctx_t mock_client_ctx;

// ============================================================================
// Harness
// ============================================================================

#define HARNESS_BUFFER_SIZE 16384

typedef struct {
    connection_t* conn;
    httpresponse_t* response;
    httprequest_t* request;
    httpresponseparser_t* parser;
    char buffer[HARNESS_BUFFER_SIZE];
} response_harness_t;

static connection_t* create_mock_connection(char* buffer, size_t buffer_size) {
    connection_t* conn = malloc(sizeof(connection_t));
    if (!conn) return NULL;
    memset(conn, 0, sizeof(connection_t));
    conn->buffer = buffer;
    conn->buffer_size = buffer_size;
    conn->ctx = (connection_ctx_t*)&mock_client_ctx;
    return conn;
}

// Build a fresh connection + response + request + parser wired together.
static int harness_init(response_harness_t* h, route_methods_e method) {
    memset(h, 0, sizeof(*h));

    h->conn = create_mock_connection(h->buffer, HARNESS_BUFFER_SIZE);
    if (!h->conn) return 0;

    h->response = httpresponse_create(h->conn);
    if (!h->response) { free(h->conn); h->conn = NULL; return 0; }

    h->request = httprequest_create(h->conn);
    if (!h->request) { httpresponse_free(h->response); h->response = NULL; free(h->conn); h->conn = NULL; return 0; }
    h->request->method = method;

    mock_client_ctx.response = h->response;
    mock_client_ctx.request = h->request;
    h->conn->ctx = (connection_ctx_t*)&mock_client_ctx;

    h->parser = h->response->parser;
    httpresponseparser_set_connection(h->parser, h->conn);
    httpresponseparser_set_buffer(h->parser, h->conn->buffer);

    return 1;
}

static void harness_free(response_harness_t* h) {
    if (h->request) httprequest_free(h->request);
    if (h->response) httpresponse_free(h->response);
    if (h->conn) free(h->conn);
    memset(h, 0, sizeof(*h));
}

// Copy data into the harness buffer and run one parser pass.
static int harness_feed(response_harness_t* h, const char* data, size_t len) {
    if (len > HARNESS_BUFFER_SIZE) len = HARNESS_BUFFER_SIZE;
    memcpy(h->buffer, data, len);
    httpresponseparser_set_bytes_readed(h->parser, (ssize_t)len);
    return httpresponseparser_run(h->parser);
}

// Read back the decoded payload (malloc'd, caller frees). Returns NULL if empty.
static char* harness_read_body(response_harness_t* h) {
    return h->response->get_payload(h->response);
}

// Compress data into a gzip stream (malloc'd, caller frees).
static char* gzip_compress(const char* data, size_t len, size_t* out_len) {
    z_stream s;
    memset(&s, 0, sizeof(s));
    if (deflateInit2(&s, Z_BEST_SPEED, Z_DEFLATED, MAX_WBITS + 16,
                     MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK)
        return NULL;

    size_t bound = deflateBound(&s, (uLong)len);
    char* buf = malloc(bound);
    if (!buf) { deflateEnd(&s); return NULL; }

    s.next_in = (Bytef*)(uintptr_t)data;
    s.avail_in = (uInt)len;
    s.next_out = (Bytef*)buf;
    s.avail_out = (uInt)bound;

    if (deflate(&s, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&s);
        free(buf);
        return NULL;
    }

    *out_len = bound - s.avail_out;
    deflateEnd(&s);
    return buf;
}

// ============================================================================
// Test Suite 1: Status line and protocol
// ============================================================================

TEST(test_httpresponseparser_simple_200) {
    TEST_SUITE("HTTP Response Parser - Status Line");
    TEST_CASE("Parse simple 200 response with body");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    int result = harness_feed(&h, resp, strlen(resp));

    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "Parser should complete");
    TEST_ASSERT_EQUAL(200, h.response->status_code, "Status should be 200");
    TEST_ASSERT_EQUAL(HTTP1_VER_1_1, h.response->version, "Version should be HTTP/1.1");

    char* body = harness_read_body(&h);
    TEST_ASSERT_NOT_NULL(body, "Body should be present");
    TEST_ASSERT_EQUAL_SIZE((size_t)5, strlen(body), "Body length should be 5");
    TEST_ASSERT_STR_EQUAL("hello", body, "Body should match");
    free(body);

    harness_free(&h);
}

TEST(test_httpresponseparser_http10) {
    TEST_CASE("Accept HTTP/1.0 response");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* resp = "HTTP/1.0 200 OK\r\n\r\n";
    int result = harness_feed(&h, resp, strlen(resp));

    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "HTTP/1.0 should be accepted");
    TEST_ASSERT_EQUAL(HTTP1_VER_1_0, h.response->version, "Version should be HTTP/1.0");

    harness_free(&h);
}

TEST(test_httpresponseparser_invalid_protocol) {
    TEST_CASE("Reject unsupported protocol version");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* resp = "HTTP/2.0 200 OK\r\n\r\n";
    int result = harness_feed(&h, resp, strlen(resp));

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "HTTP/2.0 should be rejected");

    harness_free(&h);
}

TEST(test_httpresponseparser_status_codes) {
    TEST_CASE("Parse various status codes and reason phrases");

    const char* cases[] = {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"
    };
    const int expected[] = { 404, 500, 302 };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        response_harness_t h;
        TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");
        int result = harness_feed(&h, cases[i], strlen(cases[i]));
        TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "Should complete");
        TEST_ASSERT_EQUAL(expected[i], h.response->status_code, "Status should match");
        harness_free(&h);
    }
}

TEST(test_httpresponseparser_head_no_body) {
    TEST_CASE("HEAD response completes without reading body");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_HEAD), "Harness should initialize");

    // Content-Length claims 100 bytes, but HEAD must not read a body.
    const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
    int result = harness_feed(&h, resp, strlen(resp));

    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "HEAD should complete immediately");

    harness_free(&h);
}

// ============================================================================
// Test Suite 2: Chunked transfer-encoding
// ============================================================================

TEST(test_httpresponseparser_chunked) {
    TEST_SUITE("HTTP Response Parser - Chunked");
    TEST_CASE("Reassemble chunked body");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* resp =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n"
        "6\r\n world\r\n"
        "0\r\n\r\n";
    int result = harness_feed(&h, resp, strlen(resp));

    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "Chunked response should complete");

    char* body = harness_read_body(&h);
    TEST_ASSERT_NOT_NULL(body, "Body should be present");
    TEST_ASSERT_STR_EQUAL("hello world", body, "Chunked body should be reassembled");
    free(body);

    harness_free(&h);
}

TEST(test_httpresponseparser_chunked_size_limit) {
    TEST_CASE("Chunked body exceeding client_max_body_size is rejected");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    // Temporarily shrink the limit so we don't have to send megabytes.
    const size_t saved_limit = env()->main.client_max_body_size;
    env()->main.client_max_body_size = 10;

    // Two chunks of 8 bytes each => 16 > 10.
    const char* resp =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "8\r\n12345678\r\n"
        "8\r\n12345678\r\n"
        "0\r\n\r\n";
    int result = harness_feed(&h, resp, strlen(resp));

    env()->main.client_max_body_size = saved_limit;

    TEST_ASSERT_EQUAL(HTTP1PARSER_PAYLOAD_LARGE, result,
                      "Oversized chunked body should be rejected");

    harness_free(&h);
}

// ============================================================================
// Test Suite 3: Content-Encoding: gzip
// ============================================================================

TEST(test_httpresponseparser_gzip_single_read) {
    TEST_SUITE("HTTP Response Parser - Gzip");
    TEST_CASE("Decompress gzip body delivered in one read");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* original = "hello world hello world hello world";
    size_t clen = 0;
    char* gz = gzip_compress(original, strlen(original), &clen);
    TEST_ASSERT_NOT_NULL(gz, "Test gzip data should be produced");

    char header[256];
    int hlen = snprintf(header, sizeof(header),
                        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %zu\r\n\r\n", clen);
    TEST_ASSERT(hlen > 0 && (size_t)hlen + clen < HARNESS_BUFFER_SIZE, "Response fits buffer");

    char resp[HARNESS_BUFFER_SIZE];
    memcpy(resp, header, hlen);
    memcpy(resp + hlen, gz, clen);

    int result = harness_feed(&h, resp, (size_t)hlen + clen);
    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "Gzip response should complete");

    char* body = harness_read_body(&h);
    TEST_ASSERT_NOT_NULL(body, "Decompressed body should be present");
    TEST_ASSERT_STR_EQUAL(original, body, "Decompressed body should match original");
    free(body);
    free(gz);

    harness_free(&h);
}

TEST(test_httpresponseparser_gzip_multi_read_not_truncated) {
    TEST_CASE("Gzip body split across reads is not truncated");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    // Highly compressible payload: decompresses to far more bytes than it
    // occupies on the wire. This is exactly the case where comparing
    // decompressed bytes against the (compressed) Content-Length used to
    // complete the response prematurely.
    const size_t original_len = 5000;
    char* original = malloc(original_len + 1);
    TEST_ASSERT_NOT_NULL(original, "Original buffer should allocate");
    memset(original, 'A', original_len);
    original[original_len] = 0;

    size_t clen = 0;
    char* gz = gzip_compress(original, original_len, &clen);
    TEST_ASSERT_NOT_NULL(gz, "Test gzip data should be produced");
    TEST_ASSERT(clen < original_len, "Compressed form should be smaller");

    char header[256];
    int hlen = snprintf(header, sizeof(header),
                        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %zu\r\n\r\n", clen);

    // First read: headers + first half of the compressed stream.
    const size_t half = clen / 2;
    char feed1[HARNESS_BUFFER_SIZE];
    size_t feed1_len = (size_t)hlen + half;
    TEST_ASSERT(feed1_len < HARNESS_BUFFER_SIZE, "First feed fits buffer");
    memcpy(feed1, header, hlen);
    memcpy(feed1 + hlen, gz, half);

    int r1 = harness_feed(&h, feed1, feed1_len);
    // Completion must be driven by wire bytes, not decompressed bytes, so a
    // partial compressed stream must NOT yet complete.
    TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, r1, "Partial gzip body should not complete early");

    // Second read: remainder of the compressed stream.
    int r2 = harness_feed(&h, gz + half, clen - half);
    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, r2, "Full gzip body should complete");

    char* body = harness_read_body(&h);
    TEST_ASSERT_NOT_NULL(body, "Decompressed body should be present");
    TEST_ASSERT_EQUAL_SIZE(original_len, strlen(body), "Decompressed length should match");
    TEST_ASSERT(memcmp(body, original, original_len) == 0, "Decompressed body should match");
    free(body);
    free(original);
    free(gz);

    harness_free(&h);
}

// ============================================================================
// Test Suite 4: Transfer-Encoding: gzip, chunked
// ============================================================================

TEST(test_httpresponseparser_transfer_encoding_gzip_chunked) {
    TEST_SUITE("HTTP Response Parser - Combined Transfer-Encoding");
    TEST_CASE("Decode 'Transfer-Encoding: gzip, chunked'");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* original = "combined transfer encoding payload payload payload";
    size_t glen = 0;
    char* gz = gzip_compress(original, strlen(original), &glen);
    TEST_ASSERT_NOT_NULL(gz, "Test gzip data should be produced");

    // Chunk-encode the gzip bytes as a single chunk.
    char resp[HARNESS_BUFFER_SIZE];
    int n = snprintf(resp, sizeof(resp),
                     "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n%zx\r\n",
                     glen);
    TEST_ASSERT(n > 0 && (size_t)n + glen + 7 < HARNESS_BUFFER_SIZE, "Response fits buffer");
    memcpy(resp + n, gz, glen);
    size_t off = (size_t)n + glen;
    memcpy(resp + off, "\r\n0\r\n\r\n", 7);

    int result = harness_feed(&h, resp, off + 7);
    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "Combined TE response should complete");

    char* body = harness_read_body(&h);
    TEST_ASSERT_NOT_NULL(body, "Decompressed body should be present");
    TEST_ASSERT_STR_EQUAL(original, body, "Body should be decompressed and match");
    free(body);
    free(gz);

    harness_free(&h);
}

// ============================================================================
// Test Suite 5: Robustness of header parsing
// ============================================================================

TEST(test_httpresponseparser_content_length_negative) {
    TEST_SUITE("HTTP Response Parser - Robustness");
    TEST_CASE("Negative Content-Length is ignored (no huge size_t)");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n";
    int result = harness_feed(&h, resp, strlen(resp));

    // Invalid Content-Length is ignored; with no body framing the response
    // completes. Previously atoll("-1") produced a huge size_t.
    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "Should complete without reading a body");
    TEST_ASSERT_EQUAL_SIZE((size_t)0, h.response->content_length, "Content-Length should stay 0");

    harness_free(&h);
}

TEST(test_httpresponseparser_content_length_overflow) {
    TEST_CASE("Overflowing Content-Length is ignored");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999\r\n\r\n";
    int result = harness_feed(&h, resp, strlen(resp));

    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "Should complete without reading a body");
    TEST_ASSERT_EQUAL_SIZE((size_t)0, h.response->content_length, "Content-Length should stay 0");

    harness_free(&h);
}

TEST(test_httpresponseparser_multiple_headers) {
    TEST_CASE("Parse and expose multiple headers");

    response_harness_t h;
    TEST_ASSERT(harness_init(&h, ROUTE_GET), "Harness should initialize");

    const char* resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 2\r\n"
        "X-Custom: value\r\n"
        "\r\nhi";
    int result = harness_feed(&h, resp, strlen(resp));

    TEST_ASSERT_EQUAL(HTTP1RESPONSEPARSER_COMPLETE, result, "Should complete");

    http_header_t* ct = h.response->get_header(h.response, "Content-Type");
    TEST_ASSERT_NOT_NULL(ct, "Content-Type header should be stored");
    if (ct) TEST_ASSERT_STR_EQUAL("text/plain", ct->value, "Content-Type value");

    http_header_t* custom = h.response->get_header(h.response, "x-custom");
    TEST_ASSERT_NOT_NULL(custom, "X-Custom header should be stored (case-insensitive)");
    if (custom) TEST_ASSERT_STR_EQUAL("value", custom->value, "X-Custom value");

    char* body = harness_read_body(&h);
    TEST_ASSERT_NOT_NULL(body, "Body should be present");
    TEST_ASSERT_STR_EQUAL("hi", body, "Body should match");
    free(body);

    harness_free(&h);
}

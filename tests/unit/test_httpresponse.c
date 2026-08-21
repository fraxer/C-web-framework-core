/*
 * Unit tests for protocols/http/httpresponse.c
 *
 * Covers the response-building surface: status string/length tables, header
 * add/get/remove (including the unique and length-explicit variants), the
 * Content-Length builder, send_datan/send_default/send_json body assembly,
 * redirects, cookies, reset, static file path resolution and the payload
 * getters. Several cases are regression guards for bugs fixed alongside these
 * tests (each is marked REGRESSION below):
 *
 *   - __httpresponse_header_remove returned 0 and left last_header dangling
 *     when a non-head header was deleted; the next add_header wrote through
 *     the freed node (heap-UAF).
 *   - httpresponse_default with an unlisted status code underflowed
 *     `status_length - 2` to SIZE_MAX and memcpy'd from a NULL status string.
 *   - the path resolver read an uninitialized `struct stat` when stat()
 *     failed with an errno other than ENOENT (e.g. ENOTDIR). The resolver is
 *     now http_open_file, which opens instead of stat'ing (§10.4).
 *   - __httpresponse_reset kept content_length/version from the previous
 *     response, so httpresponse_has_payload() lied on reused connections.
 *   - __httpresponse_headern_add ran strlen() on the key although the API
 *     receives explicit lengths (OOB read for non NUL-terminated slices).
 *   - __httpresponse_payload_parse_plain leaked the previous payload part on
 *     repeated get_payload_file calls; get_payload_file reported ok=1 even
 *     when no payload file exists (dead `field` logic).
 *
 * env()/appconfig() are provided as weak symbols by test_httprequestparser.c
 * and shared across the runner (env()->main.gzip is NULL there, so the gzip
 * negotiation paths are inert no-ops in these tests).
 */

#include "framework.h"
#include "httpresponse.h"
#include "httpcommon.h"
#include "connection_s.h"
#include "appconfig.h"
#include "helpers.h"
#include "json.h"
#include "file.h"
#include "httpgzipcache.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

// ============================================================================
// Helpers
// ============================================================================

static connection_server_ctx_t test_response_ctx;

static connection_t* make_connection(void) {
    connection_t* conn = calloc(1, sizeof(connection_t));
    if (conn == NULL) return NULL;

    memset(&test_response_ctx, 0, sizeof(test_response_ctx));
    conn->ctx = &test_response_ctx;
    conn->keepalive = 0;

    return conn;
}

static httpresponse_t* make_response(connection_t** out_conn) {
    connection_t* conn = make_connection();
    if (conn == NULL) return NULL;

    httpresponse_t* response = httpresponse_create(conn);
    if (response == NULL) {
        free(conn);
        return NULL;
    }

    *out_conn = conn;
    return response;
}

static void free_response(httpresponse_t* response, connection_t* conn) {
    if (response != NULL) httpresponse_free(response);
    free(conn);
}

static int header_count(httpresponse_t* response, const char* key) {
    int count = 0;
    for (http_header_t* header = response->header_; header != NULL; header = header->next)
        if (cmpstr_lower(header->key, key))
            count++;

    return count;
}

static int write_whole_file(const char* path, const char* content) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return 0;

    const size_t length = strlen(content);
    const ssize_t written = write(fd, content, length);
    close(fd);

    return written == (ssize_t)length;
}

// ============================================================================
// Status string/length tables
// ============================================================================

static const int known_status_codes[] = {
    100, 101, 102, 103,
    200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
    300, 301, 302, 303, 304, 305, 306, 307, 308,
    400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413,
    414, 415, 416, 417, 418, 421, 422, 423, 424, 426, 428, 429, 431, 451,
    500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511
};

TEST(test_httpresponse_status_tables_consistent) {
    TEST_SUITE("httpresponse: status tables");
    TEST_CASE("status_string and status_length agree for every known code");

    const size_t count = sizeof(known_status_codes) / sizeof(known_status_codes[0]);
    for (size_t i = 0; i < count; i++) {
        const int code = known_status_codes[i];
        const char* string = httpresponse_status_string(code);
        const size_t length = httpresponse_status_length(code);

        TEST_ASSERT_NOT_NULL(string, "status string present");
        if (string == NULL) continue;

        TEST_ASSERT_EQUAL_SIZE(strlen(string), length, "length matches strlen");

        char prefix[8];
        snprintf(prefix, sizeof(prefix), "%d ", code);
        TEST_ASSERT(strncmp(string, prefix, strlen(prefix)) == 0, "string starts with the code");

        const size_t string_length = strlen(string);
        TEST_ASSERT(string_length >= 2 && strcmp(&string[string_length - 2], "\r\n") == 0, "string ends with CRLF");
    }
}

TEST(test_httpresponse_status_tables_unknown_codes) {
    TEST_SUITE("httpresponse: status tables");
    TEST_CASE("unknown codes return NULL string and zero length");

    const int unknown[] = { 0, -1, 99, 104, 199, 299, 309, 419, 420, 512, 600, 999 };
    const size_t count = sizeof(unknown) / sizeof(unknown[0]);
    for (size_t i = 0; i < count; i++) {
        TEST_ASSERT_NULL(httpresponse_status_string(unknown[i]), "unknown code -> NULL string");
        TEST_ASSERT_EQUAL_SIZE(0, httpresponse_status_length(unknown[i]), "unknown code -> zero length");
    }
}

// ============================================================================
// Creation defaults
// ============================================================================

TEST(test_httpresponse_create_defaults) {
    TEST_SUITE("httpresponse: create");
    TEST_CASE("httpresponse_create initializes a clean response");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    TEST_ASSERT_EQUAL(200, response->status_code, "status defaults to 200");
    TEST_ASSERT_EQUAL(HTTP1_VER_NONE, response->version, "version defaults to NONE");
    TEST_ASSERT_EQUAL(TE_NONE, response->transfer_encoding, "no transfer encoding");
    TEST_ASSERT_EQUAL(CE_NONE, response->content_encoding, "no content encoding");
    TEST_ASSERT_EQUAL_SIZE(0, response->content_length, "content_length is zero");
    TEST_ASSERT_NULL(response->header_, "no headers");
    TEST_ASSERT_NULL((void*)response->last_header, "no last header");
    TEST_ASSERT_NOT_NULL(response->parser, "parser allocated");
    TEST_ASSERT_NOT_NULL(response->filter, "filter chain allocated");
    TEST_ASSERT_NULL(response->body.data, "body not allocated");
    TEST_ASSERT_EQUAL(-1, response->file_.fd, "no file open");
    TEST_ASSERT_EQUAL(-1, response->payload_.file.fd, "no payload file");
    TEST_ASSERT_EQUAL(NONE, response->payload_.type, "payload type NONE");

    free_response(response, conn);
}

// ============================================================================
// Header add/get/exist
// ============================================================================

TEST(test_httpresponse_header_add_and_get) {
    TEST_SUITE("httpresponse: headers");
    TEST_CASE("add_header stores headers, get_header finds them case-insensitively");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    TEST_ASSERT_EQUAL(1, response->add_header(response, "X-One", "first"), "add X-One");
    TEST_ASSERT_EQUAL(1, response->add_header(response, "X-Two", "second"), "add X-Two");

    http_header_t* header = response->get_header(response, "x-one");
    TEST_REQUIRE_NOT_NULL(header, "case-insensitive lookup finds X-One");
    TEST_ASSERT_STR_EQUAL("X-One", header->key, "key preserved verbatim");
    TEST_ASSERT_STR_EQUAL("first", header->value, "value stored");
    TEST_ASSERT_EQUAL_SIZE(5, header->key_length, "key length stored");
    TEST_ASSERT_EQUAL_SIZE(5, header->value_length, "value length stored");

    header = response->get_header(response, "X-TWO");
    TEST_REQUIRE_NOT_NULL(header, "lookup finds X-Two");
    TEST_ASSERT_STR_EQUAL("second", header->value, "second value stored");

    TEST_ASSERT_NULL((void*)response->get_header(response, "X-Missing"), "missing header -> NULL");

    TEST_REQUIRE_NOT_NULL(response->last_header, "last_header set");
    TEST_ASSERT_STR_EQUAL("X-Two", response->last_header->key, "last_header tracks the tail");

    free_response(response, conn);
}

TEST(test_httpresponse_headern_add_accepts_unterminated_slices) {
    TEST_SUITE("httpresponse: headers");
    TEST_CASE("add_headern honors explicit lengths (no NUL terminator required)");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    /* Exact-size buffers without NUL terminators: under ASan an strlen()
     * inside add_headern would be reported as a stack overflow read. */
    char key_slice[8];
    char value_slice[6];
    memcpy(key_slice, "X-Slice!", 8);
    memcpy(value_slice, "value?", 6);

    TEST_ASSERT_EQUAL(1, response->add_headern(response, key_slice, 7, value_slice, 5), "slice added");

    http_header_t* header = response->get_header(response, "X-Slice");
    TEST_REQUIRE_NOT_NULL(header, "header found by truncated key");
    TEST_ASSERT_STR_EQUAL("X-Slice", header->key, "key copied up to length");
    TEST_ASSERT_STR_EQUAL("value", header->value, "value copied up to length");

    free_response(response, conn);
}

TEST(test_httpresponse_headeru_add_is_unique) {
    TEST_SUITE("httpresponse: headers");
    TEST_CASE("add_headeru keeps the first value and reports success on duplicates");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    TEST_ASSERT_EQUAL(1, response->add_headeru(response, "Connection", 10, "close", 5), "first add");
    TEST_ASSERT_EQUAL(1, response->add_headeru(response, "connection", 10, "keep-alive", 10), "duplicate reports success");

    TEST_ASSERT_EQUAL(1, header_count(response, "Connection"), "only one Connection header");
    http_header_t* header = response->get_header(response, "Connection");
    TEST_REQUIRE_NOT_NULL(header, "header present");
    TEST_ASSERT_STR_EQUAL("close", header->value, "first value wins");

    free_response(response, conn);
}

// ============================================================================
// Header removal
// ============================================================================

TEST(test_httpresponse_header_remove_positions) {
    TEST_SUITE("httpresponse: headers");
    TEST_CASE("remove_header works for head, middle and tail nodes");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    TEST_ASSERT_EQUAL(0, response->remove_header(response, "X-A"), "remove on empty list -> 0");

    response->add_header(response, "X-A", "1");
    response->add_header(response, "X-B", "2");
    response->add_header(response, "X-C", "3");

    /* REGRESSION: removing a non-head node used to return 0 (head unchanged)
     * and leave last_header pointing at the freed tail node. */
    TEST_ASSERT_EQUAL(1, response->remove_header(response, "X-B"), "middle removal reports success");
    TEST_ASSERT_NULL((void*)response->get_header(response, "X-B"), "X-B gone");
    TEST_ASSERT_NOT_NULL(response->get_header(response, "X-A"), "X-A kept");
    TEST_ASSERT_NOT_NULL(response->get_header(response, "X-C"), "X-C kept");

    TEST_ASSERT_EQUAL(1, response->remove_header(response, "X-C"), "tail removal reports success");
    TEST_REQUIRE_NOT_NULL(response->last_header, "last_header rebuilt after tail removal");
    TEST_ASSERT_STR_EQUAL("X-A", response->last_header->key, "last_header points at the new tail");

    /* REGRESSION (heap-UAF): appending after a tail removal used to write
     * through the freed node: last_header->next = new. ASan guards this. */
    TEST_ASSERT_EQUAL(1, response->add_header(response, "X-D", "4"), "append after tail removal");
    http_header_t* header = response->get_header(response, "X-D");
    TEST_REQUIRE_NOT_NULL(header, "X-D present");
    TEST_ASSERT_STR_EQUAL("4", header->value, "X-D value intact");
    TEST_REQUIRE_NOT_NULL(response->last_header, "last_header set");
    TEST_ASSERT_STR_EQUAL("X-D", response->last_header->key, "last_header tracks X-D");

    TEST_ASSERT_EQUAL(1, response->remove_header(response, "x-a"), "head removal (case-insensitive)");
    TEST_ASSERT_NULL((void*)response->get_header(response, "X-A"), "X-A gone");
    TEST_ASSERT_EQUAL(0, response->remove_header(response, "X-Missing"), "missing key -> 0");

    TEST_ASSERT_EQUAL(1, response->remove_header(response, "X-D"), "remove the last node");
    TEST_ASSERT_NULL(response->header_, "list empty");
    TEST_ASSERT_NULL((void*)response->last_header, "last_header cleared");

    TEST_ASSERT_EQUAL(1, response->add_header(response, "X-E", "5"), "list usable after emptying");
    TEST_ASSERT_NOT_NULL(response->get_header(response, "X-E"), "X-E present");

    free_response(response, conn);
}

// ============================================================================
// Range mode header filtering and encoding flags
// ============================================================================

TEST(test_httpresponse_range_drops_encoding_headers) {
    TEST_SUITE("httpresponse: headers");
    TEST_CASE("range mode silently drops Transfer-Encoding/Content-Encoding");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->range = 1;

    /* REGRESSION: the drop check used strlen(key) although add_headern takes
     * an explicit key_length; exact-size unterminated slices caught OOB reads. */
    char te_slice[17];
    char ce_slice[16];
    memcpy(te_slice, "Transfer-Encoding", 17);
    memcpy(ce_slice, "Content-Encoding", 16);

    TEST_ASSERT_EQUAL(1, response->add_headern(response, te_slice, 17, "chunked", 7), "TE drop reports success");
    TEST_ASSERT_EQUAL(1, response->add_headern(response, ce_slice, 16, "gzip", 4), "CE drop reports success");
    TEST_ASSERT_NULL((void*)response->get_header(response, "Transfer-Encoding"), "TE not stored");
    TEST_ASSERT_NULL((void*)response->get_header(response, "Content-Encoding"), "CE not stored");
    TEST_ASSERT_EQUAL(TE_NONE, response->transfer_encoding, "TE flag untouched");
    TEST_ASSERT_EQUAL(CE_NONE, response->content_encoding, "CE flag untouched");

    TEST_ASSERT_EQUAL(1, response->add_headern(response, "X-Other", 7, "kept", 4), "other headers pass through");
    TEST_ASSERT_NOT_NULL(response->get_header(response, "X-Other"), "other header stored");

    free_response(response, conn);
}

TEST(test_httpresponse_headers_set_encoding_flags) {
    TEST_SUITE("httpresponse: headers");
    TEST_CASE("Transfer-Encoding/Content-Encoding headers set the response flags");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    TEST_ASSERT_EQUAL(1, response->add_header(response, "Transfer-Encoding", "chunked"), "add TE chunked");
    TEST_ASSERT_EQUAL(TE_CHUNKED, response->transfer_encoding, "TE flag set");

    TEST_ASSERT_EQUAL(1, response->add_header(response, "Content-Encoding", "gzip"), "add CE gzip");
    TEST_ASSERT_EQUAL(CE_GZIP, response->content_encoding, "CE flag set");

    free_response(response, conn);
}

// ============================================================================
// Content-Length builder
// ============================================================================

TEST(test_httpresponse_add_content_length) {
    TEST_SUITE("httpresponse: content length");
    TEST_CASE("add_content_length renders the decimal value exactly");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    const struct { size_t length; const char* expected; } cases[] = {
        { 0, "0" },
        { 7, "7" },
        { 10, "10" },
        { 12345, "12345" },
        { 1234567890, "1234567890" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT_EQUAL(1, response->add_content_length(response, cases[i].length), "header added");

        http_header_t* header = response->get_header(response, "Content-Length");
        TEST_REQUIRE_NOT_NULL(header, "Content-Length present");
        TEST_ASSERT_STR_EQUAL(cases[i].expected, header->value, "decimal rendering");
        TEST_ASSERT_EQUAL_SIZE(strlen(cases[i].expected), header->value_length, "value length matches");

        TEST_ASSERT_EQUAL(1, response->remove_header(response, "Content-Length"), "cleanup between cases");
    }

    free_response(response, conn);
}

// ============================================================================
// send_datan / send_default / send_json
// ============================================================================

TEST(test_httpresponse_send_datan_builds_body_and_headers) {
    TEST_SUITE("httpresponse: send data");
    TEST_CASE("send_datan copies the body and adds the default headers");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_datan(response, "hello body", 10);

    TEST_ASSERT_EQUAL_SIZE(10, response->body.size, "body size");
    TEST_REQUIRE_NOT_NULL(response->body.data, "body allocated");
    TEST_ASSERT_STR_EQUAL("hello body", response->body.data, "body NUL-terminated copy");

    http_header_t* header = response->get_header(response, "Content-Type");
    TEST_REQUIRE_NOT_NULL(header, "Content-Type present");
    TEST_ASSERT_STR_EQUAL("text/html; charset=utf-8", header->value, "text/html content type");

    header = response->get_header(response, "Connection");
    TEST_REQUIRE_NOT_NULL(header, "Connection present");
    TEST_ASSERT_STR_EQUAL("close", header->value, "keepalive off -> close");

    TEST_ASSERT_NOT_NULL(response->get_header(response, "Cache-Control"), "Cache-Control present");
    TEST_ASSERT_NOT_NULL(response->get_header(response, "Accept-Ranges"), "Accept-Ranges present");

    free_response(response, conn);
}

TEST(test_httpresponse_send_data_respects_keepalive) {
    TEST_SUITE("httpresponse: send data");
    TEST_CASE("send_data advertises keep-alive when the connection wants it");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    /* The response answers on its own snapshot, taken when it was created —
     * see the next test for why the connection's current value will not do. */
    conn->keepalive = 1;
    response->keepalive = 1;
    response->send_data(response, "hi");

    http_header_t* header = response->get_header(response, "Connection");
    TEST_REQUIRE_NOT_NULL(header, "Connection present");
    TEST_ASSERT_STR_EQUAL("keep-alive", header->value, "keepalive on -> keep-alive");

    free_response(response, conn);
}

TEST(test_httpresponse_keepalive_is_snapshotted_per_response) {
    TEST_SUITE("httpresponse: send data");
    TEST_CASE("REGRESSION: a later request's Connection: close does not close this one");

    connection_t* conn = make_connection();
    TEST_REQUIRE_NOT_NULL(conn, "connection allocated");

    /* The request being answered was persistent... */
    conn->keepalive = 1;
    httpresponse_t* response = httpresponse_create(conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");
    TEST_ASSERT_EQUAL_UINT(1, response->keepalive, "snapshot taken at creation");

    /* ...and then the parser read the NEXT pipelined request, which said
     * "Connection: close". That belongs to that request, not to this response:
     * before the snapshot existed, this response advertised close and the
     * connection went down with the remaining pipelined answers unsent. */
    conn->keepalive = 0;

    response->send_data(response, "hi");

    http_header_t* header = response->get_header(response, "Connection");
    TEST_REQUIRE_NOT_NULL(header, "Connection present");
    TEST_ASSERT_STR_EQUAL("keep-alive", header->value,
                          "this response still advertises keep-alive");
    TEST_ASSERT_EQUAL_UINT(1, response->keepalive, "and still says so to the write path");

    free_response(response, conn);
}

TEST(test_httpresponse_send_datan_too_large_destroys_connection) {
    TEST_SUITE("httpresponse: send data");
    TEST_CASE("a body above the buffer cap marks the connection destroyed");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    conn->keepalive = 1;
    /* bufo_alloc caps the body at 10MB; the data pointer is never read when
     * the allocation is rejected, so a short literal with a huge length is safe. */
    response->send_datan(response, "x", 10 * 1024 * 1024 + 1);

    TEST_ASSERT_NULL(response->body.data, "body not allocated");
    TEST_ASSERT_EQUAL(0, conn->keepalive, "keepalive dropped");
    TEST_ASSERT_EQUAL(1, (int)test_response_ctx.destroyed, "connection marked destroyed");

    free_response(response, conn);
}

TEST(test_httpresponse_default_known_code) {
    TEST_SUITE("httpresponse: send default");
    TEST_CASE("send_default renders the status page for a known code");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_default(response, 404);

    TEST_ASSERT_EQUAL(404, response->status_code, "status set");
    TEST_REQUIRE_NOT_NULL(response->body.data, "body allocated");
    TEST_ASSERT(strstr(response->body.data, "<h1>404 Not Found</h1>") != NULL, "body contains the status text");

    free_response(response, conn);
}

TEST(test_httpresponse_default_unknown_code_falls_back_to_500) {
    TEST_SUITE("httpresponse: send default");
    TEST_CASE("send_default with an unlisted code answers 500");

    /* REGRESSION: an unlisted code used to underflow `status_length - 2` to
     * SIZE_MAX (huge VLA) and memcpy from the NULL status string. */
    const int unknown[] = { 419, 999 };
    for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++) {
        connection_t* conn = NULL;
        httpresponse_t* response = make_response(&conn);
        TEST_REQUIRE_NOT_NULL(response, "response allocated");

        response->send_default(response, unknown[i]);

        TEST_ASSERT_EQUAL(500, response->status_code, "falls back to 500");
        TEST_REQUIRE_NOT_NULL_GOTO(response->body.data, "body allocated", next_case);
        TEST_ASSERT(strstr(response->body.data, "500 Internal Server Error") != NULL, "body carries 500 text");

        next_case:
        free_response(response, conn);
    }
}

TEST(test_httpresponse_send_json) {
    TEST_SUITE("httpresponse: send json");
    TEST_CASE("send_json serializes the document into the body");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    json_doc_t* document = json_parse("{\"key\":\"value\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(document, "document parsed", cleanup);

    response->send_json(response, document);

    http_header_t* header = response->get_header(response, "Content-Type");
    TEST_REQUIRE_NOT_NULL_GOTO(header, "Content-Type present", cleanup);
    TEST_ASSERT_STR_EQUAL("application/json", header->value, "json content type");

    TEST_REQUIRE_NOT_NULL_GOTO(response->body.data, "body allocated", cleanup);
    TEST_ASSERT_STR_EQUAL(json_stringify(document), response->body.data, "body equals the stringified document");

    cleanup:
    if (document != NULL) json_free(document);
    free_response(response, conn);
}

TEST(test_httpresponse_send_json_null_document) {
    TEST_SUITE("httpresponse: send json");
    TEST_CASE("send_json(NULL) answers 500");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_json(response, NULL);

    TEST_ASSERT_EQUAL(500, response->status_code, "status 500");
    TEST_REQUIRE_NOT_NULL(response->body.data, "default body rendered");
    TEST_ASSERT(strstr(response->body.data, "500 Internal Server Error") != NULL, "body carries 500 text");

    free_response(response, conn);
}

// ============================================================================
// Redirects
// ============================================================================

TEST(test_httpresponse_redirect_internal) {
    TEST_SUITE("httpresponse: redirect");
    TEST_CASE("internal redirect sets Location and keeps the connection");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->redirect(response, "/login", 302);

    TEST_ASSERT_EQUAL(302, response->status_code, "status set");
    http_header_t* header = response->get_header(response, "Location");
    TEST_REQUIRE_NOT_NULL(header, "Location present");
    TEST_ASSERT_STR_EQUAL("/login", header->value, "Location value");
    TEST_ASSERT_NULL((void*)response->get_header(response, "Connection"), "no Connection header for internal redirect");

    free_response(response, conn);
}

TEST(test_httpresponse_redirect_external_closes_connection) {
    TEST_SUITE("httpresponse: redirect");
    TEST_CASE("external redirect adds Connection: Close");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->redirect(response, "https://example.com/path", 301);

    TEST_ASSERT_EQUAL(301, response->status_code, "status set");
    http_header_t* header = response->get_header(response, "Connection");
    TEST_REQUIRE_NOT_NULL(header, "Connection present");
    TEST_ASSERT_STR_EQUAL("Close", header->value, "connection closed");

    free_response(response, conn);
}

TEST(test_httpresponse_redirect_is_external) {
    TEST_SUITE("httpresponse: redirect");
    TEST_CASE("redirect_is_external recognizes absolute http(s) URLs only");

    TEST_ASSERT_EQUAL(1, httpresponse_redirect_is_external("http://a"), "http URL");
    TEST_ASSERT_EQUAL(1, httpresponse_redirect_is_external("https://example.com"), "https URL");
    TEST_ASSERT_EQUAL(0, httpresponse_redirect_is_external("/path/only"), "relative path");
    TEST_ASSERT_EQUAL(0, httpresponse_redirect_is_external("ftp://example"), "other scheme");
    TEST_ASSERT_EQUAL(0, httpresponse_redirect_is_external("http:/a.com"), "malformed scheme");
    TEST_ASSERT_EQUAL(0, httpresponse_redirect_is_external(""), "empty string");
    TEST_ASSERT_EQUAL(0, httpresponse_redirect_is_external("http://"), "scheme without host is shorter than the minimum");
}

// ============================================================================
// Reset and has_payload
// ============================================================================

TEST(test_httpresponse_reset_restores_pristine_state) {
    TEST_SUITE("httpresponse: reset");
    TEST_CASE("reset clears headers, body, encodings and parser-written fields");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_datan(response, "payload", 7);
    response->status_code = 404;
    response->range = 1;
    response->transfer_encoding = TE_CHUNKED;
    response->content_encoding = CE_GZIP;
    /* The client-side parser writes these directly into the response. */
    response->content_length = 12345;
    response->version = HTTP1_VER_1_1;

    TEST_ASSERT_EQUAL(1, httpresponse_has_payload(response), "payload visible before reset");

    response->base.reset(response);

    TEST_ASSERT_EQUAL(200, response->status_code, "status back to 200");
    TEST_ASSERT_EQUAL(TE_NONE, response->transfer_encoding, "TE cleared");
    TEST_ASSERT_EQUAL(CE_NONE, response->content_encoding, "CE cleared");
    TEST_ASSERT_EQUAL(0, response->range, "range cleared");
    TEST_ASSERT_NULL(response->header_, "headers freed");
    TEST_ASSERT_NULL((void*)response->last_header, "last_header cleared");
    TEST_ASSERT_NULL(response->body.data, "body freed");
    TEST_ASSERT_EQUAL_SIZE(0, response->body.size, "body size zero");

    /* REGRESSION: content_length/version survived reset, so has_payload()
     * reported the previous response's payload on a reused connection. */
    TEST_ASSERT_EQUAL_SIZE(0, response->content_length, "content_length cleared");
    TEST_ASSERT_EQUAL(HTTP1_VER_NONE, response->version, "version cleared");
    TEST_ASSERT_EQUAL(0, httpresponse_has_payload(response), "no payload after reset");

    TEST_ASSERT_EQUAL(1, response->add_header(response, "X-After", "reset"), "response usable after reset");
    TEST_ASSERT_NOT_NULL(response->get_header(response, "X-After"), "header added after reset");

    free_response(response, conn);
}

TEST(test_httpresponse_has_payload) {
    TEST_SUITE("httpresponse: has payload");
    TEST_CASE("payload is reported for content_length or transfer encoding");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    TEST_ASSERT_EQUAL(0, httpresponse_has_payload(response), "fresh response has none");

    response->content_length = 10;
    TEST_ASSERT_EQUAL(1, httpresponse_has_payload(response), "content_length counts");

    response->content_length = 0;
    response->transfer_encoding = TE_CHUNKED;
    TEST_ASSERT_EQUAL(1, httpresponse_has_payload(response), "transfer encoding counts");

    response->transfer_encoding = TE_NONE;
    TEST_ASSERT_EQUAL(0, httpresponse_has_payload(response), "cleared again");

    free_response(response, conn);
}

// ============================================================================
// Ranges
// ============================================================================

TEST(test_httpresponse_init_ranges) {
    TEST_SUITE("httpresponse: ranges");
    TEST_CASE("init_ranges returns an unset range; chains free cleanly");

    http_ranges_t* range = httpresponse_init_ranges();
    TEST_REQUIRE_NOT_NULL(range, "range allocated");

    TEST_ASSERT_EQUAL(-1, range->start, "start unset");
    TEST_ASSERT_EQUAL(-1, range->end, "end unset");
    TEST_ASSERT_NULL((void*)range->next, "no next");

    range->next = httpresponse_init_ranges();
    TEST_ASSERT_NOT_NULL(range->next, "second range allocated");

    http_ranges_free(range);
}

// ============================================================================
// Cookies
// ============================================================================

TEST(test_httpresponse_cookie_basic_and_lifetimes) {
    TEST_SUITE("httpresponse: cookies");
    TEST_CASE("add_cookie renders name=value and the lifetime attributes");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    /* Session cookie: negative lifetime adds no Max-Age/Expires. */
    response->add_cookie(response, (cookie_t){ .name = "sid", .value = "abc", .seconds = -1 });
    http_header_t* header = response->get_header(response, "Set-Cookie");
    TEST_REQUIRE_NOT_NULL(header, "Set-Cookie present");
    TEST_ASSERT_STR_EQUAL("sid=abc", header->value, "bare name=value for session cookie");
    TEST_ASSERT_EQUAL(1, response->remove_header(response, "Set-Cookie"), "cleanup");

    /* seconds == 0 deletes the cookie right away. */
    response->add_cookie(response, (cookie_t){ .name = "sid", .value = "", .seconds = 0 });
    header = response->get_header(response, "Set-Cookie");
    TEST_REQUIRE_NOT_NULL(header, "Set-Cookie present");
    TEST_ASSERT_STR_EQUAL("sid=; Max-Age=0", header->value, "zero lifetime -> Max-Age=0");
    TEST_ASSERT_EQUAL(1, response->remove_header(response, "Set-Cookie"), "cleanup");

    /* Positive lifetime renders an HTTP date. */
    response->add_cookie(response, (cookie_t){ .name = "sid", .value = "abc", .seconds = 3600 });
    header = response->get_header(response, "Set-Cookie");
    TEST_REQUIRE_NOT_NULL(header, "Set-Cookie present");
    TEST_ASSERT(strncmp(header->value, "sid=abc; Expires=", 17) == 0, "Expires attribute rendered");
    TEST_ASSERT(strstr(header->value, " GMT") != NULL, "expiry is an HTTP GMT date");

    free_response(response, conn);
}

TEST(test_httpresponse_cookie_attributes) {
    TEST_SUITE("httpresponse: cookies");
    TEST_CASE("path/domain/secure/httponly/samesite are appended in order");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->add_cookie(response, (cookie_t){
        .name = "token",
        .value = "v1",
        .seconds = -1,
        .path = "/app",
        .domain = "example.com",
        .secure = 1,
        .http_only = 1,
        .same_site = "Lax",
    });

    http_header_t* header = response->get_header(response, "Set-Cookie");
    TEST_REQUIRE_NOT_NULL(header, "Set-Cookie present");
    TEST_ASSERT_STR_EQUAL("token=v1; Path=/app; Domain=example.com; Secure; HttpOnly; SameSite=Lax",
                          header->value, "all attributes rendered");

    free_response(response, conn);
}

TEST(test_httpresponse_cookie_rejects_invalid_input) {
    TEST_SUITE("httpresponse: cookies");
    TEST_CASE("cookies without a name or value are not emitted");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->add_cookie(response, (cookie_t){ .name = NULL, .value = "x", .seconds = -1 });
    response->add_cookie(response, (cookie_t){ .name = "", .value = "x", .seconds = -1 });
    response->add_cookie(response, (cookie_t){ .name = "n", .value = NULL, .seconds = -1 });

    TEST_ASSERT_NULL((void*)response->get_header(response, "Set-Cookie"), "nothing emitted");

    free_response(response, conn);
}

TEST(test_httpresponse_cookie_multiple_headers) {
    TEST_SUITE("httpresponse: cookies");
    TEST_CASE("each cookie becomes its own Set-Cookie header");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->add_cookie(response, (cookie_t){ .name = "a", .value = "1", .seconds = -1 });
    response->add_cookie(response, (cookie_t){ .name = "b", .value = "2", .seconds = -1 });

    TEST_ASSERT_EQUAL(2, header_count(response, "Set-Cookie"), "two Set-Cookie headers");

    free_response(response, conn);
}

// ============================================================================
// Static file path resolution
// ============================================================================

/* http_open_file leaves an open descriptor behind on FILE_OK — the point of
 * §10.4 is that resolving the path IS the open. Most assertions below care only
 * about the status, so they close it here; the ones that check the descriptor
 * call http_open_file directly. */
static file_status_e resolve(server_t* server, char* full_path, size_t size,
                             const char* path, size_t length) {
    file_t file;
    const file_status_e status = http_open_file(server, full_path, size, path, length, &file);
    if (status == FILE_OK)
        file.close(&file);
    else if (file.fd != -1)
        TEST_FAIL("http_open_file leaked a descriptor on a failed resolve");
    return status;
}

TEST(test_http_get_file_full_path) {
    TEST_SUITE("httpresponse: file path resolution");
    TEST_CASE("http_open_file resolves files, directories and errors");

    char root[] = "/tmp/cwfr_httpresponse_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "test root created");

    char path[PATH_MAX];
    char sub[PATH_MAX];
    char emptydir[PATH_MAX];
    char plain[PATH_MAX];
    snprintf(sub, sizeof(sub), "%s/sub", root);
    snprintf(emptydir, sizeof(emptydir), "%s/emptydir", root);
    snprintf(plain, sizeof(plain), "%s/file.txt", root);

    TEST_REQUIRE(mkdir(sub, 0755) == 0, "sub dir created");
    TEST_REQUIRE(mkdir(emptydir, 0755) == 0, "empty dir created");

    snprintf(path, sizeof(path), "%s/index.html", root);
    TEST_REQUIRE(write_whole_file(path, "<h1>root</h1>"), "root index written");
    snprintf(path, sizeof(path), "%s/sub/index.html", root);
    TEST_REQUIRE(write_whole_file(path, "<h1>sub</h1>"), "sub index written");
    TEST_REQUIRE(write_whole_file(plain, "plain"), "plain file written");

    server_t server;
    memset(&server, 0, sizeof(server));
    server.root = root;
    server.root_length = strlen(root);
    server.index = NULL;

    char full_path[PATH_MAX];

    TEST_ASSERT_EQUAL(FILE_OK, resolve(&server, full_path, PATH_MAX, "/index.html", 11), "existing file");
    snprintf(path, sizeof(path), "%s/index.html", root);
    TEST_ASSERT_STR_EQUAL(path, full_path, "root + path concatenated");

    TEST_ASSERT_EQUAL(FILE_OK, resolve(&server, full_path, PATH_MAX, "index.html", 10), "missing leading slash is inserted");
    TEST_ASSERT_STR_EQUAL(path, full_path, "same resolved path");

    TEST_ASSERT_EQUAL(FILE_OK, resolve(&server, full_path, PATH_MAX, "/file.txt", 9), "regular file");

    TEST_ASSERT_EQUAL(FILE_NOTFOUND, resolve(&server, full_path, PATH_MAX, "/missing.html", 13), "missing file");

    TEST_ASSERT_EQUAL(FILE_FORBIDDEN, resolve(&server, full_path, PATH_MAX, "/sub", 4), "directory without configured index");

    /* REGRESSION: a path through a regular file makes stat() fail with
     * ENOTDIR (not ENOENT); the old code then read an uninitialized
     * struct stat instead of failing deterministically. */
    TEST_ASSERT_EQUAL(FILE_NOTFOUND, resolve(&server, full_path, PATH_MAX, "/file.txt/deeper", 16), "ENOTDIR is not found");

    TEST_ASSERT_EQUAL(FILE_NOTFOUND, resolve(&server, full_path, 4, "/index.html", 11), "tiny output buffer");

    server.index = server_index_create("index.html");
    TEST_REQUIRE_NOT_NULL_GOTO(server.index, "index created", cleanup);

    TEST_ASSERT_EQUAL(FILE_OK, resolve(&server, full_path, PATH_MAX, "/sub", 4), "directory resolves to its index");
    snprintf(path, sizeof(path), "%s/sub/index.html", root);
    TEST_ASSERT_STR_EQUAL(path, full_path, "index appended after slash");

    TEST_ASSERT_EQUAL(FILE_OK, resolve(&server, full_path, PATH_MAX, "/sub/", 5), "trailing slash directory");
    TEST_ASSERT_STR_EQUAL(path, full_path, "no double slash inserted");

    TEST_ASSERT_EQUAL(FILE_FORBIDDEN, resolve(&server, full_path, PATH_MAX, "/emptydir", 9), "directory without index file");

    /* The resolver hands back the open file, which is the whole point of §10.4:
     * the caller must not have to open the path a second time. */
    file_t opened;
    TEST_ASSERT_EQUAL(FILE_OK, http_open_file(&server, full_path, PATH_MAX, "/file.txt", 9, &opened), "regular file resolves");
    TEST_ASSERT(opened.ok && opened.fd >= 0, "descriptor is open");
    TEST_ASSERT_EQUAL_SIZE(5, opened.size, "size comes from the fstat done at open");
    char readback[8] = {0};
    TEST_ASSERT_EQUAL(5, read(opened.fd, readback, sizeof(readback)), "descriptor reads the file");
    TEST_ASSERT_STR_EQUAL("plain", readback, "and reads the right one");
    opened.close(&opened);

    /* A directory resolved through its index returns the index's descriptor,
     * not the directory's — the extra open/close pair is the directory's cost. */
    TEST_ASSERT_EQUAL(FILE_OK, http_open_file(&server, full_path, PATH_MAX, "/sub", 4, &opened), "directory resolves to its index");
    TEST_ASSERT(opened.ok && opened.fd >= 0, "index descriptor is open");
    TEST_ASSERT_EQUAL_SIZE(12, opened.size, "size is the index file's");
    opened.close(&opened);

    /* Neither regular nor directory: a fifo is not a representation this server
     * serves, and answering it would block the worker on open(). */
    char fifo[PATH_MAX];
    snprintf(fifo, sizeof(fifo), "%s/pipe", root);
    if (mkfifo(fifo, 0644) == 0) {
        TEST_ASSERT_EQUAL(FILE_NOTFOUND, resolve(&server, full_path, PATH_MAX, "/pipe", 5), "fifo is not found");
        unlink(fifo);
    }

    cleanup:
    if (server.index != NULL) server_index_destroy(server.index);
    snprintf(path, sizeof(path), "%s/index.html", root); unlink(path);
    snprintf(path, sizeof(path), "%s/sub/index.html", root); unlink(path);
    unlink(plain);
    rmdir(sub);
    rmdir(emptydir);
    rmdir(root);
}

// ============================================================================
// Payload getters
// ============================================================================

TEST(test_httpresponse_payload_from_body) {
    TEST_SUITE("httpresponse: payload");
    TEST_CASE("get_payload/get_payload_json read the in-memory body");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_datan(response, "{\"a\":1}", 7);

    char* payload = response->get_payload(response);
    TEST_REQUIRE_NOT_NULL_GOTO(payload, "payload copied", cleanup);
    TEST_ASSERT_STR_EQUAL("{\"a\":1}", payload, "payload equals the body");
    free(payload);

    json_doc_t* document = response->get_payload_json(response);
    TEST_REQUIRE_NOT_NULL_GOTO(document, "payload parsed as JSON", cleanup);
    TEST_ASSERT_STR_EQUAL("{\"a\":1}", json_stringify(document), "JSON round-trip");
    json_free(document);

    cleanup:
    free_response(response, conn);
}

TEST(test_httpresponse_payload_empty_response) {
    TEST_SUITE("httpresponse: payload");
    TEST_CASE("a response without body or payload file yields NULL/not-ok");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    TEST_ASSERT_NULL(response->get_payload(response), "no payload data");

    /* REGRESSION: get_payload_file used to report ok=1 even with no payload
     * file (dead `field` logic), sending callers to read from fd -1. */
    file_content_t content = response->get_payload_file(response);
    TEST_ASSERT_EQUAL(0, content.ok, "content not ok without a file");
    TEST_ASSERT_EQUAL(-1, content.fd, "no file descriptor");

    free_response(response, conn);
}

TEST(test_httpresponse_payload_from_file) {
    TEST_SUITE("httpresponse: payload");
    TEST_CASE("file-backed payload is read back and cleaned up on reset");

    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char dir[] = "/tmp/cwfr_httpresponse_payload_XXXXXX";
    TEST_REQUIRE_NOT_NULL_GOTO(mkdtemp(dir), "payload dir created", cleanup_response);

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/payload.txt", dir);

    file_t file = file_open(file_path, O_CREAT | O_RDWR);
    TEST_REQUIRE_GOTO(file.ok, "payload file opened", cleanup_dir);
    TEST_REQUIRE_GOTO(file.set_content(&file, "hello payload", 13) == 13, "payload written", cleanup_dir);

    response->payload_.file = file;
    response->payload_.path = copy_cstringn(file_path, strlen(file_path));
    TEST_REQUIRE_NOT_NULL_GOTO(response->payload_.path, "payload path copied", cleanup_dir);

    char* payload = response->get_payload(response);
    TEST_REQUIRE_NOT_NULL_GOTO(payload, "payload read from file", cleanup_dir);
    TEST_ASSERT_STR_EQUAL("hello payload", payload, "payload content");
    free(payload);

    file_content_t content = response->get_payload_file(response);
    TEST_ASSERT_EQUAL(1, content.ok, "content ok with a real file");
    TEST_ASSERT_EQUAL(file.fd, content.fd, "content shares the payload fd");
    TEST_ASSERT_EQUAL_SIZE(13, content.size, "content size");

    /* REGRESSION: a second parse used to allocate a fresh part and leak the
     * previous one (LeakSanitizer flags it at exit). */
    http_payloadpart_t* first_part = response->payload_.part;
    content = response->get_payload_file(response);
    TEST_ASSERT(first_part == response->payload_.part, "payload part reused, not reallocated");

    response->base.reset(response);
    TEST_ASSERT_NULL((void*)response->payload_.part, "part freed on reset");
    TEST_ASSERT_NULL(response->payload_.path, "path freed on reset");
    TEST_ASSERT_EQUAL(-1, response->payload_.file.fd, "payload file closed");
    TEST_ASSERT_EQUAL(NONE, response->payload_.type, "payload type back to NONE");
    TEST_ASSERT(access(file_path, F_OK) != 0, "payload file unlinked from disk");

    cleanup_dir:
    unlink(file_path);
    rmdir(dir);

    cleanup_response:
    free_response(response, conn);
}

// ============================================================================
// Accept-Encoding negotiation — httpresponse_set_accept_encoding decides
// whether the content-type rules in main.gzip are allowed to compress at all.
// ============================================================================

static int accepts_gzip(const char* value) {
    connection_t* conn = NULL;
    httpresponse_t* response = make_response(&conn);
    if (response == NULL) return -1;

    if (value == NULL)
        httpresponse_set_accept_encoding(response, NULL, 0);
    else
        httpresponse_set_accept_encoding(response, value, strlen(value));

    const int result = (int)response->client_gzip;

    free_response(response, conn);

    return result;
}

TEST(test_response_accept_encoding_names_gzip) {
    TEST_SUITE("httpresponse: Accept-Encoding");
    TEST_CASE("gzip is used only when the client names it");

    TEST_ASSERT_EQUAL(1, accepts_gzip("gzip"), "bare gzip");
    TEST_ASSERT_EQUAL(1, accepts_gzip("gzip, deflate, br"), "gzip among others");
    TEST_ASSERT_EQUAL(1, accepts_gzip("deflate, GZIP"), "the token is case-insensitive");
    TEST_ASSERT_EQUAL(1, accepts_gzip("  gzip  "), "surrounding whitespace is optional");
    TEST_ASSERT_EQUAL(1, accepts_gzip("gzip;q=1.0"), "an explicit q of one");
    TEST_ASSERT_EQUAL(1, accepts_gzip("gzip;q=0.001"), "a tiny q is still acceptance");

    TEST_ASSERT_EQUAL(0, accepts_gzip("deflate, br"), "gzip not offered");
    TEST_ASSERT_EQUAL(0, accepts_gzip("gzipx"), "a longer token is a different coding");
    TEST_ASSERT_EQUAL(0, accepts_gzip("identity"), "identity only");
}

TEST(test_response_accept_encoding_absent_means_identity) {
    TEST_SUITE("httpresponse: Accept-Encoding");
    TEST_CASE("a missing or empty field means identity only");

    TEST_ASSERT_EQUAL(0, accepts_gzip(NULL), "no field at all");
    TEST_ASSERT_EQUAL(0, accepts_gzip(""), "an empty field");
}

TEST(test_response_accept_encoding_zero_q_refuses) {
    TEST_SUITE("httpresponse: Accept-Encoding");
    TEST_CASE("q=0 is a refusal, not a weak preference");

    TEST_ASSERT_EQUAL(0, accepts_gzip("gzip;q=0"), "q=0");
    TEST_ASSERT_EQUAL(0, accepts_gzip("gzip;q=0.0"), "q=0.0");
    TEST_ASSERT_EQUAL(0, accepts_gzip("gzip;q=0.000"), "q=0.000");
    TEST_ASSERT_EQUAL(0, accepts_gzip("gzip; q=0, deflate"), "whitespace before the parameter");
}

TEST(test_response_accept_encoding_wildcard) {
    TEST_SUITE("httpresponse: Accept-Encoding");
    TEST_CASE("* stands in for gzip unless gzip is named separately");

    TEST_ASSERT_EQUAL(1, accepts_gzip("*"), "a bare wildcard allows gzip");
    TEST_ASSERT_EQUAL(0, accepts_gzip("*;q=0"), "a refused wildcard");

    /* An explicit entry outranks the wildcard whichever way each of them
     * points, and whichever order they appear in. */
    TEST_ASSERT_EQUAL(0, accepts_gzip("*, gzip;q=0"), "gzip refused past an allowing wildcard");
    TEST_ASSERT_EQUAL(0, accepts_gzip("gzip;q=0, *"), "the same with the wildcard last");
    TEST_ASSERT_EQUAL(1, accepts_gzip("*;q=0, gzip"), "gzip allowed past a refusing wildcard");
}

// ============================================================================
// gzip_static — a pre-compressed ".gz" next to a static file is served instead
// of compressing the original (docs/http2/10 §10.5, step 1).
// ============================================================================

/* main.gzip decides which content types are negotiable; the file tests below
 * serve extensionless names, so the mimetype falls back to "text/plain" and
 * this one entry is what makes them compressible. */
static env_gzip_str_t gzip_static_type = { .mimetype = "text/plain", .next = NULL };

typedef struct {
    char root[64];
    char path[PATH_MAX];
    char gz_path[PATH_MAX];
    connection_t* conn;
    httpresponse_t* response;
    env_gzip_str_t* saved_gzip;
    json_doc_t* saved_store;
} gzip_static_fixture_t;

/* 1200 bytes: above HTTP_GZIP_MIN_SIZE, so the response is one the gzip filter
 * would have compressed. Below it nothing negotiates and the ".gz" must be
 * ignored — which is its own case. */
static char* repeat_bytes(size_t length) {
    char* data = malloc(length + 1);
    if (data == NULL) return NULL;

    memset(data, 'a', length);
    data[length] = 0;

    return data;
}

/* Push mtime back by `seconds`: a ".gz" older than its source is a stale build
 * artefact and must not be served. utimes() rather than a sleep, so the case
 * costs nothing. */
static int set_mtime_offset(const char* path, int seconds) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;

    struct timeval times[2];
    times[0].tv_sec = st.st_atime; times[0].tv_usec = 0;
    times[1].tv_sec = st.st_mtime + seconds; times[1].tv_usec = 0;

    return utimes(path, times) == 0;
}

static void gzip_static_policy_set(gzip_static_fixture_t* fx, int enabled) {
    appconfig_t* config = appconfig();

    json_doc_t* store = json_root_create_object();
    if (store == NULL) return;

    json_token_t* value = json_create_bool(enabled);
    if (value == NULL || !json_object_set(json_root(store), "gzip_static", value)) {
        json_free(store);
        return;
    }

    if (fx->saved_store == NULL)
        fx->saved_store = config->env.custom_store;

    config->env.custom_store = store;
    http_policy_init();
}

static int gzip_static_setup(gzip_static_fixture_t* fx, size_t body_size, int enabled) {
    memset(fx, 0, sizeof(*fx));

    snprintf(fx->root, sizeof(fx->root), "/tmp/cwfr_gzipstatic_XXXXXX");
    if (mkdtemp(fx->root) == NULL) return 0;

    snprintf(fx->path, sizeof(fx->path), "%s/asset", fx->root);
    snprintf(fx->gz_path, sizeof(fx->gz_path), "%s/asset.gz", fx->root);

    char* body = repeat_bytes(body_size);
    if (body == NULL) return 0;

    const int written = write_whole_file(fx->path, body);
    free(body);
    if (!written) return 0;

    fx->saved_gzip = env()->main.gzip;
    env()->main.gzip = &gzip_static_type;

    gzip_static_policy_set(fx, enabled);

    fx->response = make_response(&fx->conn);
    if (fx->response == NULL) return 0;

    /* What the request said it would accept: without this the response never
     * reaches CE_GZIP and the ".gz" is never looked for. */
    httpresponse_set_accept_encoding(fx->response, "gzip", 4);

    return 1;
}

/* The compressed twin. `mtime_offset` is applied to it relative to the
 * original: 0 = same second (fresh), negative = stale. */
static int gzip_static_write_gz(gzip_static_fixture_t* fx, const char* content, int mtime_offset) {
    if (!write_whole_file(fx->gz_path, content)) return 0;
    if (mtime_offset == 0) return 1;

    return set_mtime_offset(fx->gz_path, mtime_offset);
}

static void gzip_static_teardown(gzip_static_fixture_t* fx) {
    if (fx->response != NULL) {
        fx->response->file_.close(&fx->response->file_);
        free_response(fx->response, fx->conn);
    }
    else
        free(fx->conn);

    env()->main.gzip = fx->saved_gzip;

    appconfig_t* config = appconfig();
    if (config->env.custom_store != NULL && config->env.custom_store != fx->saved_store) {
        json_free(config->env.custom_store);
        config->env.custom_store = fx->saved_store;
        http_policy_init();
    }

    unlink(fx->gz_path);
    unlink(fx->path);
    rmdir(fx->root);
}

/* Open the original the way the resolver does and hand it to the response. */
static int gzip_static_serve(gzip_static_fixture_t* fx) {
    file_t file = file_open(fx->path, O_RDONLY | O_NONBLOCK);
    if (!file.ok) return 0;

    http_response_file_opened(fx->response, &file, fx->path);

    return 1;
}

TEST(test_gzip_static_serves_precompressed_twin) {
    TEST_SUITE("httpresponse: gzip_static");
    TEST_CASE("a fresh .gz is served in place of compressing the original");

    gzip_static_fixture_t fx;
    TEST_REQUIRE(gzip_static_setup(&fx, 1200, 1), "fixture created");
    TEST_REQUIRE_GOTO(gzip_static_write_gz(&fx, "pretend-gzip-bytes", 0), ".gz written", cleanup);
    TEST_REQUIRE_GOTO(gzip_static_serve(&fx), "original opened and served", cleanup);

    TEST_ASSERT_EQUAL(1, (int)fx.response->gzip_precompressed, "the response says it carries the compressed twin");
    TEST_ASSERT_EQUAL_SIZE(18, fx.response->file_.size, "the open file is the .gz, not the original");

    http_header_t* encoding = fx.response->get_header(fx.response, "Content-Encoding");
    TEST_REQUIRE_NOT_NULL_GOTO(encoding, "Content-Encoding is set", cleanup);
    TEST_ASSERT_STR_EQUAL("gzip", encoding->value, "and it names gzip");

    /* Nothing is left to compress and the length is known: the body goes out as
     * an ordinary file, not chunked through the gzip filter. */
    TEST_ASSERT_EQUAL(CE_NONE, fx.response->content_encoding, "the gzip filter has nothing to do");
    TEST_ASSERT_EQUAL(TE_NONE, fx.response->transfer_encoding, "and the response is not chunked");

    /* The type is still negotiable, so the answer still varies by the request
     * field — the gzip filter reads this to emit Vary. */
    TEST_ASSERT_EQUAL(1, (int)fx.response->vary_encoding, "the response still varies on Accept-Encoding");

    http_header_t* type = fx.response->get_header(fx.response, "Content-Type");
    TEST_REQUIRE_NOT_NULL_GOTO(type, "Content-Type is set", cleanup);
    TEST_ASSERT_STR_EQUAL("text/plain", type->value, "and describes the original, not the .gz");

    cleanup:
    gzip_static_teardown(&fx);
}

TEST(test_gzip_static_ignores_stale_twin) {
    TEST_SUITE("httpresponse: gzip_static");
    TEST_CASE("a .gz older than its source is a stale build artefact");

    gzip_static_fixture_t fx;
    TEST_REQUIRE(gzip_static_setup(&fx, 1200, 1), "fixture created");
    TEST_REQUIRE_GOTO(gzip_static_write_gz(&fx, "stale-bytes", -60), "stale .gz written", cleanup);
    TEST_REQUIRE_GOTO(gzip_static_serve(&fx), "original opened and served", cleanup);

    TEST_ASSERT_EQUAL(0, (int)fx.response->gzip_precompressed, "the stale twin is refused");
    TEST_ASSERT_EQUAL_SIZE(1200, fx.response->file_.size, "the original is still the open file");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Encoding"),
                     "and nothing claims the body is compressed");
    TEST_ASSERT_EQUAL(CE_GZIP, fx.response->content_encoding, "the gzip filter compresses as before");

    cleanup:
    gzip_static_teardown(&fx);
}

TEST(test_gzip_static_without_twin_compresses_as_before) {
    TEST_SUITE("httpresponse: gzip_static");
    TEST_CASE("no .gz on disk leaves the runtime path untouched");

    gzip_static_fixture_t fx;
    TEST_REQUIRE(gzip_static_setup(&fx, 1200, 1), "fixture created");
    TEST_REQUIRE_GOTO(gzip_static_serve(&fx), "original opened and served", cleanup);

    TEST_ASSERT_EQUAL(0, (int)fx.response->gzip_precompressed, "nothing was swapped in");
    TEST_ASSERT_EQUAL(CE_GZIP, fx.response->content_encoding, "the gzip filter still compresses");
    TEST_ASSERT_EQUAL_SIZE(1200, fx.response->file_.size, "the original is the open file");

    cleanup:
    gzip_static_teardown(&fx);
}

TEST(test_gzip_static_off_by_default) {
    TEST_SUITE("httpresponse: gzip_static");
    TEST_CASE("with the setting off the .gz is not even looked for");

    gzip_static_fixture_t fx;
    TEST_REQUIRE(gzip_static_setup(&fx, 1200, 0), "fixture created");
    TEST_ASSERT_EQUAL(0, http_gzip_static_enabled(), "the policy is off");

    TEST_REQUIRE_GOTO(gzip_static_write_gz(&fx, "pretend-gzip-bytes", 0), ".gz written", cleanup);
    TEST_REQUIRE_GOTO(gzip_static_serve(&fx), "original opened and served", cleanup);

    TEST_ASSERT_EQUAL(0, (int)fx.response->gzip_precompressed, "the twin is ignored");
    TEST_ASSERT_EQUAL_SIZE(1200, fx.response->file_.size, "the original is the open file");

    cleanup:
    gzip_static_teardown(&fx);
}

TEST(test_gzip_static_identity_client_gets_the_original) {
    TEST_SUITE("httpresponse: gzip_static");
    TEST_CASE("a client that did not accept gzip pays neither the swap nor the open");

    gzip_static_fixture_t fx;
    TEST_REQUIRE(gzip_static_setup(&fx, 1200, 1), "fixture created");

    /* The whole negotiation in one field: no gzip accepted, so main.gzip marks
     * the type negotiable (Vary) but nothing is compressed and no twin is
     * looked for. */
    httpresponse_set_accept_encoding(fx.response, "identity", 8);

    TEST_REQUIRE_GOTO(gzip_static_write_gz(&fx, "pretend-gzip-bytes", 0), ".gz written", cleanup);
    TEST_REQUIRE_GOTO(gzip_static_serve(&fx), "original opened and served", cleanup);

    TEST_ASSERT_EQUAL(0, (int)fx.response->gzip_precompressed, "no swap for an identity client");
    TEST_ASSERT_EQUAL_SIZE(1200, fx.response->file_.size, "the original is the open file");
    TEST_ASSERT_EQUAL(1, (int)fx.response->vary_encoding, "the type is still negotiable");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Encoding"),
                     "and the answer does not claim gzip");

    cleanup:
    gzip_static_teardown(&fx);
}

TEST(test_gzip_static_small_file_keeps_identity) {
    TEST_SUITE("httpresponse: gzip_static");
    TEST_CASE("below the gzip minimum the .gz is ignored, as the filter would");

    gzip_static_fixture_t fx;
    TEST_REQUIRE(gzip_static_setup(&fx, 512, 1), "fixture created");
    TEST_REQUIRE_GOTO(gzip_static_write_gz(&fx, "pretend-gzip-bytes", 0), ".gz written", cleanup);
    TEST_REQUIRE_GOTO(gzip_static_serve(&fx), "original opened and served", cleanup);

    /* The gzip filter leaves bodies under HTTP_GZIP_MIN_SIZE alone. Serving the
     * twin here would compress a response that is identity today and change its
     * ETag with it. */
    TEST_ASSERT_EQUAL(0, (int)fx.response->gzip_precompressed, "small files keep the original");
    TEST_ASSERT_EQUAL_SIZE(512, fx.response->file_.size, "the original is the open file");

    cleanup:
    gzip_static_teardown(&fx);
}

TEST(test_gzip_static_rejects_non_regular_twin) {
    TEST_SUITE("httpresponse: gzip_static");
    TEST_CASE("a directory named <file>.gz is not a representation");

    gzip_static_fixture_t fx;
    TEST_REQUIRE(gzip_static_setup(&fx, 1200, 1), "fixture created");
    TEST_REQUIRE_GOTO(mkdir(fx.gz_path, 0755) == 0, "<file>.gz directory created", cleanup);
    TEST_REQUIRE_GOTO(gzip_static_serve(&fx), "original opened and served", cleanup);

    TEST_ASSERT_EQUAL(0, (int)fx.response->gzip_precompressed, "the directory is refused");
    TEST_ASSERT_EQUAL_SIZE(1200, fx.response->file_.size, "the original is the open file");

    rmdir(fx.gz_path);

    cleanup:
    gzip_static_teardown(&fx);
}

// ============================================================================
// A borrowed body — the gzip cache's bytes, served without a copy — must be let
// go the moment anything builds a body of its own on the same response.
// ============================================================================

TEST(test_gzip_cache_body_is_released_when_overwritten) {
    TEST_SUITE("httpresponse: gzip cache");
    TEST_CASE("writing a new body drops the cached representation instead of scribbling on it");

    gzip_static_fixture_t fx;
    /* The fixture's setting is gzip_static; this case wants the memory cache,
     * so it is configured directly. */
    TEST_REQUIRE(gzip_static_setup(&fx, 4096, 0), "fixture created");
    http_gzip_cache_configure(1024 * 1024, 512 * 1024);

    TEST_REQUIRE_GOTO(gzip_static_serve(&fx), "file served", cleanup);
    TEST_REQUIRE_GOTO(fx.response->gzip_precompressed == 1, "the body came from the cache", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(fx.response->body_cache, "and holds a reference to it", cleanup);
    TEST_ASSERT_EQUAL_SIZE(1, http_gzip_cache_count(), "one entry is published");

    /* What a handler answering after send_file does, and what an error page
     * does: replace the representation. Without the release below this appends
     * into memory the cache owns. */
    fx.response->send_datan(fx.response, "replaced", 8);

    TEST_ASSERT_NULL(fx.response->body_cache, "the reference went back");
    TEST_ASSERT_EQUAL(0, (int)fx.response->gzip_precompressed, "and the response no longer claims gzip");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Encoding"),
                     "nor carries the header that claimed it");
    TEST_ASSERT_EQUAL_SIZE(8, fx.response->body.size, "the new body is the one that is served");
    TEST_ASSERT(memcmp(fx.response->body.data, "replaced", 8) == 0, "and it is the caller's bytes");

    cleanup:
    gzip_static_teardown(&fx);
    http_gzip_cache_configure(0, 0);
}

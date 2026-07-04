/*
 * Unit tests for protocols/websocket/websocketsprotocolresource.c
 *
 * Covers the resource protocol factory, the "METHOD /path?query DATA" frame
 * parser (payload_parse), uri/location/query helpers, reset and the route
 * dispatch in websocketsrequest_get_resource. Several cases are regression
 * guards for bugs fixed alongside these tests (each is marked REGRESSION
 * below):
 *
 *   - get_resource never stored the head of the route-param chain into
 *     protocol->query_: without a query string in the location the params
 *     ({id} etc.) were invisible to get_query and leaked on reset.
 *   - get_resource appended params of a matching route before checking that
 *     the route has a handler for the method, so a handler-less route
 *     polluted the params seen by the route dispatched after it.
 *   - payload_parse killed the connection when a fragment ended exactly at
 *     the location-terminating space: write(fd, p, 0) returns 0, which the
 *     write error check misread as a failed write.
 *   - payload_parse billed the whole first chunk (method and location bytes
 *     included) against client_max_body_size instead of the payload bytes.
 *   - payload_parse accepted any positive write() result, so a short write
 *     (ENOSPC, rlimit) silently truncated the payload handed to the handler.
 *
 * env()/appconfig() resolve to the weak test doubles defined in
 * test_httprequestparser.c (client_max_body_size, tmp are writable per test).
 */

#include "framework.h"
#include "appconfig.h"
#include "connection_s.h"
#include "cqueue.h"
#include "queryparser.h"
#include "route.h"
#include "websocketsparser.h"
#include "websocketsprotocolresource.h"
#include "websocketsserverhandlers.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

/* Internal functions of websocketsprotocolresource.c (external linkage). */
int websocketsrequest_get_resource(connection_t* connection, websocketsrequest_t* request);
void websockets_protocol_resource_reset(void*);
int websockets_protocol_resource_payload_parse(websocketsparser_t* parser, char* data, size_t size, int unmasking);
const char* websocketsrequest_query(websockets_protocol_resource_t*, const char*, int* ok);
query_t* websocketsrequest_last_query_item(websockets_protocol_resource_t*);
void websocketsrequest_query_free(query_t*);
int websocketsparser_parse_location(websockets_protocol_resource_t*, char*, size_t);
int websocketsparser_append_uri(websockets_protocol_resource_t*, const char*, size_t);

// ============================================================================
// Helpers
// ============================================================================

static websockets_protocol_resource_t* proto(websocketsrequest_t* request) {
    return (websockets_protocol_resource_t*)request->protocol;
}

static websocketsrequest_t* make_resource_request(connection_t* connection) {
    websockets_protocol_t* protocol = websockets_protocol_resource_create();
    if (protocol == NULL) return NULL;

    websocketsrequest_t* request = websocketsrequest_create(connection, protocol);
    if (request == NULL) protocol->free(protocol);

    return request;
}

static void parser_setup(websocketsparser_t* parser, websocketsrequest_t* request) {
    memset(parser, 0, sizeof * parser);
    bufferdata_init(&parser->buf);
    parser->request = request;
}

static void parser_teardown(websocketsparser_t* parser) {
    bufferdata_clear(&parser->buf);
}

/* Begin a frame the way the wire parser does; between frames of a fragmented
 * message prepare_remains resets the per-frame counters the same way. */
static void frame_start(websocketsparser_t* parser, size_t payload_length, int fin, const unsigned char mask[4]) {
    parser->frame.fin = fin;
    parser->frame.payload_length = payload_length;
    parser->payload_index = 0;
    parser->payload_saved_length = 0;

    if (mask != NULL)
        memcpy(parser->frame.mask, mask, 4);
}

/* The real caller (websocketsparser_parse_payload) adds the chunk size to
 * payload_saved_length before invoking payload_parse; last_data detection
 * inside payload_parse relies on that bookkeeping. */
static int feed_chunk(websocketsparser_t* parser, char* data, size_t size, int unmasking) {
    parser->payload_saved_length += size;
    return websockets_protocol_resource_payload_parse(parser, data, size, unmasking);
}

/* Feed one whole unmasked frame in a single chunk. */
static int feed_frame(websocketsparser_t* parser, const char* message, int fin) {
    char buffer[256];
    const size_t length = strlen(message);
    if (length >= sizeof(buffer)) return 0;
    memcpy(buffer, message, length);

    frame_start(parser, length, fin, NULL);
    return feed_chunk(parser, buffer, length, 0);
}

static void mask_buffer(char* data, size_t length, const unsigned char mask[4], size_t key_offset) {
    for (size_t i = 0; i < length; i++)
        data[i] ^= mask[(key_offset + i) % 4];
}

/* Read the payload tmpfile back without moving its offset. */
static ssize_t payload_file_read(websockets_protocol_t* protocol, char* out, size_t out_size) {
    if (protocol->payload.fd < 0) return -1;

    return pread(protocol->payload.fd, out, out_size, 0);
}

static int query_key_count(query_t* query, const char* key) {
    int count = 0;

    for (; query != NULL; query = query->next)
        if (query->key != NULL && strcmp(query->key, key) == 0)
            count++;

    return count;
}

// ============================================================================
// websockets_protocol_resource_create
// ============================================================================

TEST(test_wsres_create_initializes_protocol) {
    TEST_SUITE("websocketsprotocolresource: create");
    TEST_CASE("vtable and parsing state are fully initialized");

    websockets_protocol_t* protocol = websockets_protocol_resource_create();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    websockets_protocol_resource_t* resource = (websockets_protocol_resource_t*)protocol;

    TEST_ASSERT(protocol->payload_parse == websockets_protocol_resource_payload_parse, "payload_parse is wired");
    TEST_ASSERT(protocol->get_resource == websocketsrequest_get_resource, "get_resource is wired");
    TEST_ASSERT(protocol->reset == websockets_protocol_resource_reset, "reset is wired");
    TEST_ASSERT_NOT_NULL(protocol->free, "free is wired");
    TEST_ASSERT(resource->get_query == websocketsrequest_query, "get_query is wired");
    TEST_ASSERT_NOT_NULL(resource->get_payload, "get_payload is wired");
    TEST_ASSERT_NOT_NULL(resource->get_payload_file, "get_payload_file is wired");
    TEST_ASSERT_NOT_NULL(resource->get_payload_json, "get_payload_json is wired");

    TEST_ASSERT_EQUAL(ROUTE_NONE, resource->method, "method starts as NONE");
    TEST_ASSERT_EQUAL(WSPROTRESOURCE_METHOD, resource->parser_stage, "stage starts at METHOD");
    TEST_ASSERT_EQUAL_SIZE(0, resource->uri_length, "uri_length starts at 0");
    TEST_ASSERT_EQUAL_SIZE(0, resource->path_length, "path_length starts at 0");
    TEST_ASSERT_NULL(resource->uri, "uri starts NULL");
    TEST_ASSERT_NULL(resource->path, "path starts NULL");
    TEST_ASSERT_NULL(resource->query_, "query starts NULL");
    TEST_ASSERT_EQUAL(-1, protocol->payload.fd, "payload fd starts at the -1 sentinel");

    protocol->free(protocol);
}

// ============================================================================
// payload_parse: method and location
// ============================================================================

TEST(test_wsres_parse_simple_get) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("GET with path only");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "GET /path", 1), "frame parsed");
    TEST_ASSERT_EQUAL(ROUTE_GET, proto(request)->method, "method is GET");
    TEST_ASSERT_STR_EQUAL("/path", proto(request)->path, "path extracted");
    TEST_ASSERT_STR_EQUAL("/path", proto(request)->uri, "uri accumulated");
    TEST_ASSERT_EQUAL_SIZE(5, proto(request)->path_length, "path length");
    TEST_ASSERT_EQUAL(-1, request->protocol->payload.fd, "no tmpfile for GET without payload");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_masked_message) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("masked frame is XOR-decoded before parsing");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    const unsigned char mask[4] = {0x2B, 0x91, 0xC4, 0x7E};
    char data[] = "POST /items {\"a\":1}";
    const size_t length = sizeof(data) - 1;
    mask_buffer(data, length, mask, 0);

    frame_start(&parser, length, 1, mask);
    TEST_ASSERT_EQUAL(1, feed_chunk(&parser, data, length, 1), "masked frame parsed");
    TEST_ASSERT_EQUAL(ROUTE_POST, proto(request)->method, "method is POST");
    TEST_ASSERT_STR_EQUAL("/items", proto(request)->path, "path extracted");
    TEST_ASSERT_EQUAL((int)length, (int)parser.payload_index, "payload_index advanced");

    char content[32] = {0};
    TEST_ASSERT_EQUAL(7, (int)payload_file_read(request->protocol, content, sizeof(content)), "payload size");
    TEST_ASSERT_STR_EQUAL("{\"a\":1}", content, "payload unmasked and stored");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_methods) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("supported methods parse, others are rejected");

    const struct { const char* message; int ok; route_methods_e method; } cases[] = {
        {"GET /x", 1, ROUTE_GET},
        {"POST /x", 1, ROUTE_POST},
        {"PATCH /x", 1, ROUTE_PATCH},
        {"DELETE /x", 1, ROUTE_DELETE},
        {"PUT /x", 0, ROUTE_NONE},
        {"FETCH /x", 0, ROUTE_NONE},
        {"OPTIONS /x", 0, ROUTE_NONE},
        {"get /x", 0, ROUTE_NONE},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        websocketsrequest_t* request = make_resource_request(NULL);
        TEST_REQUIRE_NOT_NULL(request, "request allocation");

        websocketsparser_t parser;
        parser_setup(&parser, request);

        TEST_ASSERT_EQUAL(cases[i].ok, feed_frame(&parser, cases[i].message, 1), cases[i].message);
        if (cases[i].ok)
            TEST_ASSERT_EQUAL(cases[i].method, proto(request)->method, "method value");

        parser_teardown(&parser);
        websocketsrequest_free(request);
    }
}

TEST(test_wsres_parse_split_chunks) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("method and location split across reads of one frame");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    char part1[] = "GE";
    char part2[] = "T /lo";
    char part3[] = "ng";

    frame_start(&parser, 9, 1, NULL);
    TEST_ASSERT_EQUAL(1, feed_chunk(&parser, part1, 2, 0), "first chunk");
    TEST_ASSERT_EQUAL(1, feed_chunk(&parser, part2, 5, 0), "second chunk");
    TEST_ASSERT_EQUAL(1, feed_chunk(&parser, part3, 2, 0), "final chunk");

    TEST_ASSERT_EQUAL(ROUTE_GET, proto(request)->method, "method assembled across chunks");
    TEST_ASSERT_STR_EQUAL("/long", proto(request)->path, "path assembled across chunks");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_query_string) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("query string is split from the path and parsed");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "GET /p?a=1&b=two", 1), "frame parsed");
    TEST_ASSERT_STR_EQUAL("/p", proto(request)->path, "path excludes query");

    int ok = 0;
    TEST_ASSERT_STR_EQUAL("1", proto(request)->get_query(proto(request), "a", &ok), "a=1");
    TEST_ASSERT_EQUAL(1, ok, "a found");
    TEST_ASSERT_STR_EQUAL("two", proto(request)->get_query(proto(request), "b", &ok), "b=two");
    TEST_ASSERT_NULL(proto(request)->get_query(proto(request), "c", &ok), "missing key is NULL");
    TEST_ASSERT_EQUAL(0, ok, "missing key reports ok=0");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_fragment_identifier) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("#fragment is cut from the path, query still parsed");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "GET /p#section", 1), "frame with fragment parsed");
    TEST_ASSERT_STR_EQUAL("/p", proto(request)->path, "fragment excluded from path");
    TEST_ASSERT_NULL(proto(request)->query_, "no query parsed");

    websocketsrequest_free(request);
    parser_teardown(&parser);

    request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "second request allocation");
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "GET /p?a=1#section", 1), "query+fragment parsed");
    TEST_ASSERT_STR_EQUAL("/p", proto(request)->path, "path excludes query and fragment");

    int ok = 0;
    TEST_ASSERT_STR_EQUAL("1", proto(request)->get_query(proto(request), "a", &ok), "query value stops at fragment");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_urlencoded_path) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("percent-encoded path is decoded");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "GET /a%20b", 1), "frame parsed");
    TEST_ASSERT_STR_EQUAL("/a b", proto(request)->path, "path decoded");
    TEST_ASSERT_EQUAL_SIZE(4, proto(request)->path_length, "decoded length");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_rejects_bad_locations) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("path traversal and relative locations are rejected");

    const char* messages[] = {
        "GET /../secret",
        "GET /a/%2e%2e/b",
        "GET x",
    };

    for (size_t i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
        websocketsrequest_t* request = make_resource_request(NULL);
        TEST_REQUIRE_NOT_NULL(request, "request allocation");

        websocketsparser_t parser;
        parser_setup(&parser, request);

        TEST_ASSERT_EQUAL(0, feed_frame(&parser, messages[i], 1), messages[i]);

        parser_teardown(&parser);
        websocketsrequest_free(request);
    }
}

// ============================================================================
// payload_parse: payload body
// ============================================================================

TEST(test_wsres_parse_post_payload) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("POST payload lands in the tmpfile");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "POST /x hello", 1), "frame parsed");
    TEST_ASSERT_STR_EQUAL("/x", proto(request)->path, "path extracted");

    char* payload = proto(request)->get_payload(proto(request));
    TEST_ASSERT_STR_EQUAL("hello", payload, "payload readable through accessor");
    free(payload);

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_payload_across_chunks) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("payload split across reads accumulates in order");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    char part1[] = "POST /x he";
    char part2[] = "llo";

    frame_start(&parser, 13, 1, NULL);
    TEST_ASSERT_EQUAL(1, feed_chunk(&parser, part1, 10, 0), "first chunk");
    TEST_ASSERT_EQUAL(1, feed_chunk(&parser, part2, 3, 0), "second chunk");

    char content[16] = {0};
    TEST_ASSERT_EQUAL(5, (int)payload_file_read(request->protocol, content, sizeof(content)), "payload size");
    TEST_ASSERT_STR_EQUAL("hello", content, "payload assembled");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_fragment_ends_at_space_regression) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    /* REGRESSION: a non-final fragment ending exactly at the space after the
     * location reached the write block with zero payload bytes; write(fd, p, 0)
     * returned 0 and the connection was killed for a legitimate request. */
    TEST_CASE("fragment ending at the location space is not an error");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "POST /x ", 0), "first fragment accepted");
    TEST_ASSERT_EQUAL(-1, request->protocol->payload.fd, "no tmpfile until payload bytes arrive");

    /* Continuation frame carries the body. */
    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "body", 1), "continuation fragment accepted");

    char content[16] = {0};
    TEST_ASSERT_EQUAL(4, (int)payload_file_read(request->protocol, content, sizeof(content)), "payload size");
    TEST_ASSERT_STR_EQUAL("body", content, "payload from continuation stored");

    parser_teardown(&parser);
    websocketsrequest_free(request);

    /* Same shape for a method that carries no payload at all. */
    request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "second request allocation");
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "GET /x ", 0), "GET fragment ending at space accepted");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_get_with_payload_rejected) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("payload bytes after the location are rejected for GET");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    TEST_ASSERT_EQUAL(0, feed_frame(&parser, "GET /x y", 1), "GET with payload is an error");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_limit_counts_payload_only_regression) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    /* REGRESSION: the body-size check billed the whole chunk - method and
     * location included - against client_max_body_size, so a payload that
     * fits the limit exactly was rejected on the first chunk. */
    TEST_CASE("method and location bytes do not count against the limit");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    const unsigned int saved_limit = env()->main.client_max_body_size;
    env()->main.client_max_body_size = 4;

    TEST_ASSERT_EQUAL(1, feed_frame(&parser, "POST /x data", 1), "payload equal to the limit fits");

    char content[16] = {0};
    TEST_ASSERT_EQUAL(4, (int)payload_file_read(request->protocol, content, sizeof(content)), "payload size");
    TEST_ASSERT_STR_EQUAL("data", content, "payload stored");

    env()->main.client_max_body_size = saved_limit;
    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_limit_is_cumulative) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    TEST_CASE("limit applies to the accumulated payload across chunks");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    const unsigned int saved_limit = env()->main.client_max_body_size;
    env()->main.client_max_body_size = 4;

    char part1[] = "POST /x dat";
    char part2[] = "ab";

    frame_start(&parser, 13, 1, NULL);
    TEST_ASSERT_EQUAL(1, feed_chunk(&parser, part1, 11, 0), "payload under the limit fits");
    TEST_ASSERT_EQUAL(0, feed_chunk(&parser, part2, 2, 0), "chunk crossing the limit is rejected");

    char content[16] = {0};
    TEST_ASSERT_EQUAL(3, (int)payload_file_read(request->protocol, content, sizeof(content)), "file keeps only the fitting bytes");

    env()->main.client_max_body_size = saved_limit;
    parser_teardown(&parser);
    websocketsrequest_free(request);
}

TEST(test_wsres_parse_short_write_regression) {
    TEST_SUITE("websocketsprotocolresource: payload_parse");
    /* REGRESSION: `int r = write(...); if (r <= 0)` accepted a short write as
     * success, silently truncating the payload. RLIMIT_FSIZE forces write()
     * to stop at 4 bytes (with SIGXFSZ ignored the syscall returns the
     * partial count, then EFBIG). */
    TEST_CASE("a partial payload write fails the chunk");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    struct rlimit saved_limit;
    TEST_REQUIRE(getrlimit(RLIMIT_FSIZE, &saved_limit) == 0, "read RLIMIT_FSIZE");

    struct sigaction ignore_action = {0};
    struct sigaction saved_action;
    ignore_action.sa_handler = SIG_IGN;
    TEST_REQUIRE(sigaction(SIGXFSZ, &ignore_action, &saved_action) == 0, "ignore SIGXFSZ");

    const struct rlimit small_limit = {.rlim_cur = 4, .rlim_max = saved_limit.rlim_max};
    TEST_REQUIRE(setrlimit(RLIMIT_FSIZE, &small_limit) == 0, "shrink RLIMIT_FSIZE");

    const int result = feed_frame(&parser, "POST /x 123456", 1);

    setrlimit(RLIMIT_FSIZE, &saved_limit);
    sigaction(SIGXFSZ, &saved_action, NULL);

    TEST_ASSERT_EQUAL(0, result, "truncated payload must be reported as failure");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

// ============================================================================
// websocketsparser_append_uri / websocketsparser_parse_location
// ============================================================================

TEST(test_wsres_append_uri) {
    TEST_SUITE("websocketsprotocolresource: append_uri");
    TEST_CASE("chunks accumulate; a relative uri is rejected");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    TEST_ASSERT_EQUAL(0, websocketsparser_append_uri(proto(request), "/ab", 3), "first chunk accepted");
    TEST_ASSERT_EQUAL(0, websocketsparser_append_uri(proto(request), "cd", 2), "second chunk accepted");
    TEST_ASSERT_STR_EQUAL("/abcd", proto(request)->uri, "uri accumulated");
    TEST_ASSERT_EQUAL_SIZE(5, proto(request)->uri_length, "uri length");

    websocketsrequest_free(request);

    request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "second request allocation");

    TEST_ASSERT_EQUAL(-1, websocketsparser_append_uri(proto(request), "x", 1), "relative uri rejected");

    websocketsrequest_free(request);
}

TEST(test_wsres_parse_location_direct) {
    TEST_SUITE("websocketsprotocolresource: parse_location");
    TEST_CASE("path, query and fragment combinations");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    char location1[] = "/a/b";
    TEST_ASSERT_EQUAL(1, websocketsparser_parse_location(proto(request), location1, 4), "plain path parsed");
    TEST_ASSERT_STR_EQUAL("/a/b", proto(request)->path, "path stored");

    websockets_protocol_resource_reset(proto(request));

    char location2[] = "/a?x=1";
    TEST_ASSERT_EQUAL(1, websocketsparser_parse_location(proto(request), location2, 6), "path with query parsed");
    TEST_ASSERT_STR_EQUAL("/a", proto(request)->path, "path excludes query");

    int ok = 0;
    TEST_ASSERT_STR_EQUAL("1", websocketsrequest_query(proto(request), "x", &ok), "query parsed");

    websockets_protocol_resource_reset(proto(request));

    char location3[] = "x/y";
    TEST_ASSERT_EQUAL(0, websocketsparser_parse_location(proto(request), location3, 3), "relative location rejected");

    websocketsrequest_free(request);
}

// ============================================================================
// query helpers
// ============================================================================

TEST(test_wsres_query_helpers) {
    TEST_SUITE("websocketsprotocolresource: query helpers");
    TEST_CASE("lookup, last item and free cover the edge cases");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    TEST_ASSERT_NULL(websocketsrequest_last_query_item(proto(request)), "empty chain has no last item");
    TEST_ASSERT_NULL(websocketsrequest_query(proto(request), "a", NULL), "lookup on empty chain (NULL ok accepted)");

    int ok = 1;
    TEST_ASSERT_NULL(websocketsrequest_query(proto(request), NULL, &ok), "NULL key is rejected");
    TEST_ASSERT_EQUAL(0, ok, "NULL key reports ok=0");

    query_t* first = query_create("a", 1, "1", 1);
    query_t* second = query_create("b", 1, "2", 1);
    TEST_REQUIRE(first != NULL && second != NULL, "query allocation");
    first->next = second;
    proto(request)->query_ = first;

    TEST_ASSERT(websocketsrequest_last_query_item(proto(request)) == second, "last item found");
    TEST_ASSERT_STR_EQUAL("2", websocketsrequest_query(proto(request), "b", &ok), "value found");
    TEST_ASSERT_EQUAL(1, ok, "found reports ok=1");

    websocketsrequest_query_free(NULL); /* must be a no-op */

    websocketsrequest_free(request); /* frees the chain through reset */
}

// ============================================================================
// reset
// ============================================================================

TEST(test_wsres_reset_clears_parsing_state) {
    TEST_SUITE("websocketsprotocolresource: reset");
    TEST_CASE("protocol reset clears routing state but not the payload");

    websocketsrequest_t* request = make_resource_request(NULL);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);

    TEST_REQUIRE(feed_frame(&parser, "POST /x?a=1 body", 1) == 1, "frame parsed");
    TEST_REQUIRE(request->protocol->payload.fd >= 0, "payload written");

    request->protocol->reset(request->protocol);

    TEST_ASSERT_EQUAL(ROUTE_NONE, proto(request)->method, "method reset");
    TEST_ASSERT_EQUAL(WSPROTRESOURCE_METHOD, proto(request)->parser_stage, "stage reset");
    TEST_ASSERT_NULL(proto(request)->uri, "uri released");
    TEST_ASSERT_NULL(proto(request)->path, "path released");
    TEST_ASSERT_NULL(proto(request)->query_, "query chain released");
    TEST_ASSERT_EQUAL_SIZE(0, proto(request)->uri_length, "uri_length reset");
    TEST_ASSERT_EQUAL_SIZE(0, proto(request)->path_length, "path_length reset");
    TEST_ASSERT(request->protocol->payload.fd >= 0, "payload owned by request reset, not protocol reset");

    parser_teardown(&parser);
    websocketsrequest_free(request);
}

// ============================================================================
// websocketsrequest_get_resource
// ============================================================================

static void ws_handler_get(void* arg) { (void)arg; }
static void ws_handler_post(void* arg) { (void)arg; }

typedef struct {
    connection_t connection;
    connection_server_ctx_t ctx;
    server_t server;
    int sentinel;
} dispatch_harness_t;

static int dispatch_setup(dispatch_harness_t* harness, route_t* routes) {
    memset(&harness->connection, 0, sizeof harness->connection);
    memset(&harness->ctx, 0, sizeof harness->ctx);
    memset(&harness->server, 0, sizeof harness->server);

    harness->server.websockets.route = routes;
    harness->ctx.server = &harness->server;
    harness->ctx.queue = cqueue_create();
    if (harness->ctx.queue == NULL) return 0;

    harness->connection.ctx = &harness->ctx;

    /* A non-empty per-connection queue keeps websockets_deferred_handler off
     * the global worker queue, which the unit runner does not initialize. */
    cqueue_append(harness->ctx.queue, &harness->sentinel);

    return 1;
}

/* Pop past the sentinel to the queue item created by a dispatch. */
static connection_queue_item_t* dispatch_take_item(dispatch_harness_t* harness) {
    if (cqueue_pop(harness->ctx.queue) != &harness->sentinel) return NULL;

    return cqueue_pop(harness->ctx.queue);
}

static void dispatch_teardown(dispatch_harness_t* harness) {
    cqueue_free(harness->ctx.queue);
}

TEST(test_wsres_get_resource_guards) {
    TEST_SUITE("websocketsprotocolresource: get_resource");
    TEST_CASE("requests without method or path are rejected");

    dispatch_harness_t harness;
    TEST_REQUIRE(dispatch_setup(&harness, NULL), "harness setup");

    websocketsrequest_t* request = make_resource_request(&harness.connection);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    TEST_ASSERT_EQUAL(0, websocketsrequest_get_resource(&harness.connection, request), "no method yields 0");

    proto(request)->method = ROUTE_GET;
    TEST_ASSERT_EQUAL(0, websocketsrequest_get_resource(&harness.connection, request), "no path yields 0");

    websocketsrequest_free(request);
    dispatch_teardown(&harness);
}

TEST(test_wsres_get_resource_primitive_route) {
    TEST_SUITE("websocketsprotocolresource: get_resource");
    TEST_CASE("primitive route dispatches to its method handler");

    route_t* route = route_create("/health");
    TEST_REQUIRE_NOT_NULL(route, "route creation");
    TEST_REQUIRE(route_set_websockets_handler(route, "GET", ws_handler_get, NULL), "handler binding");

    dispatch_harness_t harness;
    TEST_REQUIRE(dispatch_setup(&harness, route), "harness setup");

    websocketsrequest_t* request = make_resource_request(&harness.connection);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);
    TEST_REQUIRE(feed_frame(&parser, "GET /health", 1) == 1, "frame parsed");

    TEST_ASSERT_EQUAL(1, websocketsrequest_get_resource(&harness.connection, request), "request dispatched");

    connection_queue_item_t* item = dispatch_take_item(&harness);
    TEST_REQUIRE_NOT_NULL(item, "queue item created");
    TEST_ASSERT(item->handle == ws_handler_get, "route handler attached to the item");
    TEST_ASSERT(item->run == websockets_queue_request_handler, "queue runner attached");
    TEST_ASSERT(item->connection == &harness.connection, "connection attached");

    item->free(item); /* releases the request too */
    parser_teardown(&parser);
    dispatch_teardown(&harness);
    routes_free(route);
}

TEST(test_wsres_get_resource_params_attached_regression) {
    TEST_SUITE("websocketsprotocolresource: get_resource");
    /* REGRESSION: the head of the route-param chain was never stored into
     * protocol->query_, so without a query string in the location the params
     * were invisible to get_query and leaked on reset. */
    TEST_CASE("route params are visible through get_query without a query string");

    route_t* route = route_create("/users/{id|[0-9]+}");
    TEST_REQUIRE_NOT_NULL(route, "route creation");
    TEST_REQUIRE(route_set_websockets_handler(route, "GET", ws_handler_get, NULL), "handler binding");

    dispatch_harness_t harness;
    TEST_REQUIRE(dispatch_setup(&harness, route), "harness setup");

    websocketsrequest_t* request = make_resource_request(&harness.connection);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);
    TEST_REQUIRE(feed_frame(&parser, "GET /users/123", 1) == 1, "frame parsed");

    TEST_ASSERT_EQUAL(1, websocketsrequest_get_resource(&harness.connection, request), "request dispatched");

    int ok = 0;
    TEST_ASSERT_STR_EQUAL("123", proto(request)->get_query(proto(request), "id", &ok), "path param visible");
    TEST_ASSERT_EQUAL(1, ok, "param lookup reports ok=1");

    connection_queue_item_t* item = dispatch_take_item(&harness);
    TEST_REQUIRE_NOT_NULL(item, "queue item created");
    item->free(item);

    parser_teardown(&parser);
    dispatch_teardown(&harness);
    routes_free(route);
}

TEST(test_wsres_get_resource_params_appended_to_query) {
    TEST_SUITE("websocketsprotocolresource: get_resource");
    TEST_CASE("route params append after existing query parameters");

    route_t* route = route_create("/users/{id|[0-9]+}");
    TEST_REQUIRE_NOT_NULL(route, "route creation");
    TEST_REQUIRE(route_set_websockets_handler(route, "GET", ws_handler_get, NULL), "handler binding");

    dispatch_harness_t harness;
    TEST_REQUIRE(dispatch_setup(&harness, route), "harness setup");

    websocketsrequest_t* request = make_resource_request(&harness.connection);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);
    TEST_REQUIRE(feed_frame(&parser, "GET /users/123?sort=name", 1) == 1, "frame parsed");

    TEST_ASSERT_EQUAL(1, websocketsrequest_get_resource(&harness.connection, request), "request dispatched");

    int ok = 0;
    TEST_ASSERT_STR_EQUAL("name", proto(request)->get_query(proto(request), "sort", &ok), "query param intact");
    TEST_ASSERT_STR_EQUAL("123", proto(request)->get_query(proto(request), "id", &ok), "path param appended");

    connection_queue_item_t* item = dispatch_take_item(&harness);
    TEST_REQUIRE_NOT_NULL(item, "queue item created");
    item->free(item);

    parser_teardown(&parser);
    dispatch_teardown(&harness);
    routes_free(route);
}

TEST(test_wsres_get_resource_handlerless_route_regression) {
    TEST_SUITE("websocketsprotocolresource: get_resource");
    /* REGRESSION: a matching route without a handler for the method appended
     * its params before being skipped, so the route dispatched after it saw
     * the same param twice. */
    TEST_CASE("a handler-less route adds no params for the next route");

    route_t* post_only = route_create("/users/{id|[0-9]+}");
    route_t* get_route = route_create("/users/{id|[0-9]+}");
    TEST_REQUIRE(post_only != NULL && get_route != NULL, "route creation");
    TEST_REQUIRE(route_set_websockets_handler(post_only, "POST", ws_handler_post, NULL), "POST handler binding");
    TEST_REQUIRE(route_set_websockets_handler(get_route, "GET", ws_handler_get, NULL), "GET handler binding");
    post_only->next = get_route;

    dispatch_harness_t harness;
    TEST_REQUIRE(dispatch_setup(&harness, post_only), "harness setup");

    websocketsrequest_t* request = make_resource_request(&harness.connection);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);
    TEST_REQUIRE(feed_frame(&parser, "GET /users/7?x=1", 1) == 1, "frame parsed");

    TEST_ASSERT_EQUAL(1, websocketsrequest_get_resource(&harness.connection, request), "request dispatched");
    TEST_ASSERT_EQUAL(1, query_key_count(proto(request)->query_, "id"), "id present exactly once");

    connection_queue_item_t* item = dispatch_take_item(&harness);
    TEST_REQUIRE_NOT_NULL(item, "queue item created");
    TEST_ASSERT(item->handle == ws_handler_get, "dispatched to the GET route");
    item->free(item);

    parser_teardown(&parser);
    dispatch_teardown(&harness);
    routes_free(post_only);
}

TEST(test_wsres_get_resource_no_handler_for_method) {
    TEST_SUITE("websocketsprotocolresource: get_resource");
    TEST_CASE("matching route without a handler for the method yields 0");

    route_t* route = route_create("/health");
    TEST_REQUIRE_NOT_NULL(route, "route creation");
    TEST_REQUIRE(route_set_websockets_handler(route, "POST", ws_handler_post, NULL), "handler binding");

    dispatch_harness_t harness;
    TEST_REQUIRE(dispatch_setup(&harness, route), "harness setup");

    websocketsrequest_t* request = make_resource_request(&harness.connection);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request);
    TEST_REQUIRE(feed_frame(&parser, "GET /health", 1) == 1, "frame parsed");

    TEST_ASSERT_EQUAL(0, websocketsrequest_get_resource(&harness.connection, request), "no dispatch");
    TEST_ASSERT(cqueue_pop(harness.ctx.queue) == &harness.sentinel, "nothing queued past the sentinel");
    TEST_ASSERT_NULL(cqueue_pop(harness.ctx.queue), "queue is empty");

    websocketsrequest_free(request);
    parser_teardown(&parser);
    dispatch_teardown(&harness);
    routes_free(route);
}

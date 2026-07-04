/*
 * Unit tests for protocols/websocket/websocketsprotocoldefault.c
 *
 * Covers the default protocol factory, the payload_parse vtable entry
 * (XOR unmasking, tmpfile accumulation, body-size limit) and the
 * set_websockets_default protocol switch. Several cases are regression
 * guards for bugs fixed alongside these tests (each is marked REGRESSION
 * below):
 *
 *   - payload_parse accepted any positive write() result, so a short write
 *     (ENOSPC, rlimit, signal after a partial transfer) silently truncated
 *     the message handed to the handler instead of failing the frame.
 *   - payload_parse treated a zero-length chunk as an error: write(fd, p, 0)
 *     returns 0, which the `r <= 0` check misread as a failed write and
 *     killed the connection.
 *   - payload_parse did not check the SEEK_END lseek result: -1 folded into
 *     the unsigned body-size comparison as length - 1 and bypassed the limit.
 *   - set_websockets_default installed the websocket guard read/write and
 *     freed the old parser before checking websocketsparser_create; its only
 *     caller ignores the result, so an allocation failure left a connection
 *     whose next read dereferenced ctx->parser == NULL.
 *
 * env()/appconfig() resolve to the weak test doubles defined in
 * test_httprequestparser.c (client_max_body_size, tmp are writable per test).
 */

#include "framework.h"
#include "appconfig.h"
#include "connection_s.h"
#include "websocketsparser.h"
#include "websocketsprotocoldefault.h"
#include "websocketsserverhandlers.h"
#include "websocketsswitch.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

/* Internal functions of websocketsprotocoldefault.c (external linkage). */
int websocketsrequest_get_default(connection_t* connection, websocketsrequest_t* request);
void websockets_protocol_default_reset(void*);
void websockets_protocol_default_free(void*);
int websockets_protocol_default_payload_parse(websocketsparser_t* parser, char* data, size_t size, int unmasking);

// ============================================================================
// Helpers
// ============================================================================

/* Request wired to a real default protocol, no connection. */
static websocketsrequest_t* make_default_request(void) {
    websockets_protocol_t* protocol = websockets_protocol_default_create();
    if (protocol == NULL) return NULL;

    websocketsrequest_t* request = websocketsrequest_create(NULL, protocol);
    if (request == NULL) protocol->free(protocol);

    return request;
}

/* payload_parse reads only request, frame.mask and payload_index from the
 * parser, so a zeroed struct with those fields set is a faithful harness. */
static void parser_setup(websocketsparser_t* parser, websocketsrequest_t* request, const unsigned char mask[4]) {
    memset(parser, 0, sizeof * parser);
    parser->request = request;

    if (mask != NULL)
        memcpy(parser->frame.mask, mask, 4);
}

/* Read the tmpfile back without moving its offset. */
static ssize_t payload_file_read(websockets_protocol_t* protocol, char* out, size_t out_size) {
    if (protocol->payload.fd < 0) return -1;

    return pread(protocol->payload.fd, out, out_size, 0);
}

static void mask_buffer(char* data, size_t length, const unsigned char mask[4], size_t key_offset) {
    for (size_t i = 0; i < length; i++)
        data[i] ^= mask[(key_offset + i) % 4];
}

// ============================================================================
// websockets_protocol_default_create
// ============================================================================

TEST(test_wsdef_create_initializes_protocol) {
    TEST_SUITE("websocketsprotocoldefault: create");
    TEST_CASE("vtable and payload are fully initialized");

    websockets_protocol_t* protocol = websockets_protocol_default_create();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    TEST_ASSERT(protocol->payload_parse == websockets_protocol_default_payload_parse, "payload_parse is wired");
    TEST_ASSERT(protocol->get_resource == websocketsrequest_get_default, "get_resource is wired");
    TEST_ASSERT(protocol->reset == websockets_protocol_default_reset, "reset is wired");
    TEST_ASSERT(protocol->free == websockets_protocol_default_free, "free is wired");

    websockets_protocol_default_t* default_protocol = (websockets_protocol_default_t*)protocol;
    TEST_ASSERT_NOT_NULL(default_protocol->get_payload, "get_payload is wired");
    TEST_ASSERT_NOT_NULL(default_protocol->get_payload_file, "get_payload_file is wired");
    TEST_ASSERT_NOT_NULL(default_protocol->get_payload_json, "get_payload_json is wired");

    TEST_ASSERT_EQUAL(-1, protocol->payload.fd, "payload fd starts at the -1 sentinel");
    TEST_ASSERT_NULL(protocol->payload.path, "payload path starts NULL");

    protocol->free(protocol);
}

// ============================================================================
// websockets_protocol_default_payload_parse
// ============================================================================

TEST(test_wsdef_payload_parse_plain_chunk) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    TEST_CASE("unmasked chunk lands in the tmpfile, offset rewound");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);

    TEST_ASSERT_EQUAL(1, websockets_protocol_default_payload_parse(&parser, "hello", 5, 0), "parse succeeds");
    TEST_ASSERT(request->protocol->payload.fd >= 0, "tmpfile created");
    TEST_ASSERT_EQUAL(0, lseek(request->protocol->payload.fd, 0, SEEK_CUR), "offset rewound to start");
    TEST_ASSERT_EQUAL(0, parser.payload_index, "payload_index untouched without unmasking");

    char content[16] = {0};
    TEST_ASSERT_EQUAL(5, (int)payload_file_read(request->protocol, content, sizeof(content)), "payload size");
    TEST_ASSERT_STR_EQUAL("hello", content, "payload content");

    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_parse_unmasks_in_place) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    TEST_CASE("masked chunk is XOR-decoded into the buffer and the file");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    const unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
    websocketsparser_t parser;
    parser_setup(&parser, request, mask);

    char data[] = "Hello, WebSocket!";
    const size_t length = sizeof(data) - 1;
    mask_buffer(data, length, mask, 0);

    TEST_ASSERT_EQUAL(1, websockets_protocol_default_payload_parse(&parser, data, length, 1), "parse succeeds");
    TEST_ASSERT_EQUAL(0, memcmp(data, "Hello, WebSocket!", length), "buffer unmasked in place");
    TEST_ASSERT_EQUAL((int)length, (int)parser.payload_index, "payload_index advanced by chunk size");

    char content[32] = {0};
    TEST_ASSERT_EQUAL((int)length, (int)payload_file_read(request->protocol, content, sizeof(content)), "payload size");
    TEST_ASSERT_STR_EQUAL("Hello, WebSocket!", content, "file holds the unmasked payload");

    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_parse_mask_continues_across_chunks) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    TEST_CASE("mask keystream continues over a chunk split not aligned to 4");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    const unsigned char mask[4] = {0xA5, 0x5A, 0xF0, 0x0F};
    websocketsparser_t parser;
    parser_setup(&parser, request, mask);

    /* One frame delivered in two reads split mid-mask-key (3 is not a
     * multiple of 4): the second chunk must resume at key offset 3. */
    char chunk1[] = "abc";
    char chunk2[] = "defgh";
    mask_buffer(chunk1, 3, mask, 0);
    mask_buffer(chunk2, 5, mask, 3);

    TEST_ASSERT_EQUAL(1, websockets_protocol_default_payload_parse(&parser, chunk1, 3, 1), "first chunk parsed");
    TEST_ASSERT_EQUAL(1, websockets_protocol_default_payload_parse(&parser, chunk2, 5, 1), "second chunk parsed");
    TEST_ASSERT_EQUAL(8, (int)parser.payload_index, "payload_index spans both chunks");

    char content[16] = {0};
    TEST_ASSERT_EQUAL(8, (int)payload_file_read(request->protocol, content, sizeof(content)), "payload size");
    TEST_ASSERT_STR_EQUAL("abcdefgh", content, "chunks decoded with a continuous keystream");

    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_parse_accumulates_chunks) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    TEST_CASE("chunks append to the same tmpfile (fragmented message)");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);

    TEST_ASSERT_EQUAL(1, websockets_protocol_default_payload_parse(&parser, "frag1-", 6, 0), "first fragment");
    TEST_ASSERT_EQUAL(1, websockets_protocol_default_payload_parse(&parser, "frag2", 5, 0), "second fragment");

    char content[16] = {0};
    TEST_ASSERT_EQUAL(11, (int)payload_file_read(request->protocol, content, sizeof(content)), "payload size");
    TEST_ASSERT_STR_EQUAL("frag1-frag2", content, "fragments concatenated in order");

    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_parse_zero_length_regression) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    /* REGRESSION: write(fd, p, 0) returns 0 and the `r <= 0` error check
     * reported a healthy empty chunk as a failed write, killing the
     * connection. */
    TEST_CASE("zero-length chunk succeeds and creates no tmpfile");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);

    TEST_ASSERT_EQUAL(1, websockets_protocol_default_payload_parse(&parser, "", 0, 0), "empty chunk is not an error");
    TEST_ASSERT_EQUAL(-1, request->protocol->payload.fd, "no tmpfile is created for an empty chunk");

    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_parse_limit_first_chunk) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    TEST_CASE("chunk over client_max_body_size is rejected before writing");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);

    const unsigned int saved_limit = env()->main.client_max_body_size;
    env()->main.client_max_body_size = 4;

    TEST_ASSERT_EQUAL(0, websockets_protocol_default_payload_parse(&parser, "12345", 5, 0), "oversized chunk rejected");

    char content[8];
    TEST_ASSERT_EQUAL(0, (int)payload_file_read(request->protocol, content, sizeof(content)), "nothing was written");

    env()->main.client_max_body_size = saved_limit;
    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_parse_limit_is_cumulative) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    TEST_CASE("limit applies to the accumulated message, not per chunk");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);

    const unsigned int saved_limit = env()->main.client_max_body_size;
    env()->main.client_max_body_size = 8;

    TEST_ASSERT_EQUAL(1, websockets_protocol_default_payload_parse(&parser, "123456", 6, 0), "first chunk fits");
    TEST_ASSERT_EQUAL(0, websockets_protocol_default_payload_parse(&parser, "789", 3, 0), "second chunk crosses the limit");

    char content[16] = {0};
    TEST_ASSERT_EQUAL(6, (int)payload_file_read(request->protocol, content, sizeof(content)), "file keeps only the first chunk");
    TEST_ASSERT_STR_EQUAL("123456", content, "first chunk intact");

    env()->main.client_max_body_size = saved_limit;
    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_parse_tmpdir_failure) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    TEST_CASE("unusable tmp directory fails the chunk cleanly");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);

    char* saved_tmp = env()->main.tmp;
    env()->main.tmp = "/nonexistent_dir_cwfr_test";

    TEST_ASSERT_EQUAL(0, websockets_protocol_default_payload_parse(&parser, "data", 4, 0), "chunk fails without tmpfile");
    TEST_ASSERT_EQUAL(-1, request->protocol->payload.fd, "fd stays at the -1 sentinel");

    env()->main.tmp = saved_tmp;
    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_parse_short_write_regression) {
    TEST_SUITE("websocketsprotocoldefault: payload_parse");
    /* REGRESSION: `int r = write(...); if (r <= 0)` accepted a short write as
     * success, so a payload cut by ENOSPC/rlimit reached the handler silently
     * truncated. RLIMIT_FSIZE forces write() to stop at 4 bytes here (with
     * SIGXFSZ ignored the syscall returns the partial count, then EFBIG). */
    TEST_CASE("a partial write fails the chunk instead of truncating it");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);

    struct rlimit saved_limit;
    TEST_REQUIRE(getrlimit(RLIMIT_FSIZE, &saved_limit) == 0, "read RLIMIT_FSIZE");

    struct sigaction ignore_action = {0};
    struct sigaction saved_action;
    ignore_action.sa_handler = SIG_IGN;
    TEST_REQUIRE(sigaction(SIGXFSZ, &ignore_action, &saved_action) == 0, "ignore SIGXFSZ");

    const struct rlimit small_limit = {.rlim_cur = 4, .rlim_max = saved_limit.rlim_max};
    TEST_REQUIRE(setrlimit(RLIMIT_FSIZE, &small_limit) == 0, "shrink RLIMIT_FSIZE");

    const int result = websockets_protocol_default_payload_parse(&parser, "123456", 6, 0);

    setrlimit(RLIMIT_FSIZE, &saved_limit);
    sigaction(SIGXFSZ, &saved_action, NULL);

    TEST_ASSERT_EQUAL(0, result, "truncated chunk must be reported as failure");

    websocketsrequest_free(request);
}

TEST(test_wsdef_payload_accessors_roundtrip) {
    TEST_SUITE("websocketsprotocoldefault: payload accessors");
    TEST_CASE("get_payload/get_payload_json read back what payload_parse wrote");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websockets_protocol_default_t* protocol = (websockets_protocol_default_t*)request->protocol;
    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);

    const char* json = "{\"key\":\"value\"}";
    TEST_REQUIRE(websockets_protocol_default_payload_parse(&parser, (char*)json, strlen(json), 0) == 1, "payload written");

    char* payload = protocol->get_payload(protocol);
    TEST_ASSERT_STR_EQUAL(json, payload, "get_payload returns the message");
    free(payload);

    file_content_t file_content = protocol->get_payload_file(protocol);
    TEST_ASSERT_EQUAL(1, file_content.ok, "get_payload_file reports a valid payload");
    TEST_ASSERT_EQUAL_SIZE(strlen(json), file_content.size, "file size matches the message");

    json_doc_t* document = protocol->get_payload_json(protocol);
    TEST_REQUIRE_NOT_NULL(document, "get_payload_json parses the message");
    TEST_ASSERT_EQUAL(1, json_is_object(json_root(document)), "root is an object");
    json_free(document);

    websocketsrequest_free(request);
}

// ============================================================================
// websockets_protocol_default_reset / free
// ============================================================================

TEST(test_wsdef_reset_leaves_payload_to_request) {
    TEST_SUITE("websocketsprotocoldefault: reset");
    TEST_CASE("protocol reset is a no-op; request reset owns the tmpfile");

    websocketsrequest_t* request = make_default_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    websocketsparser_t parser;
    parser_setup(&parser, request, NULL);
    TEST_REQUIRE(websockets_protocol_default_payload_parse(&parser, "data", 4, 0) == 1, "payload written");

    /* The default protocol has no per-message state of its own, so its reset
     * must not touch the payload - websocketsrequest_reset releases it. */
    request->protocol->reset(request->protocol);
    TEST_ASSERT(request->protocol->payload.fd >= 0, "payload survives protocol reset");

    char* path = strdup(request->protocol->payload.path);
    TEST_REQUIRE_NOT_NULL(path, "path copy");

    request->base.reset(request);
    TEST_ASSERT_EQUAL(-1, request->protocol->payload.fd, "request reset releases the payload");
    TEST_ASSERT(access(path, F_OK) != 0, "tmpfile removed from disk");

    free(path);
    websocketsrequest_free(request);
}

// ============================================================================
// set_websockets_default
// ============================================================================

/* Fake previous parser to observe the ownership handover. */
static int g_old_parser_free_calls;

static void old_parser_free(void* arg) {
    (void)arg;
    g_old_parser_free_calls++;
}

static void connection_setup(connection_t* connection, connection_server_ctx_t* ctx, char* buffer, size_t buffer_size) {
    memset(connection, 0, sizeof * connection);
    memset(ctx, 0, sizeof * ctx);

    connection->buffer = buffer;
    connection->buffer_size = buffer_size;
    connection->ctx = ctx;

    g_old_parser_free_calls = 0;
}

static void connection_teardown(connection_server_ctx_t* ctx) {
    if (ctx->parser == NULL) return;

    requestparser_t* parser = ctx->parser;
    parser->free(parser);
}

TEST(test_wsdef_set_protocol_success) {
    TEST_SUITE("websocketsprotocoldefault: set_websockets_default");
    TEST_CASE("switch installs guards, parser and protocol factory");

    connection_t connection;
    connection_server_ctx_t ctx;
    char buffer[64];
    connection_setup(&connection, &ctx, buffer, sizeof(buffer));

    TEST_ASSERT_EQUAL(1, set_websockets_default(&connection, NULL), "switch succeeds");
    TEST_ASSERT(connection.read == websockets_guard_read, "guard read installed");
    TEST_ASSERT(connection.write == websockets_guard_write, "guard write installed");
    TEST_REQUIRE_NOT_NULL(ctx.parser, "parser created");

    websocketsparser_t* parser = ctx.parser;
    TEST_ASSERT(parser->protocol_create == websockets_protocol_default_create, "default protocol factory wired");
    TEST_ASSERT(parser->connection == &connection, "parser bound to the connection");
    TEST_ASSERT(parser->buffer == connection.buffer, "parser reads the connection buffer");
    TEST_ASSERT_EQUAL(0, parser->ws_deflate_enabled, "deflate stays off without handshake data");

    connection_teardown(&ctx);
}

TEST(test_wsdef_set_protocol_frees_previous_parser) {
    TEST_SUITE("websocketsprotocoldefault: set_websockets_default");
    TEST_CASE("previous parser is released exactly once and replaced");

    connection_t connection;
    connection_server_ctx_t ctx;
    char buffer[64];
    connection_setup(&connection, &ctx, buffer, sizeof(buffer));

    requestparser_t old_parser = {.free = old_parser_free};
    ctx.parser = &old_parser;

    TEST_ASSERT_EQUAL(1, set_websockets_default(&connection, NULL), "switch succeeds");
    TEST_ASSERT_EQUAL(1, g_old_parser_free_calls, "old parser freed exactly once");
    TEST_ASSERT(ctx.parser != (void*)&old_parser, "parser pointer replaced");
    TEST_ASSERT_NOT_NULL(ctx.parser, "new parser installed");

    connection_teardown(&ctx);
}

TEST(test_wsdef_set_protocol_deflate_negotiated) {
    TEST_SUITE("websocketsprotocoldefault: set_websockets_default");
    TEST_CASE("negotiated permessage-deflate is initialized on the parser");

    connection_t connection;
    connection_server_ctx_t ctx;
    char buffer[64];
    connection_setup(&connection, &ctx, buffer, sizeof(buffer));

    ws_handshake_data_t handshake_data = {
        .deflate_config = {
            .server_max_window_bits = 15,
            .client_max_window_bits = 15,
            .server_no_context_takeover = 0,
            .client_no_context_takeover = 0,
        },
        .deflate_enabled = 1,
    };

    TEST_ASSERT_EQUAL(1, set_websockets_default(&connection, &handshake_data), "switch succeeds");
    TEST_REQUIRE_NOT_NULL(ctx.parser, "parser created");

    websocketsparser_t* parser = ctx.parser;
    TEST_ASSERT_EQUAL(1, parser->ws_deflate_enabled, "deflate enabled from handshake");
    TEST_ASSERT_EQUAL(15, parser->ws_deflate.config.client_max_window_bits, "negotiated config copied");

    connection_teardown(&ctx);
}

TEST(test_wsdef_set_protocol_deflate_not_negotiated) {
    TEST_SUITE("websocketsprotocoldefault: set_websockets_default");
    TEST_CASE("handshake without deflate leaves the extension off");

    connection_t connection;
    connection_server_ctx_t ctx;
    char buffer[64];
    connection_setup(&connection, &ctx, buffer, sizeof(buffer));

    ws_handshake_data_t handshake_data = {.deflate_enabled = 0};

    TEST_ASSERT_EQUAL(1, set_websockets_default(&connection, &handshake_data), "switch succeeds");
    TEST_REQUIRE_NOT_NULL(ctx.parser, "parser created");

    websocketsparser_t* parser = ctx.parser;
    TEST_ASSERT_EQUAL(0, parser->ws_deflate_enabled, "deflate stays off");

    connection_teardown(&ctx);
}

/*
 * Unit tests for protocols/websocket/websocketsrequest.c
 *
 * Covers request lifecycle (create/reset/free), payload tmpfile management
 * and the payload accessors (string/file/json) over a stub protocol.
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - websocketsrequest_payload did not check the SEEK_END lseek result: on a
 *     stale/invalid fd it malloc'ed payload_size+1 = 0 bytes and wrote the
 *     terminator at buffer[-1] (heap underflow). A short read also returned a
 *     buffer with an uninitialized tail instead of failing.
 *   - websocketsrequest_payload_file did not validate payload.fd: with no
 *     payload it lseek'ed fd 0 (stdin) and could hand out ok=1 with fd 0, so
 *     a handler would serve stdin as the message payload.
 *   - websocketsrequest_free ran the payload cleanup only through a reset
 *     gated on can_reset: freeing a request with can_reset == 0 leaked the
 *     tmpfile fd, its heap path and the on-disk inode (protocol->free does
 *     not touch payload).
 *   - websockets_create_tmpfile treated any non-zero fd (including negative)
 *     as "already created" and reported success without a file.
 *
 * The stub protocol only counts reset/free calls; payload bytes are written
 * straight into the tmpfile the way payload_parse implementations do.
 */

#include "framework.h"
#include "websocketsrequest.h"
#include "json.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// ============================================================================
// Stub protocol
// ============================================================================

static int g_protocol_reset_calls;
static int g_protocol_free_calls;

static void stub_protocol_reset(void* arg) {
    (void)arg;
    g_protocol_reset_calls++;
}

static void stub_protocol_free(void* arg) {
    g_protocol_free_calls++;
    free(arg);
}

static websockets_protocol_t* make_protocol(void) {
    websockets_protocol_t* protocol = malloc(sizeof * protocol);
    if (protocol == NULL) return NULL;

    websockets_protocol_init_payload(protocol);
    protocol->payload_parse = NULL;
    protocol->get_resource = NULL;
    protocol->reset = stub_protocol_reset;
    protocol->free = stub_protocol_free;

    g_protocol_reset_calls = 0;
    g_protocol_free_calls = 0;

    return protocol;
}

static websocketsrequest_t* make_request(void) {
    websockets_protocol_t* protocol = make_protocol();
    if (protocol == NULL) return NULL;

    websocketsrequest_t* request = websocketsrequest_create(NULL, protocol);
    if (request == NULL) free(protocol);

    return request;
}

/* Write payload bytes into the tmpfile the way payload_parse does. */
static int payload_write(websockets_protocol_t* protocol, const void* data, size_t size) {
    if (!websockets_create_tmpfile(protocol, "/tmp")) return 0;
    if (size == 0) return 1;

    return write(protocol->payload.fd, data, size) == (ssize_t)size;
}

/* Release a protocol used without a request. */
static void protocol_cleanup(websockets_protocol_t* protocol) {
    if (protocol->payload.fd >= 0) {
        close(protocol->payload.fd);
        unlink(protocol->payload.path);
    }

    free(protocol->payload.path);
    free(protocol);
}

// ============================================================================
// websockets_protocol_init_payload
// ============================================================================

TEST(test_ws_init_payload_clears_fields) {
    TEST_SUITE("websocketsrequest: init_payload");
    TEST_CASE("fd and path are reset");

    websockets_protocol_t protocol;
    protocol.payload.fd = 42;
    protocol.payload.path = (char*)0x1;

    websockets_protocol_init_payload(&protocol);

    TEST_ASSERT_EQUAL(-1, protocol.payload.fd, "fd must be the -1 sentinel after init");
    TEST_ASSERT_NULL(protocol.payload.path, "path must be NULL after init");
}

// ============================================================================
// websocketsrequest_create
// ============================================================================

TEST(test_ws_create_null_protocol) {
    TEST_SUITE("websocketsrequest: create");
    TEST_CASE("NULL protocol is rejected");

    TEST_ASSERT_NULL(websocketsrequest_create(NULL, NULL), "create(NULL protocol) must return NULL");
}

TEST(test_ws_create_initializes_fields) {
    TEST_SUITE("websocketsrequest: create");
    TEST_CASE("all fields are initialized");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    websocketsrequest_t* request = websocketsrequest_create(NULL, protocol);
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    TEST_ASSERT_EQUAL(WEBSOCKETS_NONE, request->type, "type starts as NONE");
    TEST_ASSERT_EQUAL(1, request->can_reset, "can_reset starts as 1");
    TEST_ASSERT_EQUAL(0, request->fragmented, "fragmented starts as 0");
    TEST_ASSERT_EQUAL(0, request->compressed, "compressed starts as 0");
    TEST_ASSERT(request->protocol == protocol, "protocol is stored");
    TEST_ASSERT_NULL(request->connection, "connection is stored as passed");
    TEST_ASSERT_NOT_NULL(request->base.reset, "base.reset is set");
    TEST_ASSERT(request->base.free == websocketsrequest_free, "base.free is set");

    websocketsrequest_free(request);
    TEST_ASSERT_EQUAL(1, g_protocol_free_calls, "protocol freed exactly once");
}

// ============================================================================
// websockets_create_tmpfile
// ============================================================================

TEST(test_ws_create_tmpfile_creates_and_reuses) {
    TEST_SUITE("websocketsrequest: create_tmpfile");
    TEST_CASE("tmpfile is created once and reused");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    TEST_ASSERT_EQUAL(1, websockets_create_tmpfile(protocol, "/tmp"), "first call succeeds");
    TEST_ASSERT(protocol->payload.fd >= 0, "fd is a real descriptor");
    TEST_REQUIRE_NOT_NULL(protocol->payload.path, "path is set");
    TEST_ASSERT_EQUAL(0, access(protocol->payload.path, F_OK), "file exists on disk");

    const int fd = protocol->payload.fd;
    char* path = protocol->payload.path;

    TEST_ASSERT_EQUAL(1, websockets_create_tmpfile(protocol, "/tmp"), "second call succeeds");
    TEST_ASSERT_EQUAL(fd, protocol->payload.fd, "fd is unchanged on reuse");
    TEST_ASSERT(protocol->payload.path == path, "path is unchanged on reuse");

    protocol_cleanup(protocol);
}

TEST(test_ws_create_tmpfile_bad_dir) {
    TEST_SUITE("websocketsrequest: create_tmpfile");
    TEST_CASE("nonexistent directory fails cleanly");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    TEST_ASSERT_EQUAL(0, websockets_create_tmpfile(protocol, "/nonexistent_dir_cwfr_test"), "creation fails");
    TEST_ASSERT_EQUAL(-1, protocol->payload.fd, "fd stays at the -1 sentinel on failure");
    TEST_ASSERT_NULL(protocol->payload.path, "path is released on failure");

    protocol_cleanup(protocol);
}

TEST(test_ws_create_tmpfile_retry_after_failure_regression) {
    TEST_SUITE("websocketsrequest: create_tmpfile");
    /* REGRESSION: `if (fd)` treated the -1 left by a failed attempt as
     * "already created" and reported success without any file, silently
     * dropping every later payload of the connection. */
    TEST_CASE("a failed attempt does not block a later retry");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    TEST_ASSERT_EQUAL(0, websockets_create_tmpfile(protocol, "/nonexistent_dir_cwfr_test"), "first attempt fails");
    TEST_ASSERT_EQUAL(1, websockets_create_tmpfile(protocol, "/tmp"), "retry succeeds");
    TEST_ASSERT(protocol->payload.fd >= 0, "a real descriptor replaces the sentinel");
    TEST_ASSERT_NOT_NULL(protocol->payload.path, "path is set");

    protocol_cleanup(protocol);
}

// ============================================================================
// websocketsrequest_payload
// ============================================================================

TEST(test_ws_payload_without_file) {
    TEST_SUITE("websocketsrequest: payload");
    TEST_CASE("no payload file yields NULL");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    TEST_ASSERT_NULL(websocketsrequest_payload(protocol), "payload without tmpfile is NULL");

    protocol_cleanup(protocol);
}

TEST(test_ws_payload_returns_content) {
    TEST_SUITE("websocketsrequest: payload");
    TEST_CASE("payload bytes come back null-terminated, offset rewound");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");
    TEST_REQUIRE(payload_write(protocol, "hello world", 11), "payload write");

    char* payload = websocketsrequest_payload(protocol);
    TEST_ASSERT_STR_EQUAL("hello world", payload, "payload content");
    TEST_ASSERT_EQUAL(0, lseek(protocol->payload.fd, 0, SEEK_CUR), "offset rewound to start");
    free(payload);

    /* The accessor must be repeatable: it rewinds before and after reading. */
    payload = websocketsrequest_payload(protocol);
    TEST_ASSERT_STR_EQUAL("hello world", payload, "second read returns same content");
    free(payload);

    protocol_cleanup(protocol);
}

TEST(test_ws_payload_empty_file) {
    TEST_SUITE("websocketsrequest: payload");
    TEST_CASE("empty payload yields empty string");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");
    TEST_REQUIRE(payload_write(protocol, NULL, 0), "tmpfile creation");

    char* payload = websocketsrequest_payload(protocol);
    TEST_ASSERT_STR_EQUAL("", payload, "empty payload is an empty string");
    free(payload);

    protocol_cleanup(protocol);
}

TEST(test_ws_payload_embedded_nul) {
    TEST_SUITE("websocketsrequest: payload");
    TEST_CASE("binary payload with NUL bytes is copied fully");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");
    TEST_REQUIRE(payload_write(protocol, "a\0b", 3), "payload write");

    char* payload = websocketsrequest_payload(protocol);
    TEST_REQUIRE_NOT_NULL(payload, "payload read");
    TEST_ASSERT_EQUAL(0, memcmp(payload, "a\0b\0", 4), "all bytes present, terminator appended");
    free(payload);

    protocol_cleanup(protocol);
}

TEST(test_ws_payload_stale_fd_regression) {
    TEST_SUITE("websocketsrequest: payload");
    /* REGRESSION: an fd whose lseek fails made payload_size -1, so the
     * terminator was written at buffer[-1] (heap underflow under ASan). */
    TEST_CASE("stale descriptor yields NULL instead of heap underflow");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    int fd = open("/dev/null", O_RDONLY);
    TEST_REQUIRE(fd >= 0, "open /dev/null");
    close(fd);

    protocol->payload.fd = fd; /* valid number, closed descriptor */

    TEST_ASSERT_NULL(websocketsrequest_payload(protocol), "stale fd must fail cleanly");

    protocol->payload.fd = -1;
    protocol_cleanup(protocol);
}

// ============================================================================
// websocketsrequest_payload_file
// ============================================================================

TEST(test_ws_payload_file_without_payload_regression) {
    TEST_SUITE("websocketsrequest: payload_file");
    /* REGRESSION: fd 0 (no payload) was lseek'ed as stdin; when stdin is a
     * non-empty regular file the caller received ok=1 with fd 0 and served
     * stdin as the message payload. */
    TEST_CASE("no payload yields ok=0 and an invalid fd");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    file_content_t file_content = websocketsrequest_payload_file(protocol);

    TEST_ASSERT_EQUAL(0, file_content.ok, "ok must be 0 without payload");
    TEST_ASSERT_EQUAL(-1, file_content.fd, "fd must be invalid, not stdin");

    protocol_cleanup(protocol);
}

TEST(test_ws_payload_file_empty) {
    TEST_SUITE("websocketsrequest: payload_file");
    TEST_CASE("empty payload yields ok=0");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");
    TEST_REQUIRE(payload_write(protocol, NULL, 0), "tmpfile creation");

    file_content_t file_content = websocketsrequest_payload_file(protocol);

    TEST_ASSERT_EQUAL(0, file_content.ok, "ok must be 0 for empty payload");
    TEST_ASSERT_EQUAL_SIZE(0, file_content.size, "size is 0");

    protocol_cleanup(protocol);
}

TEST(test_ws_payload_file_with_content) {
    TEST_SUITE("websocketsrequest: payload_file");
    TEST_CASE("payload descriptor is exposed with size and rewound offset");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");
    TEST_REQUIRE(payload_write(protocol, "hello", 5), "payload write");

    file_content_t file_content = websocketsrequest_payload_file(protocol);

    TEST_ASSERT_EQUAL(1, file_content.ok, "ok is set");
    TEST_ASSERT_EQUAL(protocol->payload.fd, file_content.fd, "payload fd is exposed");
    TEST_ASSERT_EQUAL_SIZE(5, file_content.size, "size matches payload");
    TEST_ASSERT_EQUAL(0, file_content.offset, "offset starts at 0");
    TEST_ASSERT_STR_EQUAL("tmpfile", file_content.filename, "default filename");
    TEST_ASSERT_EQUAL(0, lseek(protocol->payload.fd, 0, SEEK_CUR), "file offset rewound");

    protocol_cleanup(protocol);
}

// ============================================================================
// websocketsrequest_payload_json
// ============================================================================

TEST(test_ws_payload_json_without_payload) {
    TEST_SUITE("websocketsrequest: payload_json");
    TEST_CASE("no payload yields NULL document");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    TEST_ASSERT_NULL(websocketsrequest_payload_json(protocol), "json without payload is NULL");

    protocol_cleanup(protocol);
}

TEST(test_ws_payload_json_valid) {
    TEST_SUITE("websocketsrequest: payload_json");
    TEST_CASE("valid JSON payload is parsed");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");

    const char* json = "{\"key\":\"value\"}";
    TEST_REQUIRE(payload_write(protocol, json, strlen(json)), "payload write");

    json_doc_t* document = websocketsrequest_payload_json(protocol);
    TEST_REQUIRE_NOT_NULL(document, "document parsed");
    TEST_ASSERT_EQUAL(1, json_is_object(json_root(document)), "root is an object");
    TEST_ASSERT_NOT_NULL(json_object_get(json_root(document), "key"), "key is present");

    json_free(document);
    protocol_cleanup(protocol);
}

TEST(test_ws_payload_json_invalid) {
    TEST_SUITE("websocketsrequest: payload_json");
    TEST_CASE("malformed JSON payload yields NULL");

    websockets_protocol_t* protocol = make_protocol();
    TEST_REQUIRE_NOT_NULL(protocol, "protocol allocation");
    TEST_REQUIRE(payload_write(protocol, "{broken", 7), "payload write");

    TEST_ASSERT_NULL(websocketsrequest_payload_json(protocol), "malformed json is NULL");

    protocol_cleanup(protocol);
}

// ============================================================================
// websocketsrequest_reset
// ============================================================================

TEST(test_ws_reset_clears_state_and_payload) {
    TEST_SUITE("websocketsrequest: reset");
    TEST_CASE("data frame reset clears type, fragmented and payload");

    websocketsrequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");
    TEST_REQUIRE(payload_write(request->protocol, "data", 4), "payload write");

    char* path = strdup(request->protocol->payload.path);
    TEST_REQUIRE_NOT_NULL(path, "path copy");

    request->type = WEBSOCKETS_TEXT;
    request->fragmented = 1;

    request->base.reset(request);

    TEST_ASSERT_EQUAL(WEBSOCKETS_NONE, request->type, "type is NONE after reset");
    TEST_ASSERT_EQUAL(0, request->fragmented, "fragmented cleared for data frame");
    TEST_ASSERT_EQUAL(1, request->can_reset, "can_reset stays 1");
    TEST_ASSERT_EQUAL(1, g_protocol_reset_calls, "protocol reset called once");
    TEST_ASSERT_EQUAL(-1, request->protocol->payload.fd, "payload fd released");
    TEST_ASSERT_NULL(request->protocol->payload.path, "payload path released");
    TEST_ASSERT(access(path, F_OK) != 0, "tmpfile removed from disk");

    free(path);
    websocketsrequest_free(request);
}

TEST(test_ws_reset_control_frame_preserves_fragmented) {
    TEST_SUITE("websocketsrequest: reset");
    TEST_CASE("PING/PONG reset keeps in-progress fragmented flag");

    websocketsrequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");

    request->type = WEBSOCKETS_PING;
    request->fragmented = 1;
    request->base.reset(request);
    TEST_ASSERT_EQUAL(1, request->fragmented, "fragmented survives PING");
    TEST_ASSERT_EQUAL(WEBSOCKETS_NONE, request->type, "type is NONE after PING reset");

    request->type = WEBSOCKETS_PONG;
    request->base.reset(request);
    TEST_ASSERT_EQUAL(1, request->fragmented, "fragmented survives PONG");

    request->type = WEBSOCKETS_BINARY;
    request->base.reset(request);
    TEST_ASSERT_EQUAL(0, request->fragmented, "data frame reset clears fragmented");

    websocketsrequest_free(request);
}

TEST(test_ws_reset_skipped_when_can_reset_zero) {
    TEST_SUITE("websocketsrequest: reset");
    TEST_CASE("can_reset=0 skips one reset and re-arms");

    websocketsrequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");
    TEST_REQUIRE(payload_write(request->protocol, "keep", 4), "payload write");

    request->type = WEBSOCKETS_TEXT;
    request->can_reset = 0;

    request->base.reset(request);

    TEST_ASSERT_EQUAL(0, g_protocol_reset_calls, "protocol reset skipped");
    TEST_ASSERT_EQUAL(WEBSOCKETS_TEXT, request->type, "type preserved");
    TEST_ASSERT(request->protocol->payload.fd >= 0, "payload preserved");
    TEST_ASSERT_EQUAL(1, request->can_reset, "reset re-arms can_reset");

    request->base.reset(request);

    TEST_ASSERT_EQUAL(1, g_protocol_reset_calls, "second reset runs");
    TEST_ASSERT_EQUAL(-1, request->protocol->payload.fd, "payload released by second reset");

    websocketsrequest_free(request);
}

// ============================================================================
// websocketsrequest_free
// ============================================================================

TEST(test_ws_free_releases_protocol_and_payload) {
    TEST_SUITE("websocketsrequest: free");
    TEST_CASE("free releases payload tmpfile and protocol");

    websocketsrequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");
    TEST_REQUIRE(payload_write(request->protocol, "bye", 3), "payload write");

    char* path = strdup(request->protocol->payload.path);
    TEST_REQUIRE_NOT_NULL(path, "path copy");

    websocketsrequest_free(request);

    TEST_ASSERT_EQUAL(1, g_protocol_free_calls, "protocol freed exactly once");
    TEST_ASSERT(access(path, F_OK) != 0, "tmpfile removed from disk");

    free(path);
}

TEST(test_ws_free_with_can_reset_zero_regression) {
    TEST_SUITE("websocketsrequest: free");
    /* REGRESSION: free() honored can_reset == 0, so the gated reset skipped
     * the payload cleanup and protocol->free leaked the tmpfile fd, its heap
     * path and the on-disk inode. */
    TEST_CASE("free with can_reset=0 still releases the tmpfile");

    websocketsrequest_t* request = make_request();
    TEST_REQUIRE_NOT_NULL(request, "request allocation");
    TEST_REQUIRE(payload_write(request->protocol, "leak", 4), "payload write");

    char* path = strdup(request->protocol->payload.path);
    TEST_REQUIRE_NOT_NULL(path, "path copy");

    request->can_reset = 0;
    websocketsrequest_free(request);

    TEST_ASSERT_EQUAL(1, g_protocol_free_calls, "protocol freed exactly once");
    TEST_ASSERT(access(path, F_OK) != 0, "tmpfile removed despite can_reset=0");

    free(path);
}

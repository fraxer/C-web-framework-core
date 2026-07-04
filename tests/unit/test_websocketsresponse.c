/*
 * Unit tests for protocols/websocket/websocketsresponse.c
 *
 * Covers frame size calculation, payload length encoding, text/binary/data
 * frames, control frames (pong/close), file responses and the
 * permessage-deflate compression path. Several cases are regression guards
 * for bugs fixed alongside these tests (each is marked REGRESSION below):
 *
 *   - file_status_e defined FILE_OK, FILE_FORBIDDEN and FILE_NOTFOUND all as
 *     0, so every send_file call matched the FORBIDDEN branch and failed with
 *     "resource forbidden" even for existing files.
 *   - __get_file_full_path used stat_obj uninitialized when stat() failed
 *     with an errno other than ENOENT (e.g. ENOTDIR), branching on garbage.
 *   - __get_file_full_path did not reject traversal paths, so "/../x" escaped
 *     the server root (is_path_traversal existed but was not called).
 *   - file_.fd used 0 as the "no file" sentinel (framework convention is -1),
 *     so a legitimate fd 0 was never sent by __write and leaked on reset.
 *   - websocketsresponse_prepare overwrote body.data without freeing the
 *     previous buffer: two send_* calls in a row leaked the first frame.
 *   - websocketsresponse_set_payload_length wrote only the low 32 bits of a
 *     64-bit payload length, zero-padding the high half.
 *   - websocketsresponse_pong/close with data == NULL and length > 0
 *     declared a payload but appended none, sending uninitialized heap bytes.
 *   - __compress_and_send discarded produced deflate output without resetting
 *     the stream (and sized the buffer at length + 64, truncating output for
 *     large incompressible payloads, leaving pending bytes inside zlib): with
 *     context takeover the next compressed message desynced the client.
 *   - filen did not reset file_.pos and leaked the previous fd when a file
 *     response was replaced by another one without an intervening reset.
 */

#include "framework.h"
#include "websocket/wscontext.h"
#include "websocket/ws_deflate.h"
#include "connection_s.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>

/* Internal functions under test (external linkage, declared in the .c). */
size_t websocketsresponse_data_size(size_t length);
size_t websocketsresponse_file_size(size_t length);
int websocketsresponse_set_payload_length(char* data, size_t* pos, size_t payload_length);
void websocketsresponse_reset(websocketsresponse_t* response);
void websocketsresponse_free(void* arg);

// ============================================================================
// Helpers
// ============================================================================

static connection_server_ctx_t test_ws_ctx;
static server_t test_ws_server;

static connection_t* make_connection(void) {
    connection_t* conn = calloc(1, sizeof(connection_t));
    if (conn == NULL) return NULL;

    memset(&test_ws_ctx, 0, sizeof(test_ws_ctx));
    memset(&test_ws_server, 0, sizeof(test_ws_server));
    test_ws_ctx.server = &test_ws_server;
    conn->ctx = &test_ws_ctx;

    return conn;
}

static websocketsresponse_t* make_response(connection_t** out_conn) {
    connection_t* conn = make_connection();
    if (conn == NULL) return NULL;

    websocketsresponse_t* response = websocketsresponse_create(conn);
    if (response == NULL) {
        free(conn);
        return NULL;
    }

    *out_conn = conn;
    return response;
}

static void free_response(websocketsresponse_t* response, connection_t* conn) {
    if (response != NULL) websocketsresponse_free(response);
    free(conn);
}

static void set_server_root(const char* root) {
    test_ws_server.root = (char*)root;
    test_ws_server.root_length = strlen(root);
}

/* Parse the frame header in body.data; returns the payload offset or -1 on a
 * malformed header (mask bit set / no data). */
static ssize_t frame_payload_offset(const websocketsresponse_t* response, size_t* out_length) {
    const unsigned char* data = (const unsigned char*)response->body.data;
    if (data == NULL) return -1;
    if (data[1] & 0x80) return -1; /* server frames must not be masked */

    size_t length = data[1] & 0x7F;
    size_t offset = 2;

    if (length == 126) {
        length = ((size_t)data[2] << 8) | data[3];
        offset = 4;
    }
    else if (length == 127) {
        length = 0;
        for (int i = 0; i < 8; i++)
            length = (length << 8) | data[2 + i];
        offset = 10;
    }

    *out_length = length;
    return (ssize_t)offset;
}

static int write_whole_file(const char* path, const void* data, size_t size) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return 0;

    const ssize_t written = write(fd, data, size);
    close(fd);

    return written == (ssize_t)size;
}

/* Decompress a frame payload the way a client does: append the RFC 7692
 * trailer and run it through the inflate side of the given context. */
static ssize_t inflate_frame_payload(ws_deflate_t* deflate, const char* payload, size_t payload_length,
                                     char* out, size_t out_size) {
    char* in = malloc(payload_length + 4);
    if (in == NULL) return -1;

    memcpy(in, payload, payload_length);
    memcpy(in + payload_length, "\x00\x00\xff\xff", 4);

    const ssize_t result = ws_deflate_decompress(deflate, in, payload_length + 4, out, out_size);
    free(in);

    return result;
}

// ============================================================================
// websocketsresponse_data_size / websocketsresponse_file_size
// ============================================================================

TEST(test_wsresp_data_size_boundaries) {
    TEST_SUITE("websocketsresponse: sizes");
    TEST_CASE("data_size covers all payload length encodings");

    TEST_ASSERT_EQUAL_SIZE(2, websocketsresponse_data_size(0), "empty payload: 1 + 1");
    TEST_ASSERT_EQUAL_SIZE(127, websocketsresponse_data_size(125), "125: 1 + 1 + 125");
    TEST_ASSERT_EQUAL_SIZE(130, websocketsresponse_data_size(126), "126: 1 + 3 + 126");
    TEST_ASSERT_EQUAL_SIZE(65539, websocketsresponse_data_size(65535), "65535: 1 + 3 + 65535");
    TEST_ASSERT_EQUAL_SIZE(65546, websocketsresponse_data_size(65536), "65536: 1 + 9 + 65536");
}

TEST(test_wsresp_file_size_boundaries) {
    TEST_CASE("file_size counts only the header");

    TEST_ASSERT_EQUAL_SIZE(2, websocketsresponse_file_size(0), "empty file: 1 + 1");
    TEST_ASSERT_EQUAL_SIZE(2, websocketsresponse_file_size(125), "125: 1 + 1");
    TEST_ASSERT_EQUAL_SIZE(4, websocketsresponse_file_size(126), "126: 1 + 3");
    TEST_ASSERT_EQUAL_SIZE(4, websocketsresponse_file_size(65535), "65535: 1 + 3");
    TEST_ASSERT_EQUAL_SIZE(10, websocketsresponse_file_size(65536), "65536: 1 + 9");
}

// ============================================================================
// websocketsresponse_set_payload_length
// ============================================================================

TEST(test_wsresp_payload_length_7bit) {
    TEST_SUITE("websocketsresponse: set_payload_length");
    TEST_CASE("lengths up to 125 use a single byte");

    unsigned char buffer[16] = {0};
    size_t pos = 0;

    websocketsresponse_set_payload_length((char*)buffer, &pos, 125);

    TEST_ASSERT_EQUAL_SIZE(1, pos, "single length byte");
    TEST_ASSERT_EQUAL_UINT(125, buffer[0], "length written as-is");
    TEST_ASSERT_EQUAL_UINT(0, buffer[0] & 0x80, "mask bit must be clear");
}

TEST(test_wsresp_payload_length_16bit) {
    TEST_CASE("lengths 126..65535 use the 16-bit form");

    unsigned char buffer[16] = {0};
    size_t pos = 0;

    websocketsresponse_set_payload_length((char*)buffer, &pos, 126);

    TEST_ASSERT_EQUAL_SIZE(3, pos, "marker + 2 length bytes");
    TEST_ASSERT_EQUAL_UINT(126, buffer[0], "16-bit marker");
    TEST_ASSERT_EQUAL_UINT(0, buffer[1], "big-endian high byte");
    TEST_ASSERT_EQUAL_UINT(126, buffer[2], "big-endian low byte");

    pos = 0;
    websocketsresponse_set_payload_length((char*)buffer, &pos, 65535);

    TEST_ASSERT_EQUAL_UINT(0xFF, buffer[1], "65535 high byte");
    TEST_ASSERT_EQUAL_UINT(0xFF, buffer[2], "65535 low byte");
}

TEST(test_wsresp_payload_length_64bit) {
    TEST_CASE("lengths above 65535 use the 64-bit form");

    unsigned char buffer[16] = {0};
    size_t pos = 0;

    websocketsresponse_set_payload_length((char*)buffer, &pos, 65536);

    TEST_ASSERT_EQUAL_SIZE(9, pos, "marker + 8 length bytes");
    TEST_ASSERT_EQUAL_UINT(127, buffer[0], "64-bit marker");

    const unsigned char expected[8] = {0, 0, 0, 0, 0, 1, 0, 0};
    TEST_ASSERT(memcmp(buffer + 1, expected, 8) == 0, "65536 encoded big-endian in 8 bytes");
}

#if SIZE_MAX > 0xFFFFFFFFu
TEST(test_wsresp_payload_length_above_4gib) {
    /* REGRESSION: the high 32 bits were zero-padded, so any payload above
     * 4 GiB declared a wrong (truncated) length. */
    TEST_CASE("payload lengths above 4 GiB keep the high 32 bits");

    unsigned char buffer[16] = {0};
    size_t pos = 0;

    websocketsresponse_set_payload_length((char*)buffer, &pos, ((size_t)1 << 32) | 0x0102);

    TEST_ASSERT_EQUAL_SIZE(9, pos, "marker + 8 length bytes");

    const unsigned char expected[8] = {0, 0, 0, 1, 0, 0, 1, 2};
    TEST_ASSERT(memcmp(buffer + 1, expected, 8) == 0, "full 64-bit length encoded");
}
#endif

// ============================================================================
// websocketsresponse_create / reset / free
// ============================================================================

TEST(test_wsresp_create_defaults) {
    TEST_SUITE("websocketsresponse: lifecycle");
    TEST_CASE("create initializes a clean response");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    TEST_ASSERT_EQUAL(0, response->frame_code, "no frame code");
    TEST_ASSERT_NULL(response->body.data, "no body");
    TEST_ASSERT_EQUAL_SIZE(0, response->body.size, "body size 0");
    TEST_ASSERT_EQUAL_SIZE(0, response->body.pos, "body pos 0");
    /* REGRESSION: fd was initialized to 0; the framework sentinel is -1. */
    TEST_ASSERT_EQUAL(-1, response->file_.fd, "no file open");
    TEST_ASSERT(response->connection == conn, "connection stored");
    TEST_ASSERT_NULL(response->ws_deflate, "no deflate context without a parser");
    TEST_ASSERT_NOT_NULL(response->send_text, "send_text wired");
    TEST_ASSERT_NOT_NULL(response->send_filen, "send_filen wired");
    TEST_ASSERT(response->base.free == websocketsresponse_free, "base.free wired");

    free_response(response, conn);
}

TEST(test_wsresp_create_null_connection) {
    TEST_CASE("create(NULL) is rejected");

    TEST_ASSERT_NULL(websocketsresponse_create(NULL), "NULL connection must not crash");
}

TEST(test_wsresp_reset_clears_frame) {
    TEST_CASE("reset clears a prepared frame");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_textn(response, "hello", 5);
    TEST_REQUIRE_NOT_NULL(response->body.data, "frame prepared");

    websocketsresponse_reset(response);

    TEST_ASSERT_EQUAL(0, response->frame_code, "frame code cleared");
    TEST_ASSERT_NULL(response->body.data, "body released");
    TEST_ASSERT_EQUAL_SIZE(0, response->body.size, "body size cleared");
    TEST_ASSERT_EQUAL(-1, response->file_.fd, "fd back to sentinel");

    free_response(response, conn);
}

TEST(test_wsresp_free_null_is_noop) {
    TEST_CASE("free(NULL) is a no-op");

    websocketsresponse_free(NULL);
    TEST_ASSERT(1, "no crash on NULL");
}

// ============================================================================
// send_text / send_textn / send_binary / send_binaryn
// ============================================================================

TEST(test_wsresp_textn_small_payload) {
    TEST_SUITE("websocketsresponse: text/binary frames");
    TEST_CASE("small text frame layout");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_textn(response, "hello", 5);

    TEST_ASSERT_EQUAL_UINT(0x81, response->frame_code, "FIN + text opcode");
    TEST_ASSERT_EQUAL_SIZE(7, response->body.size, "2-byte header + 5-byte payload");
    TEST_ASSERT_EQUAL_SIZE(0, response->body.pos, "write position rewound");
    TEST_REQUIRE_NOT_NULL(response->body.data, "frame prepared");
    TEST_ASSERT_EQUAL_UINT(0x81, (unsigned char)response->body.data[0], "frame byte");
    TEST_ASSERT_EQUAL_UINT(5, (unsigned char)response->body.data[1], "payload length byte");
    TEST_ASSERT(memcmp(response->body.data + 2, "hello", 5) == 0, "payload copied");

    free_response(response, conn);
}

TEST(test_wsresp_textn_empty_payload) {
    TEST_CASE("empty text frame");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_textn(response, "", 0);

    TEST_ASSERT_EQUAL_UINT(0x81, response->frame_code, "FIN + text opcode");
    TEST_ASSERT_EQUAL_SIZE(2, response->body.size, "header only");
    TEST_REQUIRE_NOT_NULL(response->body.data, "frame prepared");
    TEST_ASSERT_EQUAL_UINT(0, (unsigned char)response->body.data[1], "zero payload length");

    free_response(response, conn);
}

TEST(test_wsresp_binaryn_frame_code) {
    TEST_CASE("binary frames use opcode 0x2");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_binaryn(response, "\x01\x02\x03", 3);

    TEST_ASSERT_EQUAL_UINT(0x82, response->frame_code, "FIN + binary opcode");
    TEST_ASSERT_EQUAL_UINT(0x82, (unsigned char)response->body.data[0], "frame byte");
    TEST_ASSERT(memcmp(response->body.data + 2, "\x01\x02\x03", 3) == 0, "payload copied");

    free_response(response, conn);
}

TEST(test_wsresp_text_uses_strlen) {
    TEST_CASE("send_text measures the string itself");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_text(response, "abc");

    TEST_ASSERT_EQUAL_SIZE(5, response->body.size, "2-byte header + 3-byte payload");
    TEST_ASSERT(memcmp(response->body.data + 2, "abc", 3) == 0, "payload copied");

    free_response(response, conn);
}

TEST(test_wsresp_text_null_data_is_noop) {
    TEST_CASE("NULL data does not build a frame");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_text(response, NULL);
    response->send_binary(response, NULL);
    response->send_textn(response, NULL, 10);

    TEST_ASSERT_NULL(response->body.data, "no frame for NULL data");

    free_response(response, conn);
}

TEST(test_wsresp_textn_extended_length_header) {
    TEST_CASE("126-byte payload uses the 16-bit header");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char payload[126];
    memset(payload, 'x', sizeof(payload));

    response->send_textn(response, payload, sizeof(payload));

    TEST_ASSERT_EQUAL_SIZE(130, response->body.size, "4-byte header + 126-byte payload");

    size_t parsed_length = 0;
    const ssize_t offset = frame_payload_offset(response, &parsed_length);
    TEST_ASSERT_EQUAL(4, offset, "payload starts after extended header");
    TEST_ASSERT_EQUAL_SIZE(126, parsed_length, "parsed length matches");
    TEST_ASSERT(memcmp(response->body.data + offset, payload, sizeof(payload)) == 0, "payload copied");

    free_response(response, conn);
}

TEST(test_wsresp_double_send_replaces_frame) {
    /* REGRESSION: prepare overwrote body.data without freeing the previous
     * buffer; LSan flags the leak if it comes back. */
    TEST_CASE("second send replaces the first frame");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    response->send_textn(response, "first", 5);
    response->send_textn(response, "second!", 7);

    TEST_ASSERT_EQUAL_SIZE(9, response->body.size, "size matches the second frame");
    TEST_ASSERT_EQUAL_SIZE(0, response->body.pos, "write position rewound");
    TEST_ASSERT(memcmp(response->body.data + 2, "second!", 7) == 0, "second payload in place");

    free_response(response, conn);
}

// ============================================================================
// send_data / send_datan
// ============================================================================

TEST(test_wsresp_datan_follows_request_type) {
    TEST_SUITE("websocketsresponse: send_data");
    TEST_CASE("reply type mirrors the request type");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    websocketsrequest_t request;
    memset(&request, 0, sizeof(request));
    wsctx_t wsctx = { .request = &request, .response = response, .user_data = NULL };

    request.type = WEBSOCKETS_TEXT;
    response->send_data(&wsctx, "ping");
    TEST_ASSERT_EQUAL_UINT(0x81, response->frame_code, "text request gets a text reply");

    request.type = WEBSOCKETS_BINARY;
    response->send_datan(&wsctx, "pong", 4);
    TEST_ASSERT_EQUAL_UINT(0x82, response->frame_code, "binary request gets a binary reply");

    free_response(response, conn);
}

// ============================================================================
// websocketsresponse_pong / websocketsresponse_close
// ============================================================================

TEST(test_wsresp_pong_echoes_payload) {
    TEST_SUITE("websocketsresponse: control frames");
    TEST_CASE("pong echoes the ping payload");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    websocketsresponse_pong(response, "hi", 2);

    TEST_ASSERT_EQUAL_UINT(0x8A, response->frame_code, "FIN + pong opcode");
    TEST_ASSERT_EQUAL_SIZE(4, response->body.size, "2-byte header + 2-byte payload");
    TEST_ASSERT(memcmp(response->body.data + 2, "hi", 2) == 0, "payload echoed");

    free_response(response, conn);
}

TEST(test_wsresp_pong_null_data_sends_empty) {
    /* REGRESSION: NULL data with a nonzero length declared a payload without
     * appending one, sending uninitialized heap bytes to the client. */
    TEST_CASE("NULL data with nonzero length becomes an empty pong");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    websocketsresponse_pong(response, NULL, 5);

    TEST_ASSERT_EQUAL_SIZE(2, response->body.size, "header only");
    TEST_ASSERT_EQUAL_UINT(0, (unsigned char)response->body.data[1], "zero payload length");

    free_response(response, conn);
}

TEST(test_wsresp_pong_clamps_control_payload) {
    TEST_CASE("control frame payload is clamped to 125 bytes");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char payload[200];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (char)('a' + i % 26);

    websocketsresponse_pong(response, payload, sizeof(payload));

    TEST_ASSERT_EQUAL_SIZE(127, response->body.size, "2-byte header + 125-byte payload");
    TEST_ASSERT_EQUAL_UINT(125, (unsigned char)response->body.data[1], "length clamped to 125");
    TEST_ASSERT(memcmp(response->body.data + 2, payload, 125) == 0, "first 125 bytes kept");

    free_response(response, conn);
}

TEST(test_wsresp_close_frame) {
    TEST_CASE("close frame carries status and reason");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    websocketsresponse_close(response, "\x03\xe8ok", 4);

    TEST_ASSERT_EQUAL_UINT(0x88, response->frame_code, "FIN + close opcode");
    TEST_ASSERT_EQUAL_SIZE(6, response->body.size, "2-byte header + 4-byte payload");
    TEST_ASSERT(memcmp(response->body.data + 2, "\x03\xe8ok", 4) == 0, "payload copied");

    websocketsresponse_close(response, NULL, 7);
    TEST_ASSERT_EQUAL_UINT(0, (unsigned char)response->body.data[1], "NULL data becomes an empty close");

    free_response(response, conn);
}

// ============================================================================
// send_file / send_filen
// ============================================================================

TEST(test_wsresp_file_success) {
    /* REGRESSION: file_status_e had all enumerators equal to 0, so send_file
     * always took the FORBIDDEN branch and returned -1 for existing files. */
    TEST_SUITE("websocketsresponse: file frames");
    TEST_CASE("existing file is sent as a binary frame");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    char content[300];
    for (size_t i = 0; i < sizeof(content); i++)
        content[i] = (char)(i & 0xFF);

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/data.bin", root);
    TEST_REQUIRE(write_whole_file(file_path, content, sizeof(content)), "test file written");

    const int result = response->send_filen(response, "/data.bin", 9);

    TEST_ASSERT_EQUAL(0, result, "send_filen must succeed for an existing file");
    TEST_ASSERT_EQUAL_UINT(0x82, response->frame_code, "file goes out as binary");
    TEST_ASSERT(response->file_.fd > -1, "file descriptor kept for the write phase");
    TEST_ASSERT_EQUAL_SIZE(sizeof(content), response->file_.size, "file size recorded");
    TEST_ASSERT_EQUAL_SIZE(0, response->file_.pos, "file position rewound");
    TEST_ASSERT_EQUAL_SIZE(4, response->body.size, "header-only body (16-bit length)");
    TEST_ASSERT_EQUAL_UINT(0x82, (unsigned char)response->body.data[0], "frame byte");
    TEST_ASSERT_EQUAL_UINT(126, (unsigned char)response->body.data[1], "16-bit length marker");
    TEST_ASSERT_EQUAL_UINT(0x01, (unsigned char)response->body.data[2], "length high byte");
    TEST_ASSERT_EQUAL_UINT(0x2C, (unsigned char)response->body.data[3], "length low byte");

    char readback[sizeof(content)];
    TEST_ASSERT_EQUAL(
        (long long)sizeof(content),
        (long long)pread(response->file_.fd, readback, sizeof(readback), 0),
        "file readable through the stored fd");
    TEST_ASSERT(memcmp(readback, content, sizeof(content)) == 0, "fd points at the right file");

    free_response(response, conn);
    unlink(file_path);
    rmdir(root);
}

TEST(test_wsresp_file_relative_path) {
    TEST_CASE("path without a leading slash is resolved against the root");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/rel.txt", root);
    TEST_REQUIRE(write_whole_file(file_path, "rel", 3), "test file written");

    TEST_ASSERT_EQUAL(0, response->send_filen(response, "rel.txt", 7), "relative path accepted");
    TEST_ASSERT_EQUAL_SIZE(3, response->file_.size, "file size recorded");

    free_response(response, conn);
    unlink(file_path);
    rmdir(root);
}

TEST(test_wsresp_file_not_found) {
    TEST_CASE("missing file yields -1 and a text error frame");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    TEST_ASSERT_EQUAL(-1, response->send_filen(response, "/missing.bin", 12), "missing file fails");
    TEST_ASSERT_EQUAL_UINT(0x81, response->frame_code, "error is a text frame");
    TEST_REQUIRE_NOT_NULL(response->body.data, "error frame prepared");
    TEST_ASSERT_EQUAL_UINT(18, (unsigned char)response->body.data[1], "error text length");
    TEST_ASSERT(memcmp(response->body.data + 2, "resource not found", 18) == 0, "not-found text");
    TEST_ASSERT_EQUAL(-1, response->file_.fd, "no fd kept");

    free_response(response, conn);
    rmdir(root);
}

TEST(test_wsresp_file_directory_forbidden) {
    TEST_CASE("directory path yields -1 and a forbidden frame");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    char dir_path[PATH_MAX];
    snprintf(dir_path, sizeof(dir_path), "%s/sub", root);
    TEST_REQUIRE(mkdir(dir_path, 0755) == 0, "subdirectory created");

    TEST_ASSERT_EQUAL(-1, response->send_filen(response, "/sub", 4), "directory rejected");
    TEST_ASSERT(memcmp(response->body.data + 2, "resource forbidden", 18) == 0, "forbidden text");

    free_response(response, conn);
    rmdir(dir_path);
    rmdir(root);
}

TEST(test_wsresp_file_traversal_forbidden) {
    /* REGRESSION: "/../x" escaped the server root; is_path_traversal existed
     * in helpers but was never called on this path. */
    TEST_CASE("path traversal cannot escape the server root");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char base[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(base), "temp base created");

    char root[PATH_MAX];
    snprintf(root, sizeof(root), "%s/root", base);
    TEST_REQUIRE(mkdir(root, 0755) == 0, "server root created");
    set_server_root(root);

    char secret_path[PATH_MAX];
    snprintf(secret_path, sizeof(secret_path), "%s/secret.txt", base);
    TEST_REQUIRE(write_whole_file(secret_path, "top secret", 10), "secret written outside root");

    TEST_ASSERT_EQUAL(-1, response->send_filen(response, "/../secret.txt", 14), "absolute traversal rejected");
    TEST_ASSERT(memcmp(response->body.data + 2, "resource forbidden", 18) == 0, "forbidden text");
    TEST_ASSERT_EQUAL(-1, response->file_.fd, "no fd opened");

    TEST_ASSERT_EQUAL(-1, response->send_filen(response, "../secret.txt", 13), "relative traversal rejected");

    free_response(response, conn);
    unlink(secret_path);
    rmdir(root);
    rmdir(base);
}

TEST(test_wsresp_file_component_not_a_directory) {
    /* REGRESSION: stat() failing with ENOTDIR left stat_obj uninitialized and
     * the code branched on garbage. */
    TEST_CASE("file used as a path component is not found");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/plain.txt", root);
    TEST_REQUIRE(write_whole_file(file_path, "x", 1), "test file written");

    TEST_ASSERT_EQUAL(-1, response->send_filen(response, "/plain.txt/nested", 17), "ENOTDIR path fails");
    TEST_ASSERT(memcmp(response->body.data + 2, "resource not found", 18) == 0, "not-found text");

    free_response(response, conn);
    unlink(file_path);
    rmdir(root);
}

TEST(test_wsresp_file_path_too_long) {
    TEST_CASE("oversized path fails instead of overflowing the buffer");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    char long_path[PATH_MAX * 2];
    memset(long_path, 'a', sizeof(long_path));
    long_path[0] = '/';

    TEST_ASSERT_EQUAL(-1, response->send_filen(response, long_path, sizeof(long_path)), "oversized path rejected");
    TEST_ASSERT(memcmp(response->body.data + 2, "resource not found", 18) == 0, "not-found text");

    free_response(response, conn);
    rmdir(root);
}

TEST(test_wsresp_file_null_and_empty_path) {
    TEST_CASE("NULL and empty paths are rejected");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    TEST_ASSERT_EQUAL(-1, response->send_file(response, NULL), "NULL path via send_file");
    TEST_ASSERT_EQUAL(-1, response->send_filen(response, NULL, 3), "NULL path via send_filen");
    TEST_ASSERT_EQUAL(-1, response->send_filen(response, "", 0), "empty path");

    free_response(response, conn);
    rmdir(root);
}

TEST(test_wsresp_file_replaces_previous_file) {
    /* REGRESSION: a second file response leaked the previous fd and kept the
     * stale file_.pos. */
    TEST_CASE("second file response closes the first fd");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    char path_a[PATH_MAX];
    char path_b[PATH_MAX];
    snprintf(path_a, sizeof(path_a), "%s/a.bin", root);
    snprintf(path_b, sizeof(path_b), "%s/b.bin", root);
    TEST_REQUIRE(write_whole_file(path_a, "aaaaaaaaaa", 10), "file a written");
    TEST_REQUIRE(write_whole_file(path_b, "bb", 2), "file b written");

    TEST_REQUIRE(response->send_filen(response, "/a.bin", 6) == 0, "first file accepted");
    const int first_fd = response->file_.fd;
    response->file_.pos = 7; /* pretend part of the file was already sent */

    TEST_ASSERT_EQUAL(0, response->send_filen(response, "/b.bin", 6), "second file accepted");
    TEST_ASSERT_EQUAL(-1, fcntl(first_fd, F_GETFD), "first fd closed");
    TEST_ASSERT_EQUAL_SIZE(0, response->file_.pos, "file position rewound");
    TEST_ASSERT_EQUAL_SIZE(2, response->file_.size, "size matches the second file");

    free_response(response, conn);
    unlink(path_a);
    unlink(path_b);
    rmdir(root);
}

TEST(test_wsresp_reset_closes_file_fd) {
    TEST_CASE("reset closes the file descriptor");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/f.bin", root);
    TEST_REQUIRE(write_whole_file(file_path, "data", 4), "test file written");
    TEST_REQUIRE(response->send_filen(response, "/f.bin", 6) == 0, "file accepted");

    const int fd = response->file_.fd;
    websocketsresponse_reset(response);

    TEST_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD), "fd closed by reset");
    TEST_ASSERT_EQUAL(-1, response->file_.fd, "fd field back to sentinel");
    TEST_ASSERT_EQUAL_SIZE(0, response->file_.size, "file size cleared");

    free_response(response, conn);
    unlink(file_path);
    rmdir(root);
}

TEST(test_wsresp_default_after_file) {
    TEST_CASE("default response resets file state and sends text");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    char root[] = "/tmp/ws_resp_test_XXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(root), "temp root created");
    set_server_root(root);

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/f.bin", root);
    TEST_REQUIRE(write_whole_file(file_path, "data", 4), "test file written");
    TEST_REQUIRE(response->send_filen(response, "/f.bin", 6) == 0, "file accepted");

    const int fd = response->file_.fd;
    websocketsresponse_default(response, "bye");

    TEST_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD), "file fd closed");
    TEST_ASSERT_EQUAL_UINT(0x81, response->frame_code, "text frame");
    TEST_ASSERT(memcmp(response->body.data + 2, "bye", 3) == 0, "text payload");

    free_response(response, conn);
    unlink(file_path);
    rmdir(root);
}

// ============================================================================
// permessage-deflate compression
// ============================================================================

TEST(test_wsresp_compression_roundtrip) {
    TEST_SUITE("websocketsresponse: permessage-deflate");
    TEST_CASE("compressible text frame sets RSV1 and inflates back");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    TEST_REQUIRE(ws_deflate_start(&deflate) == 1, "deflate streams started");
    response->ws_deflate = &deflate;

    char payload[256];
    memset(payload, 'a', sizeof(payload));

    response->send_textn(response, payload, sizeof(payload));

    TEST_ASSERT_EQUAL_UINT(0xC1, response->frame_code, "FIN + RSV1 + text opcode");
    TEST_ASSERT(response->body.size < websocketsresponse_data_size(sizeof(payload)),
                "compressed frame is smaller than the plain one");

    size_t comp_length = 0;
    const ssize_t offset = frame_payload_offset(response, &comp_length);
    TEST_REQUIRE(offset > 0, "frame header parsed");
    TEST_ASSERT_EQUAL_SIZE(comp_length, response->body.size - (size_t)offset, "header length matches body");

    char inflated[512];
    const ssize_t inflated_size = inflate_frame_payload(
        &deflate, response->body.data + offset, comp_length, inflated, sizeof(inflated));
    TEST_ASSERT_EQUAL((long long)sizeof(payload), (long long)inflated_size, "inflated size matches");
    TEST_ASSERT(memcmp(inflated, payload, sizeof(payload)) == 0, "roundtrip content matches");

    response->ws_deflate = NULL;
    ws_deflate_free(&deflate);
    free_response(response, conn);
}

TEST(test_wsresp_compression_binary_opcode) {
    TEST_CASE("compressed binary frame uses 0xC2");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    TEST_REQUIRE(ws_deflate_start(&deflate) == 1, "deflate streams started");
    response->ws_deflate = &deflate;

    char payload[256];
    memset(payload, 'b', sizeof(payload));

    response->send_binaryn(response, payload, sizeof(payload));

    TEST_ASSERT_EQUAL_UINT(0xC2, response->frame_code, "FIN + RSV1 + binary opcode");

    response->ws_deflate = NULL;
    ws_deflate_free(&deflate);
    free_response(response, conn);
}

TEST(test_wsresp_compression_threshold) {
    TEST_CASE("payloads under 128 bytes stay uncompressed");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    TEST_REQUIRE(ws_deflate_start(&deflate) == 1, "deflate streams started");
    response->ws_deflate = &deflate;

    char payload[127];
    memset(payload, 'a', sizeof(payload));

    response->send_textn(response, payload, sizeof(payload));

    TEST_ASSERT_EQUAL_UINT(0x81, response->frame_code, "below threshold: plain text frame");
    TEST_ASSERT(memcmp(response->body.data + 4, payload, sizeof(payload)) == 0, "plain payload");

    response->ws_deflate = NULL;
    ws_deflate_free(&deflate);
    free_response(response, conn);
}

TEST(test_wsresp_compression_disabled_stream) {
    TEST_CASE("no compression when the deflate stream is not started");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate); /* deflate_init stays 0 without ws_deflate_start */
    response->ws_deflate = &deflate;

    char payload[256];
    memset(payload, 'a', sizeof(payload));

    response->send_textn(response, payload, sizeof(payload));

    TEST_ASSERT_EQUAL_UINT(0x81, response->frame_code, "plain frame without a started stream");

    response->ws_deflate = NULL;
    free_response(response, conn);
}

TEST(test_wsresp_compression_incompressible_fallback) {
    /* REGRESSION: the discard paths of __compress_and_send did not reset the
     * deflate stream, so with context takeover (the negotiated default) the
     * next compressed message referenced history the client never received. */
    TEST_CASE("incompressible payload falls back and keeps the stream usable");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    TEST_REQUIRE(ws_deflate_start(&deflate) == 1, "deflate streams started");
    TEST_REQUIRE(deflate.config.server_no_context_takeover == 0, "context takeover is the default");
    response->ws_deflate = &deflate;

    char noise[256];
    srand(1234);
    for (size_t i = 0; i < sizeof(noise); i++)
        noise[i] = (char)(rand() & 0xFF);

    response->send_binaryn(response, noise, sizeof(noise));

    TEST_ASSERT_EQUAL_UINT(0x82, response->frame_code, "incompressible payload sent plain");
    TEST_ASSERT(memcmp(response->body.data + 4, noise, sizeof(noise)) == 0, "plain payload intact");

    /* The next compressed message must be decodable by a client that never
     * saw the discarded output — inflate it with a fresh context. */
    char text[300];
    memset(text, 'z', sizeof(text));
    response->send_textn(response, text, sizeof(text));

    TEST_REQUIRE(response->frame_code == 0xC1, "second message is compressed");

    size_t comp_length = 0;
    const ssize_t offset = frame_payload_offset(response, &comp_length);
    TEST_REQUIRE(offset > 0, "frame header parsed");

    ws_deflate_t client;
    ws_deflate_init(&client);
    TEST_REQUIRE(ws_deflate_start(&client) == 1, "client streams started");

    char inflated[1024];
    const ssize_t inflated_size = inflate_frame_payload(
        &client, response->body.data + offset, comp_length, inflated, sizeof(inflated));
    TEST_ASSERT_EQUAL((long long)sizeof(text), (long long)inflated_size,
                      "client inflates the message after the fallback");
    TEST_ASSERT(memcmp(inflated, text, sizeof(text)) == 0, "content survives the fallback");

    ws_deflate_free(&client);
    response->ws_deflate = NULL;
    ws_deflate_free(&deflate);
    free_response(response, conn);
}

TEST(test_wsresp_compression_large_incompressible_fallback) {
    /* REGRESSION: the compression buffer was length + 64 bytes; for large
     * incompressible payloads deflate ran out of output space and kept
     * pending bytes inside zlib, corrupting the next compressed frame. */
    TEST_CASE("large incompressible payload leaves no pending zlib output");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    TEST_REQUIRE(ws_deflate_start(&deflate) == 1, "deflate streams started");
    response->ws_deflate = &deflate;

    const size_t noise_size = 250000;
    char* noise = malloc(noise_size);
    TEST_REQUIRE_NOT_NULL_GOTO(noise, "noise buffer allocated", cleanup);

    srand(4321);
    for (size_t i = 0; i < noise_size; i++)
        noise[i] = (char)(rand() & 0xFF);

    response->send_binaryn(response, noise, noise_size);

    TEST_ASSERT_EQUAL_UINT(0x82, response->frame_code, "large incompressible payload sent plain");
    TEST_ASSERT_EQUAL_SIZE(10 + noise_size, response->body.size, "64-bit header + payload");
    TEST_ASSERT(memcmp(response->body.data + 10, noise, noise_size) == 0, "plain payload intact");

    /* A fresh client must still be able to decode the next compressed frame. */
    char text[400];
    memset(text, 'q', sizeof(text));
    response->send_textn(response, text, sizeof(text));
    TEST_REQUIRE_GOTO(response->frame_code == 0xC1, "next message is compressed", cleanup_noise);

    size_t comp_length = 0;
    const ssize_t offset = frame_payload_offset(response, &comp_length);
    TEST_REQUIRE_GOTO(offset > 0, "frame header parsed", cleanup_noise);

    ws_deflate_t client;
    ws_deflate_init(&client);
    TEST_REQUIRE_GOTO(ws_deflate_start(&client) == 1, "client streams started", cleanup_noise);

    char inflated[1024];
    const ssize_t inflated_size = inflate_frame_payload(
        &client, response->body.data + offset, comp_length, inflated, sizeof(inflated));
    TEST_ASSERT_EQUAL((long long)sizeof(text), (long long)inflated_size, "frame decodable after fallback");
    TEST_ASSERT(memcmp(inflated, text, sizeof(text)) == 0, "content intact after fallback");

    ws_deflate_free(&client);

cleanup_noise:
    free(noise);
cleanup:
    response->ws_deflate = NULL;
    ws_deflate_free(&deflate);
    free_response(response, conn);
}

TEST(test_wsresp_compression_then_plain_send) {
    TEST_CASE("plain frame after a compressed one replaces the body cleanly");

    connection_t* conn = NULL;
    websocketsresponse_t* response = make_response(&conn);
    TEST_REQUIRE_NOT_NULL(response, "response allocated");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    TEST_REQUIRE(ws_deflate_start(&deflate) == 1, "deflate streams started");
    response->ws_deflate = &deflate;

    char payload[256];
    memset(payload, 'a', sizeof(payload));
    response->send_textn(response, payload, sizeof(payload));
    TEST_REQUIRE(response->frame_code == 0xC1, "first frame compressed");

    response->send_textn(response, "x", 1);

    TEST_ASSERT_EQUAL_UINT(0x81, response->frame_code, "small frame is plain");
    TEST_ASSERT_EQUAL_SIZE(3, response->body.size, "2-byte header + 1-byte payload");
    TEST_ASSERT_EQUAL_UINT('x', (unsigned char)response->body.data[2], "payload replaced");

    response->ws_deflate = NULL;
    ws_deflate_free(&deflate);
    free_response(response, conn);
}

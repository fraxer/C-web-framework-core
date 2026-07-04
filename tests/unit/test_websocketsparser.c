/*
 * Unit tests for protocols/websocket/server/parsers/websocketsparser.c
 *
 * Drives the parser the way the connection read loop does: copy a wire frame
 * into the connection buffer, set bytes_readed/pos, call websocketsparser_run.
 * Covers frame decoding (first/second byte, 126/127 lengths, mask, payload),
 * opcode/RSV/mask validation, control frames, fragmentation, the body-size
 * limit, streaming UTF-8 validation for TEXT, mask-key continuity across split
 * reads, pipelined frames and permessage-deflate (single-shot, split-read,
 * multi-message with context takeover).
 *
 * env()/appconfig() resolve to the weak test doubles defined in
 * test_httprequestparser.c (client_max_body_size, tmp are writable per test).
 */

#include "framework.h"
#include "appconfig.h"
#include "connection_s.h"
#include "websocketsparser.h"
#include "websocketsrequest.h"
#include "websocketsprotocoldefault.h"
#include "ws_deflate.h"
#include "ws_utf8.h"
#include "bufferdata.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Provided by websocketsprotocoldefault.c (external linkage). */
extern websockets_protocol_t* websockets_protocol_default_create(void);

/* Weak test double from test_httprequestparser.c. */
extern appconfig_t* appconfig(void);

#define TEST_BUFFER_SIZE 65536

typedef struct {
    connection_t connection;
    connection_server_ctx_t ctx;
    websocketsparser_t* parser;
    unsigned char buffer[TEST_BUFFER_SIZE];
} harness_t;

static websockets_protocol_t* test_protocol_create(void) {
    return websockets_protocol_default_create();
}

static void harness_init(harness_t* h) {
    memset(&h->connection, 0, sizeof h->connection);
    memset(&h->ctx, 0, sizeof h->ctx);
    memset(h->buffer, 0, sizeof h->buffer);

    h->connection.buffer = (char*)h->buffer;
    h->connection.buffer_size = sizeof h->buffer;
    h->connection.ctx = &h->ctx;

    h->parser = websocketsparser_create(&h->connection, test_protocol_create);
}

static void harness_free(harness_t* h) {
    if (h->parser != NULL) {
        websocketsparser_free(h->parser);
        h->parser = NULL;
    }
}

/* Enable permessage-deflate on the parser (mirrors set_websockets_default). */
static void harness_enable_deflate(harness_t* h) {
    h->parser->ws_deflate_enabled = 1;
    TEST_ASSERT_EQUAL(1, ws_deflate_start(&h->parser->ws_deflate), "inflate stream initialized");
}

/* Feed bytes into the connection buffer and run the parser once. Mirrors the
 * connection read loop: a fresh read overwrites the buffer, pos rewinds. */
static int harness_feed(harness_t* h, const unsigned char* data, size_t size) {
    memcpy(h->buffer, data, size);
    websocketsparser_set_bytes_readed(h->parser, size);
    h->parser->pos_start = 0;
    h->parser->pos = 0;
    return websocketsparser_run(h->parser);
}

/* Read the reassembled data-frame payload back as a malloc'd string. */
static char* harness_payload(harness_t* h) {
    return websocketsrequest_payload(h->parser->request->protocol);
}

/* Release the current request the way the connection handler does after it has
 * taken ownership (reset/prepare_remains NULL the pointer without freeing, so
 * tests that drive those paths directly must hand off the request first). */
static void harness_release_request(harness_t* h) {
    if (h->parser->request != NULL) {
        websocketsrequest_free(h->parser->request);
        h->parser->request = NULL;
    }
}

/* Read the control-frame payload that the parser left in parser->buf. */
static const char* harness_control_payload(harness_t* h, size_t* out_size) {
    if (out_size != NULL) *out_size = bufferdata_writed(&h->parser->buf);
    return bufferdata_get(&h->parser->buf);
}

/* -------------------------------------------------------------------------- */
/* Frame builders (always masked, as client-to-server frames must be).        */
/* -------------------------------------------------------------------------- */

static const unsigned char DEFAULT_MASK[4] = {0x12, 0x34, 0x56, 0x78};

/* Build a masked frame. Returns the total wire size. */
static size_t build_frame_masked(unsigned char* out, int opcode, int fin, int rsv1,
                                 const unsigned char* payload, size_t payload_len,
                                 const unsigned char mask[4]) {
    size_t pos = 0;
    unsigned char b0 = (fin ? 0x80 : 0x00) | (rsv1 ? 0x40 : 0x00) | (opcode & 0x0F);
    out[pos++] = b0;

    if (payload_len < 126) {
        out[pos++] = 0x80 | (unsigned char)(payload_len & 0x7F);
    } else if (payload_len <= 0xFFFF) {
        out[pos++] = 0x80 | 126;
        out[pos++] = (unsigned char)((payload_len >> 8) & 0xFF);
        out[pos++] = (unsigned char)(payload_len & 0xFF);
    } else {
        out[pos++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--)
            out[pos++] = (unsigned char)((payload_len >> (i * 8)) & 0xFF);
    }

    memcpy(&out[pos], mask, 4);
    pos += 4;

    for (size_t i = 0; i < payload_len; i++)
        out[pos + i] = payload[i] ^ mask[i % 4];
    pos += payload_len;

    return pos;
}

static size_t build_frame(unsigned char* out, int opcode, int fin,
                          const unsigned char* payload, size_t payload_len) {
    return build_frame_masked(out, opcode, fin, 0, payload, payload_len, DEFAULT_MASK);
}

/* Build an UNMASKED frame (invalid from a client; used to exercise rejection). */
static size_t build_frame_unmasked(unsigned char* out, int opcode, int fin,
                                   const unsigned char* payload, size_t payload_len) {
    size_t pos = 0;
    out[pos++] = (fin ? 0x80 : 0x00) | (opcode & 0x0F);
    if (payload_len < 126) {
        out[pos++] = (unsigned char)(payload_len & 0x7F);
    } else if (payload_len <= 0xFFFF) {
        out[pos++] = 126;
        out[pos++] = (unsigned char)((payload_len >> 8) & 0xFF);
        out[pos++] = (unsigned char)(payload_len & 0xFF);
    }
    memcpy(&out[pos], payload, payload_len);
    pos += payload_len;
    return pos;
}

// ============================================================================
// Basic data-frame parsing
// ============================================================================

TEST(test_wsp_text_frame_small) {
    TEST_SUITE("websocketsparser: data frames");
    TEST_CASE("small TEXT frame decodes and unmaskes the payload");

    harness_t h;
    harness_init(&h);

    const unsigned char payload[] = "hello";
    unsigned char frame[64];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, payload, 5);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "single TEXT frame completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_NOT_NULL(out, "payload returned");
    TEST_ASSERT_EQUAL_SIZE(5, strlen(out), "payload length");
    TEST_ASSERT_STR_EQUAL("hello", out, "payload unmasked correctly");
    free(out);

    TEST_ASSERT_EQUAL(WEBSOCKETS_TEXT, h.parser->request->type, "request type is TEXT");
    TEST_ASSERT_EQUAL(1, h.parser->frame.fin, "fin recorded on frame");
    TEST_ASSERT_EQUAL(0, h.parser->frame.rsv1, "rsv1 clear for uncompressed");

    harness_free(&h);
}

TEST(test_wsp_binary_frame_small) {
    TEST_SUITE("websocketsparser: data frames");
    TEST_CASE("BINARY frame carries arbitrary bytes including NUL");

    harness_t h;
    harness_init(&h);

    const unsigned char payload[] = {0x00, 0x01, 0x02, 0xFF, 0x00, 'A'};
    unsigned char frame[64];
    size_t frame_size = build_frame(frame, WSOPCODE_BINARY, 1, payload, sizeof payload);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "BINARY frame completes");

    /* BINARY payload may contain NUL bytes; read it back raw via the fd. */
    file_content_t fc = websocketsrequest_payload_file(h.parser->request->protocol);
    TEST_ASSERT_EQUAL(1, fc.ok, "payload file is valid");
    TEST_ASSERT_EQUAL_SIZE(sizeof payload, fc.size, "payload size matches");
    char buf[16];
    ssize_t n = pread(fc.fd, buf, fc.size, 0);
    TEST_ASSERT_EQUAL((int)sizeof payload, (int)n, "read payload bytes");
    TEST_ASSERT_EQUAL(0, memcmp(buf, payload, sizeof payload), "binary payload intact");

    harness_free(&h);
}

TEST(test_wsp_empty_text_frame) {
    TEST_SUITE("websocketsparser: data frames");
    TEST_CASE("empty TEXT frame (payload_length=0, fin=1) completes");

    harness_t h;
    harness_init(&h);

    unsigned char frame[16];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, NULL, 0);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "empty frame completes");
    TEST_ASSERT_NOT_NULL(h.parser->request, "request created for empty data frame");
    TEST_ASSERT_EQUAL(WEBSOCKETS_TEXT, h.parser->request->type, "type is TEXT");

    harness_free(&h);
}

// ============================================================================
// Validation / rejection
// ============================================================================

TEST(test_wsp_unknown_opcode_rejected) {
    TEST_SUITE("websocketsparser: validation");
    TEST_CASE("reserved opcode 0x03 is BAD_REQUEST (RFC 6455 §5.2)");

    harness_t h;
    harness_init(&h);

    unsigned char frame[32];
    size_t frame_size = build_frame(frame, 0x03, 1, (const unsigned char*)"x", 1);

    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, frame_size), "unknown opcode rejected");
    TEST_ASSERT_NULL(h.parser->request, "no request left after failure");

    harness_free(&h);
}

TEST(test_wsp_high_opcode_rejected) {
    TEST_SUITE("websocketsparser: validation");
    TEST_CASE("opcode 0x0B (reserved) is BAD_REQUEST");

    harness_t h;
    harness_init(&h);

    unsigned char frame[32];
    size_t frame_size = build_frame(frame, 0x0B, 1, NULL, 0);

    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, frame_size), "0x0B rejected");

    harness_free(&h);
}

TEST(test_wsp_rsv2_rsv3_rejected) {
    TEST_SUITE("websocketsparser: validation");
    TEST_CASE("RSV2 and RSV3 must be zero");

    harness_t h;
    harness_init(&h);

    /* RSV2 set (0x20). */
    unsigned char frame[32];
    size_t frame_size = build_frame_masked(frame, WSOPCODE_TEXT, 1, 0, (const unsigned char*)"x", 1, DEFAULT_MASK);
    frame[0] |= 0x20;
    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, frame_size), "RSV2 rejected");

    /* RSV3 set (0x10). */
    harness_free(&h);
    harness_init(&h);
    frame_size = build_frame(frame, WSOPCODE_TEXT, 1, (const unsigned char*)"x", 1);
    frame[0] |= 0x10;
    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, frame_size), "RSV3 rejected");

    harness_free(&h);
}

TEST(test_wsp_unmasked_rejected) {
    TEST_SUITE("websocketsparser: validation");
    TEST_CASE("client-to-server frame must be masked");

    harness_t h;
    harness_init(&h);

    unsigned char frame[32];
    size_t frame_size = build_frame_unmasked(frame, WSOPCODE_TEXT, 1, (const unsigned char*)"x", 1);

    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, frame_size), "unmasked frame rejected");

    harness_free(&h);
}

TEST(test_wsp_rsv1_without_deflate_rejected) {
    TEST_SUITE("websocketsparser: validation");
    TEST_CASE("RSV1 (permessage-deflate) without negotiated extension is rejected");

    harness_t h;
    harness_init(&h);

    unsigned char frame[32];
    size_t frame_size = build_frame_masked(frame, WSOPCODE_TEXT, 1, 1, (const unsigned char*)"x", 1, DEFAULT_MASK);

    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, frame_size), "RSV1 rejected when deflate off");

    harness_free(&h);
}

// ============================================================================
// Extended payload lengths (126 / 127)
// ============================================================================

TEST(test_wsp_length_126) {
    TEST_SUITE("websocketsparser: lengths");
    TEST_CASE("payload_length=126 path decodes a 300-byte payload");

    harness_t h;
    harness_init(&h);

    const size_t len = 300;
    unsigned char* payload = malloc(len);
    TEST_REQUIRE_NOT_NULL(payload, "payload alloc");
    for (size_t i = 0; i < len; i++) payload[i] = (unsigned char)(i & 0xFF);

    unsigned char frame[512];
    size_t frame_size = build_frame(frame, WSOPCODE_BINARY, 1, payload, len);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "126-length frame completes");

    /* Payload contains NUL bytes (i & 0xFF); read it back raw via the fd. */
    file_content_t fc = websocketsrequest_payload_file(h.parser->request->protocol);
    TEST_ASSERT_EQUAL(1, fc.ok, "payload file valid");
    TEST_ASSERT_EQUAL_SIZE(len, fc.size, "payload size");
    unsigned char verify[300];
    ssize_t n = pread(fc.fd, verify, len, 0);
    TEST_ASSERT_EQUAL((int)len, (int)n, "read payload bytes");
    TEST_ASSERT_EQUAL(0, memcmp(verify, payload, len), "126-length payload intact");

    free(payload);
    harness_free(&h);
}

TEST(test_wsp_length_127) {
    TEST_SUITE("websocketsparser: lengths");
    TEST_CASE("payload_length=127 path decodes a 70000-byte payload across reads");

    harness_t h;
    harness_init(&h);

    /* A genuine 127-encoded frame (>65535 bytes) cannot fit in one connection
     * buffer, so it arrives in two reads exactly as in production. This also
     * exercises mask-key continuity over a very large payload. */
    const size_t len = 70000;
    /* Allocate every scratch buffer up front and guard them with one check so
     * the test never returns mid-function with a prior allocation still live
     * (the framework's TEST_REQUIRE* macros return early on failure). */
    unsigned char* payload = malloc(len);
    unsigned char* frame = malloc(len + 32);
    unsigned char* verify = malloc(len);
    if (payload == NULL || frame == NULL || verify == NULL) {
        free(payload);
        free(frame);
        free(verify);
        harness_free(&h);
        TEST_REQUIRE(0, "payload/frame/verify alloc");
        return;
    }

    for (size_t i = 0; i < len; i++) payload[i] = (unsigned char)((i * 7) & 0xFF);

    size_t frame_size = build_frame(frame, WSOPCODE_BINARY, 1, payload, len);
    TEST_ASSERT_EQUAL_SIZE(10 + 4 + len, frame_size, "127 frame layout (2+8 len, mask, payload)");

    size_t split = 40000; /* within the payload */
    TEST_ASSERT_EQUAL(WSPARSER_CONTINUE, harness_feed(&h, frame, split), "first chunk -> continue");
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame + split, frame_size - split), "rest -> complete");

    file_content_t fc = websocketsrequest_payload_file(h.parser->request->protocol);
    TEST_ASSERT_EQUAL(1, fc.ok, "payload file valid");
    TEST_ASSERT_EQUAL_SIZE(len, fc.size, "payload size");
    ssize_t total = 0;
    while ((size_t)total < len) {
        ssize_t n = pread(fc.fd, verify + total, len - total, total);
        TEST_ASSERT(n > 0, "pread payload");
        total += n;
    }
    TEST_ASSERT_EQUAL(0, memcmp(verify, payload, len), "127-length payload intact");

    free(verify);
    free(payload);
    free(frame);
    harness_free(&h);
}

TEST(test_wsp_control_frame_oversized_rejected) {
    TEST_SUITE("websocketsparser: lengths");
    TEST_CASE("control frame with payload_length 126 is BAD_REQUEST");

    harness_t h;
    harness_init(&h);

    /* Hand-build a PING frame whose second byte claims 126. */
    unsigned char frame[16] = {0};
    frame[0] = 0x80 | WSOPCODE_PING;   /* fin=1, PING */
    frame[1] = 0x80 | 126;             /* masked, 126 -> needs 2 length bytes */
    frame[2] = 0x01;                   /* length = 256 (control max is 125) */
    frame[3] = 0x00;
    memcpy(&frame[4], DEFAULT_MASK, 4);

    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, 8), "oversized control frame rejected");

    harness_free(&h);
}

// ============================================================================
// Control frames
// ============================================================================

TEST(test_wsp_ping_with_payload) {
    TEST_SUITE("websocketsparser: control frames");
    TEST_CASE("PING payload is unmasked into parser->buf");

    harness_t h;
    harness_init(&h);

    const unsigned char payload[] = "heartbeat";
    unsigned char frame[64];
    size_t frame_size = build_frame(frame, WSOPCODE_PING, 1, payload, 9);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "PING completes");
    TEST_ASSERT_NULL(h.parser->request, "control frame creates no request");

    size_t size = 0;
    const char* out = harness_control_payload(&h, &size);
    TEST_ASSERT_EQUAL_SIZE(9, size, "PING payload size");
    TEST_ASSERT_EQUAL(0, memcmp(out, payload, 9), "PING payload unmasked");
    TEST_ASSERT_EQUAL(WSOPCODE_PING, h.parser->frame.opcode, "opcode recorded");

    harness_free(&h);
}

TEST(test_wsp_pong_close_handled) {
    TEST_SUITE("websocketsparser: control frames");
    TEST_CASE("PONG and CLOSE complete without a request");

    harness_t h;
    harness_init(&h);

    unsigned char frame[32];
    size_t frame_size = build_frame(frame, WSOPCODE_PONG, 1, NULL, 0);
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "empty PONG completes");

    harness_free(&h);
    harness_init(&h);

    /* CLOSE with a 2-byte status code payload (RFC 6455 §7.4). */
    const unsigned char close_payload[] = {0x03, 0xE8}; /* 1000 */
    frame_size = build_frame(frame, WSOPCODE_CLOSE, 1, close_payload, 2);
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "CLOSE completes");

    size_t size = 0;
    const char* out = harness_control_payload(&h, &size);
    TEST_ASSERT_EQUAL_SIZE(2, size, "CLOSE payload size");
    TEST_ASSERT_EQUAL(0, memcmp(out, close_payload, 2), "CLOSE payload unmasked");

    harness_free(&h);
}

TEST(test_wsp_control_non_final_rejected) {
    TEST_SUITE("websocketsparser: control frames");
    TEST_CASE("control frame with fin=0 is BAD_REQUEST (§5.5)");

    harness_t h;
    harness_init(&h);

    unsigned char frame[32];
    size_t frame_size = build_frame(frame, WSOPCODE_PING, 0, (const unsigned char*)"x", 1);

    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, frame_size), "non-final control frame rejected");

    harness_free(&h);
}

TEST(test_wsp_control_max_payload_125) {
    TEST_SUITE("websocketsparser: control frames");
    TEST_CASE("control frame with a 125-byte payload (the RFC maximum) works");

    harness_t h;
    harness_init(&h);

    unsigned char payload[125];
    for (int i = 0; i < 125; i++) payload[i] = (unsigned char)(i + 1);

    unsigned char frame[256];
    size_t frame_size = build_frame(frame, WSOPCODE_PING, 1, payload, sizeof payload);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "125-byte PING completes");

    size_t size = 0;
    const char* out = harness_control_payload(&h, &size);
    TEST_ASSERT_EQUAL_SIZE(125, size, "full control payload");
    TEST_ASSERT_EQUAL(0, memcmp(out, payload, 125), "control payload intact");

    harness_free(&h);
}

// ============================================================================
// Fragmentation
// ============================================================================

TEST(test_wsp_fragmented_text_reassembles) {
    TEST_SUITE("websocketsparser: fragmentation");
    TEST_CASE("TEXT(fin=0) + CONTINUE(fin=1) reassembles into one message");

    harness_t h;
    harness_init(&h);

    /* Split "Hello, world!" into two fragments, second fragment in a separate
     * feed so each frame is its own read. */
    const unsigned char part1[] = "Hello, ";
    const unsigned char part2[] = "world!";

    unsigned char f1[32], f2[32];
    size_t f1_size = build_frame(f1, WSOPCODE_TEXT, 0, part1, 7);
    size_t f2_size = build_frame(f2, WSOPCODE_CONTINUE, 1, part2, 6);

    TEST_ASSERT_EQUAL(WSPARSER_HANDLE_AND_CONTINUE, harness_feed(&h, f1, f1_size), "first fragment handled, expects more");
    TEST_ASSERT_EQUAL(1, h.parser->message_fragmented, "message flagged as fragmented");
    TEST_ASSERT_EQUAL(1, h.parser->request->fragmented, "request flagged as fragmented");
    websocketsparser_prepare_remains(h.parser); /* connection layer between frames */

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, f2, f2_size), "final fragment completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_NOT_NULL(out, "payload returned");
    TEST_ASSERT_STR_EQUAL("Hello, world!", out, "fragments reassembled in order");
    TEST_ASSERT_EQUAL(WEBSOCKETS_TEXT, h.parser->request->type, "type stays TEXT across fragments");
    free(out);

    harness_free(&h);
}

TEST(test_wsp_orphan_continuation_rejected) {
    TEST_SUITE("websocketsparser: fragmentation");
    TEST_CASE("CONTINUE without an open fragmented message is BAD_REQUEST");

    harness_t h;
    harness_init(&h);

    unsigned char frame[32];
    size_t frame_size = build_frame(frame, WSOPCODE_CONTINUE, 1, (const unsigned char*)"x", 1);

    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, frame, frame_size), "orphan continuation rejected");

    harness_free(&h);
}

TEST(test_wsp_new_data_frame_while_fragmented_rejected) {
    TEST_SUITE("websocketsparser: fragmentation");
    TEST_CASE("a new TEXT frame while a fragmented message is open is BAD_REQUEST");

    harness_t h;
    harness_init(&h);

    const unsigned char part1[] = "abc";
    unsigned char f1[32], f2[32];
    size_t f1_size = build_frame(f1, WSOPCODE_TEXT, 0, part1, 3);
    size_t f2_size = build_frame(f2, WSOPCODE_TEXT, 1, part1, 3); /* new TEXT, not CONTINUE */

    TEST_ASSERT_EQUAL(WSPARSER_HANDLE_AND_CONTINUE, harness_feed(&h, f1, f1_size), "first fragment opens message");
    websocketsparser_prepare_remains(h.parser);
    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, f2, f2_size), "second TEXT rejected mid-message");

    harness_free(&h);
}

TEST(test_wsp_continuation_rsv1_rejected) {
    TEST_SUITE("websocketsparser: fragmentation");
    TEST_CASE("RSV1 on a continuation frame is BAD_REQUEST (RFC 7692 §7.2)");

    harness_t h;
    harness_init(&h);
    harness_enable_deflate(&h);

    const unsigned char part1[] = "abc";
    unsigned char f1[32], f2[32];
    size_t f1_size = build_frame_masked(f1, WSOPCODE_TEXT, 0, 1, part1, 3, DEFAULT_MASK);
    size_t f2_size = build_frame_masked(f2, WSOPCODE_CONTINUE, 1, 1, part1, 3, DEFAULT_MASK);

    /* First compressed fragment is accepted (RSV1 valid on first frame). */
    TEST_ASSERT(WSPARSER_HANDLE_AND_CONTINUE == harness_feed(&h, f1, f1_size) ||
                WSPARSER_COMPLETE == harness_feed(&h, f1, f1_size), "first frame accepted");

    /* Continuation with RSV1 set must be rejected. Re-init since the first feed
     * may have completed/cleared state. */
    harness_free(&h);
    harness_init(&h);
    harness_enable_deflate(&h);
    TEST_ASSERT_EQUAL(WSPARSER_HANDLE_AND_CONTINUE, harness_feed(&h, f1, f1_size), "open fragmented message");
    websocketsparser_prepare_remains(h.parser);
    TEST_ASSERT_EQUAL(WSPARSER_BAD_REQUEST, harness_feed(&h, f2, f2_size), "RSV1 on continuation rejected");

    harness_free(&h);
}

TEST(test_wsp_interleaved_control_frame) {
    TEST_SUITE("websocketsparser: fragmentation");
    TEST_CASE("a PING between fragments is handled and the message resumes");

    harness_t h;
    harness_init(&h);

    const unsigned char part1[] = "foo";
    const unsigned char part2[] = "bar";
    const unsigned char ping[] = "Z";

    unsigned char f1[32], ping_frame[32], f2[32];
    size_t f1_size = build_frame(f1, WSOPCODE_TEXT, 0, part1, 3);
    size_t ping_size = build_frame(ping_frame, WSOPCODE_PING, 1, ping, 1);
    size_t f2_size = build_frame(f2, WSOPCODE_CONTINUE, 1, part2, 3);

    TEST_ASSERT_EQUAL(WSPARSER_HANDLE_AND_CONTINUE, harness_feed(&h, f1, f1_size), "fragment 1 handled");
    websocketsparser_prepare_remains(h.parser);
    /* Interleaved PING: the control frame itself is fin=1, but it must NOT take
     * the COMPLETE path (which would reset and drop the open fragmented data
     * message), so the parser routes it through HANDLE_AND_CONTINUE while a
     * message is fragmented. */
    TEST_ASSERT_EQUAL(WSPARSER_HANDLE_AND_CONTINUE, harness_feed(&h, ping_frame, ping_size), "PING handled mid-message");
    websocketsparser_prepare_remains(h.parser);
    TEST_ASSERT_EQUAL(1, h.parser->message_fragmented, "fragmented flag survives interleaved control frame");
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, f2, f2_size), "final fragment completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_NOT_NULL(out, "payload returned");
    TEST_ASSERT_STR_EQUAL("foobar", out, "data message reassembled around the PING");
    free(out);

    harness_free(&h);
}

// ============================================================================
// Body-size limit
// ============================================================================

TEST(test_wsp_payload_over_limit) {
    TEST_SUITE("websocketsparser: limits");
    TEST_CASE("payload over client_max_body_size is PAYLOAD_LARGE");

    harness_t h;
    harness_init(&h);

    const unsigned int saved = env()->main.client_max_body_size;
    env()->main.client_max_body_size = 8;

    unsigned char payload[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    unsigned char frame[64];
    size_t frame_size = build_frame(frame, WSOPCODE_BINARY, 1, payload, 10);

    TEST_ASSERT_EQUAL(WSPARSER_PAYLOAD_LARGE, harness_feed(&h, frame, frame_size), "oversized payload rejected");

    env()->main.client_max_body_size = saved;
    harness_free(&h);
}

TEST(test_wsp_payload_exact_limit_allowed) {
    TEST_SUITE("websocketsparser: limits");
    TEST_CASE("payload exactly at client_max_body_size is accepted");

    harness_t h;
    harness_init(&h);

    const unsigned int saved = env()->main.client_max_body_size;
    env()->main.client_max_body_size = 5;

    const unsigned char payload[] = "abcde";
    unsigned char frame[32];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, payload, 5);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "payload at the limit completes");

    env()->main.client_max_body_size = saved;
    harness_free(&h);
}

// ============================================================================
// Streaming UTF-8 validation
// ============================================================================

TEST(test_wsp_text_invalid_utf8_rejected) {
    TEST_SUITE("websocketsparser: utf-8");
    TEST_CASE("TEXT frame with an invalid UTF-8 sequence fails the frame");

    harness_t h;
    harness_init(&h);

    /* Lone continuation byte 0x80 is invalid UTF-8. */
    const unsigned char bad[] = {'a', 0x80, 'b'};
    unsigned char frame[32];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, bad, sizeof bad);

    TEST_ASSERT_EQUAL(WSPARSER_ERROR, harness_feed(&h, frame, frame_size), "invalid UTF-8 TEXT rejected");

    harness_free(&h);
}

TEST(test_wsp_binary_invalid_utf8_accepted) {
    TEST_SUITE("websocketsparser: utf-8");
    TEST_CASE("BINARY frame is not subject to UTF-8 validation");

    harness_t h;
    harness_init(&h);

    const unsigned char raw[] = {'a', 0x80, 0xFF, 0xC0};
    unsigned char frame[32];
    size_t frame_size = build_frame(frame, WSOPCODE_BINARY, 1, raw, sizeof raw);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "binary with non-UTF-8 accepted");

    harness_free(&h);
}

TEST(test_wsp_text_multibyte_valid) {
    TEST_SUITE("websocketsparser: utf-8");
    TEST_CASE("valid multibyte TEXT (Cyrillic + emoji) is accepted");

    harness_t h;
    harness_init(&h);

    /* "Привет 😀" — Cyrillic (2-byte) + space + emoji (4-byte). */
    const unsigned char text[] = "Привет 😀";
    unsigned char frame[64];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, text, sizeof text - 1);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "valid multibyte TEXT completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_EQUAL_SIZE(sizeof text - 1, strlen(out), "payload length");
    TEST_ASSERT_EQUAL(0, memcmp(out, text, sizeof text - 1), "payload intact");
    free(out);

    harness_free(&h);
}

TEST(test_wsp_text_split_utf8_across_fragments) {
    TEST_SUITE("websocketsparser: utf-8");
    TEST_CASE("a multi-byte sequence split across fragments validates");

    harness_t h;
    harness_init(&h);

    /* U+041F 'П' = D0 9F. Split between the two bytes across two fragments. */
    const unsigned char p1[] = {0xD0};
    const unsigned char p2[] = {0x9F, '!'};

    unsigned char f1[16], f2[16];
    size_t f1_size = build_frame(f1, WSOPCODE_TEXT, 0, p1, 1);
    size_t f2_size = build_frame(f2, WSOPCODE_CONTINUE, 1, p2, 2);

    TEST_ASSERT_EQUAL(WSPARSER_HANDLE_AND_CONTINUE, harness_feed(&h, f1, f1_size), "first byte of codepoint");
    websocketsparser_prepare_remains(h.parser);
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, f2, f2_size), "codepoint completed");

    char* out = harness_payload(&h);
    TEST_ASSERT_EQUAL_SIZE(3, strlen(out), "reassembled size");
    TEST_ASSERT_EQUAL(0, memcmp(out, "\xD0\x9F!", 3), "split codepoint intact");
    free(out);

    harness_free(&h);
}

TEST(test_wsp_text_dangling_sequence_rejected) {
    TEST_SUITE("websocketsparser: utf-8");
    TEST_CASE("TEXT message ending mid-codepoint is rejected at finish()");

    harness_t h;
    harness_init(&h);

    /* A 2-byte lead with no continuation. */
    const unsigned char dangling[] = {'a', 0xC2};
    unsigned char frame[32];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, dangling, sizeof dangling);

    TEST_ASSERT_EQUAL(WSPARSER_ERROR, harness_feed(&h, frame, frame_size), "dangling sequence rejected at finish");

    harness_free(&h);
}

// ============================================================================
// Mask-key continuity across split reads
// ============================================================================

TEST(test_wsp_mask_continues_across_split_read) {
    TEST_SUITE("websocketsparser: mask");
    TEST_CASE("XOR keystream continues when one frame spans two reads");

    harness_t h;
    harness_init(&h);

    /* One TEXT frame with a 10-byte payload, delivered in two reads split at 5
     * (not a multiple of the 4-byte mask). The mask keystream must resume at
     * key offset 5 % 4 = 1 for the second chunk. */
    const unsigned char payload[] = "0123456789";
    unsigned char frame[64];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, payload, 10);

    /* header(2) + mask(4) + first 3 payload bytes */
    size_t split = 2 + 4 + 3;
    TEST_ASSERT_EQUAL(WSPARSER_CONTINUE, harness_feed(&h, frame, split), "partial frame needs more");

    /* Remaining masked payload bytes; buffer is overwritten, pos rewinds. */
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame + split, frame_size - split), "rest of frame completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_STR_EQUAL("0123456789", out, "payload unmasked with a continuous keystream");
    free(out);

    harness_free(&h);
}

TEST(test_wsp_payload_split_inside_header) {
    TEST_SUITE("websocketsparser: mask");
    TEST_CASE("a frame split inside the header continues into the payload");

    harness_t h;
    harness_init(&h);

    const unsigned char payload[] = "ABCDEF";
    unsigned char frame[64];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, payload, 6);

    /* Only the first byte (FIRST_BYTE stage) arrives, then the rest. */
    TEST_ASSERT_EQUAL(WSPARSER_CONTINUE, harness_feed(&h, frame, 1), "first byte only -> continue");
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame + 1, frame_size - 1), "rest of frame completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_STR_EQUAL("ABCDEF", out, "header split across reads still decodes");
    free(out);

    harness_free(&h);
}

// ============================================================================
// Pipelined frames
// ============================================================================

TEST(test_wsp_pipelined_frames) {
    TEST_SUITE("websocketsparser: pipelining");
    TEST_CASE("two frames in one buffer: first HANDLE_AND_CONTINUE, second COMPLETE");

    harness_t h;
    harness_init(&h);

    const unsigned char a[] = "first";
    const unsigned char b[] = "second";
    unsigned char f1[32], f2[32];
    size_t f1_size = build_frame(f1, WSOPCODE_TEXT, 1, a, 5);
    size_t f2_size = build_frame(f2, WSOPCODE_BINARY, 1, b, 6);

    unsigned char both[64];
    memcpy(both, f1, f1_size);
    memcpy(both + f1_size, f2, f2_size);

    /* First run: completes frame 1 and reports pipelined data behind it. */
    TEST_ASSERT_EQUAL(WSPARSER_HANDLE_AND_CONTINUE, harness_feed(&h, both, f1_size + f2_size), "frame 1 with pipelined frame 2");

    /* The handler would dispatch frame 1 here, then prepare_remains to resume.
     * Simulate that: hand off frame 1's request, shift the remaining bytes to
     * the front of the connection buffer and run again. */
    size_t consumed = h.parser->pos;
    TEST_ASSERT_EQUAL(f1_size, consumed, "pos advanced past frame 1");
    harness_release_request(&h); /* handler took ownership of frame 1 */
    websocketsparser_prepare_remains(h.parser);

    /* Move the remains to the front of the parser's own buffer (the connection
     * reads into offset 0). */
    memmove(h.buffer, h.buffer + consumed, f2_size);
    websocketsparser_set_bytes_readed(h.parser, f2_size);
    h.parser->pos_start = 0;
    h.parser->pos = 0;
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, websocketsparser_run(h.parser), "frame 2 completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_STR_EQUAL("second", out, "second frame's payload decoded");
    free(out);

    harness_free(&h);
}

// ============================================================================
// permessage-deflate
// ============================================================================

TEST(test_wsp_compressed_text_roundtrip) {
    TEST_SUITE("websocketsparser: deflate");
    TEST_CASE("compressed TEXT frame decompresses to the original payload");

    harness_t h;
    harness_init(&h);
    harness_enable_deflate(&h);

    const char* text = "Hello, compressed WebSocket world! Hello, compressed WebSocket world!";
    const size_t text_len = strlen(text);

    /* Compress with the client's deflate context (trailer stripped, matching
     * what a client sends and what the parser re-appends). */
    ws_deflate_t client;
    ws_deflate_init(&client);
    TEST_ASSERT_EQUAL(1, ws_deflate_start(&client), "client deflate started");

    unsigned char compressed[256];
    ssize_t compressed_len = ws_deflate_compress(&client, text, text_len, (char*)compressed, sizeof compressed, 1);
    TEST_ASSERT(compressed_len > 0, "compress produced output");

    unsigned char frame[512];
    size_t frame_size = build_frame_masked(frame, WSOPCODE_TEXT, 1, 1, compressed, (size_t)compressed_len, DEFAULT_MASK);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "compressed frame completes");
    TEST_ASSERT_EQUAL(1, h.parser->request->compressed, "request flagged compressed");

    char* out = harness_payload(&h);
    TEST_ASSERT_EQUAL_SIZE(text_len, strlen(out), "decompressed length");
    TEST_ASSERT_STR_EQUAL(text, out, "decompressed payload matches");
    free(out);

    ws_deflate_free(&client);
    harness_free(&h);
}

TEST(test_wsp_compressed_large_forces_chunked_inflate) {
    TEST_SUITE("websocketsparser: deflate");
    TEST_CASE("payload decompressing to >16KB exercises the inflate loop");

    harness_t h;
    harness_init(&h);
    harness_enable_deflate(&h);

    /* Build highly repetitive text > 16KB so it both compresses tiny and
     * decompresses past one WS_DEFLATE_BUFFER_SIZE (16384) window. */
    const size_t text_len = 40000;
    char* text = malloc(text_len + 1);
    TEST_REQUIRE_NOT_NULL(text, "text alloc");
    for (size_t i = 0; i < text_len; i++) text[i] = (char)('A' + (i % 26));
    text[text_len] = 0;

    ws_deflate_t client;
    ws_deflate_init(&client);
    TEST_ASSERT_EQUAL(1, ws_deflate_start(&client), "client deflate started");

    unsigned char compressed[2048];
    ssize_t compressed_len = ws_deflate_compress(&client, text, text_len, (char*)compressed, sizeof compressed, 1);
    TEST_ASSERT(compressed_len > 0, "compress produced output");
    TEST_ASSERT((size_t)compressed_len < sizeof compressed, "compressed fits (sanity)");

    unsigned char frame[4096];
    size_t frame_size = build_frame_masked(frame, WSOPCODE_TEXT, 1, 1, compressed, (size_t)compressed_len, DEFAULT_MASK);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "large compressed frame completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_EQUAL_SIZE(text_len, strlen(out), "decompressed length");
    TEST_ASSERT_EQUAL(0, memcmp(out, text, text_len), "decompressed payload matches");
    free(out);

    free(text);
    ws_deflate_free(&client);
    harness_free(&h);
}

TEST(test_wsp_compressed_split_across_reads) {
    TEST_SUITE("websocketsparser: deflate");
    TEST_CASE("compressed frame split across reads keeps the inflate backlog");

    harness_t h;
    harness_init(&h);
    harness_enable_deflate(&h);

    const char* text = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
    const size_t text_len = strlen(text);

    ws_deflate_t client;
    ws_deflate_init(&client);
    TEST_ASSERT_EQUAL(1, ws_deflate_start(&client), "client deflate started");

    unsigned char compressed[256];
    ssize_t compressed_len = ws_deflate_compress(&client, text, text_len, (char*)compressed, sizeof compressed, 1);
    TEST_ASSERT(compressed_len > 0, "compress produced output");

    unsigned char frame[512];
    size_t frame_size = build_frame_masked(frame, WSOPCODE_TEXT, 1, 1, compressed, (size_t)compressed_len, DEFAULT_MASK);

    /* Split inside the compressed payload: header(2)+mask(4)+half compressed. */
    size_t header = 2 + 4;
    size_t split = header + (size_t)compressed_len / 2;
    TEST_ASSERT_EQUAL(WSPARSER_CONTINUE, harness_feed(&h, frame, split), "partial compressed frame -> continue");
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame + split, frame_size - split), "rest completes");

    char* out = harness_payload(&h);
    TEST_ASSERT_EQUAL_SIZE(text_len, strlen(out), "decompressed length");
    TEST_ASSERT_STR_EQUAL(text, out, "split compressed frame decompresses");
    free(out);

    ws_deflate_free(&client);
    harness_free(&h);
}

TEST(test_wsp_compressed_two_messages_context_takeover) {
    TEST_SUITE("websocketsparser: deflate");
    TEST_CASE("two compressed messages decode with context takeover (default)");

    harness_t h;
    harness_init(&h);
    harness_enable_deflate(&h);

    /* Default config: client_no_context_takeover=0, so the parser must keep the
     * inflate stream across messages. The client reuses its deflate stream too,
     * so the second message's bytes only decode with the prior context. */
    ws_deflate_t client;
    ws_deflate_init(&client);
    TEST_ASSERT_EQUAL(1, ws_deflate_start(&client), "client deflate started");

    const char* msgs[] = {"first compressed message with repetitive text text text",
                          "second compressed message with repetitive text text text"};
    const size_t lens[] = {strlen(msgs[0]), strlen(msgs[1])};

    for (int i = 0; i < 2; i++) {
        unsigned char compressed[256];
        ssize_t clen = ws_deflate_compress(&client, msgs[i], lens[i], (char*)compressed, sizeof compressed, 1);
        TEST_ASSERT(clen > 0, "compress produced output");

        unsigned char frame[512];
        size_t frame_size = build_frame_masked(frame, WSOPCODE_TEXT, 1, 1, compressed, (size_t)clen, DEFAULT_MASK);

        TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "message completes");

        char* out = harness_payload(&h);
        TEST_ASSERT_EQUAL_SIZE(lens[i], strlen(out), "decompressed length");
        TEST_ASSERT_EQUAL(0, memcmp(out, msgs[i], lens[i]), "decompressed payload matches");
        free(out);

        /* Reset the parser between messages like the connection layer does. */
        harness_release_request(&h); /* handler took ownership */
        websocketsparser_reset(h.parser);
    }

    ws_deflate_free(&client);
    harness_free(&h);
}

TEST(test_wsp_compressed_invalid_data_rejected) {
    TEST_SUITE("websocketsparser: deflate");
    TEST_CASE("garbage compressed payload fails the frame");

    harness_t h;
    harness_init(&h);
    harness_enable_deflate(&h);

    /* Bytes that are not a valid raw-deflate stream. */
    const unsigned char garbage[] = {0xFF, 0xFE, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    unsigned char frame[64];
    size_t frame_size = build_frame_masked(frame, WSOPCODE_TEXT, 1, 1, garbage, sizeof garbage, DEFAULT_MASK);

    TEST_ASSERT_EQUAL(WSPARSER_ERROR, harness_feed(&h, frame, frame_size), "invalid compressed data rejected");

    harness_free(&h);
}

// ============================================================================
// Reset / lifecycle
// ============================================================================

TEST(test_wsp_reset_clears_state) {
    TEST_SUITE("websocketsparser: lifecycle");
    TEST_CASE("reset returns the parser to the FIRST_BYTE stage cleanly");

    harness_t h;
    harness_init(&h);

    const unsigned char payload[] = "temp";
    unsigned char frame[32];
    size_t frame_size = build_frame(frame, WSOPCODE_TEXT, 1, payload, 4);

    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "first frame completes");
    TEST_ASSERT_NOT_NULL(h.parser->request, "request present before reset");

    harness_release_request(&h); /* handler took ownership */
    websocketsparser_reset(h.parser);
    TEST_ASSERT_EQUAL(WSPARSER_STAGE_FIRST_BYTE, h.parser->stage, "stage reset");
    TEST_ASSERT_NULL(h.parser->request, "request dropped on reset");
    TEST_ASSERT_EQUAL(0, h.parser->message_fragmented, "fragmented flag cleared");

    /* The parser must be reusable after reset. */
    TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, harness_feed(&h, frame, frame_size), "second frame after reset completes");
    char* out = harness_payload(&h);
    TEST_ASSERT_STR_EQUAL("temp", out, "payload after reset");
    free(out);

    harness_free(&h);
}

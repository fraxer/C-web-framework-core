#include "framework.h"
#include "h2frame.h"

#include <stdlib.h>
#include <string.h>

/* A fixed-capacity list of decoded frames with owned payload copies. The
 * parser's payload borrow is invalidated by the next feed, so tests deep-copy
 * at FRAME_READY. The fixed array lets -fanalyzer prove indexing stays in bounds. */
#define H2F_MAX_FRAMES 8

typedef struct {
    uint32_t length;
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream_id;
    uint8_t* payload;
    size_t   payload_len;
} collected_t;

typedef struct {
    int count;
    collected_t f[H2F_MAX_FRAMES];
} frame_list_t;

static void frame_list_free(frame_list_t* l) {
    for (int i = 0; i < l->count; i++) free(l->f[i].payload);
    l->count = 0;
}

static void put_header(uint8_t* h, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid) {
    h[0] = (uint8_t)(len >> 16); h[1] = (uint8_t)(len >> 8); h[2] = (uint8_t)len;
    h[3] = type; h[4] = flags;
    h[5] = (uint8_t)((sid >> 24) & 0x7f); h[6] = (uint8_t)(sid >> 16);
    h[7] = (uint8_t)(sid >> 8); h[8] = (uint8_t)sid;
}

/* Feed `buf` in `chunk`-sized pieces, appending decoded frames to `list`.
 * Returns the total frame count, or -1 on a parser error. */
static int feed_chunked(int preface, const uint8_t* buf, size_t len, size_t chunk,
                        frame_list_t* list) {
    h2frame_parser_t p;
    h2frame_parser_init(&p, preface, H2_MAX_FRAME_SIZE_DEFAULT);
    size_t off = 0;
    int total = 0;
    while (off < len) {
        size_t take = len - off;
        if (chunk && take > chunk) take = chunk;
        const uint8_t* pp = buf + off;
        const uint8_t* end = pp + take;
        while (pp < end) {
            h2parse_status_e s = h2frame_parser_feed(&p, &pp, end);
            if (s == H2PARSE_FRAME_READY) {
                if (list->count < H2F_MAX_FRAMES) {
                    h2_frame_t f;
                    h2frame_parser_get(&p, &f);
                    collected_t* c = &list->f[list->count];
                    c->length = f.length; c->type = f.type;
                    c->flags = f.flags; c->stream_id = f.stream_id;
                    c->payload_len = f.payload_len;
                    c->payload = malloc(f.payload_len ? f.payload_len : 1);
                    if (c->payload == NULL) { h2frame_parser_free(&p); return -1; }
                    memcpy(c->payload, f.payload, f.payload_len);
                    list->count++;
                }
                total++;
            } else if (s == H2PARSE_CONTINUE) {
                break;
            } else {
                h2frame_parser_free(&p);
                return -1;
            }
        }
        off += take;
    }
    h2frame_parser_free(&p);
    return total;
}

static int frames_equal(const collected_t* a, const collected_t* b) {
    if (a->length != b->length || a->type != b->type || a->flags != b->flags ||
        a->stream_id != b->stream_id || a->payload_len != b->payload_len)
        return 0;
    return memcmp(a->payload, b->payload, a->payload_len) == 0;
}

/* ===================================================================== *
 *  Encode/decode round-trip
 * ===================================================================== */

TEST(test_h2frame_roundtrip) {
    TEST_CASE("encode then decode reproduces frame fields");
    uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03};
    uint8_t enc[64];
    size_t n = h2frame_encode(enc, sizeof(enc), H2_FRAME_HEADERS, H2_FLAG_END_HEADERS,
                              5, payload, sizeof(payload));
    TEST_ASSERT_EQUAL((size_t)(H2_FRAME_HEADER_LEN + sizeof(payload)), n, "encoded size");

    frame_list_t out = {0};
    int got = feed_chunked(0, enc, n, 0, &out);
    TEST_ASSERT_EQUAL(1, got, "decoded one frame");
    TEST_ASSERT_EQUAL(1, out.count, "stored one frame");
    TEST_ASSERT_EQUAL((uint32_t)H2_FRAME_HEADERS, out.f[0].type, "type");
    TEST_ASSERT_EQUAL((uint32_t)H2_FLAG_END_HEADERS, out.f[0].flags, "flags");
    TEST_ASSERT_EQUAL(5u, out.f[0].stream_id, "stream id");
    TEST_ASSERT_EQUAL((uint32_t)sizeof(payload), out.f[0].length, "length");
    TEST_ASSERT(memcmp(out.f[0].payload, payload, sizeof(payload)) == 0, "payload bytes");
    frame_list_free(&out);
}

TEST(test_h2frame_encode_rejects_oversized) {
    TEST_CASE("encode refuses payload above absolute frame limit");
    uint8_t enc[16];
    size_t n = h2frame_encode(enc, sizeof(enc), H2_FRAME_DATA, 0, 1, NULL,
                              H2_MAX_FRAME_SIZE_LIMIT + 1);
    TEST_ASSERT_EQUAL(0u, n, "oversize encode returns 0");
}

/* ===================================================================== *
 *  Resumability — the Phase 2 acceptance test
 * ===================================================================== */

static void build_sequence(uint8_t* buf, size_t* out_len) {
    /* Preface + SETTINGS(empty) + HEADERS(stream 1, payload) + PING(stream 0) +
     * zero-length SETTINGS ACK. */
    size_t off = 0;
    memcpy(buf + off, H2_CONNECTION_PREFACE, H2_CONNECTION_PREFACE_LEN);
    off += H2_CONNECTION_PREFACE_LEN;
    off += h2frame_encode(buf + off, 32, H2_FRAME_SETTINGS, 0, 0, NULL, 0);
    uint8_t hp[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    off += h2frame_encode(buf + off, 32, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                          1, hp, sizeof(hp));
    uint8_t ping[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    off += h2frame_encode(buf + off, 32, H2_FRAME_PING, 0, 0, ping, sizeof(ping));
    off += h2frame_encode(buf + off, 32, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, NULL, 0);
    *out_len = off;
}

TEST(test_h2frame_resumability_all_chunks) {
    TEST_CASE("same frames emerge regardless of chunk boundary");
    uint8_t seq[256];
    size_t seq_len;
    build_sequence(seq, &seq_len);

    frame_list_t ref = {0};
    int ref_n = feed_chunked(1, seq, seq_len, 0, &ref); /* one-shot */
    TEST_ASSERT_EQUAL(4, ref_n, "one-shot count (settings, headers, ping, ack)");
    TEST_ASSERT_EQUAL(4, ref.count, "stored count");

    size_t chunks[] = {1, 2, 3, 5, 7, 9, 13};
    for (size_t ci = 0; ci < sizeof(chunks) / sizeof(chunks[0]); ci++) {
        frame_list_t c = {0};
        int n = feed_chunked(1, seq, seq_len, chunks[ci], &c);
        TEST_ASSERT_EQUAL(ref_n, n, "chunked count matches one-shot");
        TEST_ASSERT_EQUAL(ref.count, c.count, "stored count matches");
        int ok = 1;
        for (int i = 0; i < c.count; i++)
            if (!frames_equal(&ref.f[i], &c.f[i])) ok = 0;
        TEST_ASSERT(ok, "chunked frames equal one-shot frames");
        frame_list_free(&c);
    }
    frame_list_free(&ref);
}

TEST(test_h2frame_partial_then_more) {
    TEST_CASE("feed first half, then the rest — frame completes");
    uint8_t payload[] = {0xaa, 0xbb, 0xcc, 0xdd};
    uint8_t enc[32];
    size_t n = h2frame_encode(enc, sizeof(enc), H2_FRAME_DATA, H2_FLAG_END_STREAM,
                              9, payload, sizeof(payload));

    h2frame_parser_t p;
    h2frame_parser_init(&p, 0, H2_MAX_FRAME_SIZE_DEFAULT);

    const uint8_t* pp = enc;
    h2parse_status_e s = h2frame_parser_feed(&p, &pp, enc + 5); /* split inside header */
    TEST_ASSERT_EQUAL(H2PARSE_CONTINUE, s, "partial header → CONTINUE");
    s = h2frame_parser_feed(&p, &pp, enc + 8); /* header done, no payload yet */
    TEST_ASSERT_EQUAL(H2PARSE_CONTINUE, s, "header boundary → CONTINUE");
    s = h2frame_parser_feed(&p, &pp, enc + n); /* rest of payload */
    TEST_ASSERT_EQUAL(H2PARSE_FRAME_READY, s, "complete → FRAME_READY");
    h2_frame_t f;
    h2frame_parser_get(&p, &f);
    TEST_ASSERT_EQUAL((uint32_t)H2_FRAME_DATA, f.type, "type");
    TEST_ASSERT_EQUAL(9u, f.stream_id, "stream id");
    TEST_ASSERT_EQUAL((uint32_t)sizeof(payload), f.payload_len, "payload len");
    TEST_ASSERT(memcmp(f.payload, payload, sizeof(payload)) == 0, "payload");
    h2frame_parser_free(&p);
}

/* ===================================================================== *
 *  Connection preface
 * ===================================================================== */

TEST(test_h2frame_preface_bad_magic) {
    TEST_CASE("bad connection preface magic → PREFACE_BAD");
    uint8_t bad[24];
    memcpy(bad, H2_CONNECTION_PREFACE, 24);
    bad[5] ^= 0xff; /* corrupt one byte */
    h2frame_parser_t p;
    h2frame_parser_init(&p, 1, H2_MAX_FRAME_SIZE_DEFAULT);
    const uint8_t* pp = bad;
    h2parse_status_e s = h2frame_parser_feed(&p, &pp, bad + sizeof(bad));
    TEST_ASSERT_EQUAL(H2PARSE_PREFACE_BAD, s, "corrupt preface rejected");
    h2frame_parser_free(&p);
}

/* ===================================================================== *
 *  Validation (RFC 9113 §8)
 * ===================================================================== */

static void expect_bad(const char* label, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid) {
    uint8_t hdr[H2_FRAME_HEADER_LEN];
    put_header(hdr, len, type, flags, sid);
    uint8_t* buf = malloc(sizeof(hdr) + len);
    if (buf == NULL) { TEST_ASSERT(0, label); return; }
    memcpy(buf, hdr, sizeof(hdr));
    for (uint32_t i = 0; i < len; i++) buf[sizeof(hdr) + i] = (uint8_t)i;
    h2frame_parser_t p;
    h2frame_parser_init(&p, 0, H2_MAX_FRAME_SIZE_DEFAULT);
    const uint8_t* pp = buf;
    h2parse_status_e s = h2frame_parser_feed(&p, &pp, buf + sizeof(hdr) + len);
    TEST_ASSERT_EQUAL(H2PARSE_BAD_FRAME, s, label);
    h2frame_parser_free(&p);
    free(buf);
}

TEST(test_h2frame_validation) {
    TEST_CASE("header-level rejections (§8)");
    uint8_t bad_sid_hdr[H2_FRAME_HEADER_LEN];
    put_header(bad_sid_hdr, 0, H2_FRAME_DATA, 0, 1);
    bad_sid_hdr[5] |= 0x80; /* set reserved R bit (put_header always clears it) */
    h2frame_parser_t p;
    h2frame_parser_init(&p, 0, H2_MAX_FRAME_SIZE_DEFAULT);
    const uint8_t* pp = bad_sid_hdr;
    TEST_ASSERT_EQUAL(H2PARSE_BAD_FRAME, h2frame_parser_feed(&p, &pp, bad_sid_hdr + sizeof(bad_sid_hdr)),
                      "reserved R bit set");
    h2frame_parser_free(&p);

    expect_bad("DATA with stream id 0", 0, H2_FRAME_DATA, 0, 0);
    expect_bad("SETTINGS with stream id != 0", 0, H2_FRAME_SETTINGS, 0, 1);
    expect_bad("PING with stream id != 0", 8, H2_FRAME_PING, 0, 1);
    expect_bad("PING wrong length (not 8)", 7, H2_FRAME_PING, 0, 0);
    expect_bad("WINDOW_UPDATE wrong length (not 4)", 3, H2_FRAME_WINDOW_UPDATE, 0, 1);
    expect_bad("PRIORITY wrong length (not 5)", 4, H2_FRAME_PRIORITY, 0, 1);
    expect_bad("RST_STREAM wrong length (not 4)", 5, H2_FRAME_RST_STREAM, 0, 1);
    expect_bad("SETTINGS length not multiple of 6", 7, H2_FRAME_SETTINGS, 0, 0);
    expect_bad("GOAWAY length < 8", 7, H2_FRAME_GOAWAY, 0, 0);
    expect_bad("oversize length", H2_MAX_FRAME_SIZE_DEFAULT + 1, H2_FRAME_DATA, 0, 1);
}

TEST(test_h2frame_valid_frames_pass) {
    TEST_CASE("well-formed frames of each shape are accepted");
    uint8_t buf[64]; size_t off = 0;
    uint8_t ping[8] = {0}; uint8_t setp[6] = {0};
    off += h2frame_encode(buf + off, 32, H2_FRAME_PING, 0, 0, ping, 8);
    off += h2frame_encode(buf + off, 32, H2_FRAME_GOAWAY, 0, 0, ping, 8);
    off += h2frame_encode(buf + off, 32, H2_FRAME_SETTINGS, 0, 0, setp, 6);
    frame_list_t out = {0};
    int n = feed_chunked(0, buf, off, 0, &out);
    TEST_ASSERT_EQUAL(3, n, "three valid frames decoded");
    frame_list_free(&out);
}

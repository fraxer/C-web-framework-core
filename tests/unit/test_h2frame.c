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

/* The parser separates a structural violation from a length one, because the
 * session maps them to different RFC error codes — PROTOCOL_ERROR against
 * FRAME_SIZE_ERROR (docs/http2/08, phase C.1). Which one comes back is part of
 * the contract, so the expected status is spelled out per case. */
static void expect_status(h2parse_status_e want, const char* label,
                          uint32_t len, uint8_t type, uint8_t flags, uint32_t sid) {
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
    TEST_ASSERT_EQUAL(want, s, label);
    h2frame_parser_free(&p);
    free(buf);
}

static void expect_bad(const char* label, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid) {
    expect_status(H2PARSE_BAD_FRAME, label, len, type, flags, sid);
}

static void expect_size(const char* label, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid) {
    expect_status(H2PARSE_FRAME_SIZE, label, len, type, flags, sid);
}

/* RFC 9113 §4.1 leaves the reserved bit undefined and requires receivers to
 * ignore it — rejecting the frame breaks senders that set it (h2spec 4.1/3). */
TEST(test_h2frame_reserved_bit_ignored) {
    TEST_CASE("reserved R bit is ignored, not rejected");

    uint8_t buf[H2_FRAME_HEADER_LEN + 8];
    put_header(buf, 8, H2_FRAME_PING, 0, 0);
    buf[5] |= 0x80; /* set reserved R bit (put_header always clears it) */
    memcpy(buf + H2_FRAME_HEADER_LEN, "12345678", 8);

    frame_list_t out = {0};
    const int n = feed_chunked(0, buf, sizeof(buf), 0, &out);

    TEST_ASSERT_EQUAL(1, n, "frame accepted");
    TEST_ASSERT_EQUAL(H2_FRAME_PING, out.f[0].type, "type decoded");
    TEST_ASSERT_EQUAL(0, (int)out.f[0].stream_id, "reserved bit masked out of the stream id");

    frame_list_free(&out);

    /* Same for a stream frame: the id keeps its 31 bits, the R bit vanishes. */
    uint8_t data[H2_FRAME_HEADER_LEN];
    put_header(data, 0, H2_FRAME_DATA, 0, 1);
    data[5] |= 0x80;

    frame_list_t out2 = {0};
    TEST_ASSERT_EQUAL(1, feed_chunked(0, data, sizeof(data), 0, &out2), "DATA accepted");
    TEST_ASSERT_EQUAL(1, (int)out2.f[0].stream_id, "stream id unaffected");

    frame_list_free(&out2);
}

TEST(test_h2frame_validation) {
    TEST_CASE("header-level rejections (§8)");

    /* Structural: the frame type and the stream id disagree (§6.x). */
    expect_bad("DATA with stream id 0", 0, H2_FRAME_DATA, 0, 0);
    expect_bad("SETTINGS with stream id != 0", 0, H2_FRAME_SETTINGS, 0, 1);
    expect_bad("PING with stream id != 0", 8, H2_FRAME_PING, 0, 1);

    /* Length: the size is wrong for the type, or past max_frame_size (§4.2). */
    expect_size("PING wrong length (not 8)", 7, H2_FRAME_PING, 0, 0);
    expect_size("WINDOW_UPDATE wrong length (not 4)", 3, H2_FRAME_WINDOW_UPDATE, 0, 1);
    expect_size("PRIORITY wrong length (not 5)", 4, H2_FRAME_PRIORITY, 0, 1);
    expect_size("RST_STREAM wrong length (not 4)", 5, H2_FRAME_RST_STREAM, 0, 1);
    expect_size("SETTINGS length not multiple of 6", 7, H2_FRAME_SETTINGS, 0, 0);
    expect_size("GOAWAY length < 8", 7, H2_FRAME_GOAWAY, 0, 0);
    expect_size("oversize length", H2_MAX_FRAME_SIZE_DEFAULT + 1, H2_FRAME_DATA, 0, 1);

    /* §6.5: a SETTINGS ACK carries no payload. A length that is a legal
     * multiple of 6 makes this the one size violation the session could not
     * catch on its own — h2_on_settings returns on the ACK flag before it looks
     * at anything else (phase C.2). */
    expect_size("SETTINGS ACK with a payload", 6, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
    expect_size("SETTINGS ACK with a 1-byte payload", 1, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
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

/* h2frame_encode_header writes only the 9-byte header, announcing a payload the
 * caller streams separately — the h2 write filter frames DATA that way to avoid
 * copying the response body. It must agree byte-for-byte with h2frame_encode. */
TEST(test_h2frame_encode_header_matches_full_encode) {
    TEST_CASE("header-only encode matches the header of a full encode");

    static const struct { uint8_t type; uint8_t flags; uint32_t sid; size_t len; } cases[] = {
        {H2_FRAME_DATA, H2_FLAG_END_STREAM, 1, 0},
        {H2_FRAME_DATA, 0, 1, 16384},
        {H2_FRAME_DATA, H2_FLAG_END_STREAM, 0x7fffffff, 255},
        {H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 3, 1},
        {H2_FRAME_CONTINUATION, 0, 65535, 0xfffe},
    };

    /* Static: the largest case carries ~64 KiB of payload, too much for the stack. */
    static uint8_t payload[0xfffe];
    static uint8_t full[H2_FRAME_HEADER_LEN + sizeof(payload)];

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t only[H2_FRAME_HEADER_LEN];

        const size_t n = h2frame_encode_header(only, cases[i].type, cases[i].flags,
                                               cases[i].sid, cases[i].len);
        TEST_ASSERT_EQUAL((int)H2_FRAME_HEADER_LEN, (int)n, "header-only encode is 9 bytes");

        const size_t m = h2frame_encode(full, sizeof(full), cases[i].type, cases[i].flags,
                                        cases[i].sid, payload, cases[i].len);
        TEST_ASSERT_EQUAL((int)(H2_FRAME_HEADER_LEN + cases[i].len), (int)m, "full encode length");
        TEST_ASSERT(memcmp(only, full, H2_FRAME_HEADER_LEN) == 0, "headers identical");
    }

    /* The reserved R bit is cleared and an oversize payload is refused. */
    uint8_t only[H2_FRAME_HEADER_LEN];
    h2frame_encode_header(only, H2_FRAME_DATA, 0, 0xffffffffu, 0);
    TEST_ASSERT_EQUAL(0x7f, only[5], "reserved bit cleared from stream id");
    TEST_ASSERT_EQUAL(0, (int)h2frame_encode_header(only, H2_FRAME_DATA, 0, 1,
                                                    (size_t)H2_MAX_FRAME_SIZE_LIMIT + 1),
                      "payload beyond the absolute frame-size limit is rejected");
}

/* A header written by h2frame_encode_header must be parsed back identically. */
TEST(test_h2frame_encode_header_roundtrip) {
    TEST_CASE("header-only encode round-trips through the parser");

    uint8_t buf[H2_FRAME_HEADER_LEN + 4];
    h2frame_encode_header(buf, H2_FRAME_DATA, H2_FLAG_END_STREAM, 5, 4);
    memcpy(buf + H2_FRAME_HEADER_LEN, "body", 4);

    frame_list_t out = {0};
    const int n = feed_chunked(0, buf, sizeof(buf), 0, &out);

    TEST_ASSERT_EQUAL(1, n, "one frame decoded");
    TEST_ASSERT_EQUAL(H2_FRAME_DATA, out.f[0].type, "type preserved");
    TEST_ASSERT_EQUAL(H2_FLAG_END_STREAM, out.f[0].flags, "flags preserved");
    TEST_ASSERT_EQUAL(5, (int)out.f[0].stream_id, "stream id preserved");
    TEST_ASSERT_EQUAL(4, (int)out.f[0].payload_len, "payload length preserved");
    TEST_ASSERT(memcmp(out.f[0].payload, "body", 4) == 0, "payload preserved");

    frame_list_free(&out);
}

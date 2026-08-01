#include "framework.h"
#include "hpack.h"

#include <stdlib.h>
#include <string.h>

/* Convert a hex string to a freshly malloc'd byte buffer. */
static uint8_t* hex_to_bytes(const char* hex, size_t* out_len) {
    size_t n = strlen(hex) / 2;
    uint8_t* b = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) {
        unsigned int v;
        sscanf(hex + 2 * i, "%2x", &v);
        b[i] = (uint8_t)v;
    }
    *out_len = n;
    return b;
}

static int hdr_eq(const hpack_header_t* h, const char* name, const char* value) {
    size_t nl = strlen(name), vl = strlen(value);
    return h->name_len == nl && h->value_len == vl &&
           memcmp(h->name, name, nl) == 0 && memcmp(h->value, value, vl) == 0;
}

/* ===================================================================== *
 *  Integer codec (RFC 7541 §5.1 / Appendix C.1)
 * ===================================================================== */

TEST(test_hpack_int_c11) {
    TEST_CASE("C.1.1: decode 10 with 5-bit prefix");
    uint8_t in[] = {0x0a};
    const uint8_t* p = in;
    hpack_status_e st;
    uint32_t v = hpack_decode_int(&p, in + 1, 5, &st);
    TEST_ASSERT_EQUAL(HPACK_OK, st, "status");
    TEST_ASSERT_EQUAL(10u, v, "value");
    TEST_ASSERT_EQUAL((size_t)1, (size_t)(p - in), "consumed 1 byte");
}

TEST(test_hpack_int_c12) {
    TEST_CASE("C.1.2: decode 1337 with 5-bit prefix");
    uint8_t in[] = {0x1f, 0x9a, 0x0a};
    const uint8_t* p = in;
    hpack_status_e st;
    uint32_t v = hpack_decode_int(&p, in + 3, 5, &st);
    TEST_ASSERT_EQUAL(HPACK_OK, st, "status");
    TEST_ASSERT_EQUAL(1337u, v, "value");
    TEST_ASSERT_EQUAL((size_t)3, (size_t)(p - in), "consumed 3 bytes");
}

TEST(test_hpack_int_c13) {
    TEST_CASE("C.1.3: decode 42 with 8-bit prefix at octet boundary");
    uint8_t in[] = {0x2a};
    const uint8_t* p = in;
    hpack_status_e st;
    uint32_t v = hpack_decode_int(&p, in + 1, 8, &st);
    TEST_ASSERT_EQUAL(HPACK_OK, st, "status");
    TEST_ASSERT_EQUAL(42u, v, "value");
}

TEST(test_hpack_int_encode_roundtrip) {
    TEST_CASE("encode_int round-trips across prefix widths");
    uint32_t values[] = {0, 1, 9, 10, 14, 15, 16, 30, 31, 32, 127, 128, 1337, 65535, 1048576};
    uint8_t prefixes[] = {1, 3, 5, 7, 8};
    for (size_t vi = 0; vi < sizeof(values) / sizeof(values[0]); vi++) {
        for (size_t pi = 0; pi < sizeof(prefixes) / sizeof(prefixes[0]); pi++) {
            uint8_t out[8] = {0};
            size_t n = hpack_encode_int(out, sizeof(out), values[vi], prefixes[pi], 0x00);
            TEST_ASSERT(n > 0 && n <= 5, "encode produced bytes");
            const uint8_t* p = out;
            hpack_status_e st;
            uint32_t back = hpack_decode_int(&p, out + n, prefixes[pi], &st);
            TEST_ASSERT_EQUAL(HPACK_OK, st, "decode status");
            TEST_ASSERT_EQUAL(values[vi], back, "round-trip value");
        }
    }
}

TEST(test_hpack_int_truncated) {
    TEST_CASE("integer decode rejects truncated continuation");
    uint8_t in[] = {0x1f, 0x9a}; /* needs one more byte */
    const uint8_t* p = in;
    hpack_status_e st;
    (void)hpack_decode_int(&p, in + 2, 5, &st);
    TEST_ASSERT_EQUAL(HPACK_ERR_INVALID, st, "truncated → INVALID");
}

/* ===================================================================== *
 *  Huffman (RFC 7541 §5.2)
 * ===================================================================== */

TEST(test_hpack_huffman_roundtrip) {
    TEST_CASE("Huffman encode/decode round-trip on varied strings");
    const char* samples[] = {
        "a", "www.example.com", "/index.html", "GET", "no-cache",
        "Mon, 21 Oct 2013 20:13:21 GMT", "accept-encoding",
        "x-custom-header-value-1234567890", "", "AAAAAAA"
    };
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
        size_t len = strlen(samples[i]);
        size_t enc_cap = hpack_huffman_encoded_len((const uint8_t*)samples[i], len) + 1;
        uint8_t* enc = malloc(enc_cap);
        size_t en = 0;
        TEST_ASSERT_EQUAL(HPACK_OK,
            hpack_huffman_encode((const uint8_t*)samples[i], len, enc, enc_cap, &en),
            "encode status");
        size_t dec_cap = len * 2 + 16;
        uint8_t* dec = malloc(dec_cap);
        size_t dn = 0;
        TEST_ASSERT_EQUAL(HPACK_OK,
            hpack_huffman_decode(enc, en, dec, dec_cap, &dn), "decode status");
        TEST_ASSERT_EQUAL(len, dn, "decoded length");
        TEST_ASSERT(memcmp(dec, samples[i], len) == 0, "decoded content");
        free(enc); free(dec);
    }
}

TEST(test_hpack_huffman_rejects_garbage) {
    TEST_CASE("Huffman decode rejects EOS / non-EOS-prefix padding");
    uint8_t bad1[] = {0xff, 0xff, 0xff, 0xff};      /* long all-ones run → EOS path */
    uint8_t bad2[] = {0x80};                          /* 0b10000000: trailing bits not all-1 */
    uint8_t out[64]; size_t n;
    /* Each must fail (COMPRESSION or INVALID) without crashing. */
    hpack_status_e s1 = hpack_huffman_decode(bad1, sizeof(bad1), out, sizeof(out), &n);
    hpack_status_e s2 = hpack_huffman_decode(bad2, sizeof(bad2), out, sizeof(out), &n);
    TEST_ASSERT(s1 != HPACK_OK, "all-ones run rejected");
    TEST_ASSERT(s2 != HPACK_OK, "non-EOS padding rejected");
}

/* ===================================================================== *
 *  Static table
 * ===================================================================== */

TEST(test_hpack_static_table) {
    TEST_CASE("resolve_index returns static entries 1..61");
    hpack_dynamic_table_t t; hpack_dynamic_table_init(&t, 4096);
    const char *n, *v; size_t nl, vl;

    TEST_ASSERT_EQUAL(HPACK_OK, hpack_resolve_index(&t, 2, &n, &nl, &v, &vl), "idx 2");
    TEST_ASSERT(hdr_eq(&(hpack_header_t){(char*)n, nl, (char*)v, vl}, ":method", "GET"),
                "idx 2 = :method GET");

    TEST_ASSERT_EQUAL(HPACK_OK, hpack_resolve_index(&t, 4, &n, &nl, &v, &vl), "idx 4");
    TEST_ASSERT(hdr_eq(&(hpack_header_t){(char*)n, nl, (char*)v, vl}, ":path", "/"),
                "idx 4 = :path /");

    TEST_ASSERT_EQUAL(HPACK_ERR_INVALID, hpack_resolve_index(&t, 0, &n, &nl, &v, &vl),
                      "idx 0 invalid");
    TEST_ASSERT_EQUAL(HPACK_ERR_INVALID, hpack_resolve_index(&t, 62, &n, &nl, &v, &vl),
                      "idx 62 out of range when dynamic empty");
    hpack_dynamic_table_free(&t);
}

/* ===================================================================== *
 *  Decoder: RFC 7541 Appendix C request sequence (no Huffman)
 * ===================================================================== */

TEST(test_hpack_decode_c3_sequence) {
    TEST_CASE("C.3.1→C.3.3 decode with persistent dynamic table");
    hpack_decoder_t* d = hpack_decoder_create(4096);

    /* C.3.1 */
    size_t l1; uint8_t* b1 = hex_to_bytes("828684410f7777772e6578616d706c652e636f6d", &l1);
    hpack_header_t* h; size_t n;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, b1, l1, &h, &n), "C.3.1 status");
    TEST_ASSERT_EQUAL((size_t)4, n, "C.3.1 count");
    TEST_ASSERT(hdr_eq(&h[0], ":method", "GET"), "C.3.1 h0");
    TEST_ASSERT(hdr_eq(&h[1], ":scheme", "http"), "C.3.1 h1");
    TEST_ASSERT(hdr_eq(&h[2], ":path", "/"), "C.3.1 h2");
    TEST_ASSERT(hdr_eq(&h[3], ":authority", "www.example.com"), "C.3.1 h3");
    hpack_headers_free(h, n); free(b1);

    /* C.3.2 reuses :authority via dynamic index 62 (0xbe) */
    size_t l2; uint8_t* b2 = hex_to_bytes("828684be58086e6f2d6361636865", &l2);
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, b2, l2, &h, &n), "C.3.2 status");
    TEST_ASSERT_EQUAL((size_t)5, n, "C.3.2 count");
    TEST_ASSERT(hdr_eq(&h[0], ":method", "GET"), "C.3.2 h0");
    TEST_ASSERT(hdr_eq(&h[3], ":authority", "www.example.com"), "C.3.2 authority via dyn");
    TEST_ASSERT(hdr_eq(&h[4], "cache-control", "no-cache"), "C.3.2 cache-control");
    hpack_headers_free(h, n); free(b2);

    /* C.3.3 references :authority via dynamic index 63 (0xbf) */
    size_t l3; uint8_t* b3 = hex_to_bytes("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565", &l3);
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, b3, l3, &h, &n), "C.3.3 status");
    TEST_ASSERT_EQUAL((size_t)5, n, "C.3.3 count");
    TEST_ASSERT(hdr_eq(&h[1], ":scheme", "https"), "C.3.3 https");
    TEST_ASSERT(hdr_eq(&h[2], ":path", "/index.html"), "C.3.3 path");
    TEST_ASSERT(hdr_eq(&h[3], ":authority", "www.example.com"), "C.3.3 authority via dyn");
    TEST_ASSERT(hdr_eq(&h[4], "custom-key", "custom-value"), "C.3.3 custom");
    hpack_headers_free(h, n); free(b3);

    hpack_decoder_free(d);
}

/* ===================================================================== *
 *  Decoder: Huffman-encoded request sequence (Appendix C.4)
 * ===================================================================== */

TEST(test_hpack_decode_c4_huffman) {
    TEST_CASE("C.4.1→C.4.3 decode Huffman-encoded requests");
    hpack_decoder_t* d = hpack_decoder_create(4096);

    size_t l; uint8_t* b; hpack_header_t* h; size_t n;

    b = hex_to_bytes("828684418cf1e3c2e5f23a6ba0ab90f4ff", &l);
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, b, l, &h, &n), "C.4.1 status");
    TEST_ASSERT_EQUAL((size_t)4, n, "C.4.1 count");
    TEST_ASSERT(hdr_eq(&h[3], ":authority", "www.example.com"), "C.4.1 authority (huffman)");
    hpack_headers_free(h, n); free(b);

    b = hex_to_bytes("828684be5886a8eb10649cbf", &l);
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, b, l, &h, &n), "C.4.2 status");
    TEST_ASSERT_EQUAL((size_t)5, n, "C.4.2 count");
    TEST_ASSERT(hdr_eq(&h[4], "cache-control", "no-cache"), "C.4.2 cache-control (huffman)");
    hpack_headers_free(h, n); free(b);

    b = hex_to_bytes("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf", &l);
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, b, l, &h, &n), "C.4.3 status");
    TEST_ASSERT_EQUAL((size_t)5, n, "C.4.3 count");
    TEST_ASSERT(hdr_eq(&h[4], "custom-key", "custom-value"), "C.4.3 custom (huffman)");
    hpack_headers_free(h, n); free(b);

    hpack_decoder_free(d);
}

TEST(test_hpack_decode_c51_response) {
    TEST_CASE("C.5.1 decode first response (dynamic table growth)");
    hpack_decoder_t* d = hpack_decoder_create(4096);
    size_t l;
    uint8_t* b = hex_to_bytes(
        "4803333032580770726976617465611d4d6f6e2c203231204f63742032303133"
        "2032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d70"
        "6c652e636f6d", &l);
    hpack_header_t* h; size_t n;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, b, l, &h, &n), "C.5.1 status");
    TEST_ASSERT_EQUAL((size_t)4, n, "C.5.1 count");
    TEST_ASSERT(hdr_eq(&h[0], ":status", "302"), "C.5.1 status");
    TEST_ASSERT(hdr_eq(&h[1], "cache-control", "private"), "C.5.1 cache-control");
    TEST_ASSERT(hdr_eq(&h[2], "date", "Mon, 21 Oct 2013 20:13:21 GMT"), "C.5.1 date");
    TEST_ASSERT(hdr_eq(&h[3], "location", "https://www.example.com"), "C.5.1 location");
    hpack_headers_free(h, n); free(b);
    hpack_decoder_free(d);
}

TEST(test_hpack_decode_rejects_bad_index) {
    TEST_CASE("decoder rejects oversized / zero index");
    hpack_decoder_t* d = hpack_decoder_create(4096);
    uint8_t in[] = {0xff, 0xff, 0xff, 0xff, 0x07}; /* indexed index ~2^28 → out of range */
    hpack_header_t* h; size_t n;
    hpack_status_e s = hpack_decoder_decode(d, in, sizeof(in), &h, &n);
    TEST_ASSERT(s != HPACK_OK, "oversized index rejected");
    hpack_decoder_free(d);
}

/* ===================================================================== *
 *  Encoder round-trip
 * ===================================================================== */

TEST(test_hpack_encoder_roundtrip) {
    TEST_CASE("encode → decode reproduces headers (with and without Huffman)");
    hpack_header_t in[] = {
        {(char*)":method", 7, (char*)"GET", 3},
        {(char*)":scheme", 7, (char*)"https", 5},
        {(char*)":path", 5, (char*)"/index.html", 11},
        {(char*)":authority", 10, (char*)"www.example.com", 15},
        {(char*)"custom-key", 10, (char*)"custom-value", 12},
        {(char*)"x-long-value", 12, (char*)"some fairly long descriptive value here", 38},
    };
    size_t cnt = sizeof(in) / sizeof(in[0]);

    for (int use_huff = 0; use_huff <= 1; use_huff++) {
        hpack_encoder_t* e = hpack_encoder_create(4096);
        hpack_decoder_t* d = hpack_decoder_create(4096);
        uint8_t* out = NULL; size_t out_len = 0;
        TEST_ASSERT_EQUAL(HPACK_OK,
            hpack_encoder_encode(e, in, cnt, use_huff, &out, &out_len), "encode");
        TEST_ASSERT(out_len > 0, "produced bytes");

        hpack_header_t* h = NULL; size_t n = 0;
        TEST_ASSERT_EQUAL(HPACK_OK,
            hpack_decoder_decode(d, out, out_len, &h, &n), "decode");
        TEST_ASSERT_EQUAL(cnt, n, "count matches");
        for (size_t i = 0; i < n; i++) {
            TEST_ASSERT(h[i].name_len == in[i].name_len &&
                        memcmp(h[i].name, in[i].name, in[i].name_len) == 0, "name matches");
            TEST_ASSERT(h[i].value_len == in[i].value_len &&
                        memcmp(h[i].value, in[i].value, in[i].value_len) == 0, "value matches");
        }
        hpack_headers_free(h, n);
        free(out);
        hpack_encoder_free(e);
        hpack_decoder_free(d);
    }
}

TEST(test_hpack_encoder_uses_huffman_when_shorter) {
    TEST_CASE("encoder with Huffman shrinks long values");
    hpack_header_t in[] = {
        {(char*)"x-key", 5, (char*)"www.example.com is a long repetitive string", 44},
    };
    hpack_encoder_t* e1 = hpack_encoder_create(0);
    hpack_encoder_t* e2 = hpack_encoder_create(0);
    uint8_t *a = NULL, *b = NULL; size_t la = 0, lb = 0;
    hpack_encoder_encode(e1, in, 1, 0, &a, &la); /* no huffman */
    hpack_encoder_encode(e2, in, 1, 1, &b, &lb); /* huffman */
    TEST_ASSERT(lb < la, "Huffman encoding must be shorter for ASCII-heavy value");
    free(a); free(b);
    hpack_encoder_free(e1);
    hpack_encoder_free(e2);
}

/* ===================================================================== *
 *  Fuzz: random blocks must never crash (always OK or a clean error)
 * ===================================================================== */

TEST(test_hpack_fuzz_no_crash) {
    TEST_CASE("decoder stays safe on arbitrary byte streams");
    unsigned int seed = 1234567u;
    for (int iter = 0; iter < 5000; iter++) {
        /* LCG-derived pseudo-random length + bytes. */
        size_t len = (seed % 64);
        uint8_t buf[64];
        for (size_t i = 0; i < len; i++) {
            seed = seed * 1103515245u + 12345u;
            buf[i] = (uint8_t)(seed >> 13);
        }
        hpack_decoder_t* d = hpack_decoder_create(4096);
        hpack_header_t* h = NULL; size_t n = 0;
        hpack_status_e s = hpack_decoder_decode(d, buf, len, &h, &n);
        (void)s;
        hpack_headers_free(h, n);
        hpack_decoder_free(d);
        seed = seed * 1103515245u + 999u;
    }
    TEST_ASSERT(1, "fuzz completed without crash");
}

/* ===================================================================== *
 *  Dynamic table size update (RFC 7541 §4.2 / §6.3)
 * ===================================================================== */

/* SETTINGS_HEADER_TABLE_SIZE bounds the *peer's decoder* table, so it resizes
 * our encoder. Shrinking silently would desync the two tables — the encoder has
 * to announce it with a size-update instruction leading the next block. */
TEST(test_hpack_encoder_emits_size_update) {
    TEST_CASE("a shrink is announced and honoured by the decoder");

    hpack_encoder_t* e = hpack_encoder_create(4096);
    hpack_decoder_t* d = hpack_decoder_create(4096);
    TEST_REQUIRE(e != NULL && d != NULL, "codecs created");

    hpack_encoder_set_max_table_size(e, 256);

    hpack_header_t in[] = {
        {":status", 7, "200", 3},
        {"content-type", 12, "text/html", 9},
    };

    uint8_t* block = NULL; size_t block_len = 0;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_encoder_encode(e, in, 2, 1, &block, &block_len),
                      "encode succeeds");
    TEST_REQUIRE(block != NULL && block_len > 0, "block produced");

    /* 001xxxxx with a 5-bit prefix carrying 256 → 0x3f then the continuation. */
    TEST_ASSERT_EQUAL(0x3f, block[0], "block starts with a size-update instruction");
    TEST_ASSERT_EQUAL(256, (int)e->table.max, "encoder table resized");

    hpack_header_t* out = NULL; size_t n = 0;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, block, block_len, &out, &n),
                      "decoder accepts the block");
    TEST_ASSERT_EQUAL(2, (int)n, "both headers decoded");
    TEST_ASSERT_EQUAL(256, (int)d->table.max, "decoder table followed the update");

    hpack_headers_free(out, n);
    free(block);
    hpack_encoder_free(e);
    hpack_decoder_free(d);
}

/* The update is emitted once, not on every subsequent block. */
TEST(test_hpack_encoder_size_update_emitted_once) {
    TEST_CASE("only the first block after a resize carries the update");

    hpack_encoder_t* e = hpack_encoder_create(4096);
    TEST_REQUIRE(e != NULL, "encoder created");

    hpack_encoder_set_max_table_size(e, 512);

    hpack_header_t in[] = {{":status", 7, "200", 3}};

    uint8_t* first = NULL; size_t first_len = 0;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_encoder_encode(e, in, 1, 1, &first, &first_len), "first block");
    TEST_REQUIRE(first != NULL && first_len > 0, "first block produced");
    TEST_ASSERT_EQUAL(0x20, first[0] & 0xe0, "first block leads with the size update");

    uint8_t* second = NULL; size_t second_len = 0;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_encoder_encode(e, in, 1, 1, &second, &second_len), "second block");
    TEST_REQUIRE(second != NULL && second_len > 0, "second block produced");
    TEST_ASSERT(( second[0] & 0xe0) != 0x20, "second block carries no size update");

    free(first);
    free(second);
    hpack_encoder_free(e);
}

/* A peer allowing a bigger table than we were built for must not grow us past
 * the configured ceiling, and must not emit a spurious update. */
TEST(test_hpack_encoder_size_update_clamped_to_ceiling) {
    TEST_CASE("a grow beyond the configured ceiling is clamped and silent");

    hpack_encoder_t* e = hpack_encoder_create(4096);
    TEST_REQUIRE(e != NULL, "encoder created");

    hpack_encoder_set_max_table_size(e, 65536);

    hpack_header_t in[] = {{":status", 7, "200", 3}};
    uint8_t* block = NULL; size_t block_len = 0;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_encoder_encode(e, in, 1, 1, &block, &block_len), "encode");
    TEST_REQUIRE(block != NULL && block_len > 0, "block produced");

    TEST_ASSERT_EQUAL(4096, (int)e->table.max, "table stays at the ceiling");
    TEST_ASSERT((block[0] & 0xe0) != 0x20, "no size update emitted");

    free(block);
    hpack_encoder_free(e);
}

/* RFC 7541 §4.2: a dynamic table size update may only appear at the very start
 * of a header block. Accepting one later is a decoding error (h2spec HPACK
 * 4.2/1) — and would leave the two tables disagreeing about evictions. */
TEST(test_hpack_size_update_must_lead_block) {
    TEST_CASE("a size update after a header field is a compression error");

    hpack_decoder_t* d = hpack_decoder_create(4096);
    TEST_REQUIRE(d != NULL, "decoder created");

    /* 0x82 = indexed field (:method GET), then 0x20 = size update to 0. */
    const uint8_t trailing[] = {0x82, 0x20};
    hpack_header_t* out = NULL; size_t n = 0;
    TEST_ASSERT_EQUAL(HPACK_ERR_COMPRESSION,
                      hpack_decoder_decode(d, trailing, sizeof(trailing), &out, &n),
                      "size update after a field is rejected");
    hpack_headers_free(out, n);
    hpack_decoder_free(d);

    /* The same instructions in the legal order decode cleanly. */
    d = hpack_decoder_create(4096);
    TEST_REQUIRE(d != NULL, "decoder recreated");

    const uint8_t leading[] = {0x20, 0x82};
    out = NULL; n = 0;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, leading, sizeof(leading), &out, &n),
                      "size update before any field is accepted");
    TEST_ASSERT_EQUAL(1, (int)n, "the indexed field still decodes");
    TEST_ASSERT_EQUAL(0, (int)d->table.max, "table resized to 0");

    hpack_headers_free(out, n);
    hpack_decoder_free(d);
}

/* Several updates may lead a block (the RFC allows at most two); only a field
 * in between makes them illegal. */
TEST(test_hpack_consecutive_size_updates_allowed) {
    TEST_CASE("back-to-back size updates at the head of a block are fine");

    hpack_decoder_t* d = hpack_decoder_create(4096);
    TEST_REQUIRE(d != NULL, "decoder created");

    const uint8_t block[] = {0x20, 0x3f, 0xe1, 0x1f, 0x82}; /* →0, →4096, :method GET */
    hpack_header_t* out = NULL; size_t n = 0;
    TEST_ASSERT_EQUAL(HPACK_OK, hpack_decoder_decode(d, block, sizeof(block), &out, &n),
                      "two leading size updates accepted");
    TEST_ASSERT_EQUAL(1, (int)n, "one header decoded");
    TEST_ASSERT_EQUAL(4096, (int)d->table.max, "final size applied");

    hpack_headers_free(out, n);
    hpack_decoder_free(d);
}

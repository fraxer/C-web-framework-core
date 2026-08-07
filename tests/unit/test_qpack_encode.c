#include "framework.h"

#include "qpack.h"

#include <string.h>

/* QPACK-lite encoder (RFC 9204). Most cases are round-trip: encode, decode,
 * compare, so the test does not depend on whether the encoder chose Huffman.
 * The indexed-static cases are exact-byte because indexed lines carry no
 * Huffman and no literal, so the encoding is forced. */

/* Build a header pointing at a string literal. qpack_header_t.name is char* in
 * step with the decoder's malloc'd output; the encoder takes it const. */
#define H(n, v, nv) ((qpack_header_t){ (char*)(n), strlen(n), (char*)(v), strlen(v), (nv) })

static int roundtrip(qpack_encoder_t* e, qpack_decoder_t* d,
                     const qpack_header_t* in, size_t n) {
    uint8_t buf[512];
    const size_t en = qpack_encode_block(e, in, n, buf, sizeof buf);
    if (en == 0) return 0;

    qpack_header_t* out = NULL;
    size_t count = 0;
    if (qpack_decode_block(d, buf, en, 0, &out, &count) != QPACK_OK) return 0;
    if (count != n) { qpack_headers_free(out, count); return 0; }
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (out[i].name_len != in[i].name_len
            || memcmp(out[i].name, in[i].name, in[i].name_len) != 0
            || out[i].value_len != in[i].value_len
            || memcmp(out[i].value, in[i].value, in[i].value_len) != 0
            || out[i].never_indexed != in[i].never_indexed)
            ok = 0;
    }
    qpack_headers_free(out, count);
    return ok;
}

TEST(test_qpack_encode_indexed) {
    TEST_SUITE("qpack-encode");

    qpack_encoder_t* e = qpack_encoder_create(0, 0);
    uint8_t buf[16];

    TEST_CASE("an exact static match encodes to an indexed line");
    /* :method GET is static index 17 → 0xc0|17 = 0xd1, prefix 00 00. */
    qpack_header_t m = H(":method", "GET", 0);
    size_t n = qpack_encode_block(e, &m, 1, buf, sizeof buf);
    TEST_ASSERT(n == 3 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0xd1,
                ":method=GET → 00 00 d1");

    qpack_header_t p = H(":path", "/", 0);   /* index 1 → 0xc1 */
    n = qpack_encode_block(e, &p, 1, buf, sizeof buf);
    TEST_ASSERT(n == 3 && buf[2] == 0xc1, ":path=/ → 00 00 c1");

    qpack_header_t s = H(":scheme", "https", 0);  /* index 23 → 0xd7 */
    n = qpack_encode_block(e, &s, 1, buf, sizeof buf);
    TEST_ASSERT(n == 3 && buf[2] == 0xd7, ":scheme=https → 00 00 d7");

    qpack_encoder_free(e);
}

TEST(test_qpack_encode_roundtrip) {
    TEST_SUITE("qpack-encode");

    qpack_encoder_t* e = qpack_encoder_create(0, 0);
    qpack_decoder_t* d = qpack_decoder_create(0, 0);

    TEST_CASE("a mixed block round-trips: indexed, name-ref, literal, Huffman");
    qpack_header_t fields[] = {
        H(":method", "POST", 0),                       /* exact static → indexed */
        H(":path", "/api/users/42", 0),                /* :path name ref + literal */
        H(":scheme", "https", 0),                      /* exact static → indexed */
        H("content-type", "application/json", 0),      /* literal-literal-name */
        H("x-request-id", "abc-123-def-456-789", 0),   /* literal-literal, long value */
        H("x-words", "the quick brown fox jumps over the lazy dog", 0), /* Huffman-worthy */
    };
    TEST_ASSERT(roundtrip(e, d, fields, sizeof fields / sizeof fields[0]),
                "every field survives encode → decode");

    TEST_CASE("a never-indexed field round-trips and is not emitted indexed");
    qpack_header_t secret[] = {
        H(":method", "GET", 1),   /* would be indexed at 17, but never_indexed */
    };
    uint8_t buf[32];
    size_t n = qpack_encode_block(e, secret, 1, buf, sizeof buf);
    TEST_ASSERT(n > 0, "encoded");
    TEST_ASSERT((buf[2] & 0x80) == 0, "not an indexed line (N forced a literal)");
    TEST_ASSERT(roundtrip(e, d, secret, 1), "round-trips with never_indexed=1");

    qpack_encoder_free(e);
    qpack_decoder_free(d);
}

TEST(test_qpack_encode_prefix_and_capacity) {
    TEST_SUITE("qpack-encode");

    qpack_encoder_t* e = qpack_encoder_create(0, 0);

    TEST_CASE("an empty list is just the two-byte prefix");
    uint8_t buf[8];
    size_t n = qpack_encode_block(e, NULL, 0, buf, sizeof buf);
    TEST_ASSERT(n == 2 && buf[0] == 0x00 && buf[1] == 0x00, "00 00");

    TEST_CASE("a too-small cap returns 0 (unambiguous: even empty is 2 bytes)");
    qpack_header_t f = H(":method", "GET", 0);
    TEST_ASSERT(qpack_encode_block(e, &f, 1, buf, 2) == 0, "prefix alone fills 2 bytes");

    qpack_encoder_free(e);
}

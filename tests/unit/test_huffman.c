#include "framework.h"

#include "huffman.h"

#include <string.h>

/* The shared Huffman + prefix-integer primitives (misc/huffman.{c,h}) that
 * HPACK and QPACK both build on. HPACK's own exhaustively-tested paths
 * (test_hpack.c: every symbol, RFC 7541 Appendix C vectors, padding) now run
 * through these functions via wrappers, so the point of this suite is the new
 * surface itself: the ssize_t codec return contract and the prefix-integer
 * codec, which QPACK will call directly. */

TEST(test_huffman_roundtrip) {
    TEST_SUITE("huffman");

    TEST_CASE("a few samples, including empty and high-bytes");
    const char* samples[] = { "", "a", "hello", "www.example.com",
                              "content-type", "\xff\xfe\x01\x00\x7f" };
    int all_ok = 1;
    for (size_t i = 0; i < sizeof samples / sizeof samples[0]; i++) {
        size_t len = strlen(samples[i]);
        size_t cap = huffman_encoded_len((const uint8_t*)samples[i], len) + 1;
        uint8_t enc[128];
        TEST_ASSERT(cap <= sizeof enc, "fits");

        ssize_t en = huffman_encode(enc, sizeof enc, (const uint8_t*)samples[i], len);
        if (en < 0) { all_ok = 0; continue; }

        uint8_t dec[160];
        ssize_t dn = huffman_decode(dec, sizeof dec, enc, (size_t)en);
        if (dn < 0 || (size_t)dn != len) { all_ok = 0; continue; }
        if (memcmp(dec, samples[i], len) != 0) all_ok = 0;
    }
    TEST_ASSERT(all_ok, "all samples round-trip");

    TEST_CASE("empty input encodes to zero bytes and decodes back");
    ssize_t en = huffman_encode(NULL, 0, (const uint8_t*)"", 0);
    TEST_ASSERT(en == 0, "zero bytes written");
    ssize_t dn = huffman_decode(NULL, 0, (const uint8_t*)"", 0);
    TEST_ASSERT(dn == 0, "decodes to nothing");
}

TEST(test_huffman_all_bytes) {
    TEST_SUITE("huffman");

    TEST_CASE("every byte value 0..255 round-trips in one block");
    uint8_t raw[256];
    for (int i = 0; i < 256; i++) raw[i] = (uint8_t)i;

    size_t cap = huffman_encoded_len(raw, sizeof raw);
    uint8_t enc[2048];
    TEST_ASSERT(cap <= sizeof enc, "encoded fits");
    ssize_t en = huffman_encode(enc, sizeof enc, raw, sizeof raw);
    TEST_ASSERT(en > 0, "encoded");

    uint8_t dec[256 + 8];
    ssize_t dn = huffman_decode(dec, sizeof dec, enc, (size_t)en);
    TEST_ASSERT(dn == 256, "256 bytes back");
    TEST_ASSERT(memcmp(dec, raw, 256) == 0, "identical");
}

TEST(test_huffman_rejects_malformed) {
    TEST_SUITE("huffman");

    TEST_CASE("EOS may not appear inside a stream");
    /* EOS is 0x3fffffff...30 bits of 1; the longest padding a real stream
     * produces is 7 bits, so a full octet of 1s is the prefix of EOS and is
     * rejected. */
    const uint8_t eos[] = { 0xff, 0xff, 0xff, 0xff };
    uint8_t out[16];
    TEST_ASSERT(huffman_decode(out, sizeof out, eos, sizeof eos) == -1, "EOS rejected");

    TEST_CASE("padding wider than 7 bits is rejected");
    /* 0x00 is a 1-bit-then-padding state that is not accepting once the stream
     * ends mid-symbol; a lone 0x50 leaves the decoder in a non-accepting state. */
    const uint8_t badpad[] = { 0x50 };
    TEST_ASSERT(huffman_decode(out, sizeof out, badpad, sizeof badpad) == -1,
                "mid-symbol padding rejected");

    TEST_CASE("decode returns -1 when the output cap is exhausted");
    /* 'a' decodes to one byte; a cap of 0 cannot hold it. */
    uint8_t enc[8];
    ssize_t en = huffman_encode(enc, sizeof enc, (const uint8_t*)"a", 1);
    TEST_ASSERT(en > 0, "encoded 'a'");
    TEST_ASSERT(huffman_decode(NULL, 0, enc, (size_t)en) == -1, "cap too small");
}

TEST(test_prefix_int_encode) {
    TEST_SUITE("huffman");

    TEST_CASE("RFC 7541 §C.1.1 — value 10, 5-bit prefix, no flags");
    uint8_t b[8];
    size_t n = prefix_int_encode(b, sizeof b, 10, 5, 0x00);
    TEST_ASSERT(n == 1 && b[0] == 0x0a, "fits the prefix");

    TEST_CASE("RFC 7541 §C.1.2 — value 1337, 5-bit prefix, no flags");
    n = prefix_int_encode(b, sizeof b, 1337, 5, 0x00);
    TEST_ASSERT(n == 3, "three octets");
    TEST_ASSERT(b[0] == 0x1f && b[1] == 0x9a && b[2] == 0x0a, "1f 9a 0a");

    TEST_CASE("flags are OR-ed into the first octet's high bits");
    /* A 4-bit prefix leaves the top 4 bits for the opcode; value 5 with opcode
     * 0x20 produces 0x25. QPACK/HPACK literal representations rely on this. */
    n = prefix_int_encode(b, sizeof b, 5, 4, 0x20);
    TEST_ASSERT(n == 1 && b[0] == 0x25, "opcode | value");

    TEST_CASE("an 8-bit prefix carries no flags — value 42");
    n = prefix_int_encode(b, sizeof b, 42, 8, 0x00);
    TEST_ASSERT(n == 1 && b[0] == 0x2a, "whole octet");

    TEST_CASE("refuses a buffer that is too small");
    TEST_ASSERT(prefix_int_encode(b, 2, 1337, 5, 0x00) == 0, "needs 3, got 2");

    TEST_CASE("rejects an out-of-range prefix width");
    TEST_ASSERT(prefix_int_encode(b, sizeof b, 1, 0, 0) == 0, "0 bits");
    TEST_ASSERT(prefix_int_encode(b, sizeof b, 1, 9, 0) == 0, "9 bits");
}

TEST(test_prefix_int_decode) {
    TEST_SUITE("huffman");

    uint64_t v = 0;

    TEST_CASE("RFC 7541 §C.1.1 — 0x0a, 5-bit prefix");
    const uint8_t a[] = { 0x0a };
    TEST_ASSERT(prefix_int_decode(a, sizeof a, 5, &v) == 1 && v == 10, "10");

    TEST_CASE("RFC 7541 §C.1.2 — 1f 9a 0a, 5-bit prefix");
    const uint8_t b3[] = { 0x1f, 0x9a, 0x0a };
    TEST_ASSERT(prefix_int_decode(b3, sizeof b3, 5, &v) == 3 && v == 1337,
                "1337, 3 octets consumed");

    TEST_CASE("the opcode high bits are ignored on decode");
    /* 0x25 with a 4-bit prefix: opcode 0x20, value 5. */
    const uint8_t c[] = { 0x25 };
    TEST_ASSERT(prefix_int_decode(c, sizeof c, 4, &v) == 1 && v == 5, "5");

    TEST_CASE("only the bytes the integer occupies are consumed");
    /* The integer, then an unrelated trailing byte. */
    const uint8_t d[] = { 0x1f, 0x9a, 0x0a, 0xff };
    TEST_ASSERT(prefix_int_decode(d, sizeof d, 5, &v) == 3 && v == 1337,
                "stops at 3");

    TEST_CASE("a truncated continuation is an error");
    const uint8_t trunc[] = { 0x1f, 0x9a };  /* the 0x0a terminator is missing */
    TEST_ASSERT(prefix_int_decode(trunc, sizeof trunc, 5, &v) == 0, "needs more");

    TEST_CASE("a never-terminating continuation is an error");
    const uint8_t loop[] = { 0x1f, 0x80, 0x80, 0x80, 0x80 };
    TEST_ASSERT(prefix_int_decode(loop, sizeof loop, 5, &v) == 0, "no terminator");

    TEST_CASE("a continuation longer than nine bytes is rejected");
    /* Ten continuation octets would encode a 70-bit value; the decoder caps the
     * work at nine, so a peer cannot drive it unbounded. */
    const uint8_t huge[] = { 0x1f,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
    TEST_ASSERT(prefix_int_decode(huge, sizeof huge, 5, &v) == 0, "refused");
}

TEST(test_prefix_int_roundtrip) {
    TEST_SUITE("huffman");

    TEST_CASE("a large value, 5-bit prefix, round-trips");
    const uint64_t values[] = { 0, 1, 30, 31, 32, 127, 128, 1337, 65535, 1000000 };
    int all_ok = 1;
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        uint8_t b[10];
        size_t n = prefix_int_encode(b, sizeof b, values[i], 5, 0x00);
        if (n == 0) { all_ok = 0; continue; }
        uint64_t v = 0;
        size_t m = prefix_int_decode(b, n, 5, &v);
        if (m != n || v != values[i]) all_ok = 0;
    }
    TEST_ASSERT(all_ok, "every value round-trips at a 5-bit prefix");
}

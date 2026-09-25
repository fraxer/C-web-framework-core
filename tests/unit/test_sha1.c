/*
 * Unit tests for misc/sha1.c, which computes the WebSocket accept value.
 *
 * The message schedule built each word as (data[j] << 24) + ..., shifting an
 * int: any byte of 0x80 or above in the top position -- the padding byte
 * does it for every message whose length is a multiple of four -- is
 * undefined behaviour, which UBSan reported on the first WebSocket handshake
 * fuzz_h1_connection completed. The vectors are RFC 3174's, and the lengths
 * are chosen so the high bytes land in every position of a word.
 */

#include "framework.h"
#include "sha1.h"

#include <stdio.h>
#include <string.h>

static void hex(const unsigned char* digest, char* out) {
    for (int i = 0; i < 20; i++) snprintf(out + 2 * i, 3, "%02x", digest[i]);
}

static int digest_is(const void* data, size_t size, const char* want) {
    unsigned char digest[20];
    char text[41];
    sha1(data, size, digest);
    hex(digest, text);
    return strcmp(text, want) == 0;
}

TEST(test_sha1_rfc3174_vectors) {
    TEST_SUITE("sha1");
    TEST_CASE("RFC 3174 test vectors");

    TEST_ASSERT(digest_is("", 0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"), "empty");
    TEST_ASSERT(digest_is("abc", 3, "a9993e364706816aba3e25717850c26c9cd0d89d"), "abc");
    TEST_ASSERT(digest_is("abcd", 4, "81fe8bfe87576c3ecb22426f8e57847382917acf"),
                "abcd: the padding byte opens a word");

    static const char two_blocks[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    TEST_ASSERT(digest_is(two_blocks, sizeof two_blocks - 1,
                          "84983e441c3bd26ebaae4aa1f95129e5e54670f1"), "two blocks");
}

TEST(test_sha1_high_bytes) {
    TEST_SUITE("sha1");
    TEST_CASE("bytes of 0x80 and above in every position of a word");

    unsigned char data[256];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (unsigned char)(255 - i);

    /* Bytes 0xff down to 0x00, digest from Python's hashlib. */
    TEST_ASSERT(digest_is(data, sizeof data, "5bb48c1e442fd1b06a76c7a896d1b10e8f724a13"),
                "256 descending bytes");
}

TEST(test_sha1_websocket_accept_input) {
    TEST_SUITE("sha1");
    TEST_CASE("the 60 bytes RFC 6455 §1.3 hashes");

    static const char input[] = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    TEST_ASSERT(digest_is(input, sizeof input - 1, "b37a4f2cc0624f1690f64606cf385945b2bec4ea"),
                "digest behind s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

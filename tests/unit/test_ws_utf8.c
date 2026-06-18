#include "framework.h"
#include "websocket/ws_utf8.h"
#include <string.h>

/* Binary-safe streaming UTF-8 validator for WebSocket TEXT payloads.
 * These exercise ws_utf8.h directly (unmasked/decompressed bytes). */

/* Validate a full NUL-free string in one shot (feed + finish). */
static int validate_str(const char* s) {
    ws_utf8_validator_t v;
    ws_utf8_validator_reset(&v);
    if (!ws_utf8_validator_feed(&v, (const unsigned char*)s, strlen(s)))
        return 0;
    return ws_utf8_validator_finish(&v);
}

/* Validate an explicit byte buffer in one shot. */
static int validate_buf(const unsigned char* b, size_t n) {
    ws_utf8_validator_t v;
    ws_utf8_validator_reset(&v);
    if (!ws_utf8_validator_feed(&v, b, n))
        return 0;
    return ws_utf8_validator_finish(&v);
}

TEST(test_ws_utf8_ascii) {
    TEST_CASE("ASCII is valid");

    TEST_ASSERT_EQUAL(1, validate_str("Hello, world!"), "plain ASCII should validate");
    TEST_ASSERT_EQUAL(1, validate_str(""), "empty string should validate");
}

TEST(test_ws_utf8_multibyte_valid) {
    TEST_CASE("Valid multibyte sequences (2/3/4 byte)");

    TEST_ASSERT_EQUAL(1, validate_str("Привет"), "Cyrillic (2-byte) should validate");
    TEST_ASSERT_EQUAL(1, validate_str("你好"), "CJK (3-byte) should validate");
    /* U+1F600 GRINNING FACE = F0 9F 98 80 */
    const unsigned char emoji[] = {0xF0, 0x9F, 0x98, 0x80};
    TEST_ASSERT_EQUAL(1, validate_buf(emoji, sizeof emoji), "4-byte emoji should validate");
}

TEST(test_ws_utf8_overlong) {
    TEST_CASE("Overlong encodings are rejected");

    /* C0 AF = overlong encoding of U+007F */
    const unsigned char o2[] = {0xC0, 0xAF};
    TEST_ASSERT_EQUAL(0, validate_buf(o2, sizeof o2), "2-byte overlong should fail");
    /* E0 80 AF = overlong encoding of U+007F */
    const unsigned char o3[] = {0xE0, 0x80, 0xAF};
    TEST_ASSERT_EQUAL(0, validate_buf(o3, sizeof o3), "3-byte overlong should fail");
    /* F0 80 80 80 = overlong encoding of U+0000 */
    const unsigned char o4[] = {0xF0, 0x80, 0x80, 0x80};
    TEST_ASSERT_EQUAL(0, validate_buf(o4, sizeof o4), "4-byte overlong should fail");
}

TEST(test_ws_utf8_surrogates) {
    TEST_CASE("UTF-16 surrogates are rejected");

    /* ED A0 80 = U+D800 (high surrogate) */
    const unsigned char hi[] = {0xED, 0xA0, 0x80};
    TEST_ASSERT_EQUAL(0, validate_buf(hi, sizeof hi), "high surrogate should fail");
    /* ED BF BF = U+DFFF (low surrogate) */
    const unsigned char lo[] = {0xED, 0xBF, 0xBF};
    TEST_ASSERT_EQUAL(0, validate_buf(lo, sizeof lo), "low surrogate should fail");
    /* ED 9F BF = U+D7FF is the last valid before surrogates */
    const unsigned char ok[] = {0xED, 0x9F, 0xBF};
    TEST_ASSERT_EQUAL(1, validate_buf(ok, sizeof ok), "U+D7FF should validate");
}

TEST(test_ws_utf8_out_of_range) {
    TEST_CASE("Codepoints above U+10FFFF are rejected");

    /* F4 90 80 80 = U+110000 */
    const unsigned char over[] = {0xF4, 0x90, 0x80, 0x80};
    TEST_ASSERT_EQUAL(0, validate_buf(over, sizeof over), "U+110000 should fail");
    /* F4 8F BF BF = U+10FFFF is the maximum valid */
    const unsigned char max[] = {0xF4, 0x8F, 0xBF, 0xBF};
    TEST_ASSERT_EQUAL(1, validate_buf(max, sizeof max), "U+10FFFF should validate");
}

TEST(test_ws_utf8_bad_leads_and_continuations) {
    TEST_CASE("Invalid lead bytes and stray continuations");

    const unsigned char lone[] = {0x80};
    TEST_ASSERT_EQUAL(0, validate_buf(lone, sizeof lone), "lone continuation should fail");
    const unsigned char c0[] = {0xC0, 0x80};
    TEST_ASSERT_EQUAL(0, validate_buf(c0, sizeof c0), "C0 lead should fail");
    const unsigned char f5[] = {0xF5, 0x80, 0x80, 0x80};
    TEST_ASSERT_EQUAL(0, validate_buf(f5, sizeof f5), "F5 lead should fail");
    const unsigned char ff[] = {0xFF};
    TEST_ASSERT_EQUAL(0, validate_buf(ff, sizeof ff), "0xFF should fail");
    /* valid lead, non-continuation follower */
    const unsigned char bad[] = {0xC2, 0x41};
    TEST_ASSERT_EQUAL(0, validate_buf(bad, sizeof bad), "C2 + ASCII should fail");
}

TEST(test_ws_utf8_incomplete_at_finish) {
    TEST_CASE("Dangling partial sequence fails finish()");

    /* C2 with no continuation: feed ok, finish must fail */
    ws_utf8_validator_t v;
    ws_utf8_validator_reset(&v);
    const unsigned char lead[] = {0xC2};
    TEST_ASSERT_EQUAL(1, ws_utf8_validator_feed(&v, lead, sizeof lead), "partial feed should be tolerated");
    TEST_ASSERT_EQUAL(0, ws_utf8_validator_finish(&v), "unfinished sequence should fail finish");

    /* 3-byte CJK 你 = E4 BD A0 fed one byte short */
    ws_utf8_validator_reset(&v);
    const unsigned char part[] = {0xE4, 0xBD};
    TEST_ASSERT_EQUAL(1, ws_utf8_validator_feed(&v, part, sizeof part), "partial 3-byte feed should be tolerated");
    TEST_ASSERT_EQUAL(0, ws_utf8_validator_finish(&v), "unfinished 3-byte should fail finish");
}

TEST(test_ws_utf8_split_across_chunks) {
    TEST_CASE("Multi-byte sequence split across feed() calls validates");

    ws_utf8_validator_t v;
    ws_utf8_validator_reset(&v);

    /* 你 = E4 BD A0, split as [E4 BD] then [A0] */
    const unsigned char a[] = {0xE4, 0xBD};
    const unsigned char b[] = {0xA0};
    TEST_ASSERT_EQUAL(1, ws_utf8_validator_feed(&v, a, sizeof a), "first chunk should be tolerated");
    TEST_ASSERT_EQUAL(1, ws_utf8_validator_feed(&v, b, sizeof b), "second chunk should complete the sequence");
    TEST_ASSERT_EQUAL(1, ws_utf8_validator_finish(&v), "completed split sequence should validate");

    /* A full message split at arbitrary boundaries stays valid. */
    ws_utf8_validator_reset(&v);
    const unsigned char* msg = (const unsigned char*)"Привет, 世界! 👋";
    size_t len = strlen((const char*)msg);
    /* feed byte-by-byte */
    int ok = 1;
    for (size_t i = 0; i < len && ok; i++)
        ok = ws_utf8_validator_feed(&v, msg + i, 1);
    TEST_ASSERT_EQUAL(1, ok, "byte-by-byte feed should not break validation");
    TEST_ASSERT_EQUAL(1, ws_utf8_validator_finish(&v), "byte-by-byte message should validate");
}

TEST(test_ws_utf8_invalid_poison_mid_message) {
    TEST_CASE("Invalid byte mid-message is caught immediately");

    ws_utf8_validator_t v;
    ws_utf8_validator_reset(&v);
    /* "AB" then a lone continuation */
    const unsigned char good[] = {'A', 'B'};
    const unsigned char bad[] = {0x80};
    TEST_ASSERT_EQUAL(1, ws_utf8_validator_feed(&v, good, sizeof good), "ASCII prefix should validate");
    TEST_ASSERT_EQUAL(0, ws_utf8_validator_feed(&v, bad, sizeof bad), "stray continuation should fail immediately");
}

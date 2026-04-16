#include "framework.h"
#include "base64.h"
#include <string.h>
#include <stdlib.h>

// ============================================================================
// Convention:
//   _len() returns buffer size INCLUDING null terminator
//   _encode() returns string length EXCLUDING null terminator (i.e. strlen)
// ============================================================================

// ============================================================================
// base64_encode / base64_encode_len
// ============================================================================

TEST(test_base64_encode_empty) {
    TEST_CASE("Encode empty string");

    int len = base64_encode_len(0);
    char* buf = malloc(len);
    int result = base64_encode(buf, "", 0);

    TEST_ASSERT_STR_EQUAL("", buf, "Empty string should encode to empty string");
    TEST_ASSERT_EQUAL(0, result, "Result should be 0 (strlen of empty string)");
    free(buf);
}

TEST(test_base64_encode_single_byte) {
    TEST_CASE("Encode single byte (1 byte -> 2 base64 chars + 2 padding)");

    const char* input = "A";
    int len = base64_encode_len(1);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 1);

    TEST_ASSERT_STR_EQUAL("QQ==", buf, "'A' should encode to 'QQ=='");
    TEST_ASSERT_EQUAL(4, result, "Result should be 4 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_two_bytes) {
    TEST_CASE("Encode two bytes (2 bytes -> 3 base64 chars + 1 padding)");

    const char* input = "AB";
    int len = base64_encode_len(2);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 2);

    TEST_ASSERT_STR_EQUAL("QUI=", buf, "'AB' should encode to 'QUI='");
    TEST_ASSERT_EQUAL(4, result, "Result should be 4 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_three_bytes) {
    TEST_CASE("Encode three bytes (3 bytes -> 4 base64 chars, no padding)");

    const char* input = "ABC";
    int len = base64_encode_len(3);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 3);

    TEST_ASSERT_STR_EQUAL("QUJD", buf, "'ABC' should encode to 'QUJD'");
    TEST_ASSERT_EQUAL(4, result, "Result should be 4 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_four_bytes) {
    TEST_CASE("Encode four bytes (4 bytes -> 8 base64 chars + padding)");

    const char* input = "ABCD";
    int len = base64_encode_len(4);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 4);

    TEST_ASSERT_STR_EQUAL("QUJDRA==", buf, "'ABCD' should encode to 'QUJDRA=='");
    TEST_ASSERT_EQUAL(8, result, "Result should be 8 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_five_bytes) {
    TEST_CASE("Encode five bytes (5 bytes -> 8 base64 chars + padding)");

    const char* input = "ABCDE";
    int len = base64_encode_len(5);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 5);

    TEST_ASSERT_STR_EQUAL("QUJDREU=", buf, "'ABCDE' should encode to 'QUJDREU='");
    TEST_ASSERT_EQUAL(8, result, "Result should be 8 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_six_bytes) {
    TEST_CASE("Encode six bytes (6 bytes -> 8 base64 chars, no padding)");

    const char* input = "ABCDEF";
    int len = base64_encode_len(6);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 6);

    TEST_ASSERT_STR_EQUAL("QUJDREVG", buf, "'ABCDEF' should encode to 'QUJDREVG'");
    TEST_ASSERT_EQUAL(8, result, "Result should be 8 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_hello_world) {
    TEST_CASE("Encode 'Hello, World!'");

    const char* input = "Hello, World!";
    int input_len = (int)strlen(input);
    int len = base64_encode_len(input_len);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, input_len);

    TEST_ASSERT_STR_EQUAL("SGVsbG8sIFdvcmxkIQ==", buf, "'Hello, World!' should encode correctly");
    TEST_ASSERT_EQUAL(20, result, "Result should be 20 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_exact_multiple_of_3) {
    TEST_CASE("Encode 9 bytes (exact multiple of 3, no padding)");

    const char* input = "abcdefghi";
    int len = base64_encode_len(9);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 9);

    TEST_ASSERT_STR_EQUAL("YWJjZGVmZ2hp", buf, "9 bytes should encode without padding");
    TEST_ASSERT_EQUAL(12, result, "Result should be 12 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_binary_data) {
    TEST_CASE("Encode binary data with non-printable bytes");

    // Test with bytes 0-5 (non-printable)
    const char input[] = {0, 1, 2, 3, 4, 5};
    int len = base64_encode_len(6);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 6);

    TEST_ASSERT_STR_EQUAL("AAECAwQF", buf, "Bytes 0-5 should encode correctly");
    TEST_ASSERT_EQUAL(8, result, "Result should be 8 (strlen, no null)");
    free(buf);
}

TEST(test_base64_encode_all_256_values) {
    TEST_CASE("Encode all 256 byte values");

    char input[256];
    for (int i = 0; i < 256; i++)
        input[i] = (char)i;

    int len = base64_encode_len(256);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 256);

    // 256 / 3 * 4 = 344 chars (no remainder)
    TEST_ASSERT_EQUAL(344, result, "256 bytes should encode to 344 chars (strlen)");
    TEST_ASSERT_EQUAL('\0', buf[344], "Should be null terminated after 344 chars");
    free(buf);
}

TEST(test_base64_encode_len_formula) {
    TEST_CASE("Verify base64_encode_len formula: ((len+2)/3*4)+1");

    TEST_ASSERT_EQUAL(1, base64_encode_len(0), "len=0");
    TEST_ASSERT_EQUAL(5, base64_encode_len(1), "len=1");
    TEST_ASSERT_EQUAL(5, base64_encode_len(2), "len=2");
    TEST_ASSERT_EQUAL(5, base64_encode_len(3), "len=3");
    TEST_ASSERT_EQUAL(9, base64_encode_len(4), "len=4");
    TEST_ASSERT_EQUAL(9, base64_encode_len(5), "len=5");
    TEST_ASSERT_EQUAL(9, base64_encode_len(6), "len=6");
    TEST_ASSERT_EQUAL(13, base64_encode_len(7), "len=7");
    TEST_ASSERT_EQUAL(13, base64_encode_len(8), "len=8");
    TEST_ASSERT_EQUAL(13, base64_encode_len(9), "len=9");
}

TEST(test_base64_encode_null_termination) {
    TEST_CASE("Output is always null terminated");

    const char* input = "Test";
    int len = base64_encode_len(4);
    char* buf = malloc(len);
    base64_encode(buf, input, 4);

    int result = (int)strlen(buf);
    TEST_ASSERT_EQUAL('\0', buf[result], "Null terminator at strlen position");
    TEST_ASSERT(result < len, "strlen must be less than allocated buffer size");

    free(buf);
}

// ============================================================================
// base64_encode_nl / base64_encode_nl_len
// ============================================================================

TEST(test_base64_encode_nl_empty) {
    TEST_CASE("Encode empty string with newline wrapping");

    int len = base64_encode_nl_len(0, 76);
    char* buf = malloc(len);
    int result = base64_encode_nl(buf, "", 0, 76);

    TEST_ASSERT_STR_EQUAL("", buf, "Empty string should encode to empty string");
    TEST_ASSERT_EQUAL(0, result, "Result should be 0");
    free(buf);
}

TEST(test_base64_encode_nl_short_no_wrap) {
    TEST_CASE("Short string should not wrap");

    const char* input = "ABC";
    int len = base64_encode_nl_len(3, 76);
    char* buf = malloc(len);
    int result = base64_encode_nl(buf, input, 3, 76);

    TEST_ASSERT_STR_EQUAL("QUJD", buf, "Short input should not wrap");
    TEST_ASSERT_EQUAL(4, result, "Result should be 4");
    free(buf);
}

TEST(test_base64_encode_nl_zero_wrap_same_as_plain) {
    TEST_CASE("wrap=0 should produce same output as base64_encode");

    const char* input = "Hello, World!";
    int input_len = (int)strlen(input);

    int len_nl = base64_encode_nl_len(input_len, 0);
    int len_plain = base64_encode_len(input_len);
    TEST_ASSERT_EQUAL(len_plain, len_nl, "wrap=0 should produce same buffer size");

    char* buf_nl = malloc(len_nl);
    char* buf_plain = malloc(len_plain);

    base64_encode_nl(buf_nl, input, input_len, 0);
    base64_encode(buf_plain, input, input_len);

    TEST_ASSERT_STR_EQUAL(buf_plain, buf_nl, "wrap=0 should produce same output");

    free(buf_nl);
    free(buf_plain);
}

TEST(test_base64_encode_nl_exact_boundary) {
    TEST_CASE("57 bytes -> 76 base64 chars, exactly one wrap line");

    // 57 bytes * 4/3 = 76 base64 chars
    char input[57];
    memset(input, 'A', 57);

    int len = base64_encode_nl_len(57, 76);
    char* buf = malloc(len);
    int result = base64_encode_nl(buf, input, 57, 76);

    // pc reaches 76, 76 % 76 == 0, so \r\n is inserted after last char
    // Result: 76 chars + \r\n + \0 = 79 bytes, strlen = 78
    TEST_ASSERT_EQUAL(78, result, "57 bytes: 76 base64 + \\r\\n = 78 strlen");
    TEST_ASSERT_EQUAL('\r', buf[76], "Position 76 should be \\r");
    TEST_ASSERT_EQUAL('\n', buf[77], "Position 77 should be \\n");
    TEST_ASSERT_EQUAL('\0', buf[78], "Position 78 should be null");
    free(buf);
}

TEST(test_base64_encode_nl_past_boundary) {
    TEST_CASE("58 bytes -> wrap after 76 chars, then remaining 4 chars");

    // 58 bytes -> ceil(58/3)*4 = 80 base64 chars
    char input[58];
    memset(input, 'A', 58);

    int len = base64_encode_nl_len(58, 76);
    char* buf = malloc(len);
    int result = base64_encode_nl(buf, input, 58, 76);

    // First wrap at position 76
    TEST_ASSERT_EQUAL('\r', buf[76], "Position 76 should be \\r");
    TEST_ASSERT_EQUAL('\n', buf[77], "Position 77 should be \\n");

    // Second line: 4 chars (78,79,80,81), then null at 82
    TEST_ASSERT_EQUAL('\0', buf[82], "Position 82 should be null");
    TEST_ASSERT_EQUAL(82, result, "strlen should be 82");
    free(buf);
}

TEST(test_base64_encode_nl_multiple_wraps) {
    TEST_CASE("Multiple line wraps for large input");

    // 300 bytes -> 400 base64 chars
    char input[300];
    memset(input, 'X', 300);

    int len = base64_encode_nl_len(300, 76);
    char* buf = malloc(len);
    int result = base64_encode_nl(buf, input, 300, 76);

    TEST_ASSERT(result <= len, "Result must fit in buffer");
    TEST_ASSERT_EQUAL('\0', buf[result], "Must be null terminated");

    // Verify each line before \r\n is exactly 76 base64 chars
    int line_len = 0;
    for (int i = 0; i < result; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            TEST_ASSERT_EQUAL(76, line_len, "Line should be exactly 76 base64 chars before wrap");
            line_len = 0;
            i++; // skip \n
        } else if (buf[i] != '\0') {
            line_len++;
        }
    }
    free(buf);
}

TEST(test_base64_encode_nl_len_sufficient) {
    TEST_CASE("_nl_len buffer must be large enough (no overflow)");

    // Test various sizes that could trigger the original bug
    int sizes[] = {1, 2, 3, 57, 58, 100, 256, 450, 500, 1000, 9999};

    for (int s = 0; s < 11; s++) {
        int sz = sizes[s];
        char input[10000];
        memset(input, 'M', sz);

        int len = base64_encode_nl_len(sz, 76);
        char* buf = malloc(len);
        int result = base64_encode_nl(buf, input, sz, 76);

        TEST_ASSERT(result <= len, "Result must fit in buffer");
        TEST_ASSERT_EQUAL('\0', buf[result], "Must be null terminated");

        // Roundtrip check
        int dec_len = base64_decode_len(buf);
        char* decoded = malloc(dec_len);
        int dec_result = base64_decode(decoded, buf);
        TEST_ASSERT_EQUAL(sz, dec_result, "Roundtrip length must match");

        free(buf);
        free(decoded);
    }
}

TEST(test_base64_encode_nl_different_wrap_values) {
    TEST_CASE("Different wrap values produce correct line lengths");

    const char* input = "ABCDEFGHIJKLMNOPQRSTUVWX"; // 24 bytes -> 32 base64 chars
    int input_len = (int)strlen(input);

    // wrap=16: 32/16 = 2 full lines -> 2 wraps
    int len16 = base64_encode_nl_len(input_len, 16);
    char* buf16 = malloc(len16);
    base64_encode_nl(buf16, input, input_len, 16);

    // Verify each line is exactly 16 chars before wrap
    int line_len = 0;
    int max_line = 0;
    for (int i = 0; buf16[i] != '\0'; i++) {
        if (buf16[i] == '\r' && buf16[i + 1] == '\n') {
            if (max_line < line_len) max_line = line_len;
            line_len = 0;
            i++;
        } else {
            line_len++;
        }
    }
    if (line_len > max_line) max_line = line_len;

    TEST_ASSERT_EQUAL(16, max_line, "With wrap=16, max line length should be 16");
    free(buf16);
}

// ============================================================================
// base64_decode / base64_decode_len
// ============================================================================

TEST(test_base64_decode_empty) {
    TEST_CASE("Decode empty string");

    int len = base64_decode_len("");
    char* buf = malloc(len > 0 ? len : 1);
    int result = base64_decode(buf, "");

    TEST_ASSERT_EQUAL(0, result, "Empty input should decode to 0 bytes");
    free(buf);
}

TEST(test_base64_decode_single_padding) {
    TEST_CASE("Decode 'QQ==' (single byte)");

    int len = base64_decode_len("QQ==");
    char* buf = malloc(len);
    int result = base64_decode(buf, "QQ==");

    TEST_ASSERT_EQUAL(1, result, "'QQ==' should decode to 1 byte");
    TEST_ASSERT_EQUAL('A', buf[0], "Decoded byte should be 'A'");
    free(buf);
}

TEST(test_base64_decode_two_padding) {
    TEST_CASE("Decode 'QUI=' (two bytes)");

    int len = base64_decode_len("QUI=");
    char* buf = malloc(len);
    int result = base64_decode(buf, "QUI=");

    TEST_ASSERT_EQUAL(2, result, "'QUI=' should decode to 2 bytes");
    TEST_ASSERT_EQUAL('A', buf[0], "First byte should be 'A'");
    TEST_ASSERT_EQUAL('B', buf[1], "Second byte should be 'B'");
    free(buf);
}

TEST(test_base64_decode_no_padding) {
    TEST_CASE("Decode 'QUJD' (three bytes)");

    int len = base64_decode_len("QUJD");
    char* buf = malloc(len);
    int result = base64_decode(buf, "QUJD");

    TEST_ASSERT_EQUAL(3, result, "'QUJD' should decode to 3 bytes");
    TEST_ASSERT_EQUAL('A', buf[0], "First byte should be 'A'");
    TEST_ASSERT_EQUAL('B', buf[1], "Second byte should be 'B'");
    TEST_ASSERT_EQUAL('C', buf[2], "Third byte should be 'C'");
    free(buf);
}

TEST(test_base64_decode_hello_world) {
    TEST_CASE("Decode 'SGVsbG8sIFdvcmxkIQ=='");

    int len = base64_decode_len("SGVsbG8sIFdvcmxkIQ==");
    char* buf = malloc(len);
    int result = base64_decode(buf, "SGVsbG8sIFdvcmxkIQ==");

    TEST_ASSERT_EQUAL(13, result, "Should decode to 13 bytes");
    TEST_ASSERT_STR_EQUAL("Hello, World!", buf, "Should decode to 'Hello, World!'");
    free(buf);
}

TEST(test_base64_decode_with_newlines) {
    TEST_CASE("Decode base64 with CRLF line breaks");

    const char* input = "ABCDEFGHIJKLMNOPQRSTUVWX"; // 24 bytes
    int input_len = (int)strlen(input);

    int enc_len = base64_encode_nl_len(input_len, 16);
    char* encoded = malloc(enc_len);
    base64_encode_nl(encoded, input, input_len, 16);

    TEST_ASSERT(strstr(encoded, "\r\n") != NULL, "Encoded string should contain CRLF");

    int dec_len = base64_decode_len(encoded);
    char* decoded = malloc(dec_len);
    int result = base64_decode(decoded, encoded);

    TEST_ASSERT_EQUAL(input_len, result, "Decoded length should match original");
    TEST_ASSERT(memcmp(input, decoded, input_len) == 0, "Decoded content should match original");

    free(encoded);
    free(decoded);
}

TEST(test_base64_decode_binary_roundtrip) {
    TEST_CASE("Encode and decode all 256 byte values");

    char original[256];
    for (int i = 0; i < 256; i++)
        original[i] = (char)i;

    int enc_len = base64_encode_len(256);
    char* encoded = malloc(enc_len);
    base64_encode(encoded, original, 256);

    int dec_len = base64_decode_len(encoded);
    char* decoded = malloc(dec_len);
    int result = base64_decode(decoded, encoded);

    TEST_ASSERT_EQUAL(256, result, "Should decode to 256 bytes");
    TEST_ASSERT(memcmp(original, decoded, 256) == 0, "All 256 bytes should roundtrip correctly");

    free(encoded);
    free(decoded);
}

// ============================================================================
// Roundtrip tests (encode -> decode == original)
// ============================================================================

TEST(test_base64_roundtrip_short_strings) {
    TEST_CASE("Roundtrip strings of lengths 1-20");

    for (int len = 1; len <= 20; len++) {
        char input[21];
        for (int i = 0; i < len; i++)
            input[i] = (char)('a' + (i % 26));
        input[len] = '\0';

        int enc_len = base64_encode_len(len);
        char* encoded = malloc(enc_len);
        base64_encode(encoded, input, len);

        int dec_len = base64_decode_len(encoded);
        char* decoded = malloc(dec_len);
        int result = base64_decode(decoded, encoded);

        TEST_ASSERT_EQUAL(len, result, "Roundtrip length mismatch");
        TEST_ASSERT(memcmp(input, decoded, len) == 0, "Roundtrip content mismatch");

        free(encoded);
        free(decoded);
    }
}

TEST(test_base64_nl_roundtrip_500_bytes) {
    TEST_CASE("Roundtrip with wrapping for 500 bytes");

    const int input_len = 500;
    char input_buf[500];
    for (int i = 0; i < input_len; i++)
        input_buf[i] = (char)(i % 256);

    int enc_len = base64_encode_nl_len(input_len, 76);
    char* encoded = malloc(enc_len);
    base64_encode_nl(encoded, input_buf, input_len, 76);

    TEST_ASSERT(strstr(encoded, "\r\n") != NULL, "Encoded string should contain CRLF");

    int dec_len = base64_decode_len(encoded);
    char* decoded = malloc(dec_len);
    int result = base64_decode(decoded, encoded);

    TEST_ASSERT_EQUAL(input_len, result, "500-byte roundtrip length should match");
    TEST_ASSERT(memcmp(input_buf, decoded, input_len) == 0, "500-byte roundtrip content should match");

    free(encoded);
    free(decoded);
}

TEST(test_base64_nl_roundtrip_1000_bytes) {
    TEST_CASE("Roundtrip 1000 pseudo-random bytes with wrapping");

    const int input_len = 1000;
    char input_buf[1000];
    for (int i = 0; i < input_len; i++)
        input_buf[i] = (char)((i * 7 + 13) % 256);

    int enc_len = base64_encode_nl_len(input_len, 76);
    char* encoded = malloc(enc_len);
    base64_encode_nl(encoded, input_buf, input_len, 76);

    int dec_len = base64_decode_len(encoded);
    char* decoded = malloc(dec_len);
    int result = base64_decode(decoded, encoded);

    TEST_ASSERT_EQUAL(input_len, result, "1000-byte roundtrip length should match");
    TEST_ASSERT(memcmp(input_buf, decoded, input_len) == 0, "1000-byte roundtrip content should match");

    free(encoded);
    free(decoded);
}

// ============================================================================
// Edge cases / boundary conditions
// ============================================================================

TEST(test_base64_encode_single_null_byte) {
    TEST_CASE("Encode single null byte");

    const char input[] = {'\0'};
    int len = base64_encode_len(1);
    char* buf = malloc(len);
    int result = base64_encode(buf, input, 1);

    TEST_ASSERT_STR_EQUAL("AA==", buf, "Null byte should encode to 'AA=='");
    TEST_ASSERT_EQUAL(4, result, "Result should be 4 (strlen)");
    free(buf);
}

TEST(test_base64_decode_single_null_byte) {
    TEST_CASE("Decode 'AA==' back to null byte");

    int len = base64_decode_len("AA==");
    char* buf = malloc(len);
    int result = base64_decode(buf, "AA==");

    TEST_ASSERT_EQUAL(1, result, "Should decode to 1 byte");
    TEST_ASSERT_EQUAL(0, (unsigned char)buf[0], "Decoded byte should be 0");
    free(buf);
}

TEST(test_base64_encode_all_zeros) {
    TEST_CASE("Encode buffer of all zeros");

    char input[30];
    memset(input, 0, 30);

    int enc_len = base64_encode_len(30);
    char* encoded = malloc(enc_len);
    base64_encode(encoded, input, 30);

    int dec_len = base64_decode_len(encoded);
    char* decoded = malloc(dec_len);
    int result = base64_decode(decoded, encoded);

    TEST_ASSERT_EQUAL(30, result, "All-zeros roundtrip length should match");
    TEST_ASSERT(memcmp(input, decoded, 30) == 0, "All-zeros roundtrip content should match");

    free(encoded);
    free(decoded);
}

TEST(test_base64_encode_all_0xff) {
    TEST_CASE("Encode buffer of all 0xFF");

    char input[30];
    memset(input, 0xFF, 30);

    int enc_len = base64_encode_len(30);
    char* encoded = malloc(enc_len);
    base64_encode(encoded, input, 30);

    int dec_len = base64_decode_len(encoded);
    char* decoded = malloc(dec_len);
    int result = base64_decode(decoded, encoded);

    TEST_ASSERT_EQUAL(30, result, "All-0xFF roundtrip length should match");
    TEST_ASSERT(memcmp(input, decoded, 30) == 0, "All-0xFF roundtrip content should match");

    free(encoded);
    free(decoded);
}

TEST(test_base64_encode_len_large) {
    TEST_CASE("Encode length calculation for large inputs");

    // Formula: ((len + 2) / 3 * 4) + 1
    TEST_ASSERT_EQUAL(13337, base64_encode_len(10000), "10000 bytes");
    TEST_ASSERT_EQUAL(133333, base64_encode_len(99999), "99999 bytes");
    TEST_ASSERT_EQUAL(5, base64_encode_len(3), "3 bytes (exact multiple)");
}

TEST(test_base64_encode_nl_len_large) {
    TEST_CASE("Encode_nl length for large input must exceed plain len");

    int len_plain = base64_encode_len(10000);
    int len_nl = base64_encode_nl_len(10000, 76);

    TEST_ASSERT(len_nl > len_plain, "nl_len should be greater than plain len for large input");
    TEST_ASSERT(len_nl < len_plain + 10000, "nl_len overhead should be reasonable");
}

TEST(test_base64_encode_nl_no_buffer_overflow_bug_size) {
    TEST_CASE("Verify the exact size that triggered the original heap-buffer-overflow");

    // The original crash was on a 599-byte buffer with body producing ~600 bytes of output.
    // Test sizes around the boundary to ensure no overflow.
    char input[450];
    memset(input, 'M', 450);

    int len = base64_encode_nl_len(450, 76);
    char* buf = malloc(len);
    int result = base64_encode_nl(buf, input, 450, 76);

    TEST_ASSERT(result <= len, "Encoded result must fit in allocated buffer");
    TEST_ASSERT_EQUAL('\0', buf[result], "Buffer must be null terminated");

    // Roundtrip
    int dec_len = base64_decode_len(buf);
    char* decoded = malloc(dec_len);
    int dec_result = base64_decode(decoded, buf);

    TEST_ASSERT_EQUAL(450, dec_result, "Roundtrip length must match");
    TEST_ASSERT(memcmp(input, decoded, 450) == 0, "Roundtrip content must match");

    free(buf);
    free(decoded);
}

TEST(test_base64_encode_nl_wrap_1) {
    TEST_CASE("wrap=1 inserts CRLF after every single base64 char");

    const char* input = "ABC";
    int len = base64_encode_nl_len(3, 1);
    char* buf = malloc(len);
    int result = base64_encode_nl(buf, input, 3, 1);

    TEST_ASSERT(result > 4, "With wrap=1, result should be much longer than 4");
    TEST_ASSERT(strstr(buf, "\r\n") != NULL, "Should contain CRLF");

    // Roundtrip
    int dec_len = base64_decode_len(buf);
    char* decoded = malloc(dec_len);
    int dec_result = base64_decode(decoded, buf);

    TEST_ASSERT_EQUAL(3, dec_result, "Should decode back to 3 bytes");
    TEST_ASSERT(memcmp(input, decoded, 3) == 0, "Content should roundtrip");

    free(buf);
    free(decoded);
}

TEST(test_base64_encode_nl_wrap_equals_4) {
    TEST_CASE("wrap=4 inserts CRLF after every group of 4 base64 chars");

    const char* input = "ABCDEFGH"; // 8 bytes -> ~12 base64 chars (rounds up to 12)
    int input_len = (int)strlen(input);

    int len = base64_encode_nl_len(input_len, 4);
    char* buf = malloc(len);
    base64_encode_nl(buf, input, input_len, 4);

    // Each line should be exactly 4 base64 chars before \r\n
    int line_len = 0;
    int max_line = 0;
    for (int i = 0; buf[i] != '\0'; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            if (max_line < line_len) max_line = line_len;
            line_len = 0;
            i++;
        } else {
            line_len++;
        }
    }
    if (line_len > max_line) max_line = line_len;

    TEST_ASSERT_EQUAL(4, max_line, "With wrap=4, max line length should be 4");
    free(buf);
}

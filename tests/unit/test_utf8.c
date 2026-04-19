#include "framework.h"
#include "utf8.h"

/* ── utf8_strlen ─────────────────────────────────────────────────────── */

TEST(test_utf8_strlen_ascii) {
    TEST_CASE("ASCII string length");

    size_t len = utf8_strlen("Hello");
    TEST_ASSERT_EQUAL_SIZE(5, len, "ASCII string should have 5 characters");
}

TEST(test_utf8_strlen_cyrillic) {
    TEST_CASE("Cyrillic string length");

    size_t len = utf8_strlen("Привет");
    TEST_ASSERT_EQUAL_SIZE(6, len, "Cyrillic string should have 6 characters");
}

TEST(test_utf8_strlen_mixed) {
    TEST_CASE("Mixed script string length");

    size_t len = utf8_strlen("Привет world 123");
    TEST_ASSERT_EQUAL_SIZE(16, len, "Mixed string should have 16 characters");
}

TEST(test_utf8_strlen_cjk) {
    TEST_CASE("CJK string length (3-byte characters)");

    size_t len = utf8_strlen("你好");
    TEST_ASSERT_EQUAL_SIZE(2, len, "CJK string should have 2 characters");
}

TEST(test_utf8_strlen_emoji) {
    TEST_CASE("Emoji string length (4-byte characters)");

    size_t len = utf8_strlen("🎉");
    TEST_ASSERT_EQUAL_SIZE(1, len, "Single emoji should be 1 character");
}

TEST(test_utf8_strlen_empty) {
    TEST_CASE("Empty string");

    TEST_ASSERT_EQUAL_SIZE(0, utf8_strlen(""), "Empty string should be 0");
}

TEST(test_utf8_strlen_null) {
    TEST_CASE("NULL input");

    TEST_ASSERT_EQUAL_SIZE(0, utf8_strlen(NULL), "NULL should be 0");
}

/* ── utf8_toupper / utf8_tolower ─────────────────────────────────────── */

TEST(test_utf8_toupper_ascii) {
    TEST_CASE("ASCII to uppercase");

    char* upper = utf8_toupper("hello");
    TEST_ASSERT_NOT_NULL(upper, "Should return non-NULL");
    TEST_ASSERT_STR_EQUAL("HELLO", upper, "Should be uppercase");
    free(upper);
}

TEST(test_utf8_toupper_cyrillic) {
    TEST_CASE("Cyrillic to uppercase");

    char* upper = utf8_toupper("привет");
    TEST_ASSERT_NOT_NULL(upper, "Should return non-NULL");
    TEST_ASSERT_STR_EQUAL("ПРИВЕТ", upper, "Should be uppercase Cyrillic");
    free(upper);
}

TEST(test_utf8_tolower_ascii) {
    TEST_CASE("ASCII to lowercase");

    char* lower = utf8_tolower("HELLO");
    TEST_ASSERT_NOT_NULL(lower, "Should return non-NULL");
    TEST_ASSERT_STR_EQUAL("hello", lower, "Should be lowercase");
    free(lower);
}

TEST(test_utf8_tolower_cyrillic) {
    TEST_CASE("Cyrillic to lowercase");

    char* lower = utf8_tolower("ПРИВЕТ");
    TEST_ASSERT_NOT_NULL(lower, "Should return non-NULL");
    TEST_ASSERT_STR_EQUAL("привет", lower, "Should be lowercase Cyrillic");
    free(lower);
}

TEST(test_utf8_toupper_already_upper) {
    TEST_CASE("Already uppercase stays the same");

    char* upper = utf8_toupper("ABC");
    TEST_ASSERT_NOT_NULL(upper, "Should return non-NULL");
    TEST_ASSERT_STR_EQUAL("ABC", upper, "Should remain uppercase");
    free(upper);
}

TEST(test_utf8_toupper_null) {
    TEST_CASE("NULL input returns NULL");

    char* result = utf8_toupper(NULL);
    TEST_ASSERT_NULL(result, "NULL input should return NULL");
}

TEST(test_utf8_tolower_null) {
    TEST_CASE("NULL input returns NULL");

    char* result = utf8_tolower(NULL);
    TEST_ASSERT_NULL(result, "NULL input should return NULL");
}

TEST(test_utf8_case_roundtrip) {
    TEST_CASE("Uppercase then lowercase preserves content");

    char* upper = utf8_toupper("Hello Мир");
    TEST_ASSERT_NOT_NULL(upper, "Upper should not be NULL");

    char* lower = utf8_tolower(upper);
    TEST_ASSERT_NOT_NULL(lower, "Lower should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello мир", lower, "Roundtrip should match");

    free(upper);
    free(lower);
}

/* ── utf8_casecmp ────────────────────────────────────────────────────── */

TEST(test_utf8_casecmp_equal_cyrillic) {
    TEST_CASE("Equal Cyrillic strings with different case");

    int result = utf8_casecmp("Привет", "привет");
    TEST_ASSERT_EQUAL(0, result, "Should be equal ignoring case");
}

TEST(test_utf8_casecmp_equal_ascii) {
    TEST_CASE("Equal ASCII strings with different case");

    int result = utf8_casecmp("Hello", "hello");
    TEST_ASSERT_EQUAL(0, result, "Should be equal ignoring case");
}

TEST(test_utf8_casecmp_not_equal) {
    TEST_CASE("Different strings");

    int result = utf8_casecmp("Привет", "Пока");
    TEST_ASSERT(result != 0, "Should not be equal");
}

TEST(test_utf8_casecmp_null_both) {
    TEST_CASE("Both NULL");

    int result = utf8_casecmp(NULL, NULL);
    TEST_ASSERT_EQUAL(0, result, "Both NULL should return 0");
}

TEST(test_utf8_casecmp_null_one) {
    TEST_CASE("One NULL");

    int result = utf8_casecmp(NULL, "hello");
    TEST_ASSERT_EQUAL(0, result, "One NULL should return 0");
}

/* ── utf8_normalize ──────────────────────────────────────────────────── */

TEST(test_utf8_normalize_nfc) {
    TEST_CASE("NFC normalization composes characters");

    /* "cafe" + combining acute accent (U+0301) → "café" as single codepoint */
    char* nfc = utf8_normalize("cafe\xCC\x81", UTF8_NFC);
    TEST_ASSERT_NOT_NULL(nfc, "NFC should return non-NULL");

    /* After NFC: "é" is 1 codepoint (2 bytes), so total length is 4 */
    size_t len = utf8_strlen(nfc);
    TEST_ASSERT_EQUAL_SIZE(4, len, "NFC should compose e + accent into single character");

    free(nfc);
}

TEST(test_utf8_normalize_nfd) {
    TEST_CASE("NFD normalization decomposes characters");

    /* "café" with precomposed é (U+00E9) → "cafe" + combining accent */
    char* nfd = utf8_normalize("caf\xc3\xa9", UTF8_NFD);
    TEST_ASSERT_NOT_NULL(nfd, "NFD should return non-NULL");

    /* After NFD: "e" + combining accent = 2 codepoints, so total length is 5 */
    size_t len = utf8_strlen(nfd);
    TEST_ASSERT_EQUAL_SIZE(5, len, "NFD should decompose é into e + combining accent");

    free(nfd);
}

TEST(test_utf8_normalize_null) {
    TEST_CASE("NULL input returns NULL");

    char* result = utf8_normalize(NULL, UTF8_NFC);
    TEST_ASSERT_NULL(result, "NULL input should return NULL");
}

TEST(test_utf8_normalize_invalid_form) {
    TEST_CASE("Invalid normalization form returns NULL");

    char* result = utf8_normalize("test", 42);
    TEST_ASSERT_NULL(result, "Invalid form should return NULL");
}

/* ── utf8_is_* classification ────────────────────────────────────────── */

TEST(test_utf8_is_alpha_ascii) {
    TEST_CASE("ASCII letters");

    TEST_ASSERT(utf8_is_alpha('A'), "'A' should be alpha");
    TEST_ASSERT(utf8_is_alpha('z'), "'z' should be alpha");
    TEST_ASSERT(!utf8_is_alpha('5'), "'5' should not be alpha");
    TEST_ASSERT(!utf8_is_alpha(' '), "' ' should not be alpha");
}

TEST(test_utf8_is_alpha_cyrillic) {
    TEST_CASE("Cyrillic letters");

    TEST_ASSERT(utf8_is_alpha(0x0410), "'А' should be alpha");
    TEST_ASSERT(utf8_is_alpha(0x044F), "'я' should be alpha");
}

TEST(test_utf8_is_digit) {
    TEST_CASE("Digits");

    TEST_ASSERT(utf8_is_digit('0'), "'0' should be digit");
    TEST_ASSERT(utf8_is_digit('9'), "'9' should be digit");
    TEST_ASSERT(!utf8_is_digit('A'), "'A' should not be digit");
    TEST_ASSERT(!utf8_is_digit(' '), "' ' should not be digit");
}

TEST(test_utf8_is_space) {
    TEST_CASE("Whitespace");

    TEST_ASSERT(utf8_is_space(' '), "' ' should be space");
    TEST_ASSERT(utf8_is_space('\t'), "'\\t' should be space");
    TEST_ASSERT(utf8_is_space('\n'), "'\\n' should be space");
    TEST_ASSERT(!utf8_is_space('A'), "'A' should not be space");
}

TEST(test_utf8_is_upper_lower) {
    TEST_CASE("Case classification");

    TEST_ASSERT(utf8_is_upper('A'), "'A' should be upper");
    TEST_ASSERT(!utf8_is_upper('a'), "'a' should not be upper");
    TEST_ASSERT(utf8_is_lower('a'), "'a' should be lower");
    TEST_ASSERT(!utf8_is_lower('A'), "'A' should not be lower");
    TEST_ASSERT(utf8_is_upper(0x041F), "'П' should be upper");
    TEST_ASSERT(utf8_is_lower(0x043F), "'п' should be lower");
}

TEST(test_utf8_is_punct) {
    TEST_CASE("Punctuation");

    TEST_ASSERT(utf8_is_punct(','), "',' should be punctuation");
    TEST_ASSERT(utf8_is_punct('.'), "'.' should be punctuation");
    TEST_ASSERT(utf8_is_punct('!'), "'!' should be punctuation");
    TEST_ASSERT(!utf8_is_punct('A'), "'A' should not be punctuation");
}

/* ── utf8_iter_t ─────────────────────────────────────────────────────── */

TEST(test_utf8_iter_ascii) {
    TEST_CASE("Iterate ASCII characters");

    utf8_iter_t iter;
    utf8_iter_init(&iter, "ABC");

    uint32_t c;
    int count = 0;
    while ((c = utf8_iter_next(&iter)) != 0) {
        count++;
    }

    TEST_ASSERT_EQUAL(3, count, "Should iterate 3 ASCII characters");
}

TEST(test_utf8_iter_cyrillic) {
    TEST_CASE("Iterate Cyrillic characters");

    utf8_iter_t iter;
    utf8_iter_init(&iter, "Привет");

    uint32_t c;
    int count = 0;
    while ((c = utf8_iter_next(&iter)) != 0) {
        count++;
    }

    TEST_ASSERT_EQUAL(6, count, "Should iterate 6 Cyrillic characters");
}

TEST(test_utf8_iter_values) {
    TEST_CASE("Iterate and verify codepoint values");

    utf8_iter_t iter;
    utf8_iter_init(&iter, "A1");

    TEST_ASSERT_EQUAL_UINT('A', utf8_iter_next(&iter), "First char should be 'A'");
    TEST_ASSERT_EQUAL_UINT('1', utf8_iter_next(&iter), "Second char should be '1'");
    TEST_ASSERT_EQUAL_UINT(0, utf8_iter_next(&iter), "Third call should return 0 (end)");
}

TEST(test_utf8_iter_empty) {
    TEST_CASE("Iterate empty string");

    utf8_iter_t iter;
    utf8_iter_init(&iter, "");

    TEST_ASSERT_EQUAL_UINT(0, utf8_iter_next(&iter), "Empty string should return 0 immediately");
}

TEST(test_utf8_iter_null) {
    TEST_CASE("Iterate NULL string");

    utf8_iter_t iter;
    utf8_iter_init(&iter, NULL);

    TEST_ASSERT_EQUAL_UINT(0, utf8_iter_next(&iter), "NULL string should return 0");
}

TEST(test_utf8_iter_null_iter) {
    TEST_CASE("NULL iterator");

    TEST_ASSERT_EQUAL_UINT(0, utf8_iter_next(NULL), "NULL iter should return 0");
}

TEST(test_utf8_iter_mixed_with_classification) {
    TEST_CASE("Iterate mixed string and classify each character");

    utf8_iter_t iter;
    utf8_iter_init(&iter, "Hi 42");

    int alpha_count = 0, digit_count = 0, space_count = 0;

    uint32_t c;
    while ((c = utf8_iter_next(&iter)) != 0) {
        if (utf8_is_alpha(c)) alpha_count++;
        else if (utf8_is_digit(c)) digit_count++;
        else if (utf8_is_space(c)) space_count++;
    }

    TEST_ASSERT_EQUAL(2, alpha_count, "Should have 2 letters");
    TEST_ASSERT_EQUAL(2, digit_count, "Should have 2 digits");
    TEST_ASSERT_EQUAL(1, space_count, "Should have 1 space");
}

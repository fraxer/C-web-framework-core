#include <stdlib.h>
#include <string.h>

#include "framework.h"
#include "cstr.h"

/* Helper: cstr_* edit in place, so every test works on its own copy. */
static char* dup_str(const char* value) {
    char* copy = malloc(strlen(value) + 1);
    strcpy(copy, value);
    return copy;
}

TEST(test_cstr_trim_ascii_spaces) {
    TEST_CASE("Trim strips ASCII spaces on both ends");

    char* buffer = dup_str("  Ivan  ");
    char* trimmed = cstr_trim(buffer);

    TEST_ASSERT_STR_EQUAL("Ivan", trimmed, "Spaces on both ends should be gone");
    free(buffer);
}

TEST(test_cstr_trim_unicode_spaces) {
    TEST_CASE("Trim strips NBSP pasted from a word processor");

    char* buffer = dup_str("\xC2\xA0Ivan\xC2\xA0");
    char* trimmed = cstr_trim(buffer);

    TEST_ASSERT_STR_EQUAL("Ivan", trimmed, "NBSP counts as whitespace");
    free(buffer);
}

TEST(test_cstr_trim_keeps_zero_width) {
    TEST_CASE("Trim leaves a zero-width space to strip_control");

    char* buffer = dup_str("\xE2\x80\x8BIvan");
    char* trimmed = cstr_trim(buffer);

    TEST_ASSERT_STR_EQUAL("\xE2\x80\x8BIvan", trimmed,
                          "Zero-width space is not whitespace");
    free(buffer);
}

TEST(test_cstr_collapse_spaces) {
    TEST_CASE("Runs of whitespace collapse into one U+0020");

    char* buffer = dup_str("Ivan\t  Petrov");
    char* collapsed = cstr_collapse_spaces(buffer);

    TEST_ASSERT_STR_EQUAL("Ivan Petrov", collapsed, "Tab and spaces become one space");
    free(buffer);
}

TEST(test_cstr_strip_control_removes_rlo) {
    TEST_CASE("Strip control removes the right-to-left override");

    char* buffer = dup_str("file\xE2\x80\xAEgpj.exe");
    char* stripped = cstr_strip_control(buffer);

    TEST_ASSERT_STR_EQUAL("filegpj.exe", stripped, "RLO must not survive");
    free(buffer);
}

TEST(test_cstr_strip_control_leaves_no_glued_controls) {
    TEST_CASE("Stripping cannot glue broken bytes into a new control character");

    /* C2 [04 08] 80: with the controls between them gone, the stray C2 and 80
     * would meet as U+0080 -- a C1 control in a string just cleaned of them,
     * which a second pass then removes. E2 [01] 80 [02] 8B does the same with
     * a zero-width space. Found by fuzz_text; the bytes that belong to no
     * sequence go with the controls, since what they would form cannot be
     * known until their neighbours are gone. */
    char* buffer = dup_str("a\xC2\x04\x08\x80z b\xE2\x01\x80\x02\x8Bz");
    char* stripped = cstr_strip_control(buffer);

    TEST_ASSERT_STR_EQUAL("az bz", stripped, "no C1 or invisible character is formed");
    free(buffer);

    buffer = dup_str("Иван\x9BПетров");
    stripped = cstr_strip_control(buffer);
    TEST_ASSERT_STR_EQUAL("ИванПетров", stripped, "a lone byte goes, whole letters stay");
    free(buffer);
}

TEST(test_cstr_strip_newlines_blocks_header_injection) {
    TEST_CASE("A CRLF run becomes a single space");

    char* buffer = dup_str("Subject\r\n\r\nBcc: victim@example.com");
    char* stripped = cstr_strip_newlines(buffer);

    TEST_ASSERT_STR_EQUAL("Subject Bcc: victim@example.com", stripped,
                          "Newlines must not reach a mail header");
    free(buffer);
}

TEST(test_cstr_sanitize_utf8_drops_broken_sequence) {
    TEST_CASE("Sanitize drops a truncated sequence and keeps the rest");

    char* buffer = dup_str("a\xC3(b");
    char* sanitized = cstr_sanitize_utf8(buffer);

    TEST_ASSERT_STR_EQUAL("a(b", sanitized, "Only the broken byte should go");
    free(buffer);
}

TEST(test_cstr_clean_applies_fixed_order) {
    TEST_CASE("Clean applies newlines before collapse before trim");

    char* buffer = dup_str("  Ivan\r\n\r\n  Petrov  ");
    char* cleaned = cstr_clean(buffer, CSTR_CLEAN_TEXT);

    TEST_ASSERT_STR_EQUAL("Ivan Petrov", cleaned,
                          "Newlines become spaces, then collapse, then trim");
    free(buffer);
}

TEST(test_cstr_clean_multiline_keeps_newlines) {
    TEST_CASE("The multiline set preserves paragraph breaks");

    char* buffer = dup_str("  First\nSecond  ");
    char* cleaned = cstr_clean(buffer, CSTR_CLEAN_MULTILINE);

    TEST_ASSERT_STR_EQUAL("First\nSecond", cleaned, "The newline is meaning, not noise");
    free(buffer);
}

TEST(test_cstr_clean_email_lowercases_ascii) {
    TEST_CASE("The email set lowercases ASCII only");

    char* buffer = dup_str(" Ivan@Mail.RU ");
    char* cleaned = cstr_clean(buffer, CSTR_CLEAN_EMAIL);

    TEST_ASSERT_STR_EQUAL("ivan@mail.ru", cleaned, "Address should be comparable");
    free(buffer);
}

TEST(test_cstr_clean_zero_flags_is_identity) {
    TEST_CASE("Clean with no flags changes nothing");

    char* buffer = dup_str("  Ivan  ");
    char* cleaned = cstr_clean(buffer, 0);

    TEST_ASSERT_STR_EQUAL("  Ivan  ", cleaned, "No flags means no edit");
    free(buffer);
}

TEST(test_cstr_clean_null) {
    TEST_CASE("NULL in, NULL out");

    TEST_ASSERT_NULL(cstr_clean(NULL, CSTR_CLEAN_TEXT), "NULL must be safe");
    TEST_ASSERT_NULL(cstr_trim(NULL), "NULL must be safe");
    TEST_ASSERT_NULL(cstr_clean_copy(NULL, CSTR_CLEAN_TEXT), "NULL must be safe");
}

TEST(test_cstr_clean_copy_leaves_source) {
    TEST_CASE("Clean copy does not touch the source");

    const char* source = "  Ivan  ";
    char* cleaned = cstr_clean_copy(source, CSTR_CLEAN_TEXT);

    TEST_ASSERT_STR_EQUAL("Ivan", cleaned, "The copy is cleaned");
    TEST_ASSERT_STR_EQUAL("  Ivan  ", source, "The source is untouched");
    free(cleaned);
}

TEST(test_cstr_keep_chars_phone) {
    TEST_CASE("Keep chars reduces a phone to digits and plus");

    char* buffer = dup_str("+7 (900) 123-45-67");
    char* kept = cstr_keep_chars(buffer, "0123456789+");

    TEST_ASSERT_STR_EQUAL("+79001234567", kept, "Separators should go");
    free(buffer);
}

TEST(test_cstr_truncate_on_character_boundary) {
    TEST_CASE("Truncate cuts on a character, not a byte");

    char* buffer = dup_str("Привет");
    char* cut = cstr_truncate(buffer, 3);

    TEST_ASSERT_STR_EQUAL("При", cut, "Three characters, six bytes");
    free(buffer);
}

TEST(test_cstr_lower_ascii_keeps_cyrillic) {
    TEST_CASE("ASCII lowercase leaves high bytes alone");

    char* buffer = dup_str("ABCПРИВЕТ");
    char* lowered = cstr_lower_ascii(buffer);

    TEST_ASSERT_STR_EQUAL("abcПРИВЕТ", lowered, "Cyrillic is not ASCII");
    free(buffer);
}

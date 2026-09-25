#include <stdlib.h>

#include "framework.h"
#include "escape.h"

TEST(test_html_escape_all_five) {
    TEST_CASE("All five HTML characters are escaped");

    char* escaped = html_escape("<a href=\"x\">O'Neil & Co</a>");

    TEST_ASSERT_STR_EQUAL(
        "&lt;a href=&quot;x&quot;&gt;O&#39;Neil &amp; Co&lt;/a&gt;",
        escaped, "Text and quoted attribute values are both covered");
    free(escaped);
}

TEST(test_html_escape_keeps_cyrillic) {
    TEST_CASE("Escaping leaves Cyrillic readable");

    char* escaped = html_escape("Привет & пока");

    TEST_ASSERT_STR_EQUAL("Привет &amp; пока", escaped, "Only markup is escaped");
    free(escaped);
}

TEST(test_html_escape_leaves_newlines_alone) {
    TEST_CASE("The single-line variant does not touch line breaks");

    char* escaped = html_escape("First\nSecond");

    TEST_ASSERT_STR_EQUAL("First\nSecond", escaped, "<br> is the multiline variant's job");
    free(escaped);
}

TEST(test_html_escape_multiline_crlf_is_one_break) {
    TEST_CASE("CRLF becomes a single break");

    char* escaped = html_escape_multiline("First\r\nSecond\nThird");

    TEST_ASSERT_STR_EQUAL("First<br>\nSecond<br>\nThird", escaped,
                          "A paragraph break must survive into the letter");
    free(escaped);
}

TEST(test_log_escape_hides_control_characters) {
    TEST_CASE("Control characters become hex escapes in a log line");

    char* escaped = log_escape("user\nadmin logged in\x7F");

    TEST_ASSERT_STR_EQUAL("user\\x0aadmin logged in\\x7f", escaped,
                          "A newline must not forge a log line");
    free(escaped);
}

TEST(test_log_escape_keeps_cyrillic) {
    TEST_CASE("A log line stays readable in Cyrillic");

    char* escaped = log_escape("Иван Петров");

    TEST_ASSERT_STR_EQUAL("Иван Петров", escaped, "High bytes are left alone");
    free(escaped);
}

TEST(test_log_escape_hides_c1_controls) {
    TEST_CASE("C1 control characters are escaped too, in UTF-8 and as stray bytes");

    /* U+009B is CSI: a terminal showing the journal starts an escape
     * sequence on it, whether it arrives as the two bytes C2 9B or as a lone
     * 9B that is not part of any UTF-8 sequence. Found by fuzz_text. */
    char* escaped = log_escape("a\xC2\x9B" "31m b\x9B" "31m c\xC2\x85" "d");

    TEST_ASSERT_STR_EQUAL("a\\xc2\\x9b31m b\\x9b31m c\\xc2\\x85d", escaped,
                          "C1 controls and stray bytes become hex escapes");
    free(escaped);
}

TEST(test_log_escape_escapes_invalid_utf8) {
    TEST_CASE("Bytes that are not valid UTF-8 are escaped, valid sequences are kept");

    /* A truncated sequence, an overlong form and a surrogate, between two
     * letters that must survive as they are. */
    char* escaped = log_escape("Я\xD0" "x\xC0\xAF" "y\xED\xA0\x80" "z€");

    TEST_ASSERT_STR_EQUAL("Я\\xd0x\\xc0\\xafy\\xed\\xa0\\x80z€", escaped,
                          "Only whole, valid sequences pass through");
    free(escaped);
}

TEST(test_escape_null) {
    TEST_CASE("NULL in, NULL out for escaping");

    TEST_ASSERT_NULL(html_escape(NULL), "NULL must be safe");
    TEST_ASSERT_NULL(html_escape_multiline(NULL), "NULL must be safe");
    TEST_ASSERT_NULL(log_escape(NULL), "NULL must be safe");
}

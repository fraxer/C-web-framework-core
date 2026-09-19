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

TEST(test_escape_null) {
    TEST_CASE("NULL in, NULL out for escaping");

    TEST_ASSERT_NULL(html_escape(NULL), "NULL must be safe");
    TEST_ASSERT_NULL(html_escape_multiline(NULL), "NULL must be safe");
    TEST_ASSERT_NULL(log_escape(NULL), "NULL must be safe");
}

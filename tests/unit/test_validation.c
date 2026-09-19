#include <string.h>

#include "framework.h"
#include "validation.h"

TEST(test_validate_email_accepts_ordinary_address) {
    TEST_CASE("An ordinary address passes");

    TEST_ASSERT(validate_email("ivan@mail.ru"), "Plain address should pass");
    TEST_ASSERT(validate_email("ivan.petrov+tag@sub.example.co.uk"),
                "Dots, a tag and a multi-level domain are fine");
}

TEST(test_validate_email_rejects_malformed) {
    TEST_CASE("Malformed addresses fail");

    TEST_ASSERT(!validate_email("ivan..petrov@mail.ru"), "Consecutive dots are invalid");
    TEST_ASSERT(!validate_email(".ivan@mail.ru"), "A leading dot is invalid");
    TEST_ASSERT(!validate_email("ivan@mail"), "A bare hostname has no TLD");
    TEST_ASSERT(!validate_email("ivan@[192.168.0.1]"), "An IP literal is not accepted");
    TEST_ASSERT(!validate_email("ivan@mail.ru "), "A trailing space means it was not cleaned");
    TEST_ASSERT(!validate_email(""), "Empty is not an address");
    TEST_ASSERT(!validate_email(NULL), "NULL is not an address");
}

TEST(test_validate_email_length_limits) {
    TEST_CASE("RFC length limits hold");

    /* 65 characters in the local part -- one over the limit of 64. */
    char long_local[65 + 9 + 1];
    memset(long_local, 'a', 65);
    strcpy(long_local + 65, "@mail.ru");
    TEST_ASSERT(!validate_email(long_local), "A local part over 64 characters fails");

    /* 64 in the local part is the limit itself, and must pass. */
    char at_limit[64 + 9 + 1];
    memset(at_limit, 'a', 64);
    strcpy(at_limit + 64, "@mail.ru");
    TEST_ASSERT(validate_email(at_limit), "Exactly 64 characters is allowed");

    /* 255 characters total -- one over the address limit of 254:
     * 64 local + "@" + 187 domain + ".ru". */
    char too_long[256];
    memset(too_long, 'a', 64);
    too_long[64] = '@';
    memset(too_long + 65, 'b', 187);
    strcpy(too_long + 252, ".ru");
    TEST_ASSERT_EQUAL_SIZE(255, strlen(too_long), "The fixture is 255 characters");
    TEST_ASSERT(!validate_email(too_long), "An address over 254 characters fails");
}

TEST(test_validate_phone_digit_count) {
    TEST_CASE("Phone accepts 7 to 15 digits");

    TEST_ASSERT(validate_phone("+7 (900) 123-45-67"), "Separators are allowed");
    TEST_ASSERT(validate_phone("1234567"), "Seven digits is the floor");
    TEST_ASSERT(validate_phone("+123456789012345"), "Fifteen digits is the E.164 ceiling");
    TEST_ASSERT(!validate_phone("123456"), "Six digits is too few");
    TEST_ASSERT(!validate_phone("+1234567890123456"), "Sixteen digits is too many");
    TEST_ASSERT(!validate_phone("+7 900 ABC-45-67"), "Letters are not a phone");
    TEST_ASSERT(!validate_phone(NULL), "NULL is not a phone");
}

TEST(test_validate_url_scheme) {
    TEST_CASE("Only http and https with a domain pass");

    TEST_ASSERT(validate_url("https://example.com"), "https passes");
    TEST_ASSERT(validate_url("http://example.com:8080/path?q=1"), "Port and path are fine");
    TEST_ASSERT(!validate_url("javascript:alert(1)"), "javascript: must never pass");
    TEST_ASSERT(!validate_url("ftp://example.com"), "ftp is not accepted");
    TEST_ASSERT(!validate_url("http://127.0.0.1"), "An IP is not a domain name");
    TEST_ASSERT(!validate_url("http://localhost"), "localhost has no TLD");
    TEST_ASSERT(!validate_url(NULL), "NULL is not a URL");
}

TEST(test_validate_utf8_rejects_broken) {
    TEST_CASE("Broken UTF-8 is rejected");

    TEST_ASSERT(validate_utf8("Привет"), "Valid UTF-8 passes");
    TEST_ASSERT(!validate_utf8("a\xC3"), "A truncated sequence fails");
    TEST_ASSERT(!validate_utf8("\xC0\xAF"), "An overlong form fails");
    TEST_ASSERT(!validate_utf8("\xED\xA0\x80"), "A surrogate fails");
    TEST_ASSERT(!validate_utf8("\xF5\x80\x80\x80"), "Above U+10FFFF fails");
}

TEST(test_validate_length_counts_characters) {
    TEST_CASE("Length is measured in characters, not bytes");

    TEST_ASSERT(validate_length("Александр", 1, 9), "Nine characters fit a limit of nine");
    TEST_ASSERT(!validate_length("Александр", 1, 8), "Nine characters exceed eight");
    TEST_ASSERT(validate_length("Александр", 1, 0), "Zero max means no upper bound");
}

TEST(test_validate_not_empty) {
    TEST_CASE("Not empty is checked after cleaning");

    TEST_ASSERT(validate_not_empty("x"), "A character is not empty");
    TEST_ASSERT(!validate_not_empty(""), "Empty is empty");
    TEST_ASSERT(!validate_not_empty(NULL), "NULL is empty");
}

TEST(test_validate_charset_name) {
    TEST_CASE("The name predicate knows Cyrillic and name punctuation");

    TEST_ASSERT(validate_charset("Анна-Мария О'Нил", validate_char_name),
                "Hyphen and apostrophe belong in names");
    TEST_ASSERT(!validate_charset("Ivan42", validate_char_name), "Digits do not");
    TEST_ASSERT(validate_charset("", validate_char_name),
                "Empty passes; required is a separate check");
    TEST_ASSERT(!validate_charset("a\xC3", validate_char_name), "Broken input fails at once");
}

TEST(test_validate_no_control) {
    TEST_CASE("Control and invisible characters are rejected");

    TEST_ASSERT(validate_no_control("Ivan Petrov"), "Plain text passes");
    TEST_ASSERT(!validate_no_control("Ivan\x01Petrov"), "A C0 character fails");
    TEST_ASSERT(!validate_no_control("file\xE2\x80\xAEgpj.exe"), "An RLO fails");
}

TEST(test_count_links_counts_one_per_link) {
    TEST_CASE("A scheme glued to www is one link, not two");

    TEST_ASSERT_EQUAL_SIZE(1, count_links("https://www.example.com"), "One link");
    TEST_ASSERT_EQUAL_SIZE(2, count_links("see http://a.com and www.b.com"), "Two links");
    TEST_ASSERT_EQUAL_SIZE(1, count_links("HTTPS://EXAMPLE.COM"), "Case does not matter");
    TEST_ASSERT_EQUAL_SIZE(0, count_links("no links here"), "None");
    TEST_ASSERT_EQUAL_SIZE(0, count_links(NULL), "NULL has none");
}

#include "framework.h"
#include "h2field.h"

#include <string.h>

/* RFC 9113 §8.2.1 field validity — docs/http2/08-spec-gaps.md, phase B.
 *
 * Written as octet tables rather than a handful of examples: the rule is about
 * which byte values are allowed, and a spot check of "x-evil" would pass on an
 * implementation that only looked for CR and LF. */

static int name_ok(const char* n) {
    return h2_field_name_valid(n, strlen(n));
}

static int value_ok(const char* v) {
    return h2_field_value_valid(v, strlen(v));
}

TEST(test_h2field_name_charset) {
    TEST_CASE("every octet is accepted or rejected as a field name");

    /* One-octet names, so each verdict is about that octet alone. */
    for (int c = 0; c < 256; c++) {
        const char name = (char)c;
        const int got = h2_field_name_valid(&name, 1);

        const int is_lower = (c >= 'a' && c <= 'z');
        const int is_digit = (c >= '0' && c <= '9');
        const int is_punct = strchr("!#$%&'*+-.^_`|~", c) != NULL && c != 0;
        const int expect = is_lower || is_digit || is_punct;

        if (got != expect) {
            TEST_ASSERT_EQUAL(expect, got, "octet verdict");
            break; /* one report is enough; the loop would print 200 more */
        }
    }

    TEST_ASSERT(name_ok("content-type"), "ordinary name");
    TEST_ASSERT(name_ok("x-probe_1"), "underscore and digits");
    TEST_ASSERT(!name_ok("Content-Type"), "uppercase is malformed (§8.2.1)");
    TEST_ASSERT(!name_ok("x evil"), "space in a name");
    TEST_ASSERT(!name_ok("x:evil"), "interior colon — the smuggling shape");
    TEST_ASSERT(!name_ok("x(evil)"), "non-token punctuation");
    TEST_ASSERT(!h2_field_name_valid("", 0), "empty name");
    TEST_ASSERT(!h2_field_name_valid(NULL, 4), "NULL name");
}

TEST(test_h2field_name_pseudo) {
    TEST_CASE("a leading colon is the pseudo-header prefix, not a name octet");

    TEST_ASSERT(name_ok(":method"), ":method");
    TEST_ASSERT(name_ok(":authority"), ":authority");
    TEST_ASSERT(!name_ok(":"), "a bare colon is not a name");
    TEST_ASSERT(!name_ok("::method"), "only the first octet may be a colon");
    TEST_ASSERT(!name_ok(":Method"), "uppercase after the colon");
}

TEST(test_h2field_value_charset) {
    TEST_CASE("every octet is accepted or rejected as a field value");

    /* The octet under test sits between two ordinary ones, so the verdict is
     * about the octet and not about the edge-whitespace rule — SP and HTAB are
     * perfectly legal inside a value and only banned at the ends, which
     * test_h2field_value_edge_whitespace covers separately. */
    for (int c = 0; c < 256; c++) {
        const char value[3] = {'a', (char)c, 'b'};
        const int got = h2_field_value_valid(value, sizeof(value));

        /* HTAB is legal; the other C0 controls and DEL are not. */
        const int expect = !(c < 0x20 && c != '\t') && c != 0x7f;

        if (got != expect) {
            TEST_ASSERT_EQUAL(expect, got, "octet verdict");
            break;
        }
    }

    const char nul[] = {'a', '\0', 'b'};
    TEST_ASSERT(!h2_field_value_valid(nul, sizeof(nul)), "NUL inside a value");
    TEST_ASSERT(!value_ok("a\r\nInjected: 1"), "CRLF — the injection shape");
    TEST_ASSERT(!value_ok("a\rb"), "bare CR");
    TEST_ASSERT(!value_ok("a\nb"), "bare LF");
    TEST_ASSERT(value_ok("a\tb"), "interior HTAB is legal");
    TEST_ASSERT(value_ok("text/html; charset=utf-8"), "ordinary value");
    TEST_ASSERT(value_ok("\xd0\xbf\xd1\x80\xd0\xb8"), "obs-text (raw UTF-8) stays legal");
    TEST_ASSERT(h2_field_value_valid("", 0), "an empty value is legal");
}

TEST(test_h2field_value_edge_whitespace) {
    TEST_CASE("§8.2.1: a value must not start or end with SP or HTAB");

    TEST_ASSERT(!value_ok(" leading"), "leading space");
    TEST_ASSERT(!value_ok("trailing "), "trailing space");
    TEST_ASSERT(!value_ok("\tleading"), "leading tab");
    TEST_ASSERT(!value_ok("trailing\t"), "trailing tab");
    TEST_ASSERT(!value_ok(" "), "a single space");
    TEST_ASSERT(value_ok("a b"), "interior space is legal");
}

TEST(test_h2field_validate_reports_which_side) {
    TEST_CASE("the two failure codes are distinguishable");

    TEST_ASSERT_EQUAL(H2_FIELD_OK, h2_field_validate("accept", 6, "*/*", 3), "valid field");
    TEST_ASSERT_EQUAL(H2_FIELD_BAD_NAME, h2_field_validate("Accept", 6, "*/*", 3), "bad name");
    TEST_ASSERT_EQUAL(H2_FIELD_BAD_VALUE, h2_field_validate("accept", 6, "a\r\nb", 4), "bad value");
    /* A bad name wins when both are bad — the caller only reports one. */
    TEST_ASSERT_EQUAL(H2_FIELD_BAD_NAME, h2_field_validate("Accept", 6, "a\r\nb", 4), "name checked first");
}

/* The validators read raw peer bytes, so the thing worth proving under ASan is
 * that they never read past the length they are given — including the length-0
 * and NULL cases the HPACK decoder can hand them. Verdicts are not checked here
 * (the tables above own that); only that a verdict is produced, every time. */
TEST(test_h2field_fuzz) {
    TEST_CASE("random byte strings produce a verdict and no out-of-bounds read");

    unsigned int seed = 20260803u;
    char buf[64];

    for (int i = 0; i < 5000; i++) {
        seed = seed * 1103515245u + 12345u;
        const size_t len = (seed >> 16) % (sizeof(buf) + 1);

        for (size_t j = 0; j < len; j++) {
            seed = seed * 1103515245u + 12345u;
            buf[j] = (char)((seed >> 16) & 0xff);
        }

        /* Both halves, and the pair — the pair is what production calls. */
        const int n = h2_field_name_valid(buf, len);
        const int v = h2_field_value_valid(buf, len);
        const h2_field_status_e st = h2_field_validate(buf, len, buf, len);

        if ((n != 0 && n != 1) || (v != 0 && v != 1)) {
            TEST_ASSERT(0, "validator returned something other than a boolean");
            break;
        }
        if (st != (n ? (v ? H2_FIELD_OK : H2_FIELD_BAD_VALUE) : H2_FIELD_BAD_NAME)) {
            TEST_ASSERT(0, "h2_field_validate disagrees with its halves");
            break;
        }
    }

    TEST_ASSERT(1, "5000 random inputs, no crash");
}

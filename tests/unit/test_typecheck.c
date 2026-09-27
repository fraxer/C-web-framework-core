#include "framework.h"

#include "typecheck.h"

/* misc/typecheck.c -- what query_param_* and payload_param_* check a request
 * value with before converting it. */

TEST(test_typecheck_unsigned_minus_after_blanks) {
    TEST_CASE("an unsigned type refuses a minus sign after leading blanks too");

    /* The minus was looked for in the first character only, and strtoul
     * skips blanks and negates: " -1" passed is_ulong and converted to
     * ULONG_MAX (found by the typecheck helper of the text fuzz target). */
    TEST_ASSERT_EQUAL(0, is_ulong(" -1"), "is_ulong");
    TEST_ASSERT_EQUAL(0, is_ulong("\t-0"), "is_ulong, tab and zero");
    TEST_ASSERT_EQUAL(0, is_uint(" -1"), "is_uint");
    TEST_ASSERT_EQUAL(1, is_ulong(" 1"), "leading blanks still allowed");
    TEST_ASSERT_EQUAL(1, is_uint("+1"), "a plus sign still allowed");
}

/*
 * Unit tests for misc/strtemplate.c — the {N} placeholder syntax shared by a
 * redirect destination and a route's static_file.
 *
 * The parse is deliberately forgiving: anything between braces that is not a
 * short decimal number is literal text, because a template is a file path or a
 * URI first and a substitution second. Only an over-long number is an error,
 * on the grounds that it is a typo rather than an intent.
 */

#include "framework.h"
#include "strtemplate.h"

#include <stdlib.h>
#include <string.h>

/* pcre_exec leaves the entries of non-participating groups untouched, so every
 * caller pre-marks the whole vector as unset before the match. The tests do the
 * same and then write only the groups they mean to provide. */
static void fill_unset(int* vector, size_t count) {
    for (size_t i = 0; i < count; i++) vector[i] = -1;
}

static char* expand(const char* source, const char* subject, int* vector) {
    strtemplate_t* tpl = strtemplate_create(source);
    if (tpl == NULL) return NULL;

    char* out = strtemplate_expand(tpl, subject, vector);

    strtemplate_free(tpl);

    return out;
}

TEST(test_strtemplate_plain_text) {
    TEST_SUITE("strtemplate: parsing");
    TEST_CASE("a source without placeholders is copied verbatim");

    strtemplate_t* tpl = strtemplate_create("/assets/style.css");
    TEST_REQUIRE_NOT_NULL(tpl, "strtemplate_create should succeed");
    TEST_ASSERT_EQUAL(0, strtemplate_params_count(tpl), "no placeholders");
    TEST_ASSERT_EQUAL(0, strtemplate_max_param(tpl), "no group referenced");

    char* out = strtemplate_expand(tpl, "/whatever", NULL);
    TEST_REQUIRE_NOT_NULL_GOTO(out, "expand should succeed", cleanup);
    TEST_ASSERT_STR_EQUAL("/assets/style.css", out, "text is copied as is");
    free(out);

    cleanup:
    strtemplate_free(tpl);
}

TEST(test_strtemplate_empty_source_rejected) {
    TEST_SUITE("strtemplate: parsing");
    TEST_CASE("an empty or missing source is refused");

    TEST_ASSERT_NULL(strtemplate_create(""), "empty string");
    TEST_ASSERT_NULL(strtemplate_create(NULL), "null pointer");
}

TEST(test_strtemplate_counts_params) {
    TEST_SUITE("strtemplate: parsing");
    TEST_CASE("placeholders are counted and the largest number reported");

    strtemplate_t* tpl = strtemplate_create("/{2}/x/{1}/{2}");
    TEST_REQUIRE_NOT_NULL(tpl, "strtemplate_create should succeed");
    TEST_ASSERT_EQUAL(3, strtemplate_params_count(tpl), "three placeholders, repeats included");
    TEST_ASSERT_EQUAL(2, strtemplate_max_param(tpl), "largest group number");

    strtemplate_free(tpl);
}

TEST(test_strtemplate_non_numeric_braces_are_literal) {
    TEST_SUITE("strtemplate: parsing");
    TEST_CASE("braces around anything but a number are ordinary characters");

    const char* sources[] = { "/a/{name}", "/a/{}", "/a/{", "/a/{1x}", "/a/{ 1}" };

    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
        strtemplate_t* tpl = strtemplate_create(sources[i]);
        TEST_REQUIRE_NOT_NULL(tpl, "strtemplate_create should succeed");
        TEST_ASSERT_EQUAL(0, strtemplate_params_count(tpl), "no placeholder recognised");

        char* out = strtemplate_expand(tpl, "/subject", NULL);
        TEST_REQUIRE_NOT_NULL(out, "expand should succeed");
        TEST_ASSERT_STR_EQUAL(sources[i], out, "the source survives unchanged");
        free(out);

        strtemplate_free(tpl);
    }
}

TEST(test_strtemplate_long_number_rejected) {
    TEST_SUITE("strtemplate: parsing");
    TEST_CASE("a number of more than two digits is an error");

    TEST_ASSERT_NULL(strtemplate_create("/a/{100}"), "three digits");

    strtemplate_t* tpl = strtemplate_create("/a/{99}");
    TEST_REQUIRE_NOT_NULL(tpl, "two digits should be accepted");
    TEST_ASSERT_EQUAL(99, strtemplate_max_param(tpl), "the number is read");
    strtemplate_free(tpl);
}

TEST(test_strtemplate_substitutes_group) {
    TEST_SUITE("strtemplate: expansion");
    TEST_CASE("a placeholder takes the text of its capture group");

    const char* subject = "/assets/app/style.css";
    int vector[30];
    fill_unset(vector, 30);

    /* Group 1 is "app/style.css" — the tail after "/assets/". */
    vector[2] = 8;
    vector[3] = (int)strlen(subject);

    char* out = expand("/static/{1}", subject, vector);
    TEST_REQUIRE_NOT_NULL(out, "expand should succeed");
    TEST_ASSERT_STR_EQUAL("/static/app/style.css", out, "the group's text is spliced in");
    free(out);
}

TEST(test_strtemplate_keeps_the_tail) {
    TEST_SUITE("strtemplate: expansion");
    TEST_CASE("text after the last placeholder is kept");

    const char* subject = "/u/42";
    int vector[30];
    fill_unset(vector, 30);

    vector[2] = 3;
    vector[3] = 5;

    char* out = expand("/profile/{1}/edit", subject, vector);
    TEST_REQUIRE_NOT_NULL(out, "expand should succeed");
    TEST_ASSERT_STR_EQUAL("/profile/42/edit", out, "prefix, group and tail");
    free(out);
}

TEST(test_strtemplate_repeats_and_reorders_groups) {
    TEST_SUITE("strtemplate: expansion");
    TEST_CASE("a group may be used more than once and out of order");

    const char* subject = "ab";
    int vector[30];
    fill_unset(vector, 30);

    vector[2] = 0; vector[3] = 1;   /* group 1 = "a" */
    vector[4] = 1; vector[5] = 2;   /* group 2 = "b" */

    char* out = expand("{2}{1}{2}", subject, vector);
    TEST_REQUIRE_NOT_NULL(out, "expand should succeed");
    TEST_ASSERT_STR_EQUAL("bab", out, "groups spliced in template order");
    free(out);
}

TEST(test_strtemplate_unmatched_group_is_empty) {
    TEST_SUITE("strtemplate: expansion");
    TEST_CASE("a group that did not participate contributes nothing");

    int vector[30];
    fill_unset(vector, 30);   /* every offset stays -1 */

    char* out = expand("/static/{1}.css", "/x", vector);
    TEST_REQUIRE_NOT_NULL(out, "expand should succeed");
    TEST_ASSERT_STR_EQUAL("/static/.css", out, "the placeholder collapses");
    free(out);

    /* The same when the caller has no vector at all, which is what a primitive
     * route location passes. */
    out = expand("/static/{1}.css", "/x", NULL);
    TEST_REQUIRE_NOT_NULL(out, "expand without a vector should succeed");
    TEST_ASSERT_STR_EQUAL("/static/.css", out, "no vector means no text");
    free(out);
}

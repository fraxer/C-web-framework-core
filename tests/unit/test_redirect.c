#include "framework.h"
#include "redirect.h"
#include <string.h>

/* Core migrated from PCRE1 to PCRE2 (pcre2_match with a match_data); the tests
 * below were written against the pcre_exec call shape. This wrapper keeps
 * that shape: strlen-based subject, an int ovector, pairs matched as the
 * return value (negative on no match / error). Unset groups keep whatever the
 * caller pre-filled the vector with, as pcre_exec did. */
static int pcre_exec_compat(const pcre2_code* code, const char* subject, int* vector, int veclen) {
    pcre2_match_data* match_data = pcre2_match_data_create((uint32_t)(veclen / 3), NULL);
    if (match_data == NULL) return PCRE2_ERROR_NOMEMORY;

    const int rc = pcre2_match(code, (PCRE2_SPTR)subject, (PCRE2_SIZE)strlen(subject), 0, 0, match_data, NULL);
    if (rc >= 0) {
        const PCRE2_SIZE* ovector = pcre2_get_ovector_pointer(match_data);
        for (int i = 0; i < rc * 2; i++)
            vector[i] = ovector[i] == PCRE2_UNSET ? -1 : (int)ovector[i];
    }

    pcre2_match_data_free(match_data);
    return rc;
}


// ============================================================================
// Redirect tests — destination template parsing ({N} tokens) and URI
// substitution from pcre capture groups.
//
// Several cases are regressions for former bugs:
//  - heap overflow when the template has a tail after the last param
//  - out-of-bounds read on "{}" / unterminated "{" at end of destination
//  - param number exceeding the capture count passing validation
//  - param list leak when pcre_compile fails
// ============================================================================

// Matches path against redirect->location and builds the destination URI.
// Vector is pre-filled with -1 the same way the http server does, because
// pcre_exec leaves entries of non-participating groups untouched.
static char* redirect_exec_uri(redirect_t* redirect, const char* path) {
    int vector[30];
    memset(vector, -1, sizeof(vector));

    int rc = pcre_exec_compat(redirect->location, path, vector, 30);
    if (rc < 0) return NULL;

    return redirect_get_uri(redirect, path, vector);
}

TEST(test_redirect_no_params) {
    TEST_CASE("Static destination without params");

    redirect_t* r = redirect_create("^/old$", "/new");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");
    TEST_ASSERT_EQUAL(0, r->params_count, "Should have no params");

    char* uri = redirect_exec_uri(r, "/old");
    TEST_ASSERT_STR_EQUAL("/new", uri, "Static destination is copied as is");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_single_param) {
    TEST_CASE("Single {1} param substituted from capture group");

    redirect_t* r = redirect_create("^/user/(\\d+)$", "/profile/{1}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");
    TEST_ASSERT_EQUAL(1, r->params_count, "Should have 1 param");

    char* uri = redirect_exec_uri(r, "/user/42");
    TEST_ASSERT_STR_EQUAL("/profile/42", uri, "Capture 1 substituted into {1}");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_single_param_with_tail) {
    TEST_CASE("Template tail after the last param (heap overflow regression)");

    redirect_t* r = redirect_create("^/user/(\\d+)/edit$", "/profile/{1}/settings");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");

    char* uri = redirect_exec_uri(r, "/user/42/edit");
    TEST_ASSERT_STR_EQUAL("/profile/42/settings", uri, "Tail after {1} must be kept");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_param_at_start) {
    TEST_CASE("Param at position 0 of the destination");

    redirect_t* r = redirect_create("^/id/(\\d+)$", "{1}/view");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");

    char* uri = redirect_exec_uri(r, "/id/42");
    TEST_ASSERT_STR_EQUAL("42/view", uri, "Empty prefix before {1} handled");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_multiple_params) {
    TEST_CASE("Two params with text between and after");

    redirect_t* r = redirect_create("^/a/(\\d+)/b/([a-z]+)$", "/x/{1}/y/{2}/z");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");
    TEST_ASSERT_EQUAL(2, r->params_count, "Should have 2 params");

    char* uri = redirect_exec_uri(r, "/a/42/b/foo");
    TEST_ASSERT_STR_EQUAL("/x/42/y/foo/z", uri, "Both captures substituted in order");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_params_reversed) {
    TEST_CASE("Params referenced in reverse order");

    redirect_t* r = redirect_create("^/(\\d+)/([a-z]+)$", "/{2}/{1}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");

    char* uri = redirect_exec_uri(r, "/42/abc");
    TEST_ASSERT_STR_EQUAL("/abc/42", uri, "Captures substituted by number, not position");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_adjacent_params) {
    TEST_CASE("Adjacent params without separator");

    redirect_t* r = redirect_create("^/(\\d+)-([a-z]+)$", "/{1}{2}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");

    char* uri = redirect_exec_uri(r, "/42-ab");
    TEST_ASSERT_STR_EQUAL("/42ab", uri, "Adjacent params concatenated");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_params_count_mismatch) {
    TEST_CASE("Params count must equal capture groups count");

    redirect_t* r = redirect_create("^/old$", "/new/{1}");
    TEST_ASSERT_NULL(r, "1 param vs 0 captures must fail");

    r = redirect_create("^/(a)(b)$", "/{1}");
    TEST_ASSERT_NULL(r, "1 param vs 2 captures must fail");
}

TEST(test_redirect_param_number_exceeds_captures) {
    TEST_CASE("Param number above capture count is rejected (validation regression)");

    redirect_t* r = redirect_create("^/(\\d+)$", "/{2}");
    TEST_ASSERT_NULL(r, "{2} with a single capture group must fail");
}

TEST(test_redirect_empty_token_is_literal) {
    TEST_CASE("Empty {} at end of destination (OOB read regression)");

    redirect_t* r = redirect_create("^/old$", "/new{}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");
    TEST_ASSERT_EQUAL(0, r->params_count, "{} is not a param");

    char* uri = redirect_exec_uri(r, "/old");
    TEST_ASSERT_STR_EQUAL("/new{}", uri, "{} is kept literally");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_empty_token_before_param) {
    TEST_CASE("{} directly before a valid param must not swallow it");

    redirect_t* r = redirect_create("^/(\\d+)$", "/x{}{1}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");
    TEST_ASSERT_EQUAL(1, r->params_count, "{1} after {} must be parsed");

    char* uri = redirect_exec_uri(r, "/42");
    TEST_ASSERT_STR_EQUAL("/x{}42", uri, "{} literal, {1} substituted");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_unterminated_token) {
    TEST_CASE("Unterminated { at end of destination (OOB read regression)");

    redirect_t* r = redirect_create("^/old$", "/new{1");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");
    TEST_ASSERT_EQUAL(0, r->params_count, "Unterminated token is not a param");

    char* uri = redirect_exec_uri(r, "/old");
    TEST_ASSERT_STR_EQUAL("/new{1", uri, "Unterminated token is kept literally");

    free(uri);
    redirect_free(r);

    r = redirect_create("^/old$", "/new{");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");

    uri = redirect_exec_uri(r, "/old");
    TEST_ASSERT_STR_EQUAL("/new{", uri, "Bare { at end is kept literally");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_non_digit_token_is_literal) {
    TEST_CASE("Non-digit token {ab} stays literal");

    redirect_t* r = redirect_create("^/old$", "/x{ab}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");
    TEST_ASSERT_EQUAL(0, r->params_count, "{ab} is not a param");

    char* uri = redirect_exec_uri(r, "/old");
    TEST_ASSERT_STR_EQUAL("/x{ab}", uri, "{ab} is kept literally");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_nested_brace_restarts_token) {
    TEST_CASE("{{1}} parses inner {1} as a param");

    redirect_t* r = redirect_create("^/(\\d+)$", "/v{{1}}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");
    TEST_ASSERT_EQUAL(1, r->params_count, "Inner {1} must be parsed");

    char* uri = redirect_exec_uri(r, "/42");
    TEST_ASSERT_STR_EQUAL("/v{42}", uri, "Outer braces literal, inner substituted");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_big_param_number_rejected) {
    TEST_CASE("Param number longer than 2 digits is rejected");

    redirect_t* r = redirect_create("^/old$", "/x{123}");
    TEST_ASSERT_NULL(r, "{123} must fail");
}

TEST(test_redirect_empty_destination_rejected) {
    TEST_CASE("Empty destination is rejected");

    redirect_t* r = redirect_create("^/old$", "");
    TEST_ASSERT_NULL(r, "Empty destination must fail");
}

TEST(test_redirect_invalid_location_regex) {
    TEST_CASE("Invalid location regex fails (param leak regression under ASan)");

    redirect_t* r = redirect_create("(", "/new");
    TEST_ASSERT_NULL(r, "Broken regex must fail");

    // params already parsed from destination must be freed on this path
    r = redirect_create("(", "/x/{1}");
    TEST_ASSERT_NULL(r, "Broken regex with params in destination must fail");
}

TEST(test_redirect_unmatched_capture_group) {
    TEST_CASE("Non-participating capture group substitutes as empty string");

    redirect_t* r = redirect_create("^/(?:(a)|(b))$", "/{1}{2}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");

    char* uri = redirect_exec_uri(r, "/a");
    TEST_ASSERT_STR_EQUAL("/a", uri, "Group 2 did not participate -> empty");
    free(uri);

    uri = redirect_exec_uri(r, "/b");
    TEST_ASSERT_STR_EQUAL("/b", uri, "Group 1 did not participate -> empty");
    free(uri);

    redirect_free(r);
}

TEST(test_redirect_empty_capture) {
    TEST_CASE("Empty capture substitutes as empty string");

    redirect_t* r = redirect_create("^/u/(\\d*)$", "/v/{1}");
    TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");

    char* uri = redirect_exec_uri(r, "/u/");
    TEST_ASSERT_STR_EQUAL("/v/", uri, "Empty capture -> empty substitution");

    free(uri);
    redirect_free(r);
}

TEST(test_redirect_free_null_and_chain) {
    TEST_CASE("redirect_free handles NULL and frees the whole chain");

    redirect_free(NULL);

    redirect_t* first = redirect_create("^/a/(\\d+)$", "/b/{1}");
    redirect_t* second = redirect_create("^/c$", "/d");
    TEST_REQUIRE_NOT_NULL(first, "first redirect_create should succeed");
    TEST_REQUIRE_NOT_NULL(second, "second redirect_create should succeed");

    first->next = second;
    redirect_free(first);

    TEST_ASSERT(1, "Chain freed without crash (leaks caught by ASan)");
}

// ============================================================================
// The literal shortcut — a location spelled in plain text is matched by a
// substring search instead of PCRE. The shortcut and the pattern must agree on
// every path, because a redirect that fires on one and not the other sends the
// client somewhere its author never wrote.
// ============================================================================

static int redirect_pattern_matches(redirect_t* r, const char* path) {
    int vector[30];
    memset(vector, -1, sizeof(vector));
    return pcre_exec_compat(r->location, path, vector, 30) >= 0;
}

static int redirect_shortcut_matches(redirect_t* r, const char* path) {
    int vector[30];
    memset(vector, -1, sizeof(vector));
    return redirect_matches(r, path, strlen(path), vector, 30);
}

TEST(test_redirect_literal_agrees_with_pattern) {
    TEST_SUITE("redirect: literal shortcut");
    TEST_CASE("substring search and the compiled pattern answer identically");

    static const char* locations[] = {
        "/user", "/old/path", "^/anchored$", "/user(.*)/(\\d)",
    };
    static const char* paths[] = {
        "/user", "/users", "/user/42", "/prefix/user", "/old/path", "/old",
        "/anchored", "/anchored/more", "/user7/9", "/", "",
    };

    for (size_t i = 0; i < sizeof(locations) / sizeof(locations[0]); i++) {
        /* A destination without placeholders keeps every location legal here;
         * the capture-count check is a separate case. */
        const char* destination = i == 3 ? "/user-{1}-{2}" : "/persons";
        redirect_t* r = redirect_create(locations[i], destination);
        TEST_REQUIRE_NOT_NULL(r, "redirect_create should succeed");

        for (size_t j = 0; j < sizeof(paths) / sizeof(paths[0]); j++) {
            if (redirect_shortcut_matches(r, paths[j]) != redirect_pattern_matches(r, paths[j])) {
                TEST_FAIL("the literal shortcut disagreed with the pattern");
                break;
            }
        }

        redirect_free(r);
    }

    TEST_ASSERT(1, "shortcut and pattern agree on every location/path pair");
}

TEST(test_redirect_literal_flag) {
    TEST_SUITE("redirect: literal shortcut");
    TEST_CASE("only plain text without capture groups takes the shortcut");

    redirect_t* plain = redirect_create("/user", "/persons");
    TEST_REQUIRE_NOT_NULL(plain, "plain redirect created");
    TEST_ASSERT_EQUAL(1, plain->is_literal, "plain text takes the shortcut");
    TEST_ASSERT_EQUAL_SIZE(5, plain->literal_length, "and remembers its length");
    redirect_free(plain);

    redirect_t* anchored = redirect_create("^/anchored$", "/persons");
    TEST_REQUIRE_NOT_NULL(anchored, "anchored redirect created");
    TEST_ASSERT_EQUAL(0, anchored->is_literal, "anchors are pattern syntax");
    redirect_free(anchored);

    /* Capture groups rule the shortcut out even before the metacharacters do:
     * the destination needs the offsets a substring search cannot produce. */
    redirect_t* captures = redirect_create("/user(.*)/(\\d)", "/user-{1}-{2}");
    TEST_REQUIRE_NOT_NULL(captures, "capture redirect created");
    TEST_ASSERT_EQUAL(0, captures->is_literal, "a location with groups is never literal");
    redirect_free(captures);
}

#include "framework.h"
#include "dkimcanonparser.h"

#include <stdlib.h>
#include <string.h>

/* The DKIM "relaxed" body canonicalization (RFC 6376 §3.4.4):
 *   (a) reduce runs of WSP within a line to a single SP;
 *   (b) ignore all WSP at the end of lines;
 *   (c) ignore all empty lines at the end of the body;
 *   and append a single CRLF if — and only if — the body is non-empty.
 *
 * This file covers the public dkimcanonparser_* API directly (the dkim.c path
 * is exercised through test_dkim.c's __dkim_relaxed_body_canon calls). */

/* Run relaxed canonicalization on `body` (NUL-terminated) and return a freshly
 * malloc'd result the caller frees. Records the byte length in *out_len. */
static char* canon_run(const char* body, size_t* out_len) {
    dkimcanonparser_t* p = dkimcanonparser_alloc();
    TEST_REQUIRE_NOT_NULL(p, "alloc should succeed");

    dkimcanonparser_init(p);
    dkimcanonparser_set_buffer(p, body, strlen(body));
    dkimcanonparser_run(p);

    char* out = dkimcanonparser_get_content(p);
    if (out_len != NULL)
        *out_len = (out != NULL) ? strlen(out) : 0;

    dkimcanonparser_free(p);
    return out;
}

/* -------------------------------------------------------------------------- */
/* lifecycle                                                                  */
/* -------------------------------------------------------------------------- */

TEST(test_dkimcanonparser_alloc_init_free) {
    TEST_CASE("alloc/init/free is safe and yields an empty result for no buffer");

    dkimcanonparser_t* p = dkimcanonparser_alloc();
    TEST_REQUIRE_NOT_NULL(p, "alloc should succeed");

    dkimcanonparser_init(p);
    /* run without set_buffer: zero-length body → empty canonical form. */
    TEST_ASSERT_EQUAL(1, dkimcanonparser_run(p), "run returns 1");
    char* out = dkimcanonparser_get_content(p);
    TEST_ASSERT_NOT_NULL(out, "get_content returns a buffer");
    TEST_ASSERT_EQUAL(0, (int)strlen(out), "empty buffer canonicalizes to empty string");
    free(out);

    dkimcanonparser_free(p);
}

TEST(test_dkimcanonparser_get_content_returns_copy) {
    TEST_CASE("get_content returns an independent heap copy that outlives the parser");

    char* out = canon_run("Hi", NULL);
    TEST_REQUIRE_NOT_NULL(out, "canon should produce output");
    TEST_ASSERT_STR_EQUAL("Hi\r\n", out, "simple body canonicalized");

    /* The copy must remain valid after the parser is freed (canon_run freed it). */
    TEST_ASSERT_STR_EQUAL("Hi\r\n", out, "copy survives parser free");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* RFC 6376 §3.4.4(a): collapse internal WSP                                   */
/* -------------------------------------------------------------------------- */

TEST(test_dkimcanonparser_collapse_wsp) {
    TEST_CASE("runs of spaces/tabs collapse to a single space");

    char* out = canon_run("a    b", NULL);
    TEST_ASSERT_STR_EQUAL("a b\r\n", out, "multiple spaces collapse");
    free(out);

    out = canon_run("a\t\t\tb", NULL);
    TEST_ASSERT_STR_EQUAL("a b\r\n", out, "multiple tabs collapse");
    free(out);

    out = canon_run("a \t b", NULL);
    TEST_ASSERT_STR_EQUAL("a b\r\n", out, "mixed space/tab run collapses");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* RFC 6376 §3.4.4(b): ignore WSP at end of lines                             */
/* -------------------------------------------------------------------------- */

TEST(test_dkimcanonparser_strip_trailing_wsp) {
    TEST_CASE("trailing spaces/tabs before a line break are removed");

    char* out = canon_run("abc   \n", NULL);
    TEST_ASSERT_STR_EQUAL("abc\r\n", out, "trailing spaces stripped (LF)");
    free(out);

    out = canon_run("abc\t \n", NULL);
    TEST_ASSERT_STR_EQUAL("abc\r\n", out, "trailing tab+space stripped");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* CRLF input — the double-CR regression                                      */
/* -------------------------------------------------------------------------- */

TEST(test_dkimcanonparser_crlf_no_double_cr) {
    TEST_CASE("CRLF-terminated lines do not produce a doubled carriage return");

    /* Previously the '\r' fell through to the default branch and was kept,
     * so "line1\r\nline2\r\n" became "line1\r\r\nline2\r\n" on every line but
     * the last. The body hash then diverged from any RFC verifier. */
    char* out = canon_run("line1\r\nline2\r\n", NULL);
    TEST_ASSERT_STR_EQUAL("line1\r\nline2\r\n", out, "CRLF lines map to single CRLF");
    free(out);

    out = canon_run("line1\r\n", NULL);
    TEST_ASSERT_STR_EQUAL("line1\r\n", out, "single CRLF line");
    free(out);

    /* Mixed: CRLF input with trailing WSP must be stripped per line too. */
    out = canon_run("ab  \r\ncd\r\n", NULL);
    TEST_ASSERT_STR_EQUAL("ab\r\ncd\r\n", out, "trailing WSP stripped before CRLF");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* RFC 6376 §3.4.4(c) + empty body — the empty-result regression              */
/* -------------------------------------------------------------------------- */

TEST(test_dkimcanonparser_empty_body) {
    TEST_CASE("an empty body canonicalizes to a zero-length string, not \\r\\n");

    size_t len = 999;
    char* out = canon_run("", &len);
    TEST_REQUIRE_NOT_NULL(out, "empty body still returns a buffer");
    TEST_ASSERT_EQUAL(0, (int)len, "empty body length is 0");
    TEST_ASSERT_STR_EQUAL("", out, "empty body canonical form is the empty string");
    free(out);
}

TEST(test_dkimcanonparser_only_blank_lines) {
    TEST_CASE("a body of only blank/WSP lines canonicalizes to empty");

    size_t len = 999;
    char* out = canon_run("  \n\t\n\n", &len);
    TEST_REQUIRE_NOT_NULL(out, "blank body returns a buffer");
    TEST_ASSERT_EQUAL(0, (int)len, "all-WSP body length is 0");
    TEST_ASSERT_STR_EQUAL("", out, "all-WSP body canonical form is empty");
    free(out);
}

TEST(test_dkimcanonparser_strip_trailing_blank_lines) {
    TEST_CASE("trailing empty lines are removed, internal ones kept");

    /* RFC example: "foo\r\n\r\n" → "foo\r\n" */
    char* out = canon_run("foo\r\n\r\n", NULL);
    TEST_ASSERT_STR_EQUAL("foo\r\n", out, "trailing blank line removed");
    free(out);

    /* LF-only variant */
    out = canon_run("foo\n\n", NULL);
    TEST_ASSERT_STR_EQUAL("foo\r\n", out, "trailing blank LF line removed");
    free(out);

    /* A blank line in the middle is preserved. */
    out = canon_run("a\n\nb\n", NULL);
    TEST_ASSERT_STR_EQUAL("a\r\n\r\nb\r\n", out, "internal blank line preserved");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* plain (non-terminated) body gets one CRLF                                  */
/* -------------------------------------------------------------------------- */

TEST(test_dkimcanonparser_appends_single_crlf) {
    TEST_CASE("a non-empty body without a trailing line break gets one CRLF");

    char* out = canon_run("Hello", NULL);
    TEST_ASSERT_STR_EQUAL("Hello\r\n", out, "plain body gains a single CRLF");
    free(out);

    /* Already-canonical input is unchanged. */
    out = canon_run("Hello\r\n", NULL);
    TEST_ASSERT_STR_EQUAL("Hello\r\n", out, "already-terminated body unchanged");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* large body: exercises the static→dynamic buffer path with pop_back         */
/* -------------------------------------------------------------------------- */

TEST(test_dkimcanonparser_large_body_dynamic_path) {
    TEST_CASE("a body crossing the 4 KiB static threshold still strips trailing WSP");

    /* > BUFFERDATA_CAPACITY (4095) forces the output into the dynamic buffer,
     * which also exercises bufferdata_back/pop_back across the static/dynamic
     * boundary during trailing-WSP stripping. */
    const size_t n = 5000;
    char* body = malloc(n + 8); /* 'a'*n + "  \r\n" */
    TEST_REQUIRE_NOT_NULL(body, "allocate body");
    memset(body, 'a', n);
    memcpy(body + n, "  \r\n", 4);
    body[n + 4] = '\0';

    size_t len = 0;
    char* out = canon_run(body, &len);
    TEST_REQUIRE_NOT_NULL(out, "large body canonicalized");

    /* n 'a's, the two trailing spaces stripped, terminated with one CRLF. */
    TEST_ASSERT_EQUAL(n + 2, len, "large body length = a's + CRLF");
    TEST_ASSERT_EQUAL('a', out[n - 1], "last content byte is 'a'");
    TEST_ASSERT_EQUAL('\r', out[n], "CRLF CR at offset n");
    TEST_ASSERT_EQUAL('\n', out[n + 1], "CRLF LF at offset n+1");
    TEST_ASSERT(strchr(out, ' ') == NULL, "no space remains in canonical body");
    TEST_ASSERT(strchr(out, '\t') == NULL, "no tab remains in canonical body");

    free(out);
    free(body);
}

/* -------------------------------------------------------------------------- */
/* run is reusable across buffers                                             */
/* -------------------------------------------------------------------------- */

TEST(test_dkimcanonparser_reuse_across_buffers) {
    TEST_CASE("a single parser run twice produces each buffer's canonical form");

    dkimcanonparser_t* p = dkimcanonparser_alloc();
    TEST_REQUIRE_NOT_NULL(p, "alloc should succeed");
    dkimcanonparser_init(p);

    dkimcanonparser_set_buffer(p, "first", 5);
    dkimcanonparser_run(p);
    char* a = dkimcanonparser_get_content(p);
    TEST_ASSERT_STR_EQUAL("first\r\n", a, "first run");
    free(a);

    /* Without re-init, run on a new buffer must reflect only the new buffer. */
    const char* second = "second  x"; /* two internal spaces, then 'x' */
    dkimcanonparser_set_buffer(p, second, strlen(second));
    dkimcanonparser_run(p);
    char* b = dkimcanonparser_get_content(p);
    TEST_ASSERT_STR_EQUAL("second x\r\n", b, "second run reflects only the new buffer");
    TEST_ASSERT(strstr(b, "first") == NULL, "no leftover content from the first run");
    free(b);

    dkimcanonparser_free(p);
}

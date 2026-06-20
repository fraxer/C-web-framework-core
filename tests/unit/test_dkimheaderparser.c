#include "framework.h"
#include "dkimheaderparser.h"

#include <stdlib.h>
#include <string.h>

/* The DKIM "relaxed" header VALUE canonicalization (RFC 6376 §3.4.2), applied
 * to a single field value (the field NAME is lowercased separately by dkim.c):
 *   (c) collapse runs of WSP to a single SP;
 *   (d) strip trailing WSP;
 *   (e) strip leading WSP.
 * WSP is SP/TAB (RFC 5234); CR/LF are folded in as collapsible whitespace so a
 * folded value (CRLF + WSP) unfolds to a single SP. */

/* Canonicalize `value` (NUL-terminated) with a FRESH parser. Returns a malloc'd
 * result the caller frees; records its byte length in *out_len (may be NULL). */
static char* hdr_run(const char* value, size_t* out_len) {
    /* Non-void helper: a plain NULL check, not TEST_REQUIRE_* (which aborts with
     * a bare `return;` — -Wreturn-type here, and the analyzer then treats the
     * result as uninitialized at every call site). Callers guard the result. */
    dkimheaderparser_t* p = dkimheaderparser_alloc();
    if (p == NULL)
        return NULL;

    dkimheaderparser_init(p);
    dkimheaderparser_set_buffer(p, value, strlen(value));
    dkimheaderparser_run(p);

    char* out = dkimheaderparser_get_content(p);
    if (out_len != NULL)
        *out_len = (out != NULL) ? strlen(out) : 0;

    dkimheaderparser_free(p);
    return out;
}

/* -------------------------------------------------------------------------- */
/* lifecycle                                                                  */
/* -------------------------------------------------------------------------- */

TEST(test_dkimheaderparser_alloc_init_free) {
    TEST_CASE("alloc/init/free is safe; run with no buffer yields empty");

    dkimheaderparser_t* p = dkimheaderparser_alloc();
    TEST_REQUIRE_NOT_NULL(p, "alloc should succeed");

    dkimheaderparser_init(p);
    TEST_ASSERT_EQUAL(1, dkimheaderparser_run(p), "run returns 1");
    TEST_ASSERT_EQUAL(0, (int)dkimheaderparser_get_content_length(p), "no buffer → length 0");

    char* out = dkimheaderparser_get_content(p);
    TEST_ASSERT_NOT_NULL(out, "get_content returns a buffer");
    TEST_ASSERT_EQUAL(0, (int)strlen(out), "empty canonical form");
    free(out);

    dkimheaderparser_free(p);
}

TEST(test_dkimheaderparser_get_content_is_copy) {
    TEST_CASE("get_content returns an independent heap copy");

    char* out = hdr_run("Hi", NULL);
    TEST_REQUIRE_NOT_NULL(out, "canon should produce output");
    TEST_ASSERT_STR_EQUAL("Hi", out, "simple value canonicalized");
    /* Survives the parser free done inside hdr_run. */
    TEST_ASSERT_STR_EQUAL("Hi", out, "copy is independent");
    free(out);
}

TEST(test_dkimheaderparser_length_matches_strlen) {
    TEST_CASE("get_content_length equals strlen of get_content");

    size_t len = 999;
    char* out = hdr_run("  a   b  ", &len);
    TEST_REQUIRE_NOT_NULL(out, "canon should produce output");
    TEST_ASSERT_EQUAL((int)strlen(out), (int)len, "length matches strlen");
    TEST_ASSERT_EQUAL(3, (int)len, "'a b' is 3 bytes");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* RFC 6376 §3.4.2(c): collapse internal WSP                                   */
/* -------------------------------------------------------------------------- */

TEST(test_dkimheaderparser_collapse_wsp) {
    TEST_CASE("runs of spaces/tabs collapse to a single space");

    char* out = hdr_run("a    b", NULL);
    TEST_ASSERT_STR_EQUAL("a b", out, "spaces collapse");
    free(out);

    out = hdr_run("a\t\t\tb", NULL);
    TEST_ASSERT_STR_EQUAL("a b", out, "tabs collapse");
    free(out);

    out = hdr_run("a \t b", NULL);
    TEST_ASSERT_STR_EQUAL("a b", out, "mixed space/tab run collapses");
    free(out);

    out = hdr_run("one   two   three", NULL);
    TEST_ASSERT_STR_EQUAL("one two three", out, "multiple runs collapse");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* RFC 6376 §3.4.2(d)+(e): strip trailing and leading WSP                     */
/* -------------------------------------------------------------------------- */

TEST(test_dkimheaderparser_strip_leading_trailing) {
    TEST_CASE("leading and trailing WSP are removed");

    char* out = hdr_run("  abc  ", NULL);
    TEST_ASSERT_STR_EQUAL("abc", out, "both ends stripped");
    free(out);

    out = hdr_run("\t\tValue\t", NULL);
    TEST_ASSERT_STR_EQUAL("Value", out, "tab-only edges stripped");
    free(out);

    out = hdr_run("   Value with  spaces   ", NULL);
    TEST_ASSERT_STR_EQUAL("Value with spaces", out, "edges stripped, internals collapsed");
    free(out);
}

TEST(test_dkimheaderparser_all_whitespace_to_empty) {
    TEST_CASE("a value of only WSP canonicalizes to empty");

    size_t len = 999;
    char* out = hdr_run("  \t \t  ", &len);
    TEST_REQUIRE_NOT_NULL(out, "wsp-only returns a buffer");
    TEST_ASSERT_EQUAL(0, (int)len, "wsp-only length is 0");
    TEST_ASSERT_STR_EQUAL("", out, "wsp-only canonical form is empty");
    free(out);

    out = hdr_run("", NULL);
    TEST_ASSERT_STR_EQUAL("", out, "empty value stays empty");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* folding: CRLF + WSP unfolds to a single SP                                 */
/* -------------------------------------------------------------------------- */

TEST(test_dkimheaderparser_unfolds_crlf) {
    TEST_CASE("a folded value (CRLF + WSP) unfolds to a single space");

    char* out = hdr_run("folded\r\n\tvalue", NULL);
    TEST_ASSERT_STR_EQUAL("folded value", out, "CRLF+TAB folds to one SP");
    free(out);

    out = hdr_run("a\r\n b", NULL);
    TEST_ASSERT_STR_EQUAL("a b", out, "CRLF+SP folds to one SP");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* high-bit bytes are symbols, not whitespace (isspace UB guard)              */
/* -------------------------------------------------------------------------- */

TEST(test_dkimheaderparser_highbit_bytes_preserved) {
    TEST_CASE("bytes > 127 pass through as symbols (no isspace UB)");

    /* "café" in UTF-8 is 'c','a','f',0xC3,0xA9. Previously isspace() received
     * these as negative signed char (UB); they must be treated as symbols and
     * preserved verbatim. */
    const char value[] = {'c', 'a', 'f', (char)0xC3, (char)0xA9, 0};
    char* out = hdr_run(value, NULL);
    TEST_ASSERT_STR_EQUAL(value, out, "UTF-8 bytes preserved unchanged");
    free(out);
}

/* -------------------------------------------------------------------------- */
/* the reuse regression: leading WSP stripped on 2nd+ run                    */
/* -------------------------------------------------------------------------- */

TEST(test_dkimheaderparser_reuse_strips_leading_wsp_each_run) {
    TEST_CASE("a reused parser strips leading WSP on every run, not just the first");

    /* Mirrors __dkim_relaxed_header_canon: one parser, many headers. Before the
     * fix, run() did not reset stage, so the 2nd+ header kept a leading space
     * whenever the previous value ended in a symbol. */
    dkimheaderparser_t* p = dkimheaderparser_alloc();
    TEST_REQUIRE_NOT_NULL(p, "alloc should succeed");
    dkimheaderparser_init(p);

    struct { const char* in; const char* want; } cases[] = {
        { "Alice",                       "Alice" },          /* ends symbol */
        { "   bob",                      "bob" },            /* leading WSP */
        { "\t  Carol <c@d.e>",           "Carol <c@d.e>" },  /* leading TAB+WSP */
        { "x",                           "x" },
        { "   leading and  trailing  ",  "leading and trailing" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        dkimheaderparser_set_buffer(p, cases[i].in, strlen(cases[i].in));
        dkimheaderparser_run(p);
        char* out = dkimheaderparser_get_content(p);
        TEST_ASSERT_NOT_NULL(out, "get_content returns a buffer");
        TEST_ASSERT_STR_EQUAL(cases[i].want, out, "reused parser canonicalizes each value");
        free(out);
    }

    dkimheaderparser_free(p);
}

/* -------------------------------------------------------------------------- */
/* large value: exercises the static→dynamic buffer path                      */
/* -------------------------------------------------------------------------- */

TEST(test_dkimheaderparser_large_value_dynamic_path) {
    TEST_CASE("a value crossing the 4 KiB static threshold canonicalizes correctly");

    /* > BUFFERDATA_CAPACITY (4095) forces output into the dynamic buffer,
     * exercising bufferdata_back/pop_back across the static/dynamic boundary
     * during the trailing-WSP strip. */
    const size_t n = 5000;
    char* value = malloc(n + 8);
    TEST_REQUIRE_NOT_NULL(value, "allocate value");
    /* 'a'*n + "   " (trailing WSP run) */
    memset(value, 'a', n);
    memcpy(value + n, "   ", 3);
    value[n + 3] = '\0';

    size_t len = 0;
    char* out = hdr_run(value, &len);
    /* Non-aborting check + guard: an early-return TEST_REQUIRE here would leak
     * `value` on the NULL path (the analyzer flags it as CWE-401). */
    TEST_ASSERT_NOT_NULL(out, "large value canonicalized");
    if (out != NULL) {
        TEST_ASSERT_EQUAL(n, len, "large value length = a's only (trailing WSP stripped)");
        TEST_ASSERT_EQUAL('a', out[n - 1], "last content byte is 'a'");
        TEST_ASSERT_EQUAL('\0', out[n], "NUL terminator right after content");
        TEST_ASSERT(strchr(out, ' ') == NULL, "no space remains");
        free(out);
    }
    free(value);
}

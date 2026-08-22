#include "framework.h"
#include "domain.h"
#include <string.h>

// ============================================================================
// Domain template tests — domain templates from config are compiled to PCRE
// and matched against the Host header for virtual host selection, so both
// anchoring and wildcard handling are security-relevant: a template that
// matches too broadly lets a foreign Host land on the wrong vhost.
// ============================================================================

/* The compiled pattern, asked directly. Every case below goes through this, so
 * the tests keep describing the pattern -- while `agrees` (bottom of the file)
 * is what checks that domain_matches, which may skip PCRE entirely for a
 * literal template, answers the same. */
static int pattern_matches(const domain_t* domain, const char* host) {
    int vector[30];
    return pcre_exec(domain->pcre_template, NULL, host, (int)strlen(host), 0, 0, vector, 30) > 0;
}

/* What the server actually calls, with the same signature the cases use. */
static int domain_matches_host(const domain_t* domain, const char* host) {
    return domain_matches(domain, host, strlen(host));
}

TEST(test_domain_simple) {
    TEST_CASE("plain domain is escaped and fully anchored");

    domain_t* d = domain_create("example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("example.com", d->template, "original template preserved");
    TEST_ASSERT_STR_EQUAL("^example\\.com$", d->prepared_template, "dots escaped, both anchors added");

    TEST_ASSERT(pattern_matches(d, "example.com"), "exact host should match");
    TEST_ASSERT(!pattern_matches(d, "exampleXcom"), "dot must not act as regex any-char");
    TEST_ASSERT(!pattern_matches(d, "evil-example.com"), "suffix host must not match");
    TEST_ASSERT(!pattern_matches(d, "example.com.evil"), "prefix host must not match");

    domains_free(d);
}

TEST(test_domain_leading_wildcard) {
    TEST_CASE("*.example.com matches subdomains only");

    domain_t* d = domain_create("*.example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^.*\\.example\\.com$", d->prepared_template, "leading asterisk becomes .*");

    TEST_ASSERT(pattern_matches(d, "api.example.com"), "subdomain should match");
    TEST_ASSERT(pattern_matches(d, "a.b.example.com"), "nested subdomain should match");
    TEST_ASSERT(!pattern_matches(d, "example.com"), "bare domain should not match wildcard");
    TEST_ASSERT(!pattern_matches(d, "apiexample.com"), "dot before domain is required");
    TEST_ASSERT(!pattern_matches(d, "api.example.com.evil"), "suffix host must not match");

    domains_free(d);
}

TEST(test_domain_trailing_wildcard_no_dots) {
    TEST_CASE("trailing asterisk without dots before it (regression: end check compared against output position)");

    domain_t* d = domain_create("test*");
    TEST_REQUIRE_NOT_NULL(d, "test* is a valid template: asterisk is at the end");

    TEST_ASSERT_STR_EQUAL("^test.*$", d->prepared_template, "trailing asterisk becomes .*");
    TEST_ASSERT(pattern_matches(d, "test"), "bare prefix should match");
    TEST_ASSERT(pattern_matches(d, "test.example.com"), "any suffix should match");
    TEST_ASSERT(!pattern_matches(d, "atest"), "prefix must be anchored at start");

    domains_free(d);
}

TEST(test_domain_trailing_wildcard_multiple_dots) {
    TEST_CASE("trailing asterisk after several dots (regression: only exactly one escaped dot used to pass)");

    domain_t* d = domain_create("api.example.*");
    TEST_REQUIRE_NOT_NULL(d, "api.example.* is a valid template: asterisk is at the end");

    TEST_ASSERT_STR_EQUAL("^api\\.example\\..*$", d->prepared_template, "dots escaped, trailing asterisk becomes .*");
    TEST_ASSERT(pattern_matches(d, "api.example.com"), "any TLD should match");
    TEST_ASSERT(pattern_matches(d, "api.example.co.uk"), "multi-part TLD should match");
    TEST_ASSERT(!pattern_matches(d, "api.example"), "dot before wildcard is required");

    domains_free(d);
}

TEST(test_domain_trailing_wildcard_single_dot) {
    TEST_CASE("trailing asterisk after exactly one dot (the case that worked before the fix)");

    domain_t* d = domain_create("example.com*");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^example\\.com.*$", d->prepared_template, "trailing asterisk becomes .*");
    TEST_ASSERT(pattern_matches(d, "example.com"), "bare domain should match");
    TEST_ASSERT(pattern_matches(d, "example.com.ua"), "extended host should match");

    domains_free(d);
}

TEST(test_domain_middle_asterisk_rejected) {
    TEST_CASE("asterisk in the middle is rejected");

    TEST_ASSERT_NULL(domain_create("exam*ple.com"), "middle asterisk must be rejected");
    // Regression: 'a.b*c' used to be accepted because exactly one escaped dot
    // preceded the asterisk, fooling the output-position check.
    TEST_ASSERT_NULL(domain_create("a.b*c"), "middle asterisk after a dot must be rejected");
}

TEST(test_domain_wildcard_only) {
    TEST_CASE("bare asterisk matches any host");

    domain_t* d = domain_create("*");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^.*$", d->prepared_template, "bare asterisk becomes .*");
    TEST_ASSERT(pattern_matches(d, "anything.example.com"), "any host should match");
    TEST_ASSERT(pattern_matches(d, ""), "empty host should match");

    domains_free(d);
}

TEST(test_domain_both_wildcards) {
    TEST_CASE("wildcards on both ends");

    domain_t* d = domain_create("*.example.*");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^.*\\.example\\..*$", d->prepared_template, "both asterisks become .*");
    TEST_ASSERT(pattern_matches(d, "api.example.com"), "wrapped host should match");
    TEST_ASSERT(!pattern_matches(d, "example.com"), "leading dot is required");

    domains_free(d);
}

TEST(test_domain_empty_rejected) {
    TEST_CASE("empty template is rejected (regression: used to read one byte before the buffer)");

    TEST_ASSERT_NULL(domain_create(""), "empty template must be rejected");
}

TEST(test_domain_null_rejected) {
    TEST_CASE("NULL template is rejected");

    TEST_ASSERT_NULL(domain_create(NULL), "NULL template must be rejected");
}

TEST(test_domain_single_end_anchor) {
    TEST_CASE("template with only $ still gets ^ (regression: one anchor used to disable the other)");

    domain_t* d = domain_create("example.com$");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^example\\.com$", d->prepared_template, "start anchor added independently");
    TEST_ASSERT(pattern_matches(d, "example.com"), "exact host should match");
    TEST_ASSERT(!pattern_matches(d, "evil-example.com"), "suffix host must not match a $-only template");

    domains_free(d);
}

TEST(test_domain_single_start_anchor) {
    TEST_CASE("template with only ^ still gets $ (regression: one anchor used to disable the other)");

    domain_t* d = domain_create("^example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^example\\.com$", d->prepared_template, "end anchor added independently");
    TEST_ASSERT(pattern_matches(d, "example.com"), "exact host should match");
    TEST_ASSERT(!pattern_matches(d, "example.com.evil"), "prefix host must not match a ^-only template");

    domains_free(d);
}

TEST(test_domain_full_anchors_passthrough) {
    TEST_CASE("fully anchored template passes through without extra anchors");

    domain_t* d = domain_create("^(api|www)$");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^(api|www)$", d->prepared_template, "no anchors duplicated");
    TEST_ASSERT(pattern_matches(d, "api"), "first alternative should match");
    TEST_ASSERT(pattern_matches(d, "www"), "second alternative should match");
    TEST_ASSERT(!pattern_matches(d, "apiwww"), "concatenation must not match");

    domains_free(d);
}

TEST(test_domain_alternation_group) {
    TEST_CASE("parenthesized alternation is kept, dots outside are escaped");

    domain_t* d = domain_create("example.(com|org)");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^example\\.(com|org)$", d->prepared_template, "group preserved");
    TEST_ASSERT(pattern_matches(d, "example.com"), "first alternative should match");
    TEST_ASSERT(pattern_matches(d, "example.org"), "second alternative should match");
    TEST_ASSERT(!pattern_matches(d, "example.net"), "other TLD must not match");

    domains_free(d);
}

TEST(test_domain_character_class) {
    TEST_CASE("character class is kept verbatim, dot inside is not escaped");

    domain_t* d = domain_create("img[0-9].example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^img[0-9]\\.example\\.com$", d->prepared_template, "class preserved, outer dots escaped");
    TEST_ASSERT(pattern_matches(d, "img5.example.com"), "digit host should match");
    TEST_ASSERT(!pattern_matches(d, "imgx.example.com"), "non-digit host must not match");

    domains_free(d);
}

TEST(test_domain_unbalanced_brackets_rejected) {
    TEST_CASE("unbalanced brackets are rejected");

    TEST_ASSERT_NULL(domain_create("example(.com"), "unclosed group must be rejected");
    TEST_ASSERT_NULL(domain_create("example).com"), "closing without opening must be rejected");
    TEST_ASSERT_NULL(domain_create("img[0-9.example.com"), "unclosed class must be rejected");
}

TEST(test_domain_pcre_compile_failure) {
    TEST_CASE("template that survives parsing but fails PCRE compilation returns NULL without leaks");

    TEST_ASSERT_NULL(domain_create("(+)"), "quantifier with nothing to repeat must be rejected");
}

TEST(test_domain_idn_conversion) {
    TEST_CASE("non-ASCII template is converted to punycode and matched in ASCII form");

    domain_t* d = domain_create("тест.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("тест.com", d->template, "original template preserved");
    TEST_ASSERT(strncmp(d->ascii_template, "xn--", 4) == 0, "ascii template should be punycode");
    TEST_ASSERT(pattern_matches(d, d->ascii_template), "punycode host should match");
    TEST_ASSERT(!pattern_matches(d, "test.com"), "unrelated ASCII host must not match");

    domains_free(d);
}

TEST(test_domain_count_and_chain_free) {
    TEST_CASE("domain_count walks the chain; domains_free releases every node");

    TEST_ASSERT_EQUAL(0, domain_count(NULL), "empty chain has zero domains");

    domain_t* first = domain_create("one.com");
    domain_t* second = domain_create("two.com");
    domain_t* third = domain_create("three.com");
    TEST_REQUIRE_GOTO(first != NULL && second != NULL && third != NULL, "chain allocation should succeed", cleanup);

    first->next = second;
    second->next = third;

    TEST_ASSERT_EQUAL(3, domain_count(first), "chain of three domains");
    TEST_ASSERT_EQUAL(2, domain_count(second), "count from the middle of the chain");

    domains_free(first);
    return;

    cleanup:

    domains_free(first);
    domains_free(second);
    domains_free(third);
}

TEST(test_domains_free_null) {
    TEST_CASE("domains_free(NULL) is a no-op");

    domains_free(NULL);
    TEST_ASSERT(1, "no crash on NULL chain");
}

// ============================================================================
// The literal shortcut — a template that means only itself is matched by string
// comparison instead of PCRE (the top line of the worker profile was libpcre on
// hosts like "example.com"). What matters is that the shortcut and the pattern
// never disagree: a vhost picked by one rule and rejected by the other is how a
// foreign Host lands on the wrong server.
// ============================================================================

/* Both answers, compared. Returns 1 when they agree, whatever the answer is. */
static int agrees(const domain_t* domain, const char* host) {
    return domain_matches_host(domain, host) == pattern_matches(domain, host);
}

TEST(test_domain_literal_shortcut_agrees_with_pattern) {
    TEST_SUITE("domain: literal shortcut");
    TEST_CASE("string comparison and the compiled pattern answer identically");

    static const char* templates[] = {
        "example.com", "www.example.com", "localhost", "127.0.0.1",
        "xn--e1afmkfd.xn--p1ai",              /* punycode, still literal */
        "*.example.com", "example.(com|org)", /* patterns, not literal */
        "^api\\.example\\.com$",
    };

    static const char* hosts[] = {
        "example.com", "www.example.com", "sub.example.com", "localhost",
        "exampleXcom", "example.com.evil", "evil-example.com", "127.0.0.1",
        "api.example.com", "example.org", "xn--e1afmkfd.xn--p1ai", "",
        "EXAMPLE.COM",
    };

    for (size_t i = 0; i < sizeof(templates) / sizeof(templates[0]); i++) {
        domain_t* d = domain_create(templates[i]);
        TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

        for (size_t j = 0; j < sizeof(hosts) / sizeof(hosts[0]); j++) {
            if (!agrees(d, hosts[j])) {
                TEST_FAIL("the literal shortcut disagreed with the pattern");
                break;
            }
        }

        domains_free(d);
    }

    TEST_ASSERT(1, "shortcut and pattern agree on every template/host pair");
}

TEST(test_domain_literal_flag) {
    TEST_SUITE("domain: literal shortcut");
    TEST_CASE("only templates without metacharacters take the shortcut");

    static const struct { const char* template; int literal; } cases[] = {
        {"example.com", 1},
        {"www.example.com", 1},
        {"localhost", 1},
        {"127.0.0.1", 1},              /* dots are escaped, so still literal */
        {"xn--e1afmkfd.xn--p1ai", 1},  /* punycode is ASCII letters and dashes */
        {"*.example.com", 0},
        {"example.(com|org)", 0},
        {"^example\\.com$", 0},
        {"exa[m]ple.com", 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        domain_t* d = domain_create(cases[i].template);
        TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

        TEST_ASSERT_EQUAL(cases[i].literal, d->is_literal, cases[i].template);
        if (d->is_literal)
            TEST_ASSERT_EQUAL_SIZE(strlen(d->ascii_template), d->ascii_length,
                                   "the cached length matches the template");

        domains_free(d);
    }
}

TEST(test_domain_matching_is_case_insensitive) {
    TEST_SUITE("domain: case folding");
    TEST_CASE("a host matches its vhost whatever case it arrives in");

    /* REGRESSION: the pattern was compiled without PCRE_CASELESS and the
     * literal shortcut compared bytes, so `Host: EXAMPLE.COM` missed the vhost
     * `example.com` entirely and the request was answered 404. A host is
     * case-insensitive (RFC 9110 §4.2.3). */
    domain_t* d = domain_create("example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_EQUAL(1, domain_matches_host(d, "example.com"), "lower case matches");
    TEST_ASSERT_EQUAL(1, domain_matches_host(d, "EXAMPLE.COM"), "upper case matches");
    TEST_ASSERT_EQUAL(1, domain_matches_host(d, "ExAmPlE.CoM"), "mixed case matches");
    TEST_ASSERT_EQUAL(0, domain_matches_host(d, "example.org"), "a different host still does not");

    /* Both halves must fold the same way, or the shortcut and the pattern would
     * disagree on exactly the hosts that differ in case. */
    TEST_ASSERT(agrees(d, "EXAMPLE.COM"), "shortcut and pattern agree on upper case");
    TEST_ASSERT(agrees(d, "ExAmPlE.CoM"), "and on mixed case");

    domains_free(d);

    /* The same for a pattern that cannot take the shortcut. */
    domain_t* w = domain_create("*.example.com");
    TEST_REQUIRE_NOT_NULL(w, "wildcard domain created");

    TEST_ASSERT_EQUAL(1, domain_matches_host(w, "sub.example.com"), "wildcard, lower case");
    TEST_ASSERT_EQUAL(1, domain_matches_host(w, "SUB.EXAMPLE.COM"), "wildcard, upper case");
    TEST_ASSERT_EQUAL(0, domain_matches_host(w, "example.com"), "and it still needs a label");

    domains_free(w);
}

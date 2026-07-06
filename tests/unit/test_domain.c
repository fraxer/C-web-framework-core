#include "framework.h"
#include "domain.h"
#include <string.h>

// ============================================================================
// Domain template tests — domain templates from config are compiled to PCRE
// and matched against the Host header for virtual host selection, so both
// anchoring and wildcard handling are security-relevant: a template that
// matches too broadly lets a foreign Host land on the wrong vhost.
// ============================================================================

static int domain_matches(const domain_t* domain, const char* host) {
    int vector[30];
    return pcre_exec(domain->pcre_template, NULL, host, (int)strlen(host), 0, 0, vector, 30) > 0;
}

TEST(test_domain_simple) {
    TEST_CASE("plain domain is escaped and fully anchored");

    domain_t* d = domain_create("example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("example.com", d->template, "original template preserved");
    TEST_ASSERT_STR_EQUAL("^example\\.com$", d->prepared_template, "dots escaped, both anchors added");

    TEST_ASSERT(domain_matches(d, "example.com"), "exact host should match");
    TEST_ASSERT(!domain_matches(d, "exampleXcom"), "dot must not act as regex any-char");
    TEST_ASSERT(!domain_matches(d, "evil-example.com"), "suffix host must not match");
    TEST_ASSERT(!domain_matches(d, "example.com.evil"), "prefix host must not match");

    domains_free(d);
}

TEST(test_domain_leading_wildcard) {
    TEST_CASE("*.example.com matches subdomains only");

    domain_t* d = domain_create("*.example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^.*\\.example\\.com$", d->prepared_template, "leading asterisk becomes .*");

    TEST_ASSERT(domain_matches(d, "api.example.com"), "subdomain should match");
    TEST_ASSERT(domain_matches(d, "a.b.example.com"), "nested subdomain should match");
    TEST_ASSERT(!domain_matches(d, "example.com"), "bare domain should not match wildcard");
    TEST_ASSERT(!domain_matches(d, "apiexample.com"), "dot before domain is required");
    TEST_ASSERT(!domain_matches(d, "api.example.com.evil"), "suffix host must not match");

    domains_free(d);
}

TEST(test_domain_trailing_wildcard_no_dots) {
    TEST_CASE("trailing asterisk without dots before it (regression: end check compared against output position)");

    domain_t* d = domain_create("test*");
    TEST_REQUIRE_NOT_NULL(d, "test* is a valid template: asterisk is at the end");

    TEST_ASSERT_STR_EQUAL("^test.*$", d->prepared_template, "trailing asterisk becomes .*");
    TEST_ASSERT(domain_matches(d, "test"), "bare prefix should match");
    TEST_ASSERT(domain_matches(d, "test.example.com"), "any suffix should match");
    TEST_ASSERT(!domain_matches(d, "atest"), "prefix must be anchored at start");

    domains_free(d);
}

TEST(test_domain_trailing_wildcard_multiple_dots) {
    TEST_CASE("trailing asterisk after several dots (regression: only exactly one escaped dot used to pass)");

    domain_t* d = domain_create("api.example.*");
    TEST_REQUIRE_NOT_NULL(d, "api.example.* is a valid template: asterisk is at the end");

    TEST_ASSERT_STR_EQUAL("^api\\.example\\..*$", d->prepared_template, "dots escaped, trailing asterisk becomes .*");
    TEST_ASSERT(domain_matches(d, "api.example.com"), "any TLD should match");
    TEST_ASSERT(domain_matches(d, "api.example.co.uk"), "multi-part TLD should match");
    TEST_ASSERT(!domain_matches(d, "api.example"), "dot before wildcard is required");

    domains_free(d);
}

TEST(test_domain_trailing_wildcard_single_dot) {
    TEST_CASE("trailing asterisk after exactly one dot (the case that worked before the fix)");

    domain_t* d = domain_create("example.com*");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^example\\.com.*$", d->prepared_template, "trailing asterisk becomes .*");
    TEST_ASSERT(domain_matches(d, "example.com"), "bare domain should match");
    TEST_ASSERT(domain_matches(d, "example.com.ua"), "extended host should match");

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
    TEST_ASSERT(domain_matches(d, "anything.example.com"), "any host should match");
    TEST_ASSERT(domain_matches(d, ""), "empty host should match");

    domains_free(d);
}

TEST(test_domain_both_wildcards) {
    TEST_CASE("wildcards on both ends");

    domain_t* d = domain_create("*.example.*");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^.*\\.example\\..*$", d->prepared_template, "both asterisks become .*");
    TEST_ASSERT(domain_matches(d, "api.example.com"), "wrapped host should match");
    TEST_ASSERT(!domain_matches(d, "example.com"), "leading dot is required");

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
    TEST_ASSERT(domain_matches(d, "example.com"), "exact host should match");
    TEST_ASSERT(!domain_matches(d, "evil-example.com"), "suffix host must not match a $-only template");

    domains_free(d);
}

TEST(test_domain_single_start_anchor) {
    TEST_CASE("template with only ^ still gets $ (regression: one anchor used to disable the other)");

    domain_t* d = domain_create("^example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^example\\.com$", d->prepared_template, "end anchor added independently");
    TEST_ASSERT(domain_matches(d, "example.com"), "exact host should match");
    TEST_ASSERT(!domain_matches(d, "example.com.evil"), "prefix host must not match a ^-only template");

    domains_free(d);
}

TEST(test_domain_full_anchors_passthrough) {
    TEST_CASE("fully anchored template passes through without extra anchors");

    domain_t* d = domain_create("^(api|www)$");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^(api|www)$", d->prepared_template, "no anchors duplicated");
    TEST_ASSERT(domain_matches(d, "api"), "first alternative should match");
    TEST_ASSERT(domain_matches(d, "www"), "second alternative should match");
    TEST_ASSERT(!domain_matches(d, "apiwww"), "concatenation must not match");

    domains_free(d);
}

TEST(test_domain_alternation_group) {
    TEST_CASE("parenthesized alternation is kept, dots outside are escaped");

    domain_t* d = domain_create("example.(com|org)");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^example\\.(com|org)$", d->prepared_template, "group preserved");
    TEST_ASSERT(domain_matches(d, "example.com"), "first alternative should match");
    TEST_ASSERT(domain_matches(d, "example.org"), "second alternative should match");
    TEST_ASSERT(!domain_matches(d, "example.net"), "other TLD must not match");

    domains_free(d);
}

TEST(test_domain_character_class) {
    TEST_CASE("character class is kept verbatim, dot inside is not escaped");

    domain_t* d = domain_create("img[0-9].example.com");
    TEST_REQUIRE_NOT_NULL(d, "domain_create should succeed");

    TEST_ASSERT_STR_EQUAL("^img[0-9]\\.example\\.com$", d->prepared_template, "class preserved, outer dots escaped");
    TEST_ASSERT(domain_matches(d, "img5.example.com"), "digit host should match");
    TEST_ASSERT(!domain_matches(d, "imgx.example.com"), "non-digit host must not match");

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
    TEST_ASSERT(domain_matches(d, d->ascii_template), "punycode host should match");
    TEST_ASSERT(!domain_matches(d, "test.com"), "unrelated ASCII host must not match");

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

#include "framework.h"
#include "openssl.h"
#include <string.h>
#include <stdlib.h>

// ============================================================================
// openssl_split_ciphers — routes one config field to two OpenSSL APIs.
//   TLS 1.3 suite names start with "TLS_"; everything else is a 1.2 cipher or
//   a 1.2 control token (!aNULL, @STRENGTH, -MD5, ALL).
//   An empty group yields NULL, which tells the caller to keep OpenSSL's
//   defaults for that version instead of installing an empty list.
// ============================================================================

TEST(test_split_ciphers_only_tls12) {
    TEST_CASE("A classic 1.2-only list leaves the 1.3 group untouched");

    char* tls12 = NULL;
    char* tls13 = NULL;
    const int ok = openssl_split_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256", &tls12, &tls13);

    TEST_ASSERT_EQUAL(1, ok, "Split should succeed");
    TEST_ASSERT_STR_EQUAL("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
                          tls12, "1.2 list should pass through unchanged");
    TEST_ASSERT_NULL(tls13, "No TLS_ tokens means no 1.3 list (keep defaults)");

    free(tls12);
    free(tls13);
}

TEST(test_split_ciphers_only_tls13) {
    TEST_CASE("A 1.3-only list leaves the 1.2 group untouched");

    char* tls12 = NULL;
    char* tls13 = NULL;
    const int ok = openssl_split_ciphers(
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", &tls12, &tls13);

    TEST_ASSERT_EQUAL(1, ok, "Split should succeed");
    TEST_ASSERT_NULL(tls12, "No 1.2 tokens means no 1.2 list (keep defaults)");
    TEST_ASSERT_STR_EQUAL("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
                          tls13, "1.3 suites should pass through unchanged");

    free(tls12);
    free(tls13);
}

TEST(test_split_ciphers_mixed) {
    TEST_CASE("A mixed list is routed by prefix, order preserved in each group");

    char* tls12 = NULL;
    char* tls13 = NULL;
    const int ok = openssl_split_ciphers(
        "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
        "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256", &tls12, &tls13);

    TEST_ASSERT_EQUAL(1, ok, "Split should succeed");
    TEST_ASSERT_STR_EQUAL("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
                          tls12, "1.2 ciphers keep their relative order");
    TEST_ASSERT_STR_EQUAL("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256",
                          tls13, "1.3 suites keep their relative order");

    free(tls12);
    free(tls13);
}

TEST(test_split_ciphers_separators) {
    TEST_CASE("Colons, commas and whitespace all separate (ciphers(1))");

    char* tls12 = NULL;
    char* tls13 = NULL;
    const int ok = openssl_split_ciphers(
        "  AES256-SHA, TLS_AES_128_GCM_SHA256\tAES128-SHA::TLS_AES_256_GCM_SHA384  ",
        &tls12, &tls13);

    TEST_ASSERT_EQUAL(1, ok, "Split should succeed");
    TEST_ASSERT_STR_EQUAL("AES256-SHA:AES128-SHA", tls12,
                          "Mixed separators should normalise to colons");
    TEST_ASSERT_STR_EQUAL("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", tls13,
                          "Leading/trailing separators must not leak into a token");

    free(tls12);
    free(tls13);
}

TEST(test_split_ciphers_control_tokens) {
    TEST_CASE("1.2 control syntax stays in the 1.2 group verbatim");

    char* tls12 = NULL;
    char* tls13 = NULL;
    const int ok = openssl_split_ciphers("HIGH:!aNULL:!MD5:@STRENGTH", &tls12, &tls13);

    TEST_ASSERT_EQUAL(1, ok, "Split should succeed");
    TEST_ASSERT_STR_EQUAL("HIGH:!aNULL:!MD5:@STRENGTH", tls12,
                          "Control tokens must survive untouched");
    TEST_ASSERT_NULL(tls13, "Control tokens are not 1.3 suites");

    free(tls12);
    free(tls13);
}

TEST(test_split_ciphers_empty) {
    TEST_CASE("Empty and separator-only inputs produce no lists at all");

    char* tls12 = NULL;
    char* tls13 = NULL;

    TEST_ASSERT_EQUAL(1, openssl_split_ciphers("", &tls12, &tls13), "Empty is not an error");
    TEST_ASSERT_NULL(tls12, "Empty input yields no 1.2 list");
    TEST_ASSERT_NULL(tls13, "Empty input yields no 1.3 list");

    TEST_ASSERT_EQUAL(1, openssl_split_ciphers(" : , ", &tls12, &tls13), "Separators only");
    TEST_ASSERT_NULL(tls12, "Separator-only input yields no 1.2 list");
    TEST_ASSERT_NULL(tls13, "Separator-only input yields no 1.3 list");

    TEST_ASSERT_EQUAL(1, openssl_split_ciphers(NULL, &tls12, &tls13), "NULL is not an error");
    TEST_ASSERT_NULL(tls12, "NULL input yields no 1.2 list");
    TEST_ASSERT_NULL(tls13, "NULL input yields no 1.3 list");
}

TEST(test_split_ciphers_tls_prefix_boundary) {
    TEST_CASE("A bare \"TLS_\" is not a suite name, so it stays with 1.2");

    char* tls12 = NULL;
    char* tls13 = NULL;
    const int ok = openssl_split_ciphers("TLS_:TLS_AES_128_GCM_SHA256:TLSv1.2", &tls12, &tls13);

    TEST_ASSERT_EQUAL(1, ok, "Split should succeed");
    TEST_ASSERT_STR_EQUAL("TLS_:TLSv1.2", tls12,
                          "Prefix alone and TLSv1.2 are not 1.3 suite names");
    TEST_ASSERT_STR_EQUAL("TLS_AES_128_GCM_SHA256", tls13, "Only the real suite is 1.3");

    free(tls12);
    free(tls13);
}

TEST(test_split_ciphers_single_token) {
    TEST_CASE("A single token needs no separator");

    char* tls12 = NULL;
    char* tls13 = NULL;
    const int ok = openssl_split_ciphers("TLS_AES_128_GCM_SHA256", &tls12, &tls13);

    TEST_ASSERT_EQUAL(1, ok, "Split should succeed");
    TEST_ASSERT_NULL(tls12, "No 1.2 tokens");
    TEST_ASSERT_STR_EQUAL("TLS_AES_128_GCM_SHA256", tls13, "Single suite, no trailing colon");

    free(tls12);
    free(tls13);
}

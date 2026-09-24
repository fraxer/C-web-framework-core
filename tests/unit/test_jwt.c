#include <stdlib.h>
#include <string.h>

#include "framework.h"
#include "jwt.h"
#include "json.h"

/* The core had no JWT tests at all. These cover the HMAC signature path,
 * which is the one that verifies a token with a constant-time comparison. */

static jwt_key_t* test_key(void) {
    static const char secret[] = "a-test-secret-long-enough-for-hs256";
    return jwt_key_hs256(secret, sizeof secret - 1);
}

TEST(test_jwt_hs256_round_trip) {
    TEST_CASE("A token signed with HS256 verifies with the same key");

    jwt_key_t* key = test_key();
    TEST_ASSERT_NOT_NULL(key, "The key should be created");

    json_doc_t* payload = jwt_create_payload(3600);
    TEST_ASSERT_NOT_NULL(payload, "The payload should be created");

    char* token = jwt_encode(payload, key);
    TEST_ASSERT_NOT_NULL(token, "The token should be encoded");

    TEST_ASSERT_EQUAL(JWT_OK, jwt_verify(token, key), "A valid token verifies");

    free(token);
    json_free(payload);
    jwt_key_free(key);
}

TEST(test_jwt_hs256_rejects_tampered_signature) {
    TEST_CASE("A token with one flipped signature character is rejected");

    jwt_key_t* key = test_key();
    json_doc_t* payload = jwt_create_payload(3600);
    char* token = jwt_encode(payload, key);
    TEST_ASSERT_NOT_NULL(token, "The token should be encoded");

    /* Flip the last character of the signature -- the comparison that rejects
     * this is the one secure_compare_bytes now performs. */
    const size_t length = strlen(token);
    token[length - 1] = token[length - 1] == 'A' ? 'B' : 'A';

    TEST_ASSERT_EQUAL(JWT_ERROR_INVALID_SIGNATURE, jwt_verify(token, key),
                      "A tampered signature must not verify");

    free(token);
    json_free(payload);
    jwt_key_free(key);
}

TEST(test_jwt_hs256_rejects_other_key) {
    TEST_CASE("A token does not verify with a different secret");

    jwt_key_t* key = test_key();
    json_doc_t* payload = jwt_create_payload(3600);
    char* token = jwt_encode(payload, key);
    TEST_ASSERT_NOT_NULL(token, "The token should be encoded");

    static const char other_secret[] = "a-different-secret-of-its-own-size!";
    jwt_key_t* other = jwt_key_hs256(other_secret, sizeof other_secret - 1);

    TEST_ASSERT_EQUAL(JWT_ERROR_INVALID_SIGNATURE, jwt_verify(token, other),
                      "Another key must not verify the token");

    free(token);
    json_free(payload);
    jwt_key_free(key);
    jwt_key_free(other);
}

TEST(test_jwt_hs256_rejects_non_canonical_signature) {
    TEST_CASE("Only the one canonical base64url spelling of a signature verifies");

    /* Found by fuzz_jwt. The signature was decoded by a decoder that stops at
     * the first character outside its alphabet and reads the standard '+' and
     * '/' as well, so "SIG==", "SIG=anything", '+' for '-' and a last character
     * with its unused bits set all verified as the same token. Not a forgery --
     * the HMAC is the real one -- but a token that can be written any number of
     * ways defeats every check that compares tokens as strings: a revoked token
     * comes back with "==" appended. RFC 7515 §2: base64url, no padding. */
    jwt_key_t* key = test_key();
    json_doc_t* payload = jwt_create_payload(3600);
    char* token = jwt_encode(payload, key);
    TEST_ASSERT_NOT_NULL(token, "The token should be encoded");
    TEST_ASSERT_EQUAL(JWT_OK, jwt_verify(token, key), "The canonical token verifies");

    const size_t length = strlen(token);
    char* variant = malloc(length + 16);
    TEST_REQUIRE(variant != NULL, "buffer");

    snprintf(variant, length + 16, "%s==", token);
    TEST_ASSERT(jwt_verify(variant, key) != JWT_OK, "padding is refused by jwt_verify");
    jwt_t decoded = jwt_decode(variant, key);
    TEST_ASSERT(decoded.error != JWT_OK, "and by jwt_decode");
    jwt_free(&decoded);

    snprintf(variant, length + 16, "%s=anything", token);
    TEST_ASSERT(jwt_verify(variant, key) != JWT_OK, "a tail after '=' is refused");

    /* The last character of a 43-character HS256 signature carries two unused
     * bits; setting one decodes to the same bytes. */
    memcpy(variant, token, length + 1);
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const size_t v = (size_t)(strchr(alphabet, variant[length - 1]) - alphabet);
    variant[length - 1] = alphabet[v ^ 1];
    TEST_ASSERT(jwt_verify(variant, key) != JWT_OK, "set unused bits are refused");

    /* The standard alphabet's '+' and '/' in place of '-' and '_'. */
    memcpy(variant, token, length + 1);
    char* sig = strrchr(variant, '.') + 1;
    int swapped = 0;
    for (char* p = sig; *p; p++) {
        if (*p == '-') { *p = '+'; swapped = 1; }
        else if (*p == '_') { *p = '/'; swapped = 1; }
    }
    if (swapped)
        TEST_ASSERT(jwt_verify(variant, key) != JWT_OK, "the standard alphabet is refused");

    free(variant);
    free(token);
    json_free(payload);
    jwt_key_free(key);
}

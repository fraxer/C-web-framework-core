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

#ifndef __JWT__
#define __JWT__

#include <stddef.h>
#include <time.h>
#include <openssl/evp.h>

#include "json.h"

typedef enum {
    JWT_OK = 0,
    JWT_ERROR_INVALID_TOKEN,
    JWT_ERROR_INVALID_SIGNATURE,
    JWT_ERROR_INVALID_KEY,
    JWT_ERROR_ALG_MISMATCH,
    JWT_ERROR_EXPIRED,
    JWT_ERROR_MEMORY,
    JWT_ERROR_ENCODING,
    JWT_ERROR_OPENSSL
} jwt_result_t;

typedef enum {
    JWT_ALG_NONE = 0,
    // HMAC (symmetric)
    JWT_ALG_HS256,
    JWT_ALG_HS384,
    JWT_ALG_HS512,
    // RSA (asymmetric)
    JWT_ALG_RS256,
    JWT_ALG_RS384,
    JWT_ALG_RS512,
    // ECDSA (asymmetric)
    JWT_ALG_ES256,
    JWT_ALG_ES384,
    JWT_ALG_ES512,
    // EdDSA (asymmetric)
    JWT_ALG_EDDSA
} jwt_alg_t;

typedef struct jwt_key {
    jwt_alg_t alg;
    EVP_PKEY* pkey;       // For asymmetric algorithms
    char* secret;         // For HMAC algorithms
    size_t secret_len;
} jwt_key_t;

typedef struct {
    json_doc_t* header;
    json_doc_t* payload;
    jwt_result_t error;
} jwt_t;


// ============================================================================
// Key creation - HMAC
// ============================================================================

jwt_key_t* jwt_key_hs256(const char* secret, size_t len);
jwt_key_t* jwt_key_hs384(const char* secret, size_t len);
jwt_key_t* jwt_key_hs512(const char* secret, size_t len);

// ============================================================================
// Key creation - RSA (from PEM string)
// ============================================================================

jwt_key_t* jwt_key_rs256_private(const char* pem, size_t len);
jwt_key_t* jwt_key_rs256_public(const char* pem, size_t len);
jwt_key_t* jwt_key_rs384_private(const char* pem, size_t len);
jwt_key_t* jwt_key_rs384_public(const char* pem, size_t len);
jwt_key_t* jwt_key_rs512_private(const char* pem, size_t len);
jwt_key_t* jwt_key_rs512_public(const char* pem, size_t len);

// ============================================================================
// Key creation - RSA (from file)
// ============================================================================

jwt_key_t* jwt_key_rs256_private_file(const char* path);
jwt_key_t* jwt_key_rs256_public_file(const char* path);
jwt_key_t* jwt_key_rs384_private_file(const char* path);
jwt_key_t* jwt_key_rs384_public_file(const char* path);
jwt_key_t* jwt_key_rs512_private_file(const char* path);
jwt_key_t* jwt_key_rs512_public_file(const char* path);

// ============================================================================
// Key creation - ECDSA (from PEM string)
// ============================================================================

jwt_key_t* jwt_key_es256_private(const char* pem, size_t len);
jwt_key_t* jwt_key_es256_public(const char* pem, size_t len);
jwt_key_t* jwt_key_es384_private(const char* pem, size_t len);
jwt_key_t* jwt_key_es384_public(const char* pem, size_t len);
jwt_key_t* jwt_key_es512_private(const char* pem, size_t len);
jwt_key_t* jwt_key_es512_public(const char* pem, size_t len);

// ============================================================================
// Key creation - ECDSA (from file)
// ============================================================================

jwt_key_t* jwt_key_es256_private_file(const char* path);
jwt_key_t* jwt_key_es256_public_file(const char* path);
jwt_key_t* jwt_key_es384_private_file(const char* path);
jwt_key_t* jwt_key_es384_public_file(const char* path);
jwt_key_t* jwt_key_es512_private_file(const char* path);
jwt_key_t* jwt_key_es512_public_file(const char* path);

// ============================================================================
// Key creation - EdDSA (from PEM string)
// ============================================================================

jwt_key_t* jwt_key_eddsa_private(const char* pem, size_t len);
jwt_key_t* jwt_key_eddsa_public(const char* pem, size_t len);

// ============================================================================
// Key creation - EdDSA (from file)
// ============================================================================

jwt_key_t* jwt_key_eddsa_private_file(const char* path);
jwt_key_t* jwt_key_eddsa_public_file(const char* path);

// ============================================================================
// Key management
// ============================================================================

void jwt_key_free(jwt_key_t* key);

// ============================================================================
// Algorithm helpers
// ============================================================================

const char* jwt_alg_name(jwt_alg_t alg);
jwt_alg_t jwt_alg_from_name(const char* name);

// ============================================================================
// JWT encode/decode
// ============================================================================

/**
 * Encode JWT token
 *
 * @param payload JSON document with claims (iss, sub, exp, iat, etc.)
 * @param key     Key for signing (HMAC secret or private key)
 * @return        Allocated JWT string (caller must free) or NULL on error
 */
char* jwt_encode(json_doc_t* payload, const jwt_key_t* key);

/**
 * Decode and verify JWT token
 *
 * @param token   JWT token string
 * @param key     Key for verification (HMAC secret or public key)
 * @return        jwt_t structure with header, payload and error code
 *                Caller must call jwt_free() to release resources
 */
jwt_t jwt_decode(const char* token, const jwt_key_t* key);

/**
 * Verify JWT token signature without full decoding
 *
 * @param token   JWT token string
 * @param key     Key for verification (HMAC secret or public key)
 * @return        JWT_OK if valid, error code otherwise
 */
jwt_result_t jwt_verify(const char* token, const jwt_key_t* key);

/**
 * Free JWT structure resources
 */
void jwt_free(jwt_t* jwt);

/**
 * Helper: Create payload with expiration
 *
 * @param exp_seconds Seconds until expiration (from now)
 * @return            JSON document with iat and exp claims
 */
json_doc_t* jwt_create_payload(time_t exp_seconds);

#endif

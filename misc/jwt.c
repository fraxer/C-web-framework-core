#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

#include "jwt.h"
#include "base64.h"

// ============================================================================
// Algorithm name mapping
// ============================================================================

static const struct {
    jwt_alg_t alg;
    const char* name;
} alg_names[] = {
    { JWT_ALG_NONE,  "none"  },
    { JWT_ALG_HS256, "HS256" },
    { JWT_ALG_HS384, "HS384" },
    { JWT_ALG_HS512, "HS512" },
    { JWT_ALG_RS256, "RS256" },
    { JWT_ALG_RS384, "RS384" },
    { JWT_ALG_RS512, "RS512" },
    { JWT_ALG_ES256, "ES256" },
    { JWT_ALG_ES384, "ES384" },
    { JWT_ALG_ES512, "ES512" },
    { JWT_ALG_EDDSA, "EdDSA" },
};

const char* jwt_alg_name(jwt_alg_t alg) {
    for (size_t i = 0; i < sizeof(alg_names) / sizeof(alg_names[0]); i++) {
        if (alg_names[i].alg == alg) {
            return alg_names[i].name;
        }
    }
    return "none";
}

jwt_alg_t jwt_alg_from_name(const char* name) {
    if (!name) return JWT_ALG_NONE;
    for (size_t i = 0; i < sizeof(alg_names) / sizeof(alg_names[0]); i++) {
        if (strcasecmp(alg_names[i].name, name) == 0) {
            return alg_names[i].alg;
        }
    }
    return JWT_ALG_NONE;
}

// ============================================================================
// Base64URL helpers
// ============================================================================

static void base64_to_base64url(char* str) {
    char* p = str;
    char* w = str;
    while (*p) {
        if (*p == '+') {
            *w++ = '-';
        } else if (*p == '/') {
            *w++ = '_';
        } else if (*p != '=') {
            *w++ = *p;
        }
        p++;
    }
    *w = '\0';
}

static char* base64url_to_base64(const char* str) {
    size_t len = strlen(str);
    size_t padding = (4 - (len % 4)) % 4;
    char* result = malloc(len + padding + 1);
    if (!result) return NULL;

    for (size_t i = 0; i < len; i++) {
        if (str[i] == '-') {
            result[i] = '+';
        } else if (str[i] == '_') {
            result[i] = '/';
        } else {
            result[i] = str[i];
        }
    }
    for (size_t i = 0; i < padding; i++) {
        result[len + i] = '=';
    }
    result[len + padding] = '\0';
    return result;
}

// ============================================================================
// Internal: Get EVP_MD for algorithm
// ============================================================================

static const EVP_MD* get_md_for_alg(jwt_alg_t alg) {
    switch (alg) {
        case JWT_ALG_HS256:
        case JWT_ALG_RS256:
        case JWT_ALG_ES256:
            return EVP_sha256();
        case JWT_ALG_HS384:
        case JWT_ALG_RS384:
        case JWT_ALG_ES384:
            return EVP_sha384();
        case JWT_ALG_HS512:
        case JWT_ALG_RS512:
        case JWT_ALG_ES512:
            return EVP_sha512();
        case JWT_ALG_EDDSA:
        case JWT_ALG_NONE:
        default:
            return NULL;
    }
}

// ============================================================================
// Internal: ECDSA signature size
// ============================================================================

static size_t get_ecdsa_sig_size(jwt_alg_t alg) {
    switch (alg) {
        case JWT_ALG_ES256: return 64;  // 2 * 32 bytes
        case JWT_ALG_ES384: return 96;  // 2 * 48 bytes
        case JWT_ALG_ES512: return 132; // 2 * 66 bytes
        default: return 0;
    }
}

static size_t get_ecdsa_component_size(jwt_alg_t alg) {
    switch (alg) {
        case JWT_ALG_ES256: return 32;
        case JWT_ALG_ES384: return 48;
        case JWT_ALG_ES512: return 66;
        default: return 0;
    }
}

// ============================================================================
// Internal: Key creation helpers
// ============================================================================

static jwt_key_t* jwt_key_create(jwt_alg_t alg) {
    jwt_key_t* key = calloc(1, sizeof(jwt_key_t));
    if (key) {
        key->alg = alg;
    }
    return key;
}

static jwt_key_t* jwt_key_hmac(jwt_alg_t alg, const char* secret, size_t len) {
    if (!secret || len == 0) return NULL;

    jwt_key_t* key = jwt_key_create(alg);
    if (!key) return NULL;

    key->secret = malloc(len);
    if (!key->secret) {
        free(key);
        return NULL;
    }

    memcpy(key->secret, secret, len);
    key->secret_len = len;
    return key;
}

static jwt_key_t* jwt_key_pkey_private(jwt_alg_t alg, const char* pem, size_t len) {
    if (!pem) return NULL;

    BIO* bio = BIO_new_mem_buf(pem, (int)len);
    if (!bio) return NULL;

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) return NULL;

    jwt_key_t* key = jwt_key_create(alg);
    if (!key) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    key->pkey = pkey;
    return key;
}

static jwt_key_t* jwt_key_pkey_public(jwt_alg_t alg, const char* pem, size_t len) {
    if (!pem) return NULL;

    BIO* bio = BIO_new_mem_buf(pem, (int)len);
    if (!bio) return NULL;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) return NULL;

    jwt_key_t* key = jwt_key_create(alg);
    if (!key) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    key->pkey = pkey;
    return key;
}

static jwt_key_t* jwt_key_pkey_private_file(jwt_alg_t alg, const char* path) {
    if (!path) return NULL;

    FILE* fp = fopen(path, "r");
    if (!fp) return NULL;

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) return NULL;

    jwt_key_t* key = jwt_key_create(alg);
    if (!key) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    key->pkey = pkey;
    return key;
}

static jwt_key_t* jwt_key_pkey_public_file(jwt_alg_t alg, const char* path) {
    if (!path) return NULL;

    FILE* fp = fopen(path, "r");
    if (!fp) return NULL;

    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) return NULL;

    jwt_key_t* key = jwt_key_create(alg);
    if (!key) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    key->pkey = pkey;
    return key;
}

// ============================================================================
// HMAC key creation
// ============================================================================

jwt_key_t* jwt_key_hs256(const char* secret, size_t len) {
    return jwt_key_hmac(JWT_ALG_HS256, secret, len);
}

jwt_key_t* jwt_key_hs384(const char* secret, size_t len) {
    return jwt_key_hmac(JWT_ALG_HS384, secret, len);
}

jwt_key_t* jwt_key_hs512(const char* secret, size_t len) {
    return jwt_key_hmac(JWT_ALG_HS512, secret, len);
}

// ============================================================================
// RSA key creation - PEM string
// ============================================================================

jwt_key_t* jwt_key_rs256_private(const char* pem, size_t len) {
    return jwt_key_pkey_private(JWT_ALG_RS256, pem, len);
}

jwt_key_t* jwt_key_rs256_public(const char* pem, size_t len) {
    return jwt_key_pkey_public(JWT_ALG_RS256, pem, len);
}

jwt_key_t* jwt_key_rs384_private(const char* pem, size_t len) {
    return jwt_key_pkey_private(JWT_ALG_RS384, pem, len);
}

jwt_key_t* jwt_key_rs384_public(const char* pem, size_t len) {
    return jwt_key_pkey_public(JWT_ALG_RS384, pem, len);
}

jwt_key_t* jwt_key_rs512_private(const char* pem, size_t len) {
    return jwt_key_pkey_private(JWT_ALG_RS512, pem, len);
}

jwt_key_t* jwt_key_rs512_public(const char* pem, size_t len) {
    return jwt_key_pkey_public(JWT_ALG_RS512, pem, len);
}

// ============================================================================
// RSA key creation - file
// ============================================================================

jwt_key_t* jwt_key_rs256_private_file(const char* path) {
    return jwt_key_pkey_private_file(JWT_ALG_RS256, path);
}

jwt_key_t* jwt_key_rs256_public_file(const char* path) {
    return jwt_key_pkey_public_file(JWT_ALG_RS256, path);
}

jwt_key_t* jwt_key_rs384_private_file(const char* path) {
    return jwt_key_pkey_private_file(JWT_ALG_RS384, path);
}

jwt_key_t* jwt_key_rs384_public_file(const char* path) {
    return jwt_key_pkey_public_file(JWT_ALG_RS384, path);
}

jwt_key_t* jwt_key_rs512_private_file(const char* path) {
    return jwt_key_pkey_private_file(JWT_ALG_RS512, path);
}

jwt_key_t* jwt_key_rs512_public_file(const char* path) {
    return jwt_key_pkey_public_file(JWT_ALG_RS512, path);
}

// ============================================================================
// ECDSA key creation - PEM string
// ============================================================================

jwt_key_t* jwt_key_es256_private(const char* pem, size_t len) {
    return jwt_key_pkey_private(JWT_ALG_ES256, pem, len);
}

jwt_key_t* jwt_key_es256_public(const char* pem, size_t len) {
    return jwt_key_pkey_public(JWT_ALG_ES256, pem, len);
}

jwt_key_t* jwt_key_es384_private(const char* pem, size_t len) {
    return jwt_key_pkey_private(JWT_ALG_ES384, pem, len);
}

jwt_key_t* jwt_key_es384_public(const char* pem, size_t len) {
    return jwt_key_pkey_public(JWT_ALG_ES384, pem, len);
}

jwt_key_t* jwt_key_es512_private(const char* pem, size_t len) {
    return jwt_key_pkey_private(JWT_ALG_ES512, pem, len);
}

jwt_key_t* jwt_key_es512_public(const char* pem, size_t len) {
    return jwt_key_pkey_public(JWT_ALG_ES512, pem, len);
}

// ============================================================================
// ECDSA key creation - file
// ============================================================================

jwt_key_t* jwt_key_es256_private_file(const char* path) {
    return jwt_key_pkey_private_file(JWT_ALG_ES256, path);
}

jwt_key_t* jwt_key_es256_public_file(const char* path) {
    return jwt_key_pkey_public_file(JWT_ALG_ES256, path);
}

jwt_key_t* jwt_key_es384_private_file(const char* path) {
    return jwt_key_pkey_private_file(JWT_ALG_ES384, path);
}

jwt_key_t* jwt_key_es384_public_file(const char* path) {
    return jwt_key_pkey_public_file(JWT_ALG_ES384, path);
}

jwt_key_t* jwt_key_es512_private_file(const char* path) {
    return jwt_key_pkey_private_file(JWT_ALG_ES512, path);
}

jwt_key_t* jwt_key_es512_public_file(const char* path) {
    return jwt_key_pkey_public_file(JWT_ALG_ES512, path);
}

// ============================================================================
// EdDSA key creation - PEM string
// ============================================================================

jwt_key_t* jwt_key_eddsa_private(const char* pem, size_t len) {
    return jwt_key_pkey_private(JWT_ALG_EDDSA, pem, len);
}

jwt_key_t* jwt_key_eddsa_public(const char* pem, size_t len) {
    return jwt_key_pkey_public(JWT_ALG_EDDSA, pem, len);
}

// ============================================================================
// EdDSA key creation - file
// ============================================================================

jwt_key_t* jwt_key_eddsa_private_file(const char* path) {
    return jwt_key_pkey_private_file(JWT_ALG_EDDSA, path);
}

jwt_key_t* jwt_key_eddsa_public_file(const char* path) {
    return jwt_key_pkey_public_file(JWT_ALG_EDDSA, path);
}

// ============================================================================
// Key management
// ============================================================================

void jwt_key_free(jwt_key_t* key) {
    if (!key) return;

    if (key->pkey) {
        EVP_PKEY_free(key->pkey);
    }
    if (key->secret) {
        OPENSSL_cleanse(key->secret, key->secret_len);
        free(key->secret);
    }
    free(key);
}

// ============================================================================
// Internal: Signing functions
// ============================================================================

static int sign_hmac(const jwt_key_t* key, const char* data, size_t data_len,
                     unsigned char** sig, size_t* sig_len) {
    const EVP_MD* md = get_md_for_alg(key->alg);
    if (!md) return 0;

    unsigned int len = EVP_MD_size(md);
    *sig = malloc(len);
    if (!*sig) return 0;

    HMAC(md,
         key->secret, (int)key->secret_len,
         (const unsigned char*)data, data_len,
         *sig, &len);

    *sig_len = len;
    return 1;
}

static int sign_rsa(const jwt_key_t* key, const char* data, size_t data_len,
                    unsigned char** sig, size_t* sig_len) {
    const EVP_MD* md = get_md_for_alg(key->alg);
    if (!md || !key->pkey) return 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int ret = 0;

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key->pkey) != 1) {
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) {
        goto cleanup;
    }

    // Get signature length
    if (EVP_DigestSignFinal(ctx, NULL, sig_len) != 1) {
        goto cleanup;
    }

    *sig = malloc(*sig_len);
    if (!*sig) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, *sig, sig_len) != 1) {
        free(*sig);
        *sig = NULL;
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

// Convert DER-encoded ECDSA signature to fixed-size format for JWT
static int ecdsa_der_to_raw(const unsigned char* der_sig, size_t der_len,
                            unsigned char* raw_sig, size_t raw_len, size_t component_size) {
    ECDSA_SIG* ec_sig = d2i_ECDSA_SIG(NULL, &der_sig, (long)der_len);
    if (!ec_sig) return 0;

    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;
    ECDSA_SIG_get0(ec_sig, &r, &s);

    memset(raw_sig, 0, raw_len);

    // Pad r and s to component_size bytes
    int r_len = BN_num_bytes(r);
    int s_len = BN_num_bytes(s);

    if ((size_t)r_len > component_size || (size_t)s_len > component_size) {
        ECDSA_SIG_free(ec_sig);
        return 0;
    }

    BN_bn2bin(r, raw_sig + component_size - r_len);
    BN_bn2bin(s, raw_sig + component_size + component_size - s_len);

    ECDSA_SIG_free(ec_sig);
    return 1;
}

// Convert fixed-size JWT signature to DER-encoded ECDSA signature
static unsigned char* ecdsa_raw_to_der(const unsigned char* raw_sig,
                                       size_t component_size, size_t* der_len) {
    BIGNUM* r = BN_bin2bn(raw_sig, (int)component_size, NULL);
    BIGNUM* s = BN_bin2bn(raw_sig + component_size, (int)component_size, NULL);

    if (!r || !s) {
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    ECDSA_SIG* ec_sig = ECDSA_SIG_new();
    if (!ec_sig) {
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    // ECDSA_SIG_set0 takes ownership of r and s
    if (ECDSA_SIG_set0(ec_sig, r, s) != 1) {
        ECDSA_SIG_free(ec_sig);
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    int len = i2d_ECDSA_SIG(ec_sig, NULL);
    if (len <= 0) {
        ECDSA_SIG_free(ec_sig);
        return NULL;
    }

    unsigned char* der = malloc(len);
    if (!der) {
        ECDSA_SIG_free(ec_sig);
        return NULL;
    }

    unsigned char* p = der;
    *der_len = i2d_ECDSA_SIG(ec_sig, &p);

    ECDSA_SIG_free(ec_sig);
    return der;
}

static int sign_ecdsa(const jwt_key_t* key, const char* data, size_t data_len,
                      unsigned char** sig, size_t* sig_len) {
    const EVP_MD* md = get_md_for_alg(key->alg);
    if (!md || !key->pkey) return 0;

    size_t component_size = get_ecdsa_component_size(key->alg);
    size_t raw_sig_len = get_ecdsa_sig_size(key->alg);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int ret = 0;
    unsigned char* der_sig = NULL;
    size_t der_sig_len = 0;

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key->pkey) != 1) {
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) {
        goto cleanup;
    }

    // Get DER signature length
    if (EVP_DigestSignFinal(ctx, NULL, &der_sig_len) != 1) {
        goto cleanup;
    }

    der_sig = malloc(der_sig_len);
    if (!der_sig) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, der_sig, &der_sig_len) != 1) {
        goto cleanup;
    }

    // Convert DER to raw format
    *sig = malloc(raw_sig_len);
    if (!*sig) {
        goto cleanup;
    }

    if (!ecdsa_der_to_raw(der_sig, der_sig_len, *sig, raw_sig_len, component_size)) {
        free(*sig);
        *sig = NULL;
        goto cleanup;
    }

    *sig_len = raw_sig_len;
    ret = 1;

cleanup:
    free(der_sig);
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int sign_eddsa(const jwt_key_t* key, const char* data, size_t data_len,
                      unsigned char** sig, size_t* sig_len) {
    if (!key->pkey) return 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int ret = 0;

    // EdDSA uses NULL for md parameter
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key->pkey) != 1) {
        goto cleanup;
    }

    // Get signature length
    if (EVP_DigestSign(ctx, NULL, sig_len, (const unsigned char*)data, data_len) != 1) {
        goto cleanup;
    }

    *sig = malloc(*sig_len);
    if (!*sig) {
        goto cleanup;
    }

    if (EVP_DigestSign(ctx, *sig, sig_len, (const unsigned char*)data, data_len) != 1) {
        free(*sig);
        *sig = NULL;
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int jwt_sign(const jwt_key_t* key, const char* data, size_t data_len,
                    unsigned char** sig, size_t* sig_len) {
    switch (key->alg) {
        case JWT_ALG_HS256:
        case JWT_ALG_HS384:
        case JWT_ALG_HS512:
            return sign_hmac(key, data, data_len, sig, sig_len);

        case JWT_ALG_RS256:
        case JWT_ALG_RS384:
        case JWT_ALG_RS512:
            return sign_rsa(key, data, data_len, sig, sig_len);

        case JWT_ALG_ES256:
        case JWT_ALG_ES384:
        case JWT_ALG_ES512:
            return sign_ecdsa(key, data, data_len, sig, sig_len);

        case JWT_ALG_EDDSA:
            return sign_eddsa(key, data, data_len, sig, sig_len);

        case JWT_ALG_NONE:
        default:
            return 0;
    }
}

// ============================================================================
// Internal: Verification functions
// ============================================================================

static int verify_hmac(const jwt_key_t* key, const char* data, size_t data_len,
                       const unsigned char* sig, size_t sig_len) {
    unsigned char* expected_sig = NULL;
    size_t expected_len = 0;

    if (!sign_hmac(key, data, data_len, &expected_sig, &expected_len)) {
        return 0;
    }

    if (expected_len != sig_len) {
        free(expected_sig);
        return 0;
    }

    // Constant-time comparison
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < sig_len; i++) {
        diff |= expected_sig[i] ^ sig[i];
    }

    free(expected_sig);
    return diff == 0;
}

static int verify_rsa(const jwt_key_t* key, const char* data, size_t data_len,
                      const unsigned char* sig, size_t sig_len) {
    const EVP_MD* md = get_md_for_alg(key->alg);
    if (!md || !key->pkey) return 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int ret = 0;

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, key->pkey) != 1) {
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
        goto cleanup;
    }

    ret = (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1);

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int verify_ecdsa(const jwt_key_t* key, const char* data, size_t data_len,
                        const unsigned char* sig, size_t sig_len) {
    const EVP_MD* md = get_md_for_alg(key->alg);
    if (!md || !key->pkey) return 0;

    size_t component_size = get_ecdsa_component_size(key->alg);
    size_t expected_sig_len = get_ecdsa_sig_size(key->alg);

    if (sig_len != expected_sig_len) return 0;

    // Convert raw format to DER
    size_t der_len = 0;
    unsigned char* der_sig = ecdsa_raw_to_der(sig, component_size, &der_len);
    if (!der_sig) return 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(der_sig);
        return 0;
    }

    int ret = 0;

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, key->pkey) != 1) {
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
        goto cleanup;
    }

    ret = (EVP_DigestVerifyFinal(ctx, der_sig, der_len) == 1);

cleanup:
    free(der_sig);
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int verify_eddsa(const jwt_key_t* key, const char* data, size_t data_len,
                        const unsigned char* sig, size_t sig_len) {
    if (!key->pkey) return 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int ret = 0;

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key->pkey) != 1) {
        goto cleanup;
    }

    ret = (EVP_DigestVerify(ctx, sig, sig_len, (const unsigned char*)data, data_len) == 1);

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int jwt_verify(const jwt_key_t* key, const char* data, size_t data_len,
                      const unsigned char* sig, size_t sig_len) {
    switch (key->alg) {
        case JWT_ALG_HS256:
        case JWT_ALG_HS384:
        case JWT_ALG_HS512:
            return verify_hmac(key, data, data_len, sig, sig_len);

        case JWT_ALG_RS256:
        case JWT_ALG_RS384:
        case JWT_ALG_RS512:
            return verify_rsa(key, data, data_len, sig, sig_len);

        case JWT_ALG_ES256:
        case JWT_ALG_ES384:
        case JWT_ALG_ES512:
            return verify_ecdsa(key, data, data_len, sig, sig_len);

        case JWT_ALG_EDDSA:
            return verify_eddsa(key, data, data_len, sig, sig_len);

        case JWT_ALG_NONE:
        default:
            return 0;
    }
}

// ============================================================================
// JWT encode
// ============================================================================

char* jwt_encode(json_doc_t* payload, const jwt_key_t* key) {
    if (!payload || !key) {
        return NULL;
    }

    if (key->alg == JWT_ALG_NONE) {
        return NULL;
    }

    // Validate key
    switch (key->alg) {
        case JWT_ALG_HS256:
        case JWT_ALG_HS384:
        case JWT_ALG_HS512:
            if (!key->secret || key->secret_len == 0) return NULL;
            break;
        default:
            if (!key->pkey) return NULL;
            break;
    }

    // Auto-add iat (issued at) and exp (expiration) if not present
    json_token_t* payload_root = json_root(payload);
    time_t now = time(NULL);
    if (!json_object_get(payload_root, "iat")) {
        json_object_set(payload_root, "iat", json_create_number((long double)now));
    }
    if (!json_object_get(payload_root, "exp")) {
        json_object_set(payload_root, "exp", json_create_number((long double)(now + 3600))); // 1 hour default
    }

    // Create header
    json_doc_t* header = json_root_create_object();
    if (!header) {
        return NULL;
    }

    json_token_t* root = json_root(header);
    json_object_set(root, "alg", json_create_string(jwt_alg_name(key->alg)));
    json_object_set(root, "typ", json_create_string("JWT"));

    // Stringify header and payload
    const char* header_str = json_stringify(header);
    const char* payload_str = json_stringify(payload);

    if (!header_str || !payload_str) {
        json_free(header);
        return NULL;
    }

    size_t header_len = json_stringify_size(header);
    size_t payload_len = json_stringify_size(payload);

    // Base64URL encode header
    int header_b64_len = base64_encode_len((int)header_len);
    char* header_b64 = malloc(header_b64_len);
    if (!header_b64) {
        json_free(header);
        return NULL;
    }
    base64_encode(header_b64, header_str, (int)header_len);
    base64_to_base64url(header_b64);

    // Base64URL encode payload
    int payload_b64_len = base64_encode_len((int)payload_len);
    char* payload_b64 = malloc(payload_b64_len);
    if (!payload_b64) {
        free(header_b64);
        json_free(header);
        return NULL;
    }
    base64_encode(payload_b64, payload_str, (int)payload_len);
    base64_to_base64url(payload_b64);

    // Create signing input: header.payload
    size_t header_b64_actual = strlen(header_b64);
    size_t payload_b64_actual = strlen(payload_b64);
    size_t signing_input_len = header_b64_actual + 1 + payload_b64_actual;
    char* signing_input = malloc(signing_input_len + 1);
    if (!signing_input) {
        free(payload_b64);
        free(header_b64);
        json_free(header);
        return NULL;
    }

    memcpy(signing_input, header_b64, header_b64_actual);
    signing_input[header_b64_actual] = '.';
    memcpy(signing_input + header_b64_actual + 1, payload_b64, payload_b64_actual);
    signing_input[signing_input_len] = '\0';

    // Sign
    unsigned char* signature = NULL;
    size_t signature_len = 0;

    if (!jwt_sign(key, signing_input, signing_input_len, &signature, &signature_len)) {
        free(signing_input);
        free(payload_b64);
        free(header_b64);
        json_free(header);
        return NULL;
    }

    // Base64URL encode signature
    int signature_b64_len = base64_encode_len((int)signature_len);
    char* signature_b64 = malloc(signature_b64_len);
    if (!signature_b64) {
        free(signature);
        free(signing_input);
        free(payload_b64);
        free(header_b64);
        json_free(header);
        return NULL;
    }
    base64_encode(signature_b64, (const char*)signature, (int)signature_len);
    base64_to_base64url(signature_b64);
    free(signature);

    // Build final JWT: header.payload.signature
    size_t signature_b64_actual = strlen(signature_b64);
    size_t jwt_len = signing_input_len + 1 + signature_b64_actual;
    char* jwt = malloc(jwt_len + 1);
    if (!jwt) {
        free(signature_b64);
        free(signing_input);
        free(payload_b64);
        free(header_b64);
        json_free(header);
        return NULL;
    }

    memcpy(jwt, signing_input, signing_input_len);
    jwt[signing_input_len] = '.';
    memcpy(jwt + signing_input_len + 1, signature_b64, signature_b64_actual);
    jwt[jwt_len] = '\0';

    // Cleanup
    free(signature_b64);
    free(signing_input);
    free(payload_b64);
    free(header_b64);
    json_free(header);

    return jwt;
}

// ============================================================================
// JWT decode
// ============================================================================

jwt_t jwt_decode(const char* token, const jwt_key_t* key) {
    jwt_t result = {0};
    result.header = NULL;
    result.payload = NULL;
    result.error = JWT_OK;

    if (!token || !key) {
        result.error = JWT_ERROR_INVALID_TOKEN;
        return result;
    }

    // Find the two dots separating header.payload.signature
    const char* first_dot = strchr(token, '.');
    if (!first_dot) {
        result.error = JWT_ERROR_INVALID_TOKEN;
        return result;
    }

    const char* second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) {
        result.error = JWT_ERROR_INVALID_TOKEN;
        return result;
    }

    // Extract parts
    size_t header_b64_len = first_dot - token;
    size_t payload_b64_len = second_dot - first_dot - 1;
    size_t signature_b64_len = strlen(second_dot + 1);

    // Decode header first to check algorithm
    char* header_b64 = malloc(header_b64_len + 1);
    if (!header_b64) {
        result.error = JWT_ERROR_MEMORY;
        return result;
    }
    memcpy(header_b64, token, header_b64_len);
    header_b64[header_b64_len] = '\0';

    char* header_std_b64 = base64url_to_base64(header_b64);
    free(header_b64);
    if (!header_std_b64) {
        result.error = JWT_ERROR_MEMORY;
        return result;
    }

    int header_decoded_len = base64_decode_len(header_std_b64);
    char* header_json = malloc(header_decoded_len + 1);
    if (!header_json) {
        free(header_std_b64);
        result.error = JWT_ERROR_MEMORY;
        return result;
    }
    base64_decode(header_json, header_std_b64);
    header_json[header_decoded_len] = '\0';
    free(header_std_b64);

    result.header = json_parse(header_json);
    free(header_json);

    if (!result.header) {
        result.error = JWT_ERROR_INVALID_TOKEN;
        return result;
    }

    // Check algorithm matches
    json_token_t* header_root = json_root(result.header);
    json_token_t* alg_token = json_object_get(header_root, "alg");
    if (!alg_token || !json_is_string(alg_token)) {
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_INVALID_TOKEN;
        return result;
    }

    const char* alg_str = json_string(alg_token);
    jwt_alg_t token_alg = jwt_alg_from_name(alg_str);

    if (token_alg != key->alg) {
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_ALG_MISMATCH;
        return result;
    }

    // Verify signature
    size_t signing_input_len = header_b64_len + 1 + payload_b64_len;
    char* signing_input = malloc(signing_input_len + 1);
    if (!signing_input) {
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_MEMORY;
        return result;
    }
    memcpy(signing_input, token, signing_input_len);
    signing_input[signing_input_len] = '\0';

    // Decode provided signature
    char* sig_b64 = malloc(signature_b64_len + 1);
    if (!sig_b64) {
        free(signing_input);
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_MEMORY;
        return result;
    }
    memcpy(sig_b64, second_dot + 1, signature_b64_len);
    sig_b64[signature_b64_len] = '\0';

    char* sig_std_b64 = base64url_to_base64(sig_b64);
    free(sig_b64);
    if (!sig_std_b64) {
        free(signing_input);
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_MEMORY;
        return result;
    }

    int sig_decoded_len = base64_decode_len(sig_std_b64);
    unsigned char* provided_sig = malloc(sig_decoded_len);
    if (!provided_sig) {
        free(sig_std_b64);
        free(signing_input);
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_MEMORY;
        return result;
    }
    int actual_sig_len = base64_decode((char*)provided_sig, sig_std_b64);
    free(sig_std_b64);

    // Verify
    int sig_valid = jwt_verify(key, signing_input, signing_input_len,
                               provided_sig, (size_t)actual_sig_len);

    free(provided_sig);
    free(signing_input);

    if (!sig_valid) {
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_INVALID_SIGNATURE;
        return result;
    }

    // Decode payload
    char* payload_b64 = malloc(payload_b64_len + 1);
    if (!payload_b64) {
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_MEMORY;
        return result;
    }
    memcpy(payload_b64, first_dot + 1, payload_b64_len);
    payload_b64[payload_b64_len] = '\0';

    char* payload_std_b64 = base64url_to_base64(payload_b64);
    free(payload_b64);
    if (!payload_std_b64) {
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_MEMORY;
        return result;
    }

    int payload_decoded_len = base64_decode_len(payload_std_b64);
    char* payload_json = malloc(payload_decoded_len + 1);
    if (!payload_json) {
        free(payload_std_b64);
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_MEMORY;
        return result;
    }
    base64_decode(payload_json, payload_std_b64);
    payload_json[payload_decoded_len] = '\0';
    free(payload_std_b64);

    result.payload = json_parse(payload_json);
    free(payload_json);

    if (!result.payload) {
        json_free(result.header);
        result.header = NULL;
        result.error = JWT_ERROR_INVALID_TOKEN;
        return result;
    }

    // Check expiration
    json_token_t* payload_root = json_root(result.payload);
    json_token_t* exp_token = json_object_get(payload_root, "exp");
    if (exp_token && json_is_number(exp_token)) {
        int ok = 0;
        long long exp_time = json_llong(exp_token, &ok);
        if (ok && exp_time < (long long)time(NULL)) {
            result.error = JWT_ERROR_EXPIRED;
            return result;
        }
    }

    return result;
}

// ============================================================================
// JWT free and helpers
// ============================================================================

void jwt_free(jwt_t* jwt) {
    if (!jwt) {
        return;
    }

    if (jwt->header) {
        json_free(jwt->header);
        jwt->header = NULL;
    }

    if (jwt->payload) {
        json_free(jwt->payload);
        jwt->payload = NULL;
    }
}

json_doc_t* jwt_create_payload(time_t exp_seconds) {
    json_doc_t* doc = json_root_create_object();
    if (!doc) {
        return NULL;
    }

    time_t now = time(NULL);
    json_token_t* root = json_root(doc);

    json_object_set(root, "iat", json_create_number((long double)now));
    json_object_set(root, "exp", json_create_number((long double)(now + exp_seconds)));

    return doc;
}

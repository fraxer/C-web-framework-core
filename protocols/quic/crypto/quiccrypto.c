#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/ssl.h>
#include <string.h>

#include "quiccrypto.h"

/* RFC 9001 §5.2: the salt is version-specific and fixed for QUIC v1. Kept in a
 * named constant rather than inline because QUIC v2 (RFC 9369) differs only in
 * this value and the labels. */
static const uint8_t QUIC_V1_INITIAL_SALT[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

/* §6.6 confidentiality and integrity limits. */
#define QUIC_AES_SEAL_LIMIT      (1ULL << 23)
#define QUIC_AES_OPEN_LIMIT      (1ULL << 52)
#define QUIC_CHACHA_SEAL_LIMIT   UINT64_MAX
#define QUIC_CHACHA_OPEN_LIMIT   (1ULL << 36)

quic_aead_e quiccrypto_suite_of(const SSL_CIPHER* cipher) {
    if (cipher == NULL) return QUIC_AEAD_UNSUPPORTED;

    /* SSL_CIPHER_get_id returns the IANA suite number in its low two bytes. */
    const uint32_t id = (uint32_t)(SSL_CIPHER_get_id(cipher) & 0xffff);

    switch (id) {
    case 0x1301: return QUIC_AEAD_AES_128_GCM;
    case 0x1302: return QUIC_AEAD_AES_256_GCM;
    case 0x1303: return QUIC_AEAD_CHACHA20_POLY1305;
    default:     return QUIC_AEAD_UNSUPPORTED;
    }
}

const EVP_MD* quiccrypto_md(quic_aead_e suite) {
    switch (suite) {
    case QUIC_AEAD_AES_256_GCM: return EVP_sha384();
    case QUIC_AEAD_AES_128_GCM:
    case QUIC_AEAD_CHACHA20_POLY1305: return EVP_sha256();
    default: return NULL;
    }
}

size_t quiccrypto_key_len(quic_aead_e suite) {
    switch (suite) {
    case QUIC_AEAD_AES_128_GCM: return 16;
    case QUIC_AEAD_AES_256_GCM:
    case QUIC_AEAD_CHACHA20_POLY1305: return 32;
    default: return 0;
    }
}

static const EVP_CIPHER* __aead_cipher(quic_aead_e suite) {
    switch (suite) {
    case QUIC_AEAD_AES_128_GCM: return EVP_aes_128_gcm();
    case QUIC_AEAD_AES_256_GCM: return EVP_aes_256_gcm();
    case QUIC_AEAD_CHACHA20_POLY1305: return EVP_chacha20_poly1305();
    default: return NULL;
    }
}

/* Header protection uses a different primitive from the AEAD: a raw block
 * cipher, because the mask is one block of keystream and nothing more. */
static const EVP_CIPHER* __hp_cipher(quic_aead_e suite) {
    switch (suite) {
    case QUIC_AEAD_AES_128_GCM: return EVP_aes_128_ecb();
    case QUIC_AEAD_AES_256_GCM: return EVP_aes_256_ecb();
    case QUIC_AEAD_CHACHA20_POLY1305: return EVP_chacha20();
    default: return NULL;
    }
}

int quic_hkdf_expand_label(const EVP_MD* md,
                           const uint8_t* secret, size_t secret_len,
                           const char* label,
                           const uint8_t* context, size_t context_len,
                           uint8_t* out, size_t out_len) {
    if (md == NULL || secret == NULL || label == NULL || out == NULL) return 0;
    if (out_len == 0 || out_len > 0xffff) return 0;

    const size_t label_len = strlen(label);
    /* "tls13 " + label must fit the one-byte length that precedes it. */
    if (label_len + 6 > 255 || context_len > 255) return 0;

    /* struct HkdfLabel { uint16 length; opaque label<7..255>; opaque context<0..255>; } */
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t n = 0;

    info[n++] = (uint8_t)(out_len >> 8);
    info[n++] = (uint8_t)(out_len);
    info[n++] = (uint8_t)(label_len + 6);
    memcpy(info + n, "tls13 ", 6);
    n += 6;
    memcpy(info + n, label, label_len);
    n += label_len;
    info[n++] = (uint8_t)context_len;
    if (context_len > 0) {
        memcpy(info + n, context, context_len);
        n += context_len;
    }

    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) return 0;

    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) return 0;

    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int("mode", &mode),
        OSSL_PARAM_construct_utf8_string("digest", (char*)EVP_MD_get0_name(md), 0),
        OSSL_PARAM_construct_octet_string("key", (void*)secret, secret_len),
        OSSL_PARAM_construct_octet_string("info", info, n),
        OSSL_PARAM_construct_end()
    };

    const int ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;

    EVP_KDF_CTX_free(ctx);

    return ok;
}

/* HKDF-Extract, the other half of the schedule. Only Initial needs it: every
 * later secret comes from TLS already extracted. */
static int __hkdf_extract(const EVP_MD* md,
                          const uint8_t* salt, size_t salt_len,
                          const uint8_t* ikm, size_t ikm_len,
                          uint8_t* out, size_t out_len) {
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) return 0;

    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) return 0;

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int("mode", &mode),
        OSSL_PARAM_construct_utf8_string("digest", (char*)EVP_MD_get0_name(md), 0),
        OSSL_PARAM_construct_octet_string("key", (void*)ikm, ikm_len),
        OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len),
        OSSL_PARAM_construct_end()
    };

    const int ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;

    EVP_KDF_CTX_free(ctx);

    return ok;
}

int quiccrypto_initial_secrets(const quiccid_t* dcid,
                               uint8_t client_secret[32],
                               uint8_t server_secret[32]) {
    if (dcid == NULL) return 0;

    uint8_t initial_secret[32];

    /* §5.2. Initial keys are always SHA-256 and AES-128-GCM, whatever the
     * handshake later negotiates -- neither side knows the suite yet. */
    if (!__hkdf_extract(EVP_sha256(), QUIC_V1_INITIAL_SALT, sizeof QUIC_V1_INITIAL_SALT,
                        dcid->data, dcid->len, initial_secret, sizeof initial_secret))
        return 0;

    int ok = quic_hkdf_expand_label(EVP_sha256(), initial_secret, sizeof initial_secret,
                                    "client in", NULL, 0, client_secret, 32) &&
             quic_hkdf_expand_label(EVP_sha256(), initial_secret, sizeof initial_secret,
                                    "server in", NULL, 0, server_secret, 32);

    explicit_bzero(initial_secret, sizeof initial_secret);

    return ok;
}

int quickeys_install(quickeys_t* keys, quic_aead_e suite,
                     const uint8_t* secret, size_t secret_len) {
    if (keys == NULL || secret == NULL) return 0;

    const EVP_MD* md = quiccrypto_md(suite);
    const size_t key_len = quiccrypto_key_len(suite);
    const EVP_CIPHER* aead = __aead_cipher(suite);
    const EVP_CIPHER* hp = __hp_cipher(suite);
    if (md == NULL || key_len == 0 || aead == NULL || hp == NULL) return 0;

    uint8_t key[32];
    int ok = 1;

    ok = ok && quic_hkdf_expand_label(md, secret, secret_len, "quic key", NULL, 0,
                                      key, key_len);
    ok = ok && quic_hkdf_expand_label(md, secret, secret_len, "quic iv", NULL, 0,
                                      keys->iv, sizeof keys->iv);
    ok = ok && quic_hkdf_expand_label(md, secret, secret_len, "quic hp", NULL, 0,
                                      keys->hp_key, key_len);

    if (!ok) {
        explicit_bzero(key, sizeof key);
        return 0;
    }

    keys->hp_key_len = key_len;
    keys->suite = suite;
    keys->sealed = 0;
    keys->open_failures = 0;

    /* Kept for quickeys_next. A secret longer than the buffer would mean a hash
     * this build does not support, so it is refused rather than truncated. */
    if (secret_len > sizeof keys->secret) {
        explicit_bzero(key, sizeof key);
        return 0;
    }

    memcpy(keys->secret, secret, secret_len);
    keys->secret_len = secret_len;

    /* Both contexts are keyed once here and reused for every packet: only the
     * nonce changes. Recreating an EVP_CIPHER_CTX per packet costs several
     * times the cost of the encryption itself at QUIC's packet sizes, and this
     * runs on every packet in both directions. */
    EVP_CIPHER_CTX_free(keys->aead);
    EVP_CIPHER_CTX_free(keys->hp);

    keys->aead = EVP_CIPHER_CTX_new();
    keys->hp = EVP_CIPHER_CTX_new();
    if (keys->aead == NULL || keys->hp == NULL) goto failed;

    /* Key now, nonce later: EVP allows the two to be set in separate calls, and
     * that is what makes the per-packet path cheap. */
    if (EVP_CipherInit_ex(keys->aead, aead, NULL, NULL, NULL, -1) != 1) goto failed;
    if (EVP_CIPHER_CTX_ctrl(keys->aead, EVP_CTRL_AEAD_SET_IVLEN,
                            (int)sizeof keys->iv, NULL) != 1) goto failed;
    if (EVP_CipherInit_ex(keys->aead, NULL, NULL, key, NULL, -1) != 1) goto failed;

    /* ChaCha20 takes its 16-byte counter+nonce at use time, so only AES-ECB can
     * be keyed here; for ChaCha the key is kept and applied in quichp. */
    if (suite != QUIC_AEAD_CHACHA20_POLY1305)
        if (EVP_EncryptInit_ex(keys->hp, hp, NULL, keys->hp_key, NULL) != 1) goto failed;

    explicit_bzero(key, sizeof key);
    keys->valid = 1;

    return 1;

    failed:

    explicit_bzero(key, sizeof key);
    quickeys_free(keys);

    return 0;
}

int quiccrypto_next_secret(quic_aead_e suite,
                           const uint8_t* secret, size_t secret_len,
                           uint8_t* out) {
    const EVP_MD* md = quiccrypto_md(suite);
    if (md == NULL) return 0;

    /* §6.1: the next generation's secret, derived ahead of time so a key update
     * costs no key schedule work on the packet path. */
    return quic_hkdf_expand_label(md, secret, secret_len, "quic ku", NULL, 0,
                                  out, secret_len);
}

int quickeys_next(quickeys_t* into, const quickeys_t* from) {
    if (into == NULL || from == NULL || !from->valid || from->secret_len == 0)
        return 0;

    const EVP_MD* md = quiccrypto_md(from->suite);
    const EVP_CIPHER* aead = __aead_cipher(from->suite);
    const size_t key_len = quiccrypto_key_len(from->suite);
    if (md == NULL || aead == NULL || key_len == 0) return 0;

    uint8_t secret[sizeof from->secret];
    uint8_t key[32];
    uint8_t iv[12];

    int ok = quiccrypto_next_secret(from->suite, from->secret, from->secret_len, secret);

    ok = ok && quic_hkdf_expand_label(md, secret, from->secret_len, "quic key", NULL, 0,
                                      key, key_len);
    ok = ok && quic_hkdf_expand_label(md, secret, from->secret_len, "quic iv", NULL, 0,
                                      iv, sizeof iv);

    /* The AEAD context is built before anything in `into` is touched, so a
     * failure here leaves the caller's current keys usable. That matters more
     * than usual: `into` may be the live receive keys. */
    EVP_CIPHER_CTX* ctx = ok ? EVP_CIPHER_CTX_new() : NULL;

    ok = ok && ctx != NULL;
    ok = ok && EVP_CipherInit_ex(ctx, aead, NULL, NULL, NULL, -1) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof iv, NULL) == 1;
    ok = ok && EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, -1) == 1;

    if (!ok) {
        EVP_CIPHER_CTX_free(ctx);
        explicit_bzero(secret, sizeof secret);
        explicit_bzero(key, sizeof key);
        return 0;
    }

    /* Header protection carries over untouched -- §5.4, and the reason this
     * function exists. When into == from that is automatic; when it is a
     * different object the material is copied, including the keyed ChaCha
     * context's key, which quichp applies per packet. */
    if (into != from) {
        /* Rebuilt from from->hp_key the same way quickeys_install does, rather
         * than copied with EVP_CIPHER_CTX_copy: for ChaCha20 the header
         * protection context is deliberately left unkeyed (quichp applies the
         * key per packet), and copying a context that was never initialised is
         * not something to rely on. */
        const EVP_CIPHER* hp = __hp_cipher(from->suite);
        EVP_CIPHER_CTX* hp_ctx = hp != NULL ? EVP_CIPHER_CTX_new() : NULL;

        int hp_ok = hp_ctx != NULL;
        if (hp_ok && from->suite != QUIC_AEAD_CHACHA20_POLY1305)
            hp_ok = EVP_EncryptInit_ex(hp_ctx, hp, NULL, from->hp_key, NULL) == 1;

        if (!hp_ok) {
            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_CTX_free(hp_ctx);
            explicit_bzero(secret, sizeof secret);
            explicit_bzero(key, sizeof key);
            return 0;
        }

        EVP_CIPHER_CTX_free(into->aead);
        EVP_CIPHER_CTX_free(into->hp);
        into->hp = hp_ctx;

        memcpy(into->hp_key, from->hp_key, sizeof into->hp_key);
        into->hp_key_len = from->hp_key_len;
        into->suite = from->suite;
    }
    else
        EVP_CIPHER_CTX_free(into->aead);

    into->aead = ctx;
    memcpy(into->iv, iv, sizeof iv);
    memcpy(into->secret, secret, from->secret_len);
    into->secret_len = from->secret_len;
    into->sealed = 0;
    into->open_failures = 0;
    into->valid = 1;

    explicit_bzero(secret, sizeof secret);
    explicit_bzero(key, sizeof key);

    return 1;
}

void quickeys_free(quickeys_t* keys) {
    if (keys == NULL) return;

    EVP_CIPHER_CTX_free(keys->aead);
    EVP_CIPHER_CTX_free(keys->hp);
    keys->aead = NULL;
    keys->hp = NULL;

    explicit_bzero(keys->iv, sizeof keys->iv);
    explicit_bzero(keys->hp_key, sizeof keys->hp_key);
    explicit_bzero(keys->secret, sizeof keys->secret);
    keys->secret_len = 0;
    keys->valid = 0;
}

/* §5.3: nonce = iv XOR the packet number, right-aligned in the 12 bytes. */
static void __nonce(const uint8_t iv[12], uint64_t pn, uint8_t out[12]) {
    memcpy(out, iv, 12);

    for (int i = 0; i < 8; i++)
        out[11 - i] ^= (uint8_t)(pn >> (8 * i));
}

int quiccrypto_seal(quickeys_t* keys, uint64_t pn,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* pt, size_t pt_len,
                    uint8_t* out, size_t* out_len) {
    if (keys == NULL || !keys->valid || out == NULL) return 0;

    uint8_t nonce[12];
    __nonce(keys->iv, pn, nonce);

    int len = 0;
    int total = 0;

    if (EVP_EncryptInit_ex(keys->aead, NULL, NULL, NULL, nonce) != 1) return 0;

    if (aad_len > 0)
        if (EVP_EncryptUpdate(keys->aead, NULL, &len, aad, (int)aad_len) != 1) return 0;

    if (pt_len > 0) {
        if (EVP_EncryptUpdate(keys->aead, out, &len, pt, (int)pt_len) != 1) return 0;
        total = len;
    }

    if (EVP_EncryptFinal_ex(keys->aead, out + total, &len) != 1) return 0;
    total += len;

    if (EVP_CIPHER_CTX_ctrl(keys->aead, EVP_CTRL_AEAD_GET_TAG,
                            QUIC_AEAD_TAG_LEN, out + total) != 1) return 0;

    if (out_len != NULL) *out_len = (size_t)total + QUIC_AEAD_TAG_LEN;

    keys->sealed++;

    return 1;
}

int quiccrypto_open(quickeys_t* keys, uint64_t pn,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* ct, size_t ct_len,
                    uint8_t* out, size_t* out_len) {
    if (keys == NULL || !keys->valid || out == NULL) return 0;
    if (ct_len < QUIC_AEAD_TAG_LEN) return 0;

    const size_t body_len = ct_len - QUIC_AEAD_TAG_LEN;

    uint8_t nonce[12];
    __nonce(keys->iv, pn, nonce);

    int len = 0;
    int total = 0;
    int ok = 1;

    ok = ok && EVP_DecryptInit_ex(keys->aead, NULL, NULL, NULL, nonce) == 1;

    if (ok && aad_len > 0)
        ok = EVP_DecryptUpdate(keys->aead, NULL, &len, aad, (int)aad_len) == 1;

    if (ok && body_len > 0) {
        ok = EVP_DecryptUpdate(keys->aead, out, &len, ct, (int)body_len) == 1;
        total = len;
    }

    ok = ok && EVP_CIPHER_CTX_ctrl(keys->aead, EVP_CTRL_AEAD_SET_TAG,
                                   QUIC_AEAD_TAG_LEN,
                                   (void*)(ct + body_len)) == 1;

    /* This is the authentication check: a wrong tag fails here and nowhere
     * else. */
    ok = ok && EVP_DecryptFinal_ex(keys->aead, out + total, &len) == 1;

    if (!ok) {
        /* Ordinary, not exceptional: a stray packet from a closed connection or
         * one that crossed a key update fails here. The caller drops it and
         * counts it, and only the §6.6 limit turns that into an error. */
        keys->open_failures++;
        return 0;
    }

    total += len;
    if (out_len != NULL) *out_len = (size_t)total;

    return 1;
}

int quiccrypto_seal_limit_reached(const quickeys_t* keys) {
    if (keys == NULL) return 0;

    const uint64_t limit = keys->suite == QUIC_AEAD_CHACHA20_POLY1305
                           ? QUIC_CHACHA_SEAL_LIMIT : QUIC_AES_SEAL_LIMIT;

    return keys->sealed >= limit;
}

int quiccrypto_open_limit_reached(const quickeys_t* keys) {
    if (keys == NULL) return 0;

    const uint64_t limit = keys->suite == QUIC_AEAD_CHACHA20_POLY1305
                           ? QUIC_CHACHA_OPEN_LIMIT : QUIC_AES_OPEN_LIMIT;

    return keys->open_failures >= limit;
}

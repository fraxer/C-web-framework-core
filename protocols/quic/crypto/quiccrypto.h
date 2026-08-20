#ifndef __QUICCRYPTO__
#define __QUICCRYPTO__

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>

#include "quic.h"
#include "quicversion.h"

/* QUIC packet protection (RFC 9001 §5).
 *
 * This is where the line between "library" and "our code" runs. OpenSSL gives
 * us the TLS 1.3 handshake and the primitives -- AES-GCM, ChaCha20-Poly1305,
 * HKDF; everything that turns a per-level secret into a protected packet is
 * here: the key schedule, the nonce construction, the AEAD framing and the
 * header protection.
 *
 * Two protections are applied to every packet, in this order on the way out and
 * the reverse on the way in:
 *
 *   1. AEAD over the payload, with the *unprotected* header as additional data;
 *   2. header protection over the packet number and the low bits of the first
 *      byte, keyed separately and sampled from the ciphertext.
 *
 * The order is not a choice. Header protection samples bytes of the AEAD
 * output, so it cannot be applied before the AEAD has run; and on receive the
 * packet number is unreadable -- it is under the header protection -- until the
 * mask is removed, yet the AEAD needs it to build the nonce. Getting this
 * backwards produces a stack that talks only to itself. */

/* Suites we implement. CCM is deliberately absent: RFC 9001 §5.3 forbids
 * TLS_AES_128_CCM_8_SHA256 in QUIC outright (its 64-bit tag is too short for
 * the integrity limits), and plain CCM is rare enough that supporting it would
 * be untested code on a security path. quictls restricts the ciphersuite list
 * accordingly, so a suite outside this set never reaches us. */
typedef enum {
    QUIC_AEAD_AES_128_GCM = 0,
    QUIC_AEAD_AES_256_GCM,
    QUIC_AEAD_CHACHA20_POLY1305,
    QUIC_AEAD_UNSUPPORTED
} quic_aead_e;

/* Keys for one direction at one encryption level. */
typedef struct quickeys {
    EVP_CIPHER_CTX* aead;      /* keyed once; only the nonce changes per packet */
    EVP_CIPHER_CTX* hp;        /* header protection: AES-ECB or ChaCha20 */
    uint8_t  iv[12];
    uint8_t  hp_key[32];
    size_t   hp_key_len;
    quic_aead_e suite;
    int      valid;

    /* Which version's labels derived this key set. Kept so that a key update
     * does not have to be told again -- quickeys_next derives from `from`, and
     * asking the caller for a version it has already given once is one more
     * place to give a different answer. */
    const quicversion_t* ver;

    /* The secret these keys came from, kept so a key update can derive the next
     * generation from it (§6.1).48 bytes covers SHA-384, the largest hash any
     * suite here uses. Zeroed by quickeys_free like the rest of the material. */
    uint8_t  secret[48];
    size_t   secret_len;

    /* Packets sealed with this key, against the confidentiality limit of §6.6:
     * 2^23 for AES-GCM, effectively unbounded for ChaCha20-Poly1305. Exceeding
     * it requires a key update rather than being merely inadvisable. */
    uint64_t sealed;
    /* Packets that failed to open. §6.6 caps this too (2^52 for AES-GCM, 2^36
     * for ChaCha20-Poly1305): an attacker who could forge one packet in that
     * many would be able to, so the connection must close first. */
    uint64_t open_failures;
} quickeys_t;

/* Which TLS suite OpenSSL negotiated, from SSL_get_current_cipher. */
quic_aead_e quiccrypto_suite_of(const SSL_CIPHER* cipher);

/* Hash and key sizes of a suite. */
const EVP_MD* quiccrypto_md(quic_aead_e suite);
size_t quiccrypto_key_len(quic_aead_e suite);

/* HKDF-Expand-Label (RFC 8446 §7.1) with QUIC's labels.
 *
 * `label` is given without the "tls13 " prefix this adds -- so "quic key",
 * not "tls13 quic key". Returns 1 on success. */
int quic_hkdf_expand_label(const EVP_MD* md,
                           const uint8_t* secret, size_t secret_len,
                           const char* label,
                           const uint8_t* context, size_t context_len,
                           uint8_t* out, size_t out_len);

/* Derive the Initial secrets (§5.2) from the Destination Connection ID of the
 * client's first Initial packet -- the only key material both sides can compute
 * before any handshake has happened, which is exactly why Initial packets are
 * authenticated but not confidential.
 *
 * After a Retry the input is the connection id from the *second* Initial, i.e.
 * the Source Connection ID we put in the Retry.
 *
 * Both outputs are 32 bytes (Initial is always SHA-256 / AES-128-GCM). */
int quiccrypto_initial_secrets(const quicversion_t* ver, const quiccid_t* dcid,
                               uint8_t client_secret[32],
                               uint8_t server_secret[32]);

/* Turn a level secret into a usable key set: key, iv and hp key (§5.1).
 *
 * The version decides the three labels. It is a parameter and not a constant
 * because that is the whole of QUIC v2's difference here (RFC 9369 §3.1), and
 * because getting it wrong is silent: the keys derive perfectly well and
 * nothing the peer sends will ever open. */
int quickeys_install(const quicversion_t* ver, quickeys_t* keys, quic_aead_e suite,
                     const uint8_t* secret, size_t secret_len);

/* Derive the next generation's secret for a key update (§6): the version's key
 * update label ("quic ku", "quicv2 ku") applied to the current secret. */
int quiccrypto_next_secret(const quicversion_t* ver, quic_aead_e suite,
                           const uint8_t* secret, size_t secret_len,
                           uint8_t* out);

/* Install the next generation of `from` into `into` -- a key update (§6).
 *
 * Not quickeys_install with the next secret, and the difference is the whole
 * point: §5.4 says the header protection key does **not** change on a key
 * update, so `into` keeps the header protection of `from` while its AEAD key
 * and IV move on. Re-deriving "quic hp" from the new secret would produce a
 * key the peer never computes, and every packet after the update would fail to
 * unprotect -- a failure that looks like the AEAD, three layers away.
 *
 * `into` and `from` may be the same object. Returns 0 on failure, leaving
 * `into` untouched. */
int quickeys_next(quickeys_t* into, const quickeys_t* from);

void quickeys_free(quickeys_t* keys);

/* AEAD-protect a payload. `aad` is the packet header as it stands before header
 * protection, packet number included. `out` needs pt_len + 16 bytes. */
int quiccrypto_seal(quickeys_t* keys, uint64_t pn,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* pt, size_t pt_len,
                    uint8_t* out, size_t* out_len);

/* The inverse. A failure here is ordinary -- a stray packet from a dead
 * connection, or one that arrived after a key update -- so the caller counts it
 * and drops the packet rather than closing the connection, up to the §6.6
 * limit. */
int quiccrypto_open(quickeys_t* keys, uint64_t pn,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* ct, size_t ct_len,
                    uint8_t* out, size_t* out_len);

/* 1 when this key has sealed enough packets that §6.6 requires a key update. */
int quiccrypto_seal_limit_reached(const quickeys_t* keys);
/* 1 when the failed-decryption count has passed the §6.6 limit and the
 * connection must close with AEAD_LIMIT_REACHED. */
int quiccrypto_open_limit_reached(const quickeys_t* keys);

#define QUIC_AEAD_TAG_LEN 16

#endif

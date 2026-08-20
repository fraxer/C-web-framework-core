#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#include "quicretry.h"

/* The Retry key and nonce are published in the RFC and differ per version
 * (RFC 9001 §5.8, RFC 9369 §3.3). Their being public is the point -- the tag
 * proves the sender saw the original connection id, not that it holds a
 * secret -- which is also why the version has to be right: a v2 Retry tagged
 * with the v1 key is indistinguishable, to the client, from an off-path
 * attacker's forgery, and is dropped without a word.
 *
 * They live in quicversion.h with the rest of the per-version constants. */

#define QUIC_TOKEN_NONCE_LEN 12
#define QUIC_TOKEN_TAG_LEN   16

int quicretry_integrity_tag(const quicversion_t* ver, const quiccid_t* odcid,
                            const uint8_t* retry, size_t retry_len,
                            uint8_t tag[16]) {
    if (ver == NULL || odcid == NULL || retry == NULL || tag == NULL) return 0;

    /* The "Retry Pseudo-Packet": the original connection id prefixed by its
     * length, then the Retry packet itself. It is all additional data -- there
     * is no plaintext, so the AEAD output is the tag alone. */
    uint8_t pseudo[1 + QUIC_MAX_CID_LEN + 512];
    if (retry_len > sizeof pseudo - 1 - odcid->len) return 0;

    size_t n = 0;
    pseudo[n++] = odcid->len;
    if (odcid->len > 0) {
        memcpy(pseudo + n, odcid->data, odcid->len);
        n += odcid->len;
    }
    memcpy(pseudo + n, retry, retry_len);
    n += retry_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;

    int len = 0;
    int ok = 1;

    ok = ok && EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, ver->retry_key,
                                  ver->retry_nonce) == 1;
    ok = ok && EVP_EncryptUpdate(ctx, NULL, &len, pseudo, (int)n) == 1;
    ok = ok && EVP_EncryptFinal_ex(ctx, NULL, &len) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1;

    EVP_CIPHER_CTX_free(ctx);

    return ok;
}

size_t quicretry_write(const quicversion_t* ver, uint8_t* dst, size_t cap,
                       const quiccid_t* odcid,
                       const quiccid_t* dcid, const quiccid_t* scid,
                       const uint8_t* token, size_t token_len) {
    if (ver == NULL || dst == NULL || odcid == NULL || dcid == NULL || scid == NULL)
        return 0;
    if (token == NULL || token_len == 0) return 0;

    const size_t need = 1 + 4 + 1 + dcid->len + 1 + scid->len + token_len + 16;
    if (cap < need) return 0;

    size_t n = 0;

    /* Long header, fixed bit, and the version's own code for a Retry -- 3 in
     * v1, 0 in v2. The low four bits are unused in a Retry and are left zero;
     * there is no header protection here, since there is no packet number to
     * protect. */
    dst[n++] = (uint8_t)(0xc0 | (quicversion_wire_type(ver, QUIC_PKT_RETRY) << 4));

    dst[n++] = (uint8_t)(ver->number >> 24);
    dst[n++] = (uint8_t)(ver->number >> 16);
    dst[n++] = (uint8_t)(ver->number >> 8);
    dst[n++] = (uint8_t)(ver->number);

    dst[n++] = dcid->len;
    if (dcid->len > 0) { memcpy(dst + n, dcid->data, dcid->len); n += dcid->len; }

    dst[n++] = scid->len;
    if (scid->len > 0) { memcpy(dst + n, scid->data, scid->len); n += scid->len; }

    memcpy(dst + n, token, token_len);
    n += token_len;

    uint8_t tag[16];
    if (!quicretry_integrity_tag(ver, odcid, dst, n, tag)) return 0;

    memcpy(dst + n, tag, 16);
    n += 16;

    return n;
}

/* Just the address bytes, without the port: enough to bind a token to a client
 * without breaking one whose NAT reassigns ports. */
static size_t __addr_bytes(const struct sockaddr* addr, socklen_t addr_len,
                           uint8_t out[16]) {
    if (addr == NULL) return 0;

    if (addr->sa_family == AF_INET && addr_len >= (socklen_t)sizeof(struct sockaddr_in)) {
        memcpy(out, &((const struct sockaddr_in*)addr)->sin_addr, 4);
        return 4;
    }

    if (addr->sa_family == AF_INET6 && addr_len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        memcpy(out, &((const struct sockaddr_in6*)addr)->sin6_addr, 16);
        return 16;
    }

    return 0;
}

size_t quic_token_write(uint8_t* dst, size_t cap,
                        const uint8_t key[32],
                        quic_token_kind_e kind,
                        const struct sockaddr* peer, socklen_t peer_len,
                        const quiccid_t* odcid,
                        uint64_t now_us) {
    if (dst == NULL || key == NULL) return 0;
    if (kind == QUIC_TOKEN_RETRY && odcid == NULL) return 0;

    uint8_t addr[16];
    const size_t addr_len = __addr_bytes(peer, peer_len, addr);
    if (addr_len == 0) return 0;

    /* kind | timestamp | address length | address | odcid length | odcid */
    uint8_t plain[1 + 8 + 1 + 16 + 1 + QUIC_MAX_CID_LEN];
    size_t p = 0;

    plain[p++] = (uint8_t)kind;

    for (int i = 7; i >= 0; i--)
        plain[p++] = (uint8_t)(now_us >> (8 * i));

    plain[p++] = (uint8_t)addr_len;
    memcpy(plain + p, addr, addr_len);
    p += addr_len;

    if (kind == QUIC_TOKEN_RETRY) {
        plain[p++] = odcid->len;
        if (odcid->len > 0) { memcpy(plain + p, odcid->data, odcid->len); p += odcid->len; }
    }
    else {
        plain[p++] = 0;
    }

    if (cap < QUIC_TOKEN_NONCE_LEN + p + QUIC_TOKEN_TAG_LEN) return 0;

    uint8_t* nonce = dst;
    if (RAND_bytes(nonce, QUIC_TOKEN_NONCE_LEN) != 1) return 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;

    int len = 0;
    int ok = 1;
    size_t n = QUIC_TOKEN_NONCE_LEN;

    ok = ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) == 1;
    ok = ok && EVP_EncryptUpdate(ctx, dst + n, &len, plain, (int)p) == 1;
    if (ok) n += (size_t)len;
    ok = ok && EVP_EncryptFinal_ex(ctx, dst + n, &len) == 1;
    if (ok) n += (size_t)len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                   QUIC_TOKEN_TAG_LEN, dst + n) == 1;
    if (ok) n += QUIC_TOKEN_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
    explicit_bzero(plain, sizeof plain);

    return ok ? n : 0;
}

quic_token_status_e quic_token_read(const uint8_t* token, size_t token_len,
                                    const uint8_t key[32],
                                    quic_token_kind_e expect_kind,
                                    const struct sockaddr* peer, socklen_t peer_len,
                                    uint64_t now_us, uint64_t lifetime_us,
                                    quiccid_t* out_odcid) {
    if (token == NULL || key == NULL) return QUIC_TOKEN_BAD;
    if (token_len <= QUIC_TOKEN_NONCE_LEN + QUIC_TOKEN_TAG_LEN) return QUIC_TOKEN_BAD;
    if (token_len > QUIC_TOKEN_MAX_LEN) return QUIC_TOKEN_BAD;

    const size_t body_len = token_len - QUIC_TOKEN_NONCE_LEN - QUIC_TOKEN_TAG_LEN;

    uint8_t plain[QUIC_TOKEN_MAX_LEN];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return QUIC_TOKEN_BAD;

    int len = 0;
    int ok = 1;
    size_t p = 0;

    ok = ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, token) == 1;
    ok = ok && EVP_DecryptUpdate(ctx, plain, &len, token + QUIC_TOKEN_NONCE_LEN,
                                 (int)body_len) == 1;
    if (ok) p = (size_t)len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, QUIC_TOKEN_TAG_LEN,
                                   (void*)(token + QUIC_TOKEN_NONCE_LEN + body_len)) == 1;
    ok = ok && EVP_DecryptFinal_ex(ctx, plain + p, &len) == 1;
    if (ok) p += (size_t)len;

    EVP_CIPHER_CTX_free(ctx);

    /* Anything that fails here was not issued by this process: a token from
     * another server, a stale one from before a restart, or a forgery. All
     * three are the same to us. */
    if (!ok) return QUIC_TOKEN_BAD;

    size_t q = 0;
    if (p < 1 + 8 + 1) return QUIC_TOKEN_BAD;

    const quic_token_kind_e kind = (quic_token_kind_e)plain[q++];

    uint64_t issued = 0;
    for (int i = 0; i < 8; i++)
        issued = (issued << 8) | plain[q++];

    const uint8_t addr_len = plain[q++];
    if (addr_len != 4 && addr_len != 16) return QUIC_TOKEN_BAD;
    if (q + addr_len + 1 > p) return QUIC_TOKEN_BAD;

    const uint8_t* addr = plain + q;
    q += addr_len;

    const uint8_t odcid_len = plain[q++];
    if (odcid_len > QUIC_MAX_CID_LEN || q + odcid_len > p) return QUIC_TOKEN_BAD;

    /* Kind before anything else: a Retry token presented where a NEW_TOKEN is
     * expected (or the reverse) is a different claim about the client, and
     * treating them alike would let a client skip a Retry it was asked for. */
    if (kind != expect_kind) return QUIC_TOKEN_WRONG_KIND;

    /* Monotonic time, so a token issued before a clock jump is not suddenly
     * from the future; still guard the comparison rather than subtracting. */
    if (now_us < issued) return QUIC_TOKEN_EXPIRED;
    if (now_us - issued > lifetime_us) return QUIC_TOKEN_EXPIRED;

    uint8_t now_addr[16];
    const size_t now_addr_len = __addr_bytes(peer, peer_len, now_addr);
    if (now_addr_len == 0) return QUIC_TOKEN_BAD;
    if (now_addr_len != addr_len) return QUIC_TOKEN_WRONG_ADDR;
    if (memcmp(now_addr, addr, addr_len) != 0) return QUIC_TOKEN_WRONG_ADDR;

    if (out_odcid != NULL) {
        out_odcid->len = odcid_len;
        if (odcid_len > 0) memcpy(out_odcid->data, plain + q, odcid_len);
    }

    return QUIC_TOKEN_OK;
}

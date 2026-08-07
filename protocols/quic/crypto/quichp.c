#include <string.h>

#include "quichp.h"

#define QUICHP_FORM_LONG 0x80

/* Derive the five-byte mask from a sample of the packet's ciphertext (§5.4.3,
 * §5.4.4).
 *
 * AES: the mask is the first block of the sample encrypted in ECB mode.
 * ChaCha20: the sample is split into a 32-bit little-endian counter and a
 * 96-bit nonce, and the mask is the keystream those produce -- so it is written
 * as "encrypt five zero bytes". */
static int __mask(quickeys_t* keys, const uint8_t sample[QUICHP_SAMPLE_LEN],
                  uint8_t out[5]) {
    if (keys->suite == QUIC_AEAD_CHACHA20_POLY1305) {
        /* EVP_chacha20 takes the counter and nonce together as a 16-byte IV,
         * counter first in little endian -- exactly the layout §5.4.4
         * prescribes, so the sample is passed straight through. */
        EVP_CIPHER_CTX* ctx = keys->hp;

        if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, keys->hp_key, sample) != 1)
            return 0;

        static const uint8_t zeros[5] = { 0 };
        int len = 0;
        if (EVP_EncryptUpdate(ctx, out, &len, zeros, sizeof zeros) != 1) return 0;

        return len == (int)sizeof zeros;
    }

    /* AES-ECB. The context is already keyed (quickeys_install), and ECB has no
     * IV, so one call per packet is all this costs. */
    uint8_t block[QUICHP_SAMPLE_LEN];
    int len = 0;

    if (EVP_EncryptUpdate(keys->hp, block, &len, sample, QUICHP_SAMPLE_LEN) != 1)
        return 0;
    if (len < 5) return 0;

    memcpy(out, block, 5);

    return 1;
}

/* The first byte's protected bits: four on a long header (reserved + packet
 * number length), five on a short one (reserved + key phase + length). */
static uint8_t __first_byte_mask(uint8_t first) {
    return (first & QUICHP_FORM_LONG) ? 0x0f : 0x1f;
}

int quichp_apply(quickeys_t* keys, uint8_t* pkt, size_t pkt_len,
                 size_t pn_offset, size_t pn_len) {
    if (keys == NULL || !keys->valid || pkt == NULL) return 0;
    if (pn_len < 1 || pn_len > 4) return 0;

    /* The sample sits at a fixed offset past the packet number, not past its
     * end, so a short packet must have been padded to reach it. */
    if (pn_offset + QUICHP_MIN_AFTER_PN > pkt_len) return 0;

    uint8_t mask[5];
    if (!__mask(keys, pkt + pn_offset + QUICHP_SAMPLE_OFFSET, mask)) return 0;

    pkt[0] ^= mask[0] & __first_byte_mask(pkt[0]);

    for (size_t i = 0; i < pn_len; i++)
        pkt[pn_offset + i] ^= mask[1 + i];

    return 1;
}

int quichp_remove(quickeys_t* keys, uint8_t* pkt, size_t pkt_len,
                  size_t pn_offset, size_t* out_pn_len,
                  uint64_t* out_truncated_pn, int* out_key_phase) {
    if (keys == NULL || !keys->valid || pkt == NULL) return 0;

    if (pn_offset + QUICHP_MIN_AFTER_PN > pkt_len) return 0;

    uint8_t mask[5];
    if (!__mask(keys, pkt + pn_offset + QUICHP_SAMPLE_OFFSET, mask)) return 0;

    pkt[0] ^= mask[0] & __first_byte_mask(pkt[0]);

    /* Only now is the length readable -- which is why the sample offset had to
     * be independent of it. */
    const size_t pn_len = (size_t)(pkt[0] & 0x03) + 1;

    uint64_t pn = 0;
    for (size_t i = 0; i < pn_len; i++) {
        pkt[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | pkt[pn_offset + i];
    }

    if (out_pn_len != NULL) *out_pn_len = pn_len;
    if (out_truncated_pn != NULL) *out_truncated_pn = pn;
    if (out_key_phase != NULL)
        *out_key_phase = (pkt[0] & QUICHP_FORM_LONG) ? 0 : ((pkt[0] & 0x04) != 0);

    return 1;
}

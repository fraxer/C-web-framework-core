#include "huffman.h"

#include <string.h>

#include "huffman_table.h"   /* generated: huff_code/huff_len/huff_decode DFA */

/* ---- Huffman (RFC 7541 §5.2, Appendix B) ---- */

size_t huffman_encoded_len(const uint8_t* src, size_t len) {
    size_t bits = 0;
    for (size_t i = 0; i < len; i++) bits += huff_len[src[i]];
    return (bits + 7) / 8;
}

ssize_t huffman_encode(uint8_t* dst, size_t cap, const uint8_t* src, size_t len) {
    if (dst == NULL && cap != 0) return -1;

    uint64_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        uint32_t code = huff_code[src[i]];
        int l = huff_len[src[i]];
        acc = (acc << l) | code;
        bits += l;
        while (bits >= 8) {
            bits -= 8;
            if (n >= cap) return -1;
            dst[n++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    if (bits > 0) {
        if (n >= cap) return -1;
        /* Pad the final octet with the EOS prefix (all 1 bits). RFC 7541 §5.2
         * requires padding shorter than 8 bits, which bits>0 guarantees. */
        uint8_t pad = (uint8_t)((acc << (8 - bits)) & 0xff);
        pad |= (uint8_t)((1u << (8 - bits)) - 1);
        dst[n++] = pad;
    }
    return (ssize_t)n;
}

/* Decode through the generated nibble DFA (huffman_table.h): two table lookups
 * per octet, no per-bit work. The state encodes the position in the code tree,
 * so a symbol split across octets needs no accumulator of its own. Output is
 * bounded by ~8/5 of the input, so callers allocate ~len*2. */
ssize_t huffman_decode(uint8_t* dst, size_t cap, const uint8_t* src, size_t len) {
    if ((dst == NULL && cap != 0) || (src == NULL && len != 0)) return -1;

    size_t n = 0;
    uint8_t state = 0;
    /* Empty input decodes to the empty string; every other verdict comes from
     * the last nibble's entry. */
    int accept = 1;

    for (size_t i = 0; i < len; i++) {
        const huff_decode_t* e = &huff_decode[state][src[i] >> 4];

        if (e->flags & HUFF_FAIL) return -1;
        if (e->flags & HUFF_SYM) {
            if (n >= cap) return -1;
            dst[n++] = e->sym;
        }
        state = e->state;

        e = &huff_decode[state][src[i] & 0x0f];

        if (e->flags & HUFF_FAIL) return -1;
        if (e->flags & HUFF_SYM) {
            if (n >= cap) return -1;
            dst[n++] = e->sym;
        }
        state = e->state;
        accept = (e->flags & HUFF_ACCEPT) != 0;
    }

    /* Anything left over must be EOS-prefix padding shorter than an octet; the
     * ACCEPT flag is exactly that property of the resulting state. */
    if (!accept) return -1;

    return (ssize_t)n;
}

/* ---- Prefix integer (RFC 7541 §5.1) ---- */

size_t prefix_int_encode(uint8_t* dst, size_t cap, uint64_t value,
                         uint8_t prefix_bits, uint8_t flags) {
    if (dst == NULL || prefix_bits < 1 || prefix_bits > 8 || cap < 1) return 0;

    const uint64_t max = ((uint64_t)1 << prefix_bits) - 1;
    size_t n = 0;

    dst[n++] = (uint8_t)(flags | (value < max ? value : max));
    if (value < max) return n;

    value -= max;
    while (value >= 128) {
        if (n >= cap) return 0;
        dst[n++] = (uint8_t)((value & 0x7f) | 0x80);
        value >>= 7;
    }
    if (n >= cap) return 0;
    dst[n++] = (uint8_t)value;
    return n;
}

size_t prefix_int_decode(const uint8_t* src, size_t len, uint8_t prefix_bits,
                         uint64_t* out) {
    if (src == NULL || out == NULL || len == 0) return 0;
    if (prefix_bits < 1 || prefix_bits > 8) return 0;

    const uint64_t max = ((uint64_t)1 << prefix_bits) - 1;
    uint64_t v = (uint64_t)src[0] & max;
    size_t consumed = 1;
    if (v < max) {
        *out = v;
        return consumed;
    }

    uint64_t m = 0;
    for (;;) {
        if (consumed >= len) return 0;   /* truncated continuation */
        uint8_t octet = src[consumed++];
        /* Cap at 2^62-1: a longer continuation encodes nothing either protocol
         * uses, and lets a peer run the decoder into unbounded work otherwise. */
        if (m > 56) return 0;
        uint64_t add = (uint64_t)(octet & 0x7f) << m;
        if (add > UINT64_MAX - v) return 0;
        v += add;
        m += 7;
        if (!(octet & 0x80)) break;
    }

    *out = v;
    return consumed;
}

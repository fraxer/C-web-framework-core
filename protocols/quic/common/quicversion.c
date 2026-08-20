#include <stddef.h>

#include "quicversion.h"

/* RFC 9001 §5.2. */
static const uint8_t V1_SALT[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

/* RFC 9001 §5.8. */
static const uint8_t V1_RETRY_KEY[16] = {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
};
static const uint8_t V1_RETRY_NONCE[12] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb
};

/* RFC 9369 §3.1. */
static const uint8_t V2_SALT[20] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
};

/* RFC 9369 §3.3. */
static const uint8_t V2_RETRY_KEY[16] = {
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92
};
static const uint8_t V2_RETRY_NONCE[12] = {
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a
};

static const quicversion_t VERSION_1 = {
    .number         = QUIC_VERSION_1,
    .initial_salt   = V1_SALT,
    .label_key      = "quic key",
    .label_iv       = "quic iv",
    .label_hp       = "quic hp",
    .label_ku       = "quic ku",
    .retry_key      = V1_RETRY_KEY,
    .retry_nonce    = V1_RETRY_NONCE,
    .wire_initial   = 0x00,
    .wire_0rtt      = 0x01,
    .wire_handshake = 0x02,
    .wire_retry     = 0x03
};

static const quicversion_t VERSION_2 = {
    .number         = QUIC_VERSION_2,
    .initial_salt   = V2_SALT,
    .label_key      = "quicv2 key",
    .label_iv       = "quicv2 iv",
    .label_hp       = "quicv2 hp",
    .label_ku       = "quicv2 ku",
    .retry_key      = V2_RETRY_KEY,
    .retry_nonce    = V2_RETRY_NONCE,
    /* RFC 9369 §3.2, and the whole point of the exercise: 1/2/3/0 where v1 has
     * 0/1/2/3. */
    .wire_initial   = 0x01,
    .wire_0rtt      = 0x02,
    .wire_handshake = 0x03,
    .wire_retry     = 0x00
};

/* Preference order, newest first (RFC 9368 §2.3 leaves the choice to the
 * server, and this list is how the choice is expressed). */
static const quicversion_t* const ALL[] = { &VERSION_2, &VERSION_1 };

const quicversion_t* quicversion_find(uint32_t number) {
    for (size_t i = 0; i < sizeof ALL / sizeof * ALL; i++)
        if (ALL[i]->number == number) return ALL[i];

    return NULL;
}

const quicversion_t* const* quicversion_all(size_t* out_count) {
    if (out_count != NULL) *out_count = sizeof ALL / sizeof * ALL;

    return ALL;
}

uint8_t quicversion_wire_type(const quicversion_t* v, quic_pkt_type_e type) {
    if (v == NULL) return 0;

    switch (type) {
    case QUIC_PKT_INITIAL:   return v->wire_initial;
    case QUIC_PKT_0RTT:      return v->wire_0rtt;
    case QUIC_PKT_HANDSHAKE: return v->wire_handshake;
    case QUIC_PKT_RETRY:     return v->wire_retry;
    default:                 return 0;
    }
}

quic_pkt_type_e quicversion_type_of_wire(const quicversion_t* v, uint8_t bits) {
    /* Not a table lookup on purpose: the mapping is a permutation, so asking it
     * this way round means one definition of the permutation rather than two
     * that can disagree. Four comparisons on a packet that is about to be
     * decrypted is not a cost worth a second table. */
    if (v == NULL) return QUIC_PKT_INITIAL;

    bits &= 0x03;

    if (bits == v->wire_initial)   return QUIC_PKT_INITIAL;
    if (bits == v->wire_0rtt)      return QUIC_PKT_0RTT;
    if (bits == v->wire_handshake) return QUIC_PKT_HANDSHAKE;

    return QUIC_PKT_RETRY;
}

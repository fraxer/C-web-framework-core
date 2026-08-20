#ifndef __QUICVERSION__
#define __QUICVERSION__

#include <stdint.h>

#include "quic.h"

/* Everything that differs between QUIC versions, in one table (RFC 9369).
 *
 * QUIC v2 is not a new protocol: it is v1 with four constants moved so that
 * middleboxes cannot assume the v1 encoding is the only one -- a different
 * initial salt, a "quicv2 " prefix on the packet-protection labels, a different
 * Retry integrity key, and the four long-header type codes rotated. Nothing
 * else changes, which is exactly why it is worth doing as a table rather than
 * as branches: a branch per difference would put four `if (version == ...)`
 * into four unrelated modules, and the fifth difference -- whenever a v3 turns
 * up -- would have to find them all again.
 *
 * So the rule here is that no module outside this one names a version number.
 * They take a `const quicversion_t*` and read the constant they need; a version
 * this build does not implement has no descriptor, and quicversion_find returns
 * NULL, which is the single place "unsupported version" is decided.
 *
 * What is *not* here: whether a supported version is currently offered. That is
 * a runtime policy (http3_version_2 in the configuration), it differs between
 * virtual hosts, and it belongs to the endpoint -- see quicendpoint.c. This
 * table only says what the code can do. */

typedef struct quicversion {
    uint32_t number;

    /* RFC 9001 §5.2 / RFC 9369 §3.1: the salt that turns a client's first DCID
     * into the Initial secret. Twenty bytes. */
    const uint8_t* initial_salt;

    /* RFC 9001 §5.1, §5.4, §6 / RFC 9369 §3.1. The "client in" and "server in"
     * labels are deliberately absent: they are the same in both versions. */
    const char* label_key;
    const char* label_iv;
    const char* label_hp;
    const char* label_ku;

    /* RFC 9001 §5.8 / RFC 9369 §3.3: sixteen bytes of key, twelve of nonce. */
    const uint8_t* retry_key;
    const uint8_t* retry_nonce;

    /* The two Type bits of a long header, already shifted down, for each of the
     * four long-header packets. In v1 they are 0/1/2/3 in the order below; v2
     * rotates them so that a middlebox keyed on "type 0 means Initial" fails
     * loudly rather than silently. */
    uint8_t wire_initial;
    uint8_t wire_0rtt;
    uint8_t wire_handshake;
    uint8_t wire_retry;
} quicversion_t;

/* The descriptor for a version this build implements, or NULL. NULL is the
 * answer for version 0 (Version Negotiation is not a version), for the GREASE
 * pattern, and for anything else a peer invents. */
const quicversion_t* quicversion_find(uint32_t number);

/* Every version this build implements, in the order it prefers them -- which is
 * also the order they go into a Version Negotiation packet and into the
 * `available_versions` of the version_information transport parameter
 * (RFC 9368 §3). Newest first: RFC 9368 §2.3 lets a server choose any version
 * the client listed, and preference is expressed by this order. */
const quicversion_t* const* quicversion_all(size_t* out_count);

/* The two Type bits this version writes for a packet of this kind, and the
 * reverse. `quicversion_type_of_wire` returns QUIC_PKT_VERSION_NEGOTIATION for
 * nothing -- every two-bit pattern is a valid long-header type in both
 * versions, so the reverse map is total. */
uint8_t         quicversion_wire_type(const quicversion_t* v, quic_pkt_type_e type);
quic_pkt_type_e quicversion_type_of_wire(const quicversion_t* v, uint8_t bits);

#endif

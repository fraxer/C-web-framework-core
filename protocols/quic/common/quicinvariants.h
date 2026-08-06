#ifndef __QUICINVARIANTS__
#define __QUICINVARIANTS__

#include <stddef.h>
#include <stdint.h>

#include "quic.h"

/* Version-independent properties of QUIC packets (RFC 8999).
 *
 * This is deliberately NOT the QUIC v1 packet codec (quicpacket.{c,h},
 * phase 2). It parses only the fields RFC 8999 promises will mean the same
 * thing in every QUIC version -- the header form bit, the version, and the
 * connection ids -- which is exactly, and only, what the demultiplexer needs to
 * route a datagram to a connection or to decide that there is none
 * (docs/http3/01-udp-endpoint.md §5.1).
 *
 * Keeping the two apart is what makes it possible to answer a packet of a
 * version we do not implement: a Version Negotiation packet has to be produced
 * from a header we cannot otherwise interpret. Parsing such a packet with the
 * v1 codec would be wrong by construction.
 *
 * Nothing here touches protected bits: the low bits of the first byte and the
 * packet number are under header protection and are meaningless until the
 * crypto layer removes it. */

typedef enum {
    QUICINV_OK = 0,
    /* The buffer ends inside the invariant header. */
    QUICINV_TRUNCATED,
    /* A connection id longer than QUIC_MAX_CID_LEN. RFC 8999 permits up to 255
     * bytes, but RFC 9000 §5.1 caps version 1 at 20 and requires longer ones to
     * be dropped, so this server has no representation for them. Reported
     * separately from TRUNCATED because the datagram is well-formed -- it is
     * refused by policy, and the counter should say so. */
    QUICINV_CID_TOO_LONG
} quicinv_status_e;

typedef struct quicinvariants {
    /* Header form bit (0x80 of the first byte). */
    int       long_header;
    /* Long header only. 0 means a Version Negotiation packet (§17.2.1), which
     * a server receives only from a broken or hostile peer. Short headers carry
     * no version; the field reads 0 for them, so callers must check
     * `long_header` before treating 0 as "version negotiation". */
    uint32_t  version;
    quiccid_t dcid;
    /* Long header only; length 0 on a short header, which carries no SCID. */
    quiccid_t scid;
    /* First byte as received, still header-protected. Kept for the v1 codec,
     * which needs it once the protection is removed. */
    uint8_t   first;
    /* Total bytes of invariant header consumed -- where the version-specific
     * part begins. */
    size_t    header_len;
} quicinvariants_t;

/* Parse the invariant header at the start of `buf`.
 *
 * `local_cid_len` is the length of the connection ids this endpoint issues. A
 * short header does not carry its DCID length -- only the issuer knows it --
 * so the parser has to be told. Must be <= QUIC_MAX_CID_LEN. */
quicinv_status_e quic_invariants_parse(const uint8_t* buf, size_t len,
                                       size_t local_cid_len,
                                       quicinvariants_t* out);

/* True when the packet is a Version Negotiation packet (long header, version 0).
 * A server must never answer one -- doing so is an infinite loop between two
 * endpoints that disagree (RFC 9000 §6.1). */
static inline int quic_invariants_is_version_negotiation(const quicinvariants_t* inv) {
    return inv->long_header && inv->version == 0;
}

/* Write a Version Negotiation packet (RFC 9000 §17.2.1).
 *
 * The caller supplies the connection ids ALREADY SWAPPED: a Version Negotiation
 * packet echoes the peer's Source CID as its Destination CID and vice versa, and
 * making that the caller's job keeps the mistake visible at the call site rather
 * than hidden behind an argument order.
 *
 * `unused_bits` fills the seven bits below the header form bit. RFC 9000 §17.2.1
 * leaves them arbitrary and recommends varying them, so that peers cannot come
 * to depend on a fixed value -- including the "fixed bit", which is not fixed
 * here. It is a parameter rather than a call to a random source so that this
 * module stays free of dependencies and the encoder stays deterministic under
 * test; the endpoint passes a random byte.
 *
 * Returns the number of bytes written, or 0 if `cap` is too small. */
size_t quic_invariants_write_version_negotiation(uint8_t* dst, size_t cap,
                                                 const quiccid_t* dcid,
                                                 const quiccid_t* scid,
                                                 uint8_t unused_bits,
                                                 const uint32_t* versions,
                                                 size_t version_count);

#endif

#ifndef __QUICPACKET__
#define __QUICPACKET__

#include <stddef.h>
#include <stdint.h>

#include "quic.h"

/* QUIC version 1 packet headers (RFC 9000 §17).
 *
 * This is the version-*specific* codec, and it is deliberately a different
 * module from quicinvariants.{c,h}: that one reads only what RFC 8999 promises
 * every QUIC version will agree on, which is what the demultiplexer needs to
 * route a datagram it may not be able to interpret at all. Here we know the
 * packet is version 1 and can read its types, token and length.
 *
 * ## What can be read before decryption
 *
 * Header protection (RFC 9001 §5.4) masks the low four bits of a long header's
 * first byte and the low five of a short header's -- the reserved bits, the key
 * phase, and the packet number length. Everything this module reads sits
 * outside that mask: the header form, the fixed bit, the long packet type, the
 * version, the connection ids, the token and the length.
 *
 * The packet number is therefore NOT parsed here. quicpkt_parse reports where
 * it starts (`pn_offset`); the crypto layer removes the protection, learns the
 * length, and only then calls quicpkt_decode_pn. Trying to read it earlier is
 * the classic way to get a QUIC receive path subtly wrong. */

typedef enum {
    QUICPKT_OK = 0,
    /* The buffer ends inside the header, or the announced Length runs past it. */
    QUICPKT_SHORT_BUFFER,
    /* Structurally not a version 1 packet: the fixed bit is clear, or a
     * connection id is longer than §5.1 allows. */
    QUICPKT_BAD_FORM,
    /* A long header carrying a version we do not implement. The caller answers
     * with Version Negotiation; it must not try to interpret the rest. */
    QUICPKT_UNSUPPORTED_VERSION,
    /* Version 0: the peer sent US a Version Negotiation packet. */
    QUICPKT_VERSION_NEGOTIATION
} quicpkt_status_e;

typedef struct quicpkt {
    quic_pkt_type_e type;
    uint32_t  version;      /* 0 on a short header */
    quiccid_t dcid;
    quiccid_t scid;         /* len 0 on a short header */

    /* Initial only: the address validation token echoed back from a Retry or a
     * NEW_TOKEN frame. Borrowed from the input buffer. */
    const uint8_t* token;
    size_t    token_len;

    /* Long header only: the Length field, covering the packet number plus the
     * protected payload. */
    uint64_t  length;

    /* Offset of the packet number from the start of the packet. Also where the
     * header protection sample is measured from (pn_offset + 4). Zero for
     * Retry and Version Negotiation, which carry no packet number. */
    size_t    pn_offset;

    /* Total bytes this packet occupies inside the datagram. For a long header
     * that is pn_offset + length; a short header, Retry and Version
     * Negotiation all run to the end of the datagram, since they carry no
     * length of their own -- which is why they may only appear last. */
    size_t    pkt_len;

    uint8_t   first;        /* first byte as received, still protected */
} quicpkt_t;

/* Parse the header of one version 1 packet at the start of `buf`.
 *
 * `local_cid_len` is the length of the connection ids this endpoint issues; a
 * short header does not carry it. */
quicpkt_status_e quicpkt_parse(const uint8_t* buf, size_t len,
                               size_t local_cid_len, quicpkt_t* out);

/* Walk the packets coalesced into one datagram (§12.2).
 *
 * Returns 1 when a packet was produced and advances `*off` past it, 0 when the
 * datagram is exhausted. `*status` reports why a packet could not be parsed;
 * on anything but QUICPKT_OK the caller must stop -- the remainder of the
 * datagram cannot be located without a length it was unable to read. */
int quicpkt_next(const uint8_t* dgram, size_t dgram_len, size_t* off,
                 size_t local_cid_len, quicpkt_t* out, quicpkt_status_e* status);

/* Encryption level a packet type belongs to. */
quic_enc_level_e quicpkt_level(quic_pkt_type_e type);

/* ---- Packet numbers (§17.1, Appendix A.2/A.3) ---- */

/* No packet has been acknowledged in this space yet. */
#define QUICPKT_NO_ACKED UINT64_MAX

/* How many bytes (1..4) the packet number must be truncated to so the peer can
 * recover it: enough to cover twice the number of packets in flight (§A.2). */
size_t quicpkt_pn_length(uint64_t pn, uint64_t largest_acked);

/* Recover a full packet number from its truncated form (§A.3). `pn_len` is the
 * length in bytes, as read from the first byte after header protection was
 * removed. */
uint64_t quicpkt_decode_pn(uint64_t largest_pn, uint64_t truncated, size_t pn_len);

/* ---- Writing ---- */

typedef struct quicpkt_hdr_out {
    quic_pkt_type_e type;       /* INITIAL, 0RTT, HANDSHAKE or SHORT */
    uint32_t version;           /* ignored for SHORT */
    const quiccid_t* dcid;
    const quiccid_t* scid;      /* long header only */
    const uint8_t* token;       /* Initial only; NULL for none */
    size_t token_len;
    uint64_t pn;
    size_t pn_len;              /* 1..4, from quicpkt_pn_length */
    int key_phase;              /* short header only */
    /* Bytes of protected payload that will follow, AEAD tag included. Used for
     * the long header's Length field, which also covers the packet number. */
    size_t payload_len;
    /* Force the Length field to this many bytes (0 = minimal). A sender that
     * lays out the header before knowing the final payload size reserves a
     * fixed width here and patches the value afterwards. */
    size_t length_field_bytes;
} quicpkt_hdr_out_t;

/* Write a header, packet number included, into `dst`. Returns the number of
 * bytes written, or 0 if anything does not fit or is out of range.
 * `out_pn_offset` receives the offset of the packet number, which is what the
 * header protection step needs. */
size_t quicpkt_write_header(uint8_t* dst, size_t cap, const quicpkt_hdr_out_t* hdr,
                            size_t* out_pn_offset);

#endif

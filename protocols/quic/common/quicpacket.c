#include <string.h>

#include "quicpacket.h"
#include "varint.h"

#define QUICPKT_FORM_LONG   0x80
#define QUICPKT_FIXED_BIT   0x40
#define QUICPKT_LONG_TYPE   0x30
#define QUICPKT_KEY_PHASE   0x04
#define QUICPKT_PN_LEN_MASK 0x03

/* Retry carries a 128-bit integrity tag at the very end (RFC 9001 §5.8). */
#define QUICPKT_RETRY_TAG_LEN 16

static quicpkt_status_e __read_cid(const uint8_t* buf, size_t len, size_t* off,
                                   quiccid_t* out) {
    if (*off + 1 > len) return QUICPKT_SHORT_BUFFER;

    const uint8_t cid_len = buf[*off];
    *off += 1;

    /* RFC 9000 §5.1: version 1 caps connection ids at 20 bytes and requires a
     * packet with a longer one to be dropped. */
    if (cid_len > QUIC_MAX_CID_LEN) return QUICPKT_BAD_FORM;
    if (*off + cid_len > len) return QUICPKT_SHORT_BUFFER;

    out->len = cid_len;
    if (cid_len > 0) memcpy(out->data, buf + *off, cid_len);
    *off += cid_len;

    return QUICPKT_OK;
}

quic_enc_level_e quicpkt_level(quic_pkt_type_e type) {
    switch (type) {
    case QUIC_PKT_INITIAL:   return QUIC_ENC_INITIAL;
    case QUIC_PKT_0RTT:      return QUIC_ENC_EARLY;
    case QUIC_PKT_HANDSHAKE: return QUIC_ENC_HANDSHAKE;
    default:                 return QUIC_ENC_APP;
    }
}

quicpkt_status_e quicpkt_parse(const uint8_t* buf, size_t len,
                               size_t local_cid_len, quicpkt_t* out) {
    if (buf == NULL || out == NULL) return QUICPKT_SHORT_BUFFER;
    if (local_cid_len > QUIC_MAX_CID_LEN) return QUICPKT_BAD_FORM;
    if (len < 1) return QUICPKT_SHORT_BUFFER;

    memset(out, 0, sizeof * out);
    out->first = buf[0];

    if ((buf[0] & QUICPKT_FORM_LONG) == 0) {
        /* Short header (§17.3). The fixed bit is outside the header protection
         * mask, so it can be checked now. */
        if ((buf[0] & QUICPKT_FIXED_BIT) == 0) return QUICPKT_BAD_FORM;

        size_t off = 1;
        if (off + local_cid_len > len) return QUICPKT_SHORT_BUFFER;

        out->type = QUIC_PKT_SHORT;
        out->dcid.len = (uint8_t)local_cid_len;
        if (local_cid_len > 0) memcpy(out->dcid.data, buf + off, local_cid_len);
        off += local_cid_len;

        out->pn_offset = off;
        /* No length field: a short header runs to the end of the datagram, so
         * it can only ever be the last packet in one. */
        out->pkt_len = len;

        return QUICPKT_OK;
    }

    /* Long header (§17.2). */
    size_t off = 1;
    if (off + 4 > len) return QUICPKT_SHORT_BUFFER;

    out->version = ((uint32_t)buf[off] << 24) | ((uint32_t)buf[off + 1] << 16) |
                   ((uint32_t)buf[off + 2] << 8) | (uint32_t)buf[off + 3];
    off += 4;

    quicpkt_status_e st = __read_cid(buf, len, &off, &out->dcid);
    if (st != QUICPKT_OK) return st;

    st = __read_cid(buf, len, &off, &out->scid);
    if (st != QUICPKT_OK) return st;

    /* Version 0 marks a Version Negotiation packet, whose remainder is a list
     * of versions rather than anything this codec describes. Reported before
     * the fixed-bit check on purpose: §17.2.1 leaves those bits arbitrary. */
    if (out->version == 0) {
        out->type = QUIC_PKT_VERSION_NEGOTIATION;
        out->pkt_len = len;
        return QUICPKT_VERSION_NEGOTIATION;
    }

    if ((buf[0] & QUICPKT_FIXED_BIT) == 0) return QUICPKT_BAD_FORM;

    /* The type bits mean what they mean only in version 1; for any other
     * version the caller owes a Version Negotiation packet and must not read
     * further. */
    if (out->version != QUIC_VERSION_1) {
        out->pkt_len = len;
        return QUICPKT_UNSUPPORTED_VERSION;
    }

    out->type = (quic_pkt_type_e)((buf[0] & QUICPKT_LONG_TYPE) >> 4);

    if (out->type == QUIC_PKT_RETRY) {
        /* §17.2.5: no length and no packet number -- the token runs to the
         * integrity tag, and the tag ends the datagram. */
        if (off + QUICPKT_RETRY_TAG_LEN > len) return QUICPKT_SHORT_BUFFER;

        out->token = buf + off;
        out->token_len = len - off - QUICPKT_RETRY_TAG_LEN;
        out->pn_offset = 0;
        out->pkt_len = len;

        return QUICPKT_OK;
    }

    if (out->type == QUIC_PKT_INITIAL) {
        uint64_t token_len = 0;
        const size_t n = varint_read(buf + off, len - off, &token_len);
        if (n == 0) return QUICPKT_SHORT_BUFFER;
        off += n;

        if (token_len > len - off) return QUICPKT_SHORT_BUFFER;

        out->token = token_len > 0 ? buf + off : NULL;
        out->token_len = (size_t)token_len;
        off += (size_t)token_len;
    }

    uint64_t length = 0;
    const size_t n = varint_read(buf + off, len - off, &length);
    if (n == 0) return QUICPKT_SHORT_BUFFER;
    off += n;

    /* The Length covers the packet number and the protected payload. A value
     * running past the datagram is how a peer would try to make us read out of
     * bounds, and it is also what a truncated datagram looks like. */
    if (length > len - off) return QUICPKT_SHORT_BUFFER;

    /* A packet number is one to four bytes, so a Length below one leaves no
     * room for the packet number the field is defined to include. */
    if (length < 1) return QUICPKT_BAD_FORM;

    out->length = length;
    out->pn_offset = off;
    out->pkt_len = off + (size_t)length;

    return QUICPKT_OK;
}

int quicpkt_next(const uint8_t* dgram, size_t dgram_len, size_t* off,
                 size_t local_cid_len, quicpkt_t* out, quicpkt_status_e* status) {
    if (dgram == NULL || off == NULL || out == NULL || status == NULL) return 0;
    if (*off >= dgram_len) return 0;

    /* A trailing run of zero bytes is padding between coalesced packets
     * (§12.2), not a packet: a first byte of 0x00 has the fixed bit clear and
     * cannot begin a valid one. */
    if (dgram[*off] == 0x00) {
        *status = QUICPKT_OK;
        return 0;
    }

    *status = quicpkt_parse(dgram + *off, dgram_len - *off, local_cid_len, out);
    if (*status != QUICPKT_OK) return 0;

    if (out->pkt_len == 0 || out->pkt_len > dgram_len - *off) {
        *status = QUICPKT_SHORT_BUFFER;
        return 0;
    }

    *off += out->pkt_len;

    return 1;
}

size_t quicpkt_pn_length(uint64_t pn, uint64_t largest_acked) {
    /* §A.2: the truncated number must cover more than twice the range of
     * packets still unacknowledged, so the peer's recovery window cannot
     * straddle two candidates. */
    const uint64_t unacked = largest_acked == QUICPKT_NO_ACKED
                             ? pn + 1
                             : (pn > largest_acked ? pn - largest_acked : 1);

    /* The RFC writes this as ceil((log2(unacked) + 1) / 8) over real numbers.
     * Taken literally with integer logs it is wrong at the powers of two --
     * 128 unacknowledged packets needs one byte, 129 needs two -- so express
     * the same condition exactly instead: the smallest width b whose range
     * covers the value, unacked <= 2^(8b-1). */
    for (size_t bytes = 1; bytes < 4; bytes++)
        if (unacked <= (1ULL << (8 * bytes - 1)))
            return bytes;

    return 4;
}

uint64_t quicpkt_decode_pn(uint64_t largest_pn, uint64_t truncated, size_t pn_len) {
    if (pn_len == 0 || pn_len > 4) return truncated;

    const unsigned pn_nbits = (unsigned)(pn_len * 8);
    const uint64_t pn_win = 1ULL << pn_nbits;
    const uint64_t pn_hwin = pn_win / 2;
    const uint64_t pn_mask = pn_win - 1;

    const uint64_t expected = largest_pn + 1;
    const uint64_t candidate = (expected & ~pn_mask) | (truncated & pn_mask);

    /* §A.3 picks the candidate nearest the expected number. The comparisons are
     * written to avoid unsigned wrap, which the RFC's arbitrary-precision
     * pseudocode does not have to worry about: `expected - pn_hwin` underflows
     * early in a connection, and `candidate - pn_win` underflows for any
     * candidate below one window. */
    if (expected >= pn_hwin && candidate <= expected - pn_hwin &&
        candidate + pn_win < (1ULL << 62))
        return candidate + pn_win;

    if (candidate > expected + pn_hwin && candidate >= pn_win)
        return candidate - pn_win;

    return candidate;
}

size_t quicpkt_write_header(uint8_t* dst, size_t cap, const quicpkt_hdr_out_t* hdr,
                            size_t* out_pn_offset) {
    if (dst == NULL || hdr == NULL || hdr->dcid == NULL) return 0;
    if (hdr->pn_len < 1 || hdr->pn_len > 4) return 0;
    if (hdr->dcid->len > QUIC_MAX_CID_LEN) return 0;

    size_t off = 0;

    if (hdr->type == QUIC_PKT_SHORT) {
        if (cap < 1) return 0;

        /* Form 0, fixed bit 1, spin 0, reserved 0, key phase, pn length - 1.
         * The reserved bits must be zero (§17.3.1); header protection will mask
         * these low bits afterwards. */
        dst[off++] = (uint8_t)(QUICPKT_FIXED_BIT |
                               (hdr->key_phase ? QUICPKT_KEY_PHASE : 0) |
                               ((hdr->pn_len - 1) & QUICPKT_PN_LEN_MASK));

        if (off + hdr->dcid->len > cap) return 0;
        memcpy(dst + off, hdr->dcid->data, hdr->dcid->len);
        off += hdr->dcid->len;
    }
    else {
        if (hdr->scid == NULL || hdr->scid->len > QUIC_MAX_CID_LEN) return 0;
        if (hdr->type != QUIC_PKT_INITIAL && hdr->type != QUIC_PKT_0RTT &&
            hdr->type != QUIC_PKT_HANDSHAKE)
            return 0;

        if (cap < 5) return 0;

        dst[off++] = (uint8_t)(QUICPKT_FORM_LONG | QUICPKT_FIXED_BIT |
                               ((uint8_t)hdr->type << 4) |
                               ((hdr->pn_len - 1) & QUICPKT_PN_LEN_MASK));

        dst[off++] = (uint8_t)(hdr->version >> 24);
        dst[off++] = (uint8_t)(hdr->version >> 16);
        dst[off++] = (uint8_t)(hdr->version >> 8);
        dst[off++] = (uint8_t)(hdr->version);

        if (off + 1 + hdr->dcid->len > cap) return 0;
        dst[off++] = hdr->dcid->len;
        memcpy(dst + off, hdr->dcid->data, hdr->dcid->len);
        off += hdr->dcid->len;

        if (off + 1 + hdr->scid->len > cap) return 0;
        dst[off++] = hdr->scid->len;
        memcpy(dst + off, hdr->scid->data, hdr->scid->len);
        off += hdr->scid->len;

        if (hdr->type == QUIC_PKT_INITIAL) {
            const size_t n = varint_write(dst + off, cap - off, hdr->token_len);
            if (n == 0) return 0;
            off += n;

            if (hdr->token_len > 0) {
                if (hdr->token == NULL || off + hdr->token_len > cap) return 0;
                memcpy(dst + off, hdr->token, hdr->token_len);
                off += hdr->token_len;
            }
        }

        /* Length covers the packet number as well as the payload. */
        const uint64_t length = (uint64_t)hdr->pn_len + (uint64_t)hdr->payload_len;
        const size_t n = hdr->length_field_bytes > 0
            ? varint_write_fixed(dst + off, cap - off, length, hdr->length_field_bytes)
            : varint_write(dst + off, cap - off, length);
        if (n == 0) return 0;
        off += n;
    }

    if (out_pn_offset != NULL) *out_pn_offset = off;

    if (off + hdr->pn_len > cap) return 0;

    /* The packet number goes out truncated to pn_len bytes, big endian. */
    for (size_t i = 0; i < hdr->pn_len; i++)
        dst[off + i] = (uint8_t)(hdr->pn >> (8 * (hdr->pn_len - 1 - i)));

    off += hdr->pn_len;

    return off;
}

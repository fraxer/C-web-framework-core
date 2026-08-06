#include <string.h>

#include "quicinvariants.h"

#define QUIC_HEADER_FORM_LONG 0x80

/* Read one length-prefixed connection id.
 *
 * RFC 8999 allows 0..255 bytes; RFC 9000 §5.1 caps version 1 at 20 and requires
 * anything longer to be dropped. The length byte is still consumed on the
 * too-long path so that `off` stays meaningful to a caller that wants to report
 * how far it got. */
static quicinv_status_e __read_cid(const uint8_t* buf, size_t len, size_t* off,
                                   quiccid_t* out) {
    if (*off + 1 > len) return QUICINV_TRUNCATED;

    const uint8_t cid_len = buf[*off];
    *off += 1;

    if (cid_len > QUIC_MAX_CID_LEN) return QUICINV_CID_TOO_LONG;
    if (*off + cid_len > len) return QUICINV_TRUNCATED;

    out->len = cid_len;
    if (cid_len > 0)
        memcpy(out->data, buf + *off, cid_len);

    *off += cid_len;

    return QUICINV_OK;
}

quicinv_status_e quic_invariants_parse(const uint8_t* buf, size_t len,
                                       size_t local_cid_len,
                                       quicinvariants_t* out) {
    if (buf == NULL || out == NULL) return QUICINV_TRUNCATED;
    if (local_cid_len > QUIC_MAX_CID_LEN) return QUICINV_CID_TOO_LONG;
    if (len < 1) return QUICINV_TRUNCATED;

    memset(out, 0, sizeof * out);

    out->first = buf[0];
    out->long_header = (buf[0] & QUIC_HEADER_FORM_LONG) != 0;

    size_t off = 1;

    if (!out->long_header) {
        /* Short header: the DCID runs from byte 1 for however many bytes this
         * endpoint issues. There is no length on the wire and no SCID. */
        if (off + local_cid_len > len) return QUICINV_TRUNCATED;

        out->dcid.len = (uint8_t)local_cid_len;
        if (local_cid_len > 0)
            memcpy(out->dcid.data, buf + off, local_cid_len);

        off += local_cid_len;
        out->header_len = off;

        return QUICINV_OK;
    }

    if (off + 4 > len) return QUICINV_TRUNCATED;

    out->version = ((uint32_t)buf[off] << 24) | ((uint32_t)buf[off + 1] << 16) |
                   ((uint32_t)buf[off + 2] << 8) | (uint32_t)buf[off + 3];
    off += 4;

    quicinv_status_e st = __read_cid(buf, len, &off, &out->dcid);
    if (st != QUICINV_OK) return st;

    st = __read_cid(buf, len, &off, &out->scid);
    if (st != QUICINV_OK) return st;

    out->header_len = off;

    return QUICINV_OK;
}

size_t quic_invariants_write_version_negotiation(uint8_t* dst, size_t cap,
                                                 const quiccid_t* dcid,
                                                 const quiccid_t* scid,
                                                 uint8_t unused_bits,
                                                 const uint32_t* versions,
                                                 size_t version_count) {
    if (dst == NULL || dcid == NULL || scid == NULL) return 0;
    if (versions == NULL || version_count == 0) return 0;
    if (dcid->len > QUIC_MAX_CID_LEN || scid->len > QUIC_MAX_CID_LEN) return 0;

    const size_t need = 1 + 4 + 1 + dcid->len + 1 + scid->len + version_count * 4;
    if (cap < need) return 0;

    size_t off = 0;

    /* Header form set; the remaining seven bits are arbitrary (§17.2.1). */
    dst[off++] = (uint8_t)(QUIC_HEADER_FORM_LONG | (unused_bits & 0x7f));

    /* Version 0 is what marks the packet as Version Negotiation. */
    dst[off++] = 0;
    dst[off++] = 0;
    dst[off++] = 0;
    dst[off++] = 0;

    dst[off++] = dcid->len;
    if (dcid->len > 0) {
        memcpy(dst + off, dcid->data, dcid->len);
        off += dcid->len;
    }

    dst[off++] = scid->len;
    if (scid->len > 0) {
        memcpy(dst + off, scid->data, scid->len);
        off += scid->len;
    }

    for (size_t i = 0; i < version_count; i++) {
        dst[off++] = (uint8_t)(versions[i] >> 24);
        dst[off++] = (uint8_t)(versions[i] >> 16);
        dst[off++] = (uint8_t)(versions[i] >> 8);
        dst[off++] = (uint8_t)(versions[i]);
    }

    return off;
}

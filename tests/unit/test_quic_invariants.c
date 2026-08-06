#include "framework.h"

#include "quicinvariants.h"

#include <string.h>

/* RFC 8999 invariant header parsing and Version Negotiation encoding.
 *
 * These run before any key exists, on bytes from an unauthenticated source, so
 * every length here is attacker-controlled. The truncation cases matter more
 * than the happy path. */

TEST(test_quic_invariants_long_header) {
    TEST_SUITE("quic_invariants");

    TEST_CASE("long header with both connection ids");
    /* form|fixed|type=Initial, version 1, DCID len 4, SCID len 2 */
    const uint8_t pkt[] = {
        0xc0,
        0x00, 0x00, 0x00, 0x01,
        0x04, 0xde, 0xad, 0xbe, 0xef,
        0x02, 0x11, 0x22,
        0xaa, 0xbb /* version-specific data */
    };

    quicinvariants_t inv;
    TEST_ASSERT(quic_invariants_parse(pkt, sizeof pkt, 8, &inv) == QUICINV_OK,
                "parses");
    TEST_ASSERT(inv.long_header, "long header");
    TEST_ASSERT(inv.first == 0xc0, "first byte preserved");
    TEST_ASSERT(inv.version == 0x00000001u, "version 1");
    TEST_ASSERT(inv.dcid.len == 4, "dcid length");
    TEST_ASSERT(memcmp(inv.dcid.data, "\xde\xad\xbe\xef", 4) == 0, "dcid bytes");
    TEST_ASSERT(inv.scid.len == 2, "scid length");
    TEST_ASSERT(memcmp(inv.scid.data, "\x11\x22", 2) == 0, "scid bytes");
    TEST_ASSERT(inv.header_len == 13, "header length");
    TEST_ASSERT(!quic_invariants_is_version_negotiation(&inv), "not VN");

    TEST_CASE("local_cid_len is ignored for a long header");
    /* The long header carries its own lengths; passing a different local length
     * must not change the parse. */
    quicinvariants_t other;
    TEST_ASSERT(quic_invariants_parse(pkt, sizeof pkt, 0, &other) == QUICINV_OK,
                "parses with local_cid_len 0");
    TEST_ASSERT(other.dcid.len == 4 && other.scid.len == 2, "same lengths");

    TEST_CASE("zero-length connection ids");
    const uint8_t empty[] = { 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    TEST_ASSERT(quic_invariants_parse(empty, sizeof empty, 8, &inv) == QUICINV_OK,
                "parses");
    TEST_ASSERT(inv.dcid.len == 0 && inv.scid.len == 0, "both empty");
    TEST_ASSERT(inv.header_len == 7, "header length");
}

TEST(test_quic_invariants_short_header) {
    TEST_SUITE("quic_invariants");

    TEST_CASE("short header takes its DCID length from the endpoint");
    /* A short header does not carry the length -- only the endpoint that issued
     * the id knows it. Getting this wrong misroutes every 1-RTT packet. */
    const uint8_t pkt[] = {
        0x40,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x99, 0x99
    };

    quicinvariants_t inv;
    TEST_ASSERT(quic_invariants_parse(pkt, sizeof pkt, 8, &inv) == QUICINV_OK,
                "parses");
    TEST_ASSERT(!inv.long_header, "short header");
    TEST_ASSERT(inv.version == 0, "no version on a short header");
    TEST_ASSERT(inv.dcid.len == 8, "dcid length from endpoint");
    TEST_ASSERT(memcmp(inv.dcid.data, "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0,
                "dcid bytes");
    TEST_ASSERT(inv.scid.len == 0, "no scid");
    TEST_ASSERT(inv.header_len == 9, "header length");

    TEST_CASE("version 0 on a short header is not version negotiation");
    /* Only a long header can be a VN packet. A short header reads version 0
     * simply because it has no version field. */
    TEST_ASSERT(!quic_invariants_is_version_negotiation(&inv), "not VN");

    TEST_CASE("short header shorter than the endpoint's CID");
    const uint8_t tiny[] = { 0x40, 0x01, 0x02 };
    TEST_ASSERT(quic_invariants_parse(tiny, sizeof tiny, 8, &inv) == QUICINV_TRUNCATED,
                "truncated");
}

TEST(test_quic_invariants_malformed) {
    TEST_SUITE("quic_invariants");

    quicinvariants_t inv;

    TEST_CASE("empty and truncated buffers");
    TEST_ASSERT(quic_invariants_parse(NULL, 10, 8, &inv) == QUICINV_TRUNCATED, "NULL buffer");
    const uint8_t one[] = { 0xc0 };
    TEST_ASSERT(quic_invariants_parse(one, 0, 8, &inv) == QUICINV_TRUNCATED, "zero length");
    TEST_ASSERT(quic_invariants_parse(one, 1, 8, &inv) == QUICINV_TRUNCATED,
                "long header without a version");

    TEST_CASE("truncated at every offset of a well-formed header");
    /* The parser sees unauthenticated bytes; every prefix of a valid header
     * must be refused rather than read past. */
    const uint8_t pkt[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xde, 0xad, 0xbe, 0xef,
        0x02, 0x11, 0x22
    };
    int all_truncated = 1;
    for (size_t n = 1; n < sizeof pkt; n++)
        if (quic_invariants_parse(pkt, n, 8, &inv) != QUICINV_TRUNCATED)
            all_truncated = 0;
    TEST_ASSERT(all_truncated, "every proper prefix is truncated");
    TEST_ASSERT(quic_invariants_parse(pkt, sizeof pkt, 8, &inv) == QUICINV_OK,
                "the whole header parses");

    TEST_CASE("connection id longer than version 1 allows");
    /* RFC 8999 permits up to 255 bytes; RFC 9000 §5.1 caps v1 at 20 and
     * requires the packet to be dropped. Reported apart from TRUNCATED because
     * the datagram is well-formed -- it is refused by policy. */
    const uint8_t big_dcid[] = { 0xc0, 0x00, 0x00, 0x00, 0x01, 21 };
    TEST_ASSERT(quic_invariants_parse(big_dcid, sizeof big_dcid, 8, &inv)
                == QUICINV_CID_TOO_LONG, "oversize dcid");

    const uint8_t big_scid[] = { 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 255 };
    TEST_ASSERT(quic_invariants_parse(big_scid, sizeof big_scid, 8, &inv)
                == QUICINV_CID_TOO_LONG, "oversize scid");

    TEST_CASE("caller asking for an impossible local CID length");
    TEST_ASSERT(quic_invariants_parse(pkt, sizeof pkt, QUIC_MAX_CID_LEN + 1, &inv)
                == QUICINV_CID_TOO_LONG, "local_cid_len above the maximum");
}

TEST(test_quic_invariants_version_negotiation) {
    TEST_SUITE("quic_invariants");

    TEST_CASE("a version negotiation packet is recognised");
    const uint8_t vn[] = {
        0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x01
    };
    quicinvariants_t inv;
    TEST_ASSERT(quic_invariants_parse(vn, sizeof vn, 8, &inv) == QUICINV_OK, "parses");
    TEST_ASSERT(quic_invariants_is_version_negotiation(&inv), "is VN");

    TEST_CASE("encoding swaps the connection ids");
    /* The peer's SCID becomes our DCID. Getting this backwards produces a
     * packet the client silently ignores, which is very hard to see. */
    quiccid_t dcid = { .len = 3 };
    memcpy(dcid.data, "\xaa\xbb\xcc", 3);
    quiccid_t scid = { .len = 2 };
    memcpy(scid.data, "\x01\x02", 2);

    const uint32_t versions[] = { QUIC_VERSION_1, QUIC_VERSION_GREASE };
    uint8_t out[64];
    const size_t n = quic_invariants_write_version_negotiation(
        out, sizeof out, &dcid, &scid, 0x55, versions, 2);

    TEST_ASSERT(n == 1 + 4 + 1 + 3 + 1 + 2 + 8, "length");
    TEST_ASSERT((out[0] & 0x80) != 0, "header form set");
    TEST_ASSERT((out[0] & 0x7f) == 0x55, "unused bits carried through");
    TEST_ASSERT(out[1] == 0 && out[2] == 0 && out[3] == 0 && out[4] == 0,
                "version field is zero");
    TEST_ASSERT(out[5] == 3 && memcmp(out + 6, "\xaa\xbb\xcc", 3) == 0, "dcid");
    TEST_ASSERT(out[9] == 2 && memcmp(out + 10, "\x01\x02", 2) == 0, "scid");
    TEST_ASSERT(memcmp(out + 12, "\x00\x00\x00\x01", 4) == 0, "version 1 offered");

    const uint32_t offered_grease = ((uint32_t)out[16] << 24) | ((uint32_t)out[17] << 16) |
                                    ((uint32_t)out[18] << 8) | (uint32_t)out[19];
    TEST_ASSERT(offered_grease == QUIC_VERSION_GREASE, "grease version offered");
    TEST_ASSERT((offered_grease & 0x0f0f0f0fu) == 0x0a0a0a0au,
                "and it matches the reserved 0x?a?a?a?a pattern");

    TEST_CASE("what we encode, we can parse");
    TEST_ASSERT(quic_invariants_parse(out, n, 8, &inv) == QUICINV_OK, "round trip");
    TEST_ASSERT(quic_invariants_is_version_negotiation(&inv), "reads back as VN");
    TEST_ASSERT(inv.dcid.len == 3 && inv.scid.len == 2, "ids round trip");

    TEST_CASE("refuses to overflow the buffer");
    TEST_ASSERT(quic_invariants_write_version_negotiation(out, 5, &dcid, &scid,
                                                          0, versions, 2) == 0,
                "buffer too small");
    TEST_ASSERT(quic_invariants_write_version_negotiation(out, sizeof out, &dcid,
                                                          &scid, 0, versions, 0) == 0,
                "no versions offered");
}

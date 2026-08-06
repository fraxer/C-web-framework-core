#include "framework.h"

#include "quicpacket.h"

#include <string.h>

/* QUIC v1 packet headers (RFC 9000 §17, Appendix A.2/A.3).
 *
 * Everything here runs on bytes no key has authenticated yet: a hostile peer
 * chooses every length in the header. The Length field is the sharpest of them
 * -- it is what would walk a reader off the end of the datagram. */

static quiccid_t cid_of(const char* bytes, uint8_t len) {
    quiccid_t cid = { .len = len };
    memcpy(cid.data, bytes, len);
    return cid;
}

TEST(test_quic_packet_initial) {
    TEST_SUITE("quic_packet");

    TEST_CASE("Initial with a token");
    /* 0xc3 = long, fixed, type 0 (Initial), pn length 4 (protected, ignored) */
    const uint8_t pkt[] = {
        0xc3,
        0x00, 0x00, 0x00, 0x01,
        0x04, 0xde, 0xad, 0xbe, 0xef,    /* dcid */
        0x02, 0x11, 0x22,                /* scid */
        0x03, 0xaa, 0xbb, 0xcc,          /* token length 3 + token */
        0x10,                            /* length = 16 */
        0x00, 0x00, 0x00, 0x01,          /* packet number (protected) */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   /* payload: 12 more, 16 total */
    };

    quicpkt_t p;
    TEST_ASSERT(quicpkt_parse(pkt, sizeof pkt, 8, &p) == QUICPKT_OK, "parses");
    TEST_ASSERT(p.type == QUIC_PKT_INITIAL, "type");
    TEST_ASSERT(p.version == QUIC_VERSION_1, "version");
    TEST_ASSERT(p.dcid.len == 4 && memcmp(p.dcid.data, "\xde\xad\xbe\xef", 4) == 0, "dcid");
    TEST_ASSERT(p.scid.len == 2, "scid");
    TEST_ASSERT(p.token_len == 3 && memcmp(p.token, "\xaa\xbb\xcc", 3) == 0, "token");
    TEST_ASSERT(p.length == 16, "length field");
    TEST_ASSERT(p.pn_offset == 18, "packet number offset");
    TEST_ASSERT(p.pkt_len == 34, "total packet length");
    TEST_ASSERT(quicpkt_level(p.type) == QUIC_ENC_INITIAL, "encryption level");

    TEST_CASE("Initial with an empty token");
    const uint8_t no_token[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00,          /* both ids empty */
        0x00,                /* token length 0 */
        0x05,                /* length 5 */
        0x01, 0x02, 0x03, 0x04, 0x05
    };
    TEST_ASSERT(quicpkt_parse(no_token, sizeof no_token, 8, &p) == QUICPKT_OK, "parses");
    TEST_ASSERT(p.token_len == 0 && p.token == NULL, "no token");
    TEST_ASSERT(p.pkt_len == sizeof no_token, "consumes the datagram");
}

TEST(test_quic_packet_forms) {
    TEST_SUITE("quic_packet");

    quicpkt_t p;

    TEST_CASE("Handshake");
    const uint8_t hs[] = {
        0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04
    };
    TEST_ASSERT(quicpkt_parse(hs, sizeof hs, 8, &p) == QUICPKT_OK, "parses");
    TEST_ASSERT(p.type == QUIC_PKT_HANDSHAKE, "type");
    TEST_ASSERT(quicpkt_level(p.type) == QUIC_ENC_HANDSHAKE, "level");
    /* No token field on Handshake -- reading one would shift every later
     * offset by the size of a varint. */
    TEST_ASSERT(p.length == 4 && p.pn_offset == 8, "length and pn offset");

    TEST_CASE("0-RTT");
    const uint8_t zero[] = {
        0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0xaa, 0xbb
    };
    TEST_ASSERT(quicpkt_parse(zero, sizeof zero, 8, &p) == QUICPKT_OK, "parses");
    TEST_ASSERT(p.type == QUIC_PKT_0RTT, "type");
    TEST_ASSERT(quicpkt_level(p.type) == QUIC_ENC_EARLY, "level");

    TEST_CASE("Retry carries no length and no packet number");
    uint8_t retry[5 + 2 + 4 + 16];
    memset(retry, 0, sizeof retry);
    retry[0] = 0xf0;
    retry[4] = 0x01;                       /* version 1 */
    retry[5] = 0x00; retry[6] = 0x00;      /* both ids empty */
    memcpy(retry + 7, "TOKN", 4);
    TEST_ASSERT(quicpkt_parse(retry, sizeof retry, 8, &p) == QUICPKT_OK, "parses");
    TEST_ASSERT(p.type == QUIC_PKT_RETRY, "type");
    TEST_ASSERT(p.token_len == 4 && memcmp(p.token, "TOKN", 4) == 0, "token");
    TEST_ASSERT(p.pn_offset == 0, "no packet number");
    TEST_ASSERT(p.pkt_len == sizeof retry, "runs to the end of the datagram");

    TEST_CASE("short header");
    const uint8_t sh[] = { 0x40, 1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb };
    TEST_ASSERT(quicpkt_parse(sh, sizeof sh, 8, &p) == QUICPKT_OK, "parses");
    TEST_ASSERT(p.type == QUIC_PKT_SHORT, "type");
    TEST_ASSERT(p.dcid.len == 8, "dcid from the endpoint's own length");
    TEST_ASSERT(p.pn_offset == 9, "pn offset");
    TEST_ASSERT(p.pkt_len == sizeof sh, "runs to the end of the datagram");
    TEST_ASSERT(quicpkt_level(p.type) == QUIC_ENC_APP, "level");
}

TEST(test_quic_packet_malformed) {
    TEST_SUITE("quic_packet");

    quicpkt_t p;

    TEST_CASE("the fixed bit must be set");
    /* §17.2/17.3 require it, and it is outside the header protection mask, so
     * a packet without it is refusable before any key exists. */
    const uint8_t no_fixed_long[] = { 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00 };
    TEST_ASSERT(quicpkt_parse(no_fixed_long, sizeof no_fixed_long, 8, &p) == QUICPKT_BAD_FORM,
                "long header");
    const uint8_t no_fixed_short[] = { 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 0xaa };
    TEST_ASSERT(quicpkt_parse(no_fixed_short, sizeof no_fixed_short, 8, &p) == QUICPKT_BAD_FORM,
                "short header");

    TEST_CASE("a Length that runs past the datagram");
    /* The single most dangerous field in the header: honouring it blindly
     * reads off the end of an attacker-controlled buffer. */
    const uint8_t overlong[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7f, 0x01, 0x02
    };
    TEST_ASSERT(quicpkt_parse(overlong, sizeof overlong, 8, &p) == QUICPKT_SHORT_BUFFER,
                "refused");

    TEST_CASE("a token length that runs past the datagram");
    const uint8_t overlong_token[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x3f, 0xaa, 0xbb
    };
    TEST_ASSERT(quicpkt_parse(overlong_token, sizeof overlong_token, 8, &p)
                == QUICPKT_SHORT_BUFFER, "refused");

    TEST_CASE("a Length of zero leaves no room for the packet number");
    const uint8_t zero_len[] = { 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    TEST_ASSERT(quicpkt_parse(zero_len, sizeof zero_len, 8, &p) == QUICPKT_BAD_FORM,
                "refused");

    TEST_CASE("connection id longer than version 1 allows");
    const uint8_t big_cid[] = { 0xc0, 0x00, 0x00, 0x00, 0x01, 21 };
    TEST_ASSERT(quicpkt_parse(big_cid, sizeof big_cid, 8, &p) == QUICPKT_BAD_FORM, "refused");

    TEST_CASE("every proper prefix of a valid packet is refused");
    const uint8_t good[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0xaa, 0xbb, 0x01, 0xcc, 0x00, 0x03,
        0x01, 0x02, 0x03
    };
    int all_refused = 1;
    for (size_t n = 1; n < sizeof good; n++)
        if (quicpkt_parse(good, n, 8, &p) == QUICPKT_OK) all_refused = 0;
    TEST_ASSERT(all_refused, "no prefix parses");
    TEST_ASSERT(quicpkt_parse(good, sizeof good, 8, &p) == QUICPKT_OK, "the whole thing does");

    TEST_CASE("unsupported version and version negotiation are distinguished");
    const uint8_t other_version[] = {
        0xc0, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01, 0x00
    };
    TEST_ASSERT(quicpkt_parse(other_version, sizeof other_version, 8, &p)
                == QUICPKT_UNSUPPORTED_VERSION, "unsupported version");

    const uint8_t vn[] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    TEST_ASSERT(quicpkt_parse(vn, sizeof vn, 8, &p) == QUICPKT_VERSION_NEGOTIATION,
                "version negotiation");
}

TEST(test_quic_packet_coalescing) {
    TEST_SUITE("quic_packet");

    TEST_CASE("Initial + Handshake + short header in one datagram");
    /* §12.2. Getting the Length arithmetic wrong here loses every packet after
     * the first, which looks like packet loss rather than a parsing bug. */
    uint8_t dgram[64];
    size_t n = 0;

    const uint8_t initial[] = { 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 1, 2, 3 };
    memcpy(dgram + n, initial, sizeof initial); n += sizeof initial;

    const uint8_t hs[] = { 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 4, 5 };
    memcpy(dgram + n, hs, sizeof hs); n += sizeof hs;

    const uint8_t sh[] = { 0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    memcpy(dgram + n, sh, sizeof sh); n += sizeof sh;

    size_t off = 0;
    quicpkt_t p;
    quicpkt_status_e st = QUICPKT_OK;

    TEST_ASSERT(quicpkt_next(dgram, n, &off, 8, &p, &st) == 1, "first");
    TEST_ASSERT(p.type == QUIC_PKT_INITIAL && off == sizeof initial, "Initial consumed");

    TEST_ASSERT(quicpkt_next(dgram, n, &off, 8, &p, &st) == 1, "second");
    TEST_ASSERT(p.type == QUIC_PKT_HANDSHAKE, "Handshake");

    TEST_ASSERT(quicpkt_next(dgram, n, &off, 8, &p, &st) == 1, "third");
    TEST_ASSERT(p.type == QUIC_PKT_SHORT, "short header");
    TEST_ASSERT(off == n, "datagram consumed");

    TEST_ASSERT(quicpkt_next(dgram, n, &off, 8, &p, &st) == 0, "iteration ends");

    TEST_CASE("padding after the last packet ends the walk");
    /* Zero bytes have the fixed bit clear, so they cannot start a packet; they
     * are the padding that brings an Initial datagram up to 1200 bytes. */
    memset(dgram + n, 0, sizeof dgram - n);
    off = 0;
    int count = 0;
    while (quicpkt_next(dgram, sizeof dgram, &off, 8, &p, &st)) count++;
    TEST_ASSERT(count == 3, "three packets, padding ignored");
    TEST_ASSERT(st == QUICPKT_OK, "no error reported");
}

TEST(test_quic_packet_numbers) {
    TEST_SUITE("quic_packet");

    TEST_CASE("Appendix A.2 worked examples");
    /* The RFC states these as "two bytes" and "three bytes". */
    TEST_ASSERT(quicpkt_pn_length(0xac5c02, 0xabe8b3) == 2, "0xac5c02 after 0xabe8b3");
    TEST_ASSERT(quicpkt_pn_length(0xace8fe, 0xabe8b3) == 3, "0xace8fe after 0xabe8b3");

    TEST_CASE("the power-of-two boundary");
    /* The RFC's formula is written over real logarithms; read with integer
     * logs it is off by one exactly here, which costs a byte on every packet. */
    TEST_ASSERT(quicpkt_pn_length(128, 0) == 1, "128 unacknowledged fits one byte");
    TEST_ASSERT(quicpkt_pn_length(129, 0) == 2, "129 does not");
    TEST_ASSERT(quicpkt_pn_length(32768, 0) == 2, "2^15 fits two bytes");
    TEST_ASSERT(quicpkt_pn_length(32769, 0) == 3, "one more does not");
    TEST_ASSERT(quicpkt_pn_length(1ULL << 40, 0) == 4, "clamped at four");

    TEST_CASE("nothing acknowledged yet");
    TEST_ASSERT(quicpkt_pn_length(0, QUICPKT_NO_ACKED) == 1, "first packet");

    TEST_CASE("Appendix A.3 worked example");
    /* largest_pn 0xa82f30ea, truncated 0x9b32, two bytes -> 0xa82f9b32. */
    TEST_ASSERT(quicpkt_decode_pn(0xa82f30eaULL, 0x9b32, 2) == 0xa82f9b32ULL, "decodes");

    TEST_CASE("wrap in both directions");
    /* Truncated 0x01 just after 0xff must be the next packet, not 254 back. */
    TEST_ASSERT(quicpkt_decode_pn(0xff, 0x01, 1) == 0x101, "forward across a window");
    /* And a straggler just below the window must not jump forward. */
    TEST_ASSERT(quicpkt_decode_pn(0x100, 0xff, 1) == 0xff, "backward");

    TEST_CASE("early in a connection, where expected < half a window");
    /* expected - pn_hwin underflows in the RFC's pseudocode translated
     * literally; the result must still be the small number it looks like. */
    TEST_ASSERT(quicpkt_decode_pn(0, 1, 4) == 1, "second packet");
    TEST_ASSERT(quicpkt_decode_pn(0, 0, 1) == 0, "duplicate of the first");
    TEST_ASSERT(quicpkt_decode_pn(2, 3, 4) == 3, "third");

    TEST_CASE("round trip over a long run");
    int all_ok = 1;
    uint64_t largest = 0;
    for (uint64_t pn = 1; pn < 5000; pn++) {
        const size_t len = quicpkt_pn_length(pn, largest);
        const uint64_t truncated = pn & ((1ULL << (8 * len)) - 1);
        if (quicpkt_decode_pn(largest, truncated, len) != pn) all_ok = 0;
        largest = pn; /* peer acknowledges promptly */
    }
    TEST_ASSERT(all_ok, "every packet number recovers");
}

TEST(test_quic_packet_write) {
    TEST_SUITE("quic_packet");

    uint8_t buf[128];
    size_t pn_offset = 0;
    quicpkt_t p;

    TEST_CASE("long header round trip");
    const quiccid_t dcid = cid_of("\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    const quiccid_t scid = cid_of("\xaa\xbb", 2);
    const uint8_t token[] = { 0xde, 0xad };

    quicpkt_hdr_out_t hdr = {
        .type = QUIC_PKT_INITIAL,
        .version = QUIC_VERSION_1,
        .dcid = &dcid,
        .scid = &scid,
        .token = token,
        .token_len = sizeof token,
        .pn = 0x1234,
        .pn_len = 2,
        .payload_len = 20
    };

    size_t n = quicpkt_write_header(buf, sizeof buf, &hdr, &pn_offset);
    TEST_ASSERT(n > 0, "written");
    /* Fill the payload the Length promised so the parser sees a whole packet. */
    memset(buf + n, 0, 20);

    TEST_ASSERT(quicpkt_parse(buf, n + 20, 8, &p) == QUICPKT_OK, "parses back");
    TEST_ASSERT(p.type == QUIC_PKT_INITIAL, "type");
    TEST_ASSERT(p.dcid.len == 8 && p.scid.len == 2, "ids");
    TEST_ASSERT(p.token_len == 2 && memcmp(p.token, token, 2) == 0, "token");
    /* Length covers the packet number as well as the payload. */
    TEST_ASSERT(p.length == 22, "length = pn + payload");
    TEST_ASSERT(p.pn_offset == pn_offset, "reported pn offset agrees");
    TEST_ASSERT(buf[pn_offset] == 0x12 && buf[pn_offset + 1] == 0x34, "pn big endian");
    TEST_ASSERT((buf[0] & 0x03) == 1, "pn length encoded as len-1");

    TEST_CASE("short header round trip");
    quicpkt_hdr_out_t sh = {
        .type = QUIC_PKT_SHORT,
        .dcid = &dcid,
        .pn = 0x7f,
        .pn_len = 1,
        .key_phase = 1
    };
    n = quicpkt_write_header(buf, sizeof buf, &sh, &pn_offset);
    TEST_ASSERT(n == 1 + 8 + 1, "length");
    TEST_ASSERT((buf[0] & 0x80) == 0 && (buf[0] & 0x40) != 0, "form and fixed bit");
    TEST_ASSERT((buf[0] & 0x04) != 0, "key phase");
    TEST_ASSERT(pn_offset == 9, "pn offset");

    TEST_CASE("a reserved-width Length field, for patching later");
    hdr.length_field_bytes = 4;
    n = quicpkt_write_header(buf, sizeof buf, &hdr, &pn_offset);
    memset(buf + n, 0, 20);
    TEST_ASSERT(quicpkt_parse(buf, n + 20, 8, &p) == QUICPKT_OK, "parses back");
    TEST_ASSERT(p.length == 22, "same value in a wider field");
    hdr.length_field_bytes = 0;

    TEST_CASE("refuses what it cannot write");
    TEST_ASSERT(quicpkt_write_header(buf, 4, &hdr, &pn_offset) == 0, "buffer too small");
    hdr.pn_len = 0;
    TEST_ASSERT(quicpkt_write_header(buf, sizeof buf, &hdr, &pn_offset) == 0, "pn length 0");
    hdr.pn_len = 5;
    TEST_ASSERT(quicpkt_write_header(buf, sizeof buf, &hdr, &pn_offset) == 0, "pn length 5");
    hdr.pn_len = 2;
    hdr.type = QUIC_PKT_RETRY;
    TEST_ASSERT(quicpkt_write_header(buf, sizeof buf, &hdr, &pn_offset) == 0,
                "Retry is not written here");
}

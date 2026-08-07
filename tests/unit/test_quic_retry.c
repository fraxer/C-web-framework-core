#include "framework.h"

#include "quicretry.h"

#include <arpa/inet.h>
#include <string.h>

/* Retry packets and address validation tokens (RFC 9000 §8, RFC 9001 §5.8).
 *
 * These are the anti-amplification machinery: everything here exists so that a
 * server cannot be pointed at a victim by an attacker spoofing its address. */

static int from_hex(const char* hex, uint8_t* out, size_t out_cap) {
    size_t n = 0;

    for (const char* p = hex; *p != '\0'; ) {
        while (*p == ' ' || *p == '\n') p++;
        if (*p == '\0') break;
        if (p[1] == '\0' || n >= out_cap) return -1;

        int hi = -1, lo = -1;
        for (int i = 0; i < 16; i++) {
            const char c = "0123456789abcdef"[i];
            if (p[0] == c) hi = i;
            if (p[1] == c) lo = i;
        }
        if (hi < 0 || lo < 0) return -1;

        out[n++] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }

    return (int)n;
}

static struct sockaddr_in addr_v4(const char* ip, uint16_t port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    return sa;
}

TEST(test_quic_retry_integrity) {
    TEST_SUITE("quic_retry");

    TEST_CASE("RFC 9001 A.4: the Retry integrity tag");
    /* The RFC gives a complete Retry packet. The tag is computed over a pseudo
     * packet that prefixes the original connection id -- forgetting that prefix
     * produces a tag that is wrong in a way only a vector reveals. */
    quiccid_t odcid = { .len = 8 };
    TEST_REQUIRE(from_hex("8394c8f03e515708", odcid.data, sizeof odcid.data) == 8, "odcid");

    uint8_t packet[64];
    const int packet_len = from_hex(
        "ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f"
        "0f2496ba", packet, sizeof packet);
    TEST_REQUIRE(packet_len == 36, "retry packet hex");

    /* The last 16 bytes are the tag; recompute them over the rest. */
    uint8_t tag[16];
    TEST_REQUIRE(quicretry_integrity_tag(&odcid, packet, (size_t)packet_len - 16, tag),
                 "computed");
    TEST_ASSERT(memcmp(tag, packet + packet_len - 16, 16) == 0, "matches the RFC");

    TEST_CASE("a different original connection id gives a different tag");
    /* This is the whole point of the construction: only someone who saw the
     * client's original connection id can produce a valid Retry. */
    quiccid_t other = odcid;
    other.data[0] ^= 0x01;
    uint8_t other_tag[16];
    TEST_REQUIRE(quicretry_integrity_tag(&other, packet, (size_t)packet_len - 16, other_tag),
                 "computed");
    TEST_ASSERT(memcmp(tag, other_tag, 16) != 0, "tags differ");

    TEST_CASE("building a Retry produces a verifiable one");
    quiccid_t dcid = { .len = 4 };
    memcpy(dcid.data, "\x01\x02\x03\x04", 4);
    quiccid_t scid = { .len = 8 };
    memcpy(scid.data, "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7", 8);
    const uint8_t token[] = "opaque-token";

    uint8_t built[128];
    const size_t n = quicretry_write(built, sizeof built, &odcid, &dcid, &scid,
                                     token, sizeof token);
    TEST_ASSERT(n > 0, "written");
    TEST_ASSERT((built[0] & 0xf0) == 0xf0, "long header, fixed bit, type Retry");
    TEST_ASSERT(memcmp(built + 1, "\x00\x00\x00\x01", 4) == 0, "version 1");

    uint8_t check[16];
    TEST_ASSERT(quicretry_integrity_tag(&odcid, built, n - 16, check), "recomputed");
    TEST_ASSERT(memcmp(check, built + n - 16, 16) == 0, "self-consistent");

    TEST_CASE("refuses what it cannot write");
    TEST_ASSERT(quicretry_write(built, 8, &odcid, &dcid, &scid, token, sizeof token) == 0,
                "buffer too small");
    TEST_ASSERT(quicretry_write(built, sizeof built, &odcid, &dcid, &scid, NULL, 0) == 0,
                "a Retry with no token is pointless");
}

TEST(test_quic_token) {
    TEST_SUITE("quic_retry");

    uint8_t key[32];
    memset(key, 0x7e, sizeof key);

    struct sockaddr_in peer = addr_v4("192.0.2.10", 44444);
    quiccid_t odcid = { .len = 8 };
    memcpy(odcid.data, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);

    const uint64_t now = 1000000000ULL;          /* an arbitrary monotonic point */
    const uint64_t retry_life = 30ULL * 1000000; /* 30 s */

    uint8_t token[QUIC_TOKEN_MAX_LEN];

    TEST_CASE("a Retry token round trips and carries the original connection id");
    /* The odcid is what the retried handshake derives its Initial keys from, so
     * losing it breaks the connection in a way that looks like a crypto bug. */
    const size_t n = quic_token_write(token, sizeof token, key, QUIC_TOKEN_RETRY,
                                      (struct sockaddr*)&peer, sizeof peer, &odcid, now);
    TEST_ASSERT(n > 0, "written");
    TEST_ASSERT(n <= QUIC_TOKEN_MAX_LEN, "within the declared maximum");

    quiccid_t back;
    memset(&back, 0, sizeof back);
    TEST_ASSERT(quic_token_read(token, n, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&peer, sizeof peer,
                                now + 1000, retry_life, &back) == QUIC_TOKEN_OK,
                "accepted");
    TEST_ASSERT(back.len == 8 && memcmp(back.data, odcid.data, 8) == 0, "odcid recovered");

    TEST_CASE("tokens are opaque and unforgeable");
    /* Flipping any byte must fail: the whole token is under the AEAD. */
    int all_rejected = 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t bad[QUIC_TOKEN_MAX_LEN];
        memcpy(bad, token, n);
        bad[i] ^= 0x01;
        if (quic_token_read(bad, n, key, QUIC_TOKEN_RETRY,
                            (struct sockaddr*)&peer, sizeof peer,
                            now, retry_life, NULL) == QUIC_TOKEN_OK) all_rejected = 0;
    }
    TEST_ASSERT(all_rejected, "every single-bit change is rejected");

    TEST_CASE("a token from another server's key is rejected");
    uint8_t other_key[32];
    memset(other_key, 0x11, sizeof other_key);
    TEST_ASSERT(quic_token_read(token, n, other_key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&peer, sizeof peer,
                                now, retry_life, NULL) == QUIC_TOKEN_BAD,
                "rejected");

    TEST_CASE("expiry");
    TEST_ASSERT(quic_token_read(token, n, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&peer, sizeof peer,
                                now + retry_life - 1, retry_life, NULL) == QUIC_TOKEN_OK,
                "inside the window");
    TEST_ASSERT(quic_token_read(token, n, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&peer, sizeof peer,
                                now + retry_life + 1, retry_life, NULL) == QUIC_TOKEN_EXPIRED,
                "past it");

    TEST_CASE("a token presented from a different address");
    struct sockaddr_in elsewhere = addr_v4("198.51.100.7", 44444);
    TEST_ASSERT(quic_token_read(token, n, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&elsewhere, sizeof elsewhere,
                                now, retry_life, NULL) == QUIC_TOKEN_WRONG_ADDR,
                "rejected");

    TEST_CASE("the port may change, the address may not");
    /* A client behind NAT gets a new port routinely; requiring the port to
     * match would make NEW_TOKEN useless to the clients it helps most. */
    struct sockaddr_in same_ip = addr_v4("192.0.2.10", 55555);
    TEST_ASSERT(quic_token_read(token, n, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&same_ip, sizeof same_ip,
                                now, retry_life, NULL) == QUIC_TOKEN_OK,
                "same address, different port");

    TEST_CASE("the two kinds are not interchangeable");
    /* A Retry token says "this handshake reached you"; a NEW_TOKEN says "your
     * address was good some time ago". Accepting one for the other would let a
     * client skip a Retry it was asked for. */
    TEST_ASSERT(quic_token_read(token, n, key, QUIC_TOKEN_NEW_TOKEN,
                                (struct sockaddr*)&peer, sizeof peer,
                                now, retry_life, NULL) == QUIC_TOKEN_WRONG_KIND,
                "a Retry token offered as a NEW_TOKEN");

    const size_t m = quic_token_write(token, sizeof token, key, QUIC_TOKEN_NEW_TOKEN,
                                      (struct sockaddr*)&peer, sizeof peer, NULL, now);
    TEST_ASSERT(m > 0, "NEW_TOKEN written without an odcid");
    TEST_ASSERT(quic_token_read(token, m, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&peer, sizeof peer,
                                now, retry_life, NULL) == QUIC_TOKEN_WRONG_KIND,
                "and the reverse");
    TEST_ASSERT(quic_token_read(token, m, key, QUIC_TOKEN_NEW_TOKEN,
                                (struct sockaddr*)&peer, sizeof peer,
                                now, retry_life, NULL) == QUIC_TOKEN_OK,
                "but works as itself");

    TEST_CASE("IPv6");
    struct sockaddr_in6 peer6;
    memset(&peer6, 0, sizeof peer6);
    peer6.sin6_family = AF_INET6;
    peer6.sin6_port = htons(443);
    inet_pton(AF_INET6, "2001:db8::1", &peer6.sin6_addr);

    const size_t k = quic_token_write(token, sizeof token, key, QUIC_TOKEN_NEW_TOKEN,
                                      (struct sockaddr*)&peer6, sizeof peer6, NULL, now);
    TEST_ASSERT(k > 0, "written");
    TEST_ASSERT(quic_token_read(token, k, key, QUIC_TOKEN_NEW_TOKEN,
                                (struct sockaddr*)&peer6, sizeof peer6,
                                now, retry_life, NULL) == QUIC_TOKEN_OK, "accepted");
    /* An IPv4 client must not match an IPv6-issued token. */
    TEST_ASSERT(quic_token_read(token, k, key, QUIC_TOKEN_NEW_TOKEN,
                                (struct sockaddr*)&peer, sizeof peer,
                                now, retry_life, NULL) == QUIC_TOKEN_WRONG_ADDR,
                "and does not match an IPv4 peer");

    TEST_CASE("malformed tokens");
    TEST_ASSERT(quic_token_read(NULL, 40, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&peer, sizeof peer,
                                now, retry_life, NULL) == QUIC_TOKEN_BAD, "NULL");
    TEST_ASSERT(quic_token_read(token, 4, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&peer, sizeof peer,
                                now, retry_life, NULL) == QUIC_TOKEN_BAD, "too short");
    TEST_ASSERT(quic_token_read(token, QUIC_TOKEN_MAX_LEN + 1, key, QUIC_TOKEN_RETRY,
                                (struct sockaddr*)&peer, sizeof peer,
                                now, retry_life, NULL) == QUIC_TOKEN_BAD, "too long");

    TEST_CASE("a Retry token requires an original connection id");
    TEST_ASSERT(quic_token_write(token, sizeof token, key, QUIC_TOKEN_RETRY,
                                 (struct sockaddr*)&peer, sizeof peer, NULL, now) == 0,
                "refused");
}

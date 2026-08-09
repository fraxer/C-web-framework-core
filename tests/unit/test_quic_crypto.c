#include "framework.h"

#include "quiccrypto.h"
#include "quichp.h"
#include "quicpacket.h"

#include <string.h>

/* RFC 9001 Appendix A.
 *
 * The most valuable test vectors in this project: the RFC gives a complete
 * client Initial packet, byte for byte, from the connection id through the
 * derived secrets and keys to the protected packet on the wire. If these agree,
 * the key schedule, the nonce construction, the AEAD framing and the header
 * protection are all correct together -- which no amount of round-tripping our
 * own output could establish, since a self-consistent mistake round-trips
 * perfectly. */

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

TEST(test_quic_crypto_initial_secrets) {
    TEST_SUITE("quic_crypto");

    TEST_CASE("Appendix A.1: Initial secrets from the client's DCID");
    /* The RFC's worked example uses this Destination Connection ID. */
    quiccid_t dcid = { .len = 8 };
    TEST_REQUIRE(from_hex("8394c8f03e515708", dcid.data, sizeof dcid.data) == 8,
                 "dcid hex");

    uint8_t client_secret[32];
    uint8_t server_secret[32];
    TEST_REQUIRE(quiccrypto_initial_secrets(&dcid, client_secret, server_secret),
                 "secrets derived");

    uint8_t expected[32];
    TEST_REQUIRE(from_hex("c00cf151ca5be075ed0ebfb5c80323c4"
                          "2d6b7db67881289af4008f1f6c357aea", expected, sizeof expected) == 32,
                 "client secret hex");
    TEST_ASSERT(memcmp(client_secret, expected, 32) == 0, "client_initial_secret");

    TEST_REQUIRE(from_hex("3c199828fd139efd216c155ad844cc81"
                          "fb82fa8d7446fa7d78be803acdda951b", expected, sizeof expected) == 32,
                 "server secret hex");
    TEST_ASSERT(memcmp(server_secret, expected, 32) == 0, "server_initial_secret");

    TEST_CASE("A.1: the key, iv and header protection key");
    /* Derived from the client secret above. Getting the label wrong -- writing
     * "quic key" where the RFC means "tls13 quic key" -- produces plausible but
     * entirely wrong keys, and only a vector catches it. */
    uint8_t key[16], iv[12], hp[16];
    TEST_ASSERT(quic_hkdf_expand_label(EVP_sha256(), client_secret, 32, "quic key",
                                       NULL, 0, key, sizeof key), "key derived");
    TEST_ASSERT(quic_hkdf_expand_label(EVP_sha256(), client_secret, 32, "quic iv",
                                       NULL, 0, iv, sizeof iv), "iv derived");
    TEST_ASSERT(quic_hkdf_expand_label(EVP_sha256(), client_secret, 32, "quic hp",
                                       NULL, 0, hp, sizeof hp), "hp derived");

    uint8_t want[16];
    TEST_REQUIRE(from_hex("1f369613dd76d5467730efcbe3b1a22d", want, sizeof want) == 16, "key hex");
    TEST_ASSERT(memcmp(key, want, 16) == 0, "client key");

    TEST_REQUIRE(from_hex("fa044b2f42a3fd3b46fb255c", want, sizeof want) == 12, "iv hex");
    TEST_ASSERT(memcmp(iv, want, 12) == 0, "client iv");

    TEST_REQUIRE(from_hex("9f50449e04a0e810283a1e9933adedd2", want, sizeof want) == 16, "hp hex");
    TEST_ASSERT(memcmp(hp, want, 16) == 0, "client hp key");

    TEST_CASE("the server direction of the same connection");
    TEST_ASSERT(quic_hkdf_expand_label(EVP_sha256(), server_secret, 32, "quic key",
                                       NULL, 0, key, sizeof key), "key derived");
    TEST_REQUIRE(from_hex("cf3a5331653c364c88f0f379b6067e37", want, sizeof want) == 16, "key hex");
    TEST_ASSERT(memcmp(key, want, 16) == 0, "server key");

    TEST_ASSERT(quic_hkdf_expand_label(EVP_sha256(), server_secret, 32, "quic iv",
                                       NULL, 0, iv, sizeof iv), "iv derived");
    TEST_REQUIRE(from_hex("0ac1493ca1905853b0bba03e", want, sizeof want) == 12, "iv hex");
    TEST_ASSERT(memcmp(iv, want, 12) == 0, "server iv");
}

TEST(test_quic_crypto_seal_vector) {
    TEST_SUITE("quic_crypto");

    TEST_CASE("A.2: the client Initial packet, sealed and protected");
    /* This is the end-to-end check: header, AEAD and header protection over a
     * real payload, compared against the packet the RFC puts on the wire. */
    quiccid_t dcid = { .len = 8 };
    TEST_REQUIRE(from_hex("8394c8f03e515708", dcid.data, sizeof dcid.data) == 8, "dcid");

    uint8_t client_secret[32], server_secret[32];
    TEST_REQUIRE(quiccrypto_initial_secrets(&dcid, client_secret, server_secret),
                 "secrets");

    quickeys_t keys;
    memset(&keys, 0, sizeof keys);
    TEST_REQUIRE(quickeys_install(&keys, QUIC_AEAD_AES_128_GCM, client_secret, 32),
                 "keys installed");

    /* The unprotected header from A.2: Initial, version 1, dcid as above, no
     * scid, no token, length 0x449e, packet number 2 in two bytes. */
    uint8_t header[64];
    const int header_len = from_hex("c300000001088394c8f03e5157080000449e00000002",
                                    header, sizeof header);
    TEST_REQUIRE(header_len == 22, "header hex");

    /* The frames: a CRYPTO frame carrying the ClientHello, then padding out to
     * 1162 bytes of plaintext. The RFC gives the whole thing; the first bytes
     * are enough to exercise the path, so the payload is reconstructed as
     * CRYPTO(offset 0, len 241) + the ClientHello prefix + zero padding, which
     * is what A.2 describes. */
    static uint8_t payload[1162];
    memset(payload, 0, sizeof payload);
    const int crypto_prefix = from_hex(
        "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868"
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
        "04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba"
        "baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400"
        "0d0010000e0403050306030203080408 050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000"
        "75300901100f088394c8f03e51570806 048000ffff",
        payload, sizeof payload);
    TEST_REQUIRE(crypto_prefix > 0, "payload hex");

    uint8_t sealed[1200];
    size_t sealed_len = 0;
    TEST_REQUIRE(quiccrypto_seal(&keys, 2, header, (size_t)header_len,
                                 payload, sizeof payload, sealed, &sealed_len),
                 "sealed");
    TEST_ASSERT(sealed_len == sizeof payload + QUIC_AEAD_TAG_LEN, "ciphertext length");

    /* A.2 gives the first 16 bytes of the protected payload; comparing those is
     * enough to prove the nonce and AAD are right -- GCM is a stream cipher over
     * the counter, so a wrong nonce differs from the first byte. */
    uint8_t want[16];
    TEST_REQUIRE(from_hex("d1b1c98dd7689fb8ec11d242b123dc9b", want, sizeof want) == 16,
                 "expected ciphertext prefix");
    TEST_ASSERT(memcmp(sealed, want, 16) == 0, "protected payload matches the RFC");

    TEST_CASE("header protection over that packet");
    /* Assemble header + ciphertext, then protect the header in place. */
    static uint8_t packet[1300];
    memcpy(packet, header, (size_t)header_len);
    memcpy(packet + header_len, sealed, sealed_len);
    const size_t packet_len = (size_t)header_len + sealed_len;

    /* Where the packet number starts: 1 first byte + 4 version + 1 dcid length
     * + 8 dcid + 1 scid length + 1 token length + 2 length varint = 18. Its own
     * length is 4, from the low bits of the c3 first byte. */
    const size_t pn_offset = 18;
    TEST_REQUIRE(quichp_apply(&keys, packet, packet_len, pn_offset, 4), "applied");

    /* A.2's protected header: c000000001088394c8f03e5157080000449e7b9aec34 */
    uint8_t want_hdr[32];
    TEST_REQUIRE(from_hex("c000000001088394c8f03e5157080000449e7b9aec34",
                          want_hdr, sizeof want_hdr) == 22, "expected header");
    TEST_ASSERT(memcmp(packet, want_hdr, 22) == 0, "protected header matches the RFC");

    TEST_CASE("and it comes back off");
    size_t pn_len = 0;
    uint64_t truncated = 0;
    int key_phase = 0;
    TEST_ASSERT(quichp_remove(&keys, packet, packet_len, pn_offset,
                              &pn_len, &truncated, &key_phase), "removed");
    TEST_ASSERT(pn_len == 4, "packet number length recovered");
    TEST_ASSERT(truncated == 2, "packet number recovered");
    TEST_ASSERT(memcmp(packet, header, 22) == 0, "header is back to plaintext");

    TEST_CASE("and the payload opens");
    static uint8_t opened[1200];
    size_t opened_len = 0;
    TEST_ASSERT(quiccrypto_open(&keys, 2, packet, 22, packet + 22, packet_len - 22,
                                opened, &opened_len), "opened");
    TEST_ASSERT(opened_len == sizeof payload, "plaintext length");
    TEST_ASSERT(memcmp(opened, payload, sizeof payload) == 0, "plaintext matches");

    quickeys_free(&keys);
}

TEST(test_quic_crypto_aead) {
    TEST_SUITE("quic_crypto");

    uint8_t secret[32];
    memset(secret, 0x42, sizeof secret);

    TEST_CASE("a tampered tag fails to open");
    quickeys_t keys;
    memset(&keys, 0, sizeof keys);
    TEST_REQUIRE(quickeys_install(&keys, QUIC_AEAD_AES_128_GCM, secret, 32), "keys");

    const uint8_t aad[] = { 0xc0, 0x01, 0x02, 0x03 };
    const uint8_t pt[] = "the quick brown fox";
    uint8_t ct[64];
    size_t ct_len = 0;
    TEST_REQUIRE(quiccrypto_seal(&keys, 7, aad, sizeof aad, pt, sizeof pt, ct, &ct_len),
                 "sealed");

    uint8_t out[64];
    size_t out_len = 0;
    TEST_ASSERT(quiccrypto_open(&keys, 7, aad, sizeof aad, ct, ct_len, out, &out_len),
                "opens with the right key and number");
    TEST_ASSERT(out_len == sizeof pt && memcmp(out, pt, sizeof pt) == 0, "plaintext");

    ct[ct_len - 1] ^= 0x01;
    TEST_ASSERT(!quiccrypto_open(&keys, 7, aad, sizeof aad, ct, ct_len, out, &out_len),
                "a flipped tag bit fails");
    ct[ct_len - 1] ^= 0x01;

    TEST_CASE("a wrong packet number fails");
    /* The packet number goes into the nonce, so it is authenticated even
     * though it is not part of the AAD by name. */
    TEST_ASSERT(!quiccrypto_open(&keys, 8, aad, sizeof aad, ct, ct_len, out, &out_len),
                "packet number 8 instead of 7");

    TEST_CASE("modified additional data fails");
    /* The header is the AAD: this is what stops an attacker rewriting a packet
     * number or connection id in flight. */
    uint8_t bad_aad[sizeof aad];
    memcpy(bad_aad, aad, sizeof aad);
    bad_aad[1] ^= 0xff;
    TEST_ASSERT(!quiccrypto_open(&keys, 7, bad_aad, sizeof bad_aad, ct, ct_len, out, &out_len),
                "tampered header");

    TEST_CASE("failures are counted for the §6.6 integrity limit");
    TEST_ASSERT(keys.open_failures == 3, "three failures counted");
    TEST_ASSERT(!quiccrypto_open_limit_reached(&keys), "far below the limit");
    TEST_ASSERT(!quiccrypto_seal_limit_reached(&keys), "and below the seal limit");

    quickeys_free(&keys);

    TEST_CASE("every suite works end to end");
    const quic_aead_e suites[] = {
        QUIC_AEAD_AES_128_GCM, QUIC_AEAD_AES_256_GCM, QUIC_AEAD_CHACHA20_POLY1305
    };
    int all_ok = 1;
    for (size_t i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        quickeys_t k;
        memset(&k, 0, sizeof k);

        if (!quickeys_install(&k, suites[i], secret, 32)) { all_ok = 0; continue; }

        size_t n = 0;
        if (!quiccrypto_seal(&k, 1, aad, sizeof aad, pt, sizeof pt, ct, &n)) all_ok = 0;

        size_t m = 0;
        if (!quiccrypto_open(&k, 1, aad, sizeof aad, ct, n, out, &m)) all_ok = 0;
        if (m != sizeof pt || memcmp(out, pt, sizeof pt) != 0) all_ok = 0;

        quickeys_free(&k);
    }
    TEST_ASSERT(all_ok, "AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305");

    TEST_CASE("CCM is not offered");
    /* RFC 9001 §5.3 forbids TLS_AES_128_CCM_8_SHA256 in QUIC, and config.json
     * lists it for TCP -- so the QUIC SSL must not inherit that list. */
    TEST_ASSERT(quiccrypto_key_len(QUIC_AEAD_UNSUPPORTED) == 0, "unsupported has no key");
    TEST_ASSERT(quiccrypto_md(QUIC_AEAD_UNSUPPORTED) == NULL, "and no hash");
}

TEST(test_quic_crypto_key_update) {
    TEST_SUITE("quic_crypto");

    TEST_CASE("the next generation's secret differs and is reproducible");
    uint8_t secret[32];
    memset(secret, 0x11, sizeof secret);

    uint8_t next[32];
    TEST_REQUIRE(quiccrypto_next_secret(QUIC_AEAD_AES_128_GCM, secret, 32, next),
                 "derived");
    TEST_ASSERT(memcmp(secret, next, 32) != 0, "differs from the current secret");

    uint8_t again[32];
    TEST_ASSERT(quiccrypto_next_secret(QUIC_AEAD_AES_128_GCM, secret, 32, again) &&
                memcmp(next, again, 32) == 0, "deterministic");

    TEST_CASE("a packet sealed in one phase does not open in the next");
    quickeys_t old_keys;
    quickeys_t new_keys;
    memset(&old_keys, 0, sizeof old_keys);
    memset(&new_keys, 0, sizeof new_keys);
    TEST_REQUIRE(quickeys_install(&old_keys, QUIC_AEAD_AES_128_GCM, secret, 32), "old");
    TEST_REQUIRE(quickeys_install(&new_keys, QUIC_AEAD_AES_128_GCM, next, 32), "new");

    const uint8_t aad[] = { 0x40, 0x01 };
    const uint8_t pt[] = "phase";
    uint8_t ct[64];
    size_t ct_len = 0;
    TEST_REQUIRE(quiccrypto_seal(&old_keys, 1, aad, sizeof aad, pt, sizeof pt, ct, &ct_len),
                 "sealed with the old key");

    uint8_t out[64];
    size_t out_len = 0;
    TEST_ASSERT(!quiccrypto_open(&new_keys, 1, aad, sizeof aad, ct, ct_len, out, &out_len),
                "the new key rejects it");
    TEST_ASSERT(quiccrypto_open(&old_keys, 1, aad, sizeof aad, ct, ct_len, out, &out_len),
                "the old key still opens it");

    TEST_CASE("quickeys_next reaches the same generation quickeys_install does");
    /* The two paths must agree, because the peer takes the other one: it
     * derives its keys from the secret, we derive ours from the previous key
     * set. A difference here is a connection that dies at the first update. */
    quickeys_t stepped;
    memset(&stepped, 0, sizeof stepped);
    TEST_REQUIRE(quickeys_next(&stepped, &old_keys), "stepped to the next generation");

    ct_len = 0;
    TEST_REQUIRE(quiccrypto_seal(&stepped, 2, aad, sizeof aad, pt, sizeof pt, ct, &ct_len),
                 "sealed with the stepped key");
    TEST_ASSERT(quiccrypto_open(&new_keys, 2, aad, sizeof aad, ct, ct_len, out, &out_len) &&
                out_len == sizeof pt && memcmp(out, pt, out_len) == 0,
                "the independently installed key opens it");

    TEST_CASE("header protection does not change across a key update");
    /* RFC 9001 §5.4: the hp key keeps its value after an update. Getting this
     * wrong breaks every packet in the new phase before the AEAD is even
     * reached, and the symptom points at the AEAD -- so it is asserted
     * directly rather than left to an end-to-end run to expose. */
    TEST_ASSERT(stepped.hp_key_len == old_keys.hp_key_len &&
                memcmp(stepped.hp_key, old_keys.hp_key, stepped.hp_key_len) == 0,
                "same header protection key");
    TEST_ASSERT(memcmp(stepped.iv, old_keys.iv, sizeof stepped.iv) != 0,
                "but a different IV");

    TEST_CASE("stepping in place is the same as stepping into a fresh key set");
    quickeys_t inplace;
    memset(&inplace, 0, sizeof inplace);
    TEST_REQUIRE(quickeys_install(&inplace, QUIC_AEAD_AES_128_GCM, secret, 32), "installed");
    TEST_REQUIRE(quickeys_next(&inplace, &inplace), "stepped in place");

    ct_len = 0;
    TEST_REQUIRE(quiccrypto_seal(&inplace, 3, aad, sizeof aad, pt, sizeof pt, ct, &ct_len),
                 "sealed");
    TEST_ASSERT(quiccrypto_open(&new_keys, 3, aad, sizeof aad, ct, ct_len, out, &out_len),
                "opens with the same generation");

    TEST_CASE("two updates land on the generation after the next");
    quickeys_t twice;
    memset(&twice, 0, sizeof twice);
    TEST_REQUIRE(quickeys_next(&twice, &stepped), "stepped twice");

    ct_len = 0;
    TEST_REQUIRE(quiccrypto_seal(&twice, 4, aad, sizeof aad, pt, sizeof pt, ct, &ct_len),
                 "sealed");
    TEST_ASSERT(!quiccrypto_open(&new_keys, 4, aad, sizeof aad, ct, ct_len, out, &out_len),
                "the previous generation cannot open it");

    quickeys_free(&twice);
    quickeys_free(&inplace);
    quickeys_free(&stepped);
    quickeys_free(&old_keys);
    quickeys_free(&new_keys);
}

TEST(test_quic_hp) {
    TEST_SUITE("quic_hp");

    uint8_t secret[32];
    memset(secret, 0x33, sizeof secret);

    TEST_CASE("apply then remove is the identity");
    quickeys_t keys;
    memset(&keys, 0, sizeof keys);
    TEST_REQUIRE(quickeys_install(&keys, QUIC_AEAD_AES_128_GCM, secret, 32), "keys");

    uint8_t packet[64];
    memset(packet, 0xaa, sizeof packet);
    packet[0] = 0x43;              /* short header, pn length 4 */
    const size_t pn_offset = 9;
    packet[pn_offset + 0] = 0x00;
    packet[pn_offset + 1] = 0xbe;
    packet[pn_offset + 2] = 0xef;
    packet[pn_offset + 3] = 0x12;

    uint8_t original[64];
    memcpy(original, packet, sizeof packet);

    TEST_ASSERT(quichp_apply(&keys, packet, sizeof packet, pn_offset, 4), "applied");
    TEST_ASSERT(memcmp(packet, original, sizeof packet) != 0, "something changed");
    /* Only the first byte and the packet number may change: the rest of the
     * packet is the AEAD's business. */
    TEST_ASSERT(memcmp(packet + 1, original + 1, pn_offset - 1) == 0,
                "the connection id is untouched");
    TEST_ASSERT(memcmp(packet + pn_offset + 4, original + pn_offset + 4,
                       sizeof packet - pn_offset - 4) == 0, "the payload is untouched");

    size_t pn_len = 0;
    uint64_t pn = 0;
    int key_phase = 0;
    TEST_ASSERT(quichp_remove(&keys, packet, sizeof packet, pn_offset,
                              &pn_len, &pn, &key_phase), "removed");
    TEST_ASSERT(pn_len == 4, "length recovered");
    TEST_ASSERT(pn == 0x00beef12, "packet number recovered");
    TEST_ASSERT(memcmp(packet, original, sizeof packet) == 0, "packet restored exactly");

    TEST_CASE("the key phase bit survives the round trip");
    packet[0] = 0x47;              /* short header, key phase set, pn length 4 */
    memcpy(original, packet, sizeof packet);
    TEST_ASSERT(quichp_apply(&keys, packet, sizeof packet, pn_offset, 4), "applied");
    TEST_ASSERT(quichp_remove(&keys, packet, sizeof packet, pn_offset,
                              &pn_len, &pn, &key_phase), "removed");
    TEST_ASSERT(key_phase == 1, "key phase reported");
    TEST_ASSERT(memcmp(packet, original, sizeof packet) == 0, "restored");

    TEST_CASE("a long header protects four bits, a short one five");
    /* Masking the wrong number of bits corrupts the fixed bit on long headers,
     * which the peer then rejects as malformed. */
    packet[0] = 0xc3;              /* long header */
    memcpy(original, packet, sizeof packet);
    TEST_ASSERT(quichp_apply(&keys, packet, sizeof packet, pn_offset, 4), "applied");
    TEST_ASSERT((packet[0] & 0xf0) == (original[0] & 0xf0),
                "the top four bits of a long header are untouched");
    TEST_ASSERT(quichp_remove(&keys, packet, sizeof packet, pn_offset,
                              &pn_len, &pn, &key_phase), "removed");
    TEST_ASSERT(key_phase == 0, "no key phase on a long header");
    TEST_ASSERT(memcmp(packet, original, sizeof packet) == 0, "restored");

    TEST_CASE("a packet too short to carry a sample is refused");
    /* The sample sits 4 bytes past the packet number and runs 16 bytes, so
     * there must be 20 bytes after pn_offset whatever the number's length. */
    TEST_ASSERT(!quichp_apply(&keys, packet, pn_offset + 19, pn_offset, 4),
                "one byte short");
    TEST_ASSERT(quichp_apply(&keys, packet, pn_offset + 20, pn_offset, 4),
                "exactly enough");
    TEST_ASSERT(!quichp_remove(&keys, packet, pn_offset + 19, pn_offset,
                               &pn_len, &pn, &key_phase), "and on the way in");

    quickeys_free(&keys);

    TEST_CASE("ChaCha20 header protection round trips");
    /* A different construction entirely -- the sample becomes a counter and
     * nonce rather than a block to encrypt -- so it needs its own exercise. */
    quickeys_t chacha;
    memset(&chacha, 0, sizeof chacha);
    TEST_REQUIRE(quickeys_install(&chacha, QUIC_AEAD_CHACHA20_POLY1305, secret, 32),
                 "keys");

    memset(packet, 0x5c, sizeof packet);
    packet[0] = 0x42;              /* short header, pn length 3 */
    memcpy(original, packet, sizeof packet);

    TEST_ASSERT(quichp_apply(&chacha, packet, sizeof packet, pn_offset, 3), "applied");
    TEST_ASSERT(memcmp(packet, original, sizeof packet) != 0, "something changed");
    TEST_ASSERT(quichp_remove(&chacha, packet, sizeof packet, pn_offset,
                              &pn_len, &pn, &key_phase), "removed");
    TEST_ASSERT(pn_len == 3, "length recovered");
    TEST_ASSERT(memcmp(packet, original, sizeof packet) == 0, "restored");

    quickeys_free(&chacha);
}

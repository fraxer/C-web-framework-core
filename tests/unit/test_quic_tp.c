#include "framework.h"

#include "quictp.h"
#include "varint.h"

#include <string.h>

/* Transport parameters (RFC 9000 §18).
 *
 * These arrive inside the TLS handshake, so they are authenticated -- but they
 * set every limit the connection then runs under, and several of the checks in
 * §18.2 exist because the value would otherwise overflow arithmetic elsewhere
 * in the stack rather than merely be odd. */

/* Build one {id, length, value} triple. */
static size_t put(uint8_t* dst, uint64_t id, const uint8_t* value, size_t len) {
    size_t p = 0;
    p += varint_write(dst + p, 32, id);
    p += varint_write(dst + p, 32, len);
    if (len > 0) { memcpy(dst + p, value, len); p += len; }
    return p;
}

static size_t put_varint(uint8_t* dst, uint64_t id, uint64_t value) {
    uint8_t v[8];
    const size_t n = varint_write(v, sizeof v, value);
    return put(dst, id, v, n);
}

TEST(test_quic_tp_defaults) {
    TEST_SUITE("quic_tp");

    TEST_CASE("absent parameters take their specified defaults, not zero");
    /* ack_delay_exponent defaults to 3 and max_ack_delay to 25 ms. Treating
     * either as zero silently corrupts every RTT sample the connection takes. */
    quictp_t tp;
    quictp_defaults(&tp);

    TEST_ASSERT(tp.ack_delay_exponent == 3, "ack_delay_exponent");
    TEST_ASSERT(tp.max_ack_delay == 25, "max_ack_delay");
    TEST_ASSERT(tp.active_connection_id_limit == 2, "active_connection_id_limit");
    TEST_ASSERT(tp.max_udp_payload_size == 65527, "max_udp_payload_size");
    TEST_ASSERT(tp.max_idle_timeout == 0, "max_idle_timeout");
    TEST_ASSERT(tp.initial_max_data == 0, "initial_max_data");
    TEST_ASSERT(tp.disable_active_migration == 0, "disable_active_migration");

    TEST_CASE("an empty block leaves the defaults alone");
    TEST_ASSERT(quictp_decode(NULL, 0, 1, &tp) == QUICTP_ERR_TRUNCATED, "NULL buffer");
    const uint8_t empty[1] = { 0 };
    TEST_ASSERT(quictp_decode(empty, 0, 1, &tp) == QUICTP_OK, "zero length");
    TEST_ASSERT(tp.ack_delay_exponent == 3, "defaults intact");
}

TEST(test_quic_tp_decode) {
    TEST_SUITE("quic_tp");

    quictp_t tp;
    uint8_t buf[256];
    size_t n;

    TEST_CASE("a typical client block");
    n = 0;
    n += put_varint(buf + n, QUICTP_INITIAL_MAX_DATA, 1048576);
    n += put_varint(buf + n, QUICTP_INITIAL_MAX_STREAMS_BIDI, 100);
    n += put_varint(buf + n, QUICTP_MAX_IDLE_TIMEOUT, 30000);
    n += put_varint(buf + n, QUICTP_ACK_DELAY_EXPONENT, 10);
    n += put(buf + n, QUICTP_INITIAL_SCID, (const uint8_t*)"\x01\x02\x03\x04", 4);
    n += put(buf + n, QUICTP_DISABLE_ACTIVE_MIGRATION, NULL, 0);

    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 1, &tp) == QUICTP_OK, "decodes");
    TEST_ASSERT(tp.initial_max_data == 1048576, "initial_max_data");
    TEST_ASSERT(tp.initial_max_streams_bidi == 100, "initial_max_streams_bidi");
    TEST_ASSERT(tp.max_idle_timeout == 30000, "max_idle_timeout");
    TEST_ASSERT(tp.ack_delay_exponent == 10, "ack_delay_exponent overrides the default");
    TEST_ASSERT(tp.has_initial_scid && tp.initial_scid.len == 4, "initial_scid");
    TEST_ASSERT(tp.disable_active_migration, "disable_active_migration");
    /* Untouched parameters keep their defaults rather than becoming zero. */
    TEST_ASSERT(tp.max_ack_delay == 25, "max_ack_delay still the default");

    TEST_CASE("reserved identifiers are ignored");
    /* §18.1 reserves 31*N+27 precisely so that peers must skip what they do not
     * know. A server that fails on them breaks against greasing clients. */
    TEST_ASSERT(quictp_is_reserved(27), "27");
    TEST_ASSERT(quictp_is_reserved(58), "58");
    TEST_ASSERT(quictp_is_reserved(31027), "31027");
    TEST_ASSERT(!quictp_is_reserved(0x0e), "active_connection_id_limit is not reserved");

    n = 0;
    n += put(buf + n, 27, (const uint8_t*)"\xff\xff", 2);
    n += put_varint(buf + n, QUICTP_INITIAL_MAX_DATA, 42);
    n += put(buf + n, 31027, (const uint8_t*)"junk", 4);
    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 1, &tp) == QUICTP_OK, "decodes");
    TEST_ASSERT(tp.initial_max_data == 42, "the real parameter still lands");

    TEST_CASE("unknown non-reserved identifiers are also ignored");
    n = 0;
    n += put(buf + n, 0x5555, (const uint8_t*)"x", 1);
    n += put_varint(buf + n, QUICTP_INITIAL_MAX_DATA, 7);
    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 1, &tp) == QUICTP_OK, "decodes");
    TEST_ASSERT(tp.initial_max_data == 7, "the real parameter still lands");
}

TEST(test_quic_tp_validation) {
    TEST_SUITE("quic_tp");

    quictp_t tp;
    uint8_t buf[256];
    size_t n;

    TEST_CASE("a duplicate parameter");
    n = 0;
    n += put_varint(buf + n, QUICTP_INITIAL_MAX_DATA, 1);
    n += put_varint(buf + n, QUICTP_INITIAL_MAX_DATA, 2);
    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 1, &tp) == QUICTP_ERR_DUPLICATE, "refused");

    TEST_CASE("values outside the ranges §18.2 permits");
    struct { uint64_t id; uint64_t value; const char* what; } bad[] = {
        { QUICTP_MAX_UDP_PAYLOAD_SIZE,     1199,          "max_udp_payload_size below 1200" },
        { QUICTP_ACK_DELAY_EXPONENT,       21,            "ack_delay_exponent above 20" },
        { QUICTP_MAX_ACK_DELAY,            1ULL << 14,    "max_ack_delay at 2^14" },
        { QUICTP_ACTIVE_CONNECTION_ID_LIMIT, 1,           "active_connection_id_limit below 2" },
        { QUICTP_INITIAL_MAX_STREAMS_BIDI, (1ULL << 60) + 1, "initial_max_streams_bidi above 2^60" },
        { QUICTP_INITIAL_MAX_STREAMS_UNI,  (1ULL << 60) + 1, "initial_max_streams_uni above 2^60" }
    };

    int all_refused = 1;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        n = put_varint(buf, bad[i].id, bad[i].value);
        quictp_defaults(&tp);
        if (quictp_decode(buf, n, 1, &tp) != QUICTP_ERR_VALUE) all_refused = 0;
    }
    TEST_ASSERT(all_refused, "every out-of-range value is refused");

    TEST_CASE("the boundary values themselves are accepted");
    struct { uint64_t id; uint64_t value; } good[] = {
        { QUICTP_MAX_UDP_PAYLOAD_SIZE, 1200 },
        { QUICTP_ACK_DELAY_EXPONENT, 20 },
        { QUICTP_MAX_ACK_DELAY, (1ULL << 14) - 1 },
        { QUICTP_ACTIVE_CONNECTION_ID_LIMIT, 2 },
        { QUICTP_INITIAL_MAX_STREAMS_BIDI, 1ULL << 60 }
    };
    int all_accepted = 1;
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        n = put_varint(buf, good[i].id, good[i].value);
        quictp_defaults(&tp);
        if (quictp_decode(buf, n, 1, &tp) != QUICTP_OK) all_accepted = 0;
    }
    TEST_ASSERT(all_accepted, "the limits are inclusive where the RFC says so");

    TEST_CASE("a flag parameter carrying a value");
    n = put(buf, QUICTP_DISABLE_ACTIVE_MIGRATION, (const uint8_t*)"\x01", 1);
    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 1, &tp) == QUICTP_ERR_VALUE, "refused");

    TEST_CASE("a stateless reset token of the wrong size");
    n = put(buf, QUICTP_STATELESS_RESET_TOKEN, (const uint8_t*)"short", 5);
    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 0, &tp) == QUICTP_ERR_VALUE, "refused");

    TEST_CASE("a connection id longer than 20 bytes");
    uint8_t big[21];
    memset(big, 0xaa, sizeof big);
    n = put(buf, QUICTP_INITIAL_SCID, big, sizeof big);
    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 1, &tp) == QUICTP_ERR_VALUE, "refused");

    TEST_CASE("server-only parameters sent by a client");
    /* §18.2. A client sending these is either broken or trying to confuse the
     * two roles, and the connection must fail either way. */
    const uint64_t server_only[] = {
        QUICTP_ORIGINAL_DCID, QUICTP_RETRY_SCID,
        QUICTP_PREFERRED_ADDRESS, QUICTP_STATELESS_RESET_TOKEN
    };
    int all_role_refused = 1;
    for (size_t i = 0; i < sizeof server_only / sizeof server_only[0]; i++) {
        n = put(buf, server_only[i], (const uint8_t*)"\x00\x01\x02\x03", 4);
        quictp_defaults(&tp);
        if (quictp_decode(buf, n, 1, &tp) != QUICTP_ERR_ROLE) all_role_refused = 0;
    }
    TEST_ASSERT(all_role_refused, "all four refused from a client");

    /* The same parameters from a server are ordinary. */
    n = put(buf, QUICTP_ORIGINAL_DCID, (const uint8_t*)"\x00\x01\x02\x03", 4);
    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 0, &tp) == QUICTP_OK, "accepted from a server");
    TEST_ASSERT(tp.has_original_dcid && tp.original_dcid.len == 4, "value read");

    TEST_CASE("truncation at every offset");
    n = 0;
    n += put_varint(buf + n, QUICTP_INITIAL_MAX_DATA, 1048576);
    n += put(buf + n, QUICTP_INITIAL_SCID, (const uint8_t*)"\x01\x02\x03\x04", 4);

    int all_truncated = 1;
    for (size_t cut = 1; cut < n; cut++) {
        quictp_defaults(&tp);
        const quictp_status_e st = quictp_decode(buf, cut, 1, &tp);
        /* A prefix ending exactly on a parameter boundary is a valid, shorter
         * block; anything else must be reported rather than read past. */
        if (st != QUICTP_OK && st != QUICTP_ERR_TRUNCATED) all_truncated = 0;
    }
    TEST_ASSERT(all_truncated, "no prefix is misread");

    TEST_CASE("a value length running past the block");
    n = 0;
    n += varint_write(buf + n, sizeof buf, QUICTP_INITIAL_MAX_DATA);
    n += varint_write(buf + n, sizeof buf, 40);   /* claims 40 bytes */
    buf[n++] = 0x01;
    quictp_defaults(&tp);
    TEST_ASSERT(quictp_decode(buf, n, 1, &tp) == QUICTP_ERR_TRUNCATED, "refused");
}

TEST(test_quic_tp_encode) {
    TEST_SUITE("quic_tp");

    TEST_CASE("a server block round trips");
    quictp_t out;
    quictp_defaults(&out);
    out.max_idle_timeout = 30000;
    out.max_udp_payload_size = 1452;
    out.initial_max_data = 1048576;
    out.initial_max_stream_data_bidi_remote = 262144;
    out.initial_max_stream_data_uni = 262144;
    out.initial_max_streams_bidi = 100;
    out.initial_max_streams_uni = 8;
    out.active_connection_id_limit = 4;

    out.has_original_dcid = 1;
    out.original_dcid.len = 8;
    memcpy(out.original_dcid.data, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);

    out.has_initial_scid = 1;
    out.initial_scid.len = 8;
    memcpy(out.initial_scid.data, "\x11\x12\x13\x14\x15\x16\x17\x18", 8);

    out.has_stateless_reset_token = 1;
    memset(out.stateless_reset_token, 0x5a, 16);

    uint8_t buf[512];
    const size_t n = quictp_encode(buf, sizeof buf, &out);
    TEST_ASSERT(n > 0, "encoded");

    /* Decoded as if from a server, since that is who sends these. */
    quictp_t back;
    quictp_defaults(&back);
    TEST_ASSERT(quictp_decode(buf, n, 0, &back) == QUICTP_OK, "decodes");

    TEST_ASSERT(back.max_idle_timeout == 30000, "max_idle_timeout");
    TEST_ASSERT(back.max_udp_payload_size == 1452, "max_udp_payload_size");
    TEST_ASSERT(back.initial_max_data == 1048576, "initial_max_data");
    TEST_ASSERT(back.initial_max_stream_data_bidi_remote == 262144, "stream window");
    TEST_ASSERT(back.initial_max_streams_bidi == 100, "streams bidi");
    TEST_ASSERT(back.initial_max_streams_uni == 8, "streams uni");
    TEST_ASSERT(back.active_connection_id_limit == 4, "cid limit");
    TEST_ASSERT(back.has_original_dcid && back.original_dcid.len == 8 &&
                memcmp(back.original_dcid.data, out.original_dcid.data, 8) == 0,
                "original_dcid");
    TEST_ASSERT(back.has_initial_scid &&
                memcmp(back.initial_scid.data, out.initial_scid.data, 8) == 0,
                "initial_scid");
    TEST_ASSERT(back.has_stateless_reset_token &&
                back.stateless_reset_token[0] == 0x5a, "reset token");

    TEST_CASE("we emit a reserved parameter of our own");
    /* Sending one is how a peer's handling of them gets exercised in the wild
     * rather than only in its test suite. */
    int found_reserved = 0;
    size_t p = 0;
    while (p < n) {
        uint64_t id = 0, vlen = 0;
        p += varint_read(buf + p, n - p, &id);
        p += varint_read(buf + p, n - p, &vlen);
        p += (size_t)vlen;
        if (quictp_is_reserved(id)) found_reserved = 1;
    }
    TEST_ASSERT(found_reserved, "a reserved identifier is present");
    TEST_ASSERT(p == n, "the block walks exactly to its end");

    TEST_CASE("refuses a buffer that is too small");
    TEST_ASSERT(quictp_encode(buf, 8, &out) == 0, "8 bytes");
    TEST_ASSERT(quictp_encode(NULL, 100, &out) == 0, "NULL buffer");
}

#include "framework.h"

#include "quic.h"
#include "quicerror.h"
#include "quicqlog.h"
#include "quictime.h"
#include "h3error.h"

#include <string.h>

/* Phase 0 smoke test for the QUIC/HTTP/3 build path.
 *
 * Its real subject is not the three functions below -- it is the chain that has
 * to hold for any later phase to be testable at all: the sources compile under
 * the core's warning set, land in the quic_common/h3frame archives, get pulled
 * whole into libcwfr_framework.so, and their include directories reach the test
 * runner. Each of those is a separate place the gating can be wrong, and all of
 * them fail as "undefined reference" hours later if nobody checks now.
 *
 * This file is excluded from the glob unless INCLUDE_HTTP3=yes
 * (tests/CMakeLists.txt), which is itself part of what is being verified. */

static uint64_t __fake_now = 0;

static uint64_t __fake_clock(void) {
    return __fake_now;
}

TEST(test_quic_common_smoke) {
    TEST_SUITE("quic_common");

    TEST_CASE("transport error names");
    TEST_ASSERT(strcmp(quic_error_name(QUIC_NO_ERROR), "NO_ERROR") == 0,
                "QUIC_NO_ERROR name");
    TEST_ASSERT(strcmp(quic_error_name(QUIC_FINAL_SIZE_ERROR), "FINAL_SIZE_ERROR") == 0,
                "QUIC_FINAL_SIZE_ERROR name");
    TEST_ASSERT(strcmp(quic_error_name(0x4242), "UNKNOWN") == 0,
                "unknown transport code");

    TEST_CASE("CRYPTO_ERROR carries the TLS alert in its low byte");
    /* 0x0100-0x01ff is one code per alert, not one code (RFC 9000 §20.1). A
     * decoder that compares against a single constant silently mislabels every
     * handshake failure. */
    TEST_ASSERT(QUIC_CRYPTO_ERROR(0x2a) == 0x012a, "alert 42 encodes to 0x012a");
    TEST_ASSERT(QUIC_IS_CRYPTO_ERROR(0x012a), "0x012a is a crypto error");
    TEST_ASSERT(QUIC_IS_CRYPTO_ERROR(0x0100), "0x0100 is a crypto error");
    TEST_ASSERT(!QUIC_IS_CRYPTO_ERROR(0x0200), "0x0200 (QPACK) is not");
    TEST_ASSERT(!QUIC_IS_CRYPTO_ERROR(QUIC_PROTOCOL_VIOLATION),
                "PROTOCOL_VIOLATION is not");
    TEST_ASSERT(strcmp(quic_error_name(QUIC_CRYPTO_ERROR(0x28)), "CRYPTO_ERROR") == 0,
                "crypto error name");

    TEST_CASE("HTTP/3 and QPACK codes are application codes, kept apart");
    TEST_ASSERT(strcmp(h3_error_name(H3_MESSAGE_ERROR), "H3_MESSAGE_ERROR") == 0,
                "H3_MESSAGE_ERROR name");
    TEST_ASSERT(strcmp(h3_error_name(QPACK_DECOMPRESSION_FAILED),
                       "QPACK_DECOMPRESSION_FAILED") == 0,
                "QPACK_DECOMPRESSION_FAILED name");
    TEST_ASSERT(strcmp(h3_error_name(0x4242), "UNKNOWN") == 0, "unknown h3 code");
    /* The two spaces must not collide: an h3 code is never a transport code. */
    TEST_ASSERT(H3_NO_ERROR > QUIC_NO_VIABLE_PATH, "h3 codes sit above transport codes");

    TEST_CASE("wire constants");
    TEST_ASSERT(QUIC_VERSION_1 == 0x00000001u, "QUIC v1");
    TEST_ASSERT((QUIC_VERSION_GREASE & 0x0f0f0f0fu) == 0x0a0a0a0au,
                "GREASE version matches the 0x?a?a?a?a reserved pattern");
    TEST_ASSERT(QUIC_MIN_INITIAL_DATAGRAM == 1200, "minimum Initial datagram");
    TEST_ASSERT(QUIC_LOCAL_CID_LEN <= QUIC_MAX_CID_LEN, "issued CID fits the field");
    TEST_ASSERT(QUIC_DEFAULT_UDP_PAYLOAD >= QUIC_MIN_INITIAL_DATAGRAM,
                "default datagram can still carry an Initial");
    TEST_ASSERT(QUIC_VARINT_MAX == 0x3FFFFFFFFFFFFFFFULL, "62-bit varint ceiling");
    TEST_ASSERT(QUIC_ENC_COUNT == 4, "four encryption levels");

    TEST_CASE("clock is replaceable");
    /* Loss detection and pacing are defined entirely in elapsed time; if this
     * indirection ever stops working, none of phase 4 can be unit-tested. */
    quic_time_set_source(__fake_clock);
    __fake_now = 1000;
    TEST_ASSERT(quic_now_us() == 1000, "fake clock is used");
    __fake_now = 2500;
    TEST_ASSERT(quic_now_us() == 2500, "fake clock advances");

    quic_time_set_source(NULL);
    const uint64_t a = quic_now_us();
    const uint64_t b = quic_now_us();
    TEST_ASSERT(a != 0, "real clock returns a time");
    TEST_ASSERT(b >= a, "real clock is monotonic");

    TEST_CASE("qlog stub compiles away");
    /* The stub type-checks its format arguments in an unevaluated context. This
     * call exists so that the checking itself is exercised: if the macro ever
     * stops seeing its arguments, phase 1-3 call sites rot unnoticed. */
    QLOG(NULL, "transport", "packet_dropped", "\"reason\":\"%s\",\"len\":%zu",
         "unknown_cid", (size_t)1200);
    TEST_ASSERT(1, "qlog stub is a no-op");
}

#include "framework.h"

#include "quic.h"
#include "quicerror.h"
#include "quicqlog.h"
#include "quictime.h"
#include "h3error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

    TEST_CASE("qlog on a closed connection does nothing");
    /* Every call site passes a pointer that is NULL on all but a handful of
     * connections, so "off" is the path that runs in production and the one
     * worth asserting. */
    QLOG(NULL, "transport", "packet_dropped", "\"reason\":\"%s\",\"len\":%zu",
         "unknown_cid", (size_t)1200);
    TEST_ASSERT(1, "qlog with no log open is a no-op");
}

/* Read a whole file, or return NULL. The test asserts against the bytes that
 * reached the disk rather than against what the writer thinks it wrote --
 * buffering is part of what is being checked. */
static char* __slurp(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (f == NULL) return NULL;

    static char buffer[65536];
    const size_t n = fread(buffer, 1, sizeof buffer - 1, f);
    fclose(f);
    buffer[n] = 0;
    if (out_len != NULL) *out_len = n;

    return buffer;
}

TEST(test_quic_qlog) {
    TEST_SUITE("quic_qlog");

    char dir[] = "/tmp/cwfr_qlog_testXXXXXX";
    TEST_ASSERT(mkdtemp(dir) != NULL, "temporary directory for the traces");

    const uint8_t cid[8] = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    char path[512];
    snprintf(path, sizeof path, "%s/deadbeef01020304.sqlog", dir);

    TEST_CASE("disabled by default");
    /* An empty directory is the shipped configuration, and the assertion that
     * matters most: a server that writes a file per connection because the
     * default leaked is a server this feature broke. */
    TEST_ASSERT(quicqlog_configure("", 10), "an empty directory configures cleanly");
    TEST_ASSERT(quicqlog_open(cid, sizeof cid) == NULL, "no trace is opened");

    TEST_CASE("a configured trace is written");
    TEST_ASSERT(quicqlog_configure(dir, 2), "the directory is accepted");

    quicqlog_t* q = quicqlog_open(cid, sizeof cid);
    TEST_ASSERT(q != NULL, "a trace opens for the first connection");

    QLOG(q, "transport", "packet_sent", "\"pn\":%llu,\"len\":%zu",
         (unsigned long long)7, (size_t)1200);
    QLOG(q, "recovery", "packet_lost", "\"pn\":%llu", (unsigned long long)7);

    /* Read while the connection is still open: the events of a hang are wanted
     * before anything closes, which is what the line buffering is for. */
    size_t len = 0;
    const char* body = __slurp(path, &len);
    TEST_ASSERT(body != NULL, "the trace file exists under the odcid");
    TEST_ASSERT(body != NULL && body[0] == 0x1e, "JSON-SEQ record separator");
    TEST_ASSERT(body != NULL && strstr(body, "\"qlog_format\":\"JSON-SEQ\"") != NULL,
                "the header names the format qvis reads");
    TEST_ASSERT(body != NULL && strstr(body, "\"ODCID\":\"deadbeef01020304\"") != NULL,
                "the header carries the connection id");
    TEST_ASSERT(body != NULL && strstr(body, "\"name\":\"transport:packet_sent\"") != NULL,
                "an event is named category:event");
    TEST_ASSERT(body != NULL && strstr(body, "\"name\":\"recovery:packet_lost\"") != NULL,
                "events keep arriving without a flush");

    size_t records = 0;
    for (size_t i = 0; i < len; i++)
        if (body[i] == 0x1e) records++;
    TEST_ASSERT(records == 3, "one record for the header and one per event");

    TEST_CASE("the connection budget bounds the traces");
    const uint8_t second[4] = { 1, 2, 3, 4 };
    const uint8_t third[4] = { 5, 6, 7, 8 };
    quicqlog_t* q2 = quicqlog_open(second, sizeof second);
    TEST_ASSERT(q2 != NULL, "the second connection is within the budget of two");
    TEST_ASSERT(quicqlog_open(third, sizeof third) == NULL,
                "the third is refused rather than logged");

    quicqlog_close(q2);
    quicqlog_close(q);
    quicqlog_close(NULL);

    TEST_CASE("peer bytes cannot corrupt a trace");
    /* The CONNECTION_CLOSE reason is chosen by the peer, and a quote or a
     * newline in it would end the JSON object or the record early -- corrupting
     * the whole file rather than one field. */
    char escaped[64];
    quicqlog_escape("a\"b\nc\\d", 7, escaped, sizeof escaped);
    TEST_ASSERT(strcmp(escaped, "a\\\"b\\u000ac\\\\d") == 0,
                "quotes, control bytes and backslashes are escaped");

    quicqlog_escape("abcdef", 6, escaped, 4);
    TEST_ASSERT(strcmp(escaped, "abc") == 0, "truncation still terminates");

    quicqlog_escape("\xd0\x9f", 2, escaped, sizeof escaped);
    TEST_ASSERT(strcmp(escaped, "\\u00d0\\u009f") == 0,
                "non-ASCII is escaped byte by byte, so a cut sequence is still JSON");

    /* Leave nothing behind: the suite runs in CI and under the sanitizers. */
    unlink(path);
    snprintf(path, sizeof path, "%s/01020304.sqlog", dir);
    unlink(path);
    rmdir(dir);

    /* And turn logging off again for whatever runs next in this process. */
    quicqlog_configure("", 0);
}

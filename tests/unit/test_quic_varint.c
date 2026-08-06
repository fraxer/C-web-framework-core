#include "framework.h"

#include "varint.h"

#include <string.h>

/* RFC 9000 §16 and Appendix A.1.
 *
 * Nearly every field in QUIC is a varint, and this code reads bytes that no
 * key has authenticated yet, so the truncation and range cases carry more
 * weight than the round trips. */

TEST(test_quic_varint_rfc_examples) {
    TEST_SUITE("quic_varint");

    TEST_CASE("Appendix A.1 worked examples");
    uint64_t value = 0;

    const uint8_t eight[] = { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
    TEST_ASSERT(varint_read(eight, sizeof eight, &value) == 8, "8-byte length");
    TEST_ASSERT(value == 151288809941952652ULL, "8-byte value");

    const uint8_t four[] = { 0x9d, 0x7f, 0x3e, 0x7d };
    TEST_ASSERT(varint_read(four, sizeof four, &value) == 4, "4-byte length");
    TEST_ASSERT(value == 494878333ULL, "4-byte value");

    const uint8_t two[] = { 0x7b, 0xbd };
    TEST_ASSERT(varint_read(two, sizeof two, &value) == 2, "2-byte length");
    TEST_ASSERT(value == 15293ULL, "2-byte value");

    const uint8_t one[] = { 0x25 };
    TEST_ASSERT(varint_read(one, sizeof one, &value) == 1, "1-byte length");
    TEST_ASSERT(value == 37ULL, "1-byte value");

    TEST_CASE("the same value in a longer encoding (A.1's last example)");
    /* RFC 9000 §16: values need not use the minimum number of bytes. Rejecting
     * this would break a peer that is entirely within its rights, and it is the
     * single easiest rule in the section to get wrong. */
    const uint8_t two_but_37[] = { 0x40, 0x25 };
    TEST_ASSERT(varint_read(two_but_37, sizeof two_but_37, &value) == 2, "length");
    TEST_ASSERT(value == 37ULL, "same value as the 1-byte form");
}

TEST(test_quic_varint_boundaries) {
    TEST_SUITE("quic_varint");

    TEST_CASE("encoded size at each boundary");
    TEST_ASSERT(varint_size(0) == 1, "0");
    TEST_ASSERT(varint_size(63) == 1, "63 is the largest 1-byte value");
    TEST_ASSERT(varint_size(64) == 2, "64 needs 2");
    TEST_ASSERT(varint_size(16383) == 2, "16383 is the largest 2-byte value");
    TEST_ASSERT(varint_size(16384) == 4, "16384 needs 4");
    TEST_ASSERT(varint_size(1073741823ULL) == 4, "2^30-1 is the largest 4-byte value");
    TEST_ASSERT(varint_size(1073741824ULL) == 8, "2^30 needs 8");
    TEST_ASSERT(varint_size(QUIC_VARINT_MAX) == 8, "2^62-1 fits");
    TEST_ASSERT(varint_size(QUIC_VARINT_MAX + 1) == 0, "2^62 does not");
    TEST_ASSERT(varint_size(UINT64_MAX) == 0, "nor does UINT64_MAX");

    TEST_CASE("round trip at each boundary");
    const uint64_t values[] = {
        0, 1, 63, 64, 16383, 16384, 1073741823ULL, 1073741824ULL, QUIC_VARINT_MAX
    };
    uint8_t buf[8];
    int all_ok = 1;

    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        const size_t written = varint_write(buf, sizeof buf, values[i]);
        uint64_t back = 0;
        const size_t read = varint_read(buf, written, &back);

        if (written == 0 || written != read || back != values[i]) all_ok = 0;
        /* Output is always minimal even though input need not be. */
        if (written != varint_size(values[i])) all_ok = 0;
    }
    TEST_ASSERT(all_ok, "every boundary value round trips minimally");

    TEST_CASE("out-of-range values are refused, not truncated");
    TEST_ASSERT(varint_write(buf, sizeof buf, QUIC_VARINT_MAX + 1) == 0, "2^62");
    TEST_ASSERT(varint_write(buf, sizeof buf, UINT64_MAX) == 0, "UINT64_MAX");
}

TEST(test_quic_varint_truncation) {
    TEST_SUITE("quic_varint");

    TEST_CASE("a buffer shorter than the announced length");
    /* The length lives in the first byte, so a hostile peer can announce eight
     * bytes and send one. Reading past the buffer here would be a remote
     * out-of-bounds read before any authentication has happened. */
    uint64_t value = 0;
    const uint8_t eight[] = { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };

    int all_refused = 1;
    for (size_t avail = 0; avail < 8; avail++)
        if (varint_read(eight, avail, &value) != 0) all_refused = 0;

    TEST_ASSERT(all_refused, "every short prefix is refused");
    TEST_ASSERT(varint_read(eight, 8, &value) == 8, "the full eight bytes read");

    TEST_CASE("NULL arguments");
    TEST_ASSERT(varint_read(NULL, 8, &value) == 0, "NULL buffer");
    TEST_ASSERT(varint_read(eight, 8, NULL) == 0, "NULL output");
    TEST_ASSERT(varint_write(NULL, 8, 1) == 0, "NULL buffer");

    TEST_CASE("writing into a buffer that is too small");
    uint8_t small[1];
    TEST_ASSERT(varint_write(small, 1, 63) == 1, "1 byte fits");
    TEST_ASSERT(varint_write(small, 1, 64) == 0, "2 bytes do not");
    TEST_ASSERT(varint_write(small, 0, 0) == 0, "zero capacity");
}

TEST(test_quic_varint_write_fixed) {
    TEST_SUITE("quic_varint");

    TEST_CASE("a value padded into a wider encoding");
    /* Used for a long header's Length: space is reserved before the payload
     * exists, then patched once its size is known. */
    uint8_t buf[8];
    uint64_t back = 0;

    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, 37, 4) == 4, "37 in 4 bytes");
    TEST_ASSERT(buf[0] == 0x80, "4-byte prefix");
    TEST_ASSERT(varint_read(buf, 4, &back) == 4 && back == 37, "reads back as 37");

    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, 0, 8) == 8, "0 in 8 bytes");
    TEST_ASSERT(varint_read(buf, 8, &back) == 8 && back == 0, "reads back as 0");

    TEST_CASE("a value that does not fit the requested width");
    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, 64, 1) == 0, "64 in 1 byte");
    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, 16384, 2) == 0, "16384 in 2 bytes");
    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, QUIC_VARINT_MAX + 1, 8) == 0,
                "out of range in 8 bytes");

    TEST_CASE("widths that are not legal varint lengths");
    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, 1, 0) == 0, "0");
    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, 1, 3) == 0, "3");
    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, 1, 5) == 0, "5");
    TEST_ASSERT(varint_write_fixed(buf, sizeof buf, 1, 16) == 0, "16");

    TEST_CASE("no write past the capacity");
    TEST_ASSERT(varint_write_fixed(buf, 3, 1, 4) == 0, "4 bytes into 3");
}

#include "varint.h"

/* Largest value each encoding length can carry: 6, 14, 30 and 62 bits. */
#define VARINT_MAX_1 0x3fULL
#define VARINT_MAX_2 0x3fffULL
#define VARINT_MAX_4 0x3fffffffULL

size_t varint_read(const uint8_t* p, size_t avail, uint64_t* out) {
    if (p == NULL || out == NULL || avail < 1) return 0;

    const size_t len = (size_t)1 << (p[0] >> 6);
    if (avail < len) return 0;

    uint64_t value = (uint64_t)(p[0] & 0x3f);
    for (size_t i = 1; i < len; i++)
        value = (value << 8) | (uint64_t)p[i];

    *out = value;

    return len;
}

size_t varint_size(uint64_t value) {
    if (value <= VARINT_MAX_1) return 1;
    if (value <= VARINT_MAX_2) return 2;
    if (value <= VARINT_MAX_4) return 4;
    if (value <= QUIC_VARINT_MAX) return 8;

    return 0;
}

size_t varint_write(uint8_t* p, size_t cap, uint64_t value) {
    const size_t len = varint_size(value);
    if (len == 0) return 0;

    return varint_write_fixed(p, cap, value, len);
}

size_t varint_write_fixed(uint8_t* p, size_t cap, uint64_t value, size_t len) {
    if (p == NULL || cap < len) return 0;

    uint8_t prefix;
    uint64_t ceiling;

    switch (len) {
    case 1: prefix = 0x00; ceiling = VARINT_MAX_1; break;
    case 2: prefix = 0x40; ceiling = VARINT_MAX_2; break;
    case 4: prefix = 0x80; ceiling = VARINT_MAX_4; break;
    case 8: prefix = 0xc0; ceiling = QUIC_VARINT_MAX; break;
    default: return 0;
    }

    if (value > ceiling) return 0;

    for (size_t i = 0; i < len; i++)
        p[len - 1 - i] = (uint8_t)(value >> (8 * i));

    /* The value occupies at most `ceiling` bits, so the top two bits of the
     * first byte are clear and the prefix can simply be or-ed in. */
    p[0] |= prefix;

    return len;
}

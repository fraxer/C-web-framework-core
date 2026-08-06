#ifndef __QUICVARINT__
#define __QUICVARINT__

#include <stddef.h>
#include <stdint.h>

#include "quic.h"

/* Variable-length integers (RFC 9000 §16).
 *
 * The two most significant bits of the first byte give the length -- 1, 2, 4 or
 * 8 bytes -- and the remaining 62 bits carry the value. Almost every length,
 * offset, identifier and limit in QUIC is one of these, so this is the most
 * heavily used code in the stack and the first place a bounds mistake would
 * show up.
 *
 * One rule is easy to get wrong and expensive to get wrong: **a non-minimal
 * encoding is legal on input**. RFC 9000 §16 says values "do not need to be
 * encoded on the minimum number of bytes necessary", so 37 may arrive as one
 * byte or as eight, and rejecting the long forms breaks peers that are within
 * their rights. We always emit the minimal form and accept any. */

/* Read one varint. Returns how many bytes it occupied (1, 2, 4 or 8), or 0 if
 * `avail` is too small -- which for a parser reading attacker-supplied bytes is
 * the common case, not an exception. */
size_t varint_read(const uint8_t* p, size_t avail, uint64_t* out);

/* Write `value` in the fewest bytes that hold it. Returns bytes written, or 0
 * if `cap` is too small or the value exceeds QUIC_VARINT_MAX. */
size_t varint_write(uint8_t* p, size_t cap, uint64_t value);

/* Bytes varint_write would produce. 0 if the value is out of range, so that a
 * size computation cannot silently under-count and hand a short buffer to the
 * writer. */
size_t varint_size(uint64_t value);

/* Write `value` in exactly `len` bytes (1, 2, 4 or 8), padding the encoding out
 * rather than minimising it.
 *
 * This is the one place the non-minimal form is emitted deliberately, and it
 * exists for length fields that are patched after the fact: a long header's
 * Length covers a payload whose size is only known once the payload has been
 * built, so space for it has to be reserved first. Returns bytes written, or 0
 * if the length is not a legal varint size, the value does not fit in it, or
 * `cap` is too small. */
size_t varint_write_fixed(uint8_t* p, size_t cap, uint64_t value, size_t len);

#endif

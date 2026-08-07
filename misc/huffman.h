#ifndef __HUFFMAN__
#define __HUFFMAN__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */

/* Huffman coding (RFC 7541 §5.2, Appendix B) and prefix integers (RFC 7541
 * §5.1) -- the two string/integer primitives HPACK and QPACK share.
 *
 * RFC 9204 §5 defines QPACK to use "the Huffman coding defined in [HPACK]", so
 * the code table (misc/huffman_table.h) and the codec below are verbatim what
 * HPACK uses. The prefix-integer representation is identical between the two
 * protocols; only the prefix widths and the opcode carried in the first octet's
 * high bits differ, and the caller supplies those. Both live in misc/ so neither
 * protocol layer has to depend on the other.
 *
 * Status reporting here is protocol-neutral: lengths and byte counts, with -1
 * for a malformed Huffman stream. Each protocol maps that onto its own error
 * code (HPACK_ERR_COMPRESSION, QPACK_DECOMPRESSION_FAILED). */

/* ---- Huffman (RFC 7541 §5.2, Appendix B) ---- */

/* Encoded length in bytes for `len` input bytes (rounded up to the padded
 * octet). Size a buffer with this and huffman_encode will not overflow it. */
size_t huffman_encoded_len(const uint8_t* src, size_t len);

/* Encode `len` bytes into dst[0..cap). Returns bytes written, or -1 if the
 * output does not fit (the caller should have sized dst with
 * huffman_encoded_len). Empty input encodes to zero bytes and returns 0. */
ssize_t huffman_encode(uint8_t* dst, size_t cap, const uint8_t* src, size_t len);

/* Decode `len` bytes into dst[0..cap). Returns bytes written, or -1 on a
 * malformed input: EOS reached inside the stream, a nibble that lands on no
 * symbol, padding wider than 7 bits, or the output cap exhausted. The cap-exhaustion
 * case is -1 rather than a partial count so a caller cannot mistake a truncation
 * for a complete decode. */
ssize_t huffman_decode(uint8_t* dst, size_t cap, const uint8_t* src, size_t len);

/* ---- Prefix integer (RFC 7541 §5.1) ---- *
 *
 * An integer is encoded into a `prefix_bits`-bit prefix of the first octet; the
 * remaining high bits of that octet are the caller's opcode (the representation
 * type). A value that fits the prefix occupies one octet; a larger value fills
 * the prefix with all ones and continues in 7-bit chunks, the last one clear of
 * its high bit. prefix_bits is 1..8. */

/* Encode `value` with a `prefix_bits`-bit prefix, OR-ing `flags` into the high
 * bits of the first octet. Returns bytes written, or 0 if cap is too small or
 * prefix_bits is out of range. */
size_t prefix_int_encode(uint8_t* dst, size_t cap, uint64_t value,
                         uint8_t prefix_bits, uint8_t flags);

/* Decode an integer with a `prefix_bits`-bit prefix from src[0..len). The high
 * bits of the first octet (the opcode) are ignored. Returns bytes consumed, or
 * 0 on a truncated or overflowing input; *out receives the value on success.
 * The continuation is capped at nine bytes (values up to ~2^63) -- beyond any
 * index or length either protocol uses, and it keeps a peer from running the
 * decoder unbounded. Callers still clamp to their own ranges (HPACK to 32 bits). */
size_t prefix_int_decode(const uint8_t* src, size_t len, uint8_t prefix_bits,
                         uint64_t* out);

#endif

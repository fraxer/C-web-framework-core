#ifndef __QPACK__
#define __QPACK__

#include <stddef.h>
#include <stdint.h>

/* QPACK (RFC 9204) -- header compression for HTTP/3.
 *
 * This is the QPACK-lite decoder (RFC 9204 §6 of docs/http3/06-qpack.md): our
 * decoder advertises QPACK_MAX_TABLE_CAPACITY=0 and QPACK_BLOCKED_STREAMS=0, so
 * the peer may not insert anything into a dynamic table, no block ever blocks,
 * and Required Insert Count is always 0. Field sections reference only the
 * 99-entry static table (qpack_statictable.h) and literals. That is fully RFC-
 * compliant -- the dynamic table is optional on both sides -- and loses ~10-20%
 * compression versus h2, acceptable for a first h3. The full dynamic table,
 * encoder/decoder-stream instructions, blocked-stream accounting and our encoder
 * arrive in phase 6.2; the API below carries only what lite needs.
 *
 * Field validity (RFC 9114 §4.3) is NOT checked here -- this module hands back
 * the fields the peer encoded, exactly as HPACK does. The caller (the future
 * h3session, via the shared httpfields_to_request) applies the protocol rules. */

typedef enum {
    QPACK_OK = 0,
    /* A malformed block: a bad Huffman string, a reference into the (absent)
     * dynamic table, Required Insert Count != 0, or a truncated representation.
     * Maps to QPACK_DECOMPRESSION_FAILED -- a connection error. */
    QPACK_ERR_DECOMPRESSION,
    /* The peer sent an encoder-stream instruction (an insert/duplicate/set-
     * capacity), which it may not when we advertised capacity 0. Connection
     * error QPACK_ENCODER_STREAM_ERROR. Reserved for phase 6.2's read path. */
    QPACK_ERR_ENCODER_STREAM,
    QPACK_ERR_MEMORY,
    /* The decoded field section exceeded max_list_size. The caller answers 431
     * on the stream; the connection stays usable. */
    QPACK_ERR_TOO_LARGE
} qpack_status_e;

/* One decoded field. Bytes are malloc'd, null-terminated; the caller frees the
 * array with qpack_headers_free. Mirrors hpack_header_t so the request-building
 * path is the same for h2 and h3. */
typedef struct {
    char*  name;
    size_t name_len;
    char*  value;
    size_t value_len;
    /* RFC 9204 §4.1.3 "never indexed": the N bit the peer set. Carried for
     * diagnostics/intermediaries, as in HPACK; this server sets it on the encode
     * side for sensitive fields. */
    int    never_indexed;
} qpack_header_t;

/* Lite decoder. max_capacity and max_blocked are stored for phase 6.2; in lite
 * both are 0, and qpack_decode_block enforces that the peer respects them. */
typedef struct qpack_decoder {
    size_t max_capacity;
    size_t max_blocked;
} qpack_decoder_t;

/* Create a decoder. For lite pass (0, 0); the full decoder (6.2) takes the
 * negotiated capacity and blocked-stream limit. Returns NULL on OOM. */
qpack_decoder_t* qpack_decoder_create(size_t max_capacity, size_t max_blocked);
void qpack_decoder_free(qpack_decoder_t* d);

/* Decode one field section (request headers or trailers). On QPACK_OK, *out is
 * a malloc'd array of *out_count fields in the order they appeared; the caller
 * frees it with qpack_headers_free. On any error *out is NULL and *out_count 0.
 *
 * `max_list_size` is the advisory MAX_FIELD_SECTION_SIZE the peer advertised,
 * counted as name_len + value_len + 32 per field (RFC 9113 §6.5.2, same as
 * HPACK). 0 disables the check. */
qpack_status_e qpack_decode_block(qpack_decoder_t* d, const uint8_t* block, size_t len,
                                  size_t max_list_size,
                                  qpack_header_t** out, size_t* out_count);

void qpack_headers_free(qpack_header_t* headers, size_t count);

/* ---- Encoder (lite) ---- *
 *
 * Emits a field section that references only the static table and literals:
 * the prefix is always RIC=0, Delta Base=0. For each field it picks the smallest
 * lite representation -- indexed static on an exact match, else a literal with a
 * static name reference, else a literal with a literal name -- Huffman-encoding
 * a string only when that is shorter. A field marked never_indexed is emitted
 * as a literal with N=1 (never an indexed line), so a peer intermediary does
 * not re-index a value that may be sensitive. */

typedef struct qpack_encoder {
    size_t max_capacity;   /* 0 in lite */
    size_t max_blocked;    /* 0 in lite */
} qpack_encoder_t;

qpack_encoder_t* qpack_encoder_create(size_t max_capacity, size_t max_blocked);
void qpack_encoder_free(qpack_encoder_t* e);

/* Encode `count` fields into dst[0..cap). Returns bytes written, or 0 on error
 * (cap too small / OOM). Even an empty field section is two bytes (the prefix),
 * so 0 is unambiguous. The caller sizes dst to roughly twice the raw header size
 * and retries larger on 0. */
size_t qpack_encode_block(qpack_encoder_t* e, const qpack_header_t* fields, size_t count,
                          uint8_t* dst, size_t cap);

#endif

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
    /* Required Insert Count is valid but has not arrived on the encoder stream
     * yet. The HTTP/3 layer retains the field section and retries it after an
     * insertion, subject to SETTINGS_QPACK_BLOCKED_STREAMS. */
    QPACK_BLOCKED,
    /* A malformed block: a bad Huffman string, a reference into the (absent)
     * dynamic table, Required Insert Count != 0, or a truncated representation.
     * Maps to QPACK_DECOMPRESSION_FAILED -- a connection error. */
    QPACK_ERR_DECOMPRESSION,
    /* The peer sent an encoder-stream instruction (an insert/duplicate/set-
     * capacity), which it may not when we advertised capacity 0. Connection
     * error QPACK_ENCODER_STREAM_ERROR. Reserved for phase 6.2's read path. */
    QPACK_ERR_ENCODER_STREAM,
    /* The peer sent a decoder-stream instruction our encoder cannot make sense
     * of: an Insert Count Increment, which §4.4.3 forbids at zero and which any
     * value of describes a dynamic table a static-only encoder never built.
     * Connection error QPACK_DECODER_STREAM_ERROR. */
    QPACK_ERR_DECODER_STREAM,
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

typedef struct qpack_dynamic_entry qpack_dynamic_entry_t;

/* Decoder-side dynamic table. Entries are accounted as name + value + 32
 * bytes (§3.2.1); insert_count is the monotonically increasing absolute index
 * space and does not fall when old entries are evicted. */
typedef struct qpack_decoder {
    size_t max_capacity;
    size_t max_blocked;
    size_t capacity;
    size_t bytes;
    uint64_t insert_count;
    qpack_dynamic_entry_t* entries; /* oldest first */
    size_t entry_count;
    size_t entry_cap;
    uint8_t* pending;
    size_t pending_len;
    size_t pending_cap;
} qpack_decoder_t;

/* Create a decoder. For lite pass (0, 0); the full decoder (6.2) takes the
 * negotiated capacity and blocked-stream limit. Returns NULL on OOM. */
qpack_decoder_t* qpack_decoder_create(size_t max_capacity, size_t max_blocked);
void qpack_decoder_free(qpack_decoder_t* d);

size_t qpack_decoder_capacity(const qpack_decoder_t* d);
size_t qpack_decoder_bytes(const qpack_decoder_t* d);
uint64_t qpack_decoder_insert_count(const qpack_decoder_t* d);

/* Decode only the Field Section Prefix's Required Insert Count. Returns
 * QPACK_BLOCKED when the count is valid but still in the future, while still
 * storing it in *required so the HTTP/3 scheduler knows when to retry. */
qpack_status_e qpack_required_insert_count(const qpack_decoder_t* d,
                                            const uint8_t* block, size_t len,
                                            uint64_t* required);

/* Bytes to write on our QPACK decoder stream (§4.4). Insert Count Increment is
 * queued as peer insertions arrive; the HTTP/3 layer adds Section
 * Acknowledgment after decoding a dynamic section and Stream Cancellation when
 * abandoning one. The returned storage belongs to the decoder. */
size_t qpack_decoder_pending(const qpack_decoder_t* d, const uint8_t** out);
void qpack_decoder_consume(qpack_decoder_t* d, size_t n);
qpack_status_e qpack_decoder_ack_section(qpack_decoder_t* d, uint64_t stream_id);
qpack_status_e qpack_decoder_cancel_stream(qpack_decoder_t* d, uint64_t stream_id);

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

/* Instructions arriving on the peer's QPACK encoder stream (RFC 9204 §4.3).
 *
 * In lite we advertise QPACK_MAX_TABLE_CAPACITY=0, so the peer has no table to
 * insert into and exactly one instruction remains legal: `Set Dynamic Table
 * Capacity` with a value of 0, which real clients do send as an opener. Insert
 * With Name Reference, Insert With Literal Name, Duplicate, and any capacity
 * above what we advertised are all QPACK_ERR_ENCODER_STREAM -- a connection
 * error of type QPACK_ENCODER_STREAM_ERROR (§4.3.1).
 *
 * Refusing every byte instead would be wrong: capacity-0 is legal and common.
 * The parser is resumable, because a stream hands over bytes in arbitrary
 * pieces; a partial instruction leaves *consumed short of len and the caller
 * re-feeds the remainder. */
qpack_status_e qpack_decoder_read_encoder(qpack_decoder_t* d, const uint8_t* data,
                                          size_t len, size_t* consumed);

/* The mirror of the above for the peer's decoder stream, which talks to our
 * encoder. Section Acknowledgment and Stream Cancellation are read past: they
 * name a stream and ask nothing of an encoder that inserts nothing. An Insert
 * Count Increment is QPACK_ERR_DECODER_STREAM -- §4.4.3 forbids the value zero
 * outright, and every other value claims we made insertions we did not.
 *
 * Takes no decoder: there is no encoder state to keep while the dynamic table
 * does not exist. Resumable on the same terms as the encoder-stream reader. */
struct qpack_encoder;
typedef struct qpack_outstanding_section qpack_outstanding_section_t;
qpack_status_e qpack_encoder_read_decoder_state(struct qpack_encoder* e,
                                                 const uint8_t* data, size_t len,
                                                 size_t* consumed);
qpack_status_e qpack_encoder_read_decoder(const uint8_t* data, size_t len,
                                          size_t* consumed); /* lite compatibility */

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
    uint64_t insert_count;
    uint64_t known_received_count;
    size_t capacity;
    uint8_t* pending;
    size_t pending_len;
    size_t pending_cap;
    qpack_dynamic_entry_t* entries;
    size_t entry_count;
    size_t entry_cap;
    size_t bytes;
    qpack_outstanding_section_t* sections;
    size_t section_count;
    size_t section_cap;
} qpack_encoder_t;

qpack_encoder_t* qpack_encoder_create(size_t max_capacity, size_t max_blocked);
void qpack_encoder_free(qpack_encoder_t* e);
qpack_status_e qpack_encoder_set_capacity(qpack_encoder_t* e, size_t capacity);
size_t qpack_encoder_pending(const qpack_encoder_t* e, const uint8_t** out);
void qpack_encoder_consume(qpack_encoder_t* e, size_t n);
qpack_status_e qpack_encoder_section_open(qpack_encoder_t* e, uint64_t stream_id,
                                           uint64_t required_insert_count);
qpack_status_e qpack_encoder_insert_literal(qpack_encoder_t* e,
                                             const char* name, size_t name_len,
                                             const char* value, size_t value_len,
                                             uint64_t* absolute);
qpack_status_e qpack_encoder_insert_static_name(qpack_encoder_t* e,
                                                 uint64_t static_index,
                                                 const char* value, size_t value_len,
                                                 uint64_t* absolute);
qpack_status_e qpack_encoder_insert_dynamic_name(qpack_encoder_t* e,
                                                  uint64_t relative_index,
                                                  const char* value, size_t value_len,
                                                  uint64_t* absolute);
qpack_status_e qpack_encoder_duplicate(qpack_encoder_t* e, uint64_t relative_index,
                                        uint64_t* absolute);

/* Encode `count` fields into dst[0..cap). Returns bytes written, or 0 on error
 * (cap too small / OOM). Even an empty field section is two bytes (the prefix),
 * so 0 is unambiguous. The caller sizes dst to roughly twice the raw header size
 * and retries larger on 0. */
size_t qpack_encode_block(qpack_encoder_t* e, const qpack_header_t* fields, size_t count,
                          uint8_t* dst, size_t cap);
size_t qpack_encode_block_for_stream(qpack_encoder_t* e, uint64_t stream_id,
                                     const qpack_header_t* fields, size_t count,
                                     uint8_t* dst, size_t cap);

#endif

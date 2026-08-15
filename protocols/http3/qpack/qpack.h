#ifndef __QPACK__
#define __QPACK__

#include <stddef.h>
#include <stdint.h>

/* QPACK (RFC 9204) -- header compression for HTTP/3.
 *
 * Complete on both sides (docs/http3/06-qpack.md §6.2): dynamic tables with
 * absolute indexing and eviction, all three insert forms, Duplicate, the
 * encoder and decoder instruction streams, blocked field sections, and the
 * acknowledgement bookkeeping that lets an encoder know which entries the peer
 * has actually seen.
 *
 * Two decoders live in this file, and the difference is what each *advertises*:
 * a decoder created with (0, 0) is the static-only case -- it refuses any
 * reference into a dynamic table and any Required Insert Count above zero,
 * because it told the peer there was no table -- while one created with a real
 * capacity accepts the lot. Both are conforming; the dynamic table is optional
 * per RFC 9204, and the zero case is what a peer gets when it advertises zero
 * to us. What this server advertises is in h3session.c.
 *
 * Field validity (RFC 9114 §4.3) is NOT checked here -- this module hands back
 * the fields the peer encoded, exactly as HPACK does. The caller (h3session,
 * via the shared httpfields_to_request) applies the protocol rules. */

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
    /* An encoder-stream instruction this decoder cannot accept: an insert or
     * duplicate when we advertised capacity 0, or a Set Dynamic Table Capacity
     * above what we advertised. Connection error QPACK_ENCODER_STREAM_ERROR
     * (§4.3.1). */
    QPACK_ERR_ENCODER_STREAM,
    /* A decoder-stream instruction that contradicts what our encoder has done:
     * an Insert Count Increment of zero, which §4.4.3 forbids outright, or one
     * that acknowledges more insertions than we made. Connection error
     * QPACK_DECODER_STREAM_ERROR. */
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
    uint64_t insertions;
    uint64_t evictions;
} qpack_decoder_t;

/* Create a decoder with the capacity and blocked-stream limit this side is
 * about to advertise. (0, 0) builds the static-only decoder described at the
 * top of this file. Returns NULL on OOM. */
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
 * What is legal here follows from what this decoder advertised. With a real
 * capacity, all of them are: Set Dynamic Table Capacity (up to that value),
 * Insert With Name Reference, Insert With Literal Name and Duplicate. With
 * capacity 0 the peer has no table to insert into, so exactly one instruction
 * remains legal -- `Set Dynamic Table Capacity` with a value of 0, which real
 * clients do send as an opener -- and every other one, or any capacity above
 * what we advertised, is QPACK_ERR_ENCODER_STREAM: a connection error of type
 * QPACK_ENCODER_STREAM_ERROR (§4.3.1).
 *
 * Refusing every byte instead would be wrong: capacity-0 is legal and common.
 * The parser is resumable, because a stream hands over bytes in arbitrary
 * pieces; a partial instruction leaves *consumed short of len and the caller
 * re-feeds the remainder. */
qpack_status_e qpack_decoder_read_encoder(qpack_decoder_t* d, const uint8_t* data,
                                          size_t len, size_t* consumed);

/* The mirror of the above for the peer's decoder stream, which talks to our
 * encoder (§4.4).
 *
 * `qpack_encoder_read_decoder_state` applies them: Section Acknowledgment
 * settles an outstanding section and raises the Known Received Count, Stream
 * Cancellation drops one, and Insert Count Increment advances what the peer has
 * confirmed -- which is what tells the encoder an entry is safe to reference
 * without blocking the peer.
 *
 * Resumable on the same terms as the encoder-stream reader. */
struct qpack_encoder;
typedef struct qpack_outstanding_section qpack_outstanding_section_t;
qpack_status_e qpack_encoder_read_decoder_state(struct qpack_encoder* e,
                                                 const uint8_t* data, size_t len,
                                                 size_t* consumed);
/* Validate decoder-stream instructions without an encoder to apply them to --
 * for a caller that keeps no dynamic table of its own, and for tests. */
qpack_status_e qpack_encoder_read_decoder(const uint8_t* data, size_t len,
                                          size_t* consumed);

/* ---- Encoder ---- *
 *
 * Picks the smallest representation available for each field: an indexed line
 * (static or dynamic) on an exact match, else a literal with a name reference,
 * else a literal with a literal name -- Huffman-encoding a string only when
 * that is shorter. Whether the dynamic half of that is used at all depends on
 * what the peer advertised: against a peer offering capacity 0 the output is
 * static-and-literal only, with the prefix fixed at RIC=0, Delta Base=0.
 *
 * A field marked never_indexed is emitted as a literal with N=1 (never an
 * indexed line, and never inserted), so neither this table nor a peer
 * intermediary re-indexes a value that may be sensitive. */

typedef struct qpack_encoder {
    /* Negotiated from the peer's SETTINGS: both are 0 until they arrive, which
     * is what keeps the first field sections static-only. */
    size_t max_capacity;
    size_t max_blocked;
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
    uint64_t evictions;
    uint64_t literal_fields;
    uint64_t dynamic_fields;
    uint64_t admission_hashes[64]; /* bounded two-hit admission sketch */
    size_t admission_next;
} qpack_encoder_t;

qpack_encoder_t* qpack_encoder_create(size_t max_capacity, size_t max_blocked);
void qpack_encoder_free(qpack_encoder_t* e);
/* Apply the peer's SETTINGS before the first encoder instruction or field
 * section. Limits cannot be raised or changed after encoder state exists. */
qpack_status_e qpack_encoder_set_limits(qpack_encoder_t* e, size_t max_capacity,
                                        size_t max_blocked);
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
qpack_status_e qpack_encoder_prepare_fields(qpack_encoder_t* e,
                                             const qpack_header_t* fields,
                                             size_t count);

/* Encode `count` fields into dst[0..cap). Returns bytes written, or 0 on error
 * (cap too small / OOM). Even an empty field section is two bytes (the prefix),
 * so 0 is unambiguous. The caller sizes dst to roughly twice the raw header size
 * and retries larger on 0. */
size_t qpack_encode_block(qpack_encoder_t* e, const qpack_header_t* fields, size_t count,
                          uint8_t* dst, size_t cap);
size_t qpack_encode_block_for_stream(qpack_encoder_t* e, uint64_t stream_id,
                                     const qpack_header_t* fields, size_t count,
                                     uint8_t* dst, size_t cap);
size_t qpack_encode_block_for_stream_confirmed(qpack_encoder_t* e, uint64_t stream_id,
                                               const qpack_header_t* fields,
                                               size_t count, uint8_t* dst, size_t cap);

#endif

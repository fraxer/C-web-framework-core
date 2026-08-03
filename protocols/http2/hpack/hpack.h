#ifndef __HPACK__
#define __HPACK__

#include <stddef.h>
#include <stdint.h>

/* HPACK (RFC 7541) header compression for HTTP/2.
 *
 * Self-contained module: depends only on the C standard library, so it can be
 * unit-tested in isolation and reused by the future HTTP/2 connection layer.
 * Tables (Huffman, static) are generated verbatim from RFC 7541 Appendix A/B
 * by gen_tables.py — see hpack_huffman.h / hpack_statictable.h.
 *
 * A decoded/encoded header field uses non-null-terminated byte slices, mirroring
 * the codebase's http_header_t (name_len/value_len carry the real length). */

typedef struct hpack_header {
    char*  name;
    size_t name_len;
    char*  value;
    size_t value_len;
} hpack_header_t;

typedef enum {
    HPACK_OK = 0,
    HPACK_ERR_COMPRESSION, /* bad Huffman code / EOS mid-stream / bad padding → connection error */
    HPACK_ERR_INVALID,     /* bad index, forbidden representation, truncated input, overflow */
    HPACK_ERR_MEMORY,
    HPACK_ERR_TOO_LARGE    /* decoded list exceeded max_list_size — decode aborted */
} hpack_status_e;

/* ---- Dynamic table (RFC 7541 §4) ----
 * Contiguous array, index 0 = newest. The decoder and encoder keep independent
 * instances (the dynamic table is per-direction per RFC §4.2). */
typedef struct hpack_dtable_entry {
    char*  name;
    size_t name_len;
    char*  value;
    size_t value_len;
} hpack_dtable_entry_t;

typedef struct hpack_dynamic_table {
    hpack_dtable_entry_t* entries;
    size_t count;
    size_t cap;
    size_t total;    /* sum of entry sizes (name + value + 32) */
    size_t max;      /* current size limit (may shrink via size-update) */
    size_t hard_max; /* configured ceiling (SETTINGS_HEADER_TABLE_SIZE) */
} hpack_dynamic_table_t;

void hpack_dynamic_table_init(hpack_dynamic_table_t* t, size_t max_table_size);
void hpack_dynamic_table_free(hpack_dynamic_table_t* t);
/* Apply a dynamic table size update (RFC §4.2 / §6.3). new_max <= hard_max. */
hpack_status_e hpack_dynamic_table_set_max(hpack_dynamic_table_t* t, size_t new_max);
/* Insert a header (copied) at the front, evicting oldest entries as needed. */
hpack_status_e hpack_dynamic_table_insert(hpack_dynamic_table_t* t,
                                          const char* name, size_t name_len,
                                          const char* value, size_t value_len);
/* Resolve a 1-based HPACK index: 1..61 static, 62+ dynamic. Pointers are borrowed
 * from the table (do not free). */
hpack_status_e hpack_resolve_index(const hpack_dynamic_table_t* t, size_t idx,
                                   const char** name, size_t* name_len,
                                   const char** value, size_t* value_len);

/* ---- Decoder ---- */
typedef struct hpack_decoder {
    hpack_dynamic_table_t table;
} hpack_decoder_t;

hpack_decoder_t* hpack_decoder_create(size_t max_table_size);
void hpack_decoder_free(hpack_decoder_t* d);
/* Decode a complete header block. On HPACK_OK, *out is a malloc'd array of
 * *out_count entries (caller frees with hpack_headers_free). Name/value bytes
 * within each entry are null-terminated for convenience but name_len/value_len
 * hold the authoritative length.
 *
 * max_list_size bounds the *decoded* size — the sum of `name_len + value_len +
 * 32` over the fields, which is how RFC 9113 §6.5.2 measures
 * SETTINGS_MAX_HEADER_LIST_SIZE — and returns HPACK_ERR_TOO_LARGE as soon as it
 * is passed. 0 disables the check. This is the only bound on how much a block
 * can expand to: a few bytes of indexed repeats decode into megabytes, so a
 * caller with no limit has none. Aborting mid-block leaves the dynamic table
 * out of step with the peer's, so a caller that wants to keep the connection
 * must pass a limit it is willing to lose the connection over, and enforce any
 * softer, per-request limit on the returned fields. */
hpack_status_e hpack_decoder_decode(hpack_decoder_t* d,
                                    const uint8_t* block, size_t len,
                                    size_t max_list_size,
                                    hpack_header_t** out, size_t* out_count);
void hpack_headers_free(hpack_header_t* headers, size_t count);

/* ---- Encoder ---- */
typedef struct hpack_encoder {
    hpack_dynamic_table_t table;
    /* Pending dynamic table size update (RFC §6.3), emitted at the head of the
     * next block. SIZE_MAX = none pending. */
    size_t pending_size_update;
} hpack_encoder_t;

hpack_encoder_t* hpack_encoder_create(size_t max_table_size);
void hpack_encoder_free(hpack_encoder_t* e);
/* Resize the encoder's dynamic table after the peer changed
 * SETTINGS_HEADER_TABLE_SIZE. The new size is clamped to the ceiling the
 * encoder was created with, and the change is announced to the peer's decoder
 * by the size-update instruction at the start of the next encoded block —
 * resizing the table silently would desync the two tables. */
void hpack_encoder_set_max_table_size(hpack_encoder_t* e, size_t max_table_size);
/* Encode headers into a malloc'd buffer. If use_huffman != 0, string literals
 * are Huffman-encoded when it shortens them. *out is owned by the caller. */
hpack_status_e hpack_encoder_encode(hpack_encoder_t* e,
                                    const hpack_header_t* headers, size_t count,
                                    int use_huffman,
                                    uint8_t** out, size_t* out_len);

/* ---- Primitives exposed for unit tests ---- */
/* Decode an HPACK integer (RFC §5.1). *pp points at the first byte (whose low
 * `prefix_bits` carry the value; high bits are the representation type) and is
 * advanced past the integer. Returns 0 with *st=HPACK_OK on success. */
uint32_t hpack_decode_int(const uint8_t** pp, const uint8_t* end,
                          uint8_t prefix_bits, hpack_status_e* st);
/* Encode an HPACK integer into dst[0..cap). prefix_byte carries the high
 * (representation) bits to OR with the prefix. Returns bytes written, or 0 on
 * cap overflow (0 is also a valid length for value<prefix encoded in one byte,
 * so callers must size dst >= 1). */
size_t hpack_encode_int(uint8_t* dst, size_t cap, uint32_t value,
                        uint8_t prefix_bits, uint8_t prefix_byte);

/* Huffman (RFC §5.2). */
size_t hpack_huffman_encoded_len(const uint8_t* data, size_t len);
hpack_status_e hpack_huffman_encode(const uint8_t* data, size_t len,
                                    uint8_t* dst, size_t cap, size_t* out_len);
hpack_status_e hpack_huffman_decode(const uint8_t* data, size_t len,
                                    uint8_t* dst, size_t cap, size_t* out_len);

#endif

#include "hpack.h"

#include <stdlib.h>
#include <string.h>

#include "huffman.h"
#include "hpack_statictable.h"

/* ======================================================================= *
 *  Internal growable byte buffer (encoder side; keeps hpack dependency-free)
 * ======================================================================= */

typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
    int      oom;
} hpack_bytebuf_t;

static void bb_init(hpack_bytebuf_t* b) {
    b->data = NULL; b->len = 0; b->cap = 0; b->oom = 0;
}

static int bb_reserve(hpack_bytebuf_t* b, size_t need) {
    if (b->oom) return 0;
    if (need <= b->cap - b->len && b->len <= b->cap) return 1;
    size_t ncap = b->cap ? b->cap : 64;
    while (ncap - b->len < need) {
        if (ncap > ((size_t)-1) / 2) { b->oom = 1; return 0; }
        ncap *= 2;
    }
    uint8_t* nd = realloc(b->data, ncap);
    if (nd == NULL) { b->oom = 1; return 0; }
    b->data = nd; b->cap = ncap;
    return 1;
}

static int bb_write(hpack_bytebuf_t* b, const uint8_t* d, size_t n) {
    if (n == 0) return 1;
    if (!bb_reserve(b, n)) return 0;
    memcpy(b->data + b->len, d, n);
    b->len += n;
    return 1;
}

/* Encode an integer straight into the buffer. A 32-bit prefix integer occupies
 * at most 6 octets (1 prefix + 5 continuation), so reserve once and encode into
 * the tail via the shared primitive. */
static int bb_encode_int(hpack_bytebuf_t* b, uint32_t value,
                         uint8_t prefix_bits, uint8_t prefix_byte) {
    if (!bb_reserve(b, 6)) return 0;
    const size_t n = prefix_int_encode(b->data + b->len, b->cap - b->len, value,
                                       prefix_bits, prefix_byte);
    if (n == 0) { b->oom = 1; return 0; }
    b->len += n;
    return 1;
}

/* ======================================================================= *
 *  Integer representation (RFC 7541 §5.1)
 * ======================================================================= *
 *  Thin wrappers over the shared prefix-int codec in misc/huffman.c, keeping
 *  the hpack-shaped signatures (cursor + status, 32-bit) this file and its tests
 *  were written against. The bounds checks the codec used to carry inlined here
 *  move with it: prefix_int_decode caps at 2^62, and the 32-bit clamp below
 *  preserves HPACK's narrower range. */

uint32_t hpack_decode_int(const uint8_t** pp, const uint8_t* end,
                          uint8_t prefix_bits, hpack_status_e* st) {
    uint64_t v = 0;
    const size_t n = prefix_int_decode(*pp, (size_t)(end - *pp), prefix_bits, &v);
    if (n == 0 || v > 0xffffffffu) { *st = HPACK_ERR_INVALID; return 0; }
    *pp += n;
    *st = HPACK_OK;
    return (uint32_t)v;
}

size_t hpack_encode_int(uint8_t* dst, size_t cap, uint32_t value,
                        uint8_t prefix_bits, uint8_t prefix_byte) {
    return prefix_int_encode(dst, cap, value, prefix_bits, prefix_byte);
}

/* ======================================================================= *
 *  Huffman coding (RFC 7541 §5.2, Appendix B)
 * ======================================================================= *
 *  Thin wrappers over the shared codec in misc/huffman.c (the nibble DFA lives
 *  in misc/huffman_table.h). The hpack-shaped signatures and the
 *  COMPRESSION/INVALID split are kept so callers and tests are unchanged; -1
 *  from the shared codec maps to COMPRESSION on decode (a malformed stream) and
 *  to INVALID on encode (output cap too small). The decode cap-overflow case is
 *  unreachable in practice -- hpack_decode_string sizes the buffer at 2*length+8
 *  and Huffman expands by at most ~8/5 -- which is why collapsing it onto
 *  COMPRESSION changes no observable behaviour. */

size_t hpack_huffman_encoded_len(const uint8_t* data, size_t len) {
    return huffman_encoded_len(data, len);
}

hpack_status_e hpack_huffman_encode(const uint8_t* data, size_t len,
                                    uint8_t* dst, size_t cap, size_t* out_len) {
    const ssize_t n = huffman_encode(dst, cap, data, len);
    if (n < 0) return HPACK_ERR_INVALID;
    *out_len = (size_t)n;
    return HPACK_OK;
}

hpack_status_e hpack_huffman_decode(const uint8_t* data, size_t len,
                                    uint8_t* dst, size_t cap, size_t* out_len) {
    const ssize_t n = huffman_decode(dst, cap, data, len);
    if (n < 0) return HPACK_ERR_COMPRESSION;
    *out_len = (size_t)n;
    return HPACK_OK;
}

/* ======================================================================= *
 *  String literals (RFC 7541 §5.2)
 * ======================================================================= */

/* Decode a string literal. *out is a malloc'd, null-terminated buffer. */
static hpack_status_e hpack_decode_string(const uint8_t** pp, const uint8_t* end,
                                          char** out, size_t* out_len) {
    if (*pp >= end) return HPACK_ERR_INVALID;
    int huffman = (**pp & 0x80) != 0;
    hpack_status_e st;
    uint32_t length = hpack_decode_int(pp, end, 7, &st);
    if (st) return st;
    if ((size_t)(end - *pp) < length) return HPACK_ERR_INVALID;
    const uint8_t* strdata = *pp;
    *pp += length;

    if (huffman) {
        size_t cap = (size_t)length * 2 + 8; /* worst case ~8/5 expansion */
        char* dst = malloc(cap);
        if (dst == NULL) return HPACK_ERR_MEMORY;
        size_t n = 0;
        st = hpack_huffman_decode(strdata, length, (uint8_t*)dst, cap - 1, &n);
        if (st) { free(dst); return st; }
        dst[n] = '\0';
        *out = dst; *out_len = n;
    } else {
        char* dst = malloc(length + 1);
        if (dst == NULL) return HPACK_ERR_MEMORY;
        memcpy(dst, strdata, length);
        dst[length] = '\0';
        *out = dst; *out_len = length;
    }
    return HPACK_OK;
}

/* ======================================================================= *
 *  Dynamic table (RFC 7541 §4)
 * ======================================================================= */

static size_t entry_size(size_t name_len, size_t value_len) {
    return name_len + value_len + 32;
}

void hpack_dynamic_table_init(hpack_dynamic_table_t* t, size_t max_table_size) {
    t->entries = NULL; t->count = 0; t->cap = 0; t->total = 0;
    t->max = max_table_size; t->hard_max = max_table_size;
}

void hpack_dynamic_table_free(hpack_dynamic_table_t* t) {
    for (size_t i = 0; i < t->count; i++) {
        free(t->entries[i].name);
        free(t->entries[i].value);
    }
    free(t->entries);
    t->entries = NULL; t->count = 0; t->cap = 0; t->total = 0;
}

static void dt_evict_oldest(hpack_dynamic_table_t* t) {
    if (t->count == 0) return;
    size_t i = --t->count; /* oldest = entries[count-1] */
    hpack_dtable_entry_t* e = &t->entries[i];
    t->total -= entry_size(e->name_len, e->value_len);
    free(e->name); free(e->value);
    e->name = NULL; e->value = NULL; e->name_len = e->value_len = 0;
}

hpack_status_e hpack_dynamic_table_set_max(hpack_dynamic_table_t* t, size_t new_max) {
    if (new_max > t->hard_max) return HPACK_ERR_INVALID;
    t->max = new_max;
    while (t->count > 0 && t->total > t->max) dt_evict_oldest(t);
    return HPACK_OK;
}

hpack_status_e hpack_dynamic_table_insert(hpack_dynamic_table_t* t,
                                          const char* name, size_t name_len,
                                          const char* value, size_t value_len) {
    size_t sz = entry_size(name_len, value_len);
    if (sz > t->max) {
        /* Entry larger than the whole table: empty it, do not insert (RFC §4.4).
         * Nothing is read from name/value here, so the eviction is safe. */
        while (t->count > 0) dt_evict_oldest(t);
        return HPACK_OK;
    }

    /* Copy first, evict second. `name` and `value` may point *into* this very
     * table — a literal field takes its name by index from it — and the entry
     * they point at may be the one the eviction below frees. RFC 7541 §4.4 warns
     * about exactly this; doing it in the other order is a use-after-free that
     * also writes the resulting garbage back into the table, desynchronising
     * every later block on the connection (docs/http2/10, H.1). */
    char* ncopy = malloc(name_len + 1);
    char* vcopy = malloc(value_len + 1);
    if (ncopy == NULL || vcopy == NULL) { free(ncopy); free(vcopy); return HPACK_ERR_MEMORY; }
    memcpy(ncopy, name, name_len); ncopy[name_len] = '\0';
    memcpy(vcopy, value, value_len); vcopy[value_len] = '\0';

    if (t->count == t->cap) {
        size_t ncap = t->cap ? t->cap * 2 : 8;
        hpack_dtable_entry_t* ne = realloc(t->entries, ncap * sizeof(*ne));
        if (ne == NULL) { free(ncopy); free(vcopy); return HPACK_ERR_MEMORY; }
        t->entries = ne; t->cap = ncap;
    }

    while (t->count > 0 && t->total + sz > t->max) dt_evict_oldest(t);

    memmove(t->entries + 1, t->entries, t->count * sizeof(*t->entries));
    t->entries[0].name = ncopy; t->entries[0].name_len = name_len;
    t->entries[0].value = vcopy; t->entries[0].value_len = value_len;
    t->count++;
    t->total += sz;
    return HPACK_OK;
}

hpack_status_e hpack_resolve_index(const hpack_dynamic_table_t* t, size_t idx,
                                   const char** name, size_t* name_len,
                                   const char** value, size_t* value_len) {
    if (idx == 0) return HPACK_ERR_INVALID;
    if (idx < HPACK_STATIC_TABLE_SIZE) {
        const hpack_static_entry_t* e = &hpack_static_table[idx];
        *name = e->name; *name_len = e->name_len;
        *value = e->value; *value_len = e->value_len;
        return HPACK_OK;
    }
    size_t didx = idx - (HPACK_STATIC_TABLE_SIZE - 1); /* 62 → dynamic index 1 (newest) */
    if (didx == 0 || didx > t->count) return HPACK_ERR_INVALID;
    const hpack_dtable_entry_t* e = &t->entries[didx - 1];
    *name = e->name; *name_len = e->name_len;
    *value = e->value; *value_len = e->value_len;
    return HPACK_OK;
}

/* ======================================================================= *
 *  Decoder (RFC 7541 §6)
 * ======================================================================= */

hpack_decoder_t* hpack_decoder_create(size_t max_table_size) {
    hpack_decoder_t* d = malloc(sizeof(*d));
    if (d == NULL) return NULL;
    hpack_dynamic_table_init(&d->table, max_table_size);
    return d;
}

void hpack_decoder_free(hpack_decoder_t* d) {
    if (d == NULL) return;
    hpack_dynamic_table_free(&d->table);
    free(d);
}

void hpack_headers_free(hpack_header_t* headers, size_t count) {
    if (headers == NULL) return;
    for (size_t i = 0; i < count; i++) {
        free(headers[i].name);
        free(headers[i].value);
    }
    free(headers);
}

/* Append an owned header (copies name/value, null-terminated). */
static int out_push(hpack_header_t** arr, size_t* count, size_t* cap,
                    const char* name, size_t name_len,
                    const char* value, size_t value_len, int never_indexed) {
    if (*count == *cap) {
        size_t nc = *cap ? *cap * 2 : 8;
        hpack_header_t* na = realloc(*arr, nc * sizeof(**arr));
        if (na == NULL) return 0;
        *arr = na; *cap = nc;
    }
    char* n = malloc(name_len + 1);
    char* v = malloc(value_len + 1);
    if (n == NULL || v == NULL) { free(n); free(v); return 0; }
    memcpy(n, name, name_len); n[name_len] = '\0';
    memcpy(v, value, value_len); v[value_len] = '\0';
    (*arr)[*count].name = n; (*arr)[*count].name_len = name_len;
    (*arr)[*count].value = v; (*arr)[*count].value_len = value_len;
    (*arr)[*count].never_indexed = never_indexed;
    (*count)++;
    return 1;
}

/* Accumulate the decoded size of one field and report whether the block has
 * outgrown the limit (RFC 9113 §6.5.2 accounting: name + value + 32). */
static int list_size_exceeded(size_t* total, size_t max_list_size,
                              size_t name_len, size_t value_len) {
    if (max_list_size == 0) return 0;

    *total += name_len + value_len + 32;

    return *total > max_list_size;
}

hpack_status_e hpack_decoder_decode(hpack_decoder_t* d,
                                    const uint8_t* block, size_t len,
                                    size_t max_list_size,
                                    hpack_header_t** out, size_t* out_count) {
    const uint8_t* p = block;
    const uint8_t* end = block + len;
    hpack_header_t* arr = NULL;
    size_t cnt = 0, cap = 0;
    size_t list_size = 0;
    hpack_status_e st = HPACK_OK;
    /* RFC 7541 §4.2: dynamic table size updates MUST occur at the beginning of
     * a header block, before any header field representation. */
    int field_seen = 0;

    while (p < end) {
        uint8_t b = *p;

        if (b & 0x80) {
            /* Indexed Header Field (§6.1) */
            st = HPACK_OK;
            uint32_t idx = hpack_decode_int(&p, end, 7, &st);
            if (st) goto done;
            const char *name, *value; size_t nl, vl;
            st = hpack_resolve_index(&d->table, idx, &name, &nl, &value, &vl);
            if (st) goto done;
            /* Checked before the copy: an indexed field is one byte on the wire
             * and can be repeated for as long as the block lasts, so this is the
             * representation a decompression bomb is built from. */
            if (list_size_exceeded(&list_size, max_list_size, nl, vl)) { st = HPACK_ERR_TOO_LARGE; goto done; }
            if (!out_push(&arr, &cnt, &cap, name, nl, value, vl, 0)) { st = HPACK_ERR_MEMORY; goto done; }
            field_seen = 1;
        } else if ((b & 0xe0) == 0x20) {
            /* Dynamic Table Size Update (§6.3) */
            if (field_seen) { st = HPACK_ERR_COMPRESSION; goto done; }
            st = HPACK_OK;
            uint32_t new_max = hpack_decode_int(&p, end, 5, &st);
            if (st) goto done;
            st = hpack_dynamic_table_set_max(&d->table, new_max);
            if (st) goto done;
        } else {
            /* Literal Header Field: incremental indexing (01xxxxxx, 0x40-0x7f),
             * without indexing (0000xxxx), or never indexed (0001xxxx). For the
             * decoder the last two are identical; only incremental indexing adds
             * to the dynamic table. */
            int do_index = (b & 0xc0) == 0x40; /* top two bits == 01 */
            /* §6.2.3: 0001xxxx is "never indexed" — like "without indexing" for
             * us, but the distinction is reported so a caller can see how the
             * peer classified the field. */
            int never_indexed = (b & 0xf0) == 0x10;
            uint8_t prefix = do_index ? 6 : 4;
            st = HPACK_OK;
            uint32_t idx = hpack_decode_int(&p, end, prefix, &st);
            if (st) goto done;

            const char* name; size_t name_len;
            char* owned_name = NULL; size_t owned_name_len = 0;
            if (idx == 0) {
                st = hpack_decode_string(&p, end, &owned_name, &owned_name_len);
                if (st) goto done;
                name = owned_name; name_len = owned_name_len;
            } else {
                const char* dummy_v; size_t dummy_vl;
                st = hpack_resolve_index(&d->table, idx, &name, &name_len, &dummy_v, &dummy_vl);
                if (st) goto done;
            }

            char* value; size_t value_len;
            st = hpack_decode_string(&p, end, &value, &value_len);
            if (st) { free(owned_name); goto done; }

            if (list_size_exceeded(&list_size, max_list_size, name_len, value_len)) {
                free(owned_name); free(value); st = HPACK_ERR_TOO_LARGE; goto done;
            }

            if (!out_push(&arr, &cnt, &cap, name, name_len, value, value_len, never_indexed)) {
                free(owned_name); free(value); st = HPACK_ERR_MEMORY; goto done;
            }
            if (do_index)
                st = hpack_dynamic_table_insert(&d->table, name, name_len, value, value_len);

            free(owned_name);
            free(value);
            if (st) goto done;

            field_seen = 1;
        }
    }

    *out = arr;
    *out_count = cnt;
    return HPACK_OK;

done:
    hpack_headers_free(arr, cnt);
    *out = NULL; *out_count = 0;
    return st;
}

/* ======================================================================= *
 *  Encoder
 * ======================================================================= */

hpack_encoder_t* hpack_encoder_create(size_t max_table_size) {
    hpack_encoder_t* e = malloc(sizeof(*e));
    if (e == NULL) return NULL;
    hpack_dynamic_table_init(&e->table, max_table_size);
    e->pending_size_update = SIZE_MAX;
    e->pending_min_size = SIZE_MAX;
    return e;
}

void hpack_encoder_set_max_table_size(hpack_encoder_t* e, size_t max_table_size) {
    if (max_table_size > e->table.hard_max) max_table_size = e->table.hard_max;
    if (max_table_size == e->table.max) return;
    if (max_table_size < e->pending_min_size) e->pending_min_size = max_table_size;
    e->pending_size_update = max_table_size;
    /* Evict immediately, including when more SETTINGS arrive before encoding. */
    hpack_dynamic_table_set_max(&e->table, max_table_size);
}

void hpack_encoder_free(hpack_encoder_t* e) {
    if (e == NULL) return;
    hpack_dynamic_table_free(&e->table);
    free(e);
}

/* Append a string literal, Huffman-encoded when requested and shorter. */
static int enc_string(hpack_bytebuf_t* b, const uint8_t* data, size_t len, int use_huffman) {
    if (use_huffman) {
        size_t hlen = hpack_huffman_encoded_len(data, len);
        if (hlen < len) {
            if (!bb_encode_int(b, (uint32_t)hlen, 7, 0x80)) return 0; /* H=1 */
            if (!bb_reserve(b, hlen)) return 0;
            size_t n = 0;
            if (hpack_huffman_encode(data, len, b->data + b->len, hlen, &n) != HPACK_OK) return 0;
            b->len += n;
            return 1;
        }
    }
    /* Literal (no Huffman). */
    if (!bb_encode_int(b, (uint32_t)len, 7, 0x00)) return 0; /* H=0 */
    return bb_write(b, data, len);
}

/* Find an existing table entry that matches name (+ optionally value).
 * Returns a 1-based HPACK index, or 0 if no match (0 is never a valid index).
 * Static table (1..61) is scanned first, then the dynamic table (62+). */
static size_t enc_find(const hpack_dynamic_table_t* t,
                       const char* name, size_t name_len,
                       const char* value, size_t value_len,
                       int match_value) {
    for (size_t i = 1; i < HPACK_STATIC_TABLE_SIZE; i++) {
        const hpack_static_entry_t* e = &hpack_static_table[i];
        /* Length first: it rejects nearly every entry without touching the
         * strings, and the table carries its lengths precisely so that this
         * scan costs no strlen at all. */
        if (e->name_len == name_len && memcmp(e->name, name, name_len) == 0) {
            if (!match_value) return i;
            if (e->value_len == value_len && memcmp(e->value, value, value_len) == 0)
                return i;
        }
    }
    for (size_t i = 0; i < t->count; i++) {
        const hpack_dtable_entry_t* e = &t->entries[i];
        if (e->name_len == name_len && memcmp(e->name, name, name_len) == 0) {
            size_t dyn_idx = (size_t)(HPACK_STATIC_TABLE_SIZE - 1) + i + 1; /* 62 + i */
            if (!match_value) return dyn_idx;
            if (e->value_len == value_len && memcmp(e->value, value, value_len) == 0)
                return dyn_idx;
        }
    }
    return 0; /* not found */
}

hpack_status_e hpack_encoder_encode(hpack_encoder_t* e,
                                    const hpack_header_t* headers, size_t count,
                                    int use_huffman,
                                    uint8_t** out, size_t* out_len) {
    hpack_bytebuf_t b;
    bb_init(&b);

    /* Dynamic table size update (RFC §6.3) must lead the block. */
    if (e->pending_size_update != SIZE_MAX) {
        if ((e->pending_min_size < e->pending_size_update &&
             !bb_encode_int(&b, (uint32_t)e->pending_min_size, 5, 0x20)) ||
            !bb_encode_int(&b, (uint32_t)e->pending_size_update, 5, 0x20)) {
            free(b.data);
            *out = NULL; *out_len = 0;
            return HPACK_ERR_MEMORY;
        }
        e->pending_size_update = SIZE_MAX;
        e->pending_min_size = SIZE_MAX;
    }

    for (size_t i = 0; i < count; i++) {
        const char* name = headers[i].name;
        size_t name_len = headers[i].name_len;
        const uint8_t* value = (const uint8_t*)headers[i].value;
        size_t value_len = headers[i].value_len;

        /* Never indexed (§6.2.3 / §7.1.3): the value is a secret, so it must not
         * enter our dynamic table — nor the peer's, which the 0001 pattern is
         * what tells it. An indexed representation is skipped for the same
         * reason: it could only come from the table this field never enters, and
         * looking it up would be pointless work.
         *
         * The *name* is not secret, so an indexed name is still used when there
         * is one — that is the whole compression this field gets. */
        if (headers[i].never_indexed) {
            const size_t name_idx = enc_find(&e->table, name, name_len, NULL, 0, 0);

            if (!bb_encode_int(&b, (uint32_t)name_idx, 4, 0x10)) b.oom = 1;
            if (name_idx == 0 && !enc_string(&b, (const uint8_t*)name, name_len, use_huffman))
                b.oom = 1;
            if (!enc_string(&b, value, value_len, use_huffman)) b.oom = 1;

            if (b.oom) {
                free(b.data);
                *out = NULL; *out_len = 0;
                return HPACK_ERR_MEMORY;
            }

            continue;
        }

        /* Exact (name+value) match → indexed. */
        size_t exact = enc_find(&e->table, name, name_len,
                                (const char*)value, value_len, 1);
        if (exact != 0) {
            if (!bb_encode_int(&b, (uint32_t)exact, 7, 0x80)) { b.oom = 1; }
        } else {
            /* Literal with incremental indexing. */
            size_t name_idx = enc_find(&e->table, name, name_len, NULL, 0, 0);
            if (name_idx != 0) {
                if (!bb_encode_int(&b, (uint32_t)name_idx, 6, 0x40)) b.oom = 1;
            } else {
                if (!bb_encode_int(&b, 0, 6, 0x40)) b.oom = 1;
                if (!enc_string(&b, (const uint8_t*)name, name_len, use_huffman)) b.oom = 1;
            }
            if (!enc_string(&b, value, value_len, use_huffman)) b.oom = 1;
            if (hpack_dynamic_table_insert(&e->table, name, name_len,
                                           (const char*)value, value_len) != HPACK_OK)
                b.oom = 1;
        }
        if (b.oom) {
            free(b.data);
            *out = NULL; *out_len = 0;
            return HPACK_ERR_MEMORY;
        }
    }

    *out = b.data; *out_len = b.len;
    return HPACK_OK;
}

#include "qpack.h"

#include <stdlib.h>
#include <string.h>

#include "huffman.h"            /* shared Huffman + prefix-int (RFC 9204 §5) */
#include "qpack_statictable.h"  /* generated: 99-entry static table */

struct qpack_dynamic_entry {
    char* name;
    size_t name_len;
    char* value;
    size_t value_len;
    size_t size;
    uint64_t absolute;
};

struct qpack_outstanding_section {
    uint64_t stream_id;
    uint64_t required_insert_count;
};

static qpack_status_e __decode_raw(const uint8_t*, size_t, int, char**, size_t*);
static qpack_status_e __decode_value(const uint8_t**, const uint8_t*, char**, size_t*);

/* ---- Lifecycle ---- */

qpack_decoder_t* qpack_decoder_create(size_t max_capacity, size_t max_blocked) {
    qpack_decoder_t* d = calloc(1, sizeof * d);
    if (d == NULL) return NULL;
    d->max_capacity = max_capacity;
    d->max_blocked = max_blocked;
    return d;
}

void qpack_decoder_free(qpack_decoder_t* d) {
    if (d == NULL) return;
    for (size_t i = 0; i < d->entry_count; i++) {
        free(d->entries[i].name);
        free(d->entries[i].value);
    }
    free(d->entries);
    free(d->pending);
    free(d);
}

size_t qpack_decoder_capacity(const qpack_decoder_t* d) { return d ? d->capacity : 0; }
size_t qpack_decoder_bytes(const qpack_decoder_t* d) { return d ? d->bytes : 0; }
uint64_t qpack_decoder_insert_count(const qpack_decoder_t* d) {
    return d ? d->insert_count : 0;
}

static int __decoder_pending_int(qpack_decoder_t* d, uint64_t value,
                                 uint8_t prefix, uint8_t flags) {
    uint8_t encoded[16];
    const size_t n = prefix_int_encode(encoded, sizeof encoded, value, prefix, flags);
    if (n == 0) return 0;
    if (d->pending_len > SIZE_MAX - n) return 0;
    const size_t need = d->pending_len + n;
    if (need > d->pending_cap) {
        size_t cap = d->pending_cap ? d->pending_cap : 32;
        while (cap < need) {
            if (cap > SIZE_MAX / 2) return 0;
            cap *= 2;
        }
        uint8_t* grown = realloc(d->pending, cap);
        if (grown == NULL) return 0;
        d->pending = grown;
        d->pending_cap = cap;
    }
    memcpy(d->pending + d->pending_len, encoded, n);
    d->pending_len += n;
    return 1;
}

size_t qpack_decoder_pending(const qpack_decoder_t* d, const uint8_t** out) {
    if (out != NULL) *out = d != NULL ? d->pending : NULL;
    return d != NULL ? d->pending_len : 0;
}

void qpack_decoder_consume(qpack_decoder_t* d, size_t n) {
    if (d == NULL || n == 0) return;
    if (n >= d->pending_len) { d->pending_len = 0; return; }
    memmove(d->pending, d->pending + n, d->pending_len - n);
    d->pending_len -= n;
}

qpack_status_e qpack_decoder_ack_section(qpack_decoder_t* d, uint64_t stream_id) {
    if (d == NULL) return QPACK_ERR_DECODER_STREAM;
    return __decoder_pending_int(d, stream_id, 7, 0x80)
           ? QPACK_OK : QPACK_ERR_MEMORY;
}

qpack_status_e qpack_decoder_cancel_stream(qpack_decoder_t* d, uint64_t stream_id) {
    if (d == NULL) return QPACK_ERR_DECODER_STREAM;
    return __decoder_pending_int(d, stream_id, 6, 0x40)
           ? QPACK_OK : QPACK_ERR_MEMORY;
}

void qpack_headers_free(qpack_header_t* headers, size_t count) {
    if (headers == NULL) return;
    for (size_t i = 0; i < count; i++) {
        free(headers[i].name);
        free(headers[i].value);
    }
    free(headers);
}

/* ---- The peer's encoder stream ---- */

static void __dynamic_drop_oldest(qpack_decoder_t* d) {
    if (d->entry_count == 0) return;
    qpack_dynamic_entry_t* e = &d->entries[0];
    d->bytes -= e->size;
    free(e->name);
    free(e->value);
    d->entry_count--;
    if (d->entry_count != 0)
        memmove(d->entries, d->entries + 1, d->entry_count * sizeof *d->entries);
}

static const qpack_dynamic_entry_t* __dynamic_relative(const qpack_decoder_t* d,
                                                        uint64_t relative) {
    if (relative >= d->entry_count) return NULL;
    return &d->entries[d->entry_count - 1 - (size_t)relative];
}

static const qpack_dynamic_entry_t* __dynamic_absolute(const qpack_decoder_t* d,
                                                        uint64_t absolute) {
    for (size_t i = 0; i < d->entry_count; i++)
        if (d->entries[i].absolute == absolute) return &d->entries[i];
    return NULL;
}

static int __dynamic_insert(qpack_decoder_t* d, const char* name, size_t name_len,
                            const char* value, size_t value_len) {
    if (name_len > SIZE_MAX - value_len - 32) return 0;
    const size_t size = name_len + value_len + 32;

    /* §3.2.2: an entry larger than the current capacity cannot be inserted. */
    if (size > d->capacity) return 0;
    while (d->bytes > d->capacity - size) __dynamic_drop_oldest(d);

    if (d->entry_count == d->entry_cap) {
        const size_t ncap = d->entry_cap ? d->entry_cap * 2 : 8;
        if (ncap < d->entry_cap) return 0;
        qpack_dynamic_entry_t* grown = realloc(d->entries, ncap * sizeof *grown);
        if (grown == NULL) return 0;
        d->entries = grown;
        d->entry_cap = ncap;
    }

    char* ncopy = malloc(name_len + 1);
    char* vcopy = malloc(value_len + 1);
    if (ncopy == NULL || vcopy == NULL) {
        free(ncopy); free(vcopy); return 0;
    }
    memcpy(ncopy, name, name_len); ncopy[name_len] = '\0';
    memcpy(vcopy, value, value_len); vcopy[value_len] = '\0';

    qpack_dynamic_entry_t* e = &d->entries[d->entry_count++];
    e->name = ncopy; e->name_len = name_len;
    e->value = vcopy; e->value_len = value_len;
    e->size = size; e->absolute = d->insert_count++;
    d->bytes += size;
    return 1;
}

/* Return 1 only when the whole QPACK string (prefix plus payload) is present. */
static int __string_complete(const uint8_t* data, size_t len, unsigned prefix,
                             size_t* wire_len) {
    uint64_t slen = 0;
    const size_t n = prefix_int_decode(data, len, prefix, &slen);
    if (n == 0 || slen > SIZE_MAX - n || n + (size_t)slen > len) return 0;
    *wire_len = n + (size_t)slen;
    return 1;
}

qpack_status_e qpack_decoder_read_encoder(qpack_decoder_t* d, const uint8_t* data,
                                          size_t len, size_t* consumed) {
    if (consumed != NULL) *consumed = 0;
    if (d == NULL || (data == NULL && len != 0)) return QPACK_ERR_ENCODER_STREAM;

    size_t p = 0;
    while (p < len) {
        const uint8_t octet = data[p];

        if ((octet & 0xe0) == 0x20) { /* Set Dynamic Table Capacity: 001xxxxx */
            uint64_t capacity = 0;
            const size_t n = prefix_int_decode(data + p, len - p, 5, &capacity);
            if (n == 0) break;
            if (capacity > d->max_capacity) return QPACK_ERR_ENCODER_STREAM;
            d->capacity = (size_t)capacity;
            while (d->bytes > d->capacity) __dynamic_drop_oldest(d);
            p += n;
            continue;
        }

        /* With an advertised maximum of zero every table-mutating opcode is
         * already illegal from its first byte. Returning the error immediately
         * also preserves lite's useful behaviour for a truncated malicious
         * instruction: there is no future suffix that could make it valid. */
        if (d->max_capacity == 0) return QPACK_ERR_ENCODER_STREAM;

        if ((octet & 0x80) != 0) { /* Insert With Name Reference: 1Txxxxxx */
            uint64_t idx = 0;
            const size_t ni = prefix_int_decode(data + p, len - p, 6, &idx);
            if (ni == 0) break;
            size_t value_wire = 0;
            if (!__string_complete(data + p + ni, len - p - ni, 7, &value_wire)) break;

            const char* name = NULL;
            size_t name_len = 0;
            if ((octet & 0x40) != 0) {
                if (idx >= QPACK_STATIC_TABLE_SIZE) return QPACK_ERR_ENCODER_STREAM;
                name = qpack_static_table[idx].name;
                name_len = strlen(name);
            } else {
                const qpack_dynamic_entry_t* ref = __dynamic_relative(d, idx);
                if (ref == NULL) return QPACK_ERR_ENCODER_STREAM;
                name = ref->name; name_len = ref->name_len;
            }

            const uint8_t* valuep = data + p + ni;
            const uint8_t* value_end = valuep + value_wire;
            char* value = NULL; size_t value_len = 0;
            qpack_status_e st = __decode_value(&valuep, value_end, &value, &value_len);
            if (st != QPACK_OK) return QPACK_ERR_ENCODER_STREAM;
            const int ok = __dynamic_insert(d, name, name_len, value, value_len);
            free(value);
            if (!ok) return QPACK_ERR_ENCODER_STREAM;
            if (!__decoder_pending_int(d, 1, 6, 0x00)) return QPACK_ERR_MEMORY;
            p += ni + value_wire;
            continue;
        }

        if ((octet & 0xc0) == 0x40) { /* Insert With Literal Name: 01Hxxxxx */
            uint64_t name_wire_len = 0;
            const size_t ni = prefix_int_decode(data + p, len - p, 5, &name_wire_len);
            if (ni == 0 || name_wire_len > SIZE_MAX - ni) break;
            if (ni + (size_t)name_wire_len > len - p) break;
            const size_t value_off = p + ni + (size_t)name_wire_len;
            size_t value_wire = 0;
            if (!__string_complete(data + value_off, len - value_off, 7, &value_wire)) break;

            char* name = NULL; size_t name_len = 0;
            qpack_status_e st = __decode_raw(data + p + ni, (size_t)name_wire_len,
                                              (octet & 0x20) != 0, &name, &name_len);
            if (st != QPACK_OK) return QPACK_ERR_ENCODER_STREAM;
            const uint8_t* valuep = data + value_off;
            const uint8_t* value_end = valuep + value_wire;
            char* value = NULL; size_t value_len = 0;
            st = __decode_value(&valuep, value_end, &value, &value_len);
            if (st != QPACK_OK) { free(name); return QPACK_ERR_ENCODER_STREAM; }
            const int ok = __dynamic_insert(d, name, name_len, value, value_len);
            free(name); free(value);
            if (!ok) return QPACK_ERR_ENCODER_STREAM;
            if (!__decoder_pending_int(d, 1, 6, 0x00)) return QPACK_ERR_MEMORY;
            p = value_off + value_wire;
            continue;
        }

        /* Duplicate: 000xxxxx, relative to the current insertion count. */
        uint64_t idx = 0;
        const size_t n = prefix_int_decode(data + p, len - p, 5, &idx);
        if (n == 0) break;
        const qpack_dynamic_entry_t* ref = __dynamic_relative(d, idx);
        if (ref == NULL) return QPACK_ERR_ENCODER_STREAM;
        /* Insertion may realloc/memmove, so copy the referenced bytes first. */
        char* name = malloc(ref->name_len + 1);
        char* value = malloc(ref->value_len + 1);
        if (name == NULL || value == NULL) {
            free(name); free(value); return QPACK_ERR_MEMORY;
        }
        memcpy(name, ref->name, ref->name_len + 1);
        memcpy(value, ref->value, ref->value_len + 1);
        const size_t name_len = ref->name_len, value_len = ref->value_len;
        const int ok = __dynamic_insert(d, name, name_len, value, value_len);
        free(name); free(value);
        if (!ok) return QPACK_ERR_ENCODER_STREAM;
        if (!__decoder_pending_int(d, 1, 6, 0x00)) return QPACK_ERR_MEMORY;
        p += n;
    }

    if (consumed != NULL) *consumed = p;
    return QPACK_OK;
}

qpack_status_e qpack_encoder_read_decoder(const uint8_t* data, size_t len,
                                          size_t* consumed) {
    if (consumed != NULL) *consumed = 0;
    if (data == NULL && len != 0) return QPACK_ERR_DECODER_STREAM;

    size_t p = 0;
    while (p < len) {
        const uint8_t octet = data[p];

        /* Section Acknowledgment is `1sssssss`, Stream Cancellation `01ssssss`.
         * Both name a stream and neither asks anything of an encoder that has
         * inserted nothing, so they are read past. */
        if ((octet & 0x80) != 0 || (octet & 0xc0) == 0x40) {
            uint64_t id = 0;
            const size_t n = prefix_int_decode(data + p, len - p,
                                               (octet & 0x80) != 0 ? 7 : 6, &id);
            if (n == 0) break;   /* split across feeds; the tail comes back */
            p += n;
            continue;
        }

        /* What is left is Insert Count Increment, `00iiiiii`. §4.4.3 makes an
         * increment of zero a connection error outright, and any other value is
         * one too against this encoder: the count may not pass the number of
         * insertions, and a static-only encoder has made none. Both are the
         * peer describing a dynamic table that does not exist. */
        uint64_t increment = 0;
        const size_t n = prefix_int_decode(data + p, len - p, 6, &increment);
        if (n == 0) break;

        return QPACK_ERR_DECODER_STREAM;
    }

    if (consumed != NULL) *consumed = p;
    return QPACK_OK;
}

qpack_status_e qpack_encoder_read_decoder_state(qpack_encoder_t* e,
                                                 const uint8_t* data, size_t len,
                                                 size_t* consumed) {
    if (e == NULL) return QPACK_ERR_DECODER_STREAM;
    if (e->max_capacity == 0)
        return qpack_encoder_read_decoder(data, len, consumed);
    if (consumed != NULL) *consumed = 0;
    if (data == NULL && len != 0) return QPACK_ERR_DECODER_STREAM;

    size_t p = 0;
    while (p < len) {
        const uint8_t octet = data[p];
        if ((octet & 0x80) != 0 || (octet & 0xc0) == 0x40) {
            uint64_t stream_id = 0;
            const size_t n = prefix_int_decode(data + p, len - p,
                                                (octet & 0x80) ? 7 : 6,
                                                &stream_id);
            if (n == 0) break;
            size_t found = e->section_count;
            for (size_t i = 0; i < e->section_count; i++)
                if (e->sections[i].stream_id == stream_id) { found = i; break; }
            if (found == e->section_count) return QPACK_ERR_DECODER_STREAM;
            if ((octet & 0x80) != 0) {
                memmove(e->sections + found, e->sections + found + 1,
                        (e->section_count - found - 1) * sizeof *e->sections);
                e->section_count--;
            } else {
                for (size_t i = 0; i < e->section_count; ) {
                    if (e->sections[i].stream_id != stream_id) { i++; continue; }
                    memmove(e->sections + i, e->sections + i + 1,
                            (e->section_count - i - 1) * sizeof *e->sections);
                    e->section_count--;
                }
            }
            p += n;
            continue;
        }

        uint64_t increment = 0;
        const size_t n = prefix_int_decode(data + p, len - p, 6, &increment);
        if (n == 0) break;
        if (e->known_received_count > e->insert_count || increment == 0 ||
            increment > e->insert_count - e->known_received_count)
            return QPACK_ERR_DECODER_STREAM;
        e->known_received_count += increment;
        p += n;
    }
    if (consumed != NULL) *consumed = p;
    return QPACK_OK;
}

/* ======================================================================= *
 *  Encoder (lite)
 * ======================================================================= *
 *  A small growable buffer, the static-table lookup, and one helper per string
 *  shape QPACK literals use. The value literal is `H | length (7-bit) | bytes`,
 *  identical to HPACK; the literal-literal-name's name is `001 N H | length
 *  (3-bit) | bytes`, with the Huffman flag carried in the opcode rather than a
 *  length-prefix bit. */

typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
    int      oom;
} qpack_buf_t;

static void qpack_buf_init(qpack_buf_t* b) { b->data = NULL; b->len = 0; b->cap = 0; b->oom = 0; }

static int qpack_buf_reserve(qpack_buf_t* b, size_t need) {
    if (b->oom) return 0;
    if (need <= b->cap - b->len && b->len <= b->cap) return 1;
    size_t ncap = b->cap ? b->cap : 128;
    while (ncap - b->len < need) {
        if (ncap > ((size_t)-1) / 2) { b->oom = 1; return 0; }
        ncap *= 2;
    }
    uint8_t* nd = realloc(b->data, ncap);
    if (nd == NULL) { b->oom = 1; return 0; }
    b->data = nd; b->cap = ncap;
    return 1;
}

static int qpack_buf_int(qpack_buf_t* b, uint64_t value, uint8_t prefix_bits, uint8_t flags) {
    if (!qpack_buf_reserve(b, 10)) return 0;
    const size_t n = prefix_int_encode(b->data + b->len, b->cap - b->len, value, prefix_bits, flags);
    if (n == 0) { b->oom = 1; return 0; }
    b->len += n;
    return 1;
}

static int qpack_buf_write(qpack_buf_t* b, const uint8_t* d, size_t n) {
    if (n == 0) return 1;
    if (!qpack_buf_reserve(b, n)) return 0;
    memcpy(b->data + b->len, d, n);
    b->len += n;
    return 1;
}

/* A value string literal: `H | length (7-bit) | bytes`, Huffman only if shorter. */
static int qpack_enc_value(qpack_buf_t* b, const uint8_t* data, size_t len) {
    const size_t hlen = huffman_encoded_len(data, len);
    if (hlen < len) {
        if (!qpack_buf_int(b, hlen, 7, 0x80)) return 0;           /* H=1 */
        if (!qpack_buf_reserve(b, hlen)) return 0;
        const ssize_t n = huffman_encode(b->data + b->len, b->cap - b->len, data, len);
        if (n < 0) { b->oom = 1; return 0; }
        b->len += n;
        return 1;
    }
    if (!qpack_buf_int(b, len, 7, 0x00)) return 0;                /* H=0 */
    return qpack_buf_write(b, data, len);
}

/* Find a static-table entry. match_value=0 → first entry whose name matches;
 * match_value=1 → first whose name AND value match. 0-based index out. */
static int qpack_static_find(const char* name, size_t name_len,
                             const char* value, size_t value_len,
                             int match_value, size_t* idx) {
    for (size_t i = 0; i < QPACK_STATIC_TABLE_SIZE; i++) {
        const qpack_static_entry_t* e = &qpack_static_table[i];
        const size_t en = strlen(e->name);
        if (en != name_len || memcmp(e->name, name, name_len) != 0) continue;
        if (!match_value) { *idx = i; return 1; }
        const size_t ev = strlen(e->value);
        if (ev == value_len && memcmp(e->value, value, value_len) == 0) { *idx = i; return 1; }
    }
    return 0;
}

qpack_encoder_t* qpack_encoder_create(size_t max_capacity, size_t max_blocked) {
    qpack_encoder_t* e = calloc(1, sizeof * e);
    if (e == NULL) return NULL;
    e->max_capacity = max_capacity;
    e->max_blocked = max_blocked;
    e->insert_count = 0;
    e->known_received_count = 0;
    return e;
}

void qpack_encoder_free(qpack_encoder_t* e) {
    if (e == NULL) return;
    for (size_t i = 0; i < e->entry_count; i++) {
        free(e->entries[i].name);
        free(e->entries[i].value);
    }
    free(e->entries);
    free(e->sections);
    free(e->pending);
    free(e);
}

qpack_status_e qpack_encoder_section_open(qpack_encoder_t* e, uint64_t stream_id,
                                           uint64_t required_insert_count) {
    if (e == NULL || required_insert_count == 0 ||
        required_insert_count > e->insert_count) return QPACK_ERR_ENCODER_STREAM;
    if (e->section_count == e->section_cap) {
        const size_t cap = e->section_cap ? e->section_cap * 2 : 8;
        qpack_outstanding_section_t* grown = realloc(e->sections, cap * sizeof *grown);
        if (grown == NULL) return QPACK_ERR_MEMORY;
        e->sections = grown; e->section_cap = cap;
    }
    e->sections[e->section_count++] = (qpack_outstanding_section_t){stream_id,
                                                                    required_insert_count};
    return QPACK_OK;
}

static int __encoder_pending_bytes(qpack_encoder_t* e, const void* data, size_t n) {
    if (n == 0) return 1;
    if (e->pending_len > SIZE_MAX - n) return 0;
    const size_t need = e->pending_len + n;
    if (need > e->pending_cap) {
        size_t cap = e->pending_cap ? e->pending_cap : 32;
        while (cap < need) { if (cap > SIZE_MAX / 2) return 0; cap *= 2; }
        uint8_t* grown = realloc(e->pending, cap);
        if (grown == NULL) return 0;
        e->pending = grown; e->pending_cap = cap;
    }
    memcpy(e->pending + e->pending_len, data, n);
    e->pending_len += n;
    return 1;
}

static int __encoder_entry_protected(const qpack_encoder_t* e, uint64_t absolute) {
    for (size_t i = 0; i < e->section_count; i++)
        if (e->sections[i].required_insert_count > absolute) return 1;
    return 0;
}

static int __encoder_make_room(qpack_encoder_t* e, size_t size) {
    if (size > e->capacity) return 0;
    while (e->bytes > e->capacity - size) {
        if (e->entry_count == 0 || __encoder_entry_protected(e, e->entries[0].absolute))
            return 0;
        qpack_dynamic_entry_t* oldest = &e->entries[0];
        e->bytes -= oldest->size;
        free(oldest->name); free(oldest->value);
        e->entry_count--;
        if (e->entry_count != 0)
            memmove(e->entries, e->entries + 1, e->entry_count * sizeof *e->entries);
    }
    return 1;
}

qpack_status_e qpack_encoder_insert_literal(qpack_encoder_t* e,
                                             const char* name, size_t name_len,
                                             const char* value, size_t value_len,
                                             uint64_t* absolute) {
    if (e == NULL || name == NULL || value == NULL ||
        name_len > SIZE_MAX - value_len - 32) return QPACK_ERR_ENCODER_STREAM;
    const size_t size = name_len + value_len + 32;
    /* Until outstanding-section refcounts land, never evict speculatively. */
    if (!__encoder_make_room(e, size))
        return QPACK_ERR_ENCODER_STREAM;

    uint8_t prefix[16], vprefix[16];
    const size_t pn = prefix_int_encode(prefix, sizeof prefix, name_len, 5, 0x40);
    const size_t vn = prefix_int_encode(vprefix, sizeof vprefix, value_len, 7, 0);
    const size_t old_pending = e->pending_len;
    if (pn == 0 || vn == 0 || !__encoder_pending_bytes(e, prefix, pn) ||
        !__encoder_pending_bytes(e, name, name_len) ||
        !__encoder_pending_bytes(e, vprefix, vn) ||
        !__encoder_pending_bytes(e, value, value_len)) {
        e->pending_len = old_pending;
        return QPACK_ERR_MEMORY;
    }

    if (e->entry_count == e->entry_cap) {
        const size_t cap = e->entry_cap ? e->entry_cap * 2 : 8;
        qpack_dynamic_entry_t* grown = realloc(e->entries, cap * sizeof *grown);
        if (grown == NULL) { e->pending_len = old_pending; return QPACK_ERR_MEMORY; }
        e->entries = grown; e->entry_cap = cap;
    }
    char* nc = malloc(name_len + 1); char* vc = malloc(value_len + 1);
    if (nc == NULL || vc == NULL) {
        free(nc); free(vc); e->pending_len = old_pending; return QPACK_ERR_MEMORY;
    }
    memcpy(nc, name, name_len); nc[name_len] = 0;
    memcpy(vc, value, value_len); vc[value_len] = 0;
    qpack_dynamic_entry_t* de = &e->entries[e->entry_count++];
    de->name = nc; de->name_len = name_len; de->value = vc; de->value_len = value_len;
    de->size = size; de->absolute = e->insert_count++;
    e->bytes += size;
    if (absolute != NULL) *absolute = de->absolute;
    return QPACK_OK;
}

qpack_status_e qpack_encoder_insert_static_name(qpack_encoder_t* e,
                                                 uint64_t static_index,
                                                 const char* value, size_t value_len,
                                                 uint64_t* absolute) {
    if (e == NULL || value == NULL || static_index >= QPACK_STATIC_TABLE_SIZE)
        return QPACK_ERR_ENCODER_STREAM;
    const char* name = qpack_static_table[static_index].name;
    const size_t name_len = strlen(name);
    if (name_len > SIZE_MAX - value_len - 32) return QPACK_ERR_ENCODER_STREAM;
    const size_t size = name_len + value_len + 32;
    if (!__encoder_make_room(e, size))
        return QPACK_ERR_ENCODER_STREAM;

    uint8_t prefix[16], vprefix[16];
    const size_t pn = prefix_int_encode(prefix, sizeof prefix, static_index, 6, 0xc0);
    const size_t vn = prefix_int_encode(vprefix, sizeof vprefix, value_len, 7, 0);
    const size_t old_pending = e->pending_len;
    if (pn == 0 || vn == 0 || !__encoder_pending_bytes(e, prefix, pn) ||
        !__encoder_pending_bytes(e, vprefix, vn) ||
        !__encoder_pending_bytes(e, value, value_len)) {
        e->pending_len = old_pending;
        return QPACK_ERR_MEMORY;
    }

    if (e->entry_count == e->entry_cap) {
        const size_t cap = e->entry_cap ? e->entry_cap * 2 : 8;
        qpack_dynamic_entry_t* grown = realloc(e->entries, cap * sizeof *grown);
        if (grown == NULL) { e->pending_len = old_pending; return QPACK_ERR_MEMORY; }
        e->entries = grown; e->entry_cap = cap;
    }
    char* nc = malloc(name_len + 1); char* vc = malloc(value_len + 1);
    if (nc == NULL || vc == NULL) {
        free(nc); free(vc); e->pending_len = old_pending; return QPACK_ERR_MEMORY;
    }
    memcpy(nc, name, name_len + 1);
    memcpy(vc, value, value_len); vc[value_len] = 0;
    qpack_dynamic_entry_t* de = &e->entries[e->entry_count++];
    de->name = nc; de->name_len = name_len; de->value = vc; de->value_len = value_len;
    de->size = size; de->absolute = e->insert_count++;
    e->bytes += size;
    if (absolute != NULL) *absolute = de->absolute;
    return QPACK_OK;
}

qpack_status_e qpack_encoder_insert_dynamic_name(qpack_encoder_t* e,
                                                  uint64_t relative_index,
                                                  const char* value, size_t value_len,
                                                  uint64_t* absolute) {
    if (e == NULL || value == NULL || relative_index >= e->entry_count)
        return QPACK_ERR_ENCODER_STREAM;
    const qpack_dynamic_entry_t* ref =
        &e->entries[e->entry_count - 1 - (size_t)relative_index];
    const size_t name_len = ref->name_len;
    if (name_len > SIZE_MAX - value_len - 32) return QPACK_ERR_ENCODER_STREAM;
    const size_t size = name_len + value_len + 32;
    if (size > e->capacity || e->bytes > e->capacity - size)
        return QPACK_ERR_ENCODER_STREAM;

    /* Copy before growing the entry array: realloc may invalidate ref. */
    char* nc = malloc(name_len + 1); char* vc = malloc(value_len + 1);
    if (nc == NULL || vc == NULL) { free(nc); free(vc); return QPACK_ERR_MEMORY; }
    memcpy(nc, ref->name, name_len); nc[name_len] = 0;
    memcpy(vc, value, value_len); vc[value_len] = 0;

    uint8_t prefix[16], vprefix[16];
    const size_t pn = prefix_int_encode(prefix, sizeof prefix, relative_index, 6, 0x80);
    const size_t vn = prefix_int_encode(vprefix, sizeof vprefix, value_len, 7, 0);
    const size_t old_pending = e->pending_len;
    if (pn == 0 || vn == 0 || !__encoder_pending_bytes(e, prefix, pn) ||
        !__encoder_pending_bytes(e, vprefix, vn) ||
        !__encoder_pending_bytes(e, value, value_len)) {
        e->pending_len = old_pending; free(nc); free(vc); return QPACK_ERR_MEMORY;
    }
    if (e->entry_count == e->entry_cap) {
        const size_t cap = e->entry_cap ? e->entry_cap * 2 : 8;
        qpack_dynamic_entry_t* grown = realloc(e->entries, cap * sizeof *grown);
        if (grown == NULL) {
            e->pending_len = old_pending; free(nc); free(vc); return QPACK_ERR_MEMORY;
        }
        e->entries = grown; e->entry_cap = cap;
    }
    qpack_dynamic_entry_t* de = &e->entries[e->entry_count++];
    de->name = nc; de->name_len = name_len; de->value = vc; de->value_len = value_len;
    de->size = size; de->absolute = e->insert_count++;
    e->bytes += size;
    if (absolute != NULL) *absolute = de->absolute;
    return QPACK_OK;
}

qpack_status_e qpack_encoder_duplicate(qpack_encoder_t* e, uint64_t relative_index,
                                        uint64_t* absolute) {
    if (e == NULL || relative_index >= e->entry_count) return QPACK_ERR_ENCODER_STREAM;
    const qpack_dynamic_entry_t* ref =
        &e->entries[e->entry_count - 1 - (size_t)relative_index];
    if (ref->size > e->capacity || e->bytes > e->capacity - ref->size)
        return QPACK_ERR_ENCODER_STREAM;

    char* nc = malloc(ref->name_len + 1); char* vc = malloc(ref->value_len + 1);
    if (nc == NULL || vc == NULL) { free(nc); free(vc); return QPACK_ERR_MEMORY; }
    memcpy(nc, ref->name, ref->name_len + 1);
    memcpy(vc, ref->value, ref->value_len + 1);
    const size_t name_len = ref->name_len, value_len = ref->value_len, size = ref->size;

    uint8_t prefix[16];
    const size_t pn = prefix_int_encode(prefix, sizeof prefix, relative_index, 5, 0x00);
    const size_t old_pending = e->pending_len;
    if (pn == 0 || !__encoder_pending_bytes(e, prefix, pn)) {
        e->pending_len = old_pending; free(nc); free(vc); return QPACK_ERR_MEMORY;
    }
    if (e->entry_count == e->entry_cap) {
        const size_t cap = e->entry_cap ? e->entry_cap * 2 : 8;
        qpack_dynamic_entry_t* grown = realloc(e->entries, cap * sizeof *grown);
        if (grown == NULL) {
            e->pending_len = old_pending; free(nc); free(vc); return QPACK_ERR_MEMORY;
        }
        e->entries = grown; e->entry_cap = cap;
    }
    qpack_dynamic_entry_t* de = &e->entries[e->entry_count++];
    de->name = nc; de->name_len = name_len; de->value = vc; de->value_len = value_len;
    de->size = size; de->absolute = e->insert_count++;
    e->bytes += size;
    if (absolute != NULL) *absolute = de->absolute;
    return QPACK_OK;
}

static int __encoder_pending_int(qpack_encoder_t* e, uint64_t value,
                                 uint8_t prefix, uint8_t flags) {
    uint8_t buf[16];
    const size_t n = prefix_int_encode(buf, sizeof buf, value, prefix, flags);
    if (n == 0 || e->pending_len > SIZE_MAX - n) return 0;
    const size_t need = e->pending_len + n;
    if (need > e->pending_cap) {
        size_t cap = e->pending_cap ? e->pending_cap : 32;
        while (cap < need) {
            if (cap > SIZE_MAX / 2) return 0;
            cap *= 2;
        }
        uint8_t* grown = realloc(e->pending, cap);
        if (grown == NULL) return 0;
        e->pending = grown; e->pending_cap = cap;
    }
    memcpy(e->pending + e->pending_len, buf, n);
    e->pending_len += n;
    return 1;
}

qpack_status_e qpack_encoder_set_capacity(qpack_encoder_t* e, size_t capacity) {
    if (e == NULL || capacity > e->max_capacity) return QPACK_ERR_ENCODER_STREAM;
    if (!__encoder_pending_int(e, capacity, 5, 0x20)) return QPACK_ERR_MEMORY;
    e->capacity = capacity;
    return QPACK_OK;
}

size_t qpack_encoder_pending(const qpack_encoder_t* e, const uint8_t** out) {
    if (out != NULL) *out = e != NULL ? e->pending : NULL;
    return e != NULL ? e->pending_len : 0;
}

void qpack_encoder_consume(qpack_encoder_t* e, size_t n) {
    if (e == NULL || n == 0) return;
    if (n >= e->pending_len) { e->pending_len = 0; return; }
    memmove(e->pending, e->pending + n, e->pending_len - n);
    e->pending_len -= n;
}

size_t qpack_encode_block(qpack_encoder_t* e, const qpack_header_t* fields, size_t count,
                          uint8_t* dst, size_t cap) {
    if (e == NULL || (fields == NULL && count != 0) || dst == NULL || cap == 0) return 0;

    qpack_buf_t b;
    qpack_buf_init(&b);

    uint64_t required = 0;
    if (e->max_blocked > 0) {
        for (size_t i = 0; i < count; i++) {
            if (fields[i].never_indexed) continue;
            for (size_t j = e->entry_count; j > 0; j--) {
                const qpack_dynamic_entry_t* de = &e->entries[j - 1];
                if (de->name_len == fields[i].name_len &&
                    de->value_len == fields[i].value_len &&
                    memcmp(de->name, fields[i].name, de->name_len) == 0 &&
                    memcmp(de->value, fields[i].value, de->value_len) == 0) {
                    if (required < de->absolute + 1) required = de->absolute + 1;
                    break;
                }
            }
        }
    }
    uint64_t encoded_ric = 0;
    if (required != 0) {
        const uint64_t max_entries = e->max_capacity / 32;
        if (max_entries == 0) { free(b.data); return 0; }
        encoded_ric = (required % (2 * max_entries)) + 1;
    }
    const uint64_t base = required == 0 ? 0 : e->insert_count;
    const uint64_t delta = base - required;
    if (!qpack_buf_int(&b, encoded_ric, 8, 0x00) ||
        !qpack_buf_int(&b, delta, 7, 0x00)) {
        free(b.data);
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        const qpack_header_t* h = &fields[i];
        const uint8_t* name = (const uint8_t*)h->name;
        const uint8_t* value = (const uint8_t*)h->value;
        const int never = h->never_indexed;

        if (!never && required != 0) {
            const qpack_dynamic_entry_t* match = NULL;
            for (size_t j = e->entry_count; j > 0; j--) {
                const qpack_dynamic_entry_t* de = &e->entries[j - 1];
                if (de->name_len == h->name_len && de->value_len == h->value_len &&
                    memcmp(de->name, h->name, de->name_len) == 0 &&
                    memcmp(de->value, h->value, de->value_len) == 0) {
                    match = de; break;
                }
            }
            if (match != NULL) {
                const uint64_t relative = base - match->absolute - 1;
                if (!qpack_buf_int(&b, relative, 6, 0x80)) break;
                continue;
            }
        }

        /* Exact static match → indexed static, unless the field is never-indexed
         * (then a literal with N=1 is the conservative, intermediary-safe form). */
        size_t idx = 0;
        if (!never && qpack_static_find((const char*)name, h->name_len,
                                        (const char*)value, h->value_len, 1, &idx)) {
            if (!qpack_buf_int(&b, idx, 6, 0xc0)) break;          /* 1 T=1 (static) */
            continue;
        }

        size_t nidx = 0;
        if (qpack_static_find((const char*)name, h->name_len, NULL, 0, 0, &nidx)) {
            /* Literal With Name Reference, static name (01 N T=1 iiii). */
            const uint8_t flags = 0x40 | (never ? 0x20 : 0) | 0x10;
            if (!qpack_buf_int(&b, nidx, 4, flags)) break;
        } else {
            /* Literal With Literal Name (001 N H iii). Huffman the name iff shorter;
             * the length on the wire is then the Huffman length, not the raw one. */
            const size_t nhlen = huffman_encoded_len(name, h->name_len);
            const int H = (nhlen < h->name_len);
            const uint8_t flags = 0x20 | (never ? 0x10 : 0) | (H ? 0x08 : 0);
            if (!qpack_buf_int(&b, H ? nhlen : h->name_len, 3, flags)) break;
            if (H) {
                if (!qpack_buf_reserve(&b, nhlen)) break;
                const ssize_t n = huffman_encode(b.data + b.len, b.cap - b.len, name, h->name_len);
                if (n < 0) { b.oom = 1; break; }
                b.len += n;
            } else {
                if (!qpack_buf_write(&b, name, h->name_len)) break;
            }
        }

        if (!qpack_enc_value(&b, value, h->value_len)) break;
    }

    if (b.oom || b.len > cap) {
        free(b.data);
        return 0;
    }

    memcpy(dst, b.data, b.len);
    free(b.data);
    return b.len;
}

/* ---- String literals ---- */

/* Decode [data, data+len) into a malloc'd, null-terminated string, Huffman-
 * decoding it when `huffman` is set. Output expands by at most ~8/5, so a
 * 2*len+8 cap is always enough (and is why a cap overflow here is impossible). */
static qpack_status_e __decode_raw(const uint8_t* data, size_t len, int huffman,
                                   char** out, size_t* out_len) {
    if (huffman) {
        size_t cap = len * 2 + 8;
        char* dst = malloc(cap);
        if (dst == NULL) return QPACK_ERR_MEMORY;
        const ssize_t dn = huffman_decode((uint8_t*)dst, cap - 1, data, len);
        if (dn < 0) { free(dst); return QPACK_ERR_DECOMPRESSION; }
        dst[dn] = '\0';
        *out = dst; *out_len = (size_t)dn;
    } else {
        char* dst = malloc(len + 1);
        if (dst == NULL) return QPACK_ERR_MEMORY;
        memcpy(dst, data, len);
        dst[len] = '\0';
        *out = dst; *out_len = len;
    }
    return QPACK_OK;
}

/* A value string carries its own Huffman flag: `H | length (7-bit prefix) | bytes`. */
static qpack_status_e __decode_value(const uint8_t** pp, const uint8_t* end,
                                     char** out, size_t* out_len) {
    if (*pp >= end) return QPACK_ERR_DECOMPRESSION;
    const int huffman = (**pp & 0x80) != 0;

    uint64_t length = 0;
    const size_t n = prefix_int_decode(*pp, (size_t)(end - *pp), 7, &length);
    if (n == 0) return QPACK_ERR_DECOMPRESSION;
    *pp += n;

    if ((size_t)(end - *pp) < length) return QPACK_ERR_DECOMPRESSION;
    const uint8_t* data = *pp;
    *pp += length;

    return __decode_raw(data, (size_t)length, huffman, out, out_len);
}

/* Copy a static-table entry's name or value into a fresh malloc'd string. */
static int __dup_static(const char* src, char** out, size_t* out_len) {
    size_t len = strlen(src);
    char* dst = malloc(len + 1);
    if (dst == NULL) return 0;
    memcpy(dst, src, len + 1);
    *out = dst; *out_len = len;
    return 1;
}

static int __dup_bytes(const char* src, size_t len, char** out, size_t* out_len) {
    char* dst = malloc(len + 1);
    if (dst == NULL) return 0;
    memcpy(dst, src, len);
    dst[len] = '\0';
    *out = dst; *out_len = len;
    return 1;
}

/* ---- The block decoder ---- */

qpack_status_e qpack_required_insert_count(const qpack_decoder_t* d,
                                            const uint8_t* block, size_t len,
                                            uint64_t* required) {
    if (required == NULL) return QPACK_ERR_DECOMPRESSION;
    *required = 0;
    if (d == NULL || block == NULL || len == 0) return QPACK_ERR_DECOMPRESSION;

    uint64_t encoded = 0;
    if (prefix_int_decode(block, len, 8, &encoded) == 0)
        return QPACK_ERR_DECOMPRESSION;
    if (encoded == 0) return QPACK_OK;

    const uint64_t max_entries = d->max_capacity / 32;
    if (max_entries == 0) return QPACK_ERR_DECOMPRESSION;
    const uint64_t full_range = 2 * max_entries;
    if (encoded > full_range) return QPACK_ERR_DECOMPRESSION;
    if (d->insert_count > UINT64_MAX - max_entries) return QPACK_ERR_DECOMPRESSION;

    const uint64_t max_value = d->insert_count + max_entries;
    const uint64_t max_wrapped = (max_value / full_range) * full_range;
    uint64_t ric = max_wrapped + encoded - 1;
    if (ric > max_value) {
        if (ric <= full_range) return QPACK_ERR_DECOMPRESSION;
        ric -= full_range;
    }
    if (ric == 0) return QPACK_ERR_DECOMPRESSION;
    *required = ric;
    return ric > d->insert_count ? QPACK_BLOCKED : QPACK_OK;
}

qpack_status_e qpack_decode_block(qpack_decoder_t* d, const uint8_t* block, size_t len,
                                  size_t max_list_size,
                                  qpack_header_t** out, size_t* out_count) {
    if (out == NULL || out_count == NULL) return QPACK_ERR_DECOMPRESSION;
    *out = NULL; *out_count = 0;
    if (d == NULL || (block == NULL && len != 0)) return QPACK_ERR_DECOMPRESSION;

    const uint8_t* p = block;
    const uint8_t* end = block + len;

    /* Decode Required Insert Count from its modulo representation (§4.5.1.1). */
    uint64_t encoded_ric = 0;
    size_t n = prefix_int_decode(p, (size_t)(end - p), 8, &encoded_ric);
    if (n == 0) return QPACK_ERR_DECOMPRESSION;
    p += n;

    uint64_t ric = 0;
    const qpack_status_e rst = qpack_required_insert_count(d, block, len, &ric);
    if (rst != QPACK_OK) return rst;

    /* §4.5.1.2: Base is an insertion count, while entry absolute indices are
     * zero-based. Bounds are checked here before resolving representations. */
    if (p >= end) return QPACK_ERR_DECOMPRESSION;
    const int base_sign = (*p & 0x80) != 0;

    uint64_t delta_base = 0;
    n = prefix_int_decode(p, (size_t)(end - p), 7, &delta_base);
    if (n == 0) return QPACK_ERR_DECOMPRESSION;
    p += n;
    uint64_t base = 0;
    if (!base_sign) {
        if (ric > UINT64_MAX - delta_base) return QPACK_ERR_DECOMPRESSION;
        base = ric + delta_base;
    } else {
        if (delta_base >= ric) return QPACK_ERR_DECOMPRESSION;
        base = ric - delta_base - 1;
    }

    qpack_header_t* headers = NULL;
    size_t count = 0, cap = 0;
    size_t total = 0;
    qpack_status_e st = QPACK_OK;
    /* Set once headers[count] has been zeroed and is therefore safe to free on
     * the failure path. It is not, in particular, after a failed grow: count
     * still equals cap there, and headers[count] is one past the end. */
    int partial = 0;

    while (p < end) {
        if (count == cap) {
            const size_t ncap = cap ? cap * 2 : 8;
            qpack_header_t* grown = realloc(headers, ncap * sizeof * grown);
            if (grown == NULL) { st = QPACK_ERR_MEMORY; goto fail; }
            headers = grown; cap = ncap;
        }

        qpack_header_t* h = &headers[count];
        h->name = NULL; h->value = NULL;
        h->name_len = 0; h->value_len = 0; h->never_indexed = 0;
        partial = 1;

        const uint8_t octet = *p;

        if (octet & 0x80) {
            /* Indexed Field Line (1Tiiiiii). T=1 static, T=0 dynamic. */
            uint64_t idx = 0;
            n = prefix_int_decode(p, (size_t)(end - p), 6, &idx);
            if (n == 0) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
            p += n;
            const int T = (octet & 0x40) != 0;
            if (T) {
                if (idx >= QPACK_STATIC_TABLE_SIZE) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
                const qpack_static_entry_t* e = &qpack_static_table[idx];
                if (!__dup_static(e->name, &h->name, &h->name_len) ||
                    !__dup_static(e->value, &h->value, &h->value_len)) {
                    st = QPACK_ERR_MEMORY; goto fail;
                }
            } else {
                if (idx >= base) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
                const qpack_dynamic_entry_t* e = __dynamic_absolute(d, base - idx - 1);
                if (e == NULL || !__dup_bytes(e->name, e->name_len, &h->name, &h->name_len) ||
                    !__dup_bytes(e->value, e->value_len, &h->value, &h->value_len)) {
                    st = e == NULL ? QPACK_ERR_DECOMPRESSION : QPACK_ERR_MEMORY; goto fail;
                }
            }
        }
        else if ((octet & 0xe0) == 0x20) {
            /* Literal With Literal Name (001Nhiii). H is the name's Huffman flag;
             * the name length is a 3-bit prefix on this octet. */
            const int N = (octet & 0x10) != 0;
            const int H = (octet & 0x08) != 0;
            uint64_t namelen = 0;
            n = prefix_int_decode(p, (size_t)(end - p), 3, &namelen);
            if (n == 0) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
            p += n;
            if ((size_t)(end - p) < namelen) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
            const uint8_t* namedata = p;
            p += namelen;

            st = __decode_raw(namedata, (size_t)namelen, H, &h->name, &h->name_len);
            if (st != QPACK_OK) goto fail;
            st = __decode_value(&p, end, &h->value, &h->value_len);
            if (st != QPACK_OK) goto fail;
            h->never_indexed = N;
        }
        else if ((octet & 0xc0) == 0x40) {
            /* Literal With Name Reference (01NTiiii). T=1 static name, T=0 dynamic. */
            const int N = (octet & 0x20) != 0;
            const int T = (octet & 0x10) != 0;
            uint64_t nidx = 0;
            n = prefix_int_decode(p, (size_t)(end - p), 4, &nidx);
            if (n == 0) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
            p += n;
            if (T) {
                if (nidx >= QPACK_STATIC_TABLE_SIZE) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
                const qpack_static_entry_t* e = &qpack_static_table[nidx];
                if (!__dup_static(e->name, &h->name, &h->name_len)) {
                    st = QPACK_ERR_MEMORY; goto fail;
                }
            } else {
                if (nidx >= base) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
                const qpack_dynamic_entry_t* e = __dynamic_absolute(d, base - nidx - 1);
                if (e == NULL) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
                if (!__dup_bytes(e->name, e->name_len, &h->name, &h->name_len)) {
                    st = QPACK_ERR_MEMORY; goto fail;
                }
            }
            st = __decode_value(&p, end, &h->value, &h->value_len);
            if (st != QPACK_OK) goto fail;
            h->never_indexed = N;
        }
        else if ((octet & 0xf0) == 0x10) {
            /* Indexed Field Line With Post-Base Index (0001iiii). */
            uint64_t idx = 0;
            n = prefix_int_decode(p, (size_t)(end - p), 4, &idx);
            if (n == 0 || base > UINT64_MAX - idx) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
            p += n;
            const qpack_dynamic_entry_t* e = __dynamic_absolute(d, base + idx);
            if (e == NULL || !__dup_bytes(e->name, e->name_len, &h->name, &h->name_len) ||
                !__dup_bytes(e->value, e->value_len, &h->value, &h->value_len)) {
                st = e == NULL ? QPACK_ERR_DECOMPRESSION : QPACK_ERR_MEMORY; goto fail;
            }
        }
        else {
            /* Literal With Post-Base Name Reference (0000Niii). */
            const int N = (octet & 0x08) != 0;
            uint64_t idx = 0;
            n = prefix_int_decode(p, (size_t)(end - p), 3, &idx);
            if (n == 0 || base > UINT64_MAX - idx) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
            p += n;
            const qpack_dynamic_entry_t* e = __dynamic_absolute(d, base + idx);
            if (e == NULL || !__dup_bytes(e->name, e->name_len, &h->name, &h->name_len)) {
                st = e == NULL ? QPACK_ERR_DECOMPRESSION : QPACK_ERR_MEMORY; goto fail;
            }
            st = __decode_value(&p, end, &h->value, &h->value_len);
            if (st != QPACK_OK) goto fail;
            h->never_indexed = N;
        }

        total += h->name_len + h->value_len + 32;
        if (max_list_size != 0 && total > max_list_size) {
            /* The current field is filled; free it alongside the rest. */
            qpack_headers_free(headers, count + 1);
            return QPACK_ERR_TOO_LARGE;
        }
        count++;
        partial = 0;
    }

    *out = headers;
    *out_count = count;
    return QPACK_OK;

fail:
    /* count was not incremented for the partial entry; release its allocations
     * (NULL-safe) before freeing the completed ones. `partial` guards the case
     * where the failure was the grow itself, so slot `count` does not exist. */
    if (headers != NULL && partial) {
        free(headers[count].name);
        free(headers[count].value);
    }
    qpack_headers_free(headers, count);
    return st;
}

#include "qpack.h"

#include <stdlib.h>
#include <string.h>

#include "huffman.h"            /* shared Huffman + prefix-int (RFC 9204 §5) */
#include "qpack_statictable.h"  /* generated: 99-entry static table */

/* ---- Lifecycle ---- */

qpack_decoder_t* qpack_decoder_create(size_t max_capacity, size_t max_blocked) {
    qpack_decoder_t* d = malloc(sizeof * d);
    if (d == NULL) return NULL;
    d->max_capacity = max_capacity;
    d->max_blocked = max_blocked;
    return d;
}

void qpack_decoder_free(qpack_decoder_t* d) {
    free(d);
}

void qpack_headers_free(qpack_header_t* headers, size_t count) {
    if (headers == NULL) return;
    for (size_t i = 0; i < count; i++) {
        free(headers[i].name);
        free(headers[i].value);
    }
    free(headers);
}

/* ---- The peer's encoder stream (lite) ---- */

qpack_status_e qpack_decoder_read_encoder(qpack_decoder_t* d, const uint8_t* data,
                                          size_t len, size_t* consumed) {
    if (consumed != NULL) *consumed = 0;
    if (d == NULL || (data == NULL && len != 0)) return QPACK_ERR_ENCODER_STREAM;

    size_t p = 0;
    while (p < len) {
        const uint8_t octet = data[p];

        /* Set Dynamic Table Capacity is `001iiiii`; every other opcode --
         * `1Tiiiiii` insert-with-name-ref, `01Hiiiii` insert-with-literal-name,
         * `000iiiii` duplicate -- writes to a table we said we do not have. */
        if ((octet & 0xe0) != 0x20) return QPACK_ERR_ENCODER_STREAM;

        /* A 5-bit prefix of all ones means the value is 31 or more and a
         * continuation follows. When 31 already exceeds what we advertised the
         * verdict is settled without reading it -- which is what keeps lite
         * (capacity 0) free of any partial instruction to carry over. */
        if ((octet & 0x1f) == 0x1f && d->max_capacity < 31)
            return QPACK_ERR_ENCODER_STREAM;

        uint64_t capacity = 0;
        const size_t n = prefix_int_decode(data + p, len - p, 5, &capacity);
        /* Not an error: the instruction may simply be split across feeds. The
         * caller keeps the tail and re-feeds it with the next chunk. */
        if (n == 0) break;

        if (capacity > d->max_capacity) return QPACK_ERR_ENCODER_STREAM;

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
    qpack_encoder_t* e = malloc(sizeof * e);
    if (e == NULL) return NULL;
    e->max_capacity = max_capacity;
    e->max_blocked = max_blocked;
    return e;
}

void qpack_encoder_free(qpack_encoder_t* e) {
    free(e);
}

size_t qpack_encode_block(qpack_encoder_t* e, const qpack_header_t* fields, size_t count,
                          uint8_t* dst, size_t cap) {
    if (e == NULL || (fields == NULL && count != 0) || dst == NULL || cap == 0) return 0;

    qpack_buf_t b;
    qpack_buf_init(&b);

    /* Prefix: Required Insert Count 0 (8-bit), then S=0 | Delta Base 0 (7-bit).
     * Fixed at two zero bytes for the whole of lite. */
    if (!qpack_buf_int(&b, 0, 8, 0x00) || !qpack_buf_int(&b, 0, 7, 0x00)) {
        free(b.data);
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        const qpack_header_t* h = &fields[i];
        const uint8_t* name = (const uint8_t*)h->name;
        const uint8_t* value = (const uint8_t*)h->value;
        const int never = h->never_indexed;

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

/* ---- The block decoder ---- */

qpack_status_e qpack_decode_block(qpack_decoder_t* d, const uint8_t* block, size_t len,
                                  size_t max_list_size,
                                  qpack_header_t** out, size_t* out_count) {
    if (out == NULL || out_count == NULL) return QPACK_ERR_DECOMPRESSION;
    *out = NULL; *out_count = 0;
    if (d == NULL || (block == NULL && len != 0)) return QPACK_ERR_DECOMPRESSION;

    const uint8_t* p = block;
    const uint8_t* end = block + len;

    /* Prefix (RFC 9204 §4.5.1). Required Insert Count is an 8-bit prefix int
     * (encoded mod MaxEntries in the full codec); in lite MaxEntries is 0, so
     * the only legal value is 0. Delta Base's sign bit is the high bit of its
     * 7-bit prefix int, which prefix_int_decode reads as flags; the value is
     * unused in lite because there are no dynamic references to resolve. */
    uint64_t ric = 0;
    size_t n = prefix_int_decode(p, (size_t)(end - p), 8, &ric);
    if (n == 0) return QPACK_ERR_DECOMPRESSION;
    p += n;
    if (ric != 0) return QPACK_ERR_DECOMPRESSION;

    /* §4.5.1.2: Base = ReqInsertCount + DeltaBase when S=0, and
     * ReqInsertCount - DeltaBase - 1 when S=1. With RIC pinned at 0, S=1 would
     * put Base below zero and any DeltaBase above zero would name an entry of a
     * table that does not exist -- both are malformed rather than merely
     * unused, so lite refuses them instead of ignoring the field. */
    if (p >= end) return QPACK_ERR_DECOMPRESSION;
    const int base_sign = (*p & 0x80) != 0;

    uint64_t delta_base = 0;
    n = prefix_int_decode(p, (size_t)(end - p), 7, &delta_base);
    if (n == 0) return QPACK_ERR_DECOMPRESSION;
    p += n;
    if (base_sign || delta_base != 0) return QPACK_ERR_DECOMPRESSION;

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
            if (!T) { st = QPACK_ERR_DECOMPRESSION; goto fail; } /* dynamic: no table in lite */
            if (idx >= QPACK_STATIC_TABLE_SIZE) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
            const qpack_static_entry_t* e = &qpack_static_table[idx];
            if (!__dup_static(e->name, &h->name, &h->name_len) ||
                !__dup_static(e->value, &h->value, &h->value_len)) { st = QPACK_ERR_MEMORY; goto fail; }
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
            if (!T) { st = QPACK_ERR_DECOMPRESSION; goto fail; } /* dynamic name: no table in lite */
            if (nidx >= QPACK_STATIC_TABLE_SIZE) { st = QPACK_ERR_DECOMPRESSION; goto fail; }
            const qpack_static_entry_t* e = &qpack_static_table[nidx];
            if (!__dup_static(e->name, &h->name, &h->name_len)) { st = QPACK_ERR_MEMORY; goto fail; }
            st = __decode_value(&p, end, &h->value, &h->value_len);
            if (st != QPACK_OK) goto fail;
            h->never_indexed = N;
        }
        else if ((octet & 0xf0) == 0x10) {
            /* Indexed Field Line With Post-Base Index (0001iiii) -- dynamic only. */
            st = QPACK_ERR_DECOMPRESSION; goto fail;
        }
        else {
            /* Literal With Post-Base Name Reference (0000Niii) -- dynamic only. */
            st = QPACK_ERR_DECOMPRESSION; goto fail;
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

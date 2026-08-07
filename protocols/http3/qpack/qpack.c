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

    uint64_t delta_base = 0;
    n = prefix_int_decode(p, (size_t)(end - p), 7, &delta_base);
    if (n == 0) return QPACK_ERR_DECOMPRESSION;
    p += n;
    (void)delta_base;

    qpack_header_t* headers = NULL;
    size_t count = 0, cap = 0;
    size_t total = 0;
    qpack_status_e st = QPACK_OK;

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
    }

    *out = headers;
    *out_count = count;
    return QPACK_OK;

fail:
    /* count was not incremented for the partial entry; release its allocations
     * (NULL-safe) before freeing the completed ones. */
    if (headers != NULL) {
        free(headers[count].name);
        free(headers[count].value);
    }
    qpack_headers_free(headers, count);
    return st;
}

#include "h3response.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "h3frame.h"
#include "httpfields.h"
#include "log.h"
#include "qpack.h"

/* A field list under construction. The names need a buffer of their own because
 * they are lowercased copies of the response's canonical-cased ones, and the
 * qpack_header_t entries point into it -- so it must not move once they do,
 * which is why it is sized up front rather than grown. */
typedef struct {
    qpack_header_t* fields;
    size_t          count;
    char*           names;
    size_t          names_off;
} h3fieldlist_t;

static void __fieldlist_free(h3fieldlist_t* l) {
    free(l->fields);
    free(l->names);
}

/* Room for `capacity` fields whose names total `names_size` bytes. */
static int __fieldlist_init(h3fieldlist_t* l, size_t capacity, size_t names_size) {
    l->fields = malloc(sizeof(*l->fields) * (capacity > 0 ? capacity : 1));
    l->names = malloc(names_size > 0 ? names_size : 1);
    l->count = 0;
    l->names_off = 0;

    if (l->fields == NULL || l->names == NULL) {
        __fieldlist_free(l);
        l->fields = NULL;
        l->names = NULL;
        return 0;
    }

    return 1;
}

/* Append one response header, lowercasing the name into the list's own buffer. */
static void __fieldlist_add(h3fieldlist_t* l, const http_header_t* h) {
    char* name = l->names + l->names_off;
    httpfields_lowercase(name, h->key, h->key_length);

    qpack_header_t* f = &l->fields[l->count];
    f->name = name;
    f->name_len = h->key_length;
    f->value = h->value;
    f->value_len = h->value_length;
    f->never_indexed = httpfields_is_sensitive_header(name, h->key_length);

    l->names_off += h->key_length;
    l->count++;
}

/* Wrap an encoded field section in a HEADERS frame. Takes ownership of nothing;
 * `*out` is fresh memory. */
static h3response_status_e __encode(struct qpack_encoder* enc,
                                    uint64_t stream_id,
                                    const qpack_header_t* fields, size_t count,
                                    uint8_t** out, size_t* out_len) {
    /* A generous bound: the prefix is 2 bytes, every field costs at most its
     * own bytes plus a few of framing, and Huffman only ever shrinks a string.
     * Sizing it up front avoids a two-pass encode, and the buffer is short-
     * lived. */
    size_t bound = 64;
    for (size_t i = 0; i < count; i++)
        bound += fields[i].name_len + fields[i].value_len + 16;

    uint8_t* block = malloc(bound);
    if (block == NULL) return H3RESPONSE_ERR_MEMORY;

    const size_t block_len = qpack_encode_block_for_stream(enc, stream_id,
                                                           fields, count, block, bound);
    if (block_len == 0) {
        free(block);
        return H3RESPONSE_ERR_ENCODE;
    }

    /* The frame header's own width depends on the payload length, so the frame
     * is built after the block rather than around it. */
    const size_t total = block_len + 9;
    uint8_t* frame = malloc(total);
    if (frame == NULL) {
        free(block);
        return H3RESPONSE_ERR_MEMORY;
    }

    const size_t n = h3frame_write(frame, total, H3_FRAME_HEADERS, block, block_len);
    free(block);

    if (n == 0) {
        free(frame);
        return H3RESPONSE_ERR_ENCODE;
    }

    *out = frame;
    *out_len = n;

    return H3RESPONSE_OK;
}

/* ":status" is the one pseudo-header a response carries, and §4.3.1 requires it
 * first. Writes the decimal value into `buf`. */
static int __status_field(qpack_header_t* f, char* buf, size_t cap, int status_code) {
    const int len = snprintf(buf, cap, "%d", status_code);
    if (len < 1 || (size_t)len >= cap) return 0;

    f->name = ":status";
    f->name_len = 7;
    f->value = buf;
    f->value_len = (size_t)len;
    f->never_indexed = 0;

    return 1;
}

h3response_status_e h3response_headers(struct qpack_encoder* enc,
                                       const httpresponse_t* response,
                                       uint8_t** out, size_t* out_len) {
    return h3response_headers_for_stream(enc, UINT64_MAX, response, out, out_len);
}

h3response_status_e h3response_headers_for_stream(struct qpack_encoder* enc,
                                                  uint64_t stream_id,
                                                  const httpresponse_t* response,
                                                  uint8_t** out, size_t* out_len) {
    if (enc == NULL || response == NULL || out == NULL || out_len == NULL)
        return H3RESPONSE_ERR_ENCODE;

    *out = NULL;
    *out_len = 0;

    size_t count = 1;  /* :status */
    size_t names_size = 0;
    for (const http_header_t* h = response->header_; h != NULL; h = h->next) {
        if (h->key_length == 0 || httpfields_is_forbidden_response_header(h->key, h->key_length))
            continue;
        count++;
        names_size += h->key_length;
    }

    h3fieldlist_t list;
    if (!__fieldlist_init(&list, count, names_size)) return H3RESPONSE_ERR_MEMORY;

    char status[8];
    if (!__status_field(&list.fields[0], status, sizeof status, response->status_code)) {
        __fieldlist_free(&list);
        return H3RESPONSE_ERR_ENCODE;
    }
    list.count = 1;

    for (const http_header_t* h = response->header_; h != NULL; h = h->next) {
        if (h->key_length == 0 || httpfields_is_forbidden_response_header(h->key, h->key_length))
            continue;
        __fieldlist_add(&list, h);
    }

    const h3response_status_e st = __encode(enc, stream_id, list.fields, list.count,
                                            out, out_len);
    __fieldlist_free(&list);

    return st;
}

h3response_status_e h3response_informational(struct qpack_encoder* enc, int status_code,
                                             const http_header_t* fields,
                                             uint8_t** out, size_t* out_len) {
    return h3response_informational_for_stream(enc, UINT64_MAX, status_code,
                                               fields, out, out_len);
}

h3response_status_e h3response_informational_for_stream(struct qpack_encoder* enc,
                                                        uint64_t stream_id,
                                                        int status_code,
                                                        const http_header_t* fields,
                                                        uint8_t** out, size_t* out_len) {
    if (enc == NULL || out == NULL || out_len == NULL) return H3RESPONSE_ERR_ENCODE;

    *out = NULL;
    *out_len = 0;

    size_t count = 1;
    size_t names_size = 0;
    for (const http_header_t* h = fields; h != NULL; h = h->next) {
        if (h->key_length == 0 || httpfields_is_forbidden_response_header(h->key, h->key_length))
            continue;
        count++;
        names_size += h->key_length;
    }

    h3fieldlist_t list;
    if (!__fieldlist_init(&list, count, names_size)) return H3RESPONSE_ERR_MEMORY;

    char status[8];
    if (!__status_field(&list.fields[0], status, sizeof status, status_code)) {
        __fieldlist_free(&list);
        return H3RESPONSE_ERR_ENCODE;
    }
    list.count = 1;

    for (const http_header_t* h = fields; h != NULL; h = h->next) {
        if (h->key_length == 0 || httpfields_is_forbidden_response_header(h->key, h->key_length))
            continue;
        __fieldlist_add(&list, h);
    }

    const h3response_status_e st = __encode(enc, stream_id, list.fields, list.count,
                                            out, out_len);
    __fieldlist_free(&list);

    return st;
}

h3response_status_e h3response_trailers(struct qpack_encoder* enc,
                                        const http_header_t* trailers,
                                        uint8_t** out, size_t* out_len) {
    return h3response_trailers_for_stream(enc, UINT64_MAX, trailers, out, out_len);
}

h3response_status_e h3response_trailers_for_stream(struct qpack_encoder* enc,
                                                   uint64_t stream_id,
                                                   const http_header_t* trailers,
                                                   uint8_t** out, size_t* out_len) {
    if (enc == NULL || out == NULL || out_len == NULL) return H3RESPONSE_ERR_ENCODE;

    *out = NULL;
    *out_len = 0;

    size_t count = 0;
    size_t names_size = 0;
    for (const http_header_t* h = trailers; h != NULL; h = h->next) {
        /* §4.1: a trailer section carries no pseudo-header, and content-length
         * in it would describe a body the peer has already read. Both are
         * dropped here rather than refused, because the response is ours: a
         * handler that set one made a mistake we can quietly correct. */
        if (h->key_length == 0 || h->key[0] == ':') continue;
        if (httpfields_is_forbidden_response_header(h->key, h->key_length)) continue;
        if (h->key_length == 14 && strncasecmp(h->key, "content-length", 14) == 0) continue;
        count++;
        names_size += h->key_length;
    }

    if (count == 0) return H3RESPONSE_ERR_ENCODE;

    h3fieldlist_t list;
    if (!__fieldlist_init(&list, count, names_size)) return H3RESPONSE_ERR_MEMORY;

    for (const http_header_t* h = trailers; h != NULL; h = h->next) {
        if (h->key_length == 0 || h->key[0] == ':') continue;
        if (httpfields_is_forbidden_response_header(h->key, h->key_length)) continue;
        if (h->key_length == 14 && strncasecmp(h->key, "content-length", 14) == 0) continue;
        __fieldlist_add(&list, h);
    }

    const h3response_status_e st = __encode(enc, stream_id, list.fields, list.count,
                                            out, out_len);
    __fieldlist_free(&list);

    return st;
}

size_t h3response_data_header(uint8_t* dst, size_t cap, uint64_t payload_len) {
    return h3frame_write_header(dst, cap, H3_FRAME_DATA, payload_len);
}

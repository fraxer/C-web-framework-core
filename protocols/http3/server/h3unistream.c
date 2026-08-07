#include <string.h>

#include "h3unistream.h"
#include "varint.h"

/* ---- Predicates ---- */

int h3uni_type_is_known(uint64_t type) {
    switch (type) {
    case H3_UNI_STREAM_CONTROL:
    case H3_UNI_STREAM_PUSH:
    case H3_UNI_STREAM_QPACK_ENCODER:
    case H3_UNI_STREAM_QPACK_DECODER:
        return 1;
    default:
        return 0;
    }
}

int h3uni_type_is_critical(uint64_t type) {
    /* §6.2.6: closing the control stream, or either QPACK stream, ends the
     * connection. A push stream is not critical -- it carries one push. */
    return type == H3_UNI_STREAM_CONTROL ||
           type == H3_UNI_STREAM_QPACK_ENCODER ||
           type == H3_UNI_STREAM_QPACK_DECODER;
}

/* ---- Parsing the type prefix ---- */

void h3uni_parser_init(h3uni_parser_t* p) {
    if (p == NULL) return;

    memset(p, 0, sizeof * p);
}

/* Read a varint that may be split across feeds. Returns 1 when complete. The
 * shape is the same as h3frame's __feed_varint, on purpose: the first byte
 * announces the length, and the parser holds the partial bytes until that many
 * have arrived. */
static int __feed_varint(h3uni_parser_t* p, const uint8_t** pp, const uint8_t* end,
                         uint64_t* out) {
    while (*pp < end) {
        if (p->varint_len == 0) {
            /* The two high bits give 1, 2, 4 or 8 bytes (RFC 9000 §16). */
            p->varint_need = (size_t)1 << ((**pp) >> 6);
        }

        p->varint_buf[p->varint_len++] = *(*pp)++;

        if (p->varint_len == p->varint_need) {
            const size_t n = varint_read(p->varint_buf, p->varint_len, out);
            p->varint_len = 0;
            p->varint_need = 0;
            return n > 0;
        }
    }

    return 0;
}

h3uni_status_e h3uni_parser_feed(h3uni_parser_t* p, const uint8_t** pp,
                                 const uint8_t* end) {
    /* As in h3frame: an empty feed is "nothing new", not a bad argument -- a
     * uni-stream can be opened by a STREAM frame that carries no bytes yet. */
    if (p == NULL || pp == NULL || *pp > end) return H3UNI_ERR_ENCODING;

    /* A type prefix is one varint. Once read, the parser is done: it reports
     * READY a single time and the caller switches to type-specific parsing.
     * Guarding with `done` keeps a stray second feed from interpreting the first
     * bytes of the stream's content as another type. */
    if (p->done) return H3UNI_CONTINUE;

    if (!__feed_varint(p, pp, end, &p->type)) return H3UNI_CONTINUE;

    p->done = 1;
    return H3UNI_READY;
}

/* ---- Per-direction duplicate tracking ---- *
 *
 * The three unique types get a bit each. Push is not tracked: many per server,
 * and from a client always illegal (handled in classify, not here). */

#define __BIT_CONTROL   (1u << 0)
#define __BIT_QPACK_ENC (1u << 1)
#define __BIT_QPACK_DEC (1u << 2)

static int __unique_bit(uint64_t type, uint8_t* out) {
    switch (type) {
    case H3_UNI_STREAM_CONTROL:       *out = __BIT_CONTROL;   return 1;
    case H3_UNI_STREAM_QPACK_ENCODER: *out = __BIT_QPACK_ENC; return 1;
    case H3_UNI_STREAM_QPACK_DECODER: *out = __BIT_QPACK_DEC; return 1;
    default: return 0;
    }
}

int h3uni_seen_mark(h3uni_seen_t* seen, uint64_t type) {
    if (seen == NULL) return 1;

    uint8_t bit = 0;
    if (!__unique_bit(type, &bit)) return 1;   /* push/unknown/grease: untracked */

    if (seen->bits & bit) return 0;            /* duplicate */

    seen->bits |= bit;
    return 1;
}

/* ---- Policy ---- */

h3uni_verdict_t h3uni_server_classify(h3uni_seen_t* seen, uint64_t type) {
    h3uni_verdict_t v = {0};
    v.type = type;

    /* Grease first: it overlaps none of the checks below, and a grease value is
     * not "unknown" in the sense that triggers STOP_SENDING -- it is to be read
     * and thrown away without complaint (RFC 9114 §6.2.3). */
    if (h3uni_type_is_grease(type)) {
        v.action = H3UNI_IGNORE;
        return v;
    }

    /* A push stream originates at a server (RFC 9114 §6.2.2). Receiving one
     * from a client is a stream-creation error, not an unknown type: 0x01 is a
     * defined value, the client simply has no business sending it. */
    if (type == H3_UNI_STREAM_PUSH) {
        v.action = H3UNI_CONN_ERROR;
        v.error = H3_STREAM_CREATION_ERROR;
        return v;
    }

    /* The three service streams: unique per direction. A second sighting of any
     * is a connection error; the first is routed. */
    uint8_t bit = 0;
    if (__unique_bit(type, &bit)) {
        if (seen != NULL && (seen->bits & bit)) {
            v.action = H3UNI_CONN_ERROR;
            v.error = H3_STREAM_CREATION_ERROR;
        } else {
            if (seen != NULL) seen->bits |= bit;
            v.action = H3UNI_ROUTE;
        }
        return v;
    }

    /* Genuinely unknown: §6.2.3 permits STOP_SENDING + discard, which this
     * server does. Not fatal -- the stream is closed, the connection is not. */
    v.action = H3UNI_STOP_DROP;
    v.error = H3_STREAM_CREATION_ERROR;
    return v;
}

/* ---- Writing ---- */

size_t h3uni_write_type(uint8_t* dst, size_t cap, uint64_t type) {
    return varint_write(dst, cap, type);
}

#include <stdlib.h>
#include <string.h>

#include "h3frame.h"
#include "varint.h"

void h3frame_parser_init(h3frame_parser_t* p) {
    if (p == NULL) return;

    memset(p, 0, sizeof * p);
}

void h3frame_parser_free(h3frame_parser_t* p) {
    if (p == NULL) return;

    free(p->accum);
    p->accum = NULL;
    p->accum_len = 0;
    p->accum_cap = 0;
}

/* Frames whose payload is accumulated before it is handed over. DATA is not
 * one of them: a response body is a single frame of unbounded size. */
static int __accumulates(uint64_t type) {
    switch (type) {
    case H3_FRAME_HEADERS:
    case H3_FRAME_SETTINGS:
    case H3_FRAME_GOAWAY:
    case H3_FRAME_CANCEL_PUSH:
    case H3_FRAME_MAX_PUSH_ID:
    case H3_FRAME_PUSH_PROMISE:
    case H3_FRAME_PRIORITY_UPDATE_REQUEST:
    case H3_FRAME_PRIORITY_UPDATE_PUSH:
        return 1;
    default:
        return 0;
    }
}

/* Read a varint that may be split across feeds. Returns 1 when complete. */
static int __feed_varint(h3frame_parser_t* p, const uint8_t** pp, const uint8_t* end,
                         uint64_t* out) {
    while (*pp < end) {
        if (p->varint_len == 0) {
            /* The first byte says how long the whole thing is. */
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

static int __accum_reserve(h3frame_parser_t* p, size_t need) {
    if (need <= p->accum_cap) return 1;

    size_t cap = p->accum_cap == 0 ? 256 : p->accum_cap;
    while (cap < need) cap *= 2;

    uint8_t* grown = realloc(p->accum, cap);
    if (grown == NULL) return 0;

    p->accum = grown;
    p->accum_cap = cap;

    return 1;
}

h3frame_status_e h3frame_parser_feed(h3frame_parser_t* p,
                                     const uint8_t** pp, const uint8_t* end) {
    /* An empty feed is legal and common: a QUIC STREAM frame that carries only
     * FIN has no bytes, and the caller still has to drive the parser to learn
     * whether the stream ended on a frame boundary. `*pp == end` (both NULL
     * included) therefore means "nothing new", not "bad argument"; only a
     * cursor past its own end is an argument error. */
    if (p == NULL || pp == NULL || *pp > end) return H3FRAME_ERR_ENCODING;

    p->payload = NULL;
    p->payload_len = 0;

    while (*pp < end || p->stage == H3FRAME_STAGE_PAYLOAD ||
           p->stage == H3FRAME_STAGE_SKIP) {

        switch (p->stage) {
        case H3FRAME_STAGE_TYPE:
            if (!__feed_varint(p, pp, end, &p->type)) return H3FRAME_CONTINUE;

            /* §11.2.1: the codepoints HTTP/2 used are reserved here, and
             * passing one through would let a translating proxy smuggle a
             * frame between the versions. */
            if (h3_frame_type_is_reserved_h2(p->type)) return H3FRAME_ERR_RESERVED;

            p->stage = H3FRAME_STAGE_LENGTH;
            break;

        case H3FRAME_STAGE_LENGTH: {
            if (!__feed_varint(p, pp, end, &p->length)) return H3FRAME_CONTINUE;

            p->remaining = p->length;
            p->accum_len = 0;

            const int keep = __accumulates(p->type);

            if (keep && p->length > H3FRAME_MAX_ACCUMULATED)
                return H3FRAME_ERR_TOO_LARGE;

            if (keep && p->length > 0 && !__accum_reserve(p, (size_t)p->length))
                return H3FRAME_ERR_OOM;

            p->stage = keep || p->type == H3_FRAME_DATA
                       ? H3FRAME_STAGE_PAYLOAD : H3FRAME_STAGE_SKIP;

            /* An empty frame is complete the moment its header is. */
            if (p->remaining == 0) {
                p->stage = H3FRAME_STAGE_TYPE;

                if (p->type == H3_FRAME_DATA) {
                    p->payload = NULL;
                    p->payload_len = 0;
                    return H3FRAME_DATA_CHUNK;
                }

                if (keep) {
                    p->payload = p->accum;
                    p->payload_len = 0;
                    return H3FRAME_READY;
                }

                return H3FRAME_SKIPPED;
            }
            break;
        }

        case H3FRAME_STAGE_PAYLOAD: {
            const size_t available = (size_t)(end - *pp);
            if (available == 0) return H3FRAME_CONTINUE;

            size_t take = available;
            if ((uint64_t)take > p->remaining) take = (size_t)p->remaining;

            if (p->type == H3_FRAME_DATA) {
                /* Handed straight through: a body may be gigabytes, and
                 * holding it to hand over in one piece is not an option. */
                p->payload = *pp;
                p->payload_len = take;
                *pp += take;
                p->remaining -= take;

                if (p->remaining == 0) p->stage = H3FRAME_STAGE_TYPE;

                return H3FRAME_DATA_CHUNK;
            }

            memcpy(p->accum + p->accum_len, *pp, take);
            p->accum_len += take;
            *pp += take;
            p->remaining -= take;

            if (p->remaining > 0) return H3FRAME_CONTINUE;

            p->stage = H3FRAME_STAGE_TYPE;
            p->payload = p->accum;
            p->payload_len = p->accum_len;

            return H3FRAME_READY;
        }

        case H3FRAME_STAGE_SKIP: {
            const size_t available = (size_t)(end - *pp);
            if (available == 0) return H3FRAME_CONTINUE;

            size_t take = available;
            if ((uint64_t)take > p->remaining) take = (size_t)p->remaining;

            *pp += take;
            p->remaining -= take;

            if (p->remaining > 0) return H3FRAME_CONTINUE;

            p->stage = H3FRAME_STAGE_TYPE;
            return H3FRAME_SKIPPED;
        }
        }
    }

    return H3FRAME_CONTINUE;
}

size_t h3frame_write_header(uint8_t* dst, size_t cap, uint64_t type, uint64_t length) {
    if (dst == NULL) return 0;

    size_t p = 0;

    const size_t n = varint_write(dst + p, cap - p, type);
    if (n == 0) return 0;
    p += n;

    const size_t m = varint_write(dst + p, cap - p, length);
    if (m == 0) return 0;
    p += m;

    return p;
}

size_t h3frame_write(uint8_t* dst, size_t cap, uint64_t type,
                     const uint8_t* payload, size_t len) {
    const size_t header = h3frame_write_header(dst, cap, type, len);
    if (header == 0) return 0;

    if (len > 0) {
        if (payload == NULL || header + len > cap) return 0;
        memcpy(dst + header, payload, len);
    }

    return header + len;
}

/* ---- SETTINGS ---- */

void h3settings_defaults(h3settings_t* settings) {
    if (settings == NULL) return;

    memset(settings, 0, sizeof * settings);

    /* §7.2.4.1: absent means zero for the QPACK settings -- no dynamic table
     * and no blocked streams -- and unlimited for the field section size. */
    settings->max_field_section_size = UINT64_MAX;
}

/* The HTTP/2 settings identifiers, reserved here for the same reason as the
 * frame codepoints (§7.2.4.1). */
static int __is_reserved_h2_setting(uint64_t id) {
    return id == 0x02 || id == 0x03 || id == 0x04 || id == 0x05;
}

static int __is_grease_setting(uint64_t id) {
    return id >= 0x21 && (id - 0x21) % 0x1f == 0;
}

h3settings_status_e h3settings_decode(const uint8_t* payload, size_t len,
                                      h3settings_t* out) {
    if (out == NULL) return H3SETTINGS_ERR_ENCODING;
    if (payload == NULL && len > 0) return H3SETTINGS_ERR_ENCODING;

    /* Only the identifiers we understand need duplicate detection; a repeated
     * reserved one is meaningless either way. */
    uint32_t seen = 0;

    size_t p = 0;
    while (p < len) {
        uint64_t id = 0;
        size_t n = varint_read(payload + p, len - p, &id);
        if (n == 0) return H3SETTINGS_ERR_ENCODING;
        p += n;

        uint64_t value = 0;
        n = varint_read(payload + p, len - p, &value);
        if (n == 0) return H3SETTINGS_ERR_ENCODING;
        p += n;

        if (__is_reserved_h2_setting(id)) return H3SETTINGS_ERR_SETTINGS;
        if (__is_grease_setting(id)) continue;

        switch (id) {
        case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
            if (seen & (1u << 0)) return H3SETTINGS_ERR_SETTINGS;
            seen |= 1u << 0;
            out->qpack_max_table_capacity = value;
            break;

        case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
            if (seen & (1u << 1)) return H3SETTINGS_ERR_SETTINGS;
            seen |= 1u << 1;
            out->max_field_section_size = value;
            break;

        case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
            if (seen & (1u << 2)) return H3SETTINGS_ERR_SETTINGS;
            seen |= 1u << 2;
            out->qpack_blocked_streams = value;
            break;

        case H3_SETTINGS_ENABLE_CONNECT_PROTOCOL:
            if (seen & (1u << 3)) return H3SETTINGS_ERR_SETTINGS;
            seen |= 1u << 3;
            /* §7.2.4.1 of RFC 9220: only 0 and 1 are defined. */
            if (value > 1) return H3SETTINGS_ERR_SETTINGS;
            out->enable_connect_protocol = (int)value;
            break;

        default:
            /* Unknown but not reserved: ignore it (§7.2.4.1). */
            break;
        }
    }

    return H3SETTINGS_OK;
}

size_t h3settings_encode(uint8_t* dst, size_t cap, const h3settings_t* settings) {
    if (dst == NULL || settings == NULL) return 0;

    size_t p = 0;

#define PUT(id, value)                                       \
    do {                                                     \
        size_t __n = varint_write(dst + p, cap - p, (id));   \
        if (__n == 0) return 0;                              \
        p += __n;                                            \
        __n = varint_write(dst + p, cap - p, (value));       \
        if (__n == 0) return 0;                              \
        p += __n;                                            \
    } while (0)

    PUT(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, settings->qpack_max_table_capacity);
    PUT(H3_SETTINGS_QPACK_BLOCKED_STREAMS, settings->qpack_blocked_streams);

    if (settings->max_field_section_size != UINT64_MAX)
        PUT(H3_SETTINGS_MAX_FIELD_SECTION_SIZE, settings->max_field_section_size);

    if (settings->enable_connect_protocol)
        PUT(H3_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1);

    /* One reserved identifier, so a peer's handling of them is exercised
     * against a real server rather than only in its own tests. 0x1f*2 + 0x21. */
    PUT(0x5f, 0);

#undef PUT

    return p;
}

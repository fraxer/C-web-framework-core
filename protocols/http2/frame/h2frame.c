#include "h2frame.h"

#include <stdlib.h>
#include <string.h>

/* Validate header fields that are known once the 9-byte header is parsed.
 * Returns H2PARSE_FRAME_READY when the header is acceptable, otherwise the
 * status the caller should report — BAD_FRAME for a structural violation,
 * FRAME_SIZE for a length one. RFC 9113 §4.2, §6, §8 checks. */
static h2parse_status_e h2frame_header_invalid(const h2frame_parser_t* p) {
    /* The reserved bit (R) of the stream identifier is left undefined by
     * RFC §4.1 and MUST be ignored when receiving — a sender may set it. It is
     * masked off while decoding stream_id, which is all that is required; it is
     * deliberately NOT an error (h2spec 4.1/3 sends a PING with the bit set and
     * expects a normal PING ACK back). */

    /* Frame size limits (RFC §4.2). */
    if (p->length > p->max_frame_size) return H2PARSE_FRAME_SIZE;
    if (p->length > H2_MAX_FRAME_SIZE_LIMIT) return H2PARSE_FRAME_SIZE;

    /* Connection-control frames carry stream id 0; stream frames MUST NOT. */
    int is_conn = (p->type == H2_FRAME_SETTINGS ||
                   p->type == H2_FRAME_PING ||
                   p->type == H2_FRAME_GOAWAY);
    if (is_conn && p->stream_id != 0) return H2PARSE_BAD_FRAME;

    /* Frames that MUST carry a non-zero stream id. WINDOW_UPDATE is excluded:
     * it may target stream 0 (connection-level flow control) or a stream. */
    int is_stream = (p->type == H2_FRAME_DATA ||
                     p->type == H2_FRAME_HEADERS ||
                     p->type == H2_FRAME_PRIORITY ||
                     p->type == H2_FRAME_RST_STREAM ||
                     p->type == H2_FRAME_PUSH_PROMISE ||
                     p->type == H2_FRAME_CONTINUATION);
    if (is_stream && p->stream_id == 0) return H2PARSE_BAD_FRAME;

    /* Type-specific payload lengths that are fixed and known up front. */
    switch (p->type) {
    case H2_FRAME_PING:          if (p->length != 8) return H2PARSE_FRAME_SIZE; break;
    case H2_FRAME_WINDOW_UPDATE: if (p->length != 4) return H2PARSE_FRAME_SIZE; break;
    case H2_FRAME_PRIORITY:      if (p->length != 5) return H2PARSE_FRAME_SIZE; break;
    case H2_FRAME_RST_STREAM:    if (p->length != 4) return H2PARSE_FRAME_SIZE; break;
    case H2_FRAME_SETTINGS:
        /* §6.5: an ACK carries no payload at all, and any other length must be a
         * multiple of the 6-byte setting. Checking the ACK case here rather than
         * in the session is what makes it an error instead of a silent ignore —
         * h2_on_settings returns on the ACK flag before it ever looks at the
         * length (docs/http2/08, phase C.2). */
        if ((p->flags & H2_FLAG_ACK) && p->length != 0) return H2PARSE_FRAME_SIZE;
        if ((p->length % 6) != 0) return H2PARSE_FRAME_SIZE;
        break;
    case H2_FRAME_GOAWAY:        if (p->length < 8) return H2PARSE_FRAME_SIZE; break;
    default: break; /* unknown types pass through per RFC §5.5 */
    }

    return H2PARSE_FRAME_READY;
}

void h2frame_parser_init(h2frame_parser_t* p, int preface_required, uint32_t max_frame_size) {
    memset(p, 0, sizeof(*p));
    p->stage = preface_required ? H2FRAME_STAGE_PREFACE : H2FRAME_STAGE_HEADER;
    p->preface_required = preface_required;
    p->max_frame_size = (max_frame_size == 0) ? H2_MAX_FRAME_SIZE_DEFAULT : max_frame_size;
}

void h2frame_parser_free(h2frame_parser_t* p) {
    free(p->payload);
    p->payload = NULL;
    p->payload_cap = 0;
}

void h2frame_parser_get(const h2frame_parser_t* p, h2_frame_t* out) {
    out->length = p->length;
    out->type = p->type;
    out->flags = p->flags;
    out->stream_id = p->stream_id;
    out->payload = p->payload;
    out->payload_len = p->payload_pos;
}

h2parse_status_e h2frame_parser_feed(h2frame_parser_t* p, const uint8_t** pp, const uint8_t* end) {
    const uint8_t* cur = *pp;

    while (cur < end) {
        if (p->stage == H2FRAME_STAGE_PREFACE) {
            size_t need = H2_CONNECTION_PREFACE_LEN - p->preface_pos;
            size_t avail = (size_t)(end - cur);
            size_t take = avail < need ? avail : need;
            if (memcmp(cur, H2_CONNECTION_PREFACE + p->preface_pos, take) != 0) {
                *pp = cur; /* leave cursor at the mismatch; connection is dead anyway */
                return H2PARSE_PREFACE_BAD;
            }
            p->preface_pos += take;
            cur += take;
            if (p->preface_pos < H2_CONNECTION_PREFACE_LEN) { *pp = cur; return H2PARSE_CONTINUE; }
            p->stage = H2FRAME_STAGE_HEADER;
            p->header_pos = 0;
            /* fall through to header stage within this same feed */
        }

        if (p->stage == H2FRAME_STAGE_HEADER) {
            size_t need = H2_FRAME_HEADER_LEN - p->header_pos;
            size_t avail = (size_t)(end - cur);
            size_t take = avail < need ? avail : need;
            memcpy(p->header + p->header_pos, cur, take);
            p->header_pos += take;
            cur += take;
            if (p->header_pos < H2_FRAME_HEADER_LEN) { *pp = cur; return H2PARSE_CONTINUE; }

            /* Header complete — decode fields. */
            p->length = ((uint32_t)p->header[0] << 16) |
                        ((uint32_t)p->header[1] << 8) |
                        ((uint32_t)p->header[2]);
            p->type = p->header[3];
            p->flags = p->header[4];
            p->stream_id = ((uint32_t)(p->header[5] & 0x7f) << 24) |
                           ((uint32_t)p->header[6] << 16) |
                           ((uint32_t)p->header[7] << 8) |
                           ((uint32_t)p->header[8]);

            const h2parse_status_e bad = h2frame_header_invalid(p);
            if (bad != H2PARSE_FRAME_READY) { *pp = cur; return bad; }

            p->payload_pos = 0;
            if (p->length == 0) {
                /* Zero-payload frame (e.g. SETTINGS ACK, empty DATA): ready now. */
                p->stage = H2FRAME_STAGE_HEADER;
                p->header_pos = 0;
                *pp = cur;
                return H2PARSE_FRAME_READY;
            }
            if (p->length > p->payload_cap) {
                uint8_t* nb = realloc(p->payload, p->length);
                if (nb == NULL) { p->oom = 1; *pp = cur; return H2PARSE_OOM; }
                p->payload = nb;
                p->payload_cap = p->length;
            }
            p->stage = H2FRAME_STAGE_PAYLOAD;
            /* fall through to payload stage within this same feed */
        }

        if (p->stage == H2FRAME_STAGE_PAYLOAD) {
            size_t need = p->length - p->payload_pos;
            size_t avail = (size_t)(end - cur);
            size_t take = avail < need ? avail : need;
            memcpy(p->payload + p->payload_pos, cur, take);
            p->payload_pos += take;
            cur += take;
            if (p->payload_pos < p->length) { *pp = cur; return H2PARSE_CONTINUE; }
            /* Frame complete — position for the next frame and signal readiness. */
            p->stage = H2FRAME_STAGE_HEADER;
            p->header_pos = 0;
            *pp = cur;
            return H2PARSE_FRAME_READY;
        }
    }

    *pp = cur;
    return H2PARSE_CONTINUE;
}

size_t h2frame_encode_header(uint8_t dst[H2_FRAME_HEADER_LEN], uint8_t type, uint8_t flags,
                             uint32_t stream_id, size_t payload_len) {
    if (payload_len > H2_MAX_FRAME_SIZE_LIMIT) return 0;

    dst[0] = (uint8_t)((payload_len >> 16) & 0xff);
    dst[1] = (uint8_t)((payload_len >> 8) & 0xff);
    dst[2] = (uint8_t)(payload_len & 0xff);
    dst[3] = type;
    dst[4] = flags;
    dst[5] = (uint8_t)((stream_id >> 24) & 0x7f); /* clear reserved R bit */
    dst[6] = (uint8_t)((stream_id >> 16) & 0xff);
    dst[7] = (uint8_t)((stream_id >> 8) & 0xff);
    dst[8] = (uint8_t)(stream_id & 0xff);

    return (size_t)H2_FRAME_HEADER_LEN;
}

size_t h2frame_encode(uint8_t* dst, size_t cap, uint8_t type, uint8_t flags,
                      uint32_t stream_id, const uint8_t* payload, size_t payload_len) {
    if (payload_len > H2_MAX_FRAME_SIZE_LIMIT) return 0;
    if (cap < (size_t)H2_FRAME_HEADER_LEN + payload_len) return 0;

    h2frame_encode_header(dst, type, flags, stream_id, payload_len);

    if (payload_len > 0 && payload != NULL)
        memcpy(dst + H2_FRAME_HEADER_LEN, payload, payload_len);

    return (size_t)H2_FRAME_HEADER_LEN + payload_len;
}

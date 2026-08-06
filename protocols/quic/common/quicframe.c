#include <string.h>

#include "quicframe.h"
#include "varint.h"

/* Read a varint, failing the whole frame if it does not fit. */
#define READ_VARINT(target)                                          \
    do {                                                             \
        const size_t __n = varint_read(buf + p, len - p, &(target)); \
        if (__n == 0) return QUICFRAME_ERR_ENCODING;                 \
        p += __n;                                                    \
    } while (0)

/* Write a varint, failing the whole frame if it does not fit. */
#define WRITE_VARINT(value)                                          \
    do {                                                             \
        const size_t __n = varint_write(dst + p, cap - p, (value));  \
        if (__n == 0) return 0;                                      \
        p += __n;                                                    \
    } while (0)

int quicframe_is_ack_eliciting(uint64_t type) {
    switch (type) {
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        return 0;
    default:
        return 1;
    }
}

int quicframe_allowed_in(uint64_t type, quic_enc_level_e level) {
    /* §12.4. Initial and Handshake carry only what the handshake itself needs;
     * 0-RTT cannot carry anything that acknowledges, because the client has no
     * keys to read a reply with yet. */
    if (type >= QUIC_FRAME_STREAM && type < QUIC_FRAME_STREAM + 8)
        return level == QUIC_ENC_EARLY || level == QUIC_ENC_APP;

    switch (type) {
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_PING:
    case QUIC_FRAME_CONNECTION_CLOSE:
        return 1;

    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
    case QUIC_FRAME_CRYPTO:
        return level != QUIC_ENC_EARLY;

    /* The application-code form needs the application's error space, which
     * exists only once the handshake keys do. */
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        return level == QUIC_ENC_EARLY || level == QUIC_ENC_APP;

    case QUIC_FRAME_NEW_TOKEN:
    case QUIC_FRAME_PATH_RESPONSE:
    case QUIC_FRAME_HANDSHAKE_DONE:
        return level == QUIC_ENC_APP;

    case QUIC_FRAME_RESET_STREAM:
    case QUIC_FRAME_STOP_SENDING:
    case QUIC_FRAME_MAX_DATA:
    case QUIC_FRAME_MAX_STREAM_DATA:
    case QUIC_FRAME_MAX_STREAMS_BIDI:
    case QUIC_FRAME_MAX_STREAMS_UNI:
    case QUIC_FRAME_DATA_BLOCKED:
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
    case QUIC_FRAME_STREAMS_BLOCKED_BIDI:
    case QUIC_FRAME_STREAMS_BLOCKED_UNI:
    case QUIC_FRAME_NEW_CONNECTION_ID:
    case QUIC_FRAME_RETIRE_CONNECTION_ID:
    case QUIC_FRAME_PATH_CHALLENGE:
        return level == QUIC_ENC_EARLY || level == QUIC_ENC_APP;

    default:
        return 0;
    }
}

/* ---- ACK ranges ---- */

void quicack_iter_init(const quicframe_t* frame, quicack_iter_t* it) {
    it->p = frame->u.ack.ranges;
    it->end = frame->u.ack.ranges + frame->u.ack.ranges_len;
    it->remaining = frame->u.ack.range_count;
    it->largest = frame->u.ack.largest;
    it->first_range = frame->u.ack.first_range;
    it->first = 1;
    it->smallest = 0;
}

int quicack_iter_next(quicack_iter_t* it, quicack_block_t* out) {
    if (it->first) {
        it->first = 0;

        /* First ACK Range counts packets below the largest, so it cannot reach
         * past zero. */
        if (it->first_range > it->largest) return -1;

        out->largest = it->largest;
        out->smallest = it->largest - it->first_range;
        it->smallest = out->smallest;

        return 1;
    }

    if (it->remaining == 0) return 0;
    it->remaining--;

    uint64_t gap = 0;
    uint64_t length = 0;

    size_t n = varint_read(it->p, (size_t)(it->end - it->p), &gap);
    if (n == 0) return -1;
    it->p += n;

    n = varint_read(it->p, (size_t)(it->end - it->p), &length);
    if (n == 0) return -1;
    it->p += n;

    /* §19.3.1: both fields are stored one less than they mean, so the next
     * block's upper edge is two below the previous lower edge plus the gap.
     * This is the arithmetic every QUIC implementation gets wrong once. */
    if (it->smallest < gap + 2) return -1;

    const uint64_t largest = it->smallest - gap - 2;
    if (largest < length) return -1;

    out->largest = largest;
    out->smallest = largest - length;
    it->smallest = out->smallest;

    return 1;
}

/* Walk the ranges once at parse time, so a malformed section is caught with
 * the frame rather than halfway through applying it. */
static quicframe_status_e __validate_ack_ranges(const quicframe_t* frame) {
    quicack_iter_t it;
    quicack_iter_init(frame, &it);

    quicack_block_t block;
    int r;
    while ((r = quicack_iter_next(&it, &block)) == 1) { /* walking only */ }

    return r == 0 ? QUICFRAME_OK : QUICFRAME_ERR_ENCODING;
}

/* ---- Parsing ---- */

quicframe_status_e quicframe_next(const uint8_t* buf, size_t len, size_t* off,
                                  quicframe_t* out) {
    if (buf == NULL || off == NULL || out == NULL) return QUICFRAME_ERR_ENCODING;
    if (*off >= len) return QUICFRAME_DONE;

    size_t p = *off;
    memset(out, 0, sizeof * out);

    uint64_t type = 0;
    READ_VARINT(type);
    out->type = type;

    if (type >= QUIC_FRAME_STREAM && type < QUIC_FRAME_STREAM + 8) {
        READ_VARINT(out->u.stream.id);

        if (type & QUIC_STREAM_FLAG_OFF)
            READ_VARINT(out->u.stream.offset);

        if (type & QUIC_STREAM_FLAG_LEN) {
            READ_VARINT(out->u.stream.len);
            if (out->u.stream.len > len - p) return QUICFRAME_ERR_ENCODING;
        }
        else {
            /* Without the LEN bit the frame runs to the end of the packet --
             * how the last frame saves its length varint. */
            out->u.stream.len = len - p;
        }

        /* §19.8: the final byte offset must stay inside the varint range. */
        if (out->u.stream.offset > QUIC_VARINT_MAX - out->u.stream.len)
            return QUICFRAME_ERR_ENCODING;

        out->u.stream.data = out->u.stream.len > 0 ? buf + p : NULL;
        out->u.stream.fin = (type & QUIC_STREAM_FLAG_FIN) != 0;
        p += (size_t)out->u.stream.len;

        *off = p;
        return QUICFRAME_OK;
    }

    switch (type) {
    case QUIC_FRAME_PADDING: {
        /* Fold the whole run: a padded Initial is a thousand padding bytes,
         * and reporting them one at a time would be a thousand iterations of
         * the caller's loop. */
        const size_t start = p - 1;
        while (p < len && buf[p] == 0x00) p++;
        out->u.padding.count = p - start;
        break;
    }

    case QUIC_FRAME_PING:
    case QUIC_FRAME_HANDSHAKE_DONE:
        break;

    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN: {
        READ_VARINT(out->u.ack.largest);
        READ_VARINT(out->u.ack.delay);
        READ_VARINT(out->u.ack.range_count);
        READ_VARINT(out->u.ack.first_range);

        out->u.ack.ranges = buf + p;

        /* Only the count is given, so the section's extent has to be found by
         * walking it -- and the ECN counts sit immediately after. */
        for (uint64_t i = 0; i < out->u.ack.range_count; i++) {
            uint64_t gap = 0;
            uint64_t length = 0;
            READ_VARINT(gap);
            READ_VARINT(length);
        }

        out->u.ack.ranges_len = (size_t)((buf + p) - out->u.ack.ranges);

        if (type == QUIC_FRAME_ACK_ECN) {
            out->u.ack.has_ecn = 1;
            READ_VARINT(out->u.ack.ect0);
            READ_VARINT(out->u.ack.ect1);
            READ_VARINT(out->u.ack.ce);
        }

        const quicframe_status_e st = __validate_ack_ranges(out);
        if (st != QUICFRAME_OK) return st;
        break;
    }

    case QUIC_FRAME_RESET_STREAM:
        READ_VARINT(out->u.reset_stream.id);
        READ_VARINT(out->u.reset_stream.error);
        READ_VARINT(out->u.reset_stream.final_size);
        break;

    case QUIC_FRAME_STOP_SENDING:
        READ_VARINT(out->u.stop_sending.id);
        READ_VARINT(out->u.stop_sending.error);
        break;

    case QUIC_FRAME_CRYPTO:
        READ_VARINT(out->u.crypto.offset);
        READ_VARINT(out->u.crypto.len);
        if (out->u.crypto.len > len - p) return QUICFRAME_ERR_ENCODING;
        /* §19.6: the end of the data must stay inside the varint range. */
        if (out->u.crypto.offset > QUIC_VARINT_MAX - out->u.crypto.len)
            return QUICFRAME_ERR_ENCODING;
        out->u.crypto.data = out->u.crypto.len > 0 ? buf + p : NULL;
        p += (size_t)out->u.crypto.len;
        break;

    case QUIC_FRAME_NEW_TOKEN:
        READ_VARINT(out->u.new_token.len);
        /* §19.7: a zero-length token is a protocol violation. */
        if (out->u.new_token.len == 0) return QUICFRAME_ERR_ENCODING;
        if (out->u.new_token.len > len - p) return QUICFRAME_ERR_ENCODING;
        out->u.new_token.data = buf + p;
        p += (size_t)out->u.new_token.len;
        break;

    case QUIC_FRAME_MAX_DATA:
        READ_VARINT(out->u.max_data.max);
        break;

    case QUIC_FRAME_MAX_STREAM_DATA:
        READ_VARINT(out->u.max_stream_data.id);
        READ_VARINT(out->u.max_stream_data.max);
        break;

    case QUIC_FRAME_MAX_STREAMS_BIDI:
    case QUIC_FRAME_MAX_STREAMS_UNI:
        READ_VARINT(out->u.max_streams.max);
        /* §19.11: above 2^60 the derived stream ids leave the varint range. */
        if (out->u.max_streams.max > (1ULL << 60)) return QUICFRAME_ERR_ENCODING;
        break;

    case QUIC_FRAME_DATA_BLOCKED:
        READ_VARINT(out->u.data_blocked.limit);
        break;

    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        READ_VARINT(out->u.stream_data_blocked.id);
        READ_VARINT(out->u.stream_data_blocked.limit);
        break;

    case QUIC_FRAME_STREAMS_BLOCKED_BIDI:
    case QUIC_FRAME_STREAMS_BLOCKED_UNI:
        READ_VARINT(out->u.streams_blocked.limit);
        if (out->u.streams_blocked.limit > (1ULL << 60)) return QUICFRAME_ERR_ENCODING;
        break;

    case QUIC_FRAME_NEW_CONNECTION_ID: {
        READ_VARINT(out->u.new_cid.seq);
        READ_VARINT(out->u.new_cid.retire_prior_to);
        /* §19.15: retiring past what has been issued is a protocol error;
         * catching it here saves the connection layer from having to. */
        if (out->u.new_cid.retire_prior_to > out->u.new_cid.seq)
            return QUICFRAME_ERR_ENCODING;

        if (p >= len) return QUICFRAME_ERR_ENCODING;
        const uint8_t cid_len = buf[p++];
        /* §19.15 gives a hard range of 1..20. Unlike a packet header, where a
         * zero-length id is legal, this frame must carry one. */
        if (cid_len < 1 || cid_len > QUIC_MAX_CID_LEN) return QUICFRAME_ERR_ENCODING;
        if ((size_t)cid_len + 16 > len - p) return QUICFRAME_ERR_ENCODING;

        out->u.new_cid.cid.len = cid_len;
        memcpy(out->u.new_cid.cid.data, buf + p, cid_len);
        p += cid_len;

        memcpy(out->u.new_cid.token, buf + p, 16);
        p += 16;
        break;
    }

    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        READ_VARINT(out->u.retire_cid.seq);
        break;

    case QUIC_FRAME_PATH_CHALLENGE:
    case QUIC_FRAME_PATH_RESPONSE:
        if (len - p < 8) return QUICFRAME_ERR_ENCODING;
        memcpy(out->u.path.data, buf + p, 8);
        p += 8;
        break;

    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP: {
        READ_VARINT(out->u.close.error);
        if (type == QUIC_FRAME_CONNECTION_CLOSE)
            READ_VARINT(out->u.close.frame_type);

        uint64_t reason_len = 0;
        READ_VARINT(reason_len);
        if (reason_len > len - p) return QUICFRAME_ERR_ENCODING;

        out->u.close.reason = reason_len > 0 ? (const char*)(buf + p) : NULL;
        out->u.close.reason_len = (size_t)reason_len;
        p += (size_t)reason_len;
        break;
    }

    default:
        /* There is no length prefix to skip over, so an unrecognised type ends
         * the connection -- the opposite of HTTP/3, where unknown frames carry
         * a length precisely so they can be ignored. */
        return QUICFRAME_ERR_UNKNOWN;
    }

    *off = p;

    return QUICFRAME_OK;
}

/* ---- Writing ---- */

size_t quicframe_write_padding(uint8_t* dst, size_t cap, size_t count) {
    if (dst == NULL || count > cap) return 0;

    memset(dst, 0, count);

    return count;
}

size_t quicframe_write_ack(uint8_t* dst, size_t cap,
                           const quicack_block_t* blocks, size_t block_count,
                           uint64_t delay, const uint64_t ecn[3]) {
    if (dst == NULL || blocks == NULL || block_count == 0) return 0;

    size_t p = 0;

    WRITE_VARINT(ecn != NULL ? QUIC_FRAME_ACK_ECN : QUIC_FRAME_ACK);
    WRITE_VARINT(blocks[0].largest);
    WRITE_VARINT(delay);
    WRITE_VARINT((uint64_t)(block_count - 1));

    if (blocks[0].smallest > blocks[0].largest) return 0;
    WRITE_VARINT(blocks[0].largest - blocks[0].smallest);

    for (size_t i = 1; i < block_count; i++) {
        /* Blocks run downwards and must not touch: two adjacent runs are one
         * run, and the encoding has no way to say "gap of zero". */
        if (blocks[i].smallest > blocks[i].largest) return 0;
        if (blocks[i].largest + 2 > blocks[i - 1].smallest) return 0;

        WRITE_VARINT(blocks[i - 1].smallest - blocks[i].largest - 2);
        WRITE_VARINT(blocks[i].largest - blocks[i].smallest);
    }

    if (ecn != NULL) {
        WRITE_VARINT(ecn[0]);
        WRITE_VARINT(ecn[1]);
        WRITE_VARINT(ecn[2]);
    }

    return p;
}

size_t quicframe_write(uint8_t* dst, size_t cap, const quicframe_t* frame) {
    if (dst == NULL || frame == NULL) return 0;

    const uint64_t type = frame->type;
    size_t p = 0;

    /* ACK is built from the sender's own range state, not echoed, so it has a
     * writer of its own. */
    if (type == QUIC_FRAME_ACK || type == QUIC_FRAME_ACK_ECN) return 0;

    if (type == QUIC_FRAME_PADDING)
        return quicframe_write_padding(dst, cap, (size_t)frame->u.padding.count);

    if (type >= QUIC_FRAME_STREAM && type < QUIC_FRAME_STREAM + 8) {
        WRITE_VARINT(type);
        WRITE_VARINT(frame->u.stream.id);

        if (type & QUIC_STREAM_FLAG_OFF)
            WRITE_VARINT(frame->u.stream.offset);

        if (type & QUIC_STREAM_FLAG_LEN)
            WRITE_VARINT(frame->u.stream.len);

        if (frame->u.stream.len > 0) {
            if (frame->u.stream.data == NULL) return 0;
            if (frame->u.stream.len > cap - p) return 0;
            memcpy(dst + p, frame->u.stream.data, (size_t)frame->u.stream.len);
            p += (size_t)frame->u.stream.len;
        }

        return p;
    }

    WRITE_VARINT(type);

    switch (type) {
    case QUIC_FRAME_PING:
    case QUIC_FRAME_HANDSHAKE_DONE:
        break;

    case QUIC_FRAME_RESET_STREAM:
        WRITE_VARINT(frame->u.reset_stream.id);
        WRITE_VARINT(frame->u.reset_stream.error);
        WRITE_VARINT(frame->u.reset_stream.final_size);
        break;

    case QUIC_FRAME_STOP_SENDING:
        WRITE_VARINT(frame->u.stop_sending.id);
        WRITE_VARINT(frame->u.stop_sending.error);
        break;

    case QUIC_FRAME_CRYPTO:
        WRITE_VARINT(frame->u.crypto.offset);
        WRITE_VARINT(frame->u.crypto.len);
        if (frame->u.crypto.len > 0) {
            if (frame->u.crypto.data == NULL || frame->u.crypto.len > cap - p) return 0;
            memcpy(dst + p, frame->u.crypto.data, (size_t)frame->u.crypto.len);
            p += (size_t)frame->u.crypto.len;
        }
        break;

    case QUIC_FRAME_NEW_TOKEN:
        if (frame->u.new_token.len == 0 || frame->u.new_token.data == NULL) return 0;
        WRITE_VARINT(frame->u.new_token.len);
        if (frame->u.new_token.len > cap - p) return 0;
        memcpy(dst + p, frame->u.new_token.data, (size_t)frame->u.new_token.len);
        p += (size_t)frame->u.new_token.len;
        break;

    case QUIC_FRAME_MAX_DATA:
        WRITE_VARINT(frame->u.max_data.max);
        break;

    case QUIC_FRAME_MAX_STREAM_DATA:
        WRITE_VARINT(frame->u.max_stream_data.id);
        WRITE_VARINT(frame->u.max_stream_data.max);
        break;

    case QUIC_FRAME_MAX_STREAMS_BIDI:
    case QUIC_FRAME_MAX_STREAMS_UNI:
        if (frame->u.max_streams.max > (1ULL << 60)) return 0;
        WRITE_VARINT(frame->u.max_streams.max);
        break;

    case QUIC_FRAME_DATA_BLOCKED:
        WRITE_VARINT(frame->u.data_blocked.limit);
        break;

    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        WRITE_VARINT(frame->u.stream_data_blocked.id);
        WRITE_VARINT(frame->u.stream_data_blocked.limit);
        break;

    case QUIC_FRAME_STREAMS_BLOCKED_BIDI:
    case QUIC_FRAME_STREAMS_BLOCKED_UNI:
        if (frame->u.streams_blocked.limit > (1ULL << 60)) return 0;
        WRITE_VARINT(frame->u.streams_blocked.limit);
        break;

    case QUIC_FRAME_NEW_CONNECTION_ID:
        if (frame->u.new_cid.cid.len < 1 ||
            frame->u.new_cid.cid.len > QUIC_MAX_CID_LEN) return 0;
        if (frame->u.new_cid.retire_prior_to > frame->u.new_cid.seq) return 0;

        WRITE_VARINT(frame->u.new_cid.seq);
        WRITE_VARINT(frame->u.new_cid.retire_prior_to);

        if ((size_t)frame->u.new_cid.cid.len + 1 + 16 > cap - p) return 0;
        dst[p++] = frame->u.new_cid.cid.len;
        memcpy(dst + p, frame->u.new_cid.cid.data, frame->u.new_cid.cid.len);
        p += frame->u.new_cid.cid.len;
        memcpy(dst + p, frame->u.new_cid.token, 16);
        p += 16;
        break;

    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        WRITE_VARINT(frame->u.retire_cid.seq);
        break;

    case QUIC_FRAME_PATH_CHALLENGE:
    case QUIC_FRAME_PATH_RESPONSE:
        if (8 > cap - p) return 0;
        memcpy(dst + p, frame->u.path.data, 8);
        p += 8;
        break;

    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        WRITE_VARINT(frame->u.close.error);
        if (type == QUIC_FRAME_CONNECTION_CLOSE)
            WRITE_VARINT(frame->u.close.frame_type);

        WRITE_VARINT((uint64_t)frame->u.close.reason_len);
        if (frame->u.close.reason_len > 0) {
            if (frame->u.close.reason == NULL) return 0;
            if (frame->u.close.reason_len > cap - p) return 0;
            memcpy(dst + p, frame->u.close.reason, frame->u.close.reason_len);
            p += frame->u.close.reason_len;
        }
        break;

    default:
        return 0;
    }

    return p;
}

#include <stdlib.h>
#include <string.h>

#include "quicsendbuf.h"
#include "quicmemory.h"

void quicsendbuf_init(quicsendbuf_t* buf) {
    if (buf == NULL) return;

    memset(buf, 0, sizeof * buf);
    /* Our own state, not the peer's, so no cap: the number of ranges is bounded
     * by how many packets we have in flight. */
    quicrange_init(&buf->acked, 0);
    quicrange_init(&buf->lost, 0);
}

void quicsendbuf_free(quicsendbuf_t* buf) {
    if (buf == NULL) return;

    quicmemory_release(buf->cap);
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;

    quicrange_free(&buf->acked);
    quicrange_free(&buf->lost);
}

int quicsendbuf_write(quicsendbuf_t* buf, const uint8_t* data, size_t len) {
    if (buf == NULL || buf->fin) return 0;
    if (len == 0) return 1;
    if (data == NULL) return 0;

    if (buf->head > SIZE_MAX - buf->len ||
        len > SIZE_MAX - buf->head - buf->len) return 0;

    if (buf->head + buf->len + len > buf->cap) {
        /* Reclaim the dead prefix before growing: a buffer that is only being
         * drained from the front would otherwise double forever. */
        if (buf->head > 0) {
            memmove(buf->data, buf->data + buf->head, buf->len);
            buf->head = 0;
        }

        if (buf->len + len > buf->cap) {
            size_t cap = buf->cap == 0 ? 4096 : buf->cap;
            const size_t need = buf->len + len;
            while (cap < need) {
                if (cap > SIZE_MAX / 2) {
                    cap = need;
                    break;
                }
                cap *= 2;
            }

            const size_t growth = cap - buf->cap;
            if (!quicmemory_reserve(growth)) return 0;

            uint8_t* grown = realloc(buf->data, cap);
            if (grown == NULL) {
                quicmemory_release(growth);
                return 0;
            }

            buf->data = grown;
            buf->cap = cap;
        }
    }

    memcpy(buf->data + buf->head + buf->len, data, len);
    buf->len += len;
    buf->write_off += len;

    return 1;
}

void quicsendbuf_finish(quicsendbuf_t* buf) {
    if (buf != NULL) buf->fin = 1;
}

/* Drop the acknowledged prefix. Only the front can go: an unacknowledged byte
 * pins everything behind it, because it may still have to be sent again. */
static void __slide(quicsendbuf_t* buf) {
    if (quicrange_empty(&buf->acked)) return;

    quicrange_span_t first;
    if (!quicrange_at_desc(&buf->acked, quicrange_count(&buf->acked) - 1, &first))
        return;

    if (first.start > buf->base) return;

    const uint64_t new_base = first.end + 1;
    if (new_base <= buf->base) return;

    const size_t drop = (size_t)(new_base - buf->base);
    if (drop >= buf->len) {
        buf->len = 0;
        buf->head = 0;
    }
    else {
        /* Move the read point rather than the data, and compact only when the
         * dead prefix has grown to half the buffer.
         *
         * Compacting on every acknowledgement meant memmoving whatever was left
         * -- up to the write-ahead budget, a quarter of a megabyte -- for the
         * two packets an acknowledgement typically covers. Over a large
         * transfer that is quadratic in bytes, and it showed: CPU per megabyte
         * grew with the size of the file (docs/http3/08 §7a). Amortised, each
         * byte is now moved at most once per doubling. */
        buf->head += drop;
        buf->len -= drop;

        if (buf->head >= buf->cap / 2) {
            memmove(buf->data, buf->data + buf->head, buf->len);
            buf->head = 0;
        }
    }

    buf->base = new_base;

    /* Those offsets can never come up again. */
    quicrange_trim_below(&buf->acked, new_base - 1);
    quicrange_trim_below(&buf->lost, new_base - 1);
}

int quicsendbuf_next(quicsendbuf_t* buf, size_t max_len,
                     uint64_t* out_offset, const uint8_t** out_data,
                     size_t* out_len, int* out_fin) {
    /* max_len == 0 is not "nothing to do": the end-of-stream marker is an empty
     * frame and needs no room for data at all. The send loop relies on this --
     * it lets a pending FIN past the closed-window check on purpose, and this
     * function refusing it there is a stream that can never end while the window
     * stays shut. Only the data branches below care about the budget, and each
     * one stops at `len == 0` on its own. */
    if (buf == NULL) return 0;

    uint64_t offset;
    size_t len;
    int retransmit = 0;

    /* Retransmission first: a hole in what the peer holds stalls the stream,
     * however much new data is queued behind it. */
    if (!quicrange_empty(&buf->lost)) {
        quicrange_span_t span;
        retransmit = 1;
        /* The lowest lost range -- filling the earliest hole first is what lets
         * the peer's reassembly make progress. */
        if (!quicrange_at_desc(&buf->lost, quicrange_count(&buf->lost) - 1, &span))
            return 0;

        offset = span.start;
        len = (size_t)(span.end - span.start + 1);
        if (len > max_len) len = max_len;
    }
    else if (buf->sent_off < buf->write_off) {
        offset = buf->sent_off;
        len = (size_t)(buf->write_off - buf->sent_off);
        if (len > max_len) len = max_len;
    }
    else if (buf->fin && !buf->fin_sent) {
        /* Nothing left but the end-of-stream marker, which rides on an empty
         * frame at the final offset. */
        if (out_offset != NULL) *out_offset = buf->write_off;
        if (out_data != NULL) *out_data = NULL;
        if (out_len != NULL) *out_len = 0;
        if (out_fin != NULL) *out_fin = 1;
        return 1;
    }
    else {
        return 0;
    }

    if (offset < buf->base) return 0;

    const size_t within = (size_t)(offset - buf->base);
    if (within >= buf->len) return 0;
    if (len > buf->len - within) len = buf->len - within;
    if (len == 0) return 0;

    if (out_offset != NULL) *out_offset = offset;
    if (out_data != NULL) *out_data = buf->data + buf->head + within;
    if (out_len != NULL) *out_len = len;
    /* The FIN rides along only if this chunk really reaches the end -- and only
     * on data the peer has not been sent before.
     *
     * On a retransmission it is held back deliberately, and the empty-frame
     * branch above delivers it a frame later. The reason is that loss detection
     * is a heuristic: a range declared lost is often a range the peer already
     * holds, and then the retransmission is, to the receiver, a frame whose data
     * is duplicate from the first byte to the last. Attaching the end of the
     * stream to such a frame makes the FIN only as reliable as the peer's
     * willingness to look inside a frame it has every reason to discard -- and
     * at least one implementation does not (docs/http3/08 §3t: the response
     * arrived, the file on disk was correct, and the client sat waiting for an
     * end-of-stream it had already been sent).
     *
     * The empty frame at the final offset carries no data to be duplicate, so
     * there is nothing for the peer to discard it as. The cost is one small
     * frame, and only when a tail was declared lost. */
    if (out_fin != NULL)
        *out_fin = !retransmit && buf->fin && !buf->fin_sent &&
                   offset + len == buf->write_off;

    return 1;
}

void quicsendbuf_mark_sent(quicsendbuf_t* buf, uint64_t offset, size_t len, int fin) {
    if (buf == NULL) return;

    if (len > 0) {
        quicrange_remove(&buf->lost, offset, offset + len - 1);

        if (offset + len > buf->sent_off) buf->sent_off = offset + len;
    }

    if (fin) buf->fin_sent = 1;
}

void quicsendbuf_ack(quicsendbuf_t* buf, uint64_t offset, size_t len, int fin) {
    if (buf == NULL) return;

    if (len > 0) {
        quicrange_add(&buf->acked, offset, offset + len - 1);
        /* Acknowledged data is not lost, whatever an earlier loss declaration
         * said -- a spurious one must not resend confirmed bytes. */
        quicrange_remove(&buf->lost, offset, offset + len - 1);
        __slide(buf);
    }

    if (fin) buf->fin_acked = 1;
}

void quicsendbuf_lost(quicsendbuf_t* buf, uint64_t offset, size_t len, int fin) {
    if (buf == NULL) return;

    if (len > 0 && offset + len > buf->base) {
        if (offset < buf->base) {
            len -= (size_t)(buf->base - offset);
            offset = buf->base;
        }

        /* Only what the peer has not confirmed. Loss detection is a heuristic;
         * an ACK that crossed the declaration in flight is normal. */
        for (uint64_t p = offset; p < offset + len; ) {
            if (quicrange_contains(&buf->acked, p)) { p++; continue; }

            uint64_t end = p;
            while (end + 1 < offset + len && !quicrange_contains(&buf->acked, end + 1))
                end++;

            quicrange_add(&buf->lost, p, end);
            p = end + 1;
        }
    }

    if (fin && !buf->fin_acked) buf->fin_sent = 0;
}

int quicsendbuf_pending(const quicsendbuf_t* buf) {
    if (buf == NULL) return 0;

    if (!quicrange_empty(&buf->lost)) return 1;
    if (buf->sent_off < buf->write_off) return 1;
    if (buf->fin && !buf->fin_sent) return 1;

    return 0;
}

int quicsendbuf_has_lost(const quicsendbuf_t* buf) {
    if (buf == NULL) return 0;

    return !quicrange_empty(&buf->lost);
}

int quicsendbuf_requeue_unacked(quicsendbuf_t* buf) {
    if (buf == NULL) return 0;
    if (buf->sent_off <= buf->base) return 0;

    /* The earliest unacknowledged byte, and everything unacknowledged after it
     * up to what has been sent once. quicsendbuf_lost does the walk around
     * already-acknowledged holes; this only has to find the start and hand it
     * the range. A range already queued as lost is added again harmlessly --
     * quicrange_add merges. */
    for (uint64_t p = buf->base; p < buf->sent_off; p++) {
        if (quicrange_contains(&buf->acked, p)) continue;

        quicsendbuf_lost(buf, p, (size_t)(buf->sent_off - p), 0);

        return 1;
    }

    return 0;
}

int quicsendbuf_complete(const quicsendbuf_t* buf) {
    if (buf == NULL) return 0;

    return buf->fin && buf->fin_acked && buf->base >= buf->write_off;
}

size_t quicsendbuf_inflight_bytes(const quicsendbuf_t* buf) {
    return buf == NULL ? 0 : buf->len;
}

size_t quicsendbuf_unsent_bytes(const quicsendbuf_t* buf) {
    if (buf == NULL || buf->sent_off >= buf->write_off) return 0;

    return (size_t)(buf->write_off - buf->sent_off);
}

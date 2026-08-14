#include <stdlib.h>
#include <string.h>

#include "quicrecvbuf.h"
#include "quicmemory.h"

void quicrecvbuf_init(quicrecvbuf_t* buf, size_t limit) {
    if (buf == NULL) return;

    memset(buf, 0, sizeof * buf);
    buf->limit = limit;
}

void quicrecvbuf_free(quicrecvbuf_t* buf) {
    if (buf == NULL) return;

    quicrecvseg_t* seg = buf->head;
    while (seg != NULL) {
        quicrecvseg_t* next = seg->next;
        quicmemory_release(sizeof *seg + seg->len);
        free(seg->data);
        free(seg);
        seg = next;
    }

    buf->head = NULL;
    buf->buffered = 0;
}

/* Recompute where the readable prefix ends: walk segments from the read point
 * while each one starts exactly where the previous ended. */
static void __recompute_contig(quicrecvbuf_t* buf) {
    uint64_t end = buf->read_off;

    for (quicrecvseg_t* seg = buf->head; seg != NULL; seg = seg->next) {
        if (seg->offset > end) break;
        if (seg->offset + seg->len > end) end = seg->offset + seg->len;
    }

    buf->contig_end = end;
}

/* Insert one piece known not to overlap anything already held. */
static quicrecvbuf_status_e __insert_piece(quicrecvbuf_t* buf, uint64_t offset,
                                           const uint8_t* data, size_t len) {
    if (len == 0) return QUICRECVBUF_OK;

    if (buf->limit != 0 && buf->buffered + len > buf->limit)
        return QUICRECVBUF_TOO_MUCH;

    if (!quicmemory_reserve(sizeof(quicrecvseg_t) + len))
        return QUICRECVBUF_TOO_MUCH;

    quicrecvseg_t* seg = malloc(sizeof * seg);
    if (seg == NULL) {
        quicmemory_release(sizeof(quicrecvseg_t) + len);
        return QUICRECVBUF_OOM;
    }

    seg->data = malloc(len);
    if (seg->data == NULL) {
        quicmemory_release(sizeof *seg + len);
        free(seg);
        return QUICRECVBUF_OOM;
    }

    memcpy(seg->data, data, len);
    seg->offset = offset;
    seg->len = len;

    /* Ascending by offset. The list is short in practice -- a handful of holes
     * at most -- so a linear walk beats any cleverer structure. */
    quicrecvseg_t** link = &buf->head;
    while (*link != NULL && (*link)->offset < offset)
        link = &(*link)->next;

    seg->next = *link;
    *link = seg;

    buf->buffered += len;

    return QUICRECVBUF_OK;
}

quicrecvbuf_status_e quicrecvbuf_insert(quicrecvbuf_t* buf, uint64_t offset,
                                        const uint8_t* data, size_t len, int fin) {
    if (buf == NULL) return QUICRECVBUF_OOM;

    const uint64_t end = offset + len;

    /* §4.5: no data may arrive past a final size, and a second final size must
     * agree with the first. Both are FINAL_SIZE_ERROR. */
    if (buf->fin && end > buf->final_size) return QUICRECVBUF_FINAL_SIZE;
    if (fin && buf->fin && end != buf->final_size) return QUICRECVBUF_FINAL_SIZE;
    /* A FIN cannot cut off data already received. */
    if (fin && end < buf->max_offset) return QUICRECVBUF_FINAL_SIZE;

    if (fin) {
        buf->fin = 1;
        buf->final_size = end;
    }

    if (end > buf->max_offset) buf->max_offset = end;

    if (len == 0) return QUICRECVBUF_OK;
    if (data == NULL) return QUICRECVBUF_OOM;

    /* Entirely consumed already: an ordinary retransmission. */
    if (end <= buf->read_off) return QUICRECVBUF_OK;

    /* Trim the part already read. */
    if (offset < buf->read_off) {
        const uint64_t skip = buf->read_off - offset;
        data += skip;
        len -= (size_t)skip;
        offset = buf->read_off;
    }

    /* Walk the held segments, inserting only what is not already there. A
     * retransmission that overlaps two segments and the gap between them is
     * legal, so this has to handle the general case rather than the common
     * one. */
    uint64_t cursor = offset;
    const uint8_t* p = data;

    for (quicrecvseg_t* seg = buf->head; seg != NULL && cursor < offset + len; ) {
        const uint64_t seg_end = seg->offset + seg->len;

        if (seg_end <= cursor) {
            seg = seg->next;
            continue;
        }

        if (seg->offset > cursor) {
            /* A gap before this segment: fill what fits in it. */
            uint64_t chunk = seg->offset - cursor;
            if (chunk > offset + len - cursor) chunk = offset + len - cursor;

            const quicrecvbuf_status_e st =
                __insert_piece(buf, cursor, p + (cursor - offset), (size_t)chunk);
            if (st != QUICRECVBUF_OK) return st;

            cursor += chunk;
            continue;
        }

        /* Overlapping this segment: skip past what it already holds. */
        cursor = seg_end;
        seg = seg->next;
    }

    /* Whatever is left goes past every held segment. */
    if (cursor < offset + len) {
        const quicrecvbuf_status_e st =
            __insert_piece(buf, cursor, p + (cursor - offset),
                           (size_t)(offset + len - cursor));
        if (st != QUICRECVBUF_OK) return st;
    }

    __recompute_contig(buf);

    return QUICRECVBUF_OK;
}

quicrecvbuf_status_e quicrecvbuf_set_final_size(quicrecvbuf_t* buf, uint64_t final_size) {
    if (buf == NULL) return QUICRECVBUF_OOM;

    if (buf->fin && buf->final_size != final_size) return QUICRECVBUF_FINAL_SIZE;
    /* RESET_STREAM cannot claim a size below data already received (§4.5). */
    if (final_size < buf->max_offset) return QUICRECVBUF_FINAL_SIZE;

    buf->fin = 1;
    buf->final_size = final_size;
    if (final_size > buf->max_offset) buf->max_offset = final_size;

    return QUICRECVBUF_OK;
}

size_t quicrecvbuf_readable(const quicrecvbuf_t* buf) {
    if (buf == NULL) return 0;

    return (size_t)(buf->contig_end - buf->read_off);
}

size_t quicrecvbuf_read(quicrecvbuf_t* buf, uint8_t* dst, size_t len) {
    if (buf == NULL || dst == NULL) return 0;

    size_t taken = 0;

    while (taken < len && buf->head != NULL) {
        quicrecvseg_t* seg = buf->head;

        /* Only the readable prefix; a segment past a hole is not reachable. */
        if (seg->offset > buf->read_off) break;

        const uint64_t within = buf->read_off - seg->offset;
        size_t available = seg->len - (size_t)within;
        if (available > len - taken) available = len - taken;

        memcpy(dst + taken, seg->data + within, available);
        taken += available;
        buf->read_off += available;

        if (buf->read_off >= seg->offset + seg->len) {
            buf->head = seg->next;
            buf->buffered -= seg->len;
            quicmemory_release(sizeof *seg + seg->len);
            free(seg->data);
            free(seg);
        }
    }

    if (buf->read_off > buf->contig_end) buf->contig_end = buf->read_off;

    return taken;
}

int quicrecvbuf_complete(const quicrecvbuf_t* buf) {
    if (buf == NULL) return 0;

    return buf->fin && buf->read_off >= buf->final_size;
}

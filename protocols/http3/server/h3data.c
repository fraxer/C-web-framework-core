#include "h3data.h"

#include <string.h>

#include "h3response.h"

void h3_data_writer_reset(h3_data_writer_t* w) {
    if (w == NULL) return;

    w->fin_sent = 0;
}

/* Queue one DATA frame: header then payload, both or neither.
 *
 * "Both or neither" is the whole contract. quicsendbuf_write can only fail on
 * allocation, but if the header went in and the payload did not, the stream
 * would carry a frame announcing bytes that never arrive -- and a QUIC stream
 * cannot be rewound. So the two writes are ordered header-first and a failure
 * of the second is fatal to the stream rather than retried. */
static int __write_frame(quicstream_t* qs, const uint8_t* data, size_t len) {
    uint8_t header[9];
    const size_t hlen = h3response_data_header(header, sizeof header, len);
    if (hlen == 0) return 0;

    if (!quicstream_write(qs, header, hlen)) return 0;
    if (!quicstream_write(qs, data, len)) return 0;

    return 1;
}

h3_data_status_e h3_data_write(h3_data_writer_t* w, quicconn_t* qc, quicstream_t* qs,
                               bufo_t* src, int is_last, int fin_allowed) {
    if (w == NULL || qc == NULL || qs == NULL || src == NULL) return H3_DATA_ERROR;

    for (;;) {
        const size_t remaining = src->size > src->pos ? src->size - src->pos : 0;

        if (remaining == 0) break;

        /* Budget first: the point of the check is to not have written yet. */
        const size_t room = quicconn_write_room(qc);
        if (room == 0) return H3_DATA_BLOCKED;

        size_t chunk = remaining;
        if (chunk > H3_DATA_CHUNK_MAX) chunk = H3_DATA_CHUNK_MAX;
        /* Overshooting the budget by less than a chunk is deliberate: cutting a
         * frame to fit an arbitrary budget boundary would produce a tail frame
         * of a few bytes for no reason. The budget is a threshold to stop at,
         * not a hard cap on bytes held. */
        if (chunk > room) chunk = room;

        if (!__write_frame(qs, (const uint8_t*)src->data + src->pos, chunk))
            return H3_DATA_ERROR;

        src->pos += chunk;
    }

    /* Everything this source held is queued. FIN belongs here only if the
     * source was the last one and the stream is allowed to end at all. */
    if (is_last && fin_allowed && !w->fin_sent) {
        quicstream_finish(qs);
        w->fin_sent = 1;
    }

    return H3_DATA_DRAINED;
}

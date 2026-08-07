#ifndef __QUICRECVBUF__
#define __QUICRECVBUF__

#include <stddef.h>
#include <stdint.h>

/* Reassembly of a byte stream delivered out of order (RFC 9000 §2.2).
 *
 * QUIC guarantees ordering within a stream but delivers packets in whatever
 * order the network produces, so a stream's bytes arrive with holes. This
 * holds the pieces until a contiguous prefix exists and hands only that to the
 * application -- which is the whole contract: a consumer must never see byte
 * 100 before byte 99.
 *
 * Used for stream data and, separately, for each encryption level's CRYPTO
 * stream, which has exactly the same shape.
 *
 * ## Why the buffered bytes are bounded
 *
 * A peer may legitimately send offset 5000 before offset 0. It may also send
 * one byte at offset 2^40 and nothing else. Flow control bounds the *total*
 * bytes a peer may send, but it does not bound the *span* those bytes cover, so
 * without a cap here a single small packet would ask for a terabyte. The cap is
 * on how far past the read point anything may be buffered. */

typedef struct quicrecvseg {
    uint64_t offset;
    size_t   len;
    uint8_t* data;
    struct quicrecvseg* next;
} quicrecvseg_t;

typedef struct quicrecvbuf {
    quicrecvseg_t* head;      /* ascending by offset, never overlapping */

    uint64_t read_off;        /* everything below this has been consumed */
    uint64_t contig_end;      /* end of the readable prefix */
    uint64_t max_offset;      /* highest offset+len ever seen (for final size) */

    size_t   buffered;        /* bytes held in segments */
    size_t   limit;           /* cap on `buffered`; 0 = unlimited */

    int      fin;             /* final size is known */
    uint64_t final_size;
} quicrecvbuf_t;

typedef enum {
    QUICRECVBUF_OK = 0,
    QUICRECVBUF_OOM,
    /* Past the cap on buffered bytes -- reported as FLOW_CONTROL_ERROR by the
     * caller, since that is what it protects. */
    QUICRECVBUF_TOO_MUCH,
    /* Data beyond a final size already declared, or a second, different final
     * size. FINAL_SIZE_ERROR. */
    QUICRECVBUF_FINAL_SIZE
} quicrecvbuf_status_e;

void quicrecvbuf_init(quicrecvbuf_t* buf, size_t limit);
void quicrecvbuf_free(quicrecvbuf_t* buf);

/* Insert data at `offset`. Overlaps and exact duplicates are tolerated -- a
 * retransmission is ordinary, not an error -- and only the parts not already
 * held are copied. `fin` marks this as the last data on the stream. */
quicrecvbuf_status_e quicrecvbuf_insert(quicrecvbuf_t* buf, uint64_t offset,
                                        const uint8_t* data, size_t len, int fin);

/* Declare the final size without data (RESET_STREAM). */
quicrecvbuf_status_e quicrecvbuf_set_final_size(quicrecvbuf_t* buf, uint64_t final_size);

/* Bytes readable right now: the contiguous prefix from the read point. */
size_t quicrecvbuf_readable(const quicrecvbuf_t* buf);

/* Copy up to `len` readable bytes out and advance the read point. */
size_t quicrecvbuf_read(quicrecvbuf_t* buf, uint8_t* dst, size_t len);

/* Every byte has arrived and been read. */
int quicrecvbuf_complete(const quicrecvbuf_t* buf);

#endif

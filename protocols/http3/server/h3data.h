#ifndef __H3DATA__
#define __H3DATA__

#include <stddef.h>
#include <stdint.h>

#include "bufo.h"
#include "quicconn.h"
#include "quicstream.h"

/* Cutting a byte stream into DATA frames on one QUIC stream
 * (docs/http3/05-http3.md §6.3).
 *
 * The h2 counterpart (h2data.c) exists to hold four kinds of arithmetic in one
 * place: the peer's max frame size, both flow-control windows, the scheduler's
 * write quantum, and yielding only on a frame boundary. HTTP/3 needs none of
 * them -- QUIC owns the windows, a DATA frame has no size limit, and a stream
 * is scheduled by the transport. What is left is one thing h2 did not have to
 * think about at all:
 *
 * **How far ahead of the network to run.** A TCP write stops when the socket
 * says so. quicsendbuf_write never says so -- it grows -- so the stopping point
 * has to be chosen here, against the connection's write-ahead budget
 * (QUICCONN_WRITE_AHEAD_MAX). Reaching it is reported as AGAIN and resumed when
 * the send path has drained, exactly as a saturated socket is in h1.1 and h2.
 *
 * The frames are cut at H3_DATA_CHUNK_MAX rather than written as one frame of
 * whatever length, so that a stalled response holds one chunk rather than a
 * whole file, and so the frame header is never written for a length the writer
 * may not get to finish. */

typedef enum {
    H3_DATA_DRAINED = 0,  /* the source has no bytes left */
    H3_DATA_BLOCKED,      /* the write-ahead budget is spent, on a frame boundary */
    H3_DATA_ERROR
} h3_data_status_e;

typedef struct h3_data_writer {
    /* Nothing is ever half-written: a chunk is committed to the send buffer
     * whole or not at all, so unlike h2data there is no partial frame header to
     * resume from. The flag below is the only state, and it exists because FIN
     * must be sent once. */
    int fin_sent;
} h3_data_writer_t;

void h3_data_writer_reset(h3_data_writer_t* w);

/* Push as much of `src` onto `qs` as the connection's write-ahead budget
 * allows, advancing src->pos by what was taken.
 *
 * The stream's FIN rides the moment the source is exhausted, but only when
 * `fin_allowed` agrees. Two conditions rather than one, for the same reason h2
 * needs two gates on END_STREAM: "the data has ended" and "the stream may end"
 * are different claims. A response with trailers still owes a HEADERS frame,
 * and an Extended CONNECT tunnel never ends on its response at all. */
h3_data_status_e h3_data_write(h3_data_writer_t* w, quicconn_t* qc, quicstream_t* qs,
                               bufo_t* src, int is_last, int fin_allowed);

#endif

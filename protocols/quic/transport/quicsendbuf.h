#ifndef __QUICSENDBUF__
#define __QUICSENDBUF__

#include <stddef.h>
#include <stdint.h>

#include "quicrange.h"

/* Outgoing stream data, held until acknowledged (RFC 9000 §13.3).
 *
 * ## Why this is not a FIFO
 *
 * QUIC never retransmits a packet. A packet declared lost is examined, the
 * frames it carried are put back on the send queue, and they go out in a *new*
 * packet with a new number (§13.3). That is what makes packet numbers strictly
 * increasing, which loss detection depends on entirely.
 *
 * The consequence for a send buffer is that data cannot be dropped when it is
 * sent -- only when it is acknowledged -- and that it may be needed again from
 * the middle. So the buffer keeps three views of the same bytes: written, sent,
 * and acknowledged, with lost ranges pulled back out of "sent".
 *
 * The base slides forward only as the *front* is acknowledged, so a single
 * unacknowledged byte at the start pins everything after it. That is inherent:
 * until the peer confirms it, it may have to be sent again. */

typedef struct quicsendbuf {
    uint8_t* data;
    /* Where the live bytes start inside `data`. Acknowledging the front moves
     * this rather than the data; the buffer is compacted only when the dead
     * prefix reaches half the capacity, so each byte is memmoved at most once
     * per doubling instead of once per acknowledgement. */
    size_t   head;
    size_t   len;         /* bytes held, from base */
    size_t   cap;

    uint64_t base;        /* stream offset of data[0] */
    uint64_t write_off;   /* offset one past the last byte written */
    uint64_t sent_off;    /* offset up to which everything has been sent once */

    /* Acknowledged, relative to the stream. Only used to slide the base: once
     * the front is confirmed those bytes can never be needed again. */
    quicrange_t acked;
    /* Declared lost and awaiting retransmission. Consulted before new data,
     * because a hole in the peer's view blocks everything behind it. */
    quicrange_t lost;

    int      fin;         /* the application has finished writing */
    int      fin_sent;
    int      fin_acked;
} quicsendbuf_t;

void quicsendbuf_init(quicsendbuf_t* buf);
void quicsendbuf_free(quicsendbuf_t* buf);

/* Append application data. Returns 0 only on allocation failure -- flow control
 * is the caller's business, not the buffer's. */
int quicsendbuf_write(quicsendbuf_t* buf, const uint8_t* data, size_t len);

/* Mark the stream finished; no further writes are accepted. */
void quicsendbuf_finish(quicsendbuf_t* buf);

/* What to put in the next STREAM frame.
 *
 * Prefers retransmission: a gap in what the peer holds stalls the stream
 * regardless of how much new data is queued behind it.
 *
 * `max_len` bounds the chunk (packet space, flow control, congestion window --
 * all resolved by the caller). Returns 1 when there is something to send, with
 * `out_offset`, `out_data` and `out_len` describing it and `out_fin` set when
 * this chunk carries the end of the stream. The pointer is borrowed and stays
 * valid until the next write or ack. */
int quicsendbuf_next(quicsendbuf_t* buf, size_t max_len,
                     uint64_t* out_offset, const uint8_t** out_data,
                     size_t* out_len, int* out_fin);

/* Record that [offset, offset+len) has gone out, so quicsendbuf_next moves past
 * it. Called after the packet is built, not after it is acknowledged. */
void quicsendbuf_mark_sent(quicsendbuf_t* buf, uint64_t offset, size_t len, int fin);

/* The peer has confirmed this range; the base slides if the front is covered. */
void quicsendbuf_ack(quicsendbuf_t* buf, uint64_t offset, size_t len, int fin);

/* A packet carrying this range was declared lost: queue it for retransmission.
 * Ranges already acknowledged are ignored -- a spurious loss declaration for
 * data the peer has confirmed must not resend it. */
void quicsendbuf_lost(quicsendbuf_t* buf, uint64_t offset, size_t len, int fin);

/* Anything left to send, new or retransmitted. */
int quicsendbuf_pending(const quicsendbuf_t* buf);

/* Whether the next chunk would be a retransmission. Flow control has to know:
 * resent data is not charged to the window again (§4.5), so a closed window
 * must not hold it back -- see the stream loop in quicconn.c. */
int quicsendbuf_has_lost(const quicsendbuf_t* buf);

/* Queue the earliest sent-but-unacknowledged range for retransmission, so that
 * a PTO probe carries it. Returns 1 if anything was queued.
 *
 * RFC 9002 §6.2.4: a probe SHOULD carry new data and, failing that, previously
 * sent data -- because a bare PING only asks the peer to say something, and the
 * information the peer is actually missing waits another round trip for the
 * acknowledgement to arrive and loss detection to act on it. During a handshake
 * that no acknowledgement ever reaches, that round trip never comes. */
int quicsendbuf_requeue_unacked(quicsendbuf_t* buf);

/* Everything written has been acknowledged, FIN included. */
int quicsendbuf_complete(const quicsendbuf_t* buf);

/* Bytes held but not yet acknowledged -- what the buffer is costing. */
size_t quicsendbuf_inflight_bytes(const quicsendbuf_t* buf);

/* Bytes written by the application that have not been put in a packet yet.
 *
 * This is the half of the buffer the application controls, and therefore the
 * only half worth applying back pressure to: what has been sent but not
 * acknowledged has to be held for retransmission whatever anyone wants (§13.3),
 * while the write-ahead is purely a choice about how far to run in front of the
 * network. See quicconn_write_room. */
size_t quicsendbuf_unsent_bytes(const quicsendbuf_t* buf);

#endif

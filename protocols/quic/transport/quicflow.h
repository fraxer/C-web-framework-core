#ifndef __QUICFLOW__
#define __QUICFLOW__

#include <stddef.h>
#include <stdint.h>

/* Flow control (RFC 9000 §4).
 *
 * Two independent limits apply to every byte of stream data: one for the stream
 * and one for the connection. Both must permit it. The connection-level limit
 * is what stops a peer from opening a thousand streams and using each one's
 * full window; the stream-level limit is what stops one slow consumer from
 * consuming the whole connection's allowance.
 *
 * Distinct from congestion control, which is often confused with it: congestion
 * control asks what the *network* can carry, flow control asks what the
 * *receiver* is willing to buffer. A connection can be blocked by either.
 *
 * The same struct serves both directions. On the receive side `limit` is what
 * we have advertised and `used` is what the peer has sent; on the send side
 * `limit` is what the peer allowed and `used` is what we have sent. */

typedef struct quicflow {
    uint64_t limit;
    uint64_t used;

    /* Receive side only. Bytes the application has actually taken delivery of,
     * plus those a reset or a torn-down stream means it never will.
     *
     * This -- not `used` -- is what the advertised limit is built on. The two
     * differ by exactly what is sitting in the receive buffers, and building
     * the limit on `used` made the credit slide forward on *arrival*: a peer
     * always had a full window ahead of the highest offset it had reached,
     * whatever the application had managed to read. The buffer cap then had to
     * be the real limit, and hitting it reports FLOW_CONTROL_ERROR -- blaming
     * the peer for staying inside a window we should not have granted. */
    uint64_t consumed;

    /* The window is raised when more than half of it has been consumed -- more
     * often is wasted frames, less often stalls the peer for a round trip while
     * it waits for credit it has already earned. */
    uint64_t auto_window;
    uint64_t max_window;

    /* A *_BLOCKED frame has been sent for this limit. Sending one per blocked
     * packet would be a flood; the peer only needs telling once that we are
     * stuck at a particular value. */
    uint64_t blocked_at;
    int      blocked_sent;
} quicflow_t;

/* Send side: `limit` is the peer's advertised maximum. */
void quicflow_init_send(quicflow_t* flow, uint64_t limit);

/* Receive side: `initial` is what we advertise, `max_window` how far the
 * auto-tuner may grow it. Equal values pin the window. */
void quicflow_init_recv(quicflow_t* flow, uint64_t initial, uint64_t max_window);

/* ---- Send side ---- */

/* Bytes that may be sent right now. */
uint64_t quicflow_available(const quicflow_t* flow);

/* Account for bytes about to be sent. */
void quicflow_consume(quicflow_t* flow, uint64_t bytes);

/* Account for a stream reaching `end`, its highest offset sent.
 *
 * §4.1 puts the limit on the offset, not on the traffic: retransmitted data
 * reoccupies offsets it has already paid for, and charging it again spends a
 * window the peer never saw used. The receive side has always counted this way
 * (quicflow_record_received); the send side counted bytes, and on a lossy path
 * that is a window that shrinks with every loss until the transfer stops with
 * data still to send and no timer left to wake it.
 *
 * Returns how far the offset advanced -- which is exactly what the
 * connection-level window must be charged as well. */
uint64_t quicflow_consume_to(quicflow_t* flow, uint64_t end);

/* The peer raised the limit (MAX_DATA / MAX_STREAM_DATA). A limit that does not
 * grow is ignored: §4.1 requires limits to be monotonic, and a reordered frame
 * carrying an older value must not shrink the window. Returns 1 if it grew. */
int quicflow_update_limit(quicflow_t* flow, uint64_t limit);

/* We are blocked and should say so once. Returns 1 the first time for a given
 * limit, 0 afterwards. */
int quicflow_should_send_blocked(quicflow_t* flow);

/* ---- Receive side ---- */

/* The peer sent `bytes` more. Returns 0 if that exceeds what we advertised,
 * which is a FLOW_CONTROL_ERROR: the peer ignored a limit it agreed to. */
int quicflow_record_received(quicflow_t* flow, uint64_t highest_offset);

/* The application consumed `bytes`, freeing buffer space.
 *
 * `rtt_us` and `elapsed_us` drive the auto-tuner: a window that is exhausted
 * faster than a round trip is too small for the path, and grows. This is the
 * same idea as the HTTP/2 receive window scaling already in the codebase. */
void quicflow_consumed(quicflow_t* flow, uint64_t bytes,
                       uint64_t rtt_us, uint64_t elapsed_us);

/* Bytes charged to this window that will never be delivered: the tail a
 * RESET_STREAM abandoned, or whatever a stream still held when it was torn
 * down. They free no buffer, but they are equally never coming back, so the
 * credit they occupy has to be returned or the window shrinks by the abandoned
 * remainder of every cancelled stream -- permanently. Returns what it added, so
 * a caller can pass the same amount up to the connection-level window. */
uint64_t quicflow_abandon(quicflow_t* flow, uint64_t upto);

/* Whether a MAX_DATA / MAX_STREAM_DATA frame is worth sending, and what limit
 * it should carry. */
int quicflow_should_update(const quicflow_t* flow, uint64_t* out_limit);

/* Record that the new limit has gone out. */
void quicflow_update_sent(quicflow_t* flow, uint64_t limit);

#endif

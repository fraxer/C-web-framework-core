#ifndef __QUICCC__
#define __QUICCC__

#include <stddef.h>
#include <stdint.h>

/* Congestion control (RFC 9002 §7).
 *
 * NewReno, which the RFC specifies directly and which is the sensible starting
 * point: it is simple enough to get right, and being wrong here does not look
 * like a bug -- it looks like a slow network.
 *
 * Behind a vtable so CUBIC or BBR can be added in phase 9 without touching loss
 * detection, which is the module that would otherwise have to know which
 * controller it is driving. */

/* §7.2. The initial window is 10 packets, bounded to at least 14720 bytes and
 * at most... in practice 10 * max_datagram_size. */
#define QUICCC_INITIAL_WINDOW_PACKETS 10
#define QUICCC_INITIAL_WINDOW_MAX     14720
#define QUICCC_MIN_WINDOW_PACKETS     2
#define QUICCC_LOSS_REDUCTION_NUM     1
#define QUICCC_LOSS_REDUCTION_DEN     2
/* §7.6: a span of this many PTOs with everything lost means the path is gone,
 * not merely congested. */
#define QUICCC_PERSISTENT_CONGESTION_THRESHOLD 3

typedef struct quiccc quiccc_t;

typedef struct quiccc_ops {
    void   (*on_sent)(quiccc_t*, size_t bytes);
    void   (*on_ack)(quiccc_t*, size_t bytes, uint64_t sent_us, uint64_t now_us);
    void   (*on_loss)(quiccc_t*, size_t bytes, uint64_t sent_us, uint64_t now_us);
    /* Everything in a span longer than the persistent congestion threshold was
     * lost: collapse to the minimum window and start over. */
    void   (*on_persistent_congestion)(quiccc_t*);
    /* A PTO fired without the peer having validated the path; §7.5 requires
     * leaving slow start alone in that case, so this is separate from a loss. */
    void   (*on_pto)(quiccc_t*);
} quiccc_ops_t;

struct quiccc {
    const quiccc_ops_t* ops;

    size_t   max_datagram_size;
    uint64_t cwnd;
    uint64_t bytes_in_flight;
    uint64_t ssthresh;          /* UINT64_MAX while in slow start */

    /* Recovery period: everything sent before this time belongs to the loss
     * that started it, so one burst of losses halves the window once rather
     * than once per packet (§7.3.2). */
    uint64_t recovery_start_us;

    /* Carry for the congestion-avoidance division: cwnd grows by roughly one
     * datagram per window of acknowledged bytes, and dropping the remainder
     * each time would stall growth on small windows. */
    uint64_t ack_carry;
};

void quiccc_init(quiccc_t* cc, size_t max_datagram_size);

/* NewReno, the only controller in v1. */
extern const quiccc_ops_t quiccc_newreno;

/* How many more bytes may be put in flight right now. */
size_t quiccc_available(const quiccc_t* cc);

int quiccc_in_slow_start(const quiccc_t* cc);
int quiccc_in_recovery(const quiccc_t* cc, uint64_t sent_us);

/* ---- Pacing (§7.7) ----
 *
 * Without it a controller hands its whole window to the network at once, and
 * the burst is absorbed by whichever queue is smallest -- which shows up as
 * loss the controller then reacts to, in a loop it created itself.
 *
 * A token bucket refilled from the send rate, with the burst capped so that a
 * connection that has been idle does not resume by dumping a full window. */
typedef struct quicpacer {
    uint64_t tokens;         /* bytes that may be sent now */
    uint64_t last_us;
    uint64_t burst_limit;
    int      enabled;
} quicpacer_t;

void quicpacer_init(quicpacer_t* pacer, size_t max_datagram_size, int enabled);

/* Bytes the pacer permits at `now_us`, given the window and RTT. Returns 0 when
 * the caller must wait; quicpacer_next_time_us says until when. */
size_t quicpacer_allowance(quicpacer_t* pacer, const quiccc_t* cc,
                           uint64_t smoothed_rtt_us, uint64_t now_us);

void quicpacer_consume(quicpacer_t* pacer, size_t bytes);

/* When the pacer will next allow a full datagram, or 0 if it already does. */
uint64_t quicpacer_next_time_us(const quicpacer_t* pacer, const quiccc_t* cc,
                                uint64_t smoothed_rtt_us, uint64_t now_us);

#endif

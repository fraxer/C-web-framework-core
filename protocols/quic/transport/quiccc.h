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
 * Behind a vtable so CUBIC and BBR can be added without touching loss
 * detection, which is the module that would otherwise have to know which
 * controller it is driving. That held for CUBIC, which reacts to the same three
 * events NewReno does. BBR needed one thing more: it is not driven by losses at
 * all but by a measured delivery rate, and only the module that owns the record
 * of sent packets can measure one. Hence quiccc_sample_t and the `on_ack_end`
 * entry point -- loss detection still knows nothing about which controller it
 * drives, it just hands over what it saw. */

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

typedef enum {
    QUICCC_NEWRENO = 0,
    QUICCC_CUBIC,
    QUICCC_BBR
} quiccc_algorithm_e;

/* One delivery-rate sample, drawn once per acknowledgement by loss detection
 * (draft-cheng-iccrg-delivery-rate-estimation).
 *
 * The rate is bytes actually delivered over the interval they took to be
 * delivered -- not bytes sent over time, which measures the sender's own
 * scheduling, and not the congestion window, which measures a guess. */
typedef struct quiccc_sample {
    uint64_t delivery_rate;    /* bytes/s; 0 when the sample is unusable */
    uint64_t delivered;        /* bytes delivered on this connection, cumulative */
    uint64_t prior_delivered;  /* `delivered` when the sampled packet was sent */
    uint64_t acked_bytes;      /* newly acknowledged by this acknowledgement */
    uint64_t lost_bytes;       /* declared lost while processing it */
    uint64_t prior_in_flight;  /* bytes in flight before it was processed */
    uint64_t rtt_us;           /* the round-trip sample it produced, 0 if none */
    /* The sender ran out of data rather than out of window while this sample
     * was in flight, so the rate it reports is the application's, not the
     * path's, and must never lower the bandwidth estimate. */
    int      app_limited;
} quiccc_sample_t;

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
    /* One acknowledgement has been processed in full, with everything it said.
     * Window-based controllers have nothing left to do here; a rate-based one
     * does all of its work here, because a per-packet callback cannot see the
     * interval a rate is measured over. */
    void   (*on_ack_end)(quiccc_t*, const quiccc_sample_t* sample, uint64_t now_us);
} quiccc_ops_t;

/* ---- BBR (draft-cardwell-iccrg-bbr-congestion-control) ----
 *
 * Gains are held as 1/256ths so the whole controller stays in integers: this
 * runs on every acknowledgement, and floating point on the transport hot path
 * is a cost paid forever for arithmetic that does not need it. */
#define QUICBBR_GAIN_UNIT 256
/* 2/ln(2), the rate at which STARTUP must send to double the delivery rate
 * every round trip. */
#define QUICBBR_HIGH_GAIN 739
/* 1/high_gain: DRAIN empties the queue STARTUP built, in about the time it
 * took to build it. */
#define QUICBBR_DRAIN_GAIN 89
#define QUICBBR_CWND_GAIN  (2 * QUICBBR_GAIN_UNIT)
/* The bandwidth filter forgets a maximum after this many round trips, which is
 * what lets the estimate fall when the path gets slower. */
#define QUICBBR_BW_WINDOW_ROUNDS 10
/* §4.3.2: min_rtt is re-measured at least this often, because a standing queue
 * hides the true propagation delay for as long as it stands. */
#define QUICBBR_RTPROP_WINDOW_US    10000000
#define QUICBBR_PROBE_RTT_DURATION_US 200000
#define QUICBBR_MIN_PIPE_CWND_PACKETS 4
/* STARTUP is over when three rounds in a row fail to raise the delivery rate
 * by 25%: the pipe is full and everything further goes into a queue. */
#define QUICBBR_FULL_BW_THRESHOLD_NUM 5
#define QUICBBR_FULL_BW_THRESHOLD_DEN 4
#define QUICBBR_FULL_BW_COUNT 3
#define QUICBBR_CYCLE_LEN 8

typedef enum {
    QUICBBR_STARTUP = 0,
    QUICBBR_DRAIN,
    QUICBBR_PROBE_BW,
    QUICBBR_PROBE_RTT
} quiccc_bbr_state_e;

typedef struct quiccc_bw_entry {
    uint64_t round;
    uint64_t rate;
} quiccc_bw_entry_t;

typedef struct quiccc_bbr {
    quiccc_bbr_state_e state;

    /* Windowed maximum of the delivery rate. Three entries are enough to keep
     * a running maximum over a sliding window without storing every sample:
     * the current maximum and the best candidates from the two sub-windows
     * behind it (the same structure Linux's tcp_bbr uses). */
    quiccc_bw_entry_t bw[3];
    uint64_t btlbw;              /* bytes/s; 0 until the first usable sample */

    uint64_t rtprop_us;          /* UINT64_MAX until the first RTT sample */
    uint64_t rtprop_stamp_us;
    int      rtprop_expired;

    uint64_t round_count;
    uint64_t next_round_delivered;
    int      round_start;

    uint64_t full_bw;
    int      full_bw_count;
    int      filled_pipe;

    uint64_t pacing_gain;        /* 1/256ths */
    uint64_t cwnd_gain;

    int      cycle_index;
    uint64_t cycle_stamp_us;

    uint64_t probe_rtt_done_us;
    int      probe_rtt_round_done;
    uint64_t prior_cwnd;         /* saved across PROBE_RTT and recovery */

    /* Packet conservation (§4.2.4): for one round after a loss the sender may
     * put no more in flight than what leaves it, whatever the model says. */
    int      packet_conservation;

    /* The window the connection opened with. It stands in for the model until
     * a rate has been measured, and it is the point past which a sender is no
     * longer merely starting up. */
    uint64_t initial_cwnd;
} quiccc_bbr_t;

struct quiccc {
    const quiccc_ops_t* ops;
    quiccc_algorithm_e  algorithm;

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

    /* CUBIC (RFC 9438). Windows are kept in bytes; time is microseconds. */
    uint64_t cubic_w_max;
    uint64_t cubic_epoch_start_us;
    uint64_t cubic_k_ms;
    uint64_t cubic_rtt_us;

    /* The rate the pacer must send at, in bytes per second, or 0 when the
     * controller does not name one and §7.7's cwnd/RTT formula applies. For a
     * window-based controller the pacer is a smoothing device over a decision
     * the window already made; for BBR it is the decision, and the window is
     * only the bound that keeps a wrong rate from filling the path. */
    uint64_t pacing_rate;

    quiccc_bbr_t bbr;
};

void quiccc_init(quiccc_t* cc, size_t max_datagram_size);

/* Same, with a non-default initial window in datagrams. RFC 9002 §7.2 has ten
 * and caps the bytes at 14720; a server on a long-RTT path may knowingly open
 * wider -- the same reasoning an operator tunes TCP's initcwnd -- and the
 * deviation is the operator's, logged where the config is read. The §7.2 byte
 * cap only applies to the RFC default: it exists to keep TEN packets from
 * growing with the datagram size, not to overrule a deliberate choice. */
void quiccc_init_packets(quiccc_t* cc, size_t max_datagram_size, uint64_t packets);
void quiccc_init_algorithm(quiccc_t* cc, size_t max_datagram_size,
                           uint64_t packets, quiccc_algorithm_e algorithm);

extern const quiccc_ops_t quiccc_newreno;
extern const quiccc_ops_t quiccc_cubic;
extern const quiccc_ops_t quiccc_bbr;

/* Which of them is running, for diagnostics and for the callers that must know
 * a rate-based controller needs its pacer. */
quiccc_algorithm_e quiccc_algorithm(const quiccc_t* cc);

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

/* The burst limit is the controller's *initial* window, which is why this takes
 * the controller and must be called right after it is initialised. §7.2 defines
 * the initial window as precisely the burst a sender may open a path with, and
 * §7.7 recommends no larger burst later on -- so a connection sends its opening
 * flight exactly as it would with no pacer at all, an operator who raised
 * http3_initcwnd_packets gets the burst they asked for, and every later release
 * of a grown window is spread instead of dumped. That last case is the one that
 * matters in steady state: a single cumulative acknowledgement can free a
 * window many times the initial one. */
void quicpacer_init(quicpacer_t* pacer, const quiccc_t* cc, int enabled);

/* Bytes the pacer permits at `now_us`, given the window and RTT. Returns 0 when
 * the caller must wait; quicpacer_next_time_us says until when.
 *
 * `smoothed_rtt_us` is only consulted when the controller names no rate of its
 * own: a controller that sets cc->pacing_rate has already decided, and deriving
 * a second rate from its window would overrule it. */
size_t quicpacer_allowance(quicpacer_t* pacer, const quiccc_t* cc,
                           uint64_t smoothed_rtt_us, uint64_t now_us);

void quicpacer_consume(quicpacer_t* pacer, size_t bytes);

/* When the pacer will next allow a full datagram, or 0 if it already does. */
uint64_t quicpacer_next_time_us(const quicpacer_t* pacer, const quiccc_t* cc,
                                uint64_t smoothed_rtt_us, uint64_t now_us);

#endif

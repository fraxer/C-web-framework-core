#include <string.h>

#include "quiccc.h"

static uint64_t __min_window(const quiccc_t* cc) {
    return (uint64_t)QUICCC_MIN_WINDOW_PACKETS * cc->max_datagram_size;
}

void quiccc_init(quiccc_t* cc, size_t max_datagram_size) {
    quiccc_init_packets(cc, max_datagram_size, QUICCC_INITIAL_WINDOW_PACKETS);
}

void quiccc_init_packets(quiccc_t* cc, size_t max_datagram_size, uint64_t packets) {
    quiccc_init_algorithm(cc, max_datagram_size, packets, QUICCC_NEWRENO);
}

static void __bbr_init(quiccc_t* cc);

void quiccc_init_algorithm(quiccc_t* cc, size_t max_datagram_size,
                           uint64_t packets, quiccc_algorithm_e algorithm) {
    if (cc == NULL) return;

    memset(cc, 0, sizeof * cc);

    switch (algorithm) {
        case QUICCC_CUBIC: cc->ops = &quiccc_cubic; break;
        case QUICCC_BBR:   cc->ops = &quiccc_bbr; break;
        default:           cc->ops = &quiccc_newreno; algorithm = QUICCC_NEWRENO; break;
    }

    cc->algorithm = algorithm;
    cc->max_datagram_size = max_datagram_size;

    uint64_t initial = packets * max_datagram_size;

    /* §7.2: ten datagrams, but not more than 14720 bytes -- the cap is what
     * keeps a large-MTU path from opening with an unreasonably large burst.
     * See the header: a non-default packet count is a deliberate operator
     * choice and is not second-guessed here. */
    if (packets == QUICCC_INITIAL_WINDOW_PACKETS && initial > QUICCC_INITIAL_WINDOW_MAX)
        initial = QUICCC_INITIAL_WINDOW_MAX;

    const uint64_t floor = __min_window(cc);
    if (initial < floor) initial = floor;

    cc->cwnd = initial;
    cc->ssthresh = UINT64_MAX;   /* slow start */

    if (algorithm == QUICCC_BBR) __bbr_init(cc);
}

quiccc_algorithm_e quiccc_algorithm(const quiccc_t* cc) {
    return cc == NULL ? QUICCC_NEWRENO : cc->algorithm;
}

int quiccc_in_slow_start(const quiccc_t* cc) {
    if (cc == NULL) return 0;

    /* BBR has no ssthresh at all -- it never halves anything -- so the
     * window-based test would call it "slow start" forever. Its STARTUP is the
     * same idea by a different mechanism, and that is what callers are asking
     * about. */
    if (cc->algorithm == QUICCC_BBR) return cc->bbr.state == QUICBBR_STARTUP;

    return cc->cwnd < cc->ssthresh;
}

int quiccc_in_recovery(const quiccc_t* cc, uint64_t sent_us) {
    /* A packet sent before the recovery period began belongs to the loss that
     * started it. Without this test one burst of losses would halve the window
     * once per packet rather than once (§7.3.2). */
    return cc != NULL && cc->recovery_start_us != 0 && sent_us <= cc->recovery_start_us;
}

size_t quiccc_available(const quiccc_t* cc) {
    if (cc == NULL) return 0;
    if (cc->bytes_in_flight >= cc->cwnd) return 0;

    return (size_t)(cc->cwnd - cc->bytes_in_flight);
}

static void __newreno_on_sent(quiccc_t* cc, size_t bytes) {
    cc->bytes_in_flight += bytes;
}

static void __newreno_on_ack(quiccc_t* cc, size_t bytes, uint64_t sent_us,
                             uint64_t now_us) {
    (void)now_us;

    if (cc->bytes_in_flight >= bytes) cc->bytes_in_flight -= bytes;
    else cc->bytes_in_flight = 0;

    /* §7.3.2: an acknowledgement for a packet sent before the current recovery
     * period says nothing new -- the window was already reduced for it. */
    if (quiccc_in_recovery(cc, sent_us)) return;

    if (cc->cwnd < cc->ssthresh) {
        /* Slow start: one for one, so the window doubles every round trip. */
        cc->cwnd += bytes;
        return;
    }

    /* Congestion avoidance (§7.3.3): cwnd grows by max_datagram_size per window
     * of acknowledged bytes, i.e. by max_datagram_size * bytes / cwnd for each
     * acknowledgement.
     *
     * That division truncates to zero whenever bytes < cwnd / max_datagram_size,
     * which is almost always -- so the remainder is accumulated instead of
     * dropped. Discarding it would leave the window frozen on any path where
     * acknowledgements are smaller than the window divided by the datagram
     * size, which is the normal case. */
    cc->ack_carry += (uint64_t)bytes * cc->max_datagram_size;

    const uint64_t growth = cc->ack_carry / cc->cwnd;
    if (growth > 0) {
        cc->ack_carry -= growth * cc->cwnd;
        cc->cwnd += growth;
    }
}

static void __newreno_on_loss(quiccc_t* cc, size_t bytes, uint64_t sent_us,
                              uint64_t now_us) {
    if (cc->bytes_in_flight >= bytes) cc->bytes_in_flight -= bytes;
    else cc->bytes_in_flight = 0;

    /* Already reacted to this congestion event. */
    if (quiccc_in_recovery(cc, sent_us)) return;

    cc->recovery_start_us = now_us;

    cc->ssthresh = cc->cwnd * QUICCC_LOSS_REDUCTION_NUM / QUICCC_LOSS_REDUCTION_DEN;
    cc->cwnd = cc->ssthresh;

    const uint64_t floor = __min_window(cc);
    if (cc->cwnd < floor) cc->cwnd = floor;
    if (cc->ssthresh < floor) cc->ssthresh = floor;

    cc->ack_carry = 0;
}

static void __newreno_on_persistent_congestion(quiccc_t* cc) {
    /* §7.6: not congestion but a path that stopped working. Halving would take
     * many round trips to find that out; collapsing and starting slow start
     * again finds it in one. */
    cc->cwnd = __min_window(cc);
    cc->ssthresh = UINT64_MAX;
    cc->recovery_start_us = 0;
    cc->ack_carry = 0;
}

static void __newreno_on_pto(quiccc_t* cc) {
    /* A probe is allowed past the congestion window (§7.5): its whole purpose
     * is to elicit an acknowledgement when the window is blocked, and refusing
     * to send it would deadlock the connection. Nothing to adjust. */
    (void)cc;
}

/* A window-based controller has already done everything an acknowledgement can
 * tell it, one packet at a time. */
static void __window_on_ack_end(quiccc_t* cc, const quiccc_sample_t* sample,
                                uint64_t now_us) {
    (void)cc; (void)sample; (void)now_us;
}

const quiccc_ops_t quiccc_newreno = {
    .on_sent = __newreno_on_sent,
    .on_ack = __newreno_on_ack,
    .on_loss = __newreno_on_loss,
    .on_persistent_congestion = __newreno_on_persistent_congestion,
    .on_pto = __newreno_on_pto,
    .on_ack_end = __window_on_ack_end
};

/* ---- CUBIC (RFC 9438) ----
 * Integer arithmetic is intentional: congestion control runs for every ACK and
 * must not pull floating point into the transport hot path. */
#define CUBIC_BETA_NUM 7
#define CUBIC_BETA_DEN 10

__extension__ typedef __int128 cubic_i128_t;
__extension__ typedef unsigned __int128 cubic_u128_t;

static uint64_t __cubic_root(uint64_t n) {
    uint64_t lo = 0, hi = 1;
    while ((cubic_u128_t)hi * hi * hi <= n && hi < (1ULL << 22)) hi <<= 1;
    while (lo + 1 < hi) {
        const uint64_t mid = lo + (hi - lo) / 2;
        if ((cubic_u128_t)mid * mid * mid <= n) lo = mid;
        else hi = mid;
    }
    return lo;
}

static uint64_t __cubic_k_ms(const quiccc_t* cc, uint64_t w_max) {
    /* K^3 = W_max * (1-beta) / C; C=0.4 packets/s^3. */
    const uint64_t packets = w_max / cc->max_datagram_size;
    return __cubic_root((uint64_t)((cubic_u128_t)packets * 3 * 1000000000ULL / 4));
}

static uint64_t __cubic_window(const quiccc_t* cc, uint64_t elapsed_us) {
    const int64_t x = (int64_t)(elapsed_us / 1000) - (int64_t)cc->cubic_k_ms;
    const cubic_i128_t cube = (cubic_i128_t)x * x * x;
    /* C*x^3 packets, with x in ms: 0.4 / 10^9 = 2 / 5e9. */
    const cubic_i128_t delta = (cubic_i128_t)cc->max_datagram_size * 2 * cube /
                               5000000000LL;
    const cubic_i128_t result = (cubic_i128_t)cc->cubic_w_max + delta;
    return result > 0 ? (uint64_t)result : __min_window(cc);
}

static void __cubic_on_sent(quiccc_t* cc, size_t bytes) {
    cc->bytes_in_flight += bytes;
}

static void __cubic_on_ack(quiccc_t* cc, size_t bytes, uint64_t sent_us,
                           uint64_t now_us) {
    if (cc->bytes_in_flight >= bytes) cc->bytes_in_flight -= bytes;
    else cc->bytes_in_flight = 0;
    if (quiccc_in_recovery(cc, sent_us)) return;

    const uint64_t sample = now_us > sent_us ? now_us - sent_us : 0;
    if (sample && (!cc->cubic_rtt_us || sample < cc->cubic_rtt_us))
        cc->cubic_rtt_us = sample;

    if (cc->cwnd < cc->ssthresh) {
        cc->cwnd += bytes;
        return;
    }
    if (!cc->cubic_epoch_start_us) cc->cubic_epoch_start_us = now_us;

    const uint64_t elapsed = now_us - cc->cubic_epoch_start_us;
    uint64_t target = __cubic_window(cc, elapsed + cc->cubic_rtt_us);

    /* TCP-friendly estimate, alpha = 3(1-beta)/(1+beta) = 9/17. */
    if (cc->cubic_rtt_us) {
        const uint64_t base = cc->cubic_w_max * CUBIC_BETA_NUM / CUBIC_BETA_DEN;
        const uint64_t rounds = elapsed / cc->cubic_rtt_us;
        const uint64_t friendly = base + rounds * cc->max_datagram_size * 9 / 17;
        if (friendly > target) target = friendly;
    }

    if (target > cc->cwnd) {
        cc->ack_carry += (uint64_t)bytes * (target - cc->cwnd);
        const uint64_t growth = cc->ack_carry / cc->cwnd;
        cc->ack_carry -= growth * cc->cwnd;
        cc->cwnd += growth;
    }
}

static void __cubic_on_loss(quiccc_t* cc, size_t bytes, uint64_t sent_us,
                            uint64_t now_us) {
    if (cc->bytes_in_flight >= bytes) cc->bytes_in_flight -= bytes;
    else cc->bytes_in_flight = 0;
    if (quiccc_in_recovery(cc, sent_us)) return;

    cc->recovery_start_us = now_us;
    /* RFC 9438 fast convergence when the previous maximum was not reached. */
    if (cc->cubic_w_max && cc->cwnd < cc->cubic_w_max)
        cc->cubic_w_max = cc->cwnd * (CUBIC_BETA_DEN + CUBIC_BETA_NUM) /
                          (2 * CUBIC_BETA_DEN);
    else
        cc->cubic_w_max = cc->cwnd;

    cc->cwnd = cc->cwnd * CUBIC_BETA_NUM / CUBIC_BETA_DEN;
    const uint64_t floor = __min_window(cc);
    if (cc->cwnd < floor) cc->cwnd = floor;
    cc->ssthresh = cc->cwnd;
    cc->cubic_k_ms = __cubic_k_ms(cc, cc->cubic_w_max);
    cc->cubic_epoch_start_us = 0;
    cc->ack_carry = 0;
}

static void __cubic_on_persistent_congestion(quiccc_t* cc) {
    cc->cwnd = __min_window(cc);
    cc->ssthresh = UINT64_MAX;
    cc->recovery_start_us = 0;
    cc->cubic_w_max = 0;
    cc->cubic_epoch_start_us = 0;
    cc->cubic_k_ms = 0;
    cc->ack_carry = 0;
}

static void __cubic_on_pto(quiccc_t* cc) { (void)cc; }

const quiccc_ops_t quiccc_cubic = {
    .on_sent = __cubic_on_sent,
    .on_ack = __cubic_on_ack,
    .on_loss = __cubic_on_loss,
    .on_persistent_congestion = __cubic_on_persistent_congestion,
    .on_pto = __cubic_on_pto,
    .on_ack_end = __window_on_ack_end
};

/* ---- BBR (draft-cardwell-iccrg-bbr-congestion-control) ----
 *
 * The window-based controllers above answer one question: how much may be in
 * flight. BBR answers a different one -- how fast may bytes leave -- and treats
 * the window only as the bound that keeps a mistaken rate from filling the
 * path. That is why it needs the pacer to be its output rather than a smoothing
 * device, and why it needs a measured delivery rate rather than a loss signal.
 *
 * It keeps two estimates and probes for each in turn: the bottleneck bandwidth
 * (the maximum delivery rate seen recently, because the maximum is the one
 * figure a queue cannot inflate) and the round-trip propagation delay (the
 * minimum RTT seen recently, because the minimum is the one figure a queue
 * cannot inflate either). Their product is the bytes the path holds; anything
 * beyond it is queue, and queue is the thing loss-based controllers must build
 * before they can react.
 *
 * Integers throughout, gains in 1/256ths -- see the header. */

static void __bbr_enter_startup(quiccc_t* cc) {
    cc->bbr.state = QUICBBR_STARTUP;
    cc->bbr.pacing_gain = QUICBBR_HIGH_GAIN;
    cc->bbr.cwnd_gain = QUICBBR_HIGH_GAIN;
}

static void __bbr_init(quiccc_t* cc) {
    quiccc_bbr_t* b = &cc->bbr;

    memset(b, 0, sizeof * b);

    b->rtprop_us = UINT64_MAX;      /* no sample yet, not "instant path" */
    b->initial_cwnd = cc->cwnd;
    b->prior_cwnd = cc->cwnd;
    b->next_round_delivered = 0;

    __bbr_enter_startup(cc);

    /* Left at zero deliberately: until one round trip has been timed there is
     * nothing to derive a rate from, and the pacer falls back to §7.7 -- which
     * for an opening flight is exactly the behaviour BBR wants anyway. */
    cc->pacing_rate = 0;
}

static uint64_t __bbr_min_pipe_cwnd(const quiccc_t* cc) {
    return (uint64_t)QUICBBR_MIN_PIPE_CWND_PACKETS * cc->max_datagram_size;
}

/* A running maximum over a sliding window of round trips, held in three
 * entries: the current maximum, and the best candidates from the two
 * sub-windows behind it. Storing every sample would be exact and pointless --
 * the estimate only has to survive until a larger one replaces it or the window
 * slides past it, and three entries guarantee both. */
static uint64_t __bbr_bw_filter(quiccc_bbr_t* b, uint64_t rate, uint64_t round) {
    const quiccc_bw_entry_t sample = { .round = round, .rate = rate };

    /* A new maximum, or nothing left inside the window: the filter is this
     * sample and nothing else. */
    if (b->bw[0].rate == 0 || rate >= b->bw[0].rate ||
        round - b->bw[2].round > QUICBBR_BW_WINDOW_ROUNDS) {
        b->bw[0] = b->bw[1] = b->bw[2] = sample;
        return b->bw[0].rate;
    }

    if (rate >= b->bw[1].rate) b->bw[1] = b->bw[2] = sample;
    else if (rate >= b->bw[2].rate) b->bw[2] = sample;

    const uint64_t age = round - b->bw[0].round;

    /* The leading entry aged out: promote the sub-window candidates. This is
     * the step that lets the estimate *fall*, which is the whole reason the
     * filter is windowed -- a maximum that only ever rises would keep sending
     * at a rate the path stopped supporting minutes ago. */
    if (age > QUICBBR_BW_WINDOW_ROUNDS) {
        b->bw[0] = b->bw[1];
        b->bw[1] = b->bw[2];
        b->bw[2] = sample;

        if (round - b->bw[0].round > QUICBBR_BW_WINDOW_ROUNDS) {
            b->bw[0] = b->bw[1];
            b->bw[1] = b->bw[2];
        }
    }
    /* The candidates have to age too. Without these two the sub-windows keep
     * whatever entry the maximum was set from, and when the maximum finally
     * expires it is replaced by something just as stale -- the estimate then
     * falls in one step from a value ten rounds old to a value nine rounds old.
     * Each candidate takes over its quarter and half of the window. */
    else if (b->bw[1].round == b->bw[0].round && age > QUICBBR_BW_WINDOW_ROUNDS / 4)
        b->bw[1] = b->bw[2] = sample;
    else if (b->bw[2].round == b->bw[1].round && age > QUICBBR_BW_WINDOW_ROUNDS / 2)
        b->bw[2] = sample;

    return b->bw[0].rate;
}

/* Bytes the path holds at this gain: bandwidth * delay, plus a few datagrams so
 * that a sender whose window rounds down cannot stall itself. */
static uint64_t __bbr_inflight(const quiccc_t* cc, uint64_t gain) {
    const quiccc_bbr_t* b = &cc->bbr;

    if (b->btlbw == 0 || b->rtprop_us == UINT64_MAX) return b->initial_cwnd;

    const uint64_t bdp = b->btlbw * b->rtprop_us / 1000000ULL;
    const uint64_t quanta = 3 * (uint64_t)cc->max_datagram_size;

    return bdp * gain / QUICBBR_GAIN_UNIT + quanta;
}

/* A round trip has passed when an acknowledgement arrives for something sent
 * after the previous round began. Rounds, not microseconds, are BBR's clock for
 * everything that has to happen "once per RTT" on a path whose RTT is itself
 * one of the unknowns. */
static void __bbr_update_round(quiccc_t* cc, const quiccc_sample_t* s) {
    quiccc_bbr_t* b = &cc->bbr;

    /* An acknowledgement that delivered nothing -- one that only declared
     * losses -- carries no send-order information, and its zeroed
     * prior_delivered would compare as "older than the round" and start a new
     * one on every such call. */
    if (s->acked_bytes == 0) {
        b->round_start = 0;
        return;
    }

    if (s->prior_delivered >= b->next_round_delivered) {
        b->next_round_delivered = s->delivered;
        b->round_count++;
        b->round_start = 1;
        return;
    }

    b->round_start = 0;
}

static void __bbr_update_btlbw(quiccc_t* cc, const quiccc_sample_t* s) {
    __bbr_update_round(cc, s);

    if (s->delivery_rate == 0) return;

    /* An application-limited sample measures how fast the application had data,
     * not how fast the path moves it -- so it may raise the estimate (the path
     * demonstrably carried that much) but must never lower it. Without this
     * rule an idle moment would look like a slow network for ten round trips. */
    if (s->app_limited && s->delivery_rate < cc->bbr.btlbw) return;

    cc->bbr.btlbw = __bbr_bw_filter(&cc->bbr, s->delivery_rate, cc->bbr.round_count);
}

static const uint64_t __bbr_cycle_gain[QUICBBR_CYCLE_LEN] = {
    /* One round trip 25% above the estimate to find out whether more bandwidth
     * is available, one 25% below to give back whatever queue that created,
     * then six at the estimate itself. */
    QUICBBR_GAIN_UNIT * 5 / 4,
    QUICBBR_GAIN_UNIT * 3 / 4,
    QUICBBR_GAIN_UNIT, QUICBBR_GAIN_UNIT, QUICBBR_GAIN_UNIT,
    QUICBBR_GAIN_UNIT, QUICBBR_GAIN_UNIT, QUICBBR_GAIN_UNIT
};

static void __bbr_advance_cycle(quiccc_t* cc, uint64_t now_us) {
    quiccc_bbr_t* b = &cc->bbr;

    b->cycle_stamp_us = now_us;
    b->cycle_index = (b->cycle_index + 1) % QUICBBR_CYCLE_LEN;
    b->pacing_gain = __bbr_cycle_gain[b->cycle_index];
}

static void __bbr_enter_probe_bw(quiccc_t* cc, uint64_t now_us) {
    quiccc_bbr_t* b = &cc->bbr;

    b->state = QUICBBR_PROBE_BW;
    b->pacing_gain = QUICBBR_GAIN_UNIT;
    b->cwnd_gain = QUICBBR_CWND_GAIN;

    /* Start at any phase except the draining one, so that connections which
     * begin together do not probe and drain in lockstep -- a synchronised fleet
     * measures its own convoy rather than the path. The clock is the entropy
     * source: it costs nothing, and nothing here is a security decision. */
    b->cycle_index = QUICBBR_CYCLE_LEN - 1 -
                     (int)(now_us % (QUICBBR_CYCLE_LEN - 1));

    __bbr_advance_cycle(cc, now_us);
}

static int __bbr_next_cycle_phase(const quiccc_t* cc, const quiccc_sample_t* s,
                                  uint64_t now_us) {
    const quiccc_bbr_t* b = &cc->bbr;
    const uint64_t rtprop = b->rtprop_us == UINT64_MAX ? 0 : b->rtprop_us;
    const int full_length = now_us > b->cycle_stamp_us + rtprop;

    if (b->pacing_gain == QUICBBR_GAIN_UNIT) return full_length;

    /* Probing up ends once the extra data is actually in flight (the probe
     * happened) or the path answered with loss -- not merely once the clock
     * says a round trip elapsed, which on a slow start-up would end the probe
     * before it began. */
    if (b->pacing_gain > QUICBBR_GAIN_UNIT) {
        return full_length &&
               (s->lost_bytes > 0 ||
                s->prior_in_flight >= __bbr_inflight(cc, b->pacing_gain));
    }

    /* Draining ends early once the queue is gone: there is nothing to give back
     * and holding the rate down only wastes the path. */
    return full_length || s->prior_in_flight <= __bbr_inflight(cc, QUICBBR_GAIN_UNIT);
}

static void __bbr_check_cycle_phase(quiccc_t* cc, const quiccc_sample_t* s,
                                    uint64_t now_us) {
    if (cc->bbr.state != QUICBBR_PROBE_BW) return;
    if (!__bbr_next_cycle_phase(cc, s, now_us)) return;

    __bbr_advance_cycle(cc, now_us);
}

/* STARTUP doubles the sending rate every round trip and has to decide when to
 * stop. The pipe is full when three rounds in a row fail to raise the delivery
 * rate by 25%: after that, everything extra goes into a queue, and the queue is
 * what DRAIN then removes. */
static void __bbr_check_full_pipe(quiccc_t* cc, const quiccc_sample_t* s) {
    quiccc_bbr_t* b = &cc->bbr;

    if (b->filled_pipe || !b->round_start || s->app_limited) return;

    if (b->btlbw >= b->full_bw * QUICBBR_FULL_BW_THRESHOLD_NUM /
                    QUICBBR_FULL_BW_THRESHOLD_DEN) {
        b->full_bw = b->btlbw;
        b->full_bw_count = 0;
        return;
    }

    if (++b->full_bw_count >= QUICBBR_FULL_BW_COUNT) b->filled_pipe = 1;
}

static void __bbr_check_drain(quiccc_t* cc, uint64_t now_us) {
    quiccc_bbr_t* b = &cc->bbr;

    if (b->state == QUICBBR_STARTUP && b->filled_pipe) {
        b->state = QUICBBR_DRAIN;
        b->pacing_gain = QUICBBR_DRAIN_GAIN;
        /* The window stays where STARTUP left it: draining is done by sending
         * slower, not by refusing to send. Cutting the window here would stall
         * a sender that is merely carrying a queue it is already emptying. */
        b->cwnd_gain = QUICBBR_HIGH_GAIN;
    }

    if (b->state == QUICBBR_DRAIN &&
        cc->bytes_in_flight <= __bbr_inflight(cc, QUICBBR_GAIN_UNIT))
        __bbr_enter_probe_bw(cc, now_us);
}

static void __bbr_update_rtprop(quiccc_t* cc, const quiccc_sample_t* s,
                                uint64_t now_us) {
    quiccc_bbr_t* b = &cc->bbr;

    b->rtprop_expired = b->rtprop_stamp_us != 0 &&
                        now_us > b->rtprop_stamp_us + QUICBBR_RTPROP_WINDOW_US;

    if (s->rtt_us == 0) return;

    if (b->rtprop_us == UINT64_MAX || s->rtt_us <= b->rtprop_us || b->rtprop_expired) {
        b->rtprop_us = s->rtt_us;
        b->rtprop_stamp_us = now_us;

        /* The expiry flag is deliberately NOT cleared here. It says "ten
         * seconds have passed since the last time this estimate was taken with
         * an empty path", and taking a sample from a path that has a queue
         * standing in it does not answer that -- the sample is only as good as
         * the queue is short.
         *
         * Clearing it was the first version, and it made PROBE_RTT unreachable
         * on exactly the paths that need it: on a steady path every sample ties
         * the current minimum, so every sample cleared the flag a moment after
         * the timer set it, and the connection went on believing a delay it had
         * not re-measured since the handshake. PROBE_RTT clears it, on its way
         * out, having actually emptied the path. */
    }
}

/* The minimum RTT can only be measured when the path is briefly empty, and the
 * path is only briefly empty if the sender makes it so. Hence PROBE_RTT: once
 * every ten seconds, hold the window at four datagrams for 200 ms and take the
 * measurement. It costs a fraction of the throughput and it is the only defence
 * against a standing queue that every sender mistakes for a longer path. */
static void __bbr_check_probe_rtt(quiccc_t* cc, const quiccc_sample_t* s,
                                  uint64_t now_us) {
    quiccc_bbr_t* b = &cc->bbr;

    if (b->state != QUICBBR_PROBE_RTT && b->rtprop_expired) {
        b->state = QUICBBR_PROBE_RTT;
        b->pacing_gain = QUICBBR_GAIN_UNIT;
        b->cwnd_gain = QUICBBR_GAIN_UNIT;

        /* What to restore on the way out. Normally that is simply the window
         * being given up; under packet conservation the current window is
         * already a reduced one, and restoring *it* would make a loss during
         * PROBE_RTT permanent, so the larger of the two is kept instead. */
        b->prior_cwnd = b->packet_conservation && b->prior_cwnd > cc->cwnd
                        ? b->prior_cwnd : cc->cwnd;

        b->probe_rtt_done_us = 0;
    }

    if (b->state != QUICBBR_PROBE_RTT) return;

    if (b->probe_rtt_done_us == 0) {
        /* The clock does not start until the path has actually drained to the
         * minimum window -- otherwise the 200 ms are spent waiting for the
         * queue to leave and no low-RTT sample is ever taken. */
        if (cc->bytes_in_flight <= __bbr_min_pipe_cwnd(cc) + cc->max_datagram_size) {
            b->probe_rtt_done_us = now_us + QUICBBR_PROBE_RTT_DURATION_US;
            b->probe_rtt_round_done = 0;
            b->next_round_delivered = s->delivered;
        }
        return;
    }

    if (b->round_start) b->probe_rtt_round_done = 1;

    if (!b->probe_rtt_round_done || now_us <= b->probe_rtt_done_us) return;

    b->rtprop_stamp_us = now_us;
    b->rtprop_expired = 0;

    if (cc->cwnd < b->prior_cwnd) cc->cwnd = b->prior_cwnd;

    if (b->filled_pipe) __bbr_enter_probe_bw(cc, now_us);
    else __bbr_enter_startup(cc);
}

static void __bbr_set_pacing_rate(quiccc_t* cc) {
    quiccc_bbr_t* b = &cc->bbr;
    uint64_t rate;

    if (b->btlbw != 0) {
        rate = b->btlbw * b->pacing_gain / QUICBBR_GAIN_UNIT;
    }
    else if (b->rtprop_us != UINT64_MAX && b->rtprop_us != 0) {
        /* Nothing measured yet: one initial window per round trip at the
         * current gain, which is what a window-based sender would do anyway. */
        rate = b->initial_cwnd * 1000000ULL / b->rtprop_us *
               b->pacing_gain / QUICBBR_GAIN_UNIT;
    }
    else return;

    if (rate == 0) return;

    /* Before the pipe is known to be full the rate only ever rises: STARTUP is
     * looking for the ceiling, and a single slow sample on the way up must not
     * push the sender back down and make it look for the ceiling again. */
    if (b->filled_pipe || rate > cc->pacing_rate) cc->pacing_rate = rate;
}

static void __bbr_set_cwnd(quiccc_t* cc, const quiccc_sample_t* s) {
    quiccc_bbr_t* b = &cc->bbr;
    const uint64_t floor = __bbr_min_pipe_cwnd(cc);

    if (b->packet_conservation) {
        /* §4.2.4: after a loss, put back only what came out, until a full round
         * has passed. */
        const uint64_t bound = cc->bytes_in_flight + s->acked_bytes;
        if (cc->cwnd < bound) cc->cwnd = bound;
    }
    else {
        const uint64_t target = __bbr_inflight(cc, b->cwnd_gain);

        if (b->filled_pipe) {
            cc->cwnd += s->acked_bytes;
            if (cc->cwnd > target) cc->cwnd = target;
        }
        else if (cc->cwnd < target || s->delivered < b->initial_cwnd) {
            /* Still hunting for the ceiling: grow one for one, exactly as slow
             * start does, and let the pacing gain do the actual probing. */
            cc->cwnd += s->acked_bytes;
        }
    }

    if (cc->cwnd < floor) cc->cwnd = floor;

    /* PROBE_RTT's whole point is the small window, so it is applied last: an
     * earlier clamp would be undone by the growth above. */
    if (b->state == QUICBBR_PROBE_RTT && cc->cwnd > floor) cc->cwnd = floor;
}

static void __bbr_on_sent(quiccc_t* cc, size_t bytes) {
    cc->bytes_in_flight += bytes;
}

static void __bbr_on_ack(quiccc_t* cc, size_t bytes, uint64_t sent_us,
                         uint64_t now_us) {
    (void)sent_us; (void)now_us;

    /* Only the accounting. Everything BBR does with an acknowledgement needs
     * the interval it covered, and a per-packet callback does not have one --
     * that is what on_ack_end is for. */
    if (cc->bytes_in_flight >= bytes) cc->bytes_in_flight -= bytes;
    else cc->bytes_in_flight = 0;
}

static void __bbr_on_loss(quiccc_t* cc, size_t bytes, uint64_t sent_us,
                          uint64_t now_us) {
    (void)sent_us; (void)now_us;

    if (cc->bytes_in_flight >= bytes) cc->bytes_in_flight -= bytes;
    else cc->bytes_in_flight = 0;

    quiccc_bbr_t* b = &cc->bbr;

    /* BBR does not treat loss as the congestion signal -- the model is built
     * from delivery rate, and halving on loss is precisely what it exists to
     * avoid. But it does not ignore loss either: the window comes down by what
     * was lost and stays under packet conservation for a round, so that a path
     * which really is dropping traffic does not keep receiving a full window
     * while the model catches up. */
    if (!b->packet_conservation) {
        if (cc->cwnd > b->prior_cwnd) b->prior_cwnd = cc->cwnd;
        b->packet_conservation = 1;
    }

    const uint64_t floor = __bbr_min_pipe_cwnd(cc);
    cc->cwnd = cc->cwnd > bytes && cc->cwnd - bytes > floor ? cc->cwnd - bytes : floor;
}

static void __bbr_on_persistent_congestion(quiccc_t* cc) {
    /* The path stopped working, so every estimate in the model describes a path
     * that no longer exists. Start over: minimum window, no bandwidth estimate,
     * STARTUP again -- the same reasoning as §7.6, reached from the other
     * direction. */
    const uint64_t rtprop = cc->bbr.rtprop_us;

    cc->cwnd = __bbr_min_pipe_cwnd(cc);

    __bbr_init(cc);   /* clears the rate estimate and the pacing rate with it */

    /* The propagation delay is a property of the path, not of the congestion
     * that just destroyed the rate estimate, so it is kept: re-measuring it
     * would cost a PROBE_RTT the connection does not need. Its stamp is not
     * kept -- the first acknowledgement after this sets it, and the ten-second
     * window runs from there. */
    cc->bbr.rtprop_us = rtprop;
}

static void __bbr_on_pto(quiccc_t* cc) { (void)cc; }

static void __bbr_on_ack_end(quiccc_t* cc, const quiccc_sample_t* sample,
                             uint64_t now_us) {
    if (cc == NULL || sample == NULL) return;

    quiccc_bbr_t* b = &cc->bbr;

    __bbr_update_btlbw(cc, sample);

    if (b->packet_conservation && b->round_start) b->packet_conservation = 0;

    __bbr_check_cycle_phase(cc, sample, now_us);
    __bbr_check_full_pipe(cc, sample);
    __bbr_check_drain(cc, now_us);
    __bbr_update_rtprop(cc, sample, now_us);
    __bbr_check_probe_rtt(cc, sample, now_us);

    __bbr_set_pacing_rate(cc);
    __bbr_set_cwnd(cc, sample);
}

const quiccc_ops_t quiccc_bbr = {
    .on_sent = __bbr_on_sent,
    .on_ack = __bbr_on_ack,
    .on_loss = __bbr_on_loss,
    .on_persistent_congestion = __bbr_on_persistent_congestion,
    .on_pto = __bbr_on_pto,
    .on_ack_end = __bbr_on_ack_end
};

/* ---- Pacing ---- */

void quicpacer_init(quicpacer_t* pacer, const quiccc_t* cc, int enabled) {
    if (pacer == NULL || cc == NULL) return;

    memset(pacer, 0, sizeof * pacer);

    pacer->enabled = enabled;
    pacer->burst_floor = cc->cwnd;   /* the initial window -- see the header */
    pacer->tokens = pacer->burst_floor;
}

/* §7.7: the interval between packets is smoothed_rtt * size / (N * cwnd), with
 * N = 1.25 in congestion avoidance and 2 in slow start. Expressed as a rate,
 * that is N * cwnd / smoothed_rtt bytes per second. */
static uint64_t __rate_bytes_per_sec(const quiccc_t* cc, uint64_t rtt_us) {
    /* A rate-based controller has already answered this, from a measurement
     * rather than from its own window. Deriving a second rate from cwnd here
     * would quietly overrule it -- and cwnd, for BBR, is a safety bound that is
     * deliberately larger than the rate it intends to send at. */
    if (cc->pacing_rate != 0) return cc->pacing_rate;

    if (rtt_us == 0) return UINT64_MAX;

    const uint64_t numerator = quiccc_in_slow_start(cc) ? 200 : 125;

    /* cwnd * (N * 100) / 100 / rtt_seconds, arranged to keep the intermediate
     * inside 64 bits for any plausible window. */
    return cc->cwnd * numerator / 100 * 1000000ULL / rtt_us;
}

size_t quicpacer_allowance(quicpacer_t* pacer, const quiccc_t* cc,
                           uint64_t smoothed_rtt_us, uint64_t now_us) {
    if (pacer == NULL || cc == NULL) return 0;
    if (!pacer->enabled) return quiccc_available(cc);

    if (pacer->last_us == 0) pacer->last_us = now_us;

    const uint64_t elapsed = now_us > pacer->last_us ? now_us - pacer->last_us : 0;
    pacer->last_us = now_us;

    const uint64_t rate = __rate_bytes_per_sec(cc, smoothed_rtt_us);
    if (rate == UINT64_MAX) {
        /* No RTT sample yet -- the first flight of a connection. Pacing it
         * would delay the handshake for no benefit. */
        pacer->tokens = pacer->burst_floor;
    }
    else {
        /* One millisecond of the current rate, never below the initial window
         * and never above what may be in flight anyway: tokens past the window
         * are unusable (the allowance below is the smaller of the two) and
         * would only let an idle connection resume with a dump. */
        uint64_t burst = rate / (1000000ULL / QUICPACER_BURST_US);
        if (burst < pacer->burst_floor) burst = pacer->burst_floor;
        if (burst > cc->cwnd) burst = cc->cwnd;

        pacer->tokens += rate * elapsed / 1000000ULL;
        if (pacer->tokens > burst) pacer->tokens = burst;
    }

    const size_t window = quiccc_available(cc);

    return pacer->tokens < window ? (size_t)pacer->tokens : window;
}

void quicpacer_consume(quicpacer_t* pacer, size_t bytes) {
    if (pacer == NULL || !pacer->enabled) return;

    pacer->tokens = pacer->tokens > bytes ? pacer->tokens - bytes : 0;
}

uint64_t quicpacer_next_time_us(const quicpacer_t* pacer, const quiccc_t* cc,
                                uint64_t smoothed_rtt_us, uint64_t now_us) {
    if (pacer == NULL || cc == NULL || !pacer->enabled) return 0;
    if (pacer->tokens >= cc->max_datagram_size) return 0;

    const uint64_t rate = __rate_bytes_per_sec(cc, smoothed_rtt_us);
    if (rate == 0 || rate == UINT64_MAX) return 0;

    const uint64_t needed = cc->max_datagram_size - pacer->tokens;

    /* Rounded up, and never zero. The refill in quicpacer_allowance truncates
     * -- rate * elapsed / 1000000 -- so a deadline rounded down buys back less
     * than a datagram, the sender wakes to find itself still blocked, and asks
     * for the same instant again. That is not a slow path but a live one: the
     * stand caught it as a transfer that stopped 208 bytes short while the
     * clock crawled forward a microsecond per turn. Ceiling division makes one
     * wake-up worth at least one datagram, always. */
    uint64_t delay_us = (needed * 1000000ULL + rate - 1) / rate;
    if (delay_us == 0) delay_us = 1;

    return now_us + delay_us;
}

#include <string.h>

#include "quiccc.h"

static uint64_t __min_window(const quiccc_t* cc) {
    return (uint64_t)QUICCC_MIN_WINDOW_PACKETS * cc->max_datagram_size;
}

void quiccc_init(quiccc_t* cc, size_t max_datagram_size) {
    quiccc_init_packets(cc, max_datagram_size, QUICCC_INITIAL_WINDOW_PACKETS);
}

void quiccc_init_packets(quiccc_t* cc, size_t max_datagram_size, uint64_t packets) {
    if (cc == NULL) return;

    memset(cc, 0, sizeof * cc);

    cc->ops = &quiccc_newreno;
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
}

int quiccc_in_slow_start(const quiccc_t* cc) {
    return cc != NULL && cc->cwnd < cc->ssthresh;
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

const quiccc_ops_t quiccc_newreno = {
    .on_sent = __newreno_on_sent,
    .on_ack = __newreno_on_ack,
    .on_loss = __newreno_on_loss,
    .on_persistent_congestion = __newreno_on_persistent_congestion,
    .on_pto = __newreno_on_pto
};

/* ---- Pacing ---- */

void quicpacer_init(quicpacer_t* pacer, size_t max_datagram_size, int enabled) {
    if (pacer == NULL) return;

    memset(pacer, 0, sizeof * pacer);

    pacer->enabled = enabled;
    /* Ten datagrams of burst: enough that the common case of a few packets
     * back to back costs no timer, small enough that an idle connection cannot
     * resume by dumping a whole window. */
    pacer->burst_limit = (uint64_t)max_datagram_size * 10;
    pacer->tokens = pacer->burst_limit;
}

/* §7.7: the interval between packets is smoothed_rtt * size / (N * cwnd), with
 * N = 1.25 in congestion avoidance and 2 in slow start. Expressed as a rate,
 * that is N * cwnd / smoothed_rtt bytes per second. */
static uint64_t __rate_bytes_per_sec(const quiccc_t* cc, uint64_t rtt_us) {
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
        pacer->tokens = pacer->burst_limit;
    }
    else {
        pacer->tokens += rate * elapsed / 1000000ULL;
        if (pacer->tokens > pacer->burst_limit) pacer->tokens = pacer->burst_limit;
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

    return now_us + needed * 1000000ULL / rate;
}

#include "framework.h"

#include "quicack.h"
#include "quiccc.h"
#include "quicloss.h"
#include "quicpacket.h"
#include "quicpmtud.h"
#include "quictime.h"

#include <string.h>

/* Loss recovery and congestion control (RFC 9002).
 *
 * This is the part of QUIC that fails invisibly. A mistake here does not crash
 * and does not produce a protocol error -- it produces a connection that is
 * slower than it should be, sometimes, on some paths. The only way to hold it
 * still long enough to check is to own the clock, which is why nothing in the
 * QUIC stack calls clock_gettime directly.
 *
 * Times are in microseconds throughout. */

static uint64_t __now = 0;
static uint64_t __clock(void) { return __now; }

#define MTU 1200

TEST(test_quic_cc_newreno) {
    TEST_SUITE("quic_cc");

    quiccc_t cc;
    quiccc_init(&cc, MTU);

    TEST_CASE("the initial window (§7.2)");
    /* Ten datagrams, capped at 14720 bytes -- the cap is what stops a
     * large-MTU path from opening with an unreasonable burst. */
    TEST_ASSERT(cc.cwnd == 12000, "10 x 1200");
    TEST_ASSERT(quiccc_in_slow_start(&cc), "starts in slow start");
    TEST_ASSERT(quiccc_available(&cc) == 12000, "all of it available");

    /* §7.2 is min(10*mtu, max(14720, 2*mtu)), so a large MTU is bounded by the
     * 14720 cap only until two datagrams exceed it -- below two datagrams the
     * connection could not send at all. */
    quiccc_t big;
    quiccc_init(&big, 9000);
    TEST_ASSERT(big.cwnd == 18000, "two datagrams, since one pair exceeds 14720");

    quiccc_t medium;
    quiccc_init(&medium, 2000);
    TEST_ASSERT(medium.cwnd == QUICCC_INITIAL_WINDOW_MAX, "capped at 14720");

    TEST_CASE("bytes in flight consume the window");
    cc.ops->on_sent(&cc, 1200);
    TEST_ASSERT(cc.bytes_in_flight == 1200, "counted");
    TEST_ASSERT(quiccc_available(&cc) == 10800, "window reduced");

    TEST_CASE("slow start grows one for one");
    /* The window doubles every round trip, which is the whole point of slow
     * start: find the path's capacity in log time rather than linear. */
    const uint64_t before = cc.cwnd;
    cc.ops->on_ack(&cc, 1200, 1000, 2000);
    TEST_ASSERT(cc.cwnd == before + 1200, "grew by the acknowledged bytes");
    TEST_ASSERT(cc.bytes_in_flight == 0, "and released them");

    TEST_CASE("a loss halves the window and leaves slow start");
    quiccc_init(&cc, MTU);
    cc.ops->on_sent(&cc, 6000);
    cc.ops->on_loss(&cc, 1200, 1000, 5000);

    TEST_ASSERT(cc.cwnd == 6000, "halved");
    TEST_ASSERT(cc.ssthresh == 6000, "ssthresh set to the new window");
    TEST_ASSERT(!quiccc_in_slow_start(&cc), "now in congestion avoidance");
    TEST_ASSERT(cc.bytes_in_flight == 4800, "the lost bytes are no longer in flight");

    TEST_CASE("a burst of losses is one congestion event");
    /* Every packet sent before the recovery period began belongs to the same
     * event. Halving once per lost packet would collapse the window to its
     * minimum on a single reordering. */
    const uint64_t after_first = cc.cwnd;
    cc.ops->on_loss(&cc, 1200, 2000, 5100);
    cc.ops->on_loss(&cc, 1200, 3000, 5200);
    TEST_ASSERT(cc.cwnd == after_first, "the window did not move again");

    TEST_CASE("a loss in a new recovery period does halve again");
    cc.ops->on_sent(&cc, 1200);
    cc.ops->on_loss(&cc, 1200, 9000, 9500);
    TEST_ASSERT(cc.cwnd == 3000, "halved a second time");

    TEST_CASE("the window never falls below two datagrams");
    for (int i = 0; i < 20; i++) {
        cc.ops->on_sent(&cc, 1200);
        cc.ops->on_loss(&cc, 1200, 10000 + i * 1000, 10500 + i * 1000);
    }
    TEST_ASSERT(cc.cwnd == 2 * MTU, "floored at 2400");

    TEST_CASE("congestion avoidance grows about one datagram per window");
    /* And it must actually grow: the naive expression truncates to zero for
     * every acknowledgement smaller than cwnd / mtu, which is nearly all of
     * them, so a carried remainder is what keeps it moving. */
    quiccc_init(&cc, MTU);
    cc.ssthresh = 12000;    /* force congestion avoidance */
    cc.cwnd = 12000;

    const uint64_t start = cc.cwnd;
    for (int i = 0; i < 10; i++) {
        cc.ops->on_sent(&cc, 1200);
        cc.ops->on_ack(&cc, 1200, 1000, 2000);
    }
    TEST_ASSERT(cc.cwnd > start, "the window grew at all");
    TEST_ASSERT(cc.cwnd - start >= MTU - 50 && cc.cwnd - start <= MTU + 50,
                "by roughly one datagram per window of acknowledgements");

    TEST_CASE("persistent congestion collapses to the minimum");
    /* §7.6: a long enough span with everything lost is a path that stopped
     * working, not a congested one. Halving repeatedly would take many round
     * trips to discover that. */
    cc.ops->on_persistent_congestion(&cc);
    TEST_ASSERT(cc.cwnd == 2 * MTU, "minimum window");
    TEST_ASSERT(quiccc_in_slow_start(&cc), "and back in slow start");
}

TEST(test_quic_cc_cubic) {
    TEST_SUITE("quic_cc");

    quiccc_t cc;
    quiccc_init_algorithm(&cc, MTU, QUICCC_INITIAL_WINDOW_PACKETS, QUICCC_CUBIC);
    TEST_ASSERT(cc.ops == &quiccc_cubic, "CUBIC selected");

    TEST_CASE("CUBIC uses beta 0.7 on congestion");
    cc.ops->on_sent(&cc, MTU);
    cc.ops->on_loss(&cc, MTU, 1000, 2000);
    TEST_ASSERT(cc.cwnd == 8400, "window reduced to 70 percent");
    TEST_ASSERT(cc.ssthresh == cc.cwnd, "enters congestion avoidance");
    TEST_ASSERT(cc.cubic_w_max == 12000, "remembers the pre-loss maximum");

    TEST_CASE("the cubic curve returns to W_max and grows beyond it");
    uint64_t sent = 3000;
    for (uint64_t now = 103000; now <= 5103000; now += 100000) {
        cc.ops->on_sent(&cc, MTU);
        cc.ops->on_ack(&cc, MTU, sent, now);
        sent = now - 50000;
    }
    TEST_ASSERT(cc.cwnd > cc.cubic_w_max, "grew beyond the previous maximum");

    TEST_CASE("persistent congestion resets CUBIC to slow start");
    cc.ops->on_persistent_congestion(&cc);
    TEST_ASSERT(cc.cwnd == 2 * MTU, "minimum window");
    TEST_ASSERT(quiccc_in_slow_start(&cc), "slow start restored");
    TEST_ASSERT(cc.cubic_w_max == 0, "old path history discarded");
}

/* One acknowledgement, as loss detection would report it: `bytes` newly
 * delivered, measured at `rate`, with the round trip it produced.
 *
 * The delivered counter is threaded through by the caller because that is what
 * BBR counts round trips with -- an acknowledgement for data sent before the
 * current round began starts a new one. */
static void __bbr_feed(quiccc_t* cc, uint64_t* delivered, uint64_t bytes,
                       uint64_t rate, uint64_t rtt_us, uint64_t now_us,
                       int app_limited) {
    quiccc_sample_t s;
    memset(&s, 0, sizeof s);

    s.prior_delivered = *delivered;
    *delivered += bytes;

    s.delivered = *delivered;
    s.acked_bytes = bytes;
    s.delivery_rate = rate;
    s.rtt_us = rtt_us;
    s.app_limited = app_limited;
    s.prior_in_flight = cc->bytes_in_flight;

    cc->ops->on_ack(cc, bytes, now_us > rtt_us ? now_us - rtt_us : 0, now_us);
    cc->ops->on_ack_end(cc, &s, now_us);
}

TEST(test_quic_cc_bbr) {
    TEST_SUITE("quic_cc");

    quiccc_t cc;
    quiccc_init_algorithm(&cc, MTU, QUICCC_INITIAL_WINDOW_PACKETS, QUICCC_BBR);

    uint64_t delivered = 0;
    uint64_t now = 1000000;

    TEST_CASE("BBR starts in STARTUP with no model at all");
    TEST_ASSERT(cc.ops == &quiccc_bbr, "BBR selected");
    TEST_ASSERT(cc.bbr.state == QUICBBR_STARTUP, "STARTUP");
    TEST_ASSERT(cc.bbr.pacing_gain == QUICBBR_HIGH_GAIN, "2/ln2, to double every round");
    TEST_ASSERT(cc.bbr.btlbw == 0 && cc.bbr.rtprop_us == UINT64_MAX,
                "nothing measured yet");
    /* Nothing to derive a rate from, so the pacer keeps §7.7 until the first
     * round trip has been timed. */
    TEST_ASSERT(cc.pacing_rate == 0, "no rate named before the first sample");

    TEST_CASE("the first sample builds the model and drives the pacer");
    __bbr_feed(&cc, &delivered, 12000, 250000, 50000, now, 0);
    TEST_ASSERT(cc.bbr.btlbw == 250000, "bandwidth is the measured rate");
    TEST_ASSERT(cc.bbr.rtprop_us == 50000, "and the round trip is the delay");
    TEST_ASSERT(cc.pacing_rate == 250000 * QUICBBR_HIGH_GAIN / QUICBBR_GAIN_UNIT,
                "the pacer is told to send at the STARTUP gain");
    TEST_ASSERT(cc.cwnd > 12000, "and the window grew with the acknowledgement");

    TEST_CASE("a faster path raises the estimate at once");
    /* The maximum is the estimate, so an increase is adopted immediately --
     * unlike a loss-based controller, which has to fill a queue first. */
    now += 50000;
    __bbr_feed(&cc, &delivered, 12000, 500000, 50000, now, 0);
    TEST_ASSERT(cc.bbr.btlbw == 500000, "adopted without waiting");

    TEST_CASE("an application-limited sample cannot lower it");
    /* A pause in the application looks exactly like a slower path from the
     * outside, and mistaking one for the other costs ten round trips of
     * sending at the speed of an idle moment. */
    now += 50000;
    __bbr_feed(&cc, &delivered, 1200, 10000, 50000, now, 1);
    TEST_ASSERT(cc.bbr.btlbw == 500000, "the estimate stood");

    TEST_CASE("STARTUP ends when three rounds fail to raise the rate by 25%");
    /* Something has to be in flight, or DRAIN is entered and left in the same
     * acknowledgement -- there would be no queue to drain. */
    cc.ops->on_sent(&cc, 100000);

    for (int i = 0; i < QUICBBR_FULL_BW_COUNT + 1; i++) {
        now += 50000;
        __bbr_feed(&cc, &delivered, 1200, 500000, 50000, now, 0);
    }

    TEST_ASSERT(cc.bbr.filled_pipe, "the pipe is full");
    TEST_ASSERT(cc.bbr.state == QUICBBR_DRAIN, "so STARTUP gives way to DRAIN");
    TEST_ASSERT(cc.bbr.pacing_gain == QUICBBR_DRAIN_GAIN,
                "and the rate drops below the estimate to give the queue back");

    TEST_CASE("DRAIN ends when the path holds no more than one BDP");
    /* 500 kB/s over 50 ms is 25000 bytes in the path; the acknowledgement below
     * releases enough that what is left fits. */
    now += 50000;
    __bbr_feed(&cc, &delivered, 90000, 500000, 50000, now, 0);
    TEST_ASSERT(cc.bbr.state == QUICBBR_PROBE_BW, "steady state reached");
    TEST_ASSERT(cc.bbr.cwnd_gain == QUICBBR_CWND_GAIN,
                "the window is two BDP -- room for the probe, not for a queue");

    TEST_CASE("PROBE_BW cycles above and below the estimate");
    /* One round trip 25% up to look for more bandwidth, one 25% down to return
     * whatever queue that built. Without the second the probe would leave a
     * standing queue behind on every cycle. */
    /* The probing phase ends when the extra data is actually in flight, not
     * merely when the clock says a round trip passed -- so the sender has to
     * keep the path busy or the cycle stalls at the probe, which is exactly
     * what it should do for a sender with nothing to probe with. */
    cc.ops->on_sent(&cc, 50000);

    int seen_up = 0, seen_down = 0, seen_unit = 0;
    for (int i = 0; i < 3 * QUICBBR_CYCLE_LEN; i++) {
        now += 60000;   /* more than rtprop, so the phase may advance */
        cc.ops->on_sent(&cc, 12000);
        __bbr_feed(&cc, &delivered, 12000, 500000, 50000, now, 0);

        if (cc.bbr.pacing_gain > QUICBBR_GAIN_UNIT) seen_up = 1;
        else if (cc.bbr.pacing_gain < QUICBBR_GAIN_UNIT) seen_down = 1;
        else seen_unit = 1;
    }
    TEST_ASSERT(seen_up && seen_down && seen_unit, "all three phases occur");
    TEST_ASSERT(cc.bbr.state == QUICBBR_PROBE_BW, "and it stays in PROBE_BW");

    TEST_CASE("the bandwidth estimate falls once the window slides past it");
    /* A maximum that only ever rises would keep sending at a rate the path
     * stopped supporting. Ten round trips at a lower rate must lower it. */
    for (int i = 0; i < QUICBBR_BW_WINDOW_ROUNDS + 3; i++) {
        now += 60000;
        cc.ops->on_sent(&cc, 12000);
        __bbr_feed(&cc, &delivered, 12000, 200000, 50000, now, 0);
    }
    TEST_ASSERT(cc.bbr.btlbw == 200000, "the stale maximum expired");

    TEST_CASE("PROBE_RTT re-measures the minimum RTT every ten seconds");
    /* A standing queue inflates every RTT sample, and the only way to see past
     * it is to stop sending long enough for the queue to leave. */
    const uint64_t before_probe = cc.cwnd;
    now += QUICBBR_RTPROP_WINDOW_US + 1000000;
    /* REGRESSION: this sample ties the current minimum, and the first version
     * treated that as "re-measured" and cleared the expiry flag. On a steady
     * path every sample ties the minimum, so PROBE_RTT never happened and a
     * standing queue would have been carried as path delay indefinitely. */
    __bbr_feed(&cc, &delivered, 1200, 200000, 50000, now, 0);

    TEST_ASSERT(cc.bbr.state == QUICBBR_PROBE_RTT, "entered on the timer");
    TEST_ASSERT(cc.cwnd == QUICBBR_MIN_PIPE_CWND_PACKETS * MTU,
                "the window collapses to four datagrams");
    TEST_ASSERT(cc.bbr.prior_cwnd >= before_probe, "the old window is remembered");

    TEST_CASE("and leaves after 200 ms and a round trip, window restored");
    cc.bytes_in_flight = 0;                    /* the path drained */
    now += 1000;
    __bbr_feed(&cc, &delivered, 1200, 200000, 40000, now, 0);   /* starts the clock */
    TEST_ASSERT(cc.bbr.probe_rtt_done_us == now + QUICBBR_PROBE_RTT_DURATION_US,
                "the 200 ms begin only once the path is actually empty");

    now += QUICBBR_PROBE_RTT_DURATION_US + 1000;
    __bbr_feed(&cc, &delivered, 1200, 200000, 40000, now, 0);
    TEST_ASSERT(cc.bbr.state == QUICBBR_PROBE_BW, "back to steady state");
    TEST_ASSERT(cc.bbr.rtprop_us == 40000, "with the minimum RTT it went to measure");

    /* Bigger than the PROBE_RTT floor it was held at, and set by the model
     * rather than by the floor. Not "at least what it gave up": the probe found
     * a shorter path than the model assumed, and a shorter path holds fewer
     * bytes -- the window following that down is the measurement working, not
     * the window being lost. */
    TEST_ASSERT(cc.cwnd > QUICBBR_MIN_PIPE_CWND_PACKETS * MTU, "the floor is released");
    TEST_ASSERT(before_probe > cc.cwnd && cc.cwnd == 19600,
                "and the window is one cwnd_gain of the new, shorter BDP");

    TEST_CASE("a loss is not a halving");
    /* The whole point of a rate-based controller: loss on a lossy path is not
     * evidence of congestion, so the window comes down by what was lost rather
     * than by half. */
    quiccc_t lossy;
    quiccc_init_algorithm(&lossy, MTU, QUICCC_INITIAL_WINDOW_PACKETS, QUICCC_BBR);
    lossy.ops->on_sent(&lossy, 12000);
    lossy.ops->on_loss(&lossy, 1200, 1000, 2000);

    TEST_ASSERT(lossy.cwnd == 10800, "down by the lost bytes, not to 6000");
    TEST_ASSERT(lossy.bytes_in_flight == 10800, "and they are no longer in flight");
    TEST_ASSERT(lossy.bbr.packet_conservation,
                "but nothing new goes out beyond what came back, for a round");

    TEST_CASE("packet conservation ends after one round");
    uint64_t lossy_delivered = 0;
    __bbr_feed(&lossy, &lossy_delivered, 1200, 250000, 50000, 3000, 0);
    TEST_ASSERT(!lossy.bbr.packet_conservation, "released on the round boundary");

    TEST_CASE("persistent congestion throws the model away");
    /* Every estimate describes a path that has stopped working, so keeping any
     * of them would send the reopened connection at the speed of a path that no
     * longer exists. The propagation delay survives -- it is a property of the
     * route, and re-measuring it costs a PROBE_RTT. */
    lossy.ops->on_persistent_congestion(&lossy);
    TEST_ASSERT(lossy.cwnd == QUICBBR_MIN_PIPE_CWND_PACKETS * MTU, "minimum window");
    TEST_ASSERT(lossy.bbr.state == QUICBBR_STARTUP, "starting over");
    TEST_ASSERT(lossy.bbr.btlbw == 0 && lossy.pacing_rate == 0,
                "no bandwidth estimate and no rate to pace at");
    TEST_ASSERT(lossy.bbr.rtprop_us == 50000, "the path's delay is kept");
    TEST_ASSERT(quiccc_in_slow_start(&lossy),
                "and STARTUP answers the slow-start question");
}

TEST(test_quic_cc_bbr_pacing) {
    TEST_SUITE("quic_cc");

    quiccc_t cc;
    quiccc_init_algorithm(&cc, MTU, QUICCC_INITIAL_WINDOW_PACKETS, QUICCC_BBR);

    quicpacer_t pacer;
    quicpacer_init(&pacer, &cc, 1);

    TEST_CASE("the controller's rate overrides the cwnd/RTT formula");
    /* For a window-based controller the pacer smooths a decision the window
     * already made. For BBR the pacer *is* the decision, and cwnd is only the
     * bound that keeps a wrong rate from filling the path -- so a rate derived
     * from cwnd here would quietly overrule the measurement. */
    uint64_t delivered = 0;
    __bbr_feed(&cc, &delivered, 12000, 250000, 50000, 1000000, 0);

    const uint64_t rate = cc.pacing_rate;
    TEST_ASSERT(rate > 0, "a rate was named");

    /* Drain the bucket, then let exactly one second pass: what refills is the
     * controller's rate, whatever RTT the pacer is handed. */
    quicpacer_allowance(&pacer, &cc, 50000, 2000000);
    quicpacer_consume(&pacer, pacer.tokens);

    cc.cwnd = 1ULL << 40;   /* absurd, to prove the window is not the source */
    quicpacer_allowance(&pacer, &cc, 50000, 3000000);

    TEST_ASSERT(pacer.tokens <= pacer.burst_limit, "the burst cap still holds");
    TEST_ASSERT(pacer.burst_limit < rate,
                "and one second of the measured rate exceeds it, so the cap is what shows");

    TEST_CASE("the deadline follows the controller's rate too");
    quicpacer_consume(&pacer, pacer.tokens);
    const uint64_t resume = quicpacer_next_time_us(&pacer, &cc, 50000, 3000000);
    /* One datagram at `rate` bytes per second, rounded up. */
    const uint64_t expected = 3000000 + (MTU * 1000000ULL + rate - 1) / rate;
    TEST_ASSERT_EQUAL_UINT(expected, resume, "one datagram at the measured rate");
}

TEST(test_quic_ecn_accounting) {
    TEST_SUITE("quic_ecn");
    quicack_t ack;
    quicack_init(&ack);

    quicack_on_received_ecn(&ack, QUIC_ENC_APP, 1, 1, 0x02, 1000, 25000);
    quicack_on_received_ecn(&ack, QUIC_ENC_APP, 2, 1, 0x03, 1100, 25000);
    TEST_ASSERT(ack.has_ecn, "ACK_ECN enabled by marked packets");
    TEST_ASSERT(ack.ect0 == 1 && ack.ce == 1 && ack.ect1 == 0,
                "ECT(0) and CE counted independently");

    uint8_t frame[128];
    const size_t n = quicack_write(&ack, frame, sizeof frame, 1200, 3);
    quicframe_t parsed;
    size_t off = 0;
    TEST_ASSERT(n > 0 && quicframe_next(frame, n, &off, &parsed) == QUICFRAME_OK,
                "ACK_ECN encoded and parsed");
    TEST_ASSERT(parsed.type == QUIC_FRAME_ACK_ECN && parsed.u.ack.ect0 == 1 &&
                parsed.u.ack.ce == 1, "wire counters preserved");
    quicack_free(&ack);
}

TEST(test_quic_dplpmtud) {
    TEST_SUITE("quic_dplpmtud");
    quicpmtud_t p;
    quicpmtud_init(&p, 1350, 1472);

    TEST_ASSERT(quicpmtud_should_probe(&p, 1), "search begins at the base PLPMTU");
    TEST_ASSERT(quicpmtud_candidate(&p) == 1472, "probes the link MTU ceiling");
    quicpmtud_on_probe_sent(&p, 42, 1000, 10000);
    TEST_ASSERT(!quicpmtud_on_ack(&p, 41, 2000, 10000),
                "an unrelated ACK cannot raise PLPMTU");
    TEST_ASSERT(quicpmtud_on_ack(&p, 42, 2000, 10000),
                "the probe packet ACK confirms PLPMTU");
    TEST_ASSERT(p.current == 1472, "confirmed size becomes the packet size");

    TEST_ASSERT(quicpmtud_on_blackhole(&p, 50000, 10000),
                "a black hole reports that it took a raised size back");
    TEST_ASSERT(p.current == 1350, "black hole falls back to the safe base");
    TEST_ASSERT(p.ceiling == 1471, "failed size is excluded from the next search");
    TEST_ASSERT(!quicpmtud_on_blackhole(&p, 60000, 10000),
                "a second black hole at the base reports nothing to take back");

    /* What the search reports when it fails, which is what /metrics and the
     * qlog are written from: a lost probe every time, and the end of the search
     * only on the last of them. Without the return value neither is visible --
     * the size simply stops growing. */
    TEST_CASE("a failing search reports every attempt");
    quicpmtud_t f;
    quicpmtud_init(&f, 1350, 1472);

    uint64_t now = 1000;
    int last = 0;
    for (unsigned attempt = 1; attempt <= QUICPMTUD_MAX_PROBES; attempt++) {
        TEST_ASSERT(quicpmtud_should_probe(&f, now), "another probe is due");
        quicpmtud_candidate(&f);
        quicpmtud_on_probe_sent(&f, 100 + attempt, now, 10000);
        TEST_ASSERT(quicpmtud_on_timeout(&f, now + 1000) == 0,
                    "nothing is reported before the probe deadline");
        now += 30001;
        last = quicpmtud_on_timeout(&f, now);
        TEST_ASSERT(last & QUICPMTUD_PROBE_LOST, "each timed-out probe is reported lost");
    }

    TEST_ASSERT(last & QUICPMTUD_CEILING_LOWERED,
                "the last attempt reports that the search gave up");
    TEST_ASSERT(f.ceiling == f.current, "the ceiling drops to the size in use");
    TEST_ASSERT(!quicpmtud_should_probe(&f, now + 1000000),
                "and no further probe is attempted");
}

TEST(test_quic_pacer) {
    TEST_SUITE("quic_cc");

    quiccc_t cc;
    quiccc_init(&cc, MTU);

    quicpacer_t pacer;
    quicpacer_init(&pacer, &cc, 1);

    TEST_CASE("with no RTT sample the pacer does not delay the handshake");
    /* The first flight has nothing to pace against, and holding it back would
     * add a round trip to every connection. */
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 0, 1000) > 0, "allowed");

    TEST_CASE("the burst is the initial window");
    quicpacer_init(&pacer, &cc, 1);
    const size_t allowance = quicpacer_allowance(&pacer, &cc, 50000, 1000000);
    TEST_ASSERT_EQUAL_SIZE((size_t)cc.cwnd, allowance,
                           "the opening flight goes out exactly as it would unpaced");

    TEST_CASE("a raised initial window raises the burst with it");
    /* An operator who sets http3_initcwnd_packets asks for that burst; the pacer
     * shapes what comes after it, not the window they configured. */
    quiccc_t wide;
    quiccc_init_packets(&wide, MTU, 30);
    quicpacer_init(&pacer, &wide, 1);
    TEST_ASSERT_EQUAL_SIZE((size_t)(30 * MTU),
                           quicpacer_allowance(&pacer, &wide, 50000, 1000000),
                           "thirty datagrams at once, as configured");

    TEST_CASE("tokens are consumed and refill over time");
    quicpacer_init(&pacer, &cc, 1);
    __now = 1000000;
    quicpacer_allowance(&pacer, &cc, 50000, __now);
    quicpacer_consume(&pacer, (size_t)cc.cwnd);
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 50000, __now) == 0,
                "nothing left immediately");

    TEST_CASE("an exhausted bucket names the time it reopens");
    /* The congestion window reopens when the peer says something; this reopens
     * on the clock alone, so the sender has to be told when to come back. */
    const uint64_t resume = quicpacer_next_time_us(&pacer, &cc, 50000, __now);
    TEST_ASSERT(resume > __now, "a deadline in the future");

    TEST_CASE("waiting until that deadline buys a whole datagram");
    /* REGRESSION: the deadline was computed with a truncating division while
     * the refill truncates too, so waiting for it bought back less than a
     * datagram. The sender woke still blocked and asked for the same instant
     * again -- a live loop that the stand saw as a transfer stopping a couple
     * of hundred bytes short. One wake-up must always be worth one datagram. */
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 50000, resume) >= (size_t)MTU,
                "the wake-up is not wasted");

    /* One RTT later a full window's worth has been earned back. */
    __now += 50000;
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 50000, __now) > 0, "refilled");
    TEST_ASSERT_EQUAL_UINT(0, quicpacer_next_time_us(&pacer, &cc, 50000, __now),
                           "and no deadline while it allows a datagram");

    TEST_CASE("the pacer never exceeds the congestion window");
    quiccc_init(&cc, MTU);
    quicpacer_init(&pacer, &cc, 1);
    cc.ops->on_sent(&cc, cc.cwnd);       /* window full */
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 50000, __now) == 0,
                "no allowance when the window is full");

    TEST_CASE("disabled, it reports the raw window");
    quiccc_init(&cc, MTU);
    quicpacer_init(&pacer, &cc, 0);
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 50000, __now) == quiccc_available(&cc),
                "the window itself");
}

TEST(test_quic_loss_rtt) {
    TEST_SUITE("quic_loss");

    quic_time_set_source(__clock);
    __now = 1000000;

    quiccc_t cc;
    quiccc_init(&cc, MTU);

    quicloss_t loss;
    quicloss_init(&loss, &cc, 25000);
    loss.handshake_confirmed = 1;

    TEST_CASE("the first sample seeds the estimator (§5.3)");
    /* smoothed = latest, rttvar = latest / 2. Seeding with zero instead would
     * make the first PTO fire almost immediately. */
    quicloss_on_sent(&loss, QUIC_ENC_APP, 0, 1200, 1, 1, NULL, __now);

    __now += 100000;   /* 100 ms round trip */
    quicrange_t acked;
    quicrange_init(&acked, 0);
    quicrange_add(&acked, 0, 0);

    quicframe_ref_t* lost = NULL;
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    TEST_ASSERT(loss.smoothed_rtt_us == 100000, "smoothed");
    TEST_ASSERT(loss.rttvar_us == 50000, "variance is half");
    TEST_ASSERT(loss.min_rtt_us == 100000, "minimum");

    TEST_CASE("later samples move the average slowly");
    /* 7/8 of the old value: one outlier must not swing the estimate, or a
     * single delayed acknowledgement would suppress loss detection. */
    quicloss_on_sent(&loss, QUIC_ENC_APP, 1, 1200, 1, 1, NULL, __now);
    __now += 200000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 1, 1);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    TEST_ASSERT(loss.smoothed_rtt_us > 100000 && loss.smoothed_rtt_us < 130000,
                "moved a fraction of the way");
    TEST_ASSERT(loss.min_rtt_us == 100000, "the minimum is unchanged by a slower sample");

    TEST_CASE("min_rtt tracks downward immediately");
    quicloss_on_sent(&loss, QUIC_ENC_APP, 2, 1200, 1, 1, NULL, __now);
    __now += 20000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 2, 2);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);
    TEST_ASSERT(loss.min_rtt_us == 20000, "the new minimum");

    TEST_CASE("a peer cannot drive the estimate below min_rtt with ack_delay");
    /* An inflated delay would otherwise shrink our RTT estimate without limit,
     * and a small estimate means declaring loss on packets that are merely in
     * flight. */
    const uint64_t before = loss.smoothed_rtt_us;
    quicloss_on_sent(&loss, QUIC_ENC_APP, 3, 1200, 1, 1, NULL, __now);
    __now += 30000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 3, 3);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 10000000, __now, &lost, NULL);

    TEST_ASSERT(loss.smoothed_rtt_us > 0, "still a sane estimate");
    TEST_ASSERT(loss.smoothed_rtt_us <= before, "and it did not blow up");

    quicrange_free(&acked);
    quicloss_free(&loss);
    quic_time_set_source(NULL);
}

TEST(test_quic_loss_detection) {
    TEST_SUITE("quic_loss");

    quic_time_set_source(__clock);
    __now = 1000000;

    quiccc_t cc;
    quiccc_init(&cc, MTU);

    quicloss_t loss;
    quicloss_init(&loss, &cc, 25000);
    loss.handshake_confirmed = 1;

    quicrange_t acked;
    quicrange_init(&acked, 0);
    quicframe_ref_t* lost = NULL;

    TEST_CASE("three packets past a loss declares it (§6.1.1)");
    /* Reordering by one or two packets is ordinary; by three it is loss. The
     * threshold is what separates the two without waiting for a timer. */
    for (uint64_t pn = 0; pn < 5; pn++) {
        quicframe_ref_t* ref = quicframe_ref_new(QUIC_FRAME_STREAM);
        ref->stream_id = 0;
        ref->offset = pn * 100;
        ref->len = 100;
        quicloss_on_sent(&loss, QUIC_ENC_APP, pn, 1200, 1, 1, ref, __now);
        __now += 1000;
    }

    /* Packets 1..4 acknowledged, 0 missing: 4 - 0 >= 3, so 0 is lost. */
    quicrange_add(&acked, 1, 4);
    __now += 10000;
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    TEST_ASSERT(lost != NULL, "something was declared lost");
    TEST_ASSERT(lost->type == QUIC_FRAME_STREAM, "the frame reference came back");
    TEST_ASSERT(lost->offset == 0 && lost->len == 100, "with its range");
    TEST_ASSERT(lost->next == NULL, "and only that one");
    quicframe_ref_free(lost);
    lost = NULL;

    TEST_CASE("reordering by less than the threshold is not loss");
    quicloss_free(&loss);
    quicloss_init(&loss, &cc, 25000);
    loss.handshake_confirmed = 1;
    quicrange_clear(&acked);

    /* Establish a realistic round trip first. The time threshold is 9/8 of the
     * RTT, so on a path with a 1 ms RTT a packet 3 ms old genuinely IS lost --
     * only a path slow relative to the spacing of the packets leaves room for
     * reordering, and that is the case worth testing. */
    quicloss_on_sent(&loss, QUIC_ENC_APP, 0, 1200, 1, 1, NULL, __now);
    __now += 100000;
    quicrange_add(&acked, 0, 0);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);
    TEST_REQUIRE(loss.smoothed_rtt_us == 100000, "100 ms round trip established");

    quicrange_clear(&acked);
    for (uint64_t pn = 1; pn <= 3; pn++) {
        quicloss_on_sent(&loss, QUIC_ENC_APP, pn, 1200, 1, 1, NULL, __now);
        __now += 1000;
    }

    /* One round trip later, 2 and 3 are acknowledged and 1 is missing:
     * 3 - 1 = 2, below the packet threshold, and packet 1 is ~102 ms old
     * against a 112 ms time threshold. */
    __now += 100000;
    quicrange_add(&acked, 2, 3);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);
    TEST_ASSERT(lost == NULL, "nothing declared lost");
    TEST_ASSERT(loss.space[QUIC_ENC_APP].loss_time_us != 0,
                "but a timer is armed for the time threshold");

    TEST_CASE("the time threshold fires later (§6.1.2)");
    /* The packet-number threshold cannot help at the end of a flight, where no
     * later packet exists to count against. */
    __now = loss.space[QUIC_ENC_APP].loss_time_us + 1;
    quic_enc_level_e level = QUIC_ENC_INITIAL;
    const int was_loss = quicloss_on_timeout(&loss, __now, &lost, &level);

    TEST_ASSERT(was_loss, "it was a loss timer, not a probe");
    TEST_ASSERT(level == QUIC_ENC_APP, "in the application space");
    quicframe_ref_free(lost);
    lost = NULL;

    quicrange_free(&acked);
    quicloss_free(&loss);
    quic_time_set_source(NULL);
}

TEST(test_quic_loss_pto) {
    TEST_SUITE("quic_loss");

    quic_time_set_source(__clock);
    __now = 1000000;

    quiccc_t cc;
    quiccc_init(&cc, MTU);

    quicloss_t loss;
    quicloss_init(&loss, &cc, 25000);
    loss.handshake_confirmed = 1;

    TEST_CASE("before any sample the PTO uses the initial RTT");
    TEST_ASSERT(quicloss_pto_us(&loss, QUIC_ENC_APP) == QUICLOSS_INITIAL_RTT_US * 2,
                "twice 333 ms");

    TEST_CASE("with a sample it is smoothed + 4 variance + max_ack_delay");
    quicloss_on_sent(&loss, QUIC_ENC_APP, 0, 1200, 1, 1, NULL, __now);
    __now += 100000;
    quicrange_t acked;
    quicrange_init(&acked, 0);
    quicrange_add(&acked, 0, 0);
    quicframe_ref_t* lost = NULL;
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    /* 100000 + 4*50000 + 25000 */
    TEST_ASSERT(quicloss_pto_us(&loss, QUIC_ENC_APP) == 325000, "computed");

    TEST_CASE("the handshake spaces exclude the peer's ack delay (§6.2.1)");
    /* A peer is not obliged to honour max_ack_delay during the handshake, so
     * counting it would make handshake probes needlessly slow. */
    TEST_ASSERT(quicloss_pto_us(&loss, QUIC_ENC_HANDSHAKE) == 300000, "without the delay");

    TEST_CASE("a PTO is a probe, not a retransmission");
    /* §6.2: the sender emits ack-eliciting packets to make the peer speak.
     * Declaring the outstanding packets lost instead would collapse the window
     * on a path that is merely quiet. */
    quicloss_on_sent(&loss, QUIC_ENC_APP, 1, 1200, 1, 1, NULL, __now);

    const uint64_t timeout = quicloss_timeout(&loss, __now);
    TEST_ASSERT(timeout > __now, "armed in the future");

    __now = timeout + 1;
    quic_enc_level_e level = QUIC_ENC_INITIAL;
    const int was_loss = quicloss_on_timeout(&loss, __now, &lost, &level);

    TEST_ASSERT(!was_loss, "reported as a probe");
    TEST_ASSERT(lost == NULL, "nothing was declared lost");
    TEST_ASSERT(loss.pto_count == 1, "the backoff counter moved");

    TEST_CASE("the backoff doubles");
    /* Exponential, so a black-holed path is probed a handful of times rather
     * than flooded. */
    const uint64_t second = quicloss_timeout(&loss, __now);
    __now = second + 1;
    quicloss_on_timeout(&loss, __now, &lost, &level);
    TEST_ASSERT(loss.pto_count == 2, "again");

    const uint64_t third = quicloss_timeout(&loss, __now);
    TEST_ASSERT(third - __now > second - (timeout + 1), "the interval grew");

    TEST_CASE("an acknowledgement resets the backoff");
    quicrange_clear(&acked);
    quicrange_add(&acked, 1, 1);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);
    TEST_ASSERT(loss.pto_count == 0, "reset");

    TEST_CASE("no timer with nothing in flight");
    TEST_ASSERT(quicloss_timeout(&loss, __now) == 0, "disarmed");

    quicrange_free(&acked);
    quicloss_free(&loss);
    quic_time_set_source(NULL);
}

/* The shape a live failure had: one packet lost while the connection carries on
 * (docs/http3/08 §2a). Reproduced here because the live version could only say
 * "the announcement never came back", and a deterministic clock can say which
 * of the three recovery paths was supposed to fire. */
TEST(test_quic_loss_stranded_packet) {
    TEST_SUITE("quic_loss");

    quic_time_set_source(__clock);
    __now = 1000000;

    quiccc_t cc;
    quiccc_init(&cc, MTU);

    quicloss_t loss;
    quicloss_init(&loss, &cc, 25000);
    loss.handshake_confirmed = 1;

    quicrange_t acked;
    quicrange_init(&acked, 0);
    quicframe_ref_t* lost = NULL;

    TEST_CASE("a later acknowledgement declares the stranded packet lost");
    /* The ordinary path, and the one the live failure never reached: something
     * newer is acknowledged, so the gap becomes visible.
     *
     * The lost packet carries a frame reference on purpose. Without one a
     * declared loss produces an empty `out_lost`, and "nothing came back" reads
     * identically to "nothing was lost" -- which is how the first version of
     * this test managed to assert the opposite of what happened. */
    quicframe_ref_t* carried = quicframe_ref_new(QUIC_FRAME_NEW_CONNECTION_ID);
    TEST_REQUIRE(carried != NULL, "reference");

    quicloss_on_sent(&loss, QUIC_ENC_APP, 0, 1200, 1, 1, carried, __now);
    __now += 10000;
    quicloss_on_sent(&loss, QUIC_ENC_APP, 1, 1200, 1, 1, NULL, __now);
    __now += 10000;

    quicrange_add(&acked, 1, 1);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    /* One acknowledgement of a newer packet is enough: the time threshold is
     * 9/8 of the RTT, and 20 ms of it has passed. */
    TEST_ASSERT(lost != NULL && lost->type == QUIC_FRAME_NEW_CONNECTION_ID,
                "the stranded packet came back for retransmission");
    quicframe_ref_free(lost);
    lost = NULL;

    quic_enc_level_e level = QUIC_ENC_INITIAL;

    TEST_CASE("and with nothing left in flight the timers disarm");
    TEST_ASSERT(quicloss_timeout(&loss, __now) == 0, "disarmed");

    TEST_CASE("a packet nobody acknowledges past is reached by the PTO");
    /* The live case: the peer has nothing ack-eliciting to acknowledge, so no
     * later acknowledgement ever arrives and the branch above never runs. The
     * PTO is the only thing left, and it must arm. */
    quicloss_free(&loss);
    quicloss_init(&loss, &cc, 25000);
    loss.handshake_confirmed = 1;

    quicloss_on_sent(&loss, QUIC_ENC_APP, 0, 1200, 1, 1, NULL, __now);

    const uint64_t pto = quicloss_timeout(&loss, __now);
    TEST_ASSERT(pto > __now, "PTO armed with one packet in flight");

    __now = pto + 1;
    TEST_ASSERT(quicloss_on_timeout(&loss, __now, &lost, &level) == 0, "a PTO");
    TEST_ASSERT(level == QUIC_ENC_APP, "naming the application space");
    TEST_ASSERT(loss.pto_count == 1, "backoff moved");

    TEST_CASE("sending the probe does not disarm the PTO");
    /* The probe is itself ack-eliciting and in flight, so the timer has to stay
     * armed -- otherwise one lost probe strands the connection exactly as the
     * original packet did. */
    quicloss_on_sent(&loss, QUIC_ENC_APP, 1, 30, 1, 1, NULL, __now);
    TEST_ASSERT(quicloss_timeout(&loss, __now) > __now, "still armed after the probe");

    quicrange_free(&acked);
    quicloss_free(&loss);
    quic_time_set_source(NULL);
}

TEST(test_quic_loss_spaces) {
    TEST_SUITE("quic_loss");

    quic_time_set_source(__clock);
    __now = 1000000;

    quiccc_t cc;
    quiccc_init(&cc, MTU);

    quicloss_t loss;
    quicloss_init(&loss, &cc, 25000);

    TEST_CASE("packet numbers are per space");
    /* Initial, Handshake and Application number independently; sharing a
     * counter would make loss detection compare packets that never raced. */
    quicloss_on_sent(&loss, QUIC_ENC_INITIAL, 0, 1200, 1, 1, NULL, __now);
    quicloss_on_sent(&loss, QUIC_ENC_HANDSHAKE, 0, 1200, 1, 1, NULL, __now);

    quicrange_t acked;
    quicrange_init(&acked, 0);
    quicrange_add(&acked, 0, 0);
    quicframe_ref_t* lost = NULL;

    quicloss_on_ack(&loss, QUIC_ENC_INITIAL, &acked, 0, __now, &lost, NULL);
    TEST_ASSERT(loss.space[QUIC_ENC_INITIAL].sent_count == 0, "Initial acknowledged");
    TEST_ASSERT(loss.space[QUIC_ENC_HANDSHAKE].sent_count == 1,
                "Handshake untouched by the same packet number");

    TEST_CASE("discarding a space returns its outstanding frames");
    /* §4.9: when Initial keys go, nothing in that space can ever be
     * acknowledged -- but its CRYPTO data still has to reach the peer, at the
     * next level. Dropping it would stall the handshake silently. */
    quicframe_ref_t* ref = quicframe_ref_new(QUIC_FRAME_CRYPTO);
    ref->offset = 0;
    ref->len = 500;
    quicloss_on_sent(&loss, QUIC_ENC_INITIAL, 1, 1200, 1, 1, ref, __now);

    const uint64_t in_flight_before = cc.bytes_in_flight;
    TEST_ASSERT(in_flight_before > 0, "something is in flight");

    quicframe_ref_t* returned = quicloss_discard_space(&loss, QUIC_ENC_INITIAL);
    TEST_ASSERT(returned != NULL, "frames came back");
    TEST_ASSERT(returned->type == QUIC_FRAME_CRYPTO && returned->len == 500, "intact");
    quicframe_ref_free(returned);

    TEST_ASSERT(cc.bytes_in_flight < in_flight_before,
                "and the bytes stopped counting against the window");

    quicrange_free(&acked);
    quicloss_free(&loss);
    quic_time_set_source(NULL);
}

/* A controller that records what loss detection told it, so the estimator can
 * be checked directly rather than through BBR's reaction to it. */
static quiccc_sample_t __probe_sample;
static int __probe_calls = 0;

static void __probe_on_sent(quiccc_t* cc, size_t bytes) {
    cc->bytes_in_flight += bytes;
}

static void __probe_on_ack(quiccc_t* cc, size_t bytes, uint64_t sent_us,
                           uint64_t now_us) {
    (void)sent_us; (void)now_us;
    if (cc->bytes_in_flight >= bytes) cc->bytes_in_flight -= bytes;
    else cc->bytes_in_flight = 0;
}

static void __probe_on_loss(quiccc_t* cc, size_t bytes, uint64_t sent_us,
                            uint64_t now_us) {
    __probe_on_ack(cc, bytes, sent_us, now_us);
}

static void __probe_noop(quiccc_t* cc) { (void)cc; }

static void __probe_on_ack_end(quiccc_t* cc, const quiccc_sample_t* sample,
                               uint64_t now_us) {
    (void)cc; (void)now_us;
    __probe_sample = *sample;
    __probe_calls++;
}

static const quiccc_ops_t __probe_ops = {
    .on_sent = __probe_on_sent,
    .on_ack = __probe_on_ack,
    .on_loss = __probe_on_loss,
    .on_persistent_congestion = __probe_noop,
    .on_pto = __probe_noop,
    .on_ack_end = __probe_on_ack_end
};

TEST(test_quic_delivery_rate) {
    TEST_SUITE("quic_loss");

    /* Delivery rate sampling (draft-cheng-iccrg-delivery-rate-estimation).
     *
     * The rate is bytes delivered over the interval they took to be delivered,
     * and neither end of that interval is visible in the acknowledgement -- the
     * sender has to have written both down when it sent the packet. This is the
     * measurement BBR is built on; if it is wrong, BBR is wrong quietly. */

    quic_time_set_source(__clock);
    __now = 1000000;

    quiccc_t cc;
    quiccc_init(&cc, MTU);
    cc.ops = &__probe_ops;
    __probe_calls = 0;

    quicloss_t loss;
    quicloss_init(&loss, &cc, 25000);
    loss.handshake_confirmed = 1;

    quicrange_t acked;
    quicrange_init(&acked, 0);
    quicframe_ref_t* lost = NULL;

    TEST_CASE("a packet carries the delivery state it was sent under");
    const uint64_t start = __now;
    for (uint64_t pn = 0; pn < 10; pn++)
        quicloss_on_sent(&loss, QUIC_ENC_APP, pn, 1200, 1, 1, NULL, start + pn * 1000);

    TEST_ASSERT(loss.first_sent_us == start,
                "an empty path starts a new send interval");
    TEST_ASSERT(loss.delivered == 0, "nothing delivered yet");

    TEST_CASE("half the flight is acknowledged one round trip later");
    __now = start + 100000;
    quicrange_add(&acked, 0, 4);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    TEST_ASSERT(__probe_calls == 1, "the controller heard one acknowledgement");
    TEST_ASSERT(loss.delivered == 6000, "five datagrams delivered");
    TEST_ASSERT(__probe_sample.acked_bytes == 6000, "and reported as such");
    /* The largest acknowledged packet went out 4 ms after the first one. */
    TEST_ASSERT(__probe_sample.rtt_us == 96000, "with the round trip it produced");
    /* 6000 bytes over the 100 ms it took them to be acknowledged. */
    TEST_ASSERT_EQUAL_UINT(60000, __probe_sample.delivery_rate,
                           "bytes delivered over the interval that delivered them");
    TEST_ASSERT(__probe_sample.prior_in_flight == 12000,
                "the path was full when the acknowledgement arrived");

    TEST_CASE("an interval shorter than one round trip is not a rate");
    /* It times an acknowledgement's arrival, not a path's throughput. Dividing
     * by it reports rates the path never carried, and BBR would adopt the
     * largest of them for ten round trips. */
    __now = start + 150000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 5, 9);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);
    TEST_ASSERT(cc.bytes_in_flight == 0, "the path is empty again");

    /* Sent into an empty path and acknowledged a millisecond later, on a path
     * whose round trip is known to be 96 ms. Not ack-eliciting, so it produces
     * no RTT sample of its own -- otherwise the 1 ms *would* be the round trip
     * and the rate it implies would be real. */
    quicloss_on_sent(&loss, QUIC_ENC_APP, 10, 1200, 0, 1, NULL, __now);
    __now += 1000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 10, 10);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    TEST_ASSERT_EQUAL_UINT(0, __probe_sample.delivery_rate, "discarded as noise");
    TEST_ASSERT(__probe_sample.acked_bytes == 1200, "though the bytes still count");

    TEST_CASE("losses in the same acknowledgement are reported with it");
    /* Half of what an acknowledgement says is what it does not contain, and a
     * controller deciding on rate has to see both at once. */
    for (uint64_t pn = 11; pn < 20; pn++)
        quicloss_on_sent(&loss, QUIC_ENC_APP, pn, 1200, 1, 1, NULL, __now);

    __now += 100000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 19, 19);      /* the rest are three behind: lost */
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    TEST_ASSERT(__probe_sample.lost_bytes > 0, "the gap was reported as loss");
    TEST_ASSERT(__probe_sample.acked_bytes == 1200, "alongside what did arrive");
    quicframe_ref_free(lost);
    lost = NULL;

    TEST_CASE("a sender that runs out of data marks its samples");
    /* Otherwise an idle moment is indistinguishable from a slow path, and the
     * bandwidth estimate follows the application instead of the network. */
    quicloss_app_limited(&loss);
    TEST_ASSERT(loss.app_limited != 0, "marked while the window is open");

    quicloss_on_sent(&loss, QUIC_ENC_APP, 20, 1200, 1, 1, NULL, __now);
    __now += 100000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 20, 20);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    TEST_ASSERT(__probe_sample.app_limited, "the sample says so");

    TEST_CASE("and stops marking them once it is busy again");
    /* The mark sits past whatever was already in flight when the sender went
     * quiet, so it survives the acknowledgements for that data and clears only
     * once the connection has delivered more than it -- packets sent during the
     * idle period are still application-limited when they come back. */
    for (uint64_t pn = 21; pn < 40; pn++) {
        quicloss_on_sent(&loss, QUIC_ENC_APP, pn, 1200, 1, 1, NULL, __now);
        __now += 1000;
    }
    __now += 100000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 21, 39);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);
    TEST_ASSERT(loss.app_limited == 0, "the mark cleared");

    /* Sent after the mark cleared, so this one measures the path. */
    quicloss_on_sent(&loss, QUIC_ENC_APP, 40, 1200, 1, 1, NULL, __now);
    __now += 100000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 40, 40);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost, NULL);

    TEST_ASSERT(!__probe_sample.app_limited, "and the samples measure the path again");
    TEST_ASSERT(__probe_sample.delivery_rate > 0, "which is a rate again");

    TEST_CASE("a window-limited sender is not application-limited");
    /* It has data and the controller is what is holding it back, so its samples
     * describe the path exactly and must be believed. */
    cc.cwnd = 1200;
    cc.bytes_in_flight = 2400;
    quicloss_app_limited(&loss);
    TEST_ASSERT(loss.app_limited == 0, "not marked");

    quicrange_free(&acked);
    quicframe_ref_free(lost);
    quicloss_free(&loss);
    quic_time_set_source(NULL);
}

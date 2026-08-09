#include "framework.h"

#include "quiccc.h"
#include "quicloss.h"
#include "quicpacket.h"
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

TEST(test_quic_pacer) {
    TEST_SUITE("quic_cc");

    quiccc_t cc;
    quiccc_init(&cc, MTU);

    quicpacer_t pacer;
    quicpacer_init(&pacer, MTU, 1);

    TEST_CASE("with no RTT sample the pacer does not delay the handshake");
    /* The first flight has nothing to pace against, and holding it back would
     * add a round trip to every connection. */
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 0, 1000) > 0, "allowed");

    TEST_CASE("the burst is bounded");
    quicpacer_init(&pacer, MTU, 1);
    const size_t allowance = quicpacer_allowance(&pacer, &cc, 50000, 1000000);
    TEST_ASSERT(allowance <= 10 * MTU, "at most ten datagrams at once");

    TEST_CASE("tokens are consumed and refill over time");
    quicpacer_init(&pacer, MTU, 1);
    __now = 1000000;
    quicpacer_allowance(&pacer, &cc, 50000, __now);
    quicpacer_consume(&pacer, 10 * MTU);
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 50000, __now) == 0,
                "nothing left immediately");

    /* One RTT later a full window's worth has been earned back. */
    __now += 50000;
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 50000, __now) > 0, "refilled");

    TEST_CASE("the pacer never exceeds the congestion window");
    quiccc_init(&cc, MTU);
    cc.ops->on_sent(&cc, cc.cwnd);       /* window full */
    quicpacer_init(&pacer, MTU, 1);
    TEST_ASSERT(quicpacer_allowance(&pacer, &cc, 50000, __now) == 0,
                "no allowance when the window is full");

    TEST_CASE("disabled, it reports the raw window");
    quiccc_init(&cc, MTU);
    quicpacer_init(&pacer, MTU, 0);
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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);

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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);

    TEST_ASSERT(loss.smoothed_rtt_us > 100000 && loss.smoothed_rtt_us < 130000,
                "moved a fraction of the way");
    TEST_ASSERT(loss.min_rtt_us == 100000, "the minimum is unchanged by a slower sample");

    TEST_CASE("min_rtt tracks downward immediately");
    quicloss_on_sent(&loss, QUIC_ENC_APP, 2, 1200, 1, 1, NULL, __now);
    __now += 20000;
    quicrange_clear(&acked);
    quicrange_add(&acked, 2, 2);
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);
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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 10000000, __now, &lost);

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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);

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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);
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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);
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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);

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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);
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
    quicloss_on_ack(&loss, QUIC_ENC_APP, &acked, 0, __now, &lost);

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

    quicloss_on_ack(&loss, QUIC_ENC_INITIAL, &acked, 0, __now, &lost);
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

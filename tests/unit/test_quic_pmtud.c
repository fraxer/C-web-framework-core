#include "framework.h"

#include <string.h>

#include "quicpmtud.h"

/* protocols/quic/transport/quicpmtud.c -- the DPLPMTUD state machine on its
 * own (the growth / black hole / ceiling walk is test_quic_dplpmtud in
 * test_quic_recovery.c). These are the edges the quic_pmtud fuzz target holds
 * it to on every step: the size stays within [base, ceiling], only the ACK of
 * the probe in flight raises it, and an event repeated with the same
 * arguments changes nothing. */

TEST(test_quic_pmtud_ceiling_below_base) {
    TEST_CASE("a ceiling below the base is the base: nothing to search");

    quicpmtud_t p;
    quicpmtud_init(&p, 1350, 1200);
    TEST_ASSERT_EQUAL_SIZE((size_t)1350, p.ceiling, "ceiling raised to the base");
    TEST_ASSERT(!quicpmtud_should_probe(&p, 0), "no probe");
    TEST_ASSERT_EQUAL((uint64_t)0, quicpmtud_deadline(&p), "no deadline");
}

TEST(test_quic_pmtud_stale_ack) {
    TEST_CASE("the ACK of a probe already given up on raises nothing");

    quicpmtud_t p;
    quicpmtud_init(&p, 1350, 1472);
    quicpmtud_candidate(&p);
    quicpmtud_on_probe_sent(&p, 7, 1000, 100);
    TEST_ASSERT(quicpmtud_deadline(&p) == 1300, "deadline three PTOs out");
    TEST_ASSERT_EQUAL(0, quicpmtud_on_timeout(&p, 1299), "not yet");
    TEST_ASSERT(quicpmtud_on_timeout(&p, 1300) & QUICPMTUD_PROBE_LOST, "lost at the deadline");
    TEST_ASSERT_EQUAL(0, quicpmtud_on_ack(&p, 7, 1400, 100), "late ACK of the lost probe");
    TEST_ASSERT_EQUAL_SIZE((size_t)1350, p.current, "size unchanged");
}

TEST(test_quic_pmtud_repeated_events) {
    TEST_CASE("an ACK, a timeout or a black hole seen twice acts once");

    quicpmtud_t p, before;
    quicpmtud_init(&p, 1350, 1472);
    quicpmtud_candidate(&p);
    quicpmtud_on_probe_sent(&p, 9, 1000, 100);

    TEST_ASSERT(quicpmtud_on_ack(&p, 9, 1100, 100), "first ACK");
    memcpy(&before, &p, sizeof p);
    TEST_ASSERT_EQUAL(0, quicpmtud_on_ack(&p, 9, 1100, 100), "second ACK");
    TEST_ASSERT(memcmp(&before, &p, sizeof p) == 0, "state unchanged");

    TEST_ASSERT(quicpmtud_on_blackhole(&p, 2000, 100), "first black hole");
    memcpy(&before, &p, sizeof p);
    TEST_ASSERT_EQUAL(0, quicpmtud_on_blackhole(&p, 2000, 100), "second black hole");
    TEST_ASSERT(memcmp(&before, &p, sizeof p) == 0, "state unchanged");

    quicpmtud_candidate(&p);
    quicpmtud_on_probe_sent(&p, 10, 5000, 100);
    TEST_ASSERT(quicpmtud_on_timeout(&p, 5300), "first timeout");
    memcpy(&before, &p, sizeof p);
    TEST_ASSERT_EQUAL(0, quicpmtud_on_timeout(&p, 5300), "second timeout");
    TEST_ASSERT(memcmp(&before, &p, sizeof p) == 0, "state unchanged");
}

TEST(test_quic_pmtud_candidate_bounds) {
    TEST_CASE("a probe is always above the size in use and within the ceiling");

    quicpmtud_t p;
    quicpmtud_init(&p, 1350, 1472);
    const size_t c = quicpmtud_candidate(&p);
    TEST_ASSERT(c > p.current && c <= p.ceiling, "first candidate");
    quicpmtud_on_probe_sent(&p, 1, 0, 100);
    TEST_ASSERT_EQUAL_SIZE(c, quicpmtud_candidate(&p), "stable while in flight");
    TEST_ASSERT(!quicpmtud_should_probe(&p, 1000000), "one probe at a time");
}

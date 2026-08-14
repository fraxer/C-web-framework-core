#include "framework.h"

#include "quic.h"
#include "quicendpoint.h"

/* The connection defaults (docs/http3/07-integration.md §1.2).
 *
 * What the operator sets is checked live -- a transport parameter rides inside
 * the encrypted handshake, so the only honest way to see it is a peer that
 * reads it back, which is what tests/quicclient prints. What can be checked
 * here is the half that has no operator in it: that the defaults exist before
 * quic_policy_init() has run, and that they satisfy the invariants the rest of
 * the stack assumes about them.
 *
 * That first part is not hypothetical. Every unit test that builds a connection
 * reaches quic_policy_conn() without any config behind it, and a zeroed struct
 * there would advertise a connection that allows no streams and no data -- a
 * failure that looks like a protocol bug, three layers away from its cause. */

TEST(test_quic_policy_defaults) {
    TEST_SUITE("quic_policy");

    TEST_CASE("the defaults are there before any config is loaded");
    const quic_conn_policy_t* p = quic_policy_conn();

    TEST_REQUIRE(p != NULL, "policy is never NULL");

    TEST_ASSERT(p->idle_timeout_ms > 0, "an idle timeout exists");
    TEST_ASSERT(p->initial_max_data > 0, "a connection window exists");
    TEST_ASSERT(p->initial_max_stream_data > 0, "a stream window exists");
    TEST_ASSERT(p->max_streams_bidi > 0, "a client may open a request stream");

    TEST_CASE("HTTP/3 needs three unidirectional streams before it can answer");
    /* Control plus both QPACK streams (RFC 9114 §6.2, RFC 9204 §4.2). A limit
     * below three does not degrade the connection, it makes it unusable, which
     * is why this is a floor and not a default. */
    TEST_ASSERT(p->max_streams_uni >= 3, "at least the three service streams");

    TEST_CASE("the packet size stays inside what the code can carry");
    /* Below §14's minimum an Initial cannot even be padded to a legal size;
     * above the build's packet buffer we would be advertising room that does
     * not exist. */
    TEST_ASSERT(p->max_udp_payload_size >= QUIC_MIN_INITIAL_DATAGRAM,
                "at least the RFC 9000 §14 minimum");
    TEST_ASSERT(p->max_udp_payload_size <= QUIC_DEFAULT_UDP_PAYLOAD,
                "no larger than the packet buffer quicconn builds into");

    TEST_CASE("the auto-tuning ceiling is above the window it tunes");
    /* quicflow_init_recv takes both, and a ceiling under the starting window
     * would mean a window that can only ever shrink. */
    TEST_ASSERT(p->recv_window_max >= p->initial_max_data,
                "the ceiling is not below the start");

    TEST_CASE("max_ack_delay fits the field that carries it");
    /* §18.2 encodes it in 14 bits of milliseconds. */
    TEST_ASSERT(p->ack_delay_ms <= 16383, "within 2^14 - 1 ms");

    TEST_CASE("anti-amplification defaults to what the RFC requires");
    /* §8.1 says three. The key exists so a test can lower it; the default must
     * never be anything else, and this is what says so. */
    TEST_ASSERT(p->amplification_factor == 3, "three times what the peer sent");

    TEST_CASE("the active connection id limit is at least the RFC minimum");
    /* §18.2: a peer may not advertise less than 2. */
    TEST_ASSERT(p->active_cid_limit >= 2, "at least two");
}

TEST(test_quic_process_connection_limit) {
    TEST_SUITE("quic_policy");
    TEST_CASE("connection admission is shared process-wide and rolls back");

    const size_t limit = quic_process_conn_limit();
    TEST_REQUIRE(limit >= 64, "configured/default process limit is valid");
    TEST_ASSERT_EQUAL_SIZE(0, quic_process_conn_current(), "starts empty");

    size_t acquired = 0;
    while (acquired < limit && quic_process_conn_try_acquire()) acquired++;

    TEST_ASSERT_EQUAL_SIZE(limit, acquired, "all process slots acquired once");
    TEST_ASSERT(!quic_process_conn_try_acquire(), "next endpoint is refused at the same limit");
    TEST_ASSERT_EQUAL_SIZE(limit, quic_process_conn_current(), "failed reservation does not increment");

    while (acquired-- > 0) quic_process_conn_release();
    TEST_ASSERT_EQUAL_SIZE(0, quic_process_conn_current(), "all reservations rolled back");
}

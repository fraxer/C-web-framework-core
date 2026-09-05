#include "framework.h"

#include "quicack.h"
#include "quicflow.h"
#include "quicstream.h"

#include <string.h>

/* Acknowledgement bookkeeping, flow control and stream state.
 *
 * The error codes matter as much as the behaviour: RFC 9000 gives each of these
 * situations its own code, and a peer implementer reads that code to find their
 * own bug. Reporting everything as PROTOCOL_VIOLATION tells them nothing --
 * the same reasoning that split FRAME_SIZE_ERROR out in the HTTP/2 frame parser
 * (docs/http2/08, phase C.1). */

TEST(test_quic_ack) {
    TEST_SUITE("quic_ack");

    quicack_t ack;
    quicack_init(&ack);

    TEST_CASE("duplicates are detected");
    /* The AEAD cannot tell a replayed packet from the original -- it *is* the
     * original. This check is the only thing standing between a captured
     * packet and its frames being applied twice. */
    TEST_ASSERT(!quicack_is_duplicate(&ack, 5), "not seen yet");
    quicack_on_received(&ack, QUIC_ENC_APP, 5, 1, 1000, 25000);
    TEST_ASSERT(quicack_is_duplicate(&ack, 5), "seen now");
    TEST_ASSERT(!quicack_is_duplicate(&ack, 6), "and only that one");

    TEST_CASE("a number the bounded set has forgotten is refused, not accepted");
    /* The set holds QUICACK_MAX_RANGES intervals and no more, so a peer that
     * sends a comb of gaps can push the low end out of it. If that made an old
     * number look new, the eviction would be the way *through* this check
     * rather than a defence against the memory attack it exists for. */
    quicack_free(&ack);
    quicack_init(&ack);
    for (uint64_t pn = 0; pn < QUICACK_MAX_RANGES * 4; pn += 2)
        quicack_on_received(&ack, QUIC_ENC_APP, pn, 1, 1000, 25000);

    TEST_ASSERT(!quicrange_contains(&ack.received, 0), "the oldest is no longer held");
    TEST_ASSERT(quicack_is_duplicate(&ack, 0), "and a replay of it is still refused");
    TEST_ASSERT(quicack_is_duplicate(&ack, QUICACK_MAX_RANGES * 4 - 2),
                "while the newest is refused because it is held");

    TEST_CASE("a single ack-eliciting packet is held briefly");
    /* Batching acknowledgements is worth a few milliseconds of delay; sending
     * one per packet doubles the packet count on a busy connection. */
    quicack_free(&ack);
    quicack_init(&ack);
    quicack_on_received(&ack, QUIC_ENC_APP, 0, 1, 1000, 25000);
    TEST_ASSERT(!quicack_should_send(&ack, 1000), "not immediately");
    TEST_ASSERT(quicack_should_send(&ack, 1000 + 25000), "but by the deadline");

    TEST_CASE("two ack-eliciting packets force an immediate ACK (§13.2.1)");
    quicack_free(&ack);
    quicack_init(&ack);
    quicack_on_received(&ack, QUIC_ENC_APP, 0, 1, 1000, 25000);
    quicack_on_received(&ack, QUIC_ENC_APP, 1, 1, 1100, 25000);
    TEST_ASSERT(quicack_should_send(&ack, 1100), "immediately");

    TEST_CASE("reordering forces an immediate ACK");
    /* The peer needs to learn about the gap without waiting: its loss
     * detection is driven by what our ACKs report. */
    quicack_free(&ack);
    quicack_init(&ack);
    quicack_on_received(&ack, QUIC_ENC_APP, 5, 1, 1000, 25000);
    quicack_on_sent(&ack);
    quicack_on_received(&ack, QUIC_ENC_APP, 3, 1, 1100, 25000);
    TEST_ASSERT(quicack_should_send(&ack, 1100), "immediately");

    TEST_CASE("handshake ACKs are never delayed");
    /* Delaying one adds directly to the time to first byte, and the peer is
     * blocked on it. */
    quicack_free(&ack);
    quicack_init(&ack);
    quicack_on_received(&ack, QUIC_ENC_INITIAL, 0, 1, 1000, 25000);
    TEST_ASSERT(quicack_should_send(&ack, 1000), "immediately");

    TEST_CASE("a packet that is not ack-eliciting does not schedule anything");
    /* Otherwise two endpoints exchanging only ACKs would acknowledge each
     * other forever (§13.2.1). */
    quicack_free(&ack);
    quicack_init(&ack);
    quicack_on_received(&ack, QUIC_ENC_APP, 0, 0, 1000, 25000);
    TEST_ASSERT(!quicack_should_send(&ack, 1000 + 100000), "nothing owed");

    TEST_CASE("the frame reports the ranges received");
    quicack_free(&ack);
    quicack_init(&ack);
    quicack_on_received(&ack, QUIC_ENC_APP, 0, 1, 1000, 25000);
    quicack_on_received(&ack, QUIC_ENC_APP, 1, 1, 1000, 25000);
    quicack_on_received(&ack, QUIC_ENC_APP, 5, 1, 1000, 25000);

    uint8_t buf[128];
    const size_t n = quicack_write(&ack, buf, sizeof buf, 1000, 3);
    TEST_ASSERT(n > 0, "written");

    quicframe_t f;
    size_t off = 0;
    TEST_ASSERT(quicframe_next(buf, n, &off, &f) == QUICFRAME_OK, "parses");
    TEST_ASSERT(f.u.ack.largest == 5, "largest");
    TEST_ASSERT(f.u.ack.range_count == 1, "one gap");

    quicack_iter_t it;
    quicack_block_t block;
    quicack_iter_init(&f, &it);
    TEST_ASSERT(quicack_iter_next(&it, &block) == 1 && block.largest == 5 &&
                block.smallest == 5, "the 5 range");
    TEST_ASSERT(quicack_iter_next(&it, &block) == 1 && block.largest == 1 &&
                block.smallest == 0, "the 0..1 range");

    TEST_CASE("the reported delay is scaled by the peer's exponent");
    /* The field is small; the exponent is what lets it express long delays. */
    const size_t m = quicack_write(&ack, buf, sizeof buf, 1000 + 8000, 3);
    off = 0;
    quicframe_next(buf, m, &off, &f);
    TEST_ASSERT(f.u.ack.delay == 1000, "8000 us >> 3");

    TEST_CASE("sending clears what was owed");
    quicack_on_sent(&ack);
    TEST_ASSERT(!quicack_should_send(&ack, 1000 + 100000), "nothing owed");
    /* But the record of what arrived stays: the next ACK must still report it,
     * since an ACK may itself be lost. */
    TEST_ASSERT(quicack_is_duplicate(&ack, 5), "still remembered");

    quicack_free(&ack);

    TEST_CASE("the number of remembered ranges is bounded");
    /* A peer losing every other packet creates one range per gap. Unbounded,
     * that is memory the peer controls. */
    quicack_init(&ack);
    for (uint64_t pn = 0; pn < 200; pn += 2)
        quicack_on_received(&ack, QUIC_ENC_APP, pn, 1, 1000, 25000);

    TEST_ASSERT(quicrange_count(&ack.received) <= QUICACK_MAX_RANGES, "capped");
    TEST_ASSERT(quicack_is_duplicate(&ack, 198), "the newest is still known");

    quicack_free(&ack);
}

TEST(test_quic_flow) {
    TEST_SUITE("quic_flow");

    quicflow_t flow;

    TEST_CASE("the send side is bounded by the peer's limit");
    quicflow_init_send(&flow, 1000);
    TEST_ASSERT(quicflow_available(&flow) == 1000, "all of it");
    quicflow_consume(&flow, 600);
    TEST_ASSERT(quicflow_available(&flow) == 400, "reduced");
    quicflow_consume(&flow, 400);
    TEST_ASSERT(quicflow_available(&flow) == 0, "exhausted");

    TEST_CASE("the send window is spent by offset, not by traffic (§4.1)");
    /* A retransmission reoccupies offsets it has already paid for. Charging it
     * again spends a window the peer never saw used -- and on a lossy path that
     * window shrinks with every loss until the transfer stops with data still
     * to send. Found by the interop runner: a 500 KB transfer at 30 % loss
     * stalled at 372 KB with the stream window "exhausted" (docs/http3/08 §3f). */
    quicflow_init_send(&flow, 1000);
    TEST_ASSERT(quicflow_consume_to(&flow, 400) == 400, "first send advances by all of it");
    TEST_ASSERT(quicflow_available(&flow) == 600, "600 left");
    TEST_ASSERT(quicflow_consume_to(&flow, 400) == 0, "resending the same range costs nothing");
    TEST_ASSERT(quicflow_available(&flow) == 600, "still 600");
    TEST_ASSERT(quicflow_consume_to(&flow, 250) == 0, "nor does resending part of it");
    TEST_ASSERT(quicflow_available(&flow) == 600, "still 600");
    TEST_ASSERT(quicflow_consume_to(&flow, 700) == 300, "only the new offsets are charged");
    TEST_ASSERT(quicflow_available(&flow) == 300, "300 left");

    /* Back to where the first case left it: limit 1000, fully spent. */
    quicflow_init_send(&flow, 1000);
    quicflow_consume(&flow, 1000);

    TEST_CASE("limits only ever grow (§4.1)");
    /* A reordered MAX_DATA carrying an older value must not shrink the window:
     * shrinking below what has already been sent is unrecoverable. */
    TEST_ASSERT(quicflow_update_limit(&flow, 2000), "grew");
    TEST_ASSERT(quicflow_available(&flow) == 1000, "new allowance");
    TEST_ASSERT(!quicflow_update_limit(&flow, 1500), "a smaller limit is ignored");
    TEST_ASSERT(quicflow_available(&flow) == 1000, "unchanged");

    TEST_CASE("BLOCKED is reported once per limit");
    /* One per blocked packet would be a flood; the peer only needs telling
     * once that we are stuck at a particular value. */
    quicflow_consume(&flow, 1000);
    TEST_ASSERT(quicflow_should_send_blocked(&flow), "first time");
    TEST_ASSERT(!quicflow_should_send_blocked(&flow), "not again");

    quicflow_update_limit(&flow, 3000);
    quicflow_consume(&flow, 1000);
    TEST_ASSERT(quicflow_should_send_blocked(&flow), "but again at a new limit");

    TEST_CASE("the receive side counts the highest offset, not the bytes");
    /* A retransmission must not consume the window twice, and out-of-order
     * data consumes it up to its far end. */
    quicflow_init_recv(&flow, 1000, 8000);
    TEST_ASSERT(quicflow_record_received(&flow, 500), "first");
    TEST_ASSERT(quicflow_record_received(&flow, 300), "a retransmission behind it");
    TEST_ASSERT(flow.used == 500, "the window is unchanged by it");

    TEST_CASE("exceeding the advertised limit is an error");
    TEST_ASSERT(!quicflow_record_received(&flow, 1001), "past the limit");
    TEST_ASSERT(quicflow_record_received(&flow, 1000), "exactly at it is fine");

    TEST_CASE("credit is issued for what the application has taken, not for what arrived");
    /* Later and the peer stalls waiting for credit it has earned; earlier and
     * we spend frames saying nothing new -- or worse, credit the peer for
     * bytes that are still sitting in our receive buffer, which is memory we
     * have not got back. */
    quicflow_init_recv(&flow, 1000, 8000);
    quicflow_record_received(&flow, 400);
    uint64_t limit = 0;
    TEST_ASSERT(!quicflow_should_update(&flow, &limit), "not yet at 40%");

    quicflow_record_received(&flow, 600);
    TEST_ASSERT(!quicflow_should_update(&flow, &limit),
                "the window is spent, but the application still holds every byte of it");

    quicflow_consumed(&flow, 600, 0, 0);
    TEST_ASSERT(quicflow_should_update(&flow, &limit), "now");
    TEST_ASSERT(limit == 1600, "a fresh window beyond what has been read");

    quicflow_update_sent(&flow, limit);
    TEST_ASSERT(!quicflow_should_update(&flow, &limit), "and nothing more is owed");

    TEST_CASE("a stream nobody will ever read gives its credit back");
    /* The tail a RESET_STREAM abandons frees no buffer, but it is equally never
     * coming back. Without this the connection window shrinks by the abandoned
     * remainder of every cancelled stream, permanently. */
    quicflow_init_recv(&flow, 1000, 8000);
    quicflow_record_received(&flow, 800);
    quicflow_consumed(&flow, 300, 0, 0);
    TEST_ASSERT(quicflow_abandon(&flow, 800) == 500, "the unread remainder");
    TEST_ASSERT(quicflow_abandon(&flow, 800) == 0, "and only once");
    TEST_ASSERT(quicflow_should_update(&flow, &limit), "the whole stream is accounted for");
    TEST_ASSERT(limit == 1800, "so the peer gets a full window beyond it");

    TEST_CASE("abandoning cannot credit more than arrived");
    quicflow_init_recv(&flow, 1000, 8000);
    quicflow_record_received(&flow, 200);
    TEST_ASSERT(quicflow_abandon(&flow, 900) == 200, "clamped to the highest offset seen");

    TEST_CASE("the window grows when the peer can exhaust it inside a round trip");
    /* If the window empties faster than the path can refill it, the window is
     * what limits the transfer rather than the network. */
    quicflow_init_recv(&flow, 1000, 8000);
    const uint64_t before = flow.auto_window;
    quicflow_consumed(&flow, 1000, 100000, 50000);   /* half an RTT */
    TEST_ASSERT(flow.auto_window > before, "grew");

    TEST_CASE("and does not grow when it is not the bottleneck");
    quicflow_init_recv(&flow, 1000, 8000);
    quicflow_consumed(&flow, 1000, 100000, 500000);  /* five RTTs */
    TEST_ASSERT(flow.auto_window == 1000, "unchanged");

    TEST_CASE("growth stops at the configured maximum");
    quicflow_init_recv(&flow, 1000, 2000);
    for (int i = 0; i < 10; i++) quicflow_consumed(&flow, 1000, 100000, 1000);
    TEST_ASSERT(flow.auto_window == 2000, "capped");
}

TEST(test_quic_stream_ids) {
    TEST_SUITE("quic_stream");

    TEST_CASE("the two low bits encode who opened it and whether it is two-way");
    TEST_ASSERT(quic_stream_kind(0) == QUIC_STREAM_CLIENT_BIDI, "0");
    TEST_ASSERT(quic_stream_kind(1) == QUIC_STREAM_SERVER_BIDI, "1");
    TEST_ASSERT(quic_stream_kind(2) == QUIC_STREAM_CLIENT_UNI, "2");
    TEST_ASSERT(quic_stream_kind(3) == QUIC_STREAM_SERVER_UNI, "3");
    TEST_ASSERT(quic_stream_kind(4) == QUIC_STREAM_CLIENT_BIDI, "4 wraps round");

    TEST_CASE("the index within a kind");
    /* Opening stream 12 implicitly opens 0, 4 and 8 (§2.1) -- a client may skip
     * ids it decided not to use, and a server that does not follow fails
     * against real ones. */
    TEST_ASSERT(quic_stream_index(0) == 0, "first");
    TEST_ASSERT(quic_stream_index(4) == 1, "second");
    TEST_ASSERT(quic_stream_index(12) == 3, "fourth");

    TEST_CASE("direction");
    TEST_ASSERT(!quic_stream_is_uni(0) && !quic_stream_is_uni(1), "bidirectional");
    TEST_ASSERT(quic_stream_is_uni(2) && quic_stream_is_uni(3), "unidirectional");
    TEST_ASSERT(quic_stream_is_peer_initiated(0), "client bidi");
    TEST_ASSERT(!quic_stream_is_peer_initiated(3), "server uni");

    TEST_CASE("what a server may do with each kind");
    /* Using a unidirectional stream the wrong way is STREAM_STATE_ERROR, not
     * merely odd -- it is how a confused peer reveals itself. */
    TEST_ASSERT(quicstream_can_receive(0) && quicstream_can_send(0), "client bidi: both");
    TEST_ASSERT(quicstream_can_receive(2) && !quicstream_can_send(2),
                "client uni: receive only");
    TEST_ASSERT(!quicstream_can_receive(3) && quicstream_can_send(3),
                "server uni: send only");
}

TEST(test_quic_stream_recv) {
    TEST_SUITE("quic_stream");

    TEST_CASE("data arrives and is read in order");
    quicstream_t* s = quicstream_create(0, 1000, 8000, 1000);
    TEST_REQUIRE_NOT_NULL(s, "created");

    TEST_ASSERT(quicstream_on_data(s, 5, (const uint8_t*)"world", 5, 0)
                == QUICSTREAM_OK, "later piece");
    TEST_ASSERT(quicstream_readable(s) == 0, "nothing readable across the hole");

    TEST_ASSERT(quicstream_on_data(s, 0, (const uint8_t*)"hello", 5, 0)
                == QUICSTREAM_OK, "the gap is filled");
    TEST_ASSERT(quicstream_readable(s) == 10, "both");

    uint8_t out[32];
    TEST_ASSERT(quicstream_read(s, out, sizeof out) == 10, "read");
    TEST_ASSERT(memcmp(out, "helloworld", 10) == 0, "in order");

    TEST_CASE("the FIN moves the state through to complete");
    TEST_ASSERT(quicstream_on_data(s, 10, (const uint8_t*)"!", 1, 1)
                == QUICSTREAM_OK, "final piece");
    TEST_ASSERT(s->recv_state == QUIC_RECV_DATA_RECVD, "everything is here");
    quicstream_read(s, out, sizeof out);
    TEST_ASSERT(s->recv_state == QUIC_RECV_DATA_READ, "and taken");

    TEST_CASE("data past the final size is FINAL_SIZE_ERROR");
    TEST_ASSERT(quicstream_on_data(s, 11, (const uint8_t*)"x", 1, 0)
                == QUIC_FINAL_SIZE_ERROR, "refused with the right code");
    quicstream_free(s);

    TEST_CASE("overrunning the flow control window is FLOW_CONTROL_ERROR");
    s = quicstream_create(0, 100, 100, 1000);
    uint8_t big[200];
    memset(big, 'x', sizeof big);
    TEST_ASSERT(quicstream_on_data(s, 0, big, 200, 0) == QUIC_FLOW_CONTROL_ERROR,
                "refused with the right code");
    quicstream_free(s);

    TEST_CASE("receiving on a stream we may only send on is STREAM_STATE_ERROR");
    /* Stream 3 is server-initiated unidirectional: the peer has no business
     * writing to it. */
    s = quicstream_create(3, 1000, 8000, 1000);
    TEST_ASSERT(quicstream_on_data(s, 0, (const uint8_t*)"x", 1, 0)
                == QUIC_STREAM_STATE_ERROR, "refused with the right code");
    quicstream_free(s);

    TEST_CASE("a reset ends the receive side and hides partial data");
    /* Handing over a prefix would look to the application like a truncated
     * message rather than an aborted one. */
    s = quicstream_create(0, 1000, 8000, 1000);
    quicstream_on_data(s, 0, (const uint8_t*)"partial", 7, 0);
    TEST_ASSERT(quicstream_readable(s) == 7, "readable before the reset");

    TEST_ASSERT(quicstream_on_reset(s, 0x42, 7) == QUICSTREAM_OK, "reset");
    TEST_ASSERT(s->recv_state == QUIC_RECV_RESET_RECVD, "state");
    TEST_ASSERT(s->recv_reset_code == 0x42, "code carried");
    TEST_ASSERT(quicstream_readable(s) == 0, "nothing readable after it");
    quicstream_free(s);

    TEST_CASE("a reset claiming less than what arrived is FINAL_SIZE_ERROR");
    s = quicstream_create(0, 1000, 8000, 1000);
    quicstream_on_data(s, 0, (const uint8_t*)"abcdef", 6, 0);
    TEST_ASSERT(quicstream_on_reset(s, 0, 3) == QUIC_FINAL_SIZE_ERROR, "refused");
    quicstream_free(s);

    TEST_CASE("data arriving after a reset is ignored, not an error");
    /* It was already in flight when the reset was sent. */
    s = quicstream_create(0, 1000, 8000, 1000);
    quicstream_on_reset(s, 0, 10);
    TEST_ASSERT(quicstream_on_data(s, 0, (const uint8_t*)"late", 4, 0)
                == QUICSTREAM_OK, "accepted quietly");
    quicstream_free(s);
}

TEST(test_quic_stream_send) {
    TEST_SUITE("quic_stream");

    TEST_CASE("writing moves the state out of Ready");
    quicstream_t* s = quicstream_create(0, 1000, 8000, 1000);
    TEST_REQUIRE_NOT_NULL(s, "created");
    TEST_ASSERT(s->send_state == QUIC_SEND_READY, "starts ready");

    TEST_ASSERT(quicstream_write(s, (const uint8_t*)"data", 4), "written");
    TEST_ASSERT(s->send_state == QUIC_SEND_SEND, "sending");
    TEST_ASSERT(quicstream_wants_send(s), "has something to send");

    TEST_CASE("STOP_SENDING makes us reset the stream (§3.5)");
    /* Continuing to send would be ignored; the required response is a reset
     * carrying the code the peer asked for. */
    TEST_ASSERT(quicstream_on_stop_sending(s, 0x99) == QUICSTREAM_OK, "accepted");
    TEST_ASSERT(s->stop_sending_received, "recorded");
    TEST_ASSERT(s->send_state == QUIC_SEND_RESET_SENT, "the stream was reset");
    TEST_ASSERT(s->send_reset_code == 0x99, "with the peer's code");
    TEST_ASSERT(s->send_reset_pending, "and the frame is owed");
    quicstream_free(s);

    TEST_CASE("a reset stream sends no more data");
    s = quicstream_create(0, 1000, 8000, 1000);
    quicstream_write(s, (const uint8_t*)"data", 4);
    quicstream_reset(s, 5);
    s->send_reset_pending = 0;   /* pretend the frame went out */
    TEST_ASSERT(!quicstream_wants_send(s), "nothing further");
    TEST_ASSERT(!quicstream_write(s, (const uint8_t*)"more", 4), "and writes are refused");
    quicstream_free(s);

    TEST_CASE("STOP_SENDING on a stream we cannot send on is STREAM_STATE_ERROR");
    s = quicstream_create(2, 1000, 8000, 1000);   /* client unidirectional */
    TEST_ASSERT(quicstream_on_stop_sending(s, 0) == QUIC_STREAM_STATE_ERROR, "refused");
    TEST_ASSERT(quicstream_on_max_data(s, 5000) == QUIC_STREAM_STATE_ERROR,
                "and so is MAX_STREAM_DATA");
    quicstream_free(s);

    TEST_CASE("MAX_STREAM_DATA raises the send window");
    s = quicstream_create(0, 1000, 8000, 100);
    TEST_ASSERT(quicflow_available(&s->send_flow) == 100, "initial");
    TEST_ASSERT(quicstream_on_max_data(s, 5000) == QUICSTREAM_OK, "accepted");
    TEST_ASSERT(quicflow_available(&s->send_flow) == 5000, "raised");
    quicstream_free(s);

    TEST_CASE("a closed window still lets lost data be resent (§4.5)");
    /* Retransmission is not charged to the window -- the offsets were paid for
     * when they first went out. Holding it back is a deadlock, not a delay: the
     * peer cannot deliver anything behind the hole, so it never raises the
     * limit, and the limit is what is stopping us from filling the hole. Found
     * by the interop runner: every client stalled a multi-megabyte transfer
     * with data still queued and the connection silent (docs/http3/08 §3i). */
    s = quicstream_create(0, 1000, 8000, 100);
    TEST_ASSERT(quicstream_write(s, (const uint8_t*)"0123456789", 10), "written");
    quicsendbuf_mark_sent(&s->send, 0, 10, 0);
    quicflow_consume_to(&s->send_flow, 100);   /* the window is spent */
    TEST_ASSERT(quicflow_available(&s->send_flow) == 0, "and closed");
    TEST_ASSERT(!quicstream_wants_send(s), "new data waits for the peer");

    quicsendbuf_lost(&s->send, 0, 10, 0);
    TEST_ASSERT(quicsendbuf_has_lost(&s->send), "the range is queued again");
    TEST_ASSERT(quicstream_wants_send(s), "and goes out despite the closed window");
    quicstream_free(s);

    TEST_CASE("a stream is finished only when both directions are done");
    s = quicstream_create(0, 1000, 8000, 1000);
    TEST_ASSERT(!quicstream_is_finished(s), "neither side done");

    quicstream_on_data(s, 0, (const uint8_t*)"x", 1, 1);
    uint8_t out[8];
    quicstream_read(s, out, sizeof out);
    TEST_ASSERT(!quicstream_is_finished(s), "receive done, send not");

    quicstream_finish(s);
    s->send_state = QUIC_SEND_DATA_RECVD;   /* as if everything were acknowledged */
    TEST_ASSERT(quicstream_is_finished(s), "both done");
    quicstream_free(s);

    TEST_CASE("a unidirectional stream is finished on its one direction");
    /* Waiting for the other half of a stream that has no other half would leak
     * the slot for the life of the connection. */
    s = quicstream_create(2, 1000, 8000, 1000);   /* receive only */
    quicstream_on_data(s, 0, (const uint8_t*)"x", 1, 1);
    quicstream_read(s, out, sizeof out);
    TEST_ASSERT(quicstream_is_finished(s), "finished");
    quicstream_free(s);
}

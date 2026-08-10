#include "framework.h"

#include "quicrange.h"
#include "quicrecvbuf.h"
#include "quicsendbuf.h"

#include <string.h>

/* The three data structures the transport is built on.
 *
 * They look like plumbing and are not: a mistake in the range set silently
 * acknowledges packets that never arrived, a mistake in the receive buffer
 * hands the application bytes in the wrong order, and a mistake in the send
 * buffer either loses data or resends it forever. None of those crash. */

TEST(test_quic_range) {
    TEST_SUITE("quic_range");

    quicrange_t r;
    quicrange_init(&r, 0);

    TEST_CASE("adjacent intervals merge");
    /* [1,3] and [4,6] must become [1,6]. The ACK encoding has no way to say
     * "gap of zero", so a set that kept them apart would build frames a peer
     * rejects as malformed. */
    quicrange_add(&r, 1, 3);
    quicrange_add(&r, 4, 6);
    TEST_ASSERT(quicrange_count(&r) == 1, "one interval");
    TEST_ASSERT(quicrange_min(&r) == 1 && quicrange_max(&r) == 6, "1..6");

    TEST_CASE("a gap keeps them apart");
    quicrange_add(&r, 10, 12);
    TEST_ASSERT(quicrange_count(&r) == 2, "two intervals");

    TEST_CASE("an interval spanning the gap merges everything");
    quicrange_add(&r, 7, 9);
    TEST_ASSERT(quicrange_count(&r) == 1, "one interval");
    TEST_ASSERT(quicrange_min(&r) == 1 && quicrange_max(&r) == 12, "1..12");

    TEST_CASE("membership");
    TEST_ASSERT(quicrange_contains(&r, 1), "lower edge");
    TEST_ASSERT(quicrange_contains(&r, 12), "upper edge");
    TEST_ASSERT(quicrange_contains(&r, 7), "middle");
    TEST_ASSERT(!quicrange_contains(&r, 0), "below");
    TEST_ASSERT(!quicrange_contains(&r, 13), "above");

    TEST_CASE("removal splits");
    quicrange_remove(&r, 5, 8);
    TEST_ASSERT(quicrange_count(&r) == 2, "split in two");
    TEST_ASSERT(quicrange_contains(&r, 4) && !quicrange_contains(&r, 5), "lower part");
    TEST_ASSERT(!quicrange_contains(&r, 8) && quicrange_contains(&r, 9), "upper part");

    TEST_CASE("descending order, which is what ACK frames want");
    quicrange_span_t span;
    TEST_ASSERT(quicrange_at_desc(&r, 0, &span) && span.start == 9 && span.end == 12,
                "highest first");
    TEST_ASSERT(quicrange_at_desc(&r, 1, &span) && span.start == 1 && span.end == 4,
                "then the next");
    TEST_ASSERT(!quicrange_at_desc(&r, 2, &span), "and no more");

    TEST_CASE("single values");
    quicrange_clear(&r);
    quicrange_add(&r, 5, 5);
    TEST_ASSERT(quicrange_count(&r) == 1 && quicrange_contains(&r, 5), "one value");
    quicrange_add(&r, 6, 6);
    TEST_ASSERT(quicrange_count(&r) == 1, "and its neighbour merges");

    TEST_CASE("out-of-order insertion still sorts");
    quicrange_clear(&r);
    quicrange_add(&r, 100, 100);
    quicrange_add(&r, 1, 1);
    quicrange_add(&r, 50, 50);
    TEST_ASSERT(quicrange_count(&r) == 3, "three intervals");
    TEST_ASSERT(quicrange_min(&r) == 1 && quicrange_max(&r) == 100, "extremes");
    quicrange_at_desc(&r, 1, &span);
    TEST_ASSERT(span.start == 50, "middle one in the right place");

    TEST_CASE("trimming below a point");
    quicrange_trim_below(&r, 50);
    TEST_ASSERT(!quicrange_contains(&r, 1) && !quicrange_contains(&r, 50), "gone");
    TEST_ASSERT(quicrange_contains(&r, 100), "kept");

    TEST_CASE("zero and the top of the range");
    quicrange_clear(&r);
    quicrange_add(&r, 0, 0);
    TEST_ASSERT(quicrange_contains(&r, 0), "zero");
    quicrange_add(&r, 1, 1);
    TEST_ASSERT(quicrange_count(&r) == 1, "merges upward from zero");
    quicrange_clear(&r);
    quicrange_add(&r, UINT64_MAX - 1, UINT64_MAX);
    TEST_ASSERT(quicrange_contains(&r, UINT64_MAX), "the very top");

    quicrange_free(&r);

    TEST_CASE("the interval cap drops the oldest");
    /* A peer that loses every other packet creates one interval per gap. Held
     * without limit that is a memory attack, and an ACK frame listing hundreds
     * of ranges is abusive in itself. */
    quicrange_t capped;
    quicrange_init(&capped, 4);
    for (uint64_t i = 0; i < 20; i += 2)
        quicrange_add(&capped, i, i);

    TEST_ASSERT(quicrange_count(&capped) == 4, "capped at four");
    TEST_ASSERT(quicrange_max(&capped) == 18, "the newest survives");
    TEST_ASSERT(!quicrange_contains(&capped, 0), "the oldest was dropped");

    quicrange_free(&capped);
}

TEST(test_quic_recvbuf) {
    TEST_SUITE("quic_recvbuf");

    quicrecvbuf_t buf;
    uint8_t out[64];

    TEST_CASE("in-order data reads straight through");
    quicrecvbuf_init(&buf, 0);
    TEST_ASSERT(quicrecvbuf_insert(&buf, 0, (const uint8_t*)"hello", 5, 0)
                == QUICRECVBUF_OK, "inserted");
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 5, "readable");
    TEST_ASSERT(quicrecvbuf_read(&buf, out, sizeof out) == 5, "read");
    TEST_ASSERT(memcmp(out, "hello", 5) == 0, "contents");
    quicrecvbuf_free(&buf);

    TEST_CASE("a hole blocks everything behind it");
    /* The contract the application depends on: byte 100 must never appear
     * before byte 99, however early it arrives. */
    quicrecvbuf_init(&buf, 0);
    TEST_ASSERT(quicrecvbuf_insert(&buf, 5, (const uint8_t*)"world", 5, 0)
                == QUICRECVBUF_OK, "later piece first");
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 0, "nothing readable yet");

    TEST_ASSERT(quicrecvbuf_insert(&buf, 0, (const uint8_t*)"hello", 5, 0)
                == QUICRECVBUF_OK, "the gap is filled");
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 10, "both pieces readable");
    TEST_ASSERT(quicrecvbuf_read(&buf, out, sizeof out) == 10, "read");
    TEST_ASSERT(memcmp(out, "helloworld", 10) == 0, "in order");
    quicrecvbuf_free(&buf);

    TEST_CASE("a duplicate is ignored, not appended");
    quicrecvbuf_init(&buf, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"abcd", 4, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"abcd", 4, 0);
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 4, "still four bytes");
    quicrecvbuf_free(&buf);

    TEST_CASE("an overlapping retransmission keeps the original bytes");
    quicrecvbuf_init(&buf, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"aaaa", 4, 0);
    quicrecvbuf_insert(&buf, 2, (const uint8_t*)"aabb", 4, 0);
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 6, "six bytes");
    TEST_ASSERT(quicrecvbuf_read(&buf, out, sizeof out) == 6, "read");
    TEST_ASSERT(memcmp(out, "aaaabb", 6) == 0, "overlap resolved consistently");
    quicrecvbuf_free(&buf);

    TEST_CASE("a piece spanning a hole and a held segment");
    /* The general case: a retransmission need not line up with what is held,
     * so the insert has to fill the gap in front of a segment and skip the
     * segment itself. */
    quicrecvbuf_init(&buf, 0);
    quicrecvbuf_insert(&buf, 4, (const uint8_t*)"EF", 2, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"ABCDEF", 6, 0);
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 6, "all six");
    TEST_ASSERT(quicrecvbuf_read(&buf, out, sizeof out) == 6, "read");
    TEST_ASSERT(memcmp(out, "ABCDEF", 6) == 0, "contents");
    quicrecvbuf_free(&buf);

    TEST_CASE("a piece spanning two holes with a segment between them");
    quicrecvbuf_init(&buf, 0);
    quicrecvbuf_insert(&buf, 3, (const uint8_t*)"DE", 2, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"ABCDEFGH", 8, 0);
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 8, "all eight");
    TEST_ASSERT(quicrecvbuf_read(&buf, out, sizeof out) == 8, "read");
    TEST_ASSERT(memcmp(out, "ABCDEFGH", 8) == 0, "contents");
    quicrecvbuf_free(&buf);

    TEST_CASE("data already consumed is dropped");
    quicrecvbuf_init(&buf, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"abcd", 4, 0);
    quicrecvbuf_read(&buf, out, 4);
    TEST_ASSERT(quicrecvbuf_insert(&buf, 0, (const uint8_t*)"abcd", 4, 0)
                == QUICRECVBUF_OK, "retransmission accepted");
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 0, "and produces nothing");
    quicrecvbuf_free(&buf);

    TEST_CASE("partial reads");
    quicrecvbuf_init(&buf, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"0123456789", 10, 0);
    TEST_ASSERT(quicrecvbuf_read(&buf, out, 3) == 3 && memcmp(out, "012", 3) == 0, "first");
    TEST_ASSERT(quicrecvbuf_read(&buf, out, 3) == 3 && memcmp(out, "345", 3) == 0, "second");
    TEST_ASSERT(quicrecvbuf_readable(&buf) == 4, "remainder");
    quicrecvbuf_free(&buf);

    TEST_CASE("buffering past the read point is bounded");
    /* Flow control bounds how many bytes a peer may send, not how far apart
     * they may be. Without this cap one small packet naming a huge offset
     * would ask for an equally huge allocation. */
    quicrecvbuf_init(&buf, 64);
    TEST_ASSERT(quicrecvbuf_insert(&buf, 0, (const uint8_t*)"0123456789", 10, 0)
                == QUICRECVBUF_OK, "small piece");
    uint8_t big[100];
    memset(big, 'x', sizeof big);
    TEST_ASSERT(quicrecvbuf_insert(&buf, 1000, big, sizeof big, 0)
                == QUICRECVBUF_TOO_MUCH, "past the cap");
    quicrecvbuf_free(&buf);

    TEST_CASE("final size");
    quicrecvbuf_init(&buf, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"abc", 3, 1);
    TEST_ASSERT(buf.fin && buf.final_size == 3, "recorded");
    TEST_ASSERT(!quicrecvbuf_complete(&buf), "not complete until read");
    quicrecvbuf_read(&buf, out, 3);
    TEST_ASSERT(quicrecvbuf_complete(&buf), "complete");

    TEST_CASE("data past a declared final size is an error (§4.5)");
    TEST_ASSERT(quicrecvbuf_insert(&buf, 3, (const uint8_t*)"d", 1, 0)
                == QUICRECVBUF_FINAL_SIZE, "refused");

    TEST_CASE("a second, different final size is an error");
    TEST_ASSERT(quicrecvbuf_insert(&buf, 0, (const uint8_t*)"ab", 2, 1)
                == QUICRECVBUF_FINAL_SIZE, "refused");
    quicrecvbuf_free(&buf);

    TEST_CASE("a RESET_STREAM final size below what arrived is an error");
    quicrecvbuf_init(&buf, 0);
    quicrecvbuf_insert(&buf, 0, (const uint8_t*)"abcdef", 6, 0);
    TEST_ASSERT(quicrecvbuf_set_final_size(&buf, 3) == QUICRECVBUF_FINAL_SIZE,
                "refused");
    TEST_ASSERT(quicrecvbuf_set_final_size(&buf, 6) == QUICRECVBUF_OK, "accepted");
    quicrecvbuf_free(&buf);
}

TEST(test_quic_sendbuf) {
    TEST_SUITE("quic_sendbuf");

    quicsendbuf_t buf;
    uint64_t offset;
    const uint8_t* data;
    size_t len;
    int fin;

    TEST_CASE("write, send, acknowledge");
    quicsendbuf_init(&buf);
    TEST_ASSERT(quicsendbuf_write(&buf, (const uint8_t*)"hello", 5), "written");
    TEST_ASSERT(quicsendbuf_pending(&buf), "pending");

    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "has data");
    TEST_ASSERT(offset == 0 && len == 5 && memcmp(data, "hello", 5) == 0, "the whole lot");
    TEST_ASSERT(!fin, "no fin");

    quicsendbuf_mark_sent(&buf, 0, 5, 0);
    TEST_ASSERT(!quicsendbuf_pending(&buf), "nothing pending once sent");
    /* But still held: until the peer confirms it, it may be needed again. */
    TEST_ASSERT(quicsendbuf_inflight_bytes(&buf) == 5, "still held");

    quicsendbuf_ack(&buf, 0, 5, 0);
    TEST_ASSERT(quicsendbuf_inflight_bytes(&buf) == 0, "released once acknowledged");
    quicsendbuf_free(&buf);

    TEST_CASE("a lost range is retransmitted before new data");
    /* A hole in what the peer holds stalls the stream regardless of how much
     * new data is queued behind it, so retransmission has to win. */
    quicsendbuf_init(&buf);
    quicsendbuf_write(&buf, (const uint8_t*)"0123456789", 10);
    quicsendbuf_next(&buf, 5, &offset, &data, &len, &fin);
    quicsendbuf_mark_sent(&buf, 0, 5, 0);

    quicsendbuf_lost(&buf, 0, 5, 0);
    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "has data");
    TEST_ASSERT(offset == 0 && len == 5, "the lost range, not the new bytes");
    TEST_ASSERT(memcmp(data, "01234", 5) == 0, "original bytes");

    quicsendbuf_mark_sent(&buf, 0, 5, 0);
    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "then more");
    TEST_ASSERT(offset == 5 && len == 5, "the new data");
    quicsendbuf_free(&buf);

    TEST_CASE("a loss declaration for acknowledged data does not resend it");
    /* Loss detection is a heuristic; an ACK crossing the declaration in flight
     * is ordinary. Resending confirmed bytes wastes the window and confuses
     * the peer's offsets. */
    quicsendbuf_init(&buf);
    quicsendbuf_write(&buf, (const uint8_t*)"abcdefgh", 8);
    quicsendbuf_next(&buf, 8, &offset, &data, &len, &fin);
    quicsendbuf_mark_sent(&buf, 0, 8, 0);
    quicsendbuf_ack(&buf, 0, 4, 0);
    quicsendbuf_lost(&buf, 0, 8, 0);

    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "has data");
    TEST_ASSERT(offset == 4 && len == 4, "only the unacknowledged half");
    quicsendbuf_free(&buf);

    TEST_CASE("a PTO probe can pull back what is still unacknowledged (§6.2.4)");
    /* A probe carrying only a PING asks the peer to say something so that loss
     * detection can act a round trip later. In a handshake where nothing is
     * getting through there is no round trip to spend, and the congestion
     * window -- which only a probe may exceed -- lets nothing else out
     * (docs/http3/08 §3k). */
    quicsendbuf_init(&buf);
    quicsendbuf_write(&buf, (const uint8_t*)"abcdefgh", 8);
    quicsendbuf_next(&buf, 8, &offset, &data, &len, &fin);
    quicsendbuf_mark_sent(&buf, 0, 8, 0);
    TEST_ASSERT(!quicsendbuf_pending(&buf), "everything has been sent once");

    TEST_ASSERT(quicsendbuf_requeue_unacked(&buf), "and all of it comes back");
    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "has data");
    TEST_ASSERT(offset == 0 && len == 8, "from the earliest unacknowledged byte");

    quicsendbuf_mark_sent(&buf, 0, 8, 0);
    quicsendbuf_ack(&buf, 0, 4, 0);
    TEST_ASSERT(quicsendbuf_requeue_unacked(&buf), "again");
    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "has data");
    TEST_ASSERT(offset == 4 && len == 4, "and the confirmed half stays sent");

    quicsendbuf_mark_sent(&buf, 4, 4, 0);
    quicsendbuf_ack(&buf, 4, 4, 0);
    TEST_ASSERT(!quicsendbuf_requeue_unacked(&buf), "nothing owed once all is acked");
    quicsendbuf_free(&buf);

    TEST_CASE("the base slides only from the front");
    /* An unacknowledged byte at the start pins everything after it: it may
     * still have to be sent again. */
    quicsendbuf_init(&buf);
    quicsendbuf_write(&buf, (const uint8_t*)"0123456789", 10);
    quicsendbuf_next(&buf, 10, &offset, &data, &len, &fin);
    quicsendbuf_mark_sent(&buf, 0, 10, 0);

    quicsendbuf_ack(&buf, 5, 5, 0);
    TEST_ASSERT(buf.base == 0, "the tail alone does not move the base");
    TEST_ASSERT(quicsendbuf_inflight_bytes(&buf) == 10, "everything still held");

    quicsendbuf_ack(&buf, 0, 5, 0);
    TEST_ASSERT(buf.base == 10, "now the whole prefix is confirmed");
    TEST_ASSERT(quicsendbuf_inflight_bytes(&buf) == 0, "and released");
    quicsendbuf_free(&buf);

    TEST_CASE("retransmission from the middle after the base has moved");
    quicsendbuf_init(&buf);
    quicsendbuf_write(&buf, (const uint8_t*)"ABCDEFGHIJ", 10);
    quicsendbuf_next(&buf, 10, &offset, &data, &len, &fin);
    quicsendbuf_mark_sent(&buf, 0, 10, 0);
    quicsendbuf_ack(&buf, 0, 4, 0);

    quicsendbuf_lost(&buf, 6, 2, 0);
    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "has data");
    TEST_ASSERT(offset == 6 && len == 2, "the lost middle");
    TEST_ASSERT(memcmp(data, "GH", 2) == 0, "correct bytes after the base moved");
    quicsendbuf_free(&buf);

    TEST_CASE("FIN with data");
    quicsendbuf_init(&buf);
    quicsendbuf_write(&buf, (const uint8_t*)"bye", 3);
    quicsendbuf_finish(&buf);
    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "has data");
    TEST_ASSERT(len == 3 && fin, "the fin rides with the last chunk");
    quicsendbuf_mark_sent(&buf, 0, 3, 1);
    TEST_ASSERT(!quicsendbuf_pending(&buf), "nothing left");
    quicsendbuf_ack(&buf, 0, 3, 1);
    TEST_ASSERT(quicsendbuf_complete(&buf), "complete");
    quicsendbuf_free(&buf);

    TEST_CASE("a chunk that stops short does not carry the FIN");
    quicsendbuf_init(&buf);
    quicsendbuf_write(&buf, (const uint8_t*)"0123456789", 10);
    quicsendbuf_finish(&buf);
    TEST_ASSERT(quicsendbuf_next(&buf, 5, &offset, &data, &len, &fin), "has data");
    TEST_ASSERT(len == 5 && !fin, "no fin on a partial chunk");
    quicsendbuf_free(&buf);

    TEST_CASE("FIN alone on an empty stream");
    quicsendbuf_init(&buf);
    quicsendbuf_finish(&buf);
    TEST_ASSERT(quicsendbuf_pending(&buf), "the fin is something to send");
    TEST_ASSERT(quicsendbuf_next(&buf, 100, &offset, &data, &len, &fin), "produced");
    TEST_ASSERT(len == 0 && fin && offset == 0, "an empty frame at offset zero");
    quicsendbuf_mark_sent(&buf, 0, 0, 1);
    TEST_ASSERT(!quicsendbuf_pending(&buf), "nothing left");
    quicsendbuf_free(&buf);

    TEST_CASE("writes after finishing are refused");
    quicsendbuf_init(&buf);
    quicsendbuf_finish(&buf);
    TEST_ASSERT(!quicsendbuf_write(&buf, (const uint8_t*)"x", 1), "refused");
    quicsendbuf_free(&buf);
}

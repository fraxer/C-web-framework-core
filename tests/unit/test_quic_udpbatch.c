#include "framework.h"

#include "udpsocket.h"

#include <arpa/inet.h>
#include <string.h>

/* The transmit batch, which is where a GSO run is built.
 *
 * The kernel is told one segment size per message and cuts the message at it,
 * so everything folded into one send has to agree: the same peer, the same
 * source, the same ECN codepoint and the same length -- except for the last
 * segment, which may be shorter and ends the run. Get that wrong in the
 * permissive direction and sendmmsg answers EINVAL, which this batch treats as
 * "this machine has no offload" and turns segmentation off for good; get it
 * wrong in the conservative direction and every datagram travels on its own,
 * which is a third of the throughput and nothing else to show for it
 * (docs/http3/08 §12).
 *
 * Neither failure is visible from the outside: the datagrams arrive either
 * way. */

static void __peer(struct sockaddr_storage* out, socklen_t* out_len,
                   const char* ip, unsigned short port) {
    struct sockaddr_in* in = (struct sockaddr_in*)out;

    memset(out, 0, sizeof * out);
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
    inet_pton(AF_INET, ip, &in->sin_addr);
    *out_len = sizeof * in;
}

static int __add(udp_tx_batch_t* batch, size_t len,
                 const struct sockaddr_storage* peer, socklen_t peer_len) {
    static uint8_t data[2048];

    return udp_tx_batch_add(batch, data, len, (const struct sockaddr*)peer,
                            peer_len, NULL);
}

TEST(test_quic_udp_tx_batch_runs) {
    TEST_SUITE("quic_udp_batch");

    struct sockaddr_storage a, b;
    socklen_t a_len, b_len;

    __peer(&a, &a_len, "127.0.0.1", 4433);
    __peer(&b, &b_len, "127.0.0.2", 4433);

    TEST_CASE("datagrams of one size to one peer become one message");
    udp_tx_batch_t* batch = udp_tx_batch_create(64, 1472);
    TEST_REQUIRE_NOT_NULL(batch, "batch created");

    for (int i = 0; i < 5; i++)
        TEST_ASSERT(__add(batch, 1200, &a, a_len) == 1, "queued");

    TEST_ASSERT(udp_tx_batch_count(batch) == 5, "five datagrams");
    TEST_ASSERT(udp_tx_batch_messages(batch) == 1, "in one message");

    TEST_CASE("a shorter datagram joins the run and ends it");
    /* The kernel's own rule, and the reason the order matters: a short segment
     * is legal only as the last one. */
    TEST_ASSERT(__add(batch, 900, &a, a_len) == 1, "queued");
    TEST_ASSERT(udp_tx_batch_messages(batch) == 1, "still one message");

    TEST_ASSERT(__add(batch, 1200, &a, a_len) == 1, "queued");
    TEST_ASSERT(udp_tx_batch_messages(batch) == 2, "but the next one starts another");

    TEST_CASE("a longer datagram cannot belong to the run at all");
    TEST_ASSERT(__add(batch, 1300, &a, a_len) == 1, "queued");
    TEST_ASSERT(udp_tx_batch_messages(batch) == 3, "so it opens its own message");

    TEST_CASE("another peer opens its own message");
    TEST_ASSERT(__add(batch, 1300, &b, b_len) == 1, "queued");
    TEST_ASSERT(udp_tx_batch_messages(batch) == 4, "one message per peer");

    /* And the peer's run continues where it left off only if it is still the
     * open one -- runs are contiguous in the arena, so going back is not on
     * offer and the count must say so. */
    TEST_ASSERT(__add(batch, 1300, &a, a_len) == 1, "queued");
    TEST_ASSERT(udp_tx_batch_messages(batch) == 5, "the first peer starts afresh");

    udp_tx_batch_free(batch);
}

TEST(test_quic_udp_tx_batch_limits) {
    TEST_SUITE("quic_udp_batch");

    struct sockaddr_storage a;
    socklen_t a_len;

    __peer(&a, &a_len, "127.0.0.1", 4433);

    TEST_CASE("a run stops before the message outgrows one skb");
    /* Everything a GSO send hands over travels as a single IP datagram until
     * the device splits it, so a message is bounded by 65535 bytes less the
     * headers -- well under the 64 segments the segment count alone allows. At
     * 1472 bytes a run of 45 is already over the line, and the answer to going
     * over it is EINVAL and no offload at all afterwards.
     *
     * 128 full datagrams therefore have to come out as three messages: two runs
     * of 43 (63 296 bytes each) and the remainder. Two would mean the byte
     * limit never fired and only the segment count held the run back. */
    udp_tx_batch_t* batch = udp_tx_batch_create(128, 1472);
    TEST_REQUIRE_NOT_NULL(batch, "batch created");

    for (int i = 0; i < 128; i++)
        TEST_ASSERT(__add(batch, 1472, &a, a_len) == 1, "queued");

    TEST_ASSERT(udp_tx_batch_count(batch) == 128, "every datagram is in");
    TEST_ASSERT(udp_tx_batch_messages(batch) == 3,
                "in three messages, none of them larger than one skb");

    udp_tx_batch_free(batch);

    TEST_CASE("and before the kernel's segment count");
    /* Small datagrams reach 64 segments long before 64 KB. */
    batch = udp_tx_batch_create(200, 1472);
    TEST_REQUIRE_NOT_NULL(batch, "batch created");

    for (int i = 0; i < 130; i++)
        TEST_ASSERT(__add(batch, 100, &a, a_len) == 1, "queued");

    TEST_ASSERT(udp_tx_batch_messages(batch) == 3, "64 + 64 + 2");

    udp_tx_batch_free(batch);
}

TEST(test_quic_udp_tx_batch_capacity) {
    TEST_SUITE("quic_udp_batch");

    struct sockaddr_storage a;
    socklen_t a_len;

    __peer(&a, &a_len, "127.0.0.1", 4433);

    TEST_CASE("a full arena refuses rather than overruns");
    /* The caller answers a refusal by flushing, so this must be a 0 and not a
     * partial copy: the arena holds `count` datagrams of the size it was told,
     * and a datagram larger than a slot is refused outright. */
    udp_tx_batch_t* batch = udp_tx_batch_create(4, 1472);
    TEST_REQUIRE_NOT_NULL(batch, "batch created");

    for (int i = 0; i < 4; i++)
        TEST_ASSERT(__add(batch, 1472, &a, a_len) == 1, "queued");

    TEST_ASSERT(__add(batch, 1472, &a, a_len) == 0, "the fifth does not fit");
    TEST_ASSERT(udp_tx_batch_count(batch) == 4, "and nothing was lost or added");

    udp_tx_batch_free(batch);
}

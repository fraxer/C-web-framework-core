#include "framework.h"

#include "quicmemory.h"
#include "quicrecvbuf.h"
#include "quicsendbuf.h"

TEST(test_quic_memory_budget) {
    TEST_SUITE("quic_memory");
    TEST_CASE("the process budget reserves, refuses and rolls back exactly");

    quicmemory_configure(64, NULL);
    const unsigned long long refused = quicmemory_refused();
    TEST_ASSERT(quicmemory_current() == 0, "starts empty");
    TEST_ASSERT(quicmemory_reserve(40), "first reservation");
    TEST_ASSERT(quicmemory_reserve(24), "reservation reaches the limit");
    TEST_ASSERT(!quicmemory_reserve(1), "one byte over is refused");
    TEST_ASSERT(quicmemory_refused() == refused + 1, "refusal counted");
    quicmemory_release(64);
    TEST_ASSERT(quicmemory_current() == 0, "release returns to zero");

    TEST_CASE("send-buffer capacity is charged and released");
    quicmemory_configure(4096, NULL);
    quicsendbuf_t send;
    quicsendbuf_init(&send);
    const uint8_t byte = 1;
    TEST_ASSERT(quicsendbuf_write(&send, &byte, 1), "initial 4K allocation fits");
    TEST_ASSERT(quicmemory_current() == 4096, "send capacity charged");
    TEST_ASSERT(!quicsendbuf_write(&send, &byte, 4096), "growth over budget refused");
    quicsendbuf_free(&send);
    TEST_ASSERT(quicmemory_current() == 0, "send capacity released");

    TEST_CASE("impossible send and receive sizes fail before allocation");
    quicsendbuf_init(&send);
    TEST_ASSERT(!quicsendbuf_write(&send, &byte, SIZE_MAX),
                "send size overflow refused");
    TEST_ASSERT(quicmemory_current() == 0, "overflow reserves nothing");
    quicsendbuf_free(&send);

    TEST_CASE("receive segments charge metadata and payload");
    quicmemory_configure(sizeof(quicrecvseg_t) + 4, NULL);
    quicrecvbuf_t recv;
    quicrecvbuf_init(&recv, 1024);
    const uint8_t data[4] = {1, 2, 3, 4};
    TEST_ASSERT(quicrecvbuf_insert(&recv, 0, data, sizeof data, 0) == QUICRECVBUF_OK,
                "segment fits exactly");
    TEST_ASSERT(quicrecvbuf_insert(&recv, 4, data, 1, 0) == QUICRECVBUF_TOO_MUCH,
                "next segment refused globally");
    uint8_t out[4];
    TEST_ASSERT(quicrecvbuf_read(&recv, out, sizeof out) == sizeof out, "segment consumed");
    TEST_ASSERT(quicmemory_current() == 0, "consumption releases memory");
    quicrecvbuf_free(&recv);

    quicrecvbuf_init(&recv, 0);
    TEST_ASSERT(quicrecvbuf_insert(&recv, UINT64_MAX, data, 2, 0) ==
                    QUICRECVBUF_FINAL_SIZE,
                "receive offset overflow refused");
    TEST_ASSERT(quicmemory_current() == 0, "receive overflow reserves nothing");
    quicrecvbuf_free(&recv);

    quicmemory_configure(0, NULL); /* do not constrain later suites */
}

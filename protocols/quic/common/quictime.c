#define _GNU_SOURCE
#include <time.h>

#include "quictime.h"

static uint64_t __quic_clock_monotonic(void) {
    struct timespec ts;

    /* CLOCK_MONOTONIC cannot fail with a valid pointer on Linux; if it somehow
     * does, returning 0 makes every deadline appear expired, which degrades to
     * "retransmit and time out early" rather than to a hang. */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;

    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static uint64_t (*__quic_clock)(void) = __quic_clock_monotonic;

uint64_t quic_now_us(void) {
    return __quic_clock();
}

void quic_time_set_source(uint64_t (*source)(void)) {
    __quic_clock = source != NULL ? source : __quic_clock_monotonic;
}

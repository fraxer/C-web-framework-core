#ifndef __QUICBEACON__
#define __QUICBEACON__

/* Temporary diagnostic tracing for the send path (docs/http3/08). Off unless
 * CWFR_QUIC_BEACON is set in the environment, so a normal build pays one
 * predictable branch and nothing else. Remove once the question it was written
 * for is answered. */

#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "quictime.h"

static inline int quicbeacon_on(void) {
    static atomic_int state = -1;
    int value = atomic_load_explicit(&state, memory_order_acquire);

    if (value < 0) {
        value = getenv("CWFR_QUIC_BEACON") != NULL;
        atomic_store_explicit(&state, value, memory_order_release);
    }

    return value;
}

#define QUICBEACON(fmt, ...)                                                   \
    do {                                                                       \
        if (quicbeacon_on())                                                   \
            fprintf(stderr, "[beacon %llu] " fmt "\n",                         \
                    (unsigned long long)quic_now_us(), ##__VA_ARGS__);         \
    } while (0)

#endif

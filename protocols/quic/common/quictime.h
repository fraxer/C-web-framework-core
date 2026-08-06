#ifndef __QUICTIME__
#define __QUICTIME__

#include <stdint.h>

/* Monotonic time for the whole QUIC stack.
 *
 * Microseconds, CLOCK_MONOTONIC. Microseconds rather than nanoseconds because a
 * uint64_t of them still covers half a million years while keeping the RTT and
 * pacing arithmetic in a range where intermediate products cannot overflow;
 * milliseconds (what HTTP/2 uses -- h2_now_ms) are too coarse, since the pacer
 * schedules at sub-millisecond intervals and kGranularity in RFC 9002 is 1 ms.
 *
 * CLOCK_MONOTONIC, not wall clock: every deadline in QUIC -- PTO, idle timeout,
 * the 3xPTO close period, key update -- would shift under an NTP correction
 * otherwise.
 *
 * The indirection through a replaceable source is not a convenience. Loss
 * detection and congestion control are defined entirely in terms of elapsed
 * time, so they can only be unit-tested by a test that controls the clock and
 * fast-forwards minutes in microseconds (docs/http3/04-quic-transport.md §11,
 * 08-testing.md §2). Nothing in the QUIC stack may call clock_gettime()
 * directly. */

uint64_t quic_now_us(void);

/* Replace the clock. Pass NULL to restore the real one.
 *
 * For tests only, and specifically for single-threaded tests: the source is a
 * plain function pointer with no synchronisation, so it must not be changed
 * while any thread is inside the QUIC stack. */
void quic_time_set_source(uint64_t (*source)(void));

#endif

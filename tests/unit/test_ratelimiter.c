#include "framework.h"

#include "ipaddr.h"
#include "map.h"
#include "ratelimiter.h"

#include <stdint.h>

/* src/ratelimiter -- the token bucket in front of every route that asks for
 * one. The clock is injected (ratelimiter_set_time_source) so that refill and
 * cleanup, which are defined in elapsed time, are tested by moving a number
 * rather than by sleeping. */

#define NS_PER_S 1000000000ULL

static uint64_t __now_ns;

static uint64_t __test_clock(void) {
    return __now_ns;
}

static ratelimiter_t* __limiter(uint32_t max_tokens, uint32_t refill_rate, uint32_t cleanup_interval_s) {
    ratelimiter_config_t config = {
        .max_tokens = max_tokens,
        .refill_rate = refill_rate,
        .time_window_ns = NS_PER_S,
        .cleanup_interval_s = cleanup_interval_s,
    };

    __now_ns = 1000 * NS_PER_S;
    ratelimiter_set_time_source(__test_clock);

    return ratelimiter_init(&config);
}

static void __done(ratelimiter_t* limiter) {
    ratelimiter_free(limiter);
    ratelimiter_set_time_source(NULL);
}

static ipaddr_t __ip(const char* text) {
    ipaddr_t addr;
    ipaddr_parse(&addr, text);
    return addr;
}

static int __drain(ratelimiter_t* limiter, const ipaddr_t* ip) {
    int allowed = 0;
    while (allowed < 100000 && ratelimiter_allow(limiter, ip, 1))
        allowed++;
    return allowed;
}

TEST(test_ratelimiter_burst) {
    TEST_CASE("a new client gets max_tokens requests at once, then none");

    ratelimiter_t* limiter = __limiter(3, 1, 60);
    const ipaddr_t ip = __ip("192.0.2.1");

    TEST_ASSERT_EQUAL(3, __drain(limiter, &ip), "the burst is max_tokens");
    TEST_ASSERT(!ratelimiter_allow(limiter, &ip, 1), "an empty bucket refuses");

    __done(limiter);
}

TEST(test_ratelimiter_refill) {
    TEST_CASE("tokens come back at refill_rate per second, up to max_tokens");

    ratelimiter_t* limiter = __limiter(5, 10, 60);
    const ipaddr_t ip = __ip("192.0.2.1");

    __drain(limiter, &ip);
    __now_ns += NS_PER_S / 10;
    TEST_ASSERT_EQUAL(1, __drain(limiter, &ip), "a tenth of a second at 10/s is one token");

    __now_ns += 10 * NS_PER_S;
    TEST_ASSERT_EQUAL(5, __drain(limiter, &ip), "a long pause refills to max_tokens, not beyond");

    __done(limiter);
}

TEST(test_ratelimiter_insufficient) {
    TEST_CASE("a request for more tokens than there are is refused and takes none");

    ratelimiter_t* limiter = __limiter(3, 1, 60);
    const ipaddr_t ip = __ip("192.0.2.1");

    TEST_ASSERT(!ratelimiter_allow(limiter, &ip, 4), "4 of 3 is refused");
    TEST_ASSERT(ratelimiter_allow(limiter, &ip, 3), "the refusal took nothing: 3 of 3 passes");
    TEST_ASSERT(ratelimiter_allow(limiter, &ip, 0), "zero tokens always pass");

    __done(limiter);
}

TEST(test_ratelimiter_ipv6_prefix) {
    TEST_CASE("two addresses of one /64 share a bucket, another /64 does not");

    ratelimiter_t* limiter = __limiter(2, 1, 60);
    const ipaddr_t a = __ip("2001:db8:1:2::1");
    const ipaddr_t b = __ip("2001:db8:1:2:ffff::7");
    const ipaddr_t c = __ip("2001:db8:1:3::1");

    TEST_ASSERT(ratelimiter_allow(limiter, &a, 1), "first of the /64");
    TEST_ASSERT(ratelimiter_allow(limiter, &b, 1), "second of the /64");
    TEST_ASSERT(!ratelimiter_allow(limiter, &a, 1), "the /64 shares one limit");
    TEST_ASSERT(ratelimiter_allow(limiter, &c, 1), "the next /64 has its own");

    __done(limiter);
}

TEST(test_ratelimiter_cleanup) {
    TEST_CASE("buckets idle for longer than cleanup_interval_s are dropped");

    ratelimiter_t* limiter = __limiter(2, 1, 60);
    const ipaddr_t a = __ip("192.0.2.1");
    const ipaddr_t b = __ip("192.0.2.2");

    ratelimiter_allow(limiter, &a, 1);
    ratelimiter_allow(limiter, &b, 1);
    TEST_ASSERT_EQUAL_UINT(2, map_size(limiter->buckets), "one bucket per client");

    __now_ns += 30 * NS_PER_S;
    ratelimiter_allow(limiter, &a, 1);

    __now_ns += 31 * NS_PER_S;
    ratelimiter_allow(limiter, &a, 1);
    TEST_ASSERT_EQUAL_UINT(1, map_size(limiter->buckets), "the client idle for 61 s is gone");

    __done(limiter);
}

TEST(test_ratelimiter_null_ip) {
    TEST_CASE("a NULL address is always allowed, as ratelimiter.h says");

    ratelimiter_t* limiter = __limiter(1, 1, 60);

    TEST_ASSERT(ratelimiter_allow(limiter, NULL, 1), "first");
    TEST_ASSERT(ratelimiter_allow(limiter, NULL, 1), "second, past max_tokens");
    TEST_ASSERT_EQUAL_UINT(0, map_size(limiter->buckets), "and no bucket is made for it");

    __done(limiter);
}

TEST(test_ratelimiter_clock_backwards) {
    TEST_CASE("a clock that goes back grants nothing");

    ratelimiter_t* limiter = __limiter(3, 1, 60);
    const ipaddr_t ip = __ip("192.0.2.1");

    __drain(limiter, &ip);
    __now_ns -= 5 * NS_PER_S;
    TEST_ASSERT(!ratelimiter_allow(limiter, &ip, 1), "going back is not elapsed time");
    TEST_ASSERT_EQUAL_UINT(1, map_size(limiter->buckets), "nor does it look like 584 years idle");

    __now_ns += 5 * NS_PER_S + NS_PER_S;
    TEST_ASSERT_EQUAL(1, __drain(limiter, &ip), "one second after the original time, one token");

    __done(limiter);
}

TEST(test_ratelimiter_long_idle_multiply) {
    TEST_CASE("a pause long enough to overflow elapsed*rate still refills to max");

    /* 2^60 ns at 16 tokens/s: the product is exactly 2^64, i.e. 0 in uint64. */
    ratelimiter_t* limiter = __limiter(3, 16, UINT32_MAX);
    const ipaddr_t ip = __ip("192.0.2.1");

    __drain(limiter, &ip);
    __now_ns += 1ULL << 60;
    TEST_ASSERT_EQUAL(3, __drain(limiter, &ip), "full bucket after the pause");

    __done(limiter);
}

TEST(test_ratelimiter_long_idle_truncate) {
    TEST_CASE("a refill of 2^32 tokens is not truncated to 0");

    /* 2^31 s at 2 tokens/s: tokens_to_add is 2^32, which a uint32_t cast wraps
     * to 0. Not 2^32 s at 1/s: that is past the longest cleanup interval, and
     * the cleanup would hand out a fresh bucket and hide the wrap. */
    ratelimiter_t* limiter = __limiter(3, 2, UINT32_MAX);
    const ipaddr_t ip = __ip("192.0.2.1");

    __drain(limiter, &ip);
    __now_ns += (1ULL << 31) * NS_PER_S;
    TEST_ASSERT_EQUAL(3, __drain(limiter, &ip), "full bucket after the pause");

    __done(limiter);
}

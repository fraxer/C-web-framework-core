#include "framework.h"

#include "ipaddr.h"

#include <arpa/inet.h>
#include <string.h>

/* misc/ipaddr.h -- the address value the whole server now carries.
 *
 * Three of these tests exist because of a defect the type replaced rather than
 * because of a property worth stating twice: `inet_addr` reported a bad literal
 * as 255.255.255.255, an unset address used to be indistinguishable from the
 * wildcard, and the rate limiter keyed on the full IPv6 address, which any peer
 * could walk out of. */

static ipaddr_t parsed(const char* text) {
    ipaddr_t addr;

    memset(&addr, 0xaa, sizeof addr);
    if (!ipaddr_parse(&addr, text))
        memset(&addr, 0, sizeof addr);

    return addr;
}

TEST(test_ipaddr_parse_v4) {
    TEST_CASE("ipaddr_parse accepts IPv4 literals");

    ipaddr_t addr;

    TEST_ASSERT(ipaddr_parse(&addr, "127.0.0.1"), "loopback parses");
    TEST_ASSERT_EQUAL(AF_INET, addr.family, "family is AF_INET");
    TEST_ASSERT_EQUAL_UINT(inet_addr("127.0.0.1"), addr.u.v4.s_addr, "address kept in network order");
    TEST_ASSERT(!ipaddr_is_wildcard(&addr), "loopback is not the wildcard");

    TEST_ASSERT(ipaddr_parse(&addr, "0.0.0.0"), "wildcard parses");
    TEST_ASSERT(ipaddr_is_wildcard(&addr), "0.0.0.0 is the wildcard");
    TEST_ASSERT(ipaddr_is_set(&addr), "the wildcard is still a set address");
}

TEST(test_ipaddr_parse_v6) {
    TEST_CASE("ipaddr_parse accepts IPv6 literals, bracketed or not");

    ipaddr_t bare;
    ipaddr_t bracketed;

    TEST_ASSERT(ipaddr_parse(&bare, "::1"), "bare ::1 parses");
    TEST_ASSERT_EQUAL(AF_INET6, bare.family, "family is AF_INET6");

    /* The bracketed form is how an IPv6 address is written in a URL and in
     * every config an operator has seen (RFC 3986 §3.2.2); refusing it would be
     * a footgun and nothing else. */
    TEST_ASSERT(ipaddr_parse(&bracketed, "[::1]"), "bracketed [::1] parses");
    TEST_ASSERT(ipaddr_equal(&bare, &bracketed), "both forms give the same address");

    ipaddr_t wildcard;
    TEST_ASSERT(ipaddr_parse(&wildcard, "::"), ":: parses");
    TEST_ASSERT(ipaddr_is_wildcard(&wildcard), ":: is the wildcard");
    TEST_ASSERT(!ipaddr_equal(&wildcard, &bare), ":: is not ::1");
}

TEST(test_ipaddr_parse_rejects_garbage) {
    TEST_CASE("ipaddr_parse rejects what inet_addr used to accept");

    /* REGRESSION: `inet_addr` returns (in_addr_t)-1 for a malformed address,
     * which is also the encoding of the perfectly valid 255.255.255.255. A
     * misspelled config address became a broadcast address, and the operator
     * saw a bind failure naming an address they had never written. */
    ipaddr_t addr;

    TEST_ASSERT(!ipaddr_parse(&addr, "not-an-address"), "text is rejected");
    TEST_ASSERT(!ipaddr_is_set(&addr), "a rejected parse leaves the value unset");

    TEST_ASSERT(!ipaddr_parse(&addr, ""), "empty string is rejected");
    TEST_ASSERT(!ipaddr_parse(&addr, "1.2.3"), "short dotted quad is rejected");
    TEST_ASSERT(!ipaddr_parse(&addr, "1.2.3.4.5"), "long dotted quad is rejected");
    TEST_ASSERT(!ipaddr_parse(&addr, "[::1"), "unclosed bracket is rejected");
    TEST_ASSERT(!ipaddr_parse(&addr, "[127.0.0.1]"), "brackets are the IPv6 form only");
    TEST_ASSERT(!ipaddr_parse(&addr, "::gg"), "malformed IPv6 is rejected");
    TEST_ASSERT(!ipaddr_parse(NULL, "127.0.0.1"), "NULL output is rejected");

    /* And the address that used to be indistinguishable from a failure is
     * still a valid address. */
    TEST_ASSERT(ipaddr_parse(&addr, "255.255.255.255"), "broadcast still parses");
    TEST_ASSERT_EQUAL(AF_INET, addr.family, "and parses as IPv4");
}

TEST(test_ipaddr_unset_is_not_the_wildcard) {
    TEST_CASE("an unset address is distinct from 0.0.0.0");

    /* This distinction is what lets a missing config `ip` be caught as missing
     * instead of silently meaning "every interface". */
    ipaddr_t unset;
    memset(&unset, 0, sizeof unset);

    TEST_ASSERT(!ipaddr_is_set(&unset), "zeroed value is unset");
    TEST_ASSERT(!ipaddr_is_wildcard(&unset), "and it is not the wildcard");

    const ipaddr_t any = parsed("0.0.0.0");
    TEST_ASSERT(!ipaddr_equal(&unset, &any), "unset does not equal 0.0.0.0");
}

TEST(test_ipaddr_equal_across_families) {
    TEST_CASE("ipaddr_equal never matches across families");

    /* The vhost lookup is this comparison, so a false match here is a request
     * served by the wrong virtual server. */
    const ipaddr_t v4 = parsed("0.0.0.0");
    const ipaddr_t v6 = parsed("::");

    TEST_ASSERT(!ipaddr_equal(&v4, &v6), "0.0.0.0 is not ::");

    const ipaddr_t mapped = parsed("::ffff:127.0.0.1");
    const ipaddr_t plain = parsed("127.0.0.1");

    TEST_ASSERT_EQUAL(AF_INET6, mapped.family, "v4-mapped literal stays IPv6");
    TEST_ASSERT(!ipaddr_equal(&mapped, &plain), "and does not equal the IPv4 address");
}

TEST(test_ipaddr_sockaddr_roundtrip) {
    TEST_CASE("ipaddr <-> sockaddr in both families");

    const char* literals[] = {"127.0.0.1", "0.0.0.0", "::1", "::", "2001:db8::dead:beef"};

    for (size_t i = 0; i < sizeof literals / sizeof literals[0]; i++) {
        const ipaddr_t addr = parsed(literals[i]);
        TEST_ASSERT(ipaddr_is_set(&addr), "literal parsed");

        struct sockaddr_storage sa;
        const socklen_t len = ipaddr_to_sockaddr(&addr, 443, &sa);

        TEST_ASSERT(len > 0, "sockaddr produced");
        TEST_ASSERT_EQUAL(addr.family, sa.ss_family, "family preserved");

        const unsigned short port =
            sa.ss_family == AF_INET6 ? ntohs(((struct sockaddr_in6*)&sa)->sin6_port)
                                     : ntohs(((struct sockaddr_in*)&sa)->sin_port);
        TEST_ASSERT_EQUAL(443, port, "port written");

        ipaddr_t back;
        TEST_ASSERT(ipaddr_from_sockaddr(&back, (struct sockaddr*)&sa), "read back");
        TEST_ASSERT(ipaddr_equal(&addr, &back), "round trip is lossless");
    }

    /* An unset address has no sockaddr, and saying so is what makes a bind
     * refuse rather than bind the wildcard by accident. */
    ipaddr_t unset;
    memset(&unset, 0, sizeof unset);

    struct sockaddr_storage sa;
    TEST_ASSERT_EQUAL(0, ipaddr_to_sockaddr(&unset, 443, &sa), "unset produces no sockaddr");
}

TEST(test_ipaddr_text_and_authority) {
    TEST_CASE("formatting, including the brackets that make a port unambiguous");

    char buf[IPADDR_AUTHORITY_STRLEN];

    const ipaddr_t v4 = parsed("10.0.0.7");
    TEST_ASSERT_STR_EQUAL("10.0.0.7", ipaddr_text(&v4, buf, sizeof buf), "IPv4 text");
    TEST_ASSERT_STR_EQUAL("10.0.0.7:443", ipaddr_authority(&v4, 443, buf, sizeof buf), "IPv4 authority");

    const ipaddr_t v6 = parsed("::1");
    TEST_ASSERT_STR_EQUAL("::1", ipaddr_text(&v6, buf, sizeof buf), "IPv6 text has no brackets");
    /* "::1:443" would be an address, not an address and a port. */
    TEST_ASSERT_STR_EQUAL("[::1]:443", ipaddr_authority(&v6, 443, buf, sizeof buf), "IPv6 authority is bracketed");

    ipaddr_t unset;
    memset(&unset, 0, sizeof unset);
    TEST_ASSERT_STR_EQUAL("?", ipaddr_text(&unset, buf, sizeof buf), "unset formats as ?");

    /* Used inside log calls, so a NULL argument must produce text and not a
     * second failure on top of the one being reported. */
    TEST_ASSERT_STR_EQUAL("?", ipaddr_text(NULL, buf, sizeof buf), "NULL formats as ?");
    TEST_ASSERT_STR_EQUAL("?", ipaddr_text(&v6, NULL, 0), "NULL buffer still returns text");
}

TEST(test_ipaddr_client_key_v6_is_per_64) {
    TEST_CASE("the rate limiter counts an IPv6 client per /64");

    /* A residential subscriber is handed a whole /64 and a datacentre often a
     * /48: keying per /128 means an attacker changes source address for free
     * and the limiter never fires. */
    const ipaddr_t a = parsed("2001:db8:1:2::1");
    const ipaddr_t b = parsed("2001:db8:1:2:ffff:ffff:ffff:ffff");
    const ipaddr_t other = parsed("2001:db8:1:3::1");

    TEST_ASSERT(ipaddr_client_key(&a) == ipaddr_client_key(&b), "same /64 shares a bucket");
    TEST_ASSERT(ipaddr_client_key(&a) != ipaddr_client_key(&other), "a different /64 does not");
}

TEST(test_ipaddr_client_key_v4_cannot_collide_with_v6) {
    TEST_CASE("IPv4 keys are tagged out of the IPv6 /64 space");

    /* An untagged IPv4 key would collide with ::/64 -- which contains ::1, so
     * loopback over IPv6 would have shared a bucket with 0.0.0.0. */
    const ipaddr_t v4_zero = parsed("0.0.0.0");
    const ipaddr_t v6_loopback = parsed("::1");

    TEST_ASSERT(ipaddr_client_key(&v4_zero) != ipaddr_client_key(&v6_loopback),
                "0.0.0.0 and ::1 are different clients");

    const ipaddr_t v4_a = parsed("1.2.3.4");
    const ipaddr_t v4_b = parsed("1.2.3.5");

    TEST_ASSERT(ipaddr_client_key(&v4_a) != ipaddr_client_key(&v4_b),
                "IPv4 keys on the whole address");

    ipaddr_t unset;
    memset(&unset, 0, sizeof unset);
    TEST_ASSERT(ipaddr_client_key(&unset) == 0, "an unset address keys to 0");
    TEST_ASSERT(ipaddr_client_key(NULL) == 0, "NULL keys to 0");
}

TEST(test_ipaddr_v4_interop) {
    TEST_CASE("the IPv4-only client paths still get their in_addr_t");

    const in_addr_t raw = inet_addr("192.0.2.10");
    const ipaddr_t addr = ipaddr_from_v4(raw);

    TEST_ASSERT_EQUAL(AF_INET, addr.family, "built as IPv4");
    TEST_ASSERT_EQUAL_UINT(raw, ipaddr_v4_addr(&addr), "returned unchanged");

    /* An IPv6 address must not come back as four reinterpreted bytes: a caller
     * that forgets to check the family gets the wildcard, which fails to
     * connect, rather than a plausible wrong address. */
    const ipaddr_t v6 = parsed("2001:db8::1");
    TEST_ASSERT_EQUAL_UINT(0, ipaddr_v4_addr(&v6), "IPv6 yields 0, not garbage");
    TEST_ASSERT_EQUAL_UINT(0, ipaddr_v4_addr(NULL), "NULL yields 0");
}

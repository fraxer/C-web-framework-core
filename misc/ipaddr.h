#ifndef __IPADDR__
#define __IPADDR__

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

/* An IP address of either family, as one value (docs/http3/01 §7).
 *
 * The framework used to carry addresses as `in_addr_t`, which is an IPv4
 * address and nothing else: a config `ip`, a listener, a connection's peer and
 * the rate limiter's key were all four bytes. QUIC broke that first, because a
 * connection has a local and a remote address per path and may change them
 * mid-connection (ADR-5), so the transport has always used `sockaddr_storage`
 * internally -- and every value that crossed into the rest of the server had to
 * be flattened to IPv4 or to zero.
 *
 * This is the type that crossing no longer needs. It is not `sockaddr_storage`
 * because 128 bytes of mostly padding is the wrong shape for a field that sits
 * in every `connection_t` and every `server_t`, and it is not a `sockaddr_in6`
 * because the port does not belong here: ports are already carried separately
 * (`server_t::port`, `server_http3_t::port`, `connection_t::port`), and a second
 * copy of one is a second thing to keep in sync.
 *
 * A zeroed value is AF_UNSPEC -- "no address" -- which is distinct from the
 * wildcard 0.0.0.0. That distinction is what lets a missing config `ip` be
 * caught as missing rather than silently becoming "every interface".
 *
 * Not a value carrying a scope id: link-local addresses (`fe80::/10`) need one
 * to be usable, and a server bound to a link-local address is a case nobody has
 * asked for. `ipaddr_parse` accepts the literal, the bind then fails on the
 * missing scope; that failure is clearer than pretending to support it. */

#define IPADDR_STRLEN     46   /* INET6_ADDRSTRLEN */
#define IPADDR_AUTHORITY_STRLEN (IPADDR_STRLEN + 8)   /* "[" addr "]:" port */

typedef struct ipaddr {
    /* AF_INET, AF_INET6, or AF_UNSPEC (0) when unset. */
    uint16_t family;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } u;
} ipaddr_t;

/* Parse a textual address of either family. Accepts a bare IPv4 literal
 * ("0.0.0.0", "127.0.0.1"), a bare IPv6 literal ("::", "::1", "2001:db8::1")
 * and a bracketed IPv6 literal ("[::1]") -- the bracketed form because that is
 * how an IPv6 address is written in every URL and config the operator has seen
 * (RFC 3986 §3.2.2), and refusing it here would be a footgun and nothing else.
 *
 * Returns 1 on success, 0 on anything else -- and *0 matters*: the call this
 * replaced was `inet_addr`, which reports failure as `(in_addr_t)-1`, the same
 * value as the perfectly valid 255.255.255.255. A misspelled address became a
 * broadcast address and the bind failed with a message about an address the
 * operator never wrote. */
int ipaddr_parse(ipaddr_t* out, const char* text);

/* Build from / write to a socket address. `ipaddr_to_sockaddr` returns the
 * length to hand to bind/sendto, or 0 when the address is unset. */
int       ipaddr_from_sockaddr(ipaddr_t* out, const struct sockaddr* sa);
socklen_t ipaddr_to_sockaddr(const ipaddr_t* addr, unsigned short int port,
                             struct sockaddr_storage* out);

int ipaddr_equal(const ipaddr_t* a, const ipaddr_t* b);
int ipaddr_is_set(const ipaddr_t* addr);
/* 0.0.0.0 or :: -- "every interface of this family". */
int ipaddr_is_wildcard(const ipaddr_t* addr);

/* Text, into a caller-supplied buffer, always NUL-terminated and never NULL:
 * these are used inside log calls, where a NULL return would be a second
 * failure on top of the one being reported. An unset address formats as "?".
 *
 * `ipaddr_authority` adds the port and, for IPv6, the brackets that make the
 * result unambiguous -- "[::1]:443", not "::1:443". */
const char* ipaddr_text(const ipaddr_t* addr, char* buf, size_t size);
const char* ipaddr_authority(const ipaddr_t* addr, unsigned short int port,
                             char* buf, size_t size);

/* The key one client is counted under by the rate limiter.
 *
 * IPv4 keys on the whole address; IPv6 keys on the /64 prefix, because a
 * residential IPv6 subscriber is handed an entire /64 (and a datacentre often a
 * /48) and cycling through 2^64 source addresses costs an attacker nothing. A
 * limiter keyed per /128 is not a limiter.
 *
 * IPv4 keys are tagged into the top 32 bits so that they cannot collide with a
 * /64 prefix: the tag puts them under ffff:ffff::/32, which is inside the
 * multicast range ff00::/8 and therefore can never be the source of a packet,
 * while an untagged v4 key would collide with ::/64 -- which contains ::1. */
uint64_t ipaddr_client_key(const ipaddr_t* addr);

/* IPv4 interop for the paths that are still IPv4 by construction: the HTTP and
 * SMTP clients resolve names to `struct in_addr` and connect with a
 * `sockaddr_in`. `ipaddr_v4_addr` returns 0 for anything that is not IPv4, so a
 * caller that forgets to check gets the wildcard rather than a reinterpreted
 * IPv6 address. */
ipaddr_t  ipaddr_from_v4(in_addr_t addr);
in_addr_t ipaddr_v4_addr(const ipaddr_t* addr);

#endif

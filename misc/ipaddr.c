#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "ipaddr.h"

int ipaddr_parse(ipaddr_t* out, const char* text) {
    if (out == NULL || text == NULL) return 0;

    memset(out, 0, sizeof * out);

    const size_t length = strlen(text);
    if (length == 0) return 0;

    /* "[::1]" -- the URL form (RFC 3986 §3.2.2). Copied out rather than parsed
     * in place because inet_pton wants a NUL-terminated address and nothing
     * else. */
    char unbracketed[IPADDR_STRLEN];
    if (text[0] == '[') {
        if (text[length - 1] != ']') return 0;

        const size_t inner = length - 2;
        if (inner == 0 || inner >= sizeof unbracketed) return 0;

        memcpy(unbracketed, text + 1, inner);
        unbracketed[inner] = '\0';
        text = unbracketed;

        /* Brackets are the IPv6 form only: "[127.0.0.1]" is not an address any
         * standard defines, and accepting it would invite the reverse mistake
         * of writing a bare IPv6 literal where a bracketed one is required. */
        if (inet_pton(AF_INET6, text, &out->u.v6) != 1) return 0;

        out->family = AF_INET6;
        return 1;
    }

    /* IPv4 first: it is the overwhelmingly common case, and the two grammars do
     * not overlap, so the order is a matter of cost and not of meaning. */
    if (inet_pton(AF_INET, text, &out->u.v4) == 1) {
        out->family = AF_INET;
        return 1;
    }

    if (inet_pton(AF_INET6, text, &out->u.v6) == 1) {
        out->family = AF_INET6;
        return 1;
    }

    memset(out, 0, sizeof * out);

    return 0;
}

int ipaddr_from_sockaddr(ipaddr_t* out, const struct sockaddr* sa) {
    if (out == NULL || sa == NULL) return 0;

    memset(out, 0, sizeof * out);

    if (sa->sa_family == AF_INET) {
        out->family = AF_INET;
        out->u.v4 = ((const struct sockaddr_in*)sa)->sin_addr;
        return 1;
    }

    if (sa->sa_family == AF_INET6) {
        out->family = AF_INET6;
        out->u.v6 = ((const struct sockaddr_in6*)sa)->sin6_addr;
        return 1;
    }

    return 0;
}

socklen_t ipaddr_to_sockaddr(const ipaddr_t* addr, unsigned short int port,
                             struct sockaddr_storage* out) {
    if (addr == NULL || out == NULL) return 0;

    memset(out, 0, sizeof * out);

    if (addr->family == AF_INET) {
        struct sockaddr_in* sa = (struct sockaddr_in*)out;

        sa->sin_family = AF_INET;
        sa->sin_addr = addr->u.v4;
        sa->sin_port = htons(port);

        return sizeof(struct sockaddr_in);
    }

    if (addr->family == AF_INET6) {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)out;

        sa->sin6_family = AF_INET6;
        sa->sin6_addr = addr->u.v6;
        sa->sin6_port = htons(port);

        return sizeof(struct sockaddr_in6);
    }

    return 0;
}

int ipaddr_equal(const ipaddr_t* a, const ipaddr_t* b) {
    if (a == NULL || b == NULL) return 0;
    if (a->family != b->family) return 0;

    switch (a->family) {
    case AF_INET:
        return a->u.v4.s_addr == b->u.v4.s_addr;
    case AF_INET6:
        return memcmp(&a->u.v6, &b->u.v6, sizeof a->u.v6) == 0;
    default:
        /* Two unset addresses are equal: that is what makes a listener lookup
         * work before any address is assigned, in tests. */
        return 1;
    }
}

int ipaddr_is_set(const ipaddr_t* addr) {
    return addr != NULL && (addr->family == AF_INET || addr->family == AF_INET6);
}

int ipaddr_is_wildcard(const ipaddr_t* addr) {
    if (addr == NULL) return 0;

    switch (addr->family) {
    case AF_INET:
        return addr->u.v4.s_addr == INADDR_ANY;
    case AF_INET6:
        return IN6_IS_ADDR_UNSPECIFIED(&addr->u.v6);
    default:
        return 0;
    }
}

const char* ipaddr_text(const ipaddr_t* addr, char* buf, size_t size) {
    if (buf == NULL || size == 0) return "?";

    buf[0] = '\0';

    if (addr != NULL) {
        const void* raw = addr->family == AF_INET ? (const void*)&addr->u.v4
                                                  : (const void*)&addr->u.v6;

        if ((addr->family == AF_INET || addr->family == AF_INET6) &&
            inet_ntop(addr->family, raw, buf, (socklen_t)size) != NULL)
            return buf;
    }

    /* Unset, or a buffer too small for the literal: say so rather than return a
     * half-written address that reads like a real one. */
    if (size >= 2) {
        buf[0] = '?';
        buf[1] = '\0';
        return buf;
    }

    buf[0] = '\0';

    return buf;
}

const char* ipaddr_authority(const ipaddr_t* addr, unsigned short int port,
                             char* buf, size_t size) {
    if (buf == NULL || size == 0) return "?";

    char text[IPADDR_STRLEN];
    ipaddr_text(addr, text, sizeof text);

    const int written = addr != NULL && addr->family == AF_INET6
                        ? snprintf(buf, size, "[%s]:%u", text, port)
                        : snprintf(buf, size, "%s:%u", text, port);

    if (written < 0) buf[0] = '\0';

    return buf;
}

uint64_t ipaddr_client_key(const ipaddr_t* addr) {
    if (addr == NULL) return 0;

    switch (addr->family) {
    case AF_INET:
        return 0xffffffff00000000ULL | (uint64_t)ntohl(addr->u.v4.s_addr);
    case AF_INET6: {
        uint64_t prefix = 0;

        /* The first eight bytes, in network order, so that the key of a /64 is
         * the same number whatever the machine's endianness -- it is only ever
         * compared with other keys built here, but a key that changes shape
         * between builds is a key that cannot be logged or tested. */
        for (int i = 0; i < 8; i++)
            prefix = (prefix << 8) | addr->u.v6.s6_addr[i];

        return prefix;
    }
    default:
        return 0;
    }
}

ipaddr_t ipaddr_from_v4(in_addr_t addr) {
    ipaddr_t out;

    memset(&out, 0, sizeof out);
    out.family = AF_INET;
    out.u.v4.s_addr = addr;

    return out;
}

in_addr_t ipaddr_v4_addr(const ipaddr_t* addr) {
    if (addr == NULL || addr->family != AF_INET) return 0;

    return addr->u.v4.s_addr;
}

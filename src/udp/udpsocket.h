#ifndef __UDPSOCKET__
#define __UDPSOCKET__

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* UDP socket for the QUIC endpoint (docs/http3/01-udp-endpoint.md §4).
 *
 * Separate from src/socket/, which is TCP-only and IPv4-only: QUIC needs the
 * local address of every datagram, batched receive, and the DF bit, none of
 * which the TCP path has any use for.
 *
 * Addresses are sockaddr_storage throughout. The rest of the framework is
 * AF_INET only (connection_t::ip is an in_addr_t), but QUIC has to carry a
 * local and a remote address per path and change them on migration, so
 * narrowing here would have to be undone in phase 4 (ADR-5). */

typedef struct udp_socket_options {
    /* Several workers bind the same address; the kernel spreads datagrams by
     * 4-tuple hash. QUIC connections are addressed by connection id rather than
     * by 4-tuple, so a datagram can land on a worker that does not own the
     * connection -- which is fine here, because the connection table is
     * process-wide (ADR-3). */
    int reuseport;
    /* 0 leaves the system default. Worth raising: a burst that overruns the
     * receive buffer is a silent drop, and QUIC reads it as congestion. */
    int rcvbuf;
    int sndbuf;
} udp_socket_options_t;

/* Bind a non-blocking UDP socket. Returns the fd, or -1.
 *
 * Family comes from `addr`. IPv6 sockets are created v6-only: a dual-stack
 * socket makes the local-address cmsg ambiguous (v4-mapped addresses) and
 * behaves differently across kernels, so the endpoint opens one socket per
 * family instead. */
int udp_socket_create(const struct sockaddr* addr, socklen_t addrlen,
                      const udp_socket_options_t* options);

/* One datagram, in either direction. */
typedef struct udp_datagram {
    uint8_t*  data;
    size_t    len;

    struct sockaddr_storage peer;
    socklen_t peer_len;

    /* Address this datagram was sent TO (receive) or must be sent FROM
     * (transmit). On a wildcard bind the kernel would otherwise pick the source
     * address by route, and a reply from an address the client never contacted
     * is dropped by the client. Only the address is meaningful -- the port is
     * the socket's own. */
    struct sockaddr_storage local;
    int       local_valid;

    /* ECN bits from the IP header. Always 0 until phase 9 turns on IP_RECVTOS /
     * IPV6_RECVTCLASS -- the field is here so the datagram struct does not have
     * to change shape then, not because it carries anything today. */
    uint8_t   ecn;
} udp_datagram_t;

/* ---- Batched receive ----
 *
 * One recvmmsg() per wakeup instead of one recvmsg() per datagram. At QUIC's
 * packet sizes the syscall is a large share of the receive cost, and a busy
 * endpoint has many datagrams queued by the time epoll reports readability. */

typedef struct udp_rx_batch udp_rx_batch_t;

/* `datagram_size` bounds one datagram. Sized above the largest QUIC datagram
 * we accept so that an oversized one is visibly truncated rather than silently
 * cut to fit. */
udp_rx_batch_t* udp_rx_batch_create(size_t count, size_t datagram_size);
void udp_rx_batch_free(udp_rx_batch_t* batch);

/* Receive up to a batch. Returns the number of datagrams, 0 when the socket is
 * drained (EAGAIN), or -1 on an error that should close the endpoint. Errors
 * belonging to a single datagram (ECONNREFUSED from a previous send) are
 * swallowed: they must not take the endpoint down. */
int udp_rx_batch_recv(udp_rx_batch_t* batch, int fd);

/* Valid for indices below the count returned by the last recv. The data pointer
 * belongs to the batch and is overwritten by the next recv. */
udp_datagram_t* udp_rx_batch_get(udp_rx_batch_t* batch, size_t index);

/* ---- Transmit ----
 *
 * One datagram at a time. Phase 1 only ever answers a datagram it just received
 * (Version Negotiation, stateless reset), so batching would have no user; the
 * connection write path in phase 4 adds sendmmsg alongside this.
 *
 * Returns the number of bytes sent, 0 if the socket would block (the caller
 * decides whether to retry -- these datagrams are all droppable), or -1 on a
 * real error. EMSGSIZE is reported as -1 and means the datagram exceeded the
 * path MTU with DF set. */
ssize_t udp_send(int fd, const uint8_t* data, size_t len,
                 const struct sockaddr* peer, socklen_t peer_len,
                 const struct sockaddr_storage* local);

#endif

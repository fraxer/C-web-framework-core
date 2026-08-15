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

    /* UDP_GRO coalesces equally-sized datagrams into this receive buffer. Zero
     * means an ordinary datagram; otherwise the caller must dispatch chunks of
     * this size (the final chunk may be shorter). */
    uint16_t  gro_segment_size;

    /* Datagrams the kernel dropped because this socket's receive queue was
     * full, as a running total (SO_RXQ_OVFL). Present only on the datagram that
     * follows a drop, so the caller reports the *difference* from the last one
     * it saw.
     *
     * Without this the loss is invisible: recvmmsg cannot report what it never
     * received, and the endpoint's own drop counters only count datagrams it
     * decided to reject. Under a burst of handshakes that showed up as
     * connections that simply never completed -- 41 datagrams gone and every
     * server-side counter at zero (docs/http3/08 §7a). */
    uint32_t  drops;
    int       drops_valid;

    /* When the kernel took delivery (SO_TIMESTAMPNS), in CLOCK_REALTIME
     * microseconds. `now - stamp` is how long the datagram waited for this
     * process, which is the part of a peer-measured round trip that belongs to
     * us and not to the network. Without it a receive path that has fallen
     * behind is indistinguishable from a slow path: both show up only as the
     * peer's srtt (docs/http3/08 §7c). */
    uint64_t  stamp_us;
    int       stamp_valid;
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

/* ---- Batched transmit ----
 *
 * One `sendmmsg` per turn of the worker instead of one `sendmsg` per datagram.
 *
 * This is not a micro-optimisation: a response of an average web asset leaves
 * as ~25 datagrams, and at one syscall each that was **26 % of the server's
 * CPU** under load -- the single largest item in the profile, and most of why a
 * request cost 222 µs against HTTP/2's 46 (docs/http3/08 §7d). The receive side
 * has been batched since phase 1; this is the other half.
 *
 * Datagrams are copied in, because the caller builds each one in a buffer it
 * reuses immediately. Each carries its own destination, so a batch may mix
 * connections -- which is the point of batching at the endpoint rather than
 * inside one connection's send loop.
 *
 * The caller must flush before returning to the event loop: a datagram left in
 * the batch is not late, it is simply not sent. */
typedef struct udp_tx_batch udp_tx_batch_t;

udp_tx_batch_t* udp_tx_batch_create(size_t count, size_t datagram_size);
void udp_tx_batch_free(udp_tx_batch_t* batch);

/* Copy one datagram in. Returns 1 when queued, 0 when the batch is full or the
 * datagram does not fit a slot (the caller flushes and retries, or sends it
 * alone), -1 on a bad argument. */
int udp_tx_batch_add(udp_tx_batch_t* batch, const uint8_t* data, size_t len,
                     const struct sockaddr* peer, socklen_t peer_len,
                     const struct sockaddr_storage* local);
int udp_tx_batch_add_ecn(udp_tx_batch_t* batch, const uint8_t* data, size_t len,
                         const struct sockaddr* peer, socklen_t peer_len,
                         const struct sockaddr_storage* local, uint8_t ecn);

size_t udp_tx_batch_count(const udp_tx_batch_t* batch);

/* Send everything queued, in order, with one syscall. Returns the number of
 * datagrams the kernel accepted and writes the bytes accepted to `out_bytes`
 * when it is not NULL; the batch is emptied either way. A short send is not an
 * error to recover from -- what the kernel refused is a lost packet, and QUIC
 * has loss recovery for exactly that -- so the remainder is dropped and
 * reported through the return value. -1 means the socket itself failed. */
int udp_tx_batch_flush(udp_tx_batch_t* batch, int fd, size_t* out_bytes);

/* ---- Transmit, one at a time ----
 *
 * For datagrams answered without a connection (Version Negotiation, stateless
 * reset) and as the fallback when a batch is not available.
 *
 * Returns the number of bytes sent, 0 if the socket would block (the caller
 * decides whether to retry -- these datagrams are all droppable), or -1 on a
 * real error. EMSGSIZE is reported as -1 and means the datagram exceeded the
 * path MTU with DF set. */
ssize_t udp_send(int fd, const uint8_t* data, size_t len,
                 const struct sockaddr* peer, socklen_t peer_len,
                 const struct sockaddr_storage* local);
ssize_t udp_send_ecn(int fd, const uint8_t* data, size_t len,
                     const struct sockaddr* peer, socklen_t peer_len,
                     const struct sockaddr_storage* local, uint8_t ecn);

#endif

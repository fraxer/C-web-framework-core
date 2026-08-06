#ifndef __QUICENDPOINT__
#define __QUICENDPOINT__

#include "connection_s.h"
#include "multiplexing.h"
#include "quiccidtable.h"
#include "server.h"
#include "udpsocket.h"

/* The QUIC endpoint: one UDP socket, many connections
 * (docs/http3/01-udp-endpoint.md §5).
 *
 * TCP gives a listening socket that produces one fd per connection, and the
 * whole connection/epoll layer is built on that. QUIC gives one socket carrying
 * every connection, told apart by connection id. The endpoint is what stands
 * where accept() used to: it reads datagrams and routes each to a connection,
 * or answers it directly when there is none.
 *
 * It presents itself to the rest of the server as a listener. Its own
 * connection_t sits in epoll exactly like listener_t's does, with a read
 * callback that drains the socket, no write callback, and a close that tears
 * the endpoint down. That is why phase 1 needs no changes at all in
 * connection_s.c or multiplexingepoll.c: nothing here is a QUIC *connection*
 * yet, and it is QUIC connections -- not the endpoint -- that will need the
 * epoll bypass (§3).
 *
 * Phase 1 scope: routing only. An Initial packet that would open a connection
 * is counted and dropped, because creating one needs the TLS handshake that
 * arrives in phase 3. Everything that does not require connection state --
 * Version Negotiation, stateless reset, the drop rules -- is complete. */

typedef struct quicendpoint {
    /* MUST be first: the endpoint's connection stores &endpoint->listener in
     * ctx->listener, which __mpx_epoll_control dereferences for its api. The
     * read callback casts back the other way, so the offset has to be zero.
     * Same shape as mpxapi_epoll_t embedding mpxapi_t. */
    listener_t listener;

    int fd;
    struct sockaddr_storage local;
    socklen_t local_len;

    udp_rx_batch_t* rx;

    /* The endpoint's connection is registered in epoll by quicendpoints_listen,
     * not by creation. Teardown has to know which happened: a registered
     * connection is released through connection->close (control_del, fd close,
     * reference drop), while one that never made it there must not go anywhere
     * near control_del -- epoll_ctl would fail on an fd it never held, and the
     * error would be logged as if something had gone wrong. */
    int listening;

    /* Routing table. Borrowed, not owned: it is process-wide, shared by every
     * endpoint on every worker, because a migrating client's datagrams land on
     * whichever worker the kernel's 4-tuple hash picks (ADR-3). */
    quiccidtable_t* table;

    /* Keys for the stateless reset token and (phase 3) address validation
     * tokens. Per process, not per endpoint: a token has to verify on whichever
     * worker the next datagram reaches. */
    const uint8_t* reset_key;

    /* Token buckets, in milli-tokens, for the two replies we owe strangers.
     * Both are amplification vectors -- an attacker spoofing a victim's address
     * makes us send to the victim -- so both are rate limited, and separately:
     * a scanner's rate of unknown short-header packets has nothing to do with
     * a client's rate of unsupported versions.
     *
     * Endpoint-local and touched only by the worker that owns the endpoint,
     * hence no atomics. */
    int64_t  vn_tokens;
    uint64_t vn_epoch_us;
    int64_t  reset_tokens;
    uint64_t reset_epoch_us;

    struct quicendpoint* next;
} quicendpoint_t;

/* Read the process-wide QUIC policy from main.env and create the shared
 * connection table and endpoint keys. Call once per config load, after the
 * config is readable and BEFORE any worker thread exists -- the values are
 * plain globals, and that ordering is what makes them safe to read from every
 * worker afterwards. Mirrors h2_policy_init(). Returns 0 on failure. */
int quic_policy_init(void);

/* Release what quic_policy_init() created.
 *
 * Exists for the reload path, and quic_policy_init() calls it itself before
 * building the replacement -- that is the only caller. Process exit
 * deliberately does not call it: the table is reachable from a static pointer,
 * so it is not a leak by LSan's definition, and the shutdown drain is bounded
 * by a grace window that can expire with a worker still inside the endpoint.
 * Freeing the table under that worker would turn an orderly exit into a
 * use-after-free, which is a strictly worse trade than a process-lifetime
 * allocation the kernel reclaims a moment later. */
void quic_policy_free(void);

/* One endpoint per (address, udp port) across every vhost that enables http3,
 * mirroring how __listener_get folds vhosts onto one TCP listener. Returns the
 * head of the list, or NULL if none was configured (which is not an error).
 * `*ok` is set to 0 if a configured endpoint could not be created. */
quicendpoint_t* quicendpoints_create(mpxapi_t* api, server_t* first_server, int* ok);

int  quicendpoints_listen(quicendpoint_t* endpoints);
void quicendpoints_unlisten(quicendpoint_t* endpoints);
void quicendpoints_free(quicendpoint_t* endpoints);

#endif

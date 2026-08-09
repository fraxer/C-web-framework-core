#ifndef __QUICENDPOINT__
#define __QUICENDPOINT__

#include <stdatomic.h>

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
    /* And a third, for the one reply that is not a reply at all: accepting a
     * connection. Separate from the connection ceiling next to it because the
     * two say different things -- the ceiling is how many may exist, this is
     * how fast they may appear, and a flood exhausts the second long before it
     * reaches the first. */
    int64_t  handshake_tokens;
    uint64_t handshake_epoch_us;

    /* Connections on this endpoint, for the timer sweep and the shutdown drain.
     * Touched only by the owning worker. */
    struct quicconn* conns;
    size_t conn_count;
    /* Of those, how many are still handshaking. This is the load signal
     * `http3_retry: auto` reacts to -- not the connection count, because a
     * server with many established connections is busy, while one with many
     * half-open ones is being attacked, and only the second calls for Retry. */
    size_t handshakes_in_flight;

    /* A graceful shutdown is in progress: no new connections, existing ones
     * are being drained.
     *
     * A flag rather than closing the socket, and that is the whole difference
     * from TCP. There, closing the listener stops new connections while the
     * established ones carry on with their own descriptors. Here one socket
     * carries both, so closing it would strand exactly the connections the
     * drain is supposed to finish serving. The socket goes when the last
     * connection does. */
    int draining;

    /* Connections with something to send. Unlike `conns`, this is reachable
     * from a handler thread finishing a response, so it has a lock of its own
     * -- a leaf one, held for a few instructions and never while
     * connection_s_lock is wanted. */
    struct quicconn* tx_head;
    struct quicconn* tx_tail;
    atomic_flag tx_lock;

    struct quicendpoint* next;
} quicendpoint_t;

/* What a new connection starts with (docs/http3/07-integration.md §1.2).
 *
 * These are transport parameters, so by rights they belong to quicconn -- but
 * they are read from main.env, and reading env from the transport layer would
 * put a config dependency under every unit test that builds a connection. They
 * are read here instead, in the one function that already does exactly this at
 * exactly the right moment, and quicconn_accept asks for them. Everything below
 * is advertised to the peer in the ClientHello answer, so a value that is wrong
 * is wrong for the whole connection: there is no renegotiating it.
 *
 * Sizes are in the units the RFC uses (bytes, milliseconds, counts), not the
 * units the config uses, so the conversion happens once, here. */
typedef struct {
    uint64_t idle_timeout_ms;
    uint64_t max_udp_payload_size;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data;
    uint64_t max_streams_bidi;
    uint64_t max_streams_uni;
    /* The ceiling the connection receive window may be auto-tuned up to. Its
     * own key rather than a multiple of initial_max_data, because the two
     * answer different questions: how much an idle peer may send before we say
     * anything, and how much memory one connection may ever cost us. */
    uint64_t recv_window_max;
    uint64_t active_cid_limit;
    uint64_t ack_delay_ms;
    int      pacing;
    /* §8.1 says three. Configurable only so a test can make the limit fire
     * without sending megabytes; anything but 3 is logged as the deviation it
     * is. */
    uint64_t amplification_factor;
} quic_conn_policy_t;

/* Read the process-wide QUIC policy from main.env and create the shared
 * connection table and endpoint keys. Call once per config load, after the
 * config is readable and BEFORE any worker thread exists -- the values are
 * plain globals, and that ordering is what makes them safe to read from every
 * worker afterwards. Mirrors h2_policy_init(). Returns 0 on failure. */
int quic_policy_init(void);

/* The connection defaults, never NULL: before quic_policy_init() runs it
 * returns the built-in ones, which is what a unit test gets. */
const quic_conn_policy_t* quic_policy_conn(void);

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

/* Begin a graceful shutdown: refuse new connections, GOAWAY the existing ones
 * and let them finish what they are serving. Each endpoint unlistens itself
 * once its last connection is gone, which is what eventually lets the worker
 * loop's connection_count reach zero. */
void quicendpoints_drain(quicendpoint_t* endpoints);

void quicendpoints_unlisten(quicendpoint_t* endpoints);
void quicendpoints_free(quicendpoint_t* endpoints);

struct quicconn;
struct quicpath;

/* Send one datagram from this endpoint's socket, with the source address
 * pinned to the one the peer sent to. Returns the bytes sent, 0 if the socket
 * would block (QUIC datagrams are droppable; loss recovery will notice), or -1.
 *
 * The only way a connection reaches the wire: connections have no socket of
 * their own. */
ssize_t quicendpoint_send(quicendpoint_t* endpoint, const uint8_t* data, size_t len,
                          const struct quicpath* path);

/* Mark a connection as having something to send.
 *
 * Callable from a handler thread, which is why the queue has a leaf lock of its
 * own: the handler must not take connection_s_lock here, and the endpoint's
 * worker must not be blocked behind one. Lock order is connection_s_lock ->
 * tx_lock, never the reverse (docs/http3/01-udp-endpoint.md §8). */
void quicendpoint_wake(quicendpoint_t* endpoint, struct quicconn* conn);

/* Accessors, so quicconn.c can build its embedded connection_t without seeing
 * inside the endpoint (which would reintroduce the header cycle). */
listener_t* quicendpoint_listener(quicendpoint_t* endpoint);
int quicendpoint_fd(quicendpoint_t* endpoint);

/* The address the endpoint is bound to, in the form connection_t carries it.
 * A QUIC connection needs these because they are what selects the virtual
 * server: httpparser_select_server matches a vhost by (ip, port), and a
 * connection reporting 0/0 -- which is what it did before there was anywhere
 * to get them from -- matches nothing at all. */
in_addr_t quicendpoint_ip(quicendpoint_t* endpoint);
unsigned short quicendpoint_port(quicendpoint_t* endpoint);

/* Register one more connection id for a connection that already exists, and
 * drop one. A QUIC connection answers to several ids at once (RFC 9000 §5.1),
 * and issuing them is the connection's business while the table they live in is
 * the endpoint's -- these two are the seam.
 *
 * quicendpoint_cid_register returns 0 if the id could not be added, in which
 * case the caller must not treat it as issued. */
int  quicendpoint_cid_register(quicendpoint_t* endpoint, const quiccid_t* cid,
                               struct quicconn* conn);
void quicendpoint_cid_forget(quicendpoint_t* endpoint, const quiccid_t* cid);

/* The stateless reset token for an id (§10.3), from the process-wide key.
 *
 * Needed by two callers that never meet: the endpoint, answering a datagram for
 * a connection it no longer has, and the connection, telling the peer in
 * advance what the token for a new id will be. Both must produce the same 16
 * bytes or the peer cannot recognise a reset, so there is one derivation. */
int  quicendpoint_reset_token(const quiccid_t* cid, uint8_t out[16]);

/* A NEW_TOKEN for a peer whose address is now proven (§8.1.3): something it can
 * present on its *next* connection to skip the Retry round trip. Returns the
 * length written, or 0 when the feature is off or the token does not fit.
 *
 * Here rather than in quicconn for the same reason as the reset token: the key
 * is the endpoint's, and a token minted from anywhere else would not verify. */
size_t quicendpoint_new_token(const struct sockaddr* peer, socklen_t peer_len,
                              uint8_t* out, size_t cap);

/* Take a connection out of the routing table and the endpoint's lists. Called
 * from the connection's close path; after it, no datagram can reach it. */
void quicendpoint_detach(quicendpoint_t* endpoint, struct quicconn* conn);

/* Drain the send queue and run each connection's timers. Called from the
 * worker tick, alongside h2_server_tick. */
void quicendpoints_tick(quicendpoint_t* endpoints, int shutdown_now);

#endif

#ifndef __QUICENDPOINT__
#define __QUICENDPOINT__

#include <stdatomic.h>
#include <pthread.h>

#include "connection_s.h"
#include "multiplexing.h"
#include "quiccidtable.h"
#include "quiccc.h"
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

/* Declared before the endpoint rather than beside the functions below: the
 * struct itself now names quicpath in a member's prototype, and a tag first
 * seen inside a parameter list would be a different, incompatible type. */
struct quicconn;
struct quicpath;

typedef struct quicendpoint {
    /* MUST be first: the endpoint's connection stores &endpoint->listener in
     * ctx->listener, which __mpx_epoll_control dereferences for its api. The
     * read callback casts back the other way, so the offset has to be zero.
     * Same shape as mpxapi_epoll_t embedding mpxapi_t. */
    listener_t listener;

    int fd;
    struct quic_udp_handle* transport;
    const void* generation;
    const void* previous_generation;
    int handoff_candidate;
    struct sockaddr_storage local;
    socklen_t local_len;

    udp_rx_batch_t* rx;
    /* Snapshot of the generation's configured batch depth. Reload may publish
     * a different depth while this endpoint is still draining. */
    size_t rx_batch;

    /* Datagrams built but not yet handed to the kernel (docs/http3/08 §7d).
     *
     * Owned by the worker thread that runs this endpoint, exactly like `rx`:
     * everything that fills it -- a connection's send round, a stateless
     * answer -- runs on that thread. Flushed by `quicendpoint_send_flush()`
     * before the worker returns to the event loop, and automatically whenever
     * it fills up. */
    udp_tx_batch_t* tx_batch;
    /* Normally worker-local. During soft handoff the new UDP reader may route
     * an old CID while the old endpoint's timer/wakeup worker is still alive. */
    pthread_mutex_t tx_batch_mutex;

    /* The owning worker normally has exclusive access to this list.  During
     * soft reload, however, the new socket reader can close an old-generation
     * connection after routing one of its CIDs. */
    pthread_mutex_t conns_mutex;

    /* Last value of the kernel's receive-overflow counter for this socket, so
     * the metric can report the step rather than the running total. */
    uint32_t kernel_drops;

    /* ---- How long the socket goes unread (docs/http3/08 §7b) ---- *
     *
     * A large response makes this endpoint's own peer look far away: the
     * measured round trip on loopback climbs from 8 ms to 480 as the transfer
     * grows, and the receive queue eventually overflows. Both are consistent
     * with one thing -- the worker not coming back to the socket often enough
     * -- and neither proves it, because an acknowledgement that waits in the
     * queue is indistinguishable from one the peer sent late.
     *
     * This is the number that tells them apart: the longest interval between
     * two reads of the socket. Sampled here rather than as a metric because a
     * metric is read by an HTTP request, and the pause that request introduces
     * is exactly the thing being measured. Reported and reset when a connection
     * closes, so a single-connection run reads it per transfer. */
    uint64_t last_recv_us;
    uint64_t max_recv_gap_us;

    /* ---- And how long each datagram waits once it is here (§7c) ---- *
     *
     * The gap above measures this process; this measures the queue. They are
     * not the same number: a worker that returns every 20 ms still delays a
     * datagram by half a second if it takes fewer per visit than arrive
     * between them, and only the backlog shows that. Taken from the kernel's
     * own arrival stamp (SO_TIMESTAMPNS), so it counts the wait, not the
     * work. Reset with the report, like the gap. */
    uint64_t rx_dwell_max_us;
    uint64_t rx_dwell_sum_us;
    uint64_t rx_dwell_count;

    /* The endpoint's own deadline timer (docs/http3/01 §6).
     *
     * QUIC's timers are PTO, ack delay and pacing -- tens of milliseconds and
     * below -- while the worker sweep is once a second. A deadline that falls
     * between two sweeps fires up to a second late, which for a PTO means loss
     * recovery that does not happen; that was measured, not supposed
     * (docs/http3/08 §2a).
     *
     * Registered as an ordinary connection with a read callback rather than as
     * a tagged fd: the epoll dispatcher already tells connections apart by
     * their callbacks, and a second sentinel tag would have to be understood by
     * a layer that otherwise knows nothing about QUIC. */
    int timerfd;
    connection_t* timer_connection;
    uint64_t timer_deadline_us;   /* what it is currently armed for; 0 = idle */

    /* How a handler thread gets the worker's attention.
     *
     * quicendpoint_wake() queues the connection, but the worker is asleep in
     * epoll_wait and a queue is not a descriptor -- so before this existed the
     * response sat there until something else woke the loop, which in practice
     * meant the acknowledgement timer. Measured with a third-party client: 25 ms
     * per request, exactly http3_ack_delay_ms, and a single connection capped at
     * 40 requests a second (docs/http3/08 §7a).
     *
     * An eventfd rather than re-arming the timer: writing it is thread-safe and
     * says what it means, while a timer re-armed from another thread races with
     * the worker's own arming. */
    int eventfd;
    connection_t* wake_connection;

    /* The endpoint's connection is registered in epoll by quicendpoints_listen,
     * not by creation. Teardown has to know which happened: a registered
     * connection is released through connection->close (control_del, fd close,
     * reference drop), while one that never made it there must not go anywhere
     * near control_del -- epoll_ctl would fail on an fd it never held, and the
     * error would be logged as if something had gone wrong. */
    int listening;
    int timer_listening;
    int wake_listening;

    /* Routing table. Borrowed, not owned: it is process-wide, shared by every
     * endpoint on every worker, because a migrating client's datagrams land on
     * whichever worker the kernel's 4-tuple hash picks (ADR-3). */
    quiccidtable_t* table;

    /* Keys for the stateless reset token and (phase 3) address validation
     * tokens. Per process, not per endpoint: a token has to verify on whichever
     * worker the next datagram reaches. */
    const uint8_t* reset_key;

    /* Connections on this endpoint, for the timer sweep and the shutdown drain.
     * Touched only by the owning worker. */
    struct quicconn* conns;
    size_t conn_count;
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

    /* A wakeup is already on its way to the worker, so another response does
     * not need to write the eventfd again.
     *
     * The write is a syscall per published response, and under load that was
     * 12 % of the server's CPU (docs/http3/08 §7d) -- paid to say a second time
     * what the worker has not yet acted on once. Cleared by the worker before
     * it drains the queue, never after: a producer that enqueued before the
     * clear is then either seen by that drain or writes its own wakeup. */
    atomic_int wake_pending;

    /* ---- Test seam (docs/http3/08-testing.md §2) ---- *
     *
     * Where the endpoint's datagrams go instead of the socket. NULL in every
     * build that serves anything; set only by the in-process stand, which runs
     * a real connection against a real client with a network emulator and an
     * injected clock in between.
     *
     * A hook here rather than a fake fd because the socket is not what has to
     * be faked: the stand needs to hold a datagram, drop it, duplicate it or
     * deliver it late, and none of that is expressible to sendmsg(). The same
     * argument quictime.h makes for quic_time_set_source. */
    ssize_t (*send_hook)(void* arg, const uint8_t* data, size_t len,
                         const struct quicpath* path);
    void* send_hook_arg;

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
    /* Initial congestion window in datagrams. RFC 9002 §7.2 says ten; a
     * server on a long-RTT path may open wider, and the deviation is logged
     * where it is configured. */
    uint64_t initcwnd_packets;
    quiccc_algorithm_e cc_algorithm;
    int      pacing;
    /* §8.1 says three. Configurable only so a test can make the limit fire
     * without sending megabytes; anything but 3 is logged as the deviation it
     * is. */
    uint64_t amplification_factor;
} quic_conn_policy_t;

/* Read the process-wide QUIC policy from main.env and create the shared
 * connection table and endpoint keys. http3_max_connections defaults to
 * 65536 and values outside 64..4000000 (including zero) reject the config.
 * Call once per config load, after the
 * config is readable and BEFORE any worker thread exists -- the values are
 * plain globals, and that ordering is what makes them safe to read from every
 * worker afterwards. Mirrors h2_policy_init(). Returns 0 on failure.
 *
 * Split in two, and the split is the point. **Tunables** are re-read on every
 * call, so a reload applies them. The **connection table and the two keys** are
 * built once per process and deliberately survive a reload: a soft reload
 * leaves the previous workers draining connections that route through that
 * table, and the keys authenticate stateless reset tokens and NEW_TOKENs that
 * peers are still holding. The consequence is that http3_max_connections,
 * which sizes the table, only takes effect on a restart. Nothing frees any of
 * it -- see the comment at the split for why. */
int quic_policy_init(void);
/* Validate a parsed, unpublished reload candidate without touching process
 * policy or exposing it to workers still using the current generation. */
int quic_policy_validate(const env_t* candidate);

/* The connection defaults, never NULL: before quic_policy_init() runs it
 * returns the built-in ones, which is what a unit test gets. */
const quic_conn_policy_t* quic_policy_conn(void);

/* Process-wide admission accounting, shared by every worker/endpoint. These
 * are public primarily so the multi-endpoint invariant can be unit-tested. */
int    quic_process_conn_try_acquire(void);
void   quic_process_conn_release(void);
size_t quic_process_conn_current(void);
size_t quic_process_conn_limit(void);

/* One endpoint per (address, udp port) across every vhost that enables http3,
 * mirroring how __listener_get folds vhosts onto one TCP listener. Returns the
 * head of the list, or NULL if none was configured (which is not an error).
 * `*ok` is set to 0 if a configured endpoint could not be created. */
quicendpoint_t* quicendpoints_create(mpxapi_t* api, server_t* first_server,
                                     const void* generation, int* ok);

int  quicendpoints_listen(quicendpoint_t* endpoints);

/* Begin a graceful shutdown: refuse new connections, GOAWAY the existing ones
 * and let them finish what they are serving. Each endpoint unlistens itself
 * once its last connection is gone, which is what eventually lets the worker
 * loop's connection_count reach zero. */
void quicendpoints_drain(quicendpoint_t* endpoints);

void quicendpoints_unlisten(quicendpoint_t* endpoints);
/* Hard reload: detach every QUIC connection immediately, then remove all
 * endpoint descriptors. No GOAWAY/drain window and no socket handoff. */
void quicendpoints_abort(quicendpoint_t* endpoints);
/* Soft reload: relinquish UDP reads, but retain timer/wakeup and the shared
 * transport for existing connections until their drain completes. */
void quicendpoints_handoff(quicendpoint_t* endpoints);
void quicendpoints_free(quicendpoint_t* endpoints);

/* Queue one datagram to leave this endpoint's socket, with the source address
 * pinned to the one the peer sent to. Returns the bytes queued, 0 if the
 * datagram was dropped (QUIC datagrams are droppable; loss recovery will
 * notice), or -1 on an error the caller should stop sending after.
 *
 * "Queued", not "sent": the datagram is copied into the endpoint's transmit
 * batch and leaves on the next `quicendpoint_send_flush()`, or sooner if the
 * batch fills. That is worth 26 % of the server's CPU under load
 * (docs/http3/08 §7d) and costs one rule -- every path that produces datagrams
 * must flush before it returns to the event loop.
 *
 * The only way a connection reaches the wire: connections have no socket of
 * their own. */
ssize_t quicendpoint_send(quicendpoint_t* endpoint, const uint8_t* data, size_t len,
                          const struct quicpath* path);

/* Hand everything queued to the kernel. Cheap and idempotent when the batch is
 * empty, so it belongs at the end of every entry point that can send: the
 * datagram reader, the timer, the wake queue and the sweep. */
void quicendpoint_send_flush(quicendpoint_t* endpoint);

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

/* The kernel's receive-overflow counter for this endpoint's socket, as of the
 * last datagram that carried one (SO_RXQ_OVFL). Cumulative, so it is only
 * meaningful as a difference between two moments -- which is what a connection
 * samples at accept in order to report its own share at close. */
uint32_t quicendpoint_kernel_drops(const quicendpoint_t* endpoint);

/* Start the receive-gap measurement over. Called when a connection is accepted:
 * the counter is otherwise dominated by the idle stretch since the last one. */
void quicendpoint_recv_gap_reset(quicendpoint_t* endpoint);

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

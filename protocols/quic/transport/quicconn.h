#ifndef __QUICCONN__
#define __QUICCONN__

#include <netinet/in.h>
#include <stdatomic.h>
#include <sys/socket.h>

#include "connection_s.h"
#include "quic.h"
#include "quicack.h"
#include "quiccc.h"
#include "quiccrypto.h"
#include "quicloss.h"
#include "quicpmtud.h"
#include "quicqlog.h"
#include "quicretry.h"
#include "quicstream.h"
#include "quictls.h"
#include "quictp.h"

/* A QUIC connection (RFC 9000).
 *
 * ## Why connection_t is embedded rather than pointed to
 *
 * Everything above the transport -- the request context, the lock, the
 * reference count, the handler queue, the filter chain -- is written against
 * connection_t and knows nothing about QUIC. Embedding it means all of that
 * works unchanged, and `&qc->conn` is a connection like any other.
 *
 * What changes is that connection_t is no longer "the thing in epoll": its fd
 * is the endpoint's shared socket, and every epoll_ctl path routes around it
 * (connection.h, connection_transport_e). The cast back from connection_t to
 * quicconn_t relies on conn being the first member. */

typedef struct quicpath {
    struct sockaddr_storage local;
    struct sockaddr_storage remote;
    socklen_t local_len;
    socklen_t remote_len;
} quicpath_t;

/* A connection id we issued, with the sequence number and reset token that go
 * with it (§5.1.1). */
typedef struct quiccid_entry {
    quiccid_t cid;
    uint64_t  seq;
    uint8_t   reset_token[16];
    int       active;
    /* The NEW_CONNECTION_ID frame for this entry has gone out. Cleared again if
     * the packet carrying it is declared lost: §13.3 puts this frame among the
     * information that must be retransmitted, unlike the limits next door,
     * whose current value the next packet carries anyway. Entry 0 is born
     * announced -- the peer learned it from the packet header itself. */
    int       announced;
} quiccid_entry_t;

#define QUICCONN_MAX_LOCAL_CIDS 8
#define QUICCONN_MAX_PEER_CIDS  8

typedef enum {
    QUICCONN_HANDSHAKE = 0,
    QUICCONN_ACTIVE,
    /* We sent CONNECTION_CLOSE. The packet is kept and re-sent in answer to
     * anything that arrives, but nothing new is processed (§10.2.1). */
    QUICCONN_CLOSING,
    /* The peer closed. Nothing is sent at all; we wait out the drain so late
     * packets do not provoke a stateless reset (§10.2.2). */
    QUICCONN_DRAINING,
    QUICCONN_DEAD
} quicconn_state_e;

struct quicendpoint;

typedef struct quicconn {
    /* MUST be first: the connection layer casts between the two, and
     * connection_free's free(connection) has to be a free() of this object. */
    connection_t conn;

    struct quicendpoint* endpoint;

    quicpath_t path;

    /* Identity. `odcid` is the Destination Connection ID from the client's
     * first Initial -- the Initial keys derive from it, and the client checks
     * it against the transport parameters we send. */
    quiccid_t odcid;
    /* The Source Connection ID of the client's first Initial, kept apart from
     * the list below because §7.3 compares initial_source_connection_id against
     * *that* packet, and the list is the peer's to rewrite at will. */
    quiccid_t peer_initial_scid;
    quiccid_entry_t local_cids[QUICCONN_MAX_LOCAL_CIDS];
    quiccid_t peer_cids[QUICCONN_MAX_PEER_CIDS];
    size_t    peer_cid_count;
    uint64_t  next_cid_seq;

    /* Crypto: keys per level per direction, and the TLS bridge. */
    quictls_t tls;
    quickeys_t rx[QUIC_ENC_COUNT];
    quickeys_t tx[QUIC_ENC_COUNT];
    quic_aead_e suite;

    /* ---- Key update (RFC 9001 §6), application space only ---- *
     *
     * The Key Phase bit alternates, so which generation a 1-RTT packet belongs
     * to follows from the bit plus the packet number, and never from the bit
     * alone: a packet whose phase differs from ours is either one the peer sent
     * before an update we already applied (reordered, so its number is below
     * where the current phase began) or the peer starting a new one. */
    int      key_phase;              /* the bit our current keys carry */
    /* Derived ahead of the peer asking. §9.5 requires that answering an
     * apparent update leaks no timing signal about whether the bit was valid,
     * and deriving a key schedule only on the real thing is exactly such a
     * signal. */
    quickeys_t rx_next;
    /* The generation before the current one, kept so packets that were already
     * in flight when the update happened still open (§6.3). */
    quickeys_t rx_prev;
    uint64_t key_prev_expire_us;     /* 0 = nothing retained */
    uint64_t key_phase_first_pn;     /* lowest 1-RTT pn accepted in this phase */
    /* §6.5: a peer that toggles the bit repeatedly would otherwise make us
     * derive a key schedule per packet. No second update is applied until one
     * of our own packets in the current phase has been acknowledged. */
    uint64_t key_update_tx_pn;
    int      key_update_unconfirmed;

    /* ---- 0-RTT (RFC 9001 §4.6, docs/http3/09 §3.1) ---- *
     *
     * How many packets opened at the 0-RTT level. Whether TLS *accepted* the
     * early data is not mirrored here -- quictls_early_data_accepted() answers
     * that from the SSL, which outlives the 0-RTT keys.
     *
     * The anti-replay policy lives above this, in the endpoint: a request that
     * arrives in early data is read into its stream here, but is not dispatched
     * until the handshake completes. A replayed 0-RTT flight cannot complete a
     * handshake -- it has no key material -- so it never reaches a handler,
     * whatever it contains. That is why this server does not need to restrict
     * early data to safe methods, and why this counter is for observation
     * rather than for gating. */
    uint64_t early_data_packets;

    /* Acknowledgement state, one per packet number space. */
    quicack_t ack[QUIC_ENC_COUNT];
    uint8_t recv_ecn;
    int ecn_enabled;
    /* The first ACK that echoed our ECT counts and passed §13.4.2 has been
     * seen. Only to keep `ecn.validated` one count per connection rather than
     * one per acknowledgement -- the transport itself needs no such state,
     * since validation is re-checked against every ACK for the life of the
     * connection. */
    int ecn_validated;
    uint64_t ecn_sent[QUIC_ENC_COUNT];
    uint64_t ecn_peer_ect0[QUIC_ENC_COUNT];
    uint64_t ecn_peer_ect1[QUIC_ENC_COUNT];
    uint64_t ecn_peer_ce[QUIC_ENC_COUNT];

    /* CRYPTO send buffers, one per level: handshake data is retransmitted the
     * same way stream data is. */
    quicsendbuf_t crypto_out[QUIC_ENC_COUNT];

    quicloss_t loss;
    quiccc_t   cc;
    quicpacer_t pacer;
    quicpmtud_t pmtud;

    /* When the pacer will next let a datagram out, or 0 when it is not what is
     * holding the connection up. Unlike the congestion window this reopens on
     * the clock and on nothing the peer does, so it has to be a timer deadline
     * of its own -- quicconn_next_timeout reports it, and the turn that set it
     * left want_write raised so the wake-up finds work to do. */
    uint64_t pace_until_us;

    /* Streams, and the limits that bound them.
     *
     * The list is in the order the streams were opened, and the send loop walks
     * it from the head -- so the order here *is* the scheduling policy. See
     * __stream_append for what depends on that. */
    quicstream_t* streams;
    quicstream_t* streams_tail;
    size_t    stream_count;

    /* Streams whose priority the layer above actually set to something other
     * than the default (RFC 9218). Zero -- which is every connection whose peer
     * sends no priority signals -- means the send loop keeps the list order it
     * always had, and pays nothing for a scheduler it is not using. */
    size_t    prio_streams;

    /* Whose turn it was, last time an incremental bucket was served. Ids only
     * grow, so "the first one past the cursor, wrapping" is a round robin
     * without a per-stream field to keep in step. */
    uint64_t  sched_rr_id;
    uint64_t  next_peer_bidi;   /* lowest client bidi id not yet opened */
    uint64_t  next_peer_uni;
    uint64_t  next_local_uni;

    /* Peer-initiated streams that have finished in both directions and been
     * released. Their slots are credit the peer may reuse, and §4.6 says so
     * with a MAX_STREAMS frame -- without one the peer is capped at the initial
     * allowance for the life of the connection, which is not a slow path but a
     * wall: a hundred requests and the connection is spent (found with a
     * third-party client, docs/http3/08 §7a).
     *
     * Releasing them also keeps the per-packet walk over conn->streams short.
     * Before this the list only ever grew. */
    uint64_t  peer_bidi_closed;
    uint64_t  max_streams_bidi_sent;

    quicflow_t recv_flow;       /* connection-level, what we allow */
    quicflow_t send_flow;       /* connection-level, what the peer allows */

    quictp_t local_params;
    quictp_t peer_params;
    int      peer_params_seen;

    /* §8.1: until the peer's address is validated, no more than three times
     * what it has sent may go back to it. This is what stops the server being
     * an amplifier for a spoofed source address, and it applies always --
     * unlike Retry, which is a policy. */
    uint64_t amplification_budget;
    int      address_validated;
    /* Copied from the policy at accept, not read from it later: the budget
     * below is spent against this multiplier for the life of the connection,
     * and a reload halfway through must not change the arithmetic. */
    uint64_t amplification_factor;

    /* RFC 9000 §8.2.2: the eight bytes of the most recent PATH_CHALLENGE,
     * waiting to be echoed back in a PATH_RESPONSE.
     *
     * One slot, not a queue. The endpoint builds packets immediately after
     * every datagram it processes (__route), so challenges that arrive in
     * separate datagrams -- which is what §8.2.1's "send multiple to guard
     * against loss" produces -- each get their own answer. Only a burst inside
     * one datagram coalesces, and that is the case worth bounding: a 1200-byte
     * datagram holds over a hundred challenges, and answering all of them would
     * make PATH_CHALLENGE a way to buy packets from us. §8.2.2 anticipates
     * exactly this -- "the peer is expected to send more PATH_CHALLENGE frames
     * as necessary to evoke additional PATH_RESPONSE frames". */
    uint8_t  path_response_data[8];
    int      path_response_pending;

    /* ---- Migration (RFC 9000 §9) ---- *
     *
     * The address a peer sends from can change under it -- a NAT rebinding, a
     * phone leaving wifi -- and QUIC is meant to survive that, because it
     * routes by connection id rather than by the 4-tuple. What it must not do
     * is believe the new address on sight: anyone able to spoof a source
     * address could otherwise redirect a connection's whole output at a victim.
     * So a changed address starts a path validation (§8.2), and nothing moves
     * until the peer answers on the new path.
     *
     * Data keeps flowing to the old address meanwhile. That is the conservative
     * half of §9.3 -- an unvalidated path may carry data under a 3x limit, but
     * the old path has no such limit and, if the peer really moved, one round
     * trip of delay is all it costs. */
    /* Probes owed after a PTO (RFC 9002 §6.2.4).
     *
     * A PTO does not declare anything lost -- it says a round trip passed with
     * nothing acknowledged -- and the only way out is to make the peer say
     * something. Without a probe the connection can stall for good: loss
     * detection needs an acknowledgement of a *later* packet to declare an
     * earlier one lost, and if the last packet we sent was the one that
     * vanished, no later packet exists to be acknowledged. Found exactly that
     * way, by a client dropping one response (docs/http3/08 §2). */
    unsigned pto_probes;
    quic_enc_level_e pto_level;

    /* A NEW_TOKEN to hand the peer once its address is proven (§8.1.3), so its
     * next connection skips the Retry round trip. Retransmitted if lost, like
     * NEW_CONNECTION_ID and for the same reason: nothing else can reproduce it. */
    uint8_t  new_token[QUIC_TOKEN_MAX_LEN];
    size_t   new_token_len;
    int      new_token_sent;

    quicpath_t probe_path;
    uint8_t    probe_data[8];
    int        probe_active;
    int        probe_pending;        /* the challenge still has to go out */
    unsigned   probe_attempts;
    uint64_t   probe_next_us;        /* when to repeat it */
    uint64_t   probe_started_us;     /* for the once-per-3xPTO floor below */

    /* Where the datagram being processed came from. Set once per
     * quicconn_recv; the frame handlers need it to tell a PATH_RESPONSE that
     * arrived on the path being validated from one that took the old one, and
     * threading it through every signature to say so would be worse. */
    const quicpath_t* recv_path;

    quicconn_state_e state;
    uint64_t error_code;
    int      error_is_app;
    /* HANDSHAKE_DONE has gone out. It tells the client it may drop its
     * handshake keys and stop retransmitting (§7.5), and it must be sent
     * exactly once. */
    int      handshake_done_sent;

    /* The CONNECTION_CLOSE packet, kept so it can be re-sent (§10.2.1). */
    uint8_t  close_packet[256];
    size_t   close_packet_len;

    uint64_t idle_timeout_us;
    uint64_t last_activity_us;
    uint64_t close_deadline_us;

    /* Keep-alive (§10.1.2). `keepalive_us` is the configured interval already
     * clamped to half the *negotiated* idle timeout -- half, because the PING
     * has to reach the peer and be acknowledged before the shorter of the two
     * timers expires, and one interval of headroom is what pays for a lost
     * probe. Zero means the feature is off, which is the default.
     *
     * `keepalive_pending` is the flag the timer raises and the packet builder
     * clears, in the same shape as `pto_probes` next door -- deliberately not
     * that field, so that a keep-alive never looks like loss recovery in the
     * metrics or moves the PTO backoff.
     *
     * The timer does not check the flag before raising it: a probe the builder
     * could not fit has to be asked for again, and `keepalive_next_us` is what
     * keeps that retry to one per interval. An earlier version skipped the
     * raise while the flag was set, and a probe that was never built then
     * stopped the schedule dead -- caught by disabling the builder branch and
     * watching the *other* case fail. */
    uint64_t keepalive_conf_us;   /* what the policy asked for, unclamped */
    uint64_t keepalive_us;        /* what this connection will use */
    /* Earliest time another probe may be raised. Needed because `last_activity`
     * only moves on *receive*: a probe that goes unanswered leaves the timer
     * expired, and without this the tick would raise a fresh PING on every pass
     * instead of once per interval. */
    uint64_t keepalive_next_us;
    int      keepalive_pending;

    /* This connection's qlog, or NULL -- which is every connection unless
     * http3_qlog_dir is set and the budget was still open when it arrived.
     * Written only by the worker holding connection_s_lock, like everything
     * else here. */
    quicqlog_t* qlog;
    /* The congestion state last written to the qlog, so the transition is what
     * gets logged and not the state on every acknowledgement. A borrowed
     * pointer to one of a fixed set of string literals, which is why nothing
     * frees it. Meaningless without a log, and deliberately not readable by
     * anything else: the controller's own state is quiccc_t's business. */
    const char* qlog_cc_state;

    /* ---- What this connection cost the endpoint (docs/http3/08 §7b) ---- *
     *
     * When it started, and what the kernel's receive-overflow counter stood at
     * then. The difference at close is how many datagrams the socket dropped
     * while this connection was alive -- the one number that says whether a
     * transfer starved the receive path, and the reason the connection *after*
     * a big one may never be accepted at all.
     *
     * Sampled per connection rather than read from the process-wide metric
     * because that metric cannot answer "did it grow with the transfer": it is
     * a running total over every connection the worker ever had. */
    uint64_t accepted_us;
    uint32_t rx_overflow_at_accept;

    /* Unsent bytes across this connection's streams, as of the last time the
     * send path ran, plus whatever has been queued since (quicconn_note_queued).
     * `unsent_valid` is cleared wherever the buffers change behind its back:
     * the send path marking bytes sent, and streams being freed. */
    uint64_t unsent_cached;
    int      unsent_valid;

    /* Something is queued for sending.
     *
     * Atomic because quicconn_want_write is callable from a handler thread --
     * that is the whole point of it -- while every other setter runs on the
     * worker under connection_s_lock. Two handler threads finishing responses
     * on the same connection wrote it concurrently, which ThreadSanitizer
     * caught the first time HTTP/3 gave handler threads something to publish.
     * Release on store / acquire on load, so seeing the flag implies seeing the
     * data it announces -- the same contract connection_server_ctx_t::need_write
     * carries next door. */
    atomic_int want_write;

    /* Some stream may owe the peer a MAX_STREAM_DATA (docs/http3/09-options.md
     * §2.7).
     *
     * Without it __build_packet walked conn->streams on every packet to ask
     * each stream in turn, and the walk ran to the end of the list every time
     * because it writes almost nothing and so never fills the packet that would
     * stop it. Measured at a hundred streams: 104 node visits per packet for one
     * frame, 1.6-3.3% of the server's cycles spent answering "no".
     *
     * A hint, not a record: it may be up when nothing is owed (one wasted walk),
     * and the walk itself re-raises it when it could not finish. What it may not
     * do is be down while a stream owes, so it is raised in exactly the place
     * that can make quicflow_should_update true for a stream -- a receive
     * recording new data against the window (quicstream_on_data, and the final
     * size of a RESET_STREAM). Nothing else moves `used`: quicflow_consumed only
     * auto-tunes, and the send side is a different flow object.
     *
     * Atomic and cleared before the walk rather than after it, for the reason
     * the wake-up flag is (docs/http3/08 §7e): a receive concurrent with the
     * walk then leaves it raised and costs a walk, instead of being swallowed
     * and costing the peer its window. */
    atomic_int stream_flow_pending;

    struct quicconn* ep_next;   /* endpoint's connection list */
    struct quicconn* tx_next;   /* endpoint's send queue */

    /* Consecutive datagrams served by a worker other than the owner
     * (docs/http3/09-options.md §2.6).
     *
     * The kernel picks the worker by hashing the 4-tuple, and a client that
     * migrates or sits behind a NAT that rewrites its port changes that hash
     * without changing the connection. From then on every datagram arrives at a
     * worker that does not own the connection, while the owner keeps sweeping
     * it and draining its send queue -- two cores on one connection for the
     * rest of its life.
     *
     * Consecutive, not cumulative, on purpose: a run of them means the path
     * moved, whereas a NAT alternating between two ports produces a steady
     * trickle that no amount of rehoming would fix. Written under
     * connection_s_lock, like everything else the receive path touches. */
    uint32_t foreign_streak;
    /* One process-wide connection-limit reservation. It is acquired before
     * allocation and cleared exactly once by endpoint detach/error rollback. */
    int process_slot_reserved;
    int process_handshake_counted;

    /* Already waiting in the endpoint's send queue.
     *
     * Atomic and consulted before the queue's lock, because the answer is
     * almost always yes: a response of a few chunks asks to be sent ~150 times,
     * and only the first of those has anything to add (docs/http3/08 §7f). The
     * rest used to take a lock shared by every connection to discover it.
     *
     * Cleared by the worker *before* it serves the entry, which is what makes
     * the unlocked read safe -- the same rule as the wakeup flag next to it in
     * the endpoint. A publisher that reads 1 has its work picked up by the turn
     * that is about to run; one that reads 0 queues the connection again. */
    atomic_int in_tx_queue;
} quicconn_t;

/* Build a connection from a client's first Initial packet.
 *
 * `odcid` is that packet's Destination Connection ID, which both the Initial
 * keys and the transport parameters depend on. Returns NULL if the connection
 * could not be created; the caller drops the datagram.
 *
 * The returned connection is registered in the endpoint's tables and in the
 * worker's connection list. */
/* `address_validated` says the client proved this address by echoing a token
 * back, so the §8.1 anti-amplification limit does not apply. `retry_odcid` is
 * the Destination Connection ID of the Initial that provoked our Retry, and is
 * NULL unless this handshake followed one: after a Retry the client checks
 * *both* original_destination_connection_id (that first id) and
 * retry_source_connection_id (the id we chose for the Retry, which is the one
 * it is now addressing), and a server that reports only what it can see today
 * fails that check. */
quicconn_t* quicconn_accept(struct quicendpoint* endpoint,
                            const quiccid_t* odcid, const quiccid_t* peer_scid,
                            const quicpath_t* path, server_t* server,
                            int address_validated, const quiccid_t* retry_odcid);

void quicconn_free(quicconn_t* conn);

/* connection_t::close for a QUIC connection: detach from the endpoint's tables
 * so no further datagram can reach it, then drop the base reference. The object
 * is released when the last reference goes, like any other connection. */
int quicconn_close_cb(connection_t* connection);

/* Process one datagram. The caller has already routed it here by connection id
 * and holds connection_s_lock. Returns 0 if the connection should be closed. */
int quicconn_recv(quicconn_t* conn, const uint8_t* datagram, size_t len,
                  const quicpath_t* path, uint64_t now_us);

/* Build and send whatever is pending, within the congestion window, the pacer
 * and the anti-amplification budget. Returns 0 if the connection should be
 * closed. */
int quicconn_send(quicconn_t* conn, uint64_t now_us);

/* Mark the connection as having something to send, and wake its endpoint.
 * Callable from a handler thread; takes no lock of its own beyond the
 * endpoint's leaf lock. Declared taking connection_t* so the epoll layer can
 * call it without knowing what a quicconn_t is. */
void quicconn_want_write(connection_t* connection);

/* The keep-alive interval a connection will use, given what the policy asked
 * for and the idle timeout that was negotiated (§10.1.2). Zero configured means
 * zero -- the feature is off. Otherwise the interval is at most half the idle
 * timeout, because the PING must be sent *and answered* before the shorter of
 * the two ends' timers expires, and never below one second.
 *
 * Exposed as a pure function so the rule can be tested apart from a connection:
 * the interesting cases are arithmetic (a configured value larger than the
 * negotiated timeout is the one that matters, and it is the peer that chooses
 * that timeout), and reaching them through a handshake would prove less. */
uint64_t quicconn_keepalive_interval(uint64_t configured_us, uint64_t idle_us);

/* Timer work: idle timeout, loss detection, the close and drain periods.
 * Returns 0 when the connection has expired and must be freed. */
int quicconn_tick(quicconn_t* conn, uint64_t now_us);

/* When this connection next needs attention, or 0 if never. */
uint64_t quicconn_next_timeout(const quicconn_t* conn);

/* Begin closing with a transport error (§10.2). */
void quicconn_close(quicconn_t* conn, uint64_t error_code, int is_app,
                    uint64_t now_us);

/* ---- Streams, for the application layer ---- */

/* Find an open stream by id, or NULL. */
quicstream_t* quicconn_stream_find(quicconn_t* conn, uint64_t id);

/* Set a stream's send priority (RFC 9218 for HTTP/3: urgency 0..7, lower is
 * more urgent, and whether the response may be interleaved with its peers).
 *
 * On the connection rather than on the stream because the connection keeps the
 * count that decides whether the send loop ranks streams at all -- and because
 * a priority that only the stream knew about would be a priority the scheduler
 * never learned of. Calling it with the defaults is how a signal is withdrawn. */
void quicconn_stream_priority(quicconn_t* conn, quicstream_t* s,
                              uint8_t urgency, int incremental);

/* The application took `bytes` off a stream, so that much of the
 * connection-level receive window is free again. The stream's own window is
 * credited inside quicstream_read; this half needs the connection, which the
 * stream deliberately does not know. */
void quicconn_consumed(quicconn_t* conn, uint64_t bytes);

/* ---- Write-ahead back pressure ---- *
 *
 * quicsendbuf_write grows without bound on purpose: flow control is not a
 * buffer's business. Something above it therefore has to decide how far in
 * front of the network the application may run, or a gigabyte response becomes
 * a gigabyte of memory.
 *
 * The limit is per *connection*, not per stream. Per stream it would have to be
 * multiplied by initial_max_streams_bidi (100 here) to bound anything, which
 * makes the bound useless; per connection it is one number whatever the stream
 * count, and the send path's own round-robin already shares it out fairly.
 *
 * It bounds only the write-ahead. What has been sent and not acknowledged is
 * held for retransmission regardless, and is bounded by the congestion window
 * instead -- by the network, which is the right thing to be bounded by. */
#define QUICCONN_WRITE_AHEAD_MAX (256 * 1024)

/* Bytes written to this connection's streams that have not been packetised. */
uint64_t quicconn_unsent_bytes(const quicconn_t* conn);

/* How much more the application may write before it must wait. 0 means stop and
 * resume when the send path has drained (quicconn_send is what frees it).
 *
 * Answers from a value kept across calls rather than by walking the streams
 * every time. The walk was written on the assumption that this is asked once
 * per 16 KB chunk; measured, it is asked **146 times per request** -- the
 * write-ahead budget is shared by thirty streams, so each response goes out in
 * dribbles, and each dribble walked the whole list. That was 5300 pointer steps
 * per request and ~4 % of the server's CPU (docs/http3/08 §7f).
 *
 * The value is rebuilt by the walk on the first ask of each send turn and then
 * kept honest by quicconn_note_queued below. Not const, because asking now
 * remembers. */
size_t quicconn_write_room(quicconn_t* conn);

/* Open and close a write turn: between the two, quicconn_write_room answers
 * from a value taken once instead of walking the streams per call.
 *
 * The window is exactly a turn of h3conn_write, and that is what makes it
 * safe -- during it the application only *adds* to the buffers, and every
 * addition is declared through quicconn_note_queued. Nothing sends. Outside
 * the window the walk is used, so anything that empties a buffer by another
 * route (a test draining a stream by hand, a reset) is seen immediately. */
void quicconn_budget_open(quicconn_t* conn);
void quicconn_budget_close(quicconn_t* conn);

/* Tell the connection that `bytes` were just queued on one of its streams.
 *
 * The only thing the kept value cannot see for itself: it is refreshed when the
 * send path runs, and between two runs the application may write. Callers that
 * queue stream data and then ask for room again must say so, or the budget
 * reads high and the write-ahead limit stops limiting. */
void quicconn_note_queued(quicconn_t* conn, uint64_t bytes);

/* Open the next server-initiated unidirectional stream (§2.1), or NULL when the
 * peer's initial_max_streams_uni is exhausted or allocation fails.
 *
 * HTTP/3 needs several of these before it can say anything at all: the control
 * stream carrying SETTINGS, both QPACK streams, and a grease stream (RFC 9114
 * §6.2). Unlike peer-initiated streams there is no back-filling to do -- ids
 * are handed out in order here, so none is ever skipped. */
quicstream_t* quicconn_open_uni(quicconn_t* conn);

#endif

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

    /* Acknowledgement state, one per packet number space. */
    quicack_t ack[QUIC_ENC_COUNT];

    /* CRYPTO send buffers, one per level: handshake data is retransmitted the
     * same way stream data is. */
    quicsendbuf_t crypto_out[QUIC_ENC_COUNT];

    quicloss_t loss;
    quiccc_t   cc;
    quicpacer_t pacer;

    /* Streams, and the limits that bound them. */
    quicstream_t* streams;
    size_t    stream_count;
    uint64_t  next_peer_bidi;   /* lowest client bidi id not yet opened */
    uint64_t  next_peer_uni;
    uint64_t  next_local_uni;

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

    struct quicconn* ep_next;   /* endpoint's connection list */
    struct quicconn* tx_next;   /* endpoint's send queue */
    int      in_tx_queue;
} quicconn_t;

/* Build a connection from a client's first Initial packet.
 *
 * `odcid` is that packet's Destination Connection ID, which both the Initial
 * keys and the transport parameters depend on. Returns NULL if the connection
 * could not be created; the caller drops the datagram.
 *
 * The returned connection is registered in the endpoint's tables and in the
 * worker's connection list. */
quicconn_t* quicconn_accept(struct quicendpoint* endpoint,
                            const quiccid_t* odcid, const quiccid_t* peer_scid,
                            const quicpath_t* path, server_t* server);

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
 * resume when the send path has drained (quicconn_send is what frees it). */
size_t quicconn_write_room(const quicconn_t* conn);

/* Open the next server-initiated unidirectional stream (§2.1), or NULL when the
 * peer's initial_max_streams_uni is exhausted or allocation fails.
 *
 * HTTP/3 needs several of these before it can say anything at all: the control
 * stream carrying SETTINGS, both QPACK streams, and a grease stream (RFC 9114
 * §6.2). Unlike peer-initiated streams there is no back-filling to do -- ids
 * are handed out in order here, so none is ever skipped. */
quicstream_t* quicconn_open_uni(quicconn_t* conn);

#endif

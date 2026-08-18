#define _GNU_SOURCE
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "metrics.h"
#include "quicbeacon.h"
#include "quicconn.h"
#include "quicendpoint.h"
#include "quichp.h"
#include "quicpacket.h"
#include "quicqlog.h"
#include "quicretry.h"
#include "quictime.h"
#include "varint.h"

/* Largest packet we build. Below the path MTU with room to spare -- phase 9
 * adds discovery; until then a conservative fixed size beats a datagram that
 * is silently dropped by a tunnel. */
#define QUICCONN_MAX_PACKET QUIC_MAX_UDP_PAYLOAD_V4

/* Datagrams built per quicconn_send call. A cap rather than a loop to
 * exhaustion: one connection must not hold the worker while a large flight or
 * a large response goes out. Whatever is left keeps want_write raised.
 *
 * Four for a long time, and four was too few for a reason that has nothing to
 * do with fairness: consecutive datagrams of one connection are what the
 * transmit batch coalesces into a single GSO message (udpsocket.c), so a turn
 * that stops at four caps the run at four however much the pacer and the window
 * would have allowed. The batch itself holds ~32 datagrams, which is where this
 * number comes from; the congestion window and the pacer stop the loop long
 * before it on any real path. */
#define QUICCONN_SEND_ROUNDS 32

/* What __build_packet holds back for the header it has not written yet: a long
 * header with two connection ids, a length and a packet number fits inside it
 * with room to spare. Deliberately generous -- the cost is a few unused bytes
 * per packet, and the alternative is sizing the payload against a header whose
 * length is not known until the frames are done. */
#define QUICCONN_HEADER_RESERVE 64

/* The smallest payload worth building a packet for. Below it the packet costs
 * more than it carries, and the caller has better uses for the remaining
 * space -- there is always a next datagram. */
#define QUICCONN_MIN_PAYLOAD 32

/* ---- Small helpers ---- */

/* ---- qlog helpers (docs/http3/04 §10) ----
 *
 * The names are the ones draft-ietf-quic-qlog-quic-events uses, so that a trace
 * written here opens in qvis without a translation step -- which is the whole
 * reason for emitting a standard format rather than our own log lines. */
static const char* __qlog_level(quic_enc_level_e level) {
    switch (level) {
    case QUIC_ENC_INITIAL:   return "initial";
    case QUIC_ENC_EARLY:     return "0RTT";
    case QUIC_ENC_HANDSHAKE: return "handshake";
    default:                 return "1RTT";
    }
}

/* Printable form of one endpoint of a path. Both halves are wanted together
 * everywhere they are wanted at all, and inet_ntop plus a port is three lines
 * every time. */
static void __qlog_addr(const struct sockaddr_storage* addr, char* out,
                        size_t out_len, unsigned* port) {
    if (out_len > 0) out[0] = 0;
    if (port != NULL) *port = 0;
    if (addr == NULL) return;

    if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6* in6 = (const struct sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, out, (socklen_t)out_len);
        if (port != NULL) *port = ntohs(in6->sin6_port);
        return;
    }

    const struct sockaddr_in* in = (const struct sockaddr_in*)addr;
    inet_ntop(AF_INET, &in->sin_addr, out, (socklen_t)out_len);
    if (port != NULL) *port = ntohs(in->sin_port);
}

/* Congestion state as the recovery schema names it. Derived rather than stored
 * because the controllers do not agree on what a state is: NewReno and CUBIC
 * have slow start, recovery and congestion avoidance, and BBR has four phases
 * of its own that mean something else entirely. What a reader wants is the
 * one-word answer to "why is it sending this much". */
static const char* __qlog_cc_state(const quicconn_t* conn, uint64_t now_us) {
    if (conn->cc.algorithm == QUICCC_BBR) {
        switch (conn->cc.bbr.state) {
        case QUICBBR_STARTUP:   return "startup";
        case QUICBBR_DRAIN:     return "drain";
        case QUICBBR_PROBE_RTT: return "probe_rtt";
        default:                return "probe_bw";
        }
    }

    if (conn->cc.recovery_start_us != 0 && now_us < conn->cc.recovery_start_us)
        return "recovery";

    return conn->cc.cwnd < conn->cc.ssthresh ? "slow_start" : "congestion_avoidance";
}

/* The transition, not the state: a connection acknowledges thousands of times
 * and changes state a handful, and a log that repeated the state per
 * acknowledgement would bury every other event in it.
 *
 * Compared with strcmp rather than by a derived number, and that is not
 * pedantry -- the first version added the first two characters, which makes
 * BBR's "probe_bw" and "probe_rtt" the same state and hides exactly the
 * transition BBR is read for. */
static void __qlog_cc_state_update(quicconn_t* conn, uint64_t now_us) {
    if (conn->qlog == NULL) return;

    const char* state = __qlog_cc_state(conn, now_us);
    if (conn->qlog_cc_state != NULL && strcmp(conn->qlog_cc_state, state) == 0)
        return;

    conn->qlog_cc_state = state;
    QLOG(conn->qlog, "recovery", "congestion_state_updated", "\"new\":\"%s\"", state);
}

static int __key_update_arm(quicconn_t* conn);
static void __cids_replenish(quicconn_t* conn);
static int __path_same(const quicpath_t* a, const quicpath_t* b);
static void __path_probe_succeed(quicconn_t* conn);

static quicconn_t* __conn_of(connection_t* connection) {
    /* Safe because conn is the first member of quicconn_t, which is also why
     * that placement is load-bearing rather than stylistic. */
    return (quicconn_t*)connection;
}

/* The keep-alive interval this connection will actually use: what the operator
 * configured, but never more than half the negotiated idle timeout (§10.1.2).
 * Called both at accept and again when the peer's parameters arrive, because the
 * peer may hand us a shorter timeout than our own -- Chrome offers 30 s -- and
 * an interval computed against ours alone would then be useless: the PING would
 * be sent after the connection had already died at the other end.
 *
 * The floor is one second: an interval below that turns a quiet connection into
 * a packet generator, and nothing about §10.1.2 asks for it. */
uint64_t quicconn_keepalive_interval(uint64_t configured_us, uint64_t idle_us) {
    if (configured_us == 0) return 0;

    /* No negotiated timeout means nothing to outrun, so the configured value
     * stands as it is. */
    uint64_t interval = configured_us;
    if (idle_us > 0 && idle_us / 2 < interval) interval = idle_us / 2;

    /* One second, whatever the arithmetic says. An idle timeout of a second or
     * two would otherwise produce sub-second pinging, and a connection that
     * cannot survive that gap is not worth the traffic. */
    if (interval < 1000000) interval = 1000000;

    return interval;
}

static void __keepalive_recompute(quicconn_t* conn) {
    conn->keepalive_us = quicconn_keepalive_interval(conn->keepalive_conf_us,
                                                     conn->idle_timeout_us);
}

static void __touch(quicconn_t* conn, uint64_t now_us) {
    /* Only bytes *received* count as activity: a server talking to a peer that
     * has gone away must still time out, so our own sends cannot keep the
     * connection alive. */
    conn->last_activity_us = now_us;
}

/* ---- Send scheduling (RFC 9218 §10, applied by the layer above) ----
 *
 * Two questions, kept apart on purpose.
 *
 * **Whether to schedule at all.** A connection where nobody signalled a
 * priority has every stream at the default urgency, and RFC 9218's own
 * recommendation for that case -- finish equal-urgency, non-incremental
 * responses one at a time, lowest stream id first -- is exactly what the list
 * order already produces. So `prio_streams` gates the whole thing: while it is
 * zero the send loop does what it did before this existed, at the cost it did
 * it before, and no traffic that does not ask for scheduling pays for it.
 *
 * **Our own service streams are outside the scheme.** The control and QPACK
 * streams carry protocol machinery, not responses, and RFC 9218 has nothing to
 * say about them. Ranking them by urgency would mean a client that asks for one
 * urgent response could delay a GOAWAY or a QPACK instruction behind it. They
 * are opened before any request, so leaving them out of the ranking keeps them
 * where the list already put them: first. */

static int __sched_is_service(const quicstream_t* s) {
    return quic_stream_kind(s->id) == QUIC_STREAM_SERVER_UNI;
}

static int __sched_is_prioritised(const quicstream_t* s) {
    return s->sched_urgency != QUIC_SCHED_URGENCY_DEFAULT || s->sched_incremental;
}

typedef struct {
    int      active;        /* rank streams at all */
    uint8_t  urgency;       /* the bucket whose turn it is */
    int      incremental;   /* that bucket holds only incremental streams */
    uint64_t stream_id;     /* and this one's turn it is within it */
} quicsched_t;

/* One pass over the streams, and only for a connection that signalled
 * something. Picks the bucket to serve, and within it decides between the two
 * rules RFC 9218 §10 gives:
 *
 *   - non-incremental responses are finished one at a time, lowest id first,
 *     because a resource that is useless until complete is worth finishing;
 *   - incremental ones share, one turn each, so a response that is useful in
 *     pieces gets its pieces out.
 *
 * The RFC says nothing about a bucket holding both. We finish the
 * non-incremental ones first, for the same reason the RFC gives for finishing
 * them at all -- what they gate cannot start until they are done, while an
 * incremental response loses only latency by waiting. */
static void __sched_select(quicconn_t* conn, quicsched_t* out) {
    out->active = 0;
    out->urgency = QUIC_SCHED_URGENCY_DEFAULT;
    out->incremental = 0;
    out->stream_id = 0;

    if (conn->prio_streams == 0) return;

    int best = -1;
    int bucket_sequential = 0;
    quicstream_t* first_incremental = NULL;
    quicstream_t* after_cursor = NULL;

    for (quicstream_t* s = conn->streams; s != NULL; s = s->next) {
        if (__sched_is_service(s) || !quicstream_wants_send(s)) continue;

        const int urgency = s->sched_urgency;

        if (urgency > best && best >= 0) continue;

        if (best < 0 || urgency < best) {
            /* A more urgent bucket than anything seen so far discards what was
             * gathered for the old one. */
            best = urgency;
            bucket_sequential = 0;
            first_incremental = NULL;
            after_cursor = NULL;
        }

        if (!s->sched_incremental) {
            bucket_sequential = 1;
            continue;
        }

        if (first_incremental == NULL) first_incremental = s;
        if (after_cursor == NULL && s->id > conn->sched_rr_id) after_cursor = s;
    }

    if (best < 0) return;   /* only service streams have anything to send */

    out->active = 1;
    out->urgency = (uint8_t)best;

    if (bucket_sequential) return;   /* list order settles the bucket */

    quicstream_t* turn = after_cursor != NULL ? after_cursor : first_incremental;
    if (turn != NULL) {
        out->incremental = 1;
        out->stream_id = turn->id;
    }
}

void quicconn_stream_priority(quicconn_t* conn, quicstream_t* s,
                              uint8_t urgency, int incremental) {
    if (conn == NULL || s == NULL) return;

    if (urgency > QUIC_SCHED_URGENCY_MAX) urgency = QUIC_SCHED_URGENCY_MAX;

    const int was = __sched_is_prioritised(s);

    s->sched_urgency = urgency;
    s->sched_incremental = incremental ? 1 : 0;

    const int now = __sched_is_prioritised(s);

    if (!was && now) conn->prio_streams++;
    else if (was && !now && conn->prio_streams > 0) conn->prio_streams--;
}

static quicstream_t* __stream_find(quicconn_t* conn, uint64_t id) {
    for (quicstream_t* s = conn->streams; s != NULL; s = s->next)
        if (s->id == id) return s;

    return NULL;
}

/* At the tail, so the list reads in the order the streams were opened, which is
 * the order the send loop then serves them in.
 *
 * It used to prepend, and the cost of that was not a detail of list order: the
 * loop that fills a packet with stream data starts at the head every time and
 * gives the first stream that can send as much of the packet as it will take,
 * so the head stream holds the connection until it is finished or blocked. With
 * newest-first that head is the *last* request, and four large files asked for
 * together were delivered strictly in reverse -- the file the client asked for
 * first arrived last, after every other one had finished. A page waiting on its
 * first stylesheet waited for the whole set.
 *
 * Ascending order is also what RFC 9218 §7 recommends for responses of equal
 * urgency that are not incremental: serve them one at a time, lowest stream id
 * first, because a resource that is only useful complete is worth finishing.
 * The unidirectional control and QPACK streams are opened before any request
 * and so stay ahead of them, which is what they need.
 *
 * A tail pointer rather than a walk to the end: __stream_ensure opens every
 * stream up to the id the peer used, so a client that jumps straight to a high
 * id opens them in a loop -- and a walk inside that loop is quadratic in a
 * count the peer chooses (initial_max_streams_bidi goes to 65536). */
static void __stream_append(quicconn_t* conn, quicstream_t* s) {
    s->next = NULL;

    if (conn->streams_tail != NULL) conn->streams_tail->next = s;
    else conn->streams = s;

    conn->streams_tail = s;
    conn->stream_count++;
}

/* How many streams of a kind the peer may have opened by now.
 *
 * The transport parameter is only the *first* limit. Every MAX_STREAMS frame
 * raises it, and enforcement has to follow: checking against the initial value
 * for the life of the connection means the credit handed back for finished
 * streams is advertised and then punished for being used -- the peer opens the
 * 101st stream because we told it to, and the connection dies with
 * STREAM_LIMIT_ERROR. That is what killed every h3 connection after a hundred
 * requests, browsers included.
 *
 * The limit *sent* rather than the limit acknowledged: a MAX_STREAMS lost on
 * the way is a limit the peer will not use, and being generous here costs
 * nothing, while being strict would reject a stream the peer opened legally.
 * No MAX_STREAMS_UNI is ever sent -- the three h3 control streams live as long
 * as the connection, so there is no credit to return -- and the parameter stays
 * the whole of the unidirectional limit. */
static uint64_t __streams_limit(const quicconn_t* conn, int uni) {
    if (uni) return conn->local_params.initial_max_streams_uni;

    return conn->max_streams_bidi_sent > conn->local_params.initial_max_streams_bidi
           ? conn->max_streams_bidi_sent
           : conn->local_params.initial_max_streams_bidi;
}

/* Open a peer-initiated stream, and every stream of the same kind below it.
 *
 * §2.1: ids are a counter, and a peer may skip the ones it decided not to use.
 * Opening 12 without opening 0, 4 and 8 first would leave those ids permanently
 * unusable and the concurrency accounting wrong. */
static quicstream_t* __stream_open_peer(quicconn_t* conn, uint64_t id) {
    const uint64_t kind = id & 0x03;
    uint64_t* next = quic_stream_is_uni(id) ? &conn->next_peer_uni : &conn->next_peer_bidi;

    /* An index, like the counter it is compared against -- the id itself is
     * four times larger, and comparing the two opened four streams for every
     * one asked for. The extras are peer-initiated streams nothing will ever
     * finish, so they are never reaped either: 20000 requests left 28000 of
     * them on the list, every one of them walked on every packet. */
    const uint64_t index = quic_stream_index(id);

    quicstream_t* result = NULL;

    while (*next <= index) {
        const uint64_t open_id = (*next << 2) | kind;
        *next += 1;

        quicstream_t* s = __stream_find(conn, open_id);
        if (s == NULL) {
            s = quicstream_create(open_id,
                                  quic_stream_is_uni(open_id)
                                      ? conn->local_params.initial_max_stream_data_uni
                                      : conn->local_params.initial_max_stream_data_bidi_remote,
                                  conn->local_params.initial_max_stream_data_bidi_remote,
                                  quic_stream_is_uni(open_id)
                                      ? 0
                                      : conn->peer_params.initial_max_stream_data_bidi_local);
            if (s == NULL) return NULL;

            __stream_append(conn, s);
        }

        if (open_id == id) result = s;
    }

    return result != NULL ? result : __stream_find(conn, id);
}

quicstream_t* quicconn_stream_find(quicconn_t* conn, uint64_t id) {
    if (conn == NULL) return NULL;

    return __stream_find(conn, id);
}

void quicconn_consumed(quicconn_t* conn, uint64_t bytes) {
    if (conn == NULL || bytes == 0) return;

    quicflow_consumed(&conn->recv_flow, bytes, conn->loss.smoothed_rtt_us, 0);

    /* The credit is only real once the peer is told, and the frame that carries
     * it is built on the next send turn. */
    atomic_store_explicit(&conn->want_write, 1, memory_order_release);
}

uint64_t quicconn_unsent_bytes(const quicconn_t* conn) {
    if (conn == NULL) return 0;

    /* Summed rather than counted incrementally. The list is bounded by
     * initial_max_streams_bidi (100), and this runs once per chunk written --
     * per 16 KB, not per byte -- so a walk costs less than the two hooks a
     * running total would need in quicstream_write and quicsendbuf_mark_sent,
     * and cannot drift out of step with the buffers it describes. */
    uint64_t total = 0;
    for (const quicstream_t* s = conn->streams; s != NULL; s = s->next)
        total += quicsendbuf_unsent_bytes(&s->send);

    return total;
}

void quicconn_budget_open(quicconn_t* conn) {
    if (conn == NULL) return;

    conn->unsent_cached = quicconn_unsent_bytes(conn);
    conn->unsent_valid = 1;
}

void quicconn_budget_close(quicconn_t* conn) {
    if (conn != NULL) conn->unsent_valid = 0;
}

void quicconn_note_queued(quicconn_t* conn, uint64_t bytes) {
    if (conn == NULL || !conn->unsent_valid) return;

    conn->unsent_cached += bytes;
}

size_t quicconn_write_room(quicconn_t* conn) {
    if (conn == NULL) return 0;

    /* Inside a write turn the answer is kept; outside one it is walked, which
     * is what makes this safe: the kept value can only be wrong if bytes leave
     * the buffers while it is held, and nothing sends during a write turn.
     * A cache with no such window drifts the moment anyone marks bytes sent by
     * another route -- which the unit tests do, and which is how this was
     * caught rather than deployed. */
    const uint64_t unsent = conn->unsent_valid ? conn->unsent_cached
                                               : quicconn_unsent_bytes(conn);

    if (unsent >= QUICCONN_WRITE_AHEAD_MAX) return 0;

    return (size_t)(QUICCONN_WRITE_AHEAD_MAX - unsent);
}

quicstream_t* quicconn_open_uni(quicconn_t* conn) {
    if (conn == NULL) return NULL;

    /* §4.6: our own streams are bounded by what the peer allowed us, and the
     * limit counts streams, not ids -- next_local_uni is the count so far. */
    if (conn->next_local_uni >= conn->peer_params.initial_max_streams_uni) return NULL;

    const uint64_t id = (conn->next_local_uni << 2) | QUIC_STREAM_SERVER_UNI;

    /* Send-only: the receive limits are zero because nothing may arrive on it,
     * and the send limit is what the peer granted for our unidirectional
     * streams. */
    quicstream_t* s = quicstream_create(id, 0, 0,
                                        conn->peer_params.initial_max_stream_data_uni);
    if (s == NULL) return NULL;

    conn->next_local_uni++;

    __stream_append(conn, s);

    return s;
}

/* ---- TLS bridge callbacks ---- */

static int __on_secret(void* ctx, quic_enc_level_e level, quictls_dir_e dir,
                       quic_aead_e suite, const uint8_t* secret, size_t len) {
    quicconn_t* conn = ctx;

    conn->suite = suite;

    quickeys_t* keys = dir == QUICTLS_DIR_READ ? &conn->rx[level] : &conn->tx[level];

    if (!quickeys_install(keys, suite, secret, len)) {
        log_error("quicconn: cannot install keys for level %d\n", (int)level);
        return 0;
    }

    /* The application read keys are the only ones a key update ever touches, so
     * this is where the next generation is first armed (§6.1). */
    if (level == QUIC_ENC_APP && dir == QUICTLS_DIR_READ)
        (void)__key_update_arm(conn);

    return 1;
}

static int __on_crypto(void* ctx, quic_enc_level_e level,
                       const uint8_t* data, size_t len) {
    quicconn_t* conn = ctx;

    /* Into a send buffer, not straight onto the wire: CRYPTO data is
     * retransmitted exactly like stream data, and the packet builder decides
     * how much fits. */
    return quicsendbuf_write(&conn->crypto_out[level], data, len);
}

static int __on_peer_params(void* ctx, const quictp_t* params) {
    quicconn_t* conn = ctx;

    /* §7.3: the client MUST send initial_source_connection_id, and it must be
     * the Source Connection ID of the Initial it actually sent. The check is
     * what stops a handshake being spliced between two connections -- an
     * attacker relaying our flight into a connection of its own is caught here
     * and nowhere else, because every other field it can copy verbatim.
     *
     * Compared against the id remembered at accept rather than peer_cids[0]:
     * the two agree today, but the CID list is the peer's to rewrite, and this
     * comparison must be against what arrived in that first packet. */
    if (!params->has_initial_scid) {
        log_error("quic: peer sent no initial_source_connection_id\n");
        return 0;
    }

    if (params->initial_scid.len != conn->peer_initial_scid.len ||
        memcmp(params->initial_scid.data, conn->peer_initial_scid.data,
               params->initial_scid.len) != 0) {
        log_error("quic: initial_source_connection_id does not match the packet\n");
        return 0;
    }

    conn->peer_params = *params;
    conn->peer_params_seen = 1;

    /* The peer's limits open our send windows. Until this arrives we may send
     * nothing but handshake data. */
    quicflow_update_limit(&conn->send_flow, params->initial_max_data);

    conn->loss.max_ack_delay_us = params->max_ack_delay * 1000;

    if (params->max_idle_timeout > 0) {
        /* §10.1: the effective timeout is the smaller of the two, or whichever
         * one is non-zero. */
        const uint64_t peer_us = params->max_idle_timeout * 1000;
        if (conn->idle_timeout_us == 0 || peer_us < conn->idle_timeout_us)
            conn->idle_timeout_us = peer_us;
    }

    /* The negotiated timeout is only known now, and the keep-alive interval is
     * measured against it. */
    __keepalive_recompute(conn);

    return 1;
}

static void __on_alert(void* ctx, uint8_t alert) {
    quicconn_t* conn = ctx;

    /* A transport parameter we refused reaches TLS as a handshake failure, and
     * the alert for it arrives here first -- so without this the connection
     * would already be CLOSING with CRYPTO_ERROR by the time the caller of
     * quictls_advance gets to name the real reason. */
    if (conn->tls.transport_error != 0) {
        quicconn_close(conn, conn->tls.transport_error, 0, quic_now_us());
        return;
    }

    quicconn_close(conn, QUIC_CRYPTO_ERROR(alert), 0, quic_now_us());
}

static const quictls_ops_t __tls_ops = {
    .install_secret = __on_secret,
    .send_crypto = __on_crypto,
    .peer_params = __on_peer_params,
    .alert = __on_alert
};

/* Put the information a lost packet carried back on the queues that produced
 * it, and release the references.
 *
 * One function because there are two ways to learn a packet was lost -- an
 * acknowledgement of a later one, and the loss timer -- and they must agree.
 * They did not: the timer path handled only CRYPTO and STREAM and dropped the
 * rest on the floor, so an announcement lost on a quiet connection (where no
 * later acknowledgement ever comes, and the timer is therefore the only path)
 * was never re-sent. That is a bug duplicated handling invites, so the
 * duplication is what got removed.
 *
 * The frames are rebuilt from current state rather than replayed: a
 * retransmitted MAX_DATA must carry today's limit, not yesterday's. */
static void __requeue_lost(quicconn_t* conn, quic_enc_level_e level,
                           quicframe_ref_t* lost) {
    for (quicframe_ref_t* ref = lost; ref != NULL; ref = ref->next) {
        if (ref->type == QUIC_FRAME_CRYPTO) {
            quicsendbuf_lost(&conn->crypto_out[level], ref->offset,
                             (size_t)ref->len, 0);
        }
        else if (ref->type >= QUIC_FRAME_STREAM && ref->type < QUIC_FRAME_STREAM + 8) {
            quicstream_t* s = __stream_find(conn, ref->stream_id);
            if (s != NULL)
                quicsendbuf_lost(&s->send, ref->offset, (size_t)ref->len, ref->fin);
        }
        else if (ref->type == QUIC_FRAME_NEW_TOKEN) {
            conn->new_token_sent = 0;
            atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        }
        else if (ref->type == QUIC_FRAME_HANDSHAKE_DONE) {
            /* §13.3: retransmitted until acknowledged, and it is the one frame
             * where losing it strands the peer rather than costing it a round
             * trip. A client confirms the handshake on this frame and only then
             * drops its Handshake keys; without it, it probes the Handshake
             * space forever -- into a server that has already dropped those
             * keys and cannot even acknowledge the probes (docs/http3/08 §3j). */
            conn->handshake_done_sent = 0;
            atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        }
        else if (ref->type == QUIC_FRAME_NEW_CONNECTION_ID) {
            /* §13.3: unlike a limit, an id the peer never heard of cannot be
             * re-derived from anything, so the announcement is queued again.
             * The entry may have been retired meanwhile, in which case there is
             * nothing to announce and nothing to do. */
            for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++)
                if (conn->local_cids[i].active && conn->local_cids[i].seq == ref->offset) {
                    conn->local_cids[i].announced = 0;
                    atomic_store_explicit(&conn->want_write, 1, memory_order_release);
                    break;
                }
        }
        else if (ref->type == QUIC_FRAME_DATA_BLOCKED ||
                 ref->type == QUIC_FRAME_STREAM_DATA_BLOCKED) {
            /* §13.3: still blocked means still worth saying. Clearing the latch
             * rather than resending the frame verbatim, so the next one carries
             * the limit as it stands -- and if the peer has meanwhile raised it,
             * quicflow_should_send_blocked finds nothing to say and the send
             * loop simply carries on with the data. */
            quicflow_t* flow = NULL;

            if (ref->type == QUIC_FRAME_DATA_BLOCKED)
                flow = &conn->send_flow;
            else {
                quicstream_t* s = __stream_find(conn, ref->stream_id);
                if (s != NULL) flow = &s->send_flow;
            }

            if (flow != NULL) {
                flow->blocked_sent = 0;
                atomic_store_explicit(&conn->want_write, 1, memory_order_release);
            }
        }
        /* Other control frames carry a limit and are not queued for
         * retransmission: the next packet carries the current value anyway,
         * which is both simpler and more correct than resending a stale one. */
    }

    quicframe_ref_free(lost);
}

/* ---- Frame handling ---- */

static int __on_crypto_frame(quicconn_t* conn, quic_enc_level_e level,
                             const quicframe_t* frame) {
    /* RFC 9001 §6: QUIC does its own key updates, so a TLS KeyUpdate message is
     * not merely redundant here -- acting on it would move the TLS key schedule
     * out from under a packet protection that does not follow it. §6 names the
     * error exactly: CRYPTO_ERROR with unexpected_message.
     *
     * Read off the first byte of the message rather than left to the TLS stack:
     * OpenSSL's QUIC bridge hands post-handshake messages back without comment,
     * and a KeyUpdate arriving at 1-RTT was being accepted in silence. Only the
     * start of a message can be tested, which is what offset 0 means -- a
     * KeyUpdate is four bytes and never split. */
    if (level == QUIC_ENC_APP && frame->u.crypto.offset == 0 &&
        frame->u.crypto.len > 0 && frame->u.crypto.data[0] == 24 /* key_update */) {
        quicconn_close(conn, QUIC_CRYPTO_ERROR(10 /* unexpected_message */), 0,
                       quic_now_us());
        return 0;
    }

    /* A flight we already hold, arriving again while the handshake is still
     * running, is the peer telling us in so many words that it did not get
     * ours. Answering it now instead of waiting out a PTO is the difference
     * between a lost server flight costing a few milliseconds and costing 666
     * ms doubling each time -- and with no RTT sample yet, that backoff is what
     * a client's handshake timeout runs out of (docs/http3/08 §3l).
     *
     * Bounded by anti-amplification like everything else on this path, so a
     * peer replaying its Initial cannot use this to make us send more than
     * three times what it sent. */
    const int duplicate = quictls_crypto_is_duplicate(&conn->tls, level,
                                                      frame->u.crypto.offset,
                                                      (size_t)frame->u.crypto.len);

    /* Every byte of handshake the peer sends us, and whether we had it already.
     * A handshake that never completes is either data that did not arrive or
     * data that arrived and did not move the TLS stack, and those two look the
     * same from every other vantage point (docs/http3/08 §3v). Read together
     * with the `tls advance` line below: offsets seen here and no completion
     * there is the second case. */
    log_debug("quic: crypto cid=%02x%02x%02x%02x level=%d off=%llu len=%llu dup=%d\n",
              conn->odcid.data[0], conn->odcid.data[1],
              conn->odcid.data[2], conn->odcid.data[3],
              (int)level, (unsigned long long)frame->u.crypto.offset,
              (unsigned long long)frame->u.crypto.len, duplicate);

    if (!quictls_recv_crypto(&conn->tls, level, frame->u.crypto.offset,
                             frame->u.crypto.data, (size_t)frame->u.crypto.len)) {
        quicconn_close(conn, QUIC_CRYPTO_BUFFER_EXCEEDED, 0, quic_now_us());
        return 0;
    }

    if (duplicate && conn->state == QUICCONN_HANDSHAKE) {
        /* Every level we hold keys for: the flight the peer is missing spans
         * Initial and Handshake, and which half was lost is not knowable from
         * the level the duplicate arrived on. */
        for (int l = 0; l < QUIC_ENC_COUNT; l++)
            if (conn->tx[l].valid) quicsendbuf_requeue_unacked(&conn->crypto_out[l]);

        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
    }

    return 1;
}

static int __on_ack_frame(quicconn_t* conn, quic_enc_level_e level,
                          const quicframe_t* frame, uint64_t now_us) {
    quicrange_t acked;
    quicrange_init(&acked, 0);

    quicack_iter_t it;
    quicack_block_t block;
    quicack_iter_init(frame, &it);

    int r;
    while ((r = quicack_iter_next(&it, &block)) == 1)
        quicrange_add(&acked, block.smallest, block.largest);

    if (r < 0) {
        quicrange_free(&acked);
        quicconn_close(conn, QUIC_FRAME_ENCODING_ERROR, 0, now_us);
        return 0;
    }

    /* §13.1: acknowledging a packet we never sent is a protocol violation, and
     * it is how a peer would try to advance our loss detection artificially. */
    if (quicrange_max(&acked) >= conn->loss.space[level].next_pn) {
        quicrange_free(&acked);
        quicconn_close(conn, QUIC_PROTOCOL_VIOLATION, 0, now_us);
        return 0;
    }

    const uint64_t delay = frame->u.ack.delay
                           << (conn->local_params.ack_delay_exponent > 20
                               ? 20 : conn->local_params.ack_delay_exponent);

    /* RFC 9000 §13.4.2: an ACK for ECT-marked packets must carry monotonic ECN
     * counters and may not claim more marked packets than were sent. A path
     * that bleaches or fabricates codepoints loses ECN for this connection. */
    if (conn->ecn_enabled && conn->ecn_sent[level] > 0) {
        const uint64_t old0 = conn->ecn_peer_ect0[level];
        const uint64_t old1 = conn->ecn_peer_ect1[level];
        const uint64_t oldce = conn->ecn_peer_ce[level];
        const uint64_t total = frame->u.ack.ect0 + frame->u.ack.ect1 + frame->u.ack.ce;
        if (!frame->u.ack.has_ecn || frame->u.ack.ect0 < old0 ||
            frame->u.ack.ect1 < old1 || frame->u.ack.ce < oldce ||
            total > conn->ecn_sent[level]) {
            conn->ecn_enabled = 0;
            metrics_quic(METRICS_QUIC_ECN_VALIDATION_FAILED);
            QLOG(conn->qlog, "transport", "ecn_state_updated",
                 "\"new\":\"failed\",\"level\":\"%s\",\"sent\":%llu,"
                 "\"peer_ect0\":%llu,\"peer_ect1\":%llu,\"peer_ce\":%llu",
                 __qlog_level(level),
                 (unsigned long long)conn->ecn_sent[level],
                 (unsigned long long)frame->u.ack.ect0,
                 (unsigned long long)frame->u.ack.ect1,
                 (unsigned long long)frame->u.ack.ce);
        }
        else {
            if (!conn->ecn_validated) {
                conn->ecn_validated = 1;
                metrics_quic(METRICS_QUIC_ECN_VALIDATED);
                QLOG(conn->qlog, "transport", "ecn_state_updated",
                     "\"new\":\"capable\",\"level\":\"%s\"",
                     __qlog_level(level));
            }

            if (frame->u.ack.ce > oldce) {
                /* A congestion response with nothing lost: the counter is what
                 * separates it from a quiet connection, since packets_lost
                 * never moves for it. */
                metrics_quic(METRICS_QUIC_ECN_CE_CONGESTION);
                QLOG(conn->qlog, "recovery", "ecn_congestion",
                     "\"level\":\"%s\",\"ce\":%llu,\"previous_ce\":%llu",
                     __qlog_level(level),
                     (unsigned long long)frame->u.ack.ce,
                     (unsigned long long)oldce);
                conn->cc.ops->on_loss(&conn->cc, 0, now_us, now_us);
            }
            conn->ecn_peer_ect0[level] = frame->u.ack.ect0;
            conn->ecn_peer_ect1[level] = frame->u.ack.ect1;
            conn->ecn_peer_ce[level] = frame->u.ack.ce;
        }
    }

    quicframe_ref_t* lost = NULL;
    quicframe_ref_t* confirmed = NULL;
    quicloss_on_ack(&conn->loss, level, &acked, delay, now_us, &lost, &confirmed);

    if (level == QUIC_ENC_APP && conn->pmtud.outstanding &&
        quicrange_contains(&acked, conn->pmtud.probe_pn) &&
        quicpmtud_on_ack(&conn->pmtud, conn->pmtud.probe_pn, now_us,
                         quicloss_pto_us(&conn->loss, QUIC_ENC_APP))) {
        conn->cc.max_datagram_size = conn->pmtud.current;
        metrics_quic(METRICS_QUIC_PMTU_PROBES_SUCCEEDED);
        metrics_quic_pmtu(conn->pmtud.current);
        QLOG(conn->qlog, "recovery", "mtu_updated",
             "\"new\":%zu,\"ceiling\":%zu,\"trigger\":\"probe_acknowledged\"",
             conn->pmtud.current, conn->pmtud.ceiling);
    }

    /* Release what the peer has confirmed. Until this existed the send buffers
     * kept every byte ever written for the life of the connection, no stream
     * ever reached a terminal state, and the stream credit never came back --
     * a connection was spent after initial_max_streams_bidi requests. */
    for (quicframe_ref_t* ref = confirmed; ref != NULL; ref = ref->next) {
        if (ref->type == QUIC_FRAME_CRYPTO) {
            quicsendbuf_ack(&conn->crypto_out[level], ref->offset,
                            (size_t)ref->len, 0);
        }
        else if (ref->type >= QUIC_FRAME_STREAM && ref->type < QUIC_FRAME_STREAM + 8) {
            quicstream_t* s = __stream_find(conn, ref->stream_id);
            if (s != NULL) {
                quicsendbuf_ack(&s->send, ref->offset, (size_t)ref->len, ref->fin);

                /* §3.1: everything sent, and now everything acknowledged. */
                if (s->send_state == QUIC_SEND_DATA_SENT &&
                    quicsendbuf_complete(&s->send))
                    s->send_state = QUIC_SEND_DATA_RECVD;
            }
        }
    }

    quicframe_ref_free(confirmed);

    /* §6.5: the peer has read something we sent in the current key phase, so a
     * further update from it is no longer a way to make us derive key schedules
     * for free. */
    if (level == QUIC_ENC_APP && conn->key_update_unconfirmed &&
        quicrange_max(&acked) >= conn->key_update_tx_pn)
        conn->key_update_unconfirmed = 0;

    __requeue_lost(conn, level, lost);
    quicrange_free(&acked);

    /* After the losses this acknowledgement implied have been fed to the
     * controller, so the state reported is the one the next packet is sent
     * under and not the one it was sent under. */
    __qlog_cc_state_update(conn, now_us);

    atomic_store_explicit(&conn->want_write, 1, memory_order_release);

    return 1;
}

/* The stream a STOP_SENDING or MAX_STREAM_DATA names.
 *
 * Both frames talk about *our* send side, which is what makes this different
 * from an ordinary lookup -- there are four cases and only one of them is a
 * stream:
 *
 *  - a stream we cannot send on at all, meaning one of the peer's
 *    unidirectional ones: STREAM_STATE_ERROR whatever its state (§19.5, §19.10).
 *    Neither frame has any meaning there;
 *  - an id only we could have opened, which we have not: also STREAM_STATE_ERROR
 *    (§19.5). The peer is describing a stream that does not exist and that it
 *    cannot bring into existence;
 *  - a peer-initiated id we have not seen yet: legal, and it opens the stream,
 *    under the same limit a STREAM frame would face;
 *  - one we opened and have already released: gone, and the frame is late
 *    rather than wrong. Ignored, as §3.2 asks.
 *
 * Returns the stream, or NULL with `*ignore` telling the caller which of the
 * last two it was: 1 to carry on, 0 because the connection is now closing. */
/* `permitted` is quicstream_can_send for a frame about our send side
 * (STOP_SENDING, MAX_STREAM_DATA) and quicstream_can_receive for one about the
 * peer's (RESET_STREAM). Everything else below is the same four cases, and they
 * are subtle enough that a second copy of them would be a second set of bugs. */
static quicstream_t* __stream_for_frame(quicconn_t* conn, uint64_t id,
                                        uint64_t now_us, int* ignore,
                                        int (*permitted)(uint64_t)) {
    *ignore = 0;

    quicstream_t* s = __stream_find(conn, id);
    if (s != NULL) return s;

    if (!permitted(id)) {
        quicconn_close(conn, QUIC_STREAM_STATE_ERROR, 0, now_us);
        return NULL;
    }

    if (!quic_stream_is_peer_initiated(id)) {
        /* Ours to open. Below the count we have opened it is a released stream;
         * at or above it, one that never existed. */
        const uint64_t opened = quic_stream_is_uni(id) ? conn->next_local_uni : 0;

        if (quic_stream_index(id) >= opened) {
            quicconn_close(conn, QUIC_STREAM_STATE_ERROR, 0, now_us);
            return NULL;
        }

        *ignore = 1;
        return NULL;
    }

    /* Peer-initiated and unseen: the frame opens it, exactly as a STREAM frame
     * would, and the same limit applies. */
    const uint64_t opened = quic_stream_is_uni(id) ? conn->next_peer_uni
                                                   : conn->next_peer_bidi;
    if (quic_stream_index(id) < opened) {
        *ignore = 1;
        return NULL;
    }

    if (quic_stream_index(id) >= __streams_limit(conn, quic_stream_is_uni(id))) {
        quicconn_close(conn, QUIC_STREAM_LIMIT_ERROR, 0, now_us);
        return NULL;
    }

    s = __stream_open_peer(conn, id);
    if (s == NULL) {
        quicconn_close(conn, QUIC_INTERNAL_ERROR, 0, now_us);
        return NULL;
    }

    return s;
}

static quicstream_t* __stream_for_send_frame(quicconn_t* conn, uint64_t id,
                                             uint64_t now_us, int* ignore) {
    return __stream_for_frame(conn, id, now_us, ignore, quicstream_can_send);
}

/* RESET_STREAM speaks about the peer's send side, so the permission it needs is
 * ours to receive -- and, like a STREAM frame, it opens a peer stream we have
 * not seen (§3.2). Looking it up and ignoring the miss, which is what this did
 * before, threw away two things at once: the stream limit went unenforced for
 * ids that arrive as a reset, and the final size never reached the
 * connection-level flow controller §4.5 requires it to reach. */
static quicstream_t* __stream_for_recv_frame(quicconn_t* conn, uint64_t id,
                                             uint64_t now_us, int* ignore) {
    return __stream_for_frame(conn, id, now_us, ignore, quicstream_can_receive);
}

static int __on_stream_frame(quicconn_t* conn, const quicframe_t* frame,
                             uint64_t now_us) {
    const uint64_t id = frame->u.stream.id;

    if (!quic_stream_is_peer_initiated(id) && !__stream_find(conn, id)) {
        /* A frame for a server-initiated stream we never opened. */
        quicconn_close(conn, QUIC_STREAM_STATE_ERROR, 0, now_us);
        return 0;
    }

    quicstream_t* s = __stream_find(conn, id);
    if (s == NULL) {
        /* §4.6: the peer may not open more streams than we allowed. */
        const uint64_t index = quic_stream_index(id);
        const uint64_t limit = __streams_limit(conn, quic_stream_is_uni(id));

        if (index >= limit) {
            quicconn_close(conn, QUIC_STREAM_LIMIT_ERROR, 0, now_us);
            return 0;
        }

        s = __stream_open_peer(conn, id);
        if (s == NULL) {
            /* Not a failure if the stream simply no longer exists: it finished,
             * was released, and this is a retransmission of something already
             * delivered. §3.2 has a frame for a stream in a terminal state
             * ignored, and the open counter is what tells "gone" from "never
             * was".
             *
             * Releasing finished streams made this reachable for the first
             * time: before it every stream lived as long as the connection, so
             * a late frame always found its stream. */
            const uint64_t opened = quic_stream_is_uni(id) ? conn->next_peer_uni
                                                           : conn->next_peer_bidi;
            if (quic_stream_index(id) < opened) return 1;

            quicconn_close(conn, QUIC_INTERNAL_ERROR, 0, now_us);
            return 0;
        }
    }

    /* Connection-level flow control is separate from the stream's and applies
     * to the same bytes: it is what stops a peer opening many streams and
     * using each one's full window. */
    const uint64_t end = frame->u.stream.offset + frame->u.stream.len;
    const uint64_t previous = s->recv.max_offset;

    if (end > previous) {
        const uint64_t added = end - previous;
        if (!quicflow_record_received(&conn->recv_flow, conn->recv_flow.used + added)) {
            quicconn_close(conn, QUIC_FLOW_CONTROL_ERROR, 0, now_us);
            return 0;
        }
    }

    /* The mirror of `send`: the request as it reaches the transport. A
     * connection that completes its handshake, keeps receiving packets and
     * never answers is either one whose request never arrived or one whose
     * request arrived and stopped above this line, and until both sides of the
     * stream are printed those two are the same picture (docs/http3/08 §3v). */
    log_debug("quic: rstream cid=%02x%02x%02x%02x stream=%llu off=%llu len=%llu "
              "fin=%d\n",
              conn->odcid.data[0], conn->odcid.data[1],
              conn->odcid.data[2], conn->odcid.data[3],
              (unsigned long long)id, (unsigned long long)frame->u.stream.offset,
              (unsigned long long)frame->u.stream.len, frame->u.stream.fin);

    const quicstream_err_t err =
        quicstream_on_data(s, frame->u.stream.offset, frame->u.stream.data,
                           (size_t)frame->u.stream.len, frame->u.stream.fin);

    if (err != QUICSTREAM_OK) {
        quicconn_close(conn, err, 0, now_us);
        return 0;
    }

    /* This is what moves a stream's receive window and so the only thing that
     * can make it owe a MAX_STREAM_DATA. Raised unconditionally rather than by
     * asking quicflow_should_update here: the answer changes as the application
     * drains the stream, and the cheap place to ask is the send path, once. */
    atomic_store_explicit(&conn->stream_flow_pending, 1, memory_order_release);

    return 1;
}

static int __handle_frame(quicconn_t* conn, quic_enc_level_e level,
                          const quicframe_t* frame, uint64_t now_us) {
    /* §12.4: a frame in a packet number space that does not admit it is a
     * protocol violation -- a STREAM frame in an Initial packet, say. */
    if (!quicframe_allowed_in(frame->type, level)) {
        log_error("quic: frame 0x%llx not allowed at level %d\n",
                  (unsigned long long)frame->type, (int)level);
        quicconn_close(conn, QUIC_PROTOCOL_VIOLATION, 0, now_us);
        return 0;
    }

    if (frame->type >= QUIC_FRAME_STREAM && frame->type < QUIC_FRAME_STREAM + 8)
        return __on_stream_frame(conn, frame, now_us);

    switch (frame->type) {
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_PING:
        return 1;

    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        return __on_ack_frame(conn, level, frame, now_us);

    case QUIC_FRAME_CRYPTO:
        return __on_crypto_frame(conn, level, frame);

    case QUIC_FRAME_RESET_STREAM: {
        int ignore = 0;
        quicstream_t* s = __stream_for_recv_frame(conn, frame->u.reset_stream.id,
                                                  now_us, &ignore);
        if (s == NULL) return ignore;

        metrics_quic(METRICS_QUIC_STREAMS_RESET_RECEIVED);

        /* What this stream had already charged to the connection window, so the
         * charge below is the difference and never the whole stream twice. */
        const uint64_t counted = s->recv_flow.used;

        const quicstream_err_t err =
            quicstream_on_reset(s, frame->u.reset_stream.error,
                                frame->u.reset_stream.final_size);
        if (err != QUICSTREAM_OK) {
            quicconn_close(conn, err, 0, now_us);
            return 0;
        }

        /* The final size is recorded against the stream's receive window like
         * arriving data, so it moves the same limit -- see __on_stream_frame. */
        atomic_store_explicit(&conn->stream_flow_pending, 1, memory_order_release);

        /* §4.5: "the final size is used to account for all bytes on the stream
         * in the connection-level flow controller" -- including the bytes that
         * never arrived, which is precisely the interesting part of a reset.
         *
         * Without this our count of what the peer has spent stays below the
         * peer's own, and since the limit we advertise is derived from that
         * count (quicflow_should_update), the peer's usable window shrinks by
         * the abandoned tail of every stream it cancels, permanently. */
        const uint64_t delta = s->recv_flow.used > counted ? s->recv_flow.used - counted : 0;

        if (delta > 0) {
            if (!quicflow_record_received(&conn->recv_flow, conn->recv_flow.used + delta)) {
                quicconn_close(conn, QUIC_FLOW_CONTROL_ERROR, 0, now_us);
                return 0;
            }

            /* A MAX_DATA may be due now, and nothing else on this path would
             * build a packet to carry it. */
            atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        }

        return 1;
    }

    case QUIC_FRAME_STOP_SENDING: {
        int ignore = 0;
        quicstream_t* s = __stream_for_send_frame(conn, frame->u.stop_sending.id,
                                                  now_us, &ignore);
        if (s == NULL) return ignore;

        const quicstream_err_t err =
            quicstream_on_stop_sending(s, frame->u.stop_sending.error);
        if (err != QUICSTREAM_OK) {
            quicconn_close(conn, err, 0, now_us);
            return 0;
        }
        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        return 1;
    }

    case QUIC_FRAME_MAX_DATA:
        if (quicflow_update_limit(&conn->send_flow, frame->u.max_data.max))
            atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        return 1;

    case QUIC_FRAME_MAX_STREAM_DATA: {
        int ignore = 0;
        quicstream_t* s = __stream_for_send_frame(conn, frame->u.max_stream_data.id,
                                                  now_us, &ignore);
        if (s == NULL) return ignore;

        const quicstream_err_t err =
            quicstream_on_max_data(s, frame->u.max_stream_data.max);
        if (err != QUICSTREAM_OK) {
            quicconn_close(conn, err, 0, now_us);
            return 0;
        }
        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        return 1;
    }

    case QUIC_FRAME_MAX_STREAMS_BIDI:
    case QUIC_FRAME_MAX_STREAMS_UNI:
    case QUIC_FRAME_DATA_BLOCKED:
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
    case QUIC_FRAME_STREAMS_BLOCKED_BIDI:
    case QUIC_FRAME_STREAMS_BLOCKED_UNI:
        /* The BLOCKED family is advisory: it tells us the peer is stuck, which
         * our own flow control accounting already knows. Acted on by raising
         * limits at the normal time rather than immediately. */
        return 1;

    case QUIC_FRAME_NEW_CONNECTION_ID:
        if (conn->peer_cid_count < QUICCONN_MAX_PEER_CIDS)
            conn->peer_cids[conn->peer_cid_count++] = frame->u.new_cid.cid;
        return 1;

    case QUIC_FRAME_RETIRE_CONNECTION_ID: {
        const uint64_t seq = frame->u.retire_cid.seq;

        /* §19.16: a sequence number we never issued is a protocol violation --
         * a MUST, and the only way to notice a peer that is guessing. */
        if (seq >= conn->next_cid_seq) {
            quicconn_close(conn, QUIC_PROTOCOL_VIOLATION, 0, now_us);
            return 0;
        }

        for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++) {
            quiccid_entry_t* e = &conn->local_cids[i];
            if (!e->active || e->seq != seq) continue;

            /* Out of the routing table first: after this no datagram can find
             * the connection through it, which is the whole point of retiring. */
            quicendpoint_cid_forget(conn->endpoint, &e->cid);
            memset(e, 0, sizeof * e);
            break;
        }

        /* §5.1.1: a retirement is also a request for a replacement, and a peer
         * that retires without getting one runs out of ids to migrate with. */
        __cids_replenish(conn);

        return 1;
    }

    case QUIC_FRAME_PATH_CHALLENGE:
        /* §8.2.2: echo the data back. Answering a challenge and validating a
         * path of our own are different jobs -- the second one (probing a new
         * address before migrating to it) is docs/http3/09 §1.4 -- and this one
         * is required regardless of whether we ever do the first.
         *
         * The answer goes out on conn->path, which is the path recorded at
         * accept. Until migration exists that is the only path we have; a
         * challenge from a new address is answered to the old one, and fixing
         * that is part of §1.4, not of this. */
        memcpy(conn->path_response_data, frame->u.path.data,
               sizeof conn->path_response_data);
        conn->path_response_pending = 1;

        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        return 1;

    case QUIC_FRAME_PATH_RESPONSE:
        /* §8.2.3 validates on the data, and only on the path the challenge was
         * sent to: an answer that comes back by the old route says nothing
         * about the new one, and accepting it would be exactly the confusion an
         * off-path attacker wants (§9.3.3). */
        if (conn->probe_active && conn->recv_path != NULL &&
            __path_same(conn->recv_path, &conn->probe_path) &&
            memcmp(frame->u.path.data, conn->probe_data, sizeof conn->probe_data) == 0)
            __path_probe_succeed(conn);

        return 1;

    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        /* The peer's account of what we did wrong, and the only one there is:
         * it is not repeated and nothing else carries it. Logged because a
         * connection that simply stops looks identical to one the peer walked
         * away from. */
        log_error("quic: peer closed, %s error 0x%llx%s%.*s\n",
                  frame->type == QUIC_FRAME_CONNECTION_CLOSE_APP ? "application" : "transport",
                  (unsigned long long)frame->u.close.error,
                  frame->u.close.reason_len > 0 ? ": " : "",
                  (int)frame->u.close.reason_len,
                  frame->u.close.reason != NULL ? frame->u.close.reason : "");

        metrics_quic(METRICS_QUIC_CLOSED_PEER);

        if (conn->qlog != NULL) {
            /* The reason is bytes the peer chose, so it goes through the
             * escaper before it touches the trace -- a quote in it would
             * otherwise end the JSON object early and a newline would end the
             * record, corrupting the whole file rather than one field. */
            char reason[256];
            quicqlog_escape(frame->u.close.reason,
                            frame->u.close.reason_len, reason, sizeof reason);

            QLOG(conn->qlog, "connectivity", "connection_closed",
                 "\"owner\":\"remote\",\"%s_code\":%llu,\"reason\":\"%s\"",
                 frame->type == QUIC_FRAME_CONNECTION_CLOSE_APP
                     ? "application" : "connection",
                 (unsigned long long)frame->u.close.error, reason);
        }

        /* §10.2.2: enter draining and send nothing further -- not even an
         * acknowledgement. Answering would keep the exchange alive after both
         * ends have finished with it. */
        conn->state = QUICCONN_DRAINING;
        conn->close_deadline_us = now_us + quicloss_pto_us(&conn->loss, level) * 3;
        return 1;

    case QUIC_FRAME_HANDSHAKE_DONE:
    /* Both are server-only, and a client sending either is confused about which
     * end it is (§19.20, §19.7). NEW_TOKEN needs saying explicitly: without a
     * case of its own it reached the default below and came back as
     * FRAME_ENCODING_ERROR, which blames the encoding for what is a role
     * mistake -- the frame parsed perfectly well. */
    case QUIC_FRAME_NEW_TOKEN:
        quicconn_close(conn, QUIC_PROTOCOL_VIOLATION, 0, now_us);
        return 0;

    default:
        quicconn_close(conn, QUIC_FRAME_ENCODING_ERROR, 0, now_us);
        return 0;
    }
}

/* Release peer-initiated streams that are finished in both directions.
 *
 * "Finished" is strict on the send side: everything written must be
 * acknowledged, because until then a loss may still require the data back. A
 * stream freed early would take its send buffer with it and the retransmission
 * would find nothing.
 *
 * Called after each turn of the connection rather than from the stream code
 * itself: the h3 layer holds a pointer to the stream while it answers, and the
 * one place that knows both halves are done is here. */
static void __streams_reap(quicconn_t* conn) {
    quicstream_t** link = &conn->streams;
    /* The tail is rebuilt from the walk this function already makes, rather
     * than patched at the removal below: recovering the previous node from a
     * `quicstream_t**` is exactly the kind of pointer arithmetic that reads
     * fine and is wrong once. Last survivor wins; no survivor means an empty
     * list, and NULL is what an empty list's tail is. */
    quicstream_t* tail = NULL;

    while (*link != NULL) {
        quicstream_t* s = *link;

        const int send_done = s->send_state == QUIC_SEND_DATA_RECVD ||
                              s->send_state == QUIC_SEND_RESET_RECVD ||
                              (s->send_state == QUIC_SEND_RESET_SENT && !s->send_reset_pending) ||
                              quicsendbuf_complete(&s->send);

        const int recv_done = s->recv_state == QUIC_RECV_DATA_READ ||
                              s->recv_state == QUIC_RECV_RESET_READ ||
                              s->recv_state == QUIC_RECV_RESET_RECVD ||
                              !quicstream_can_receive(s->id);

        if (!send_done || !recv_done) {
            tail = s;
            link = &s->next;
            continue;
        }

        /* The application layer may still be holding this stream: h3 keeps the
         * request and response on it until the response is done. */
        if (s->app != NULL && s->app_done != NULL && !s->app_done(s->app)) {
            tail = s;
            link = &s->next;
            continue;
        }

        *link = s->next;
        conn->stream_count--;

        if (quic_stream_is_peer_initiated(s->id) && !quic_stream_is_uni(s->id)) {
            conn->peer_bidi_closed++;

            /* The credit is worth nothing until the peer hears about it, and
             * the frame that carries it only gets built when there is a reason
             * to build a packet. Without this the first MAX_STREAMS rode along
             * with the last response and the rest were never sent -- a peer
             * that had used its allowance then waited for credit that was
             * sitting here.
             *
             * But asking for a packet on *every* release paid for that safety
             * once per request: a stream is released when the peer acknowledges
             * the response, and at that moment there is nothing else to send,
             * so the credit left as a datagram of its own carrying four bytes.
             * Measured at 2.04 datagrams sent per request, one of them this
             * (docs/http3/08 §7j).
             *
             * The frame itself is written by every packet that finds credit
             * outstanding, so what is decided here is only whether the credit
             * is worth a packet of its own. It is when the peer is running out
             * -- and only then, because a peer with headroom will open another
             * stream, and that request is the ride this frame is waiting for. */
            const uint64_t announced = __streams_limit(conn, 0);
            const uint64_t headroom = announced > conn->next_peer_bidi
                                      ? announced - conn->next_peer_bidi : 0;

            uint64_t urgent = conn->local_params.initial_max_streams_bidi / 4;
            if (urgent == 0) urgent = 1;

            if (headroom <= urgent)
                atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        }

        metrics_quic(METRICS_QUIC_STREAMS_RELEASED);

        /* A prioritised stream that dies takes its count with it, or the
         * connection stays on the scheduling path for the rest of its life
         * after the one request that asked for it has finished. */
        if (__sched_is_prioritised(s) && conn->prio_streams > 0) conn->prio_streams--;

        quicstream_free(s);
    }

    conn->streams_tail = tail;
}

/* ---- Connection ids we answer to (RFC 9000 §5.1.1) ---- *
 *
 * A connection is reachable by several ids at once, and issuing spares is not a
 * nicety: §9.5 requires a peer to use a *different* id after it migrates, so a
 * peer with only the one it got at accept either cannot migrate or does so
 * observably. The ids live in the endpoint's shared table; this side owns which
 * ones exist. */

static quiccid_entry_t* __cid_slot_free(quicconn_t* conn) {
    for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++)
        if (!conn->local_cids[i].active) return &conn->local_cids[i];

    return NULL;
}

static size_t __cid_active_count(const quicconn_t* conn) {
    size_t n = 0;

    for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++)
        if (conn->local_cids[i].active) n++;

    return n;
}

/* One new id, registered and waiting to be announced. */
static int __cid_issue(quicconn_t* conn) {
    quiccid_entry_t* slot = __cid_slot_free(conn);
    if (slot == NULL) return 0;

    quiccid_t cid;
    cid.len = QUIC_LOCAL_CID_LEN;
    if (RAND_bytes(cid.data, QUIC_LOCAL_CID_LEN) != 1) return 0;

    /* The token first: an id the peer cannot recognise a reset for is worse
     * than no id at all, and this is the only step that can fail without
     * leaving something behind. */
    uint8_t token[16];
    if (!quicendpoint_reset_token(&cid, token)) return 0;

    if (!quicendpoint_cid_register(conn->endpoint, &cid, conn)) return 0;

    slot->cid = cid;
    slot->seq = conn->next_cid_seq++;
    memcpy(slot->reset_token, token, sizeof slot->reset_token);
    slot->active = 1;
    slot->announced = 0;

    metrics_quic(METRICS_QUIC_CIDS_ISSUED);

    atomic_store_explicit(&conn->want_write, 1, memory_order_release);

    return 1;
}

/* Keep the peer supplied up to what it said it would hold.
 *
 * §5.1.1 bounds this by the peer's active_connection_id_limit -- issuing past
 * it is a CONNECTION_ID_LIMIT_ERROR against us -- and by our own array, which
 * is what actually pays for them. */
static void __cids_replenish(quicconn_t* conn) {
    if (!conn->peer_params_seen) return;

    /* §18.2 puts the floor at 2, and a peer that omits the parameter means 2.
     * quictp_defaults already fills that in; the clamp is here because the
     * value crosses the wire and a zero would otherwise retire the id the
     * connection is running on. */
    uint64_t want = conn->peer_params.active_connection_id_limit;
    if (want < 2) want = 2;
    if (want > QUICCONN_MAX_LOCAL_CIDS) want = QUICCONN_MAX_LOCAL_CIDS;

    while (__cid_active_count(conn) < want)
        if (!__cid_issue(conn)) break;
}

/* ---- Path validation and migration (RFC 9000 §8.2, §9) ---- */

/* How many times a challenge is repeated before the new path is given up on.
 * §8.2.4 leaves the number open and asks only that it be bounded; three PTOs is
 * the same shape as the loss detector's own patience. */
#define QUICCONN_PROBE_ATTEMPTS 3

static int __path_same(const quicpath_t* a, const quicpath_t* b) {
    if (a->remote_len != b->remote_len) return 0;

    /* Compared as bytes of sockaddr_storage rather than field by field: the
     * family decides which fields exist, and getting that wrong silently
     * compares padding instead of the port. */
    return memcmp(&a->remote, &b->remote, a->remote_len) == 0;
}

/* Begin validating an address the peer has started sending from. */
static void __path_probe_start(quicconn_t* conn, const quicpath_t* path, uint64_t now_us) {
    /* §9.3: not more often than one validation per 3xPTO. An attacker able to
     * forge a source address on packets it captured could otherwise make us
     * probe an address of its choosing as fast as it can replay. */
    const uint64_t pto = quicloss_pto_us(&conn->loss, QUIC_ENC_APP);

    if (conn->probe_active && now_us < conn->probe_started_us + pto * 3) return;
    if (conn->probe_active && __path_same(&conn->probe_path, path)) return;

    if (RAND_bytes(conn->probe_data, sizeof conn->probe_data) != 1) return;

    conn->probe_path = *path;
    conn->probe_active = 1;
    conn->probe_pending = 1;
    conn->probe_attempts = 0;
    conn->probe_started_us = now_us;
    conn->probe_next_us = now_us + pto;

    metrics_quic(METRICS_QUIC_MIGRATION_ATTEMPTED);

    atomic_store_explicit(&conn->want_write, 1, memory_order_release);
}

/* The peer answered on the path being validated: move to it (§9.3). */
static void __path_probe_succeed(quicconn_t* conn) {
    conn->path = conn->probe_path;
    conn->probe_active = 0;
    conn->probe_pending = 0;

    /* §9.4: the new path is a different network. Carrying over a congestion
     * window and an RTT earned somewhere else is how a migration turns into a
     * burst of loss on the first packet.
     *
     * The estimator is cleared field by field rather than by re-running
     * quicloss_init: that would drop the sent lists on the floor, and they hold
     * packets still waiting to be acknowledged -- on the old path, but their
     * acknowledgements are still coming. */
    /* The configured initial window, not whatever the old path had grown --
     * same reasoning as the RTT estimator reset right below. The pacer follows
     * it: its bucket was filled at the old path's rate, and spending that on the
     * new one is the burst this reset exists to prevent. */
    quiccc_init_algorithm(&conn->cc, QUIC_DEFAULT_UDP_PAYLOAD,
                          quic_policy_conn()->initcwnd_packets,
                          quic_policy_conn()->cc_algorithm);
    quicpmtud_init(&conn->pmtud, QUIC_DEFAULT_UDP_PAYLOAD,
                   conn->path.remote.ss_family == AF_INET6
                       ? QUIC_MAX_UDP_PAYLOAD_V6 : QUIC_MAX_UDP_PAYLOAD_V4);
    quicpacer_init(&conn->pacer, &conn->cc, quic_policy_conn()->pacing);
    conn->pace_until_us = 0;

    conn->loss.have_rtt_sample = 0;
    conn->loss.latest_rtt_us = 0;
    conn->loss.smoothed_rtt_us = 0;
    conn->loss.rttvar_us = 0;
    conn->loss.min_rtt_us = 0;
    conn->loss.pto_count = 0;

    metrics_quic(METRICS_QUIC_MIGRATION_VALIDATED);

    log_info("quic: migrated to a new peer address\n");
}

/* ---- Key update (RFC 9001 §6) ---- */

/* Arm the next generation of receive keys. Called as soon as the 1-RTT keys
 * exist, and again after every update, so the schedule is never derived on the
 * packet path -- see the timing-signal note on quicconn_t::rx_next. */
static int __key_update_arm(quicconn_t* conn) {
    if (!conn->rx[QUIC_ENC_APP].valid) return 1;

    return quickeys_next(&conn->rx_next, &conn->rx[QUIC_ENC_APP]);
}

/* The peer's update opened a packet: adopt it.
 *
 * Both directions move together (§6.2). Ours has to: the peer switched its own
 * read keys when it updated, so a packet from us in the old phase is one it can
 * no longer open. */
static int __key_update_commit(quicconn_t* conn, uint64_t pn, uint64_t now_us) {
    /* The generation we are leaving becomes the retained one. Moved, not
     * copied -- the contexts are owned pointers, and rx_prev is released first
     * so the generation before last does not leak. */
    quickeys_free(&conn->rx_prev);
    conn->rx_prev = conn->rx[QUIC_ENC_APP];

    conn->rx[QUIC_ENC_APP] = conn->rx_next;
    memset(&conn->rx_next, 0, sizeof conn->rx_next);

    if (!quickeys_next(&conn->tx[QUIC_ENC_APP], &conn->tx[QUIC_ENC_APP]))
        return 0;

    conn->key_phase = !conn->key_phase;
    conn->key_phase_first_pn = pn;

    /* §6.3: the retained generation is good for as long as a packet sent before
     * the update could still be in flight. Three PTOs is the same figure the
     * closing period uses, and for the same reason. */
    conn->key_prev_expire_us = now_us + quicloss_pto_us(&conn->loss, QUIC_ENC_APP) * 3;

    /* §6.5: no further update until the peer acknowledges something we sent in
     * this phase. */
    conn->key_update_tx_pn = conn->loss.space[QUIC_ENC_APP].next_pn;
    conn->key_update_unconfirmed = 1;

    metrics_quic(METRICS_QUIC_KEY_UPDATE);

    log_info("quic: key update to phase %d at pn %llu\n",
             conn->key_phase, (unsigned long long)pn);

    /* Arming the next generation is deliberately last and its failure is not
     * fatal: the update itself has already succeeded, and a connection that
     * cannot pre-derive simply refuses the *following* update until it can. */
    (void)__key_update_arm(conn);

    return 1;
}

/* ---- Receive path ---- */

/* §4.9: throw away a packet number space whose keys are gone.
 *
 * Four pieces of state go together, and leaving any of them behind is a live
 * protocol failure rather than a leak: the keys (nothing may be sealed or
 * opened at that level again), the loss recovery space (nothing in it can ever
 * be acknowledged, so its bytes must leave the congestion window and its PTO
 * must stop), the pending acknowledgement (one we would no longer have the keys
 * to send), and any probe owed at that level (it could never be built, so the
 * counter would never come back down).
 *
 * What it looks like when this is missing -- it was, until Chrome's netlog said
 * so: the level stays armed for the life of the connection, its PTO keeps
 * firing, and every probe leaves as an *Initial* packet, padded to 1200 bytes
 * by §14.1 and therefore crowding the real datagram out of the send round. The
 * peer discarded those keys the moment the handshake moved on, so it counts
 * them as undecryptable and drops them: 396 packets at ENCRYPTION_INITIAL
 * against 264 that opened, on a single page load. The connection stays up and
 * the page simply never finishes.
 *
 * Outstanding CRYPTO frames are freed rather than requeued at the next level:
 * the handshake having moved on is itself the proof the peer no longer needs
 * them. */
static void __discard_space(quicconn_t* conn, quic_enc_level_e level) {
    if (!conn->tx[level].valid && !conn->rx[level].valid) return;

    quicframe_ref_free(quicloss_discard_space(&conn->loss, level));

    quickeys_free(&conn->tx[level]);
    quickeys_free(&conn->rx[level]);

    /* Freed before it is re-initialised: quicack_init memsets the struct, so
     * the range array the space accumulated would simply be forgotten. Two
     * spaces are discarded on every connection that completes a handshake, so
     * this leaked a couple of hundred bytes per connection for the life of the
     * process -- invisible to an ASan run against an idle server, and found by
     * the deterministic stand, which opens and closes connections inside one
     * (docs/http3/08-testing.md §2b). */
    quicack_free(&conn->ack[level]);
    quicack_init(&conn->ack[level]);

    /* The certificate chain lives in here; on a server it is the largest single
     * allocation the handshake makes. */
    quicsendbuf_free(&conn->crypto_out[level]);
    quicsendbuf_init(&conn->crypto_out[level]);

    if (conn->pto_level == level) conn->pto_probes = 0;
}

/* Which packet-number space a level is acknowledged in.
 *
 * RFC 9000 §12.3: 0-RTT and 1-RTT are ONE space. The numbers continue across
 * the two, and a server acknowledges a 0-RTT packet in a 1-RTT packet -- it has
 * no other way, since it never sends at the 0-RTT level. Tracking arrivals in a
 * separate ack[EARLY] would therefore lose them twice over: the ranges would
 * never be written into any packet, and the duplicate check would not see a
 * 1-RTT packet reusing a number a 0-RTT packet already had. */
static quic_enc_level_e __ack_space(quic_enc_level_e level) {
    return level == QUIC_ENC_EARLY ? QUIC_ENC_APP : level;
}

static int __process_packet(quicconn_t* conn, uint8_t* buf, size_t len,
                            const quicpkt_t* pkt, uint64_t now_us) {
    const quic_enc_level_e level = quicpkt_level(pkt->type);
    const quic_enc_level_e space = __ack_space(level);

    quickeys_t* keys = &conn->rx[level];
    if (!keys->valid) {
        /* Keys for this level do not exist yet -- a 1-RTT packet that overtook
         * the handshake, which is ordinary on a reordering path. Dropped rather
         * than buffered; the peer will retransmit. */
        QLOG(conn->qlog, "transport", "packet_dropped",
             "\"packet_type\":\"%s\",\"raw\":{\"length\":%zu},"
             "\"trigger\":\"keys_unavailable\"",
             __qlog_level(level), pkt->pkt_len);
        return 1;
    }

    /* Header protection first: the packet number length and the key phase are
     * under it, and the AEAD needs the number to build its nonce. */
    size_t pn_len = 0;
    uint64_t truncated = 0;
    int key_phase = 0;

    if (!quichp_remove(keys, buf, len, pkt->pn_offset, &pn_len, &truncated, &key_phase)) {
        QLOG(conn->qlog, "transport", "packet_dropped",
             "\"packet_type\":\"%s\",\"raw\":{\"length\":%zu},"
             "\"trigger\":\"header_protection_error\"",
             __qlog_level(level), pkt->pkt_len);
        return 1;
    }

    /* §17.2/§17.3: the reserved bits must be zero once protection is off. They
     * are two bits that carry nothing, which is exactly why they are worth
     * checking -- a peer that gets them wrong has a header-protection bug, and
     * every other field it produces is suspect. The mask differs by header
     * form: 0x0c in a long header, 0x18 in a short one, where the extra bits
     * are the spin bit and the key phase. */
    const uint8_t reserved_mask = (buf[0] & 0x80) != 0 ? 0x0c : 0x18;
    if ((buf[0] & reserved_mask) != 0) {
        log_error("quic: reserved bits set at level %d\n", (int)level);
        quicconn_close(conn, QUIC_PROTOCOL_VIOLATION, 0, now_us);
        return 0;
    }

    const uint64_t largest = conn->ack[space].any_received
                             ? conn->ack[space].largest : QUICPKT_NO_ACKED;
    const uint64_t pn = quicpkt_decode_pn(
        largest == QUICPKT_NO_ACKED ? 0 : largest, truncated, pn_len);

    /* Which generation of keys this packet belongs to (§6.3). Long headers have
     * no Key Phase bit and quichp reports 0 for them, so this only ever moves
     * off the current keys in the application space. */
    int updating = 0;

    if (level == QUIC_ENC_APP && key_phase != conn->key_phase) {
        if (pn < conn->key_phase_first_pn && conn->key_prev_expire_us > now_us &&
            conn->rx_prev.valid) {
            /* Sent before the update we already applied and reordered past it. */
            keys = &conn->rx_prev;
        }
        else if (conn->rx_next.valid && !conn->key_update_unconfirmed) {
            /* The peer is starting an update. Nothing is committed until the
             * packet actually opens -- the bit is not authenticated, and a
             * forged one must cost no more than a dropped packet. */
            keys = &conn->rx_next;
            updating = 1;
        }
        else {
            /* Either the retained generation has expired, or the peer is
             * toggling faster than §6.5 allows. Both are a dropped packet. */
            metrics_quic(METRICS_QUIC_DECRYPT_FAILURE);
            return 1;
        }
    }

    /* The AEAD's additional data is the header as it stands with the protection
     * removed -- which is why this runs after quichp_remove and not before. */
    const size_t header_len = pkt->pn_offset + pn_len;
    const size_t body_len = pkt->pkt_len - header_len;

    uint8_t plain[QUICCONN_MAX_PACKET];
    size_t plain_len = 0;

    if (body_len > sizeof plain) return 1;

    if (!quiccrypto_open(keys, pn, buf, header_len, buf + header_len, body_len,
                         plain, &plain_len)) {
        /* Ordinary: a packet from a dead connection, or one that crossed a key
         * update. Only the §6.6 limit turns it into an error. */
        metrics_quic(METRICS_QUIC_DECRYPT_FAILURE);
        QLOG(conn->qlog, "transport", "packet_dropped",
             "\"packet_type\":\"%s\",\"raw\":{\"length\":%zu},"
             "\"trigger\":\"decryption_failure\"",
             __qlog_level(level), pkt->pkt_len);

        if (quiccrypto_open_limit_reached(keys)) {
            metrics_quic(METRICS_QUIC_AEAD_LIMIT);
            quicconn_close(conn, QUIC_AEAD_LIMIT_REACHED, 0, now_us);
            return 0;
        }
        return 1;
    }

    /* §4.9.1: the first Handshake packet that opens is what tells a server the
     * client has the Handshake keys, and therefore that the Initial space is
     * finished. Here rather than at handshake completion: the client stops
     * reading Initial packets at this same moment, so everything we send at
     * that level from now on is noise it will drop. */
    if (level == QUIC_ENC_HANDSHAKE) {
        __discard_space(conn, QUIC_ENC_INITIAL);

        /* §8.1: a Handshake packet that opens also validates the address, and
         * waiting for the handshake to complete instead is a deadlock waiting
         * to happen. The proof is already complete here -- Handshake keys can
         * only be derived from the ServerHello we sent to this address, so the
         * peer demonstrably received it.
         *
         * What the delay cost: with the client's Finished lost, the server
         * still owes a flight but has spent its three-times budget, so the PTO
         * fires with nothing it may send -- `in_flight` frozen across nine
         * probes at `amp=110`. §6.2.2.1 says it is then the client's job to
         * send more, and a client that believes the handshake finished has no
         * reason to (docs/http3/08 §3n). */
        conn->address_validated = 1;
    }

    /* §4.9.3: once a 1-RTT packet opens, the 0-RTT read keys have no further
     * use -- the client has moved on and everything it sends from now is at the
     * application level. Dropping them here bounds how long a replayed 0-RTT
     * flight can be decrypted at all, and it is the moment the RFC names.
     *
     * Only the keys: the packet-number space and its acknowledgement state are
     * shared with 1-RTT (see __ack_space) and must survive. */
    if (level == QUIC_ENC_APP && conn->rx[QUIC_ENC_EARLY].valid)
        quickeys_free(&conn->rx[QUIC_ENC_EARLY]);

    if (level == QUIC_ENC_EARLY) {
        conn->early_data_packets++;
        metrics_quic(METRICS_QUIC_EARLY_DATA_PACKETS);
        metrics_quic_add(METRICS_QUIC_EARLY_DATA_BYTES, pkt->pkt_len);
    }

    /* A replayed packet is bit-identical to the original, so the AEAD cannot
     * tell them apart -- this check is the only thing that can. */
    if (quicack_is_duplicate(&conn->ack[space], pn)) return 1;

    /* The packet opened with the next generation's keys, which is the only
     * proof that the peer really updated: the Key Phase bit itself is under
     * header protection but not authenticated, so nothing above this line may
     * change state. */
    if (updating && !__key_update_commit(conn, pn, now_us)) {
        quicconn_close(conn, QUIC_INTERNAL_ERROR, 0, now_us);
        return 0;
    }

    /* §12.4: a packet with no frames at all is a protocol violation. */
    if (plain_len == 0) {
        quicconn_close(conn, QUIC_PROTOCOL_VIOLATION, 0, now_us);
        return 0;
    }

    int ack_eliciting = 0;
    /* §9.1: a packet carrying nothing but probing frames says the peer is
     * testing a path, not using it, and must not move the connection onto that
     * path by itself. */
    int non_probing = 0;
    size_t off = 0;
    quicframe_t frame;
    quicframe_status_e st;

    while ((st = quicframe_next(plain, plain_len, &off, &frame)) == QUICFRAME_OK) {
        if (quicframe_is_ack_eliciting(frame.type)) ack_eliciting = 1;

        switch (frame.type) {
        case QUIC_FRAME_PADDING:
        case QUIC_FRAME_PATH_CHALLENGE:
        case QUIC_FRAME_PATH_RESPONSE:
        case QUIC_FRAME_NEW_CONNECTION_ID:
            break;
        default:
            non_probing = 1;
        }

        if (!__handle_frame(conn, level, &frame, now_us)) return 0;
    }

    if (st != QUICFRAME_DONE && st != QUICFRAME_OK) {
        quicconn_close(conn, QUIC_FRAME_ENCODING_ERROR, 0, now_us);
        return 0;
    }

    /* §9.3: the address only moves on a non-probing packet that is *newer*
     * than anything seen before. Without the packet-number test a replayed old
     * packet, injected from an address of the attacker's choosing, would drag
     * the connection back and forth. Read before quicack_on_received, which is
     * what makes this packet the largest. */
    const int newest = !conn->ack[space].any_received || pn > conn->ack[space].largest;

    quicack_on_received_ecn(&conn->ack[space], space, pn, ack_eliciting,
                            conn->recv_ecn, now_us,
                            conn->local_params.max_ack_delay * 1000);

    if (level == QUIC_ENC_APP && non_probing && newest &&
        conn->recv_path != NULL && !__path_same(conn->recv_path, &conn->path))
        __path_probe_start(conn, conn->recv_path, now_us);

    /* The other half of `send`: what actually arrived. Without it a connection
     * that goes quiet cannot be told apart from one whose peer went quiet -- and
     * those want opposite fixes. `elic` is the part that obliges an answer, so
     * an eliciting packet here with no ACK going back out is a bug on this side
     * (docs/http3/08 §3v). */
    log_debug("quic: recv cid=%02x%02x%02x%02x level=%d pn=%llu elic=%d\n",
              conn->odcid.data[0], conn->odcid.data[1],
              conn->odcid.data[2], conn->odcid.data[3],
              (int)level, (unsigned long long)pn, ack_eliciting);

    if (ack_eliciting) atomic_store_explicit(&conn->want_write, 1, memory_order_release);

    QLOG(conn->qlog, "transport", "packet_received",
         "\"header\":{\"packet_type\":\"%s\",\"packet_number\":%llu},"
         "\"raw\":{\"length\":%zu},\"ack_eliciting\":%s,\"ecn\":\"%s\"",
         __qlog_level(level), (unsigned long long)pn, pkt->pkt_len,
         ack_eliciting ? "true" : "false",
         (conn->recv_ecn & 0x03) == 0x03 ? "CE"
             : (conn->recv_ecn & 0x03) == 0x02 ? "ECT(0)"
             : (conn->recv_ecn & 0x03) == 0x01 ? "ECT(1)" : "Not-ECT");

    QUICBEACON("cid=%02x%02x RECV  level=%d pn=%llu elic=%d pending=%u deadline_in=%lld",
               conn->odcid.data[0], conn->odcid.data[1],
               (int)level, (unsigned long long)pn, ack_eliciting,
               conn->ack[space].eliciting_pending,
               conn->ack[space].ack_deadline_us == 0
                   ? -1LL
                   : (long long)conn->ack[space].ack_deadline_us - (long long)now_us);

    return 1;
}

int quicconn_recv(quicconn_t* conn, const uint8_t* datagram, size_t len,
                  const quicpath_t* path, uint64_t now_us) {
    if (conn == NULL || datagram == NULL) return 0;

    if (conn->state == QUICCONN_DRAINING || conn->state == QUICCONN_DEAD) return 1;

    if (conn->state == QUICCONN_CLOSING) {
        /* §10.2.1: answer with the close packet again, since the peer evidently
         * did not receive it -- but not once per packet, or a peer that keeps
         * sending turns this into an amplifier. */
        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        return 1;
    }

    __touch(conn, now_us);

    /* Every byte received raises what may be sent back before the address is
     * validated (§8.1). */
    if (!conn->address_validated)
        conn->amplification_budget += (uint64_t)len * conn->amplification_factor;

    /* Where this datagram came from, for the frame handlers and the migration
     * check below. Cleared on the way out: a stale pointer here would be read
     * on a later call with nothing behind it. */
    conn->recv_path = path;

    /* A datagram may carry several packets (§12.2). The buffer is copied
     * because header protection and decryption work in place. */
    uint8_t copy[2048];
    if (len > sizeof copy) {
        conn->recv_path = NULL;
        return 1;
    }
    memcpy(copy, datagram, len);

    size_t off = 0;
    quicpkt_t pkt;
    quicpkt_status_e st;

    /* Packets whose keys do not exist yet, kept for the retry below (§5.7).
     *
     * This is not the exotic reordering case the drop in __process_packet was
     * written for. The keys for the application space are installed by
     * quictls_advance, which runs *after* this loop -- so a 1-RTT packet
     * coalesced behind the client's Finished, in the same datagram, is
     * guaranteed to arrive before its keys exist. That is exactly what a client
     * sends when it finishes the handshake and has a request ready, and
     * dropping it costs a full retransmission of the request. On a path losing
     * three packets at a time that was the difference between a request served
     * and a connection that waits out its idle timeout with the client
     * repeating itself (docs/http3/08 §3o).
     *
     * Four is the whole of the need: a datagram holds one packet per level, and
     * nothing is held past this call, so there is no buffer for a peer to
     * grow. */
    struct { uint8_t* buf; size_t len; quicpkt_t pkt; } deferred[4];
    size_t deferred_n = 0;

    while (quicpkt_next(copy, len, &off, QUIC_LOCAL_CID_LEN, &pkt, &st)) {
        uint8_t* start = copy + off - pkt.pkt_len;
        const quic_enc_level_e lvl = quicpkt_level(pkt.type);

        if (lvl < QUIC_ENC_COUNT && !conn->rx[lvl].valid &&
            deferred_n < sizeof deferred / sizeof deferred[0]) {
            deferred[deferred_n].buf = start;
            deferred[deferred_n].len = pkt.pkt_len;
            deferred[deferred_n].pkt = pkt;
            deferred_n++;
            continue;
        }

        if (!__process_packet(conn, start, pkt.pkt_len, &pkt, now_us)) {
            conn->recv_path = NULL;
            return 0;
        }

        if (conn->state == QUICCONN_DRAINING) break;
    }

    conn->recv_path = NULL;

    /* Drive the handshake with whatever CRYPTO arrived. */
    if (conn->state == QUICCONN_HANDSHAKE) {
        if (!quictls_advance(&conn->tls)) {
            /* The one counter that would have shortened phase 6 by a day: a
             * peer that rejects our certificate and one that never reached us
             * are the same silence otherwise (docs/http3/05 §10). */
            metrics_quic(METRICS_QUIC_HANDSHAKE_FAILED_TLS);

            if (conn->state != QUICCONN_CLOSING)
                quicconn_close(conn,
                               conn->tls.transport_error != 0
                                   ? conn->tls.transport_error
                                   : QUIC_CRYPTO_ERROR(0x28),
                               0, now_us);
            return 0;
        }

        /* RFC 9001 §8.2: a ClientHello without quic_transport_parameters is a
         * connection error equivalent to a fatal missing_extension alert.
         * OpenSSL does not treat the extension as required -- it simply never
         * calls the callback -- so without this check the handshake completed
         * against a peer that had agreed to nothing, and every limit stayed at
         * zero. The failure then surfaced three layers up as "h3: could not
         * open the service streams", which names the symptom and not one thing
         * about the cause.
         *
         * Tested here rather than at completion, and the difference is not
         * cosmetic: handshake keys exist only once TLS has read the
         * ClientHello, so their absence is already decided, and refusing now
         * saves signing a certificate for a connection we are about to refuse.
         * The peer also learns why while it is still listening at this level. */
        if (conn->tx[QUIC_ENC_HANDSHAKE].valid && !conn->peer_params_seen) {
            log_error("quic: peer sent no transport parameters\n");
            quicconn_close(conn, QUIC_CRYPTO_ERROR(109 /* missing_extension */),
                           0, now_us);
            return 0;
        }

        /* What the stack made of it. `complete=0` on every pass while `crypto`
         * lines keep arriving is a handshake stuck inside TLS rather than one
         * waiting for bytes -- the distinction §3v could not make. */
        log_debug("quic: tls advance cid=%02x%02x%02x%02x complete=%d "
                  "keys_hs=%d keys_app=%d params_seen=%d\n",
                  conn->odcid.data[0], conn->odcid.data[1],
                  conn->odcid.data[2], conn->odcid.data[3],
                  conn->tls.handshake_complete,
                  conn->tx[QUIC_ENC_HANDSHAKE].valid,
                  conn->tx[QUIC_ENC_APP].valid, conn->peer_params_seen);

        if (conn->tls.handshake_complete) {
            log_info("quic: handshake complete cid=%02x%02x%02x%02x; "
                     "peer streams_uni=%llu streams_bidi=%llu "
                     "max_data=%llu max_stream_data_uni=%llu\n",
                     conn->odcid.data[0], conn->odcid.data[1],
                     conn->odcid.data[2], conn->odcid.data[3],
                     (unsigned long long)conn->peer_params.initial_max_streams_uni,
                     (unsigned long long)conn->peer_params.initial_max_streams_bidi,
                     (unsigned long long)conn->peer_params.initial_max_data,
                     (unsigned long long)conn->peer_params.initial_max_stream_data_uni);

            metrics_quic(METRICS_QUIC_HANDSHAKE_COMPLETED);

            QLOG(conn->qlog, "connectivity", "connection_state_updated",
                 "\"new\":\"handshake_confirmed\",\"elapsed_us\":%llu",
                 (unsigned long long)(now_us > conn->accepted_us
                                      ? now_us - conn->accepted_us : 0));

            /* What the peer allowed us, at the moment it becomes binding. Half
             * of every "the transfer stops after N bytes" question is answered
             * by these four numbers, and they are otherwise nowhere in the
             * trace: the flow-control limits that follow are increments on
             * them. */
            QLOG(conn->qlog, "transport", "parameters_set",
                 "\"owner\":\"remote\",\"initial_max_data\":%llu,"
                 "\"initial_max_stream_data_bidi_local\":%llu,"
                 "\"initial_max_streams_bidi\":%llu,"
                 "\"initial_max_streams_uni\":%llu,"
                 "\"max_idle_timeout\":%llu,\"max_udp_payload_size\":%llu,"
                 "\"active_connection_id_limit\":%llu",
                 (unsigned long long)conn->peer_params.initial_max_data,
                 (unsigned long long)conn->peer_params.initial_max_stream_data_bidi_local,
                 (unsigned long long)conn->peer_params.initial_max_streams_bidi,
                 (unsigned long long)conn->peer_params.initial_max_streams_uni,
                 (unsigned long long)conn->peer_params.max_idle_timeout,
                 (unsigned long long)conn->peer_params.max_udp_payload_size,
                 (unsigned long long)conn->peer_params.active_connection_id_limit);

            /* Whether the client's early data was taken. Read here rather than
             * when the 0-RTT keys appeared: TLS only settles it after the
             * ClientHello is processed, and a handshake that yielded 0-RTT read
             * keys can still end with the data refused. */
            if (conn->tls.early_data_enabled) {
                if (conn->early_data_packets > 0 || quictls_early_data_accepted(&conn->tls))
                    metrics_quic(METRICS_QUIC_EARLY_DATA_OFFERED);

                if (quictls_early_data_accepted(&conn->tls)) {
                    metrics_quic(METRICS_QUIC_EARLY_DATA_ACCEPTED);

                    log_info("quic: 0-RTT accepted cid=%02x%02x%02x%02x, "
                             "%llu early packets\n",
                             conn->odcid.data[0], conn->odcid.data[1],
                             conn->odcid.data[2], conn->odcid.data[3],
                             (unsigned long long)conn->early_data_packets);
                }
            }

            conn->state = QUICCONN_ACTIVE;
            if (conn->peer_params.max_udp_payload_size < conn->pmtud.ceiling) {
                conn->pmtud.ceiling = (size_t)conn->peer_params.max_udp_payload_size;
                if (conn->pmtud.current > conn->pmtud.ceiling) {
                    conn->pmtud.current = conn->pmtud.ceiling;
                    conn->pmtud.base = conn->pmtud.ceiling;
                    conn->cc.max_datagram_size = conn->pmtud.current;
                }
            }
            conn->pmtud.next_probe_us = now_us +
                10 * quicloss_pto_us(&conn->loss, QUIC_ENC_APP);

            /* §4.9.2: for a server the handshake is confirmed by its own
             * completion -- the client's Finished cannot exist unless the
             * client processed our whole flight. The price, which the RFC
             * accepts, is that a client Handshake packet retransmitted after
             * this point can no longer be acknowledged. */
            __discard_space(conn, QUIC_ENC_HANDSHAKE);

            /* Address proven by the handshake itself, so the peer has earned a
             * token for next time (§8.1.3). */
            conn->new_token_len =
                quicendpoint_new_token((const struct sockaddr*)&conn->path.remote,
                                       conn->path.remote_len,
                                       conn->new_token, sizeof conn->new_token);

            /* Now that the peer's active_connection_id_limit is known, give it
             * the spares it said it would hold (§5.1.1). Not earlier: before
             * the transport parameters arrive the limit is a guess, and issuing
             * past it is a CONNECTION_ID_LIMIT_ERROR against us. */
            __cids_replenish(conn);

            /* Completing the handshake proves the peer received our packets,
             * which is exactly what the amplification limit was waiting for. */
            conn->address_validated = 1;
            conn->loss.handshake_confirmed = 1;
            atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        }
    }

    /* The keys the handshake just installed are what the packets held back
     * above were waiting for. Retried once, here and nowhere else: if the level
     * is still without keys the packet really did overtake its handshake, and
     * then dropping it is right -- the peer will send it again. */
    for (size_t i = 0; i < deferred_n; i++) {
        const quic_enc_level_e lvl = quicpkt_level(deferred[i].pkt.type);
        if (lvl >= QUIC_ENC_COUNT || !conn->rx[lvl].valid) continue;

        log_debug("quic: deferred packet retried at level %d\n", (int)lvl);

        conn->recv_path = path;
        const int ok = __process_packet(conn, deferred[i].buf, deferred[i].len,
                                        &deferred[i].pkt, now_us);
        conn->recv_path = NULL;

        if (!ok) return 0;
        if (conn->state == QUICCONN_DRAINING) break;
    }

    return 1;
}

/* ---- Send path ---- */

/* Build one packet at `level` into `dst`, returning its length or 0. */
static size_t __build_packet(quicconn_t* conn, quic_enc_level_e level,
                             uint8_t* dst, size_t cap, uint64_t now_us,
                             int cc_blocked, int* out_ack_eliciting) {
    quickeys_t* keys = &conn->tx[level];
    if (!keys->valid) return 0;

    /* What a full congestion window forbids is putting more *data* in flight
     * (§7). Acknowledgements are not congestion controlled at all, the frames
     * that hand credit back to the peer are the opposite of congestion, and
     * §7.5 lets a PTO probe exceed the window outright -- a probe exists to
     * make a silent peer speak, and refusing to send it for want of window is
     * how a stalled connection stays stalled. So the window gates the two
     * volume producers below, CRYPTO and STREAM, and nothing else. */
    const int cc_room = !cc_blocked ||
                        (conn->pto_probes > 0 && level == conn->pto_level);

    /* Room for the tag, the header held back below, and a payload worth the
     * packet. The check is what keeps the subtraction that follows from
     * underflowing: a `cap` of, say, 50 leaves 34 bytes after the tag, and
     * taking 64 off that hands the frame writers below a capacity of ~2^64 over
     * a 1200-byte stack buffer. Such a `cap` is not hypothetical -- the tail of
     * the anti-amplification budget is exactly that shape, and it smashed the
     * stack a few hundred handshakes in. */
    /* What the header will actually take, rather than what would always be
     * enough. For a 1-RTT packet -- every packet of a response -- it is one
     * flags byte, the peer's connection id and the packet number, all three
     * known before a single frame is written; the generous 64-byte reserve was
     * 51 bytes of every datagram left empty, so no packet ever reached the
     * PLPMTU. Long headers keep the reserve: their length field is sized from
     * the payload that has not been written yet, they carry two connection ids
     * and a token, and they exist only during a handshake -- the arithmetic is
     * worth more there than the bytes.
     *
     * The point is not only the 4 % of capacity. Datagrams that stop short of
     * the path MTU stop at *different* lengths, and a GSO run ends at the first
     * size change (udpsocket.c), so short packets also shorten every send
     * message the kernel receives. */
    size_t header_reserve = QUICCONN_HEADER_RESERVE;

    if (level == QUIC_ENC_APP && conn->peer_cid_count > 0)
        header_reserve = 1 + conn->peer_cids[0].len +
                         quicpkt_pn_length(conn->loss.space[level].next_pn,
                                           conn->loss.space[level].largest_acked);

    if (cap < QUIC_AEAD_TAG_LEN + header_reserve + QUICCONN_MIN_PAYLOAD)
        return 0;

    /* Where the frames are assembled.
     *
     * For a 1-RTT packet -- every packet of a response -- that is the datagram
     * itself, right behind the header, and the AEAD then encrypts in place. The
     * alternative, which this used to do, is to build in a stack buffer and let
     * the AEAD copy it into the datagram: one full copy of every byte the
     * server sends, and it was visible as such (memmove was the largest single
     * symbol in the profile at 11 %).
     *
     * It is possible only because a short header's length is knowable before
     * any frame is written -- one flags byte, the peer's connection id, the
     * packet number -- so the header can go down first and the payload can
     * start at a known offset. A long header cannot: its Length field is sized
     * from the payload that does not exist yet, so Initial and Handshake keep
     * the buffer. They are a handful of packets per connection. */
    uint8_t staging[QUICCONN_MAX_PACKET];
    uint8_t* payload = staging;
    size_t p = 0;

    /* Written now for a short header, at the end for a long one. */
    size_t header_len = 0;
    size_t pn_offset = 0;
    const uint64_t pn = conn->loss.space[level].next_pn;
    const size_t pn_len = quicpkt_pn_length(pn, conn->loss.space[level].largest_acked);
    quiccid_t* dcid = conn->peer_cid_count > 0 ? &conn->peer_cids[0] : NULL;

    if (dcid == NULL) return 0;

    quicpkt_hdr_out_t hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = level == QUIC_ENC_INITIAL ? QUIC_PKT_INITIAL
             : level == QUIC_ENC_HANDSHAKE ? QUIC_PKT_HANDSHAKE
                                           : QUIC_PKT_SHORT;
    hdr.version = QUIC_VERSION_1;
    hdr.dcid = dcid;
    hdr.scid = &conn->local_cids[0].cid;
    hdr.pn = pn;
    hdr.pn_len = pn_len;
    /* Ignored for long headers, which have no such bit. */
    hdr.key_phase = conn->key_phase;

    if (hdr.type == QUIC_PKT_SHORT) {
        header_len = quicpkt_write_header(dst, cap, &hdr, &pn_offset);
        if (header_len == 0) return 0;

        payload = dst + header_len;
    }
    int ack_eliciting = 0;
    quicframe_ref_t* refs = NULL;

    /* Cost of assembling this one packet, in nodes of conn->streams touched by
     * each of the two walks below and in streams that ended up writing data
     * (docs/http3/09-options.md §2.7). On the stack, published once at the end:
     * the walk is the hot path, and an atomic per node would measure itself. */
    unsigned long long visits_flow = 0;
    unsigned long long visits_data = 0;
    unsigned long long stream_frames = 0;

    /* What the frames may occupy: the datagram less the header that is already
     * written (or reserved) and the tag the AEAD will append. The staging
     * buffer bounds it too, for the long-header path that still uses one. */
    const size_t room_after_header =
        cap - QUIC_AEAD_TAG_LEN - (header_len > 0 ? header_len : header_reserve);
    const size_t payload_cap = room_after_header > sizeof staging
                               ? sizeof staging : room_after_header;

    /* An ACK first: it is what unblocks the peer, and it is cheap. */
    size_t ack_len = 0;
    const int ack_due = quicack_should_send(&conn->ack[level], now_us);

    QUICBEACON("BUILD level=%d ack_due=%d pending=%u deadline_in=%lld",
               (int)level, ack_due, conn->ack[level].eliciting_pending,
               conn->ack[level].ack_deadline_us == 0
                   ? -1LL
                   : (long long)conn->ack[level].ack_deadline_us - (long long)now_us);

    /* Written whenever anything is owed, not only when it has come due: a
     * delayed ACK is meant to save a *packet*, not to be withheld from one that
     * is leaving regardless (§13.2.1). Held back, it cost a full max_ack_delay
     * on every request -- the response left in 0.13 ms and the acknowledgement
     * of the request that asked for it followed 25 ms later, so the peer could
     * not retire the stream and h2load measured 25 ms per request against
     * 0.5 ms over HTTP/2 (docs/http3/08 §7j).
     *
     * If nothing else joins it below, the packet is dropped instead of sent --
     * see the `p == ack_len` test -- so an ACK that is not due still does not
     * put a packet on the wire by itself. */
    if (ack_due || quicack_pending(&conn->ack[level])) {
        const size_t n = quicack_write(&conn->ack[level], payload + p, payload_cap - p,
                                       now_us,
                                       conn->peer_params.ack_delay_exponent);
        if (n > 0) {
            p += n;
            ack_len = n;
        }
    }

    /* A PTO probe, if one is owed at this level. PING is the whole of it: the
     * frame exists to be acknowledged and carries nothing else. Real data, if
     * there is any, follows in the same packet -- so a probe costs an extra
     * frame, not an extra round trip. */
    if (conn->pto_probes > 0 && level == conn->pto_level && p + 8 < payload_cap) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_PING;

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
        if (n > 0) {
            p += n;
            ack_eliciting = 1;
            conn->pto_probes--;
            metrics_quic(METRICS_QUIC_PTO_PROBE_SENT);
        }
    }

    /* A keep-alive probe (§10.1.2). Its own branch rather than a second reason
     * to set `pto_probes`: this is not loss recovery, and counting it there
     * would move the PTO backoff and report a healthy connection as one that
     * keeps timing out. Like the probe above, it rides along with whatever else
     * the packet carries -- if anything else is being sent, the PING is a spare
     * frame, and if not, it is the whole packet. */
    if (conn->keepalive_pending && level == QUIC_ENC_APP && p + 8 < payload_cap) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_PING;

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
        if (n > 0) {
            p += n;
            ack_eliciting = 1;
            conn->keepalive_pending = 0;
            metrics_quic(METRICS_QUIC_KEEPALIVE_SENT);
        }
    }

    /* A pending PATH_RESPONSE next, ahead of everything that may be deferred:
     * §8.2.2 forbids delaying the packet that carries it for any reason but
     * congestion control. Only in the application space -- the peer cannot
     * challenge a path before it has 1-RTT keys, and a server never sends
     * 0-RTT.
     *
     * Not registered for loss recovery, on purpose: §13.3 says a PATH_RESPONSE
     * is not retransmitted, because a peer that did not get one sends another
     * challenge, and a stale echo would validate a path that may no longer
     * exist. */
    if (level == QUIC_ENC_APP && conn->path_response_pending && p + 16 < payload_cap) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_PATH_RESPONSE;
        memcpy(f.u.path.data, conn->path_response_data, sizeof f.u.path.data);

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
        if (n > 0) {
            p += n;
            ack_eliciting = 1;
            conn->path_response_pending = 0;
        }
    }

    if (level == QUIC_ENC_APP && conn->new_token_len > 0 && !conn->new_token_sent &&
        p + conn->new_token_len + 16 < payload_cap) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_NEW_TOKEN;
        f.u.new_token.data = conn->new_token;
        f.u.new_token.len = conn->new_token_len;

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
        if (n > 0) {
            p += n;
            ack_eliciting = 1;
            conn->new_token_sent = 1;

            quicframe_ref_t* ref = quicframe_ref_new(QUIC_FRAME_NEW_TOKEN);
            if (ref != NULL) {
                ref->next = refs;
                refs = ref;
            }
        }
    }

    /* §4.1: hand back the receive window the application has drained. Without
     * it the peer's connection-level allowance is spent once and never
     * replenished -- a connection dies with FLOW_CONTROL_ERROR after
     * initial_max_data bytes of requests, whatever it was doing. */
    if (level == QUIC_ENC_APP && p + 16 < payload_cap) {
        uint64_t limit = 0;

        if (quicflow_should_update(&conn->recv_flow, &limit)) {
            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_MAX_DATA;
            f.u.max_data.max = limit;

            const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
            if (n > 0) {
                p += n;
                ack_eliciting = 1;
                quicflow_update_sent(&conn->recv_flow, limit);
            }
        }
    }

    /* The same for each stream that has been drained (§4.1) -- but only when a
     * receive has said one of them might owe it, because this walk is the one
     * that never stops early (quicconn.h, stream_flow_pending). Taken down
     * before the walk, so a receive that lands during it is not swallowed. */
    if (level == QUIC_ENC_APP &&
        atomic_exchange_explicit(&conn->stream_flow_pending, 0,
                                 memory_order_acquire)) {
        int owed = 0;
        quicstream_t* s = conn->streams;

        for (; s != NULL && p + 24 < payload_cap; s = s->next) {
            visits_flow++;

            uint64_t limit = 0;
            if (!quicflow_should_update(&s->recv_flow, &limit)) continue;

            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_MAX_STREAM_DATA;
            f.u.max_stream_data.id = s->id;
            f.u.max_stream_data.max = limit;

            const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
            if (n > 0) {
                p += n;
                ack_eliciting = 1;
                quicflow_update_sent(&s->recv_flow, limit);
            }
            /* No room left in this packet for a frame that is owed. */
            else owed = 1;
        }

        /* `s != NULL` means the packet filled before the list ended, so the tail
         * was never asked. Either way the hint goes back up: dropping it here is
         * the one failure this may not have -- a stream whose window is never
         * extended stalls the peer for good, and nothing would raise the hint
         * again, because raising it takes the very data the peer cannot send. */
        if (s != NULL || owed)
            atomic_store_explicit(&conn->stream_flow_pending, 1, memory_order_release);
    }

    /* §4.6: hand back the credit of streams that have finished. Sent when it
     * has actually moved -- a frame repeating the current limit is the kind of
     * free-to-send, nothing-to-do traffic the control budget next door exists
     * to stop. */
    if (level == QUIC_ENC_APP && p + 16 < payload_cap) {
        const uint64_t allow = conn->local_params.initial_max_streams_bidi +
                               conn->peer_bidi_closed;

        if (allow > conn->max_streams_bidi_sent) {
            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_MAX_STREAMS_BIDI;
            f.u.max_streams.max = allow;

            const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
            if (n > 0) {
                p += n;
                ack_eliciting = 1;
                conn->max_streams_bidi_sent = allow;
            }
        }
    }

    /* Connection ids the peer has not been told about yet (§5.1.1). One frame
     * per id, each about 40 bytes, and at most a handful ever exist. */
    if (level == QUIC_ENC_APP) {
        for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS && p + 64 < payload_cap; i++) {
            quiccid_entry_t* e = &conn->local_cids[i];
            if (!e->active || e->announced) continue;

            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_NEW_CONNECTION_ID;
            f.u.new_cid.seq = e->seq;
            /* Never asks the peer to retire anything: our ids stay valid until
             * the connection ends, and a non-zero value here would force the
             * peer to drop ids it may be about to migrate onto. */
            f.u.new_cid.retire_prior_to = 0;
            f.u.new_cid.cid = e->cid;
            memcpy(f.u.new_cid.token, e->reset_token, sizeof f.u.new_cid.token);

            const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
            if (n == 0) continue;

            p += n;
            ack_eliciting = 1;
            e->announced = 1;
            metrics_quic(METRICS_QUIC_CIDS_ANNOUNCED);

            /* §13.3 has this frame retransmitted when lost. The reference
                carries the sequence number in `offset`, which is what
             * __on_ack_frame looks the entry up by. */
            quicframe_ref_t* ref = quicframe_ref_new(QUIC_FRAME_NEW_CONNECTION_ID);
            if (ref != NULL) {
                ref->offset = e->seq;
                ref->next = refs;
                refs = ref;
            }
        }
    }

    /* Handshake data. */
    if (cc_room && quicsendbuf_pending(&conn->crypto_out[level]) && p + 16 < payload_cap) {
        uint64_t offset = 0;
        const uint8_t* data = NULL;
        size_t dlen = 0;
        int fin = 0;

        if (quicsendbuf_next(&conn->crypto_out[level], payload_cap - p - 16,
                             &offset, &data, &dlen, &fin) && dlen > 0) {
            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_CRYPTO;
            f.u.crypto.offset = offset;
            f.u.crypto.len = dlen;
            f.u.crypto.data = data;

            const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
            if (n > 0) {
                p += n;
                ack_eliciting = 1;
                quicsendbuf_mark_sent(&conn->crypto_out[level], offset, dlen, 0);

                quicframe_ref_t* ref = quicframe_ref_new(QUIC_FRAME_CRYPTO);
                if (ref != NULL) {
                    ref->offset = offset;
                    ref->len = dlen;
                    ref->next = refs;
                    refs = ref;
                }
            }
        }
    }

    /* Once the handshake is done the peer is told, so it can drop its own
     * handshake keys and stop retransmitting (§7.5). */
    if (level == QUIC_ENC_APP && conn->state == QUICCONN_ACTIVE &&
        !conn->handshake_done_sent && p + 1 < payload_cap) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_HANDSHAKE_DONE;

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
        if (n > 0) {
            p += n;
            ack_eliciting = 1;
            conn->handshake_done_sent = 1;

            /* Registered for loss recovery like NEW_TOKEN above, and for a
             * sharper reason: §13.3 requires this frame to be retransmitted
             * until acknowledged, and the peer has no other way to learn the
             * handshake is confirmed. */
            quicframe_ref_t* ref = quicframe_ref_new(QUIC_FRAME_HANDSHAKE_DONE);
            if (ref != NULL) {
                ref->next = refs;
                refs = ref;
            }
        }
    }

    /* Stream data, in the order the streams were opened: the walk starts at the
     * head and the first stream that can send takes as much of the packet as it
     * will hold, so responses are finished one at a time, oldest request first.
     * RFC 9218 §7 asks for exactly that of equal-urgency, non-incremental
     * responses -- a resource that is only useful complete is worth finishing
     * rather than interleaving. A stream that is blocked falls through to the
     * next one, so the connection is never idle while anyone has data.
     *
     * The comment here used to claim round-robin. It never was: the list was
     * built newest-first, which made this reverse order of arrival, and the
     * first file a client asked for was the last one it got. See
     * __stream_append. */
    if (level == QUIC_ENC_APP) {
        /* Which streams may put data in *this* packet. Decided once per packet
         * rather than per stream: the answer is a property of the whole set,
         * and asking it per stream would make it O(n²). */
        quicsched_t sched;
        __sched_select(conn, &sched);

        for (quicstream_t* s = conn->streams; s != NULL && p + 32 < payload_cap;
             s = s->next) {
            visits_data++;

            /* STOP_SENDING is about the receive half, so it is not an
             * alternative to the RESET_STREAM below -- a stream can owe both,
             * and each is cleared on its own. */
            if (s->send_stop_sending_pending) {
                quicframe_t f;
                memset(&f, 0, sizeof f);
                f.type = QUIC_FRAME_STOP_SENDING;
                f.u.stop_sending.id = s->id;
                f.u.stop_sending.error = s->send_stop_sending_code;

                const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
                if (n > 0) {
                    p += n;
                    ack_eliciting = 1;
                    s->send_stop_sending_pending = 0;
                }
            }

            if (s->send_reset_pending) {
                quicframe_t f;
                memset(&f, 0, sizeof f);
                f.type = QUIC_FRAME_RESET_STREAM;
                f.u.reset_stream.id = s->id;
                f.u.reset_stream.error = s->send_reset_code;
                /* §4.5 defines the final size as "one higher than the offset of
                 * the byte with the largest offset **sent** on the stream" --
                 * which is sent_off, not write_off.
                 *
                 * The difference is the abandoned tail, and the abandoned tail
                 * is the entire point of a reset: a 128 KB response cancelled
                 * after 20 KB used to declare 128 KB of the peer's
                 * connection-level window consumed. The peer must account for
                 * the final size (§4.5), so its view of our consumption ran
                 * ahead of ours by everything we never sent -- and it is the
                 * peer that enforces the limit, so far enough ahead is a
                 * FLOW_CONTROL_ERROR for data we were entitled to send.
                 * Found by the deterministic stand (08-testing.md §2f). */
                f.u.reset_stream.final_size = s->send.sent_off;

                const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
                if (n > 0) {
                    p += n;
                    ack_eliciting = 1;
                    s->send_reset_pending = 0;
                }
                continue;
            }

            /* Stream data is what the congestion window is for; the terminal
             * frames above are not, which is why the gate sits here and not at
             * the top of the loop. */
            if (!cc_room || !quicstream_wants_send(s)) continue;

            /* Not this stream's turn. The terminal frames above are deliberately
             * above this line: RESET_STREAM and STOP_SENDING are how a stream
             * *ends*, they cost nothing the congestion window cares about, and
             * making them wait on urgency would let one prioritised transfer
             * hold up the cleanup of every other stream. */
            if (sched.active && !__sched_is_service(s)) {
                if (s->sched_urgency != sched.urgency) continue;

                if (sched.incremental) {
                    if (s->id != sched.stream_id) continue;

                    /* The turn is spent by being offered, not by being used. A
                     * stream that is chosen and then finds its window shut
                     * would otherwise hold the cursor for good, and every other
                     * incremental stream would wait behind a stream that is not
                     * sending. */
                    conn->sched_rr_id = s->id;
                }
                else if (s->sched_incremental) continue;
            }

            uint64_t offset = 0;
            const uint8_t* data = NULL;
            size_t dlen = 0;
            int fin = 0;

            /* Both windows apply, and so does the space left in the packet --
             * unless the next chunk is a retransmission. Resent data was
             * charged to the window the first time it went out (§4.5), so it is
             * sent regardless of what the window says now; quicsendbuf_next
             * serves the lowest lost range whole before it looks at new data,
             * so the chunk is one or the other and never a mix.
             *
             * This is not a nicety. Charging it again is a deadlock: the peer
             * needs the missing bytes before it can deliver anything behind
             * them, and it raises MAX_DATA only for what it has delivered -- so
             * the window that is stopping the retransmission can only be opened
             * by that same retransmission (docs/http3/08 §3i). */
            const int resending = quicsendbuf_has_lost(&s->send);

            uint64_t allowed = quicflow_available(&s->send_flow);
            const uint64_t conn_allowed = quicflow_available(&conn->send_flow);
            if (conn_allowed < allowed) allowed = conn_allowed;

            size_t room = payload_cap - p - 24;
            if (!resending && allowed < room) room = (size_t)allowed;

            /* A FIN with nothing in front of it left to send is the one thing a
             * closed window does not stop (§4.1: an empty frame carrying only
             * the FIN consumes no credit), so the loop falls through to it.
             *
             * The test is `sent_off == write_off`, not merely "a FIN is
             * queued": a response written in one go -- which is every response
             * the h3 layer produces -- has its FIN queued from the first byte,
             * and treating that as "the FIN is all that is left" made the whole
             * branch below unreachable for exactly the case it exists for. The
             * sender then hit the window and went completely silent: no
             * STREAM_DATA_BLOCKED, no packet, nothing in flight to arm a timer.
             * Its peer, which had no reason to raise a limit it did not know
             * was in the way, waited out the idle timeout. Found in the
             * deterministic stand (docs/http3/08-testing.md §2h), which is the
             * first thing here that could advertise a window small enough to
             * reach. */
            const int fin_alone = s->send.fin && !s->send.fin_sent &&
                                  s->send.sent_off == s->send.write_off;

            if (room == 0 && !fin_alone) {
                /* Only a closed window is counted, not a full packet: the
                 * second is the loop doing its job and would bury the first,
                 * which is a stall the peer has to end.
                 *
                 * And it has to be told, or it never will (§4.1). A sender that
                 * is blocked and silent looks to the peer exactly like one with
                 * nothing to say: the peer sees no reason to raise a limit it
                 * does not know is in the way, we stop building packets, our
                 * want_write goes down, and nothing is left in flight to arm a
                 * timer. That is a connection that is up, idle and finished,
                 * and it is what a lossy 500 KB transfer used to end as.
                 *
                 * Once per limit value, which is what quicflow_should_send_blocked
                 * is for -- a frame per blocked packet would be a flood. */
                if (allowed == 0) {
                    const int conn_level = conn_allowed == 0;

                    metrics_quic(conn_level ? METRICS_QUIC_FLOW_BLOCKED_CONN
                                            : METRICS_QUIC_FLOW_BLOCKED_STREAM);

                    quicflow_t* blocked = conn_level ? &conn->send_flow : &s->send_flow;

                    if (quicflow_should_send_blocked(blocked) && p + 24 < payload_cap) {
                        quicframe_t bf;
                        memset(&bf, 0, sizeof bf);

                        if (conn_level) {
                            bf.type = QUIC_FRAME_DATA_BLOCKED;
                            bf.u.data_blocked.limit = blocked->limit;
                        }
                        else {
                            bf.type = QUIC_FRAME_STREAM_DATA_BLOCKED;
                            bf.u.stream_data_blocked.id = s->id;
                            bf.u.stream_data_blocked.limit = blocked->limit;
                        }

                        const size_t bn = quicframe_write(payload + p, payload_cap - p, &bf);
                        if (bn > 0) {
                            p += bn;
                            ack_eliciting = 1;

                            /* §13.3: repeated while we are still blocked. The
                             * reasoning that excuses the other limit-carrying
                             * frames -- "the next packet carries the current
                             * value anyway" -- is exactly backwards here, since
                             * being blocked is the state in which there is no
                             * next packet. Lose this one and the connection is
                             * up, idle and finished: we wait for credit, the
                             * peer waits for a reason to give it. The
                             * impairment matrix produced it in the combination
                             * of loss and a window small enough to reach
                             * (docs/http3/08-testing.md §2i).
                             *
                             * `offset` carries the stream id so the loss path
                             * can find the right flow; the connection-level
                             * frame leaves it zero and is told apart by type. */
                            quicframe_ref_t* ref = quicframe_ref_new(bf.type);
                            if (ref != NULL) {
                                ref->stream_id = conn_level ? 0 : s->id;
                                ref->next = refs;
                                refs = ref;
                            }
                        }
                    }
                }
                continue;
            }

            if (!quicsendbuf_next(&s->send, room, &offset, &data, &dlen, &fin))
                continue;

            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_STREAM | QUIC_STREAM_FLAG_LEN |
                     (offset > 0 ? QUIC_STREAM_FLAG_OFF : 0) |
                     (fin ? QUIC_STREAM_FLAG_FIN : 0);
            f.u.stream.id = s->id;
            f.u.stream.offset = offset;
            f.u.stream.len = dlen;
            f.u.stream.data = data;

            const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
            if (n == 0) continue;

            p += n;
            ack_eliciting = 1;
            stream_frames++;

            quicsendbuf_mark_sent(&s->send, offset, dlen, fin);

            /* The response as the peer will see it. `rtx` is the half that
             * matters: a retransmission at an offset the peer already holds is
             * invisible to it and to us, and telling those apart from first
             * transmissions is what §3t needed and did not have. */
            log_debug("quic: send cid=%02x%02x%02x%02x stream=%llu off=%llu "
                      "len=%zu fin=%d rtx=%d\n",
                      conn->odcid.data[0], conn->odcid.data[1],
                      conn->odcid.data[2], conn->odcid.data[3],
                      (unsigned long long)s->id, (unsigned long long)offset,
                      dlen, fin, resending);

            /* By offset, not by bytes written -- see quicflow_consume_to. The
             * connection-level window is charged the same advance, because it
             * is the sum of the streams' highest offsets and nothing else. */
            quicflow_consume(&conn->send_flow,
                             quicflow_consume_to(&s->send_flow, offset + dlen));

            if (fin) s->send_state = QUIC_SEND_DATA_SENT;

            quicframe_ref_t* ref = quicframe_ref_new(f.type);
            if (ref != NULL) {
                ref->stream_id = s->id;
                ref->offset = offset;
                ref->len = dlen;
                ref->fin = fin;
                ref->next = refs;
                refs = ref;
            }
        }
    }

    /* Before the early return below, not after it: the walks have already been
     * paid for by the time we find out there is no packet, and hiding that cost
     * is how the ratio this counts would flatter itself (§2.7). */
    metrics_quic(METRICS_QUIC_BUILD_CALLS);
    metrics_quic_add(METRICS_QUIC_BUILD_VISITS_FLOW, visits_flow);
    metrics_quic_add(METRICS_QUIC_BUILD_VISITS_DATA, visits_data);
    metrics_quic_add(METRICS_QUIC_BUILD_STREAM_FRAMES, stream_frames);

    /* Nothing to send -- or nothing but an ACK that is not due yet, which is
     * the piggyback above finding no ride. Either way no packet is built, and
     * the ACK stays owed: quicack_on_sent runs only where a packet actually
     * leaves. */
    if (p == 0 || (p == ack_len && !ack_due)) {
        quicframe_ref_free(refs);
        return 0;
    }

    /* Header protection samples 16 bytes starting four bytes past the packet
     * number (RFC 9001 §5.4.2), so the ciphertext after that point must be at
     * least that long: pn_len + payload + tag >= 4 + 16, i.e. a payload of at
     * least 4 - pn_len bytes. PADDING is the frame for it (§19.1).
     *
     * Not hypothetical, and not visible without counting: a packet carrying
     * only a PING -- which is exactly what a PTO probe is -- came to one
     * payload byte, quichp_apply failed, and __build_packet returned 0. The
     * probe was built and silently never sent, so a connection that lost its
     * last packet stalled for good while the PTO fired on forever. Found by
     * dropping one response in the test client (docs/http3/08 §2). */
    if (p < 4 && p + 4 <= payload_cap) {
        memset(payload + p, 0, 4 - p);
        p = 4;
    }

    /* An Initial packet must travel in a datagram of at least 1200 bytes
     * (§14.1), so short ones are padded. Padding also guarantees the header
     * protection sample exists. */
    const int needs_padding = (level == QUIC_ENC_INITIAL);

    /* A long header could not be written before its payload existed: its Length
     * field is sized from it. The short header went down before the frames. */
    if (header_len == 0) {
        hdr.payload_len = p + QUIC_AEAD_TAG_LEN;

        header_len = quicpkt_write_header(dst, cap, &hdr, &pn_offset);
        if (header_len == 0) {
            quicframe_ref_free(refs);
            return 0;
        }
    }

    /* The payload was sized against a header this code predicted. If the
     * prediction was ever short, the seal below would write past `cap` -- so
     * the prediction is checked rather than trusted, and a miss drops the
     * packet instead of corrupting the datagram after it. It cannot fire for a
     * short header (the header is already written, and the payload was sized
     * against its actual length) and cannot fire for a long one (the reserve is
     * far larger than any header): if it ever does, the arithmetic above and
     * this line disagree, and that is a defect worth the log. */
    if (header_len + p + QUIC_AEAD_TAG_LEN > cap) {
        log_error("quic: header %zu + payload %zu + tag exceeds %zu at level %d\n",
                  header_len, p, cap, (int)level);
        quicframe_ref_free(refs);
        return 0;
    }

    /* In place when the frames were assembled in the datagram: `payload` is
     * `dst + header_len` there, and AES-GCM and ChaCha20-Poly1305 both encrypt
     * a buffer onto itself. Otherwise this is the copy out of the staging
     * buffer that the long-header path still needs. */
    size_t sealed_len = 0;
    if (!quiccrypto_seal(keys, pn, dst, header_len, payload, p,
                         dst + header_len, &sealed_len)) {
        quicframe_ref_free(refs);
        return 0;
    }

    size_t total = header_len + sealed_len;

    if (!quichp_apply(keys, dst, total, pn_offset, pn_len)) {
        quicframe_ref_free(refs);
        return 0;
    }

    if (needs_padding && total < QUIC_MIN_INITIAL_DATAGRAM &&
        cap >= QUIC_MIN_INITIAL_DATAGRAM) {
        memset(dst + total, 0, QUIC_MIN_INITIAL_DATAGRAM - total);
        total = QUIC_MIN_INITIAL_DATAGRAM;
    }

    /* Here and nowhere earlier: every failure above returns without a packet,
     * and an ACK counted as sent for a packet that was never built is an ACK
     * the peer waits for until its own timer gives up on it. */
    if (ack_len > 0) quicack_on_sent(&conn->ack[level]);

    quicloss_on_sent(&conn->loss, level, pn, total, ack_eliciting, 1, refs, now_us);
    if (conn->ecn_enabled) {
        conn->ecn_sent[level]++;
        metrics_quic(METRICS_QUIC_ECN_TX_MARKED);
    }

    metrics_quic(METRICS_QUIC_BUILD_PACKETS);

    QLOG(conn->qlog, "transport", "packet_sent",
         "\"header\":{\"packet_type\":\"%s\",\"packet_number\":%llu},"
         "\"raw\":{\"length\":%zu,\"payload_length\":%zu},"
         "\"ack_eliciting\":%s,\"acked_bytes\":%zu",
         __qlog_level(level), (unsigned long long)pn, total, p,
         ack_eliciting ? "true" : "false", ack_len);

    QUICBEACON("cid=%02x%02x SENT  level=%d pn=%llu bytes=%zu payload=%zu ack_bytes=%zu elic=%d",
               conn->odcid.data[0], conn->odcid.data[1],
               (int)level, (unsigned long long)pn, total, p, ack_len, ack_eliciting);

    if (out_ack_eliciting != NULL) *out_ack_eliciting = ack_eliciting;

    return total;
}

/* One datagram carrying nothing but the outstanding PATH_CHALLENGE, sent to the
 * address being validated rather than to the connection's current one.
 *
 * Its own function, and its own datagram, because everything else in the send
 * path is addressed to conn->path. Mixing the two would either send the
 * challenge where it proves nothing or send the connection's data to an
 * unvalidated address. */
static void __path_probe_send(quicconn_t* conn, uint64_t now_us) {
    quickeys_t* keys = &conn->tx[QUIC_ENC_APP];
    if (!keys->valid) return;

    uint8_t payload[QUICCONN_MAX_PACKET];
    quicframe_t f;
    memset(&f, 0, sizeof f);
    f.type = QUIC_FRAME_PATH_CHALLENGE;
    memcpy(f.u.path.data, conn->probe_data, sizeof f.u.path.data);

    size_t p = quicframe_write(payload, sizeof payload, &f);
    if (p == 0) return;

    quiccid_t* dcid = conn->peer_cid_count > 0 ? &conn->peer_cids[0] : NULL;
    if (dcid == NULL) return;

    const uint64_t pn = conn->loss.space[QUIC_ENC_APP].next_pn;
    const size_t pn_len = quicpkt_pn_length(pn, conn->loss.space[QUIC_ENC_APP].largest_acked);

    quicpkt_hdr_out_t hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = QUIC_PKT_SHORT;
    hdr.version = QUIC_VERSION_1;
    hdr.dcid = dcid;
    hdr.scid = &conn->local_cids[0].cid;
    hdr.pn = pn;
    hdr.pn_len = pn_len;
    hdr.key_phase = conn->key_phase;

    /* §8.2.1: the datagram is padded to 1200 bytes, because a path that cannot
     * carry that much is not a path QUIC can use, and validating it would only
     * move the failure later. The padding goes in before sealing so it is
     * covered by the AEAD like any other payload. */
    if (p < QUIC_MIN_INITIAL_DATAGRAM - 64) {
        memset(payload + p, 0, QUIC_MIN_INITIAL_DATAGRAM - 64 - p);
        p = QUIC_MIN_INITIAL_DATAGRAM - 64;
    }

    hdr.payload_len = p + QUIC_AEAD_TAG_LEN;

    uint8_t datagram[QUICCONN_MAX_PACKET];
    size_t pn_offset = 0;
    const size_t header_len = quicpkt_write_header(datagram, sizeof datagram, &hdr, &pn_offset);
    if (header_len == 0) return;

    size_t sealed_len = 0;
    if (!quiccrypto_seal(keys, pn, datagram, header_len, payload, p,
                         datagram + header_len, &sealed_len))
        return;

    const size_t total = header_len + sealed_len;
    if (!quichp_apply(keys, datagram, total, pn_offset, pn_len)) return;

    /* Recorded as sent but **not in flight**: the congestion window belongs to
     * the path in use, and a probe on a different one must neither consume it
     * nor be treated as loss on it when the new path turns out to be dead. */
    quicloss_on_sent(&conn->loss, QUIC_ENC_APP, pn, total, 1, 0, NULL, now_us);
    if (conn->ecn_enabled) {
        conn->ecn_sent[QUIC_ENC_APP]++;
        metrics_quic(METRICS_QUIC_ECN_TX_MARKED);
    }

    quicendpoint_send_ecn(conn->endpoint, datagram, total, &conn->probe_path,
                          conn->ecn_enabled ? 0x02 : 0);

    conn->probe_pending = 0;
    conn->probe_attempts++;
    conn->probe_next_us = now_us + quicloss_pto_us(&conn->loss, QUIC_ENC_APP);
}

/* RFC 8899 probe: a probe-only 1-RTT packet padded to the candidate size.
 * Application data is deliberately excluded so loss of a probe never causes
 * head-of-line delay at the application. */
static void __pmtu_probe_send(quicconn_t* conn, uint64_t now_us) {
    if (!conn->tx[QUIC_ENC_APP].valid || conn->peer_cid_count == 0) return;

    const size_t target = quicpmtud_candidate(&conn->pmtud);
    if (target <= conn->pmtud.current || target > QUICCONN_MAX_PACKET)
        return;

    const uint64_t pn = conn->loss.space[QUIC_ENC_APP].next_pn;
    const size_t pn_len = quicpkt_pn_length(
        pn, conn->loss.space[QUIC_ENC_APP].largest_acked);
    quicpkt_hdr_out_t hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = QUIC_PKT_SHORT;
    hdr.version = QUIC_VERSION_1;
    hdr.dcid = &conn->peer_cids[0];
    hdr.scid = &conn->local_cids[0].cid;
    hdr.pn = pn;
    hdr.pn_len = pn_len;
    hdr.key_phase = conn->key_phase;

    uint8_t datagram[QUICCONN_MAX_PACKET];
    size_t pn_offset = 0;
    const size_t header_len = quicpkt_write_header(datagram, sizeof datagram,
                                                    &hdr, &pn_offset);
    if (!header_len || target <= header_len + QUIC_AEAD_TAG_LEN) return;

    const size_t plain_len = target - header_len - QUIC_AEAD_TAG_LEN;
    uint8_t plain[QUICCONN_MAX_PACKET];
    plain[0] = QUIC_FRAME_PING;
    memset(plain + 1, 0, plain_len - 1);

    size_t sealed = 0;
    if (!quiccrypto_seal(&conn->tx[QUIC_ENC_APP], pn, datagram, header_len,
                         plain, plain_len, datagram + header_len, &sealed)) return;
    const size_t total = header_len + sealed;
    if (total != target || !quichp_apply(&conn->tx[QUIC_ENC_APP], datagram,
                                         total, pn_offset, pn_len)) return;

    quicframe_ref_t* ref = quicframe_ref_new(QUIC_FRAME_PING);
    /* Probe loss says the size may be wrong, not that the path is congested;
     * keep it in loss detection for its ACK, but outside bytes_in_flight. */
    quicloss_on_sent(&conn->loss, QUIC_ENC_APP, pn, total, 1, 0, ref, now_us);
    if (conn->ecn_enabled) {
        conn->ecn_sent[QUIC_ENC_APP]++;
        metrics_quic(METRICS_QUIC_ECN_TX_MARKED);
    }
    quicpmtud_on_probe_sent(&conn->pmtud, pn, now_us,
                            quicloss_pto_us(&conn->loss, QUIC_ENC_APP));
    metrics_quic(METRICS_QUIC_PMTU_PROBES_SENT);
    QLOG(conn->qlog, "recovery", "mtu_probe_sent",
         "\"size\":%zu,\"packet_number\":%llu,\"current\":%zu",
         total, (unsigned long long)pn, conn->pmtud.current);
    quicendpoint_send_ecn(conn->endpoint, datagram, total, &conn->path,
                          conn->ecn_enabled ? 0x02 : 0);
}

int quicconn_send(quicconn_t* conn, uint64_t now_us) {
    if (conn == NULL) return 0;
    if (conn->state == QUICCONN_DRAINING || conn->state == QUICCONN_DEAD) return 1;

    if (conn->state == QUICCONN_CLOSING) {
        if (conn->close_packet_len > 0) {
            const int queued = quicendpoint_send_ecn(conn->endpoint, conn->close_packet,
                                                     conn->close_packet_len, &conn->path,
                                                     conn->ecn_enabled ? 0x02 : 0);
            /* The one datagram the ordinary send loop never logs, and the one
             * whose absence is hardest to diagnose from the peer's side: a
             * missing goodbye looks exactly like a server that hung up. */
            log_debug("quic: close dgram cid=%02x%02x%02x%02x bytes=%zu queued=%d\n",
                      conn->odcid.data[0], conn->odcid.data[1],
                      conn->odcid.data[2], conn->odcid.data[3],
                      conn->close_packet_len, queued);
        }
        else
            log_debug("quic: close cid=%02x%02x%02x%02x has no packet to send\n",
                      conn->odcid.data[0], conn->odcid.data[1],
                      conn->odcid.data[2], conn->odcid.data[3]);
        atomic_store_explicit(&conn->want_write, 0, memory_order_release);
        return 1;
    }

    /* Ahead of the connection's own datagram: §8.2.2 will not have the answer
     * delayed, and the same urgency applies to the question. */
    if (conn->probe_active && conn->probe_pending)
        __path_probe_send(conn, now_us);

    /* Order matters, and it is the expensive half that goes second:
     * quicconn_unsent_bytes walks every stream of the connection, while
     * quicpmtud_should_probe is three loads and is false almost always -- no
     * probe is due until the timer opens, and once the search has finished
     * (current == ceiling) it is false forever. Asked the other way round, this
     * walk ran on every send turn of every connection: at a hundred streams it
     * was the single hottest leaf in the profile (5.3 % in
     * quicsendbuf_unsent_bytes alone) to answer a question whose answer was
     * "no". */
    if (conn->state == QUICCONN_ACTIVE &&
        quicpmtud_should_probe(&conn->pmtud, now_us) &&
        quicconn_unsent_bytes(conn) >= 4 * conn->pmtud.current)
        __pmtu_probe_send(conn, now_us);

    uint8_t datagram[QUICCONN_MAX_PACKET];
    int sent_anything = 0;
    /* Whether the loop stopped with work still owed. Only "nothing left to
     * build" clears want_write; every other exit -- the round cap, the
     * congestion window, the anti-amplification budget -- means the rest of the
     * flight is still waiting and must be asked for again. */
    int more_pending = 0;

    /* Recomputed by this turn, so cleared at its start: a deadline left over
     * from a previous turn would keep waking the endpoint for a connection that
     * is no longer waiting on the clock. */
    conn->pace_until_us = 0;

    for (int round = 0; round < QUICCONN_SEND_ROUNDS; round++) {
        size_t total = 0;
        int ack_levels = 0;

        /* §7: the window is asked *before* the packet is built. It used to be
         * asked after one had already gone out, and only to break this loop
         * while re-arming want_write -- which made it advisory, because the
         * endpoint came straight back and sent the next packet anyway. The
         * sender therefore ran at line rate: on the interop path (10 Mbps,
         * 15 ms, a 25-packet queue) it emptied the whole flow-control window
         * into a queue that could hold a twentieth of it, and the peer received
         * under a tenth of what was sent (docs/http3/08 §3i). */
        /* §7.7, and asked in the same breath as the window because it answers
         * the same question with a different clock. The window reopens when the
         * peer says something; the pacer reopens on time alone, so a turn it
         * stops has to leave a deadline behind or the rest of the flight waits
         * for a peer with nothing to say. */
        const size_t paced = quicpacer_allowance(&conn->pacer, &conn->cc,
                                                 conn->loss.smoothed_rtt_us, now_us);

        /* The allowance is the smaller of the bucket and the window, so a zero
         * does not say which of them produced it. The deadline does: it is
         * non-zero only when the bucket is short of a datagram. Asking that way
         * round also decides the failure mode -- a pacer that cannot name the
         * moment it reopens is treated as not blocking at all, because the
         * window is the limit that must hold and this one is advisory. */
        const uint64_t pace_resume_us =
            paced < conn->pmtud.current
                ? quicpacer_next_time_us(&conn->pacer, &conn->cc,
                                         conn->loss.smoothed_rtt_us, now_us)
                : 0;

        const int pace_blocked = pace_resume_us != 0;

        if (pace_blocked) {
            conn->pace_until_us = pace_resume_us;
            more_pending = 1;
        }

        /* Folded into the window's own flag, which is what gives the pacer the
         * two exemptions __build_packet already grants: an acknowledgement
         * (§7.7 paces what the controller counts, and an ACK-only packet is not
         * in flight -- holding one back costs the peer a round trip and buys
         * the path nothing) and a PTO probe (§7.7 lets one go without regard to
         * pacing, for the same reason §7.5 lets it exceed the window: a probe
         * exists to end a stall, and a stall is not eased by waiting). */
        const int cc_blocked = quiccc_available(&conn->cc) < conn->pmtud.current ||
                               pace_blocked;

        const uint64_t in_flight_before = conn->cc.bytes_in_flight;

        /* Coalesce the levels into one datagram where possible: an Initial and
         * a Handshake packet together is what makes a server flight fit in one
         * datagram rather than two (§12.2). */
        for (int i = 0; i < QUIC_ENC_COUNT && total < sizeof datagram; i++) {
            if (i == QUIC_ENC_EARLY) continue;

            const quic_enc_level_e level = (quic_enc_level_e)i;

            /* Anti-amplification: until the address is validated, nothing may
             * be sent beyond three times what arrived. */
            if (!conn->address_validated &&
                total >= conn->amplification_budget) {
                /* Counted because it is invisible from outside and looks like a
                 * stalled handshake: a long certificate chain hits it against
                 * an honest client, and that is a certificate problem, not a
                 * network one (docs/http3/04 §8). */
                metrics_quic(METRICS_QUIC_AMPLIFICATION_LIMITED);

                /* The counter says it happened somewhere; this says it happened
                 * here, to this connection, with this much owed. It is the line
                 * that decides whose deadlock it is when a handshake goes quiet
                 * (docs/http3/08 §3w): a server stopped by its own §8.1 budget
                 * is doing what the RFC tells it to and can only wait for the
                 * peer, while a server stopped by anything else is our bug. */
                log_debug("quic: amp-block cid=%02x%02x%02x%02x level=%d "
                          "budget=%llu total=%zu unsent=%llu validated=%d\n",
                          conn->odcid.data[0], conn->odcid.data[1],
                          conn->odcid.data[2], conn->odcid.data[3], (int)level,
                          (unsigned long long)conn->amplification_budget, total,
                          (unsigned long long)quicconn_unsent_bytes(conn),
                          conn->address_validated);
                break;
            }

            size_t room = conn->pmtud.current > total
                          ? conn->pmtud.current - total : 0;
            if (!conn->address_validated) {
                const uint64_t budget = conn->amplification_budget > total
                                        ? conn->amplification_budget - total : 0;
                if (budget < room) room = (size_t)budget;
            }

            const int owed_ack = quicack_should_send(&conn->ack[i], now_us);

            int eliciting = 0;
            const size_t n = __build_packet(conn, level, datagram + total, room,
                                            now_us, cc_blocked, &eliciting);
            if (n == 0) continue;

            /* Bit per level, so one line says which spaces the datagram
             * acknowledged rather than merely that something went out. */
            if (owed_ack) ack_levels |= 1 << i;

            total += n;

            /* A short header has no length field, so nothing may follow it. */
            if (level == QUIC_ENC_APP) break;
        }

        if (total == 0) break;

        if (!conn->address_validated) {
            conn->amplification_budget = conn->amplification_budget > total
                                         ? conn->amplification_budget - total : 0;
        }

        /* Every datagram that leaves, with what put it on the wire. The whole
         * of §3x rested on counting the peer's *receipts* and calling the
         * difference "not sent" -- which cannot tell an acknowledgement we never
         * built from one the network ate. This can. */
        log_debug("quic: dgram cid=%02x%02x%02x%02x bytes=%zu acked_levels=%d\n",
                  conn->odcid.data[0], conn->odcid.data[1],
                  conn->odcid.data[2], conn->odcid.data[3], total, ack_levels);

        if (quicendpoint_send_ecn(conn->endpoint, datagram, total, &conn->path,
                                  conn->ecn_enabled ? 0x02 : 0) < 0)
            break;

        sent_anything = 1;

        /* Charged exactly what the controller counted, which is how an ACK-only
         * datagram leaves the bucket alone: bytes_in_flight is raised by
         * quicloss_on_sent for the packets that are in flight and by nothing
         * else, so its rise over this round is the paced quantity. */
        const uint64_t in_flight_added = conn->cc.bytes_in_flight > in_flight_before
                                       ? conn->cc.bytes_in_flight - in_flight_before : 0;
        if (in_flight_added > 0)
            quicpacer_consume(&conn->pacer, (size_t)in_flight_added);

        /* Out of window: stop, and do *not* ask for another turn. The window
         * reopens on an acknowledgement or when the loss timer declares
         * something lost, and both of those set want_write themselves. Asking
         * again here is what turned the window into a suggestion. */
        if (quiccc_available(&conn->cc) < conn->pmtud.current) break;

        /* The last round produced a full datagram, so there may well be
         * another: a server flight carrying a certificate chain runs to six or
         * more, and clearing the flag here left the remainder waiting for the
         * peer to nudge us. */
        if (round + 1 == QUICCONN_SEND_ROUNDS) more_pending = 1;
    }

    /* Cleared before the reaping below, never after: releasing a peer's
     * bidirectional stream returns stream credit and raises want_write so the
     * MAX_STREAMS carrying it gets built, and clearing the flag afterwards
     * threw that away. It survived only because a busy connection always had
     * another reason to build a packet; a connection whose last request has
     * just finished has none, and stops at exactly initial_max_streams_bidi
     * with the credit sitting here (docs/http3/08 §3p). */
    /* The loop ran out of things to build rather than out of window, pacer or
     * budget -- `more_pending` is exactly that distinction, and it is already
     * computed. Telling the estimator matters only for a rate-based controller,
     * and only in one direction: rates measured across an idle sender are the
     * application's speed, and a controller that took them for the path's would
     * spend the next ten round trips sending at the speed of a pause. */
    if (!more_pending) {
        quicloss_app_limited(&conn->loss);
        atomic_store_explicit(&conn->want_write, 0, memory_order_release);
    }

    /* After the turn, not during it: the loop above walks conn->streams, and a
     * stream freed underneath it would be a use-after-free. */
    __streams_reap(conn);

    (void)sent_anything;

    return 1;
}

void quicconn_want_write(connection_t* connection) {
    if (connection == NULL) return;

    quicconn_t* conn = __conn_of(connection);

    atomic_store_explicit(&conn->want_write, 1, memory_order_release);
    quicendpoint_wake(conn->endpoint, conn);
}

/* ---- Lifecycle ---- */

/* Release the QUIC-specific state. Reached through
 * connection_server_ctx_t::transport_free, i.e. from connection_free, which is
 * the only code that knows when the last reference has gone. It must not free
 * the object -- connection_free does that immediately afterwards, and the
 * connection_t it frees *is* this quicconn_t. */
static void __quicconn_transport_free(void* arg) {
    quicconn_t* conn = arg;
    if (conn == NULL) return;

    quictls_free(&conn->tls);

    quickeys_free(&conn->rx_next);
    quickeys_free(&conn->rx_prev);

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        quickeys_free(&conn->rx[i]);
        quickeys_free(&conn->tx[i]);
        quicack_free(&conn->ack[i]);
        quicsendbuf_free(&conn->crypto_out[i]);
    }

    quicloss_free(&conn->loss);

    /* Last, so anything the frees above chose to log still lands in the file. */
    quicqlog_close(conn->qlog);
    conn->qlog = NULL;

    quicstream_t* s = conn->streams;
    while (s != NULL) {
        quicstream_t* next = s->next;
        quicstream_free(s);
        s = next;
    }
    conn->streams = NULL;
    conn->streams_tail = NULL;
}

quicconn_t* quicconn_accept(struct quicendpoint* endpoint,
                            const quiccid_t* odcid, const quiccid_t* peer_scid,
                            const quicpath_t* path, server_t* server,
                            int address_validated, const quiccid_t* retry_odcid) {
    if (endpoint == NULL || odcid == NULL || peer_scid == NULL || path == NULL)
        return NULL;

    quicconn_t* conn = malloc(sizeof * conn);
    if (conn == NULL) return NULL;

    memset(conn, 0, sizeof * conn);

    conn->endpoint = endpoint;
    conn->path = *path;
    conn->odcid = *odcid;
    conn->state = QUICCONN_HANDSHAKE;

    /* The other end of the pair with "handshake complete": a handshake that
     * never finishes leaves this line alone in the log, which is the only way
     * to find it among the fifty a multiconnect test starts. */
    log_debug("quic: accepted cid=%02x%02x%02x%02x\n",
              odcid->data[0], odcid->data[1], odcid->data[2], odcid->data[3]);

    /* Opened before anything can go wrong below, so that a connection which
     * fails during accept still leaves a trace saying it existed -- that is the
     * case a qlog is least able to be recreated for. NULL unless qlog is
     * configured and the budget was open, which is the ordinary case. */
    conn->qlog = quicqlog_open(odcid->data, odcid->len);

    if (conn->qlog != NULL) {
        char src[INET6_ADDRSTRLEN] = {0};
        char dst[INET6_ADDRSTRLEN] = {0};
        unsigned src_port = 0;
        __qlog_addr(&path->remote, src, sizeof src, &src_port);
        /* The local port is deliberately not reported: the address comes from
         * the datagram's control message, which carries the address the peer
         * addressed and not the port -- that one belongs to the endpoint's
         * socket (udpsocket.h). Printing the zero it holds would be a number
         * that reads as a port and is not one. */
        __qlog_addr(&path->local, dst, sizeof dst, NULL);

        QLOG(conn->qlog, "connectivity", "connection_started",
             "\"ip_version\":\"%s\",\"src_ip\":\"%s\",\"src_port\":%u,"
             "\"dst_ip\":\"%s\",\"address_validated\":%s",
             path->remote.ss_family == AF_INET6 ? "v6" : "v4",
             src, src_port, dst,
             address_validated ? "true" : "false");
    }

    const uint64_t now = quic_now_us();
    conn->last_activity_us = now;
    conn->accepted_us = now;
    conn->rx_overflow_at_accept = quicendpoint_kernel_drops(endpoint);
    /* The gap counter starts over with the connection. Left running, it reports
     * the idle stretch between two runs -- forty seconds of a server with
     * nothing to do -- which is true and useless: the question is how long the
     * socket waits while a transfer is in progress. */
    quicendpoint_recv_gap_reset(endpoint);

    /* §8.1: nothing may go back to an unvalidated address beyond three times
     * what came from it. The first Initial is at least 1200 bytes, so this
     * starts at 3600 -- enough for a certificate flight only if the chain is
     * short, which is why 07-integration.md tells operators to keep it so. */
    conn->amplification_budget = 0;

    /* The client's Source Connection ID is where our packets are addressed. */
    conn->peer_cids[0] = *peer_scid;
    conn->peer_cid_count = 1;
    /* And the same value again, as the record of what that first packet said --
     * §7.3 checks the transport parameter against it (__on_peer_params). */
    conn->peer_initial_scid = *peer_scid;

    /* Ours, which the client will use from its next packet onwards. Random so
     * that two connections of the same client cannot be linked by an observer
     * (§5.1). */
    conn->local_cids[0].cid.len = QUIC_LOCAL_CID_LEN;
    if (RAND_bytes(conn->local_cids[0].cid.data, QUIC_LOCAL_CID_LEN) != 1) {
        /* The two failure paths that free the connection directly, before any
         * of its modules exist, have to close the trace themselves -- it is the
         * one thing opened above them. */
        quicqlog_close(conn->qlog);
        free(conn);
        return NULL;
    }
    conn->local_cids[0].seq = 0;
    conn->local_cids[0].active = 1;
    /* The peer reads this one out of our packet headers, so there is no
     * NEW_CONNECTION_ID to send for it. */
    conn->local_cids[0].announced = 1;
    conn->next_cid_seq = 1;

    /* Initial keys come from the client's original Destination Connection ID --
     * the only secret both sides share before any handshake (§5.2). */
    uint8_t client_secret[32];
    uint8_t server_secret[32];
    if (!quiccrypto_initial_secrets(odcid, client_secret, server_secret)) {
        quicqlog_close(conn->qlog);
        free(conn);
        return NULL;
    }

    const int keys_ok =
        quickeys_install(&conn->rx[QUIC_ENC_INITIAL], QUIC_AEAD_AES_128_GCM,
                         client_secret, sizeof client_secret) &&
        quickeys_install(&conn->tx[QUIC_ENC_INITIAL], QUIC_AEAD_AES_128_GCM,
                         server_secret, sizeof server_secret);

    explicit_bzero(client_secret, sizeof client_secret);
    explicit_bzero(server_secret, sizeof server_secret);

    if (!keys_ok) {
        quicconn_free(conn);
        return NULL;
    }

    /* Read once, here: everything below is decided at accept time and never
     * revisited, so a reload cannot change a live connection's parameters --
     * which is correct, since they were already advertised to the peer. */
    const quic_conn_policy_t* policy = quic_policy_conn();

    conn->amplification_factor = policy->amplification_factor;
    conn->ecn_enabled = 1;

    quiccc_init_algorithm(&conn->cc, QUIC_DEFAULT_UDP_PAYLOAD,
                          policy->initcwnd_packets, policy->cc_algorithm);
    /* After the controller, always: the burst limit is the window it just
     * computed. */
    quicpacer_init(&conn->pacer, &conn->cc, policy->pacing);
    conn->pace_until_us = 0;
    quicloss_init(&conn->loss, &conn->cc, policy->ack_delay_ms * 1000);
    quicloss_set_cid_tag(&conn->loss, conn->odcid.data, conn->odcid.len);
    quicloss_set_qlog(&conn->loss, conn->qlog);
    const size_t pmtu_ceiling = conn->path.remote.ss_family == AF_INET6
                                ? QUIC_MAX_UDP_PAYLOAD_V6 : QUIC_MAX_UDP_PAYLOAD_V4;
    quicpmtud_init(&conn->pmtud, QUIC_DEFAULT_UDP_PAYLOAD, pmtu_ceiling);

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        quicack_init(&conn->ack[i]);
        quicsendbuf_init(&conn->crypto_out[i]);
    }

    /* Our transport parameters. original_destination_connection_id and
     * initial_source_connection_id are mandatory for a server (§7.3): the
     * client checks them against the ids it actually saw, and that is what
     * binds this handshake to this connection. */
    quictp_defaults(&conn->local_params);
    conn->local_params.max_idle_timeout = policy->idle_timeout_ms;
    conn->local_params.max_udp_payload_size = policy->max_udp_payload_size;
    conn->local_params.initial_max_data = policy->initial_max_data;
    conn->local_params.initial_max_stream_data_bidi_remote = policy->initial_max_stream_data;
    conn->local_params.initial_max_stream_data_uni = policy->initial_max_stream_data;
    conn->local_params.initial_max_streams_bidi = policy->max_streams_bidi;
    conn->local_params.initial_max_streams_uni = policy->max_streams_uni;
    conn->local_params.active_connection_id_limit = policy->active_cid_limit;
    conn->local_params.max_ack_delay = policy->ack_delay_ms;
    conn->local_params.has_original_dcid = 1;

    if (retry_odcid != NULL) {
        /* §7.3: after a Retry the two ids are different things. The *original*
         * is the one the client invented for its very first Initial, which only
         * the Retry token remembers; the one it is addressing us by now is the
         * one we chose for the Retry, and it goes in retry_source_connection_id.
         * Reporting the current id as the original is the classic way to make a
         * retried handshake fail with a transport parameter error. */
        conn->local_params.original_dcid = *retry_odcid;
        conn->local_params.has_retry_scid = 1;
        conn->local_params.retry_scid = *odcid;
    }
    else
        conn->local_params.original_dcid = *odcid;

    /* A token proved the address; §8.1's three-times limit has nothing left to
     * protect against and would only slow the handshake down. */
    conn->address_validated = address_validated;
    conn->local_params.has_initial_scid = 1;
    conn->local_params.initial_scid = conn->local_cids[0].cid;
    /* RFC 9000 §18.2: a server supplies the reset token for the initial CID in
     * its transport parameters. Later CIDs carry their tokens in
     * NEW_CONNECTION_ID; omitting this one leaves the original routing name
     * without a stateless-reset path. */
    if (!quicendpoint_reset_token(&conn->local_cids[0].cid,
                                  conn->local_params.stateless_reset_token)) {
        quicconn_free(conn);
        return NULL;
    }
    conn->local_params.has_stateless_reset_token = 1;

    conn->idle_timeout_us = conn->local_params.max_idle_timeout * 1000;

    conn->keepalive_conf_us = policy->keepalive_ms * 1000;
    __keepalive_recompute(conn);

    quicflow_init_recv(&conn->recv_flow, conn->local_params.initial_max_data,
                       policy->recv_window_max);
    quicflow_init_send(&conn->send_flow, 0);

    conn->next_local_uni = 0;

    /* The vhost's QUIC context, not its TCP one: TLS 1.3 only, `h3` alone in
     * ALPN, no CCM (see openssl.h). */
    if (server == NULL || server->openssl == NULL || server->openssl->quic_ctx == NULL) {
        quicconn_free(conn);
        return NULL;
    }

    /* 0-RTT, if the operator asked for it (RFC 9001 §4.6). The context binds
     * every ticket to this configuration; quictls refuses to resume across a
     * change, so a client can never bring early data into a connection whose
     * limits differ from the ones it remembered (§7.4.1). */
    quictls_early_t early;
    memset(&early, 0, sizeof early);
    early.enabled = policy->early_data;
    early.resumption_context_len = policy->resumption_context_len;
    if (early.resumption_context_len > sizeof early.resumption_context)
        early.resumption_context_len = sizeof early.resumption_context;
    memcpy(early.resumption_context, policy->resumption_context,
           early.resumption_context_len);

    if (!quictls_init_server(&conn->tls, server->openssl->quic_ctx, &__tls_ops, conn,
                             &conn->local_params, &early)) {
        quicconn_free(conn);
        return NULL;
    }

    /* The embedded connection_t, initialised in place: it has to live inside
     * this object rather than beside it, because the connection layer casts
     * between the two. The fd is the endpoint's shared socket -- kept for
     * diagnostics only, since nothing here ever reads or writes it directly. */
    ipaddr_t remote_ip;
    ipaddr_from_sockaddr(&remote_ip, (const struct sockaddr*)&path->remote);

    const unsigned short remote_port =
        path->remote.ss_family == AF_INET6
        ? ntohs(((const struct sockaddr_in6*)&path->remote)->sin6_port)
        : ntohs(((const struct sockaddr_in*)&path->remote)->sin_port);

    /* The local address matters: httpparser_select_server picks the virtual
     * server by (ip, port), so a connection that reports 0/0 matches no vhost
     * and every request is a 421. TCP gets these from accept(); QUIC has to
     * take them from the endpoint it arrived on. */
    const ipaddr_t local_ip = quicendpoint_ip(endpoint);

    if (!connection_s_init(&conn->conn, quicendpoint_listener(endpoint),
                           quicendpoint_fd(endpoint),
                           &local_ip, quicendpoint_port(endpoint),
                           &remote_ip, remote_port, NULL, 0)) {
        __quicconn_transport_free(conn);
        free(conn);
        return NULL;
    }

    conn->conn.transport = CONN_TRANSPORT_QUIC;
    conn->conn.close = quicconn_close_cb;
    /* Where the SNI callback finds us. It reads the connection to pick the
     * vhost -- and, since this one is QUIC, to pick the vhost's QUIC context
     * rather than its TCP one. Without this the callback dereferences NULL,
     * which is how it first showed up. */
    SSL_set_app_data(conn->tls.ssl, &conn->conn);
    conn->conn.read = NULL;    /* the endpoint reads; there is no fd of our own */
    conn->conn.write = NULL;

    connection_server_ctx_t* ctx = conn->conn.ctx;
    ctx->transport_data = conn;
    ctx->transport_free = __quicconn_transport_free;
    ctx->server = server;

    return conn;
}

int quicconn_close_cb(connection_t* connection) {
    if (connection == NULL) return 1;

    quicconn_t* conn = __conn_of(connection);
    connection_server_ctx_t* ctx = connection->ctx;

    /* Already holding the lock: every close path in this server takes it before
     * calling close(), and it is not recursive. */
    quicendpoint_detach(conn->endpoint, conn);

    /* The bookkeeping half of control_del -- the worker's list and count. For a
     * QUIC connection there is no epoll registration to remove. */
    if (!ctx->listener->api->control_del(connection))
        log_error("quicconn: connection not removed from api\n");

    atomic_store(&ctx->detached, 1);
    atomic_store(&ctx->destroyed, 1);

    if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_s_unlock(connection);

    return 1;
}

void quicconn_free(quicconn_t* conn) {
    if (conn == NULL) return;

    /* Only reachable from the failure paths of quicconn_accept, before the
     * connection_t exists. Once it does, the object is released through the
     * reference count like any other connection. */
    __quicconn_transport_free(conn);
    free(conn);
}

/* One CONNECTION_CLOSE packet at one encryption level, written into `dst`.
 *
 * Returns bytes written, or 0 if the level has no keys or the room runs out --
 * both of which the caller treats the same way, as "this level contributes
 * nothing to the datagram". */
static size_t __write_close_packet(quicconn_t* conn, quic_enc_level_e level,
                                   uint8_t* dst, size_t cap) {
    if (!conn->tx[level].valid) return 0;

    quiccid_t* dcid = conn->peer_cid_count > 0 ? &conn->peer_cids[0] : NULL;
    if (dcid == NULL) return 0;

    uint8_t payload[64];
    quicframe_t f;
    memset(&f, 0, sizeof f);
    /* An application error code cannot be sent before the handshake keys
     * exist, so it becomes APPLICATION_ERROR at the transport level (§10.2.3). */
    f.type = (conn->error_is_app && level == QUIC_ENC_APP)
             ? QUIC_FRAME_CONNECTION_CLOSE_APP : QUIC_FRAME_CONNECTION_CLOSE;
    f.u.close.error = (conn->error_is_app && level != QUIC_ENC_APP)
                      ? QUIC_APPLICATION_ERROR : conn->error_code;

    const size_t plen = quicframe_write(payload, sizeof payload, &f);
    if (plen == 0) return 0;

    const uint64_t pn = conn->loss.space[level].next_pn;
    const size_t pn_len = quicpkt_pn_length(pn, conn->loss.space[level].largest_acked);

    quicpkt_hdr_out_t hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = level == QUIC_ENC_APP       ? QUIC_PKT_SHORT
             : level == QUIC_ENC_HANDSHAKE ? QUIC_PKT_HANDSHAKE
                                           : QUIC_PKT_INITIAL;
    hdr.version = QUIC_VERSION_1;
    hdr.dcid = dcid;
    hdr.scid = &conn->local_cids[0].cid;
    hdr.pn = pn;
    hdr.pn_len = pn_len;
    hdr.payload_len = plen + QUIC_AEAD_TAG_LEN;

    size_t pn_offset = 0;
    const size_t header_len = quicpkt_write_header(dst, cap, &hdr, &pn_offset);
    if (header_len == 0) return 0;

    size_t sealed = 0;
    if (!quiccrypto_seal(&conn->tx[level], pn, dst, header_len,
                         payload, plen, dst + header_len, &sealed))
        return 0;

    size_t total = header_len + sealed;

    /* Header protection needs a sample four bytes past the packet number, so a
     * short packet has to be padded to reach it. Only ever the last packet in
     * the datagram: a long header carries a length, so padding one would put
     * the bytes outside it. */
    if (level == QUIC_ENC_APP && total < pn_offset + QUICHP_MIN_AFTER_PN &&
        pn_offset + QUICHP_MIN_AFTER_PN <= cap) {
        memset(dst + total, 0, pn_offset + QUICHP_MIN_AFTER_PN - total);
        total = pn_offset + QUICHP_MIN_AFTER_PN;
    }

    if (!quichp_apply(&conn->tx[level], dst, total, pn_offset, pn_len)) return 0;

    conn->loss.space[level].next_pn++;

    return total;
}

void quicconn_close(quicconn_t* conn, uint64_t error_code, int is_app,
                    uint64_t now_us) {
    if (conn == NULL) return;
    if (conn->state == QUICCONN_CLOSING || conn->state == QUICCONN_DRAINING ||
        conn->state == QUICCONN_DEAD) return;

    log_error("quic: closing, %s error 0x%llx\n",
              is_app ? "application" : "transport", (unsigned long long)error_code);

    metrics_quic(METRICS_QUIC_CLOSED_LOCAL);

    QLOG(conn->qlog, "connectivity", "connection_closed",
         "\"owner\":\"local\",\"%s_code\":%llu",
         is_app ? "application" : "connection",
         (unsigned long long)error_code);

    conn->state = QUICCONN_CLOSING;
    conn->error_code = error_code;
    conn->error_is_app = is_app;
    conn->close_deadline_us = now_us + quicloss_pto_us(&conn->loss, QUIC_ENC_APP) * 3;

    /* Build the close datagram once and keep it: §10.2.1 has it re-sent in
     * answer to anything that arrives during the closing period, and rebuilding
     * it each time would need state we are about to stop maintaining.
     *
     * Once 1-RTT keys exist the peer certainly reads them, and one short-header
     * packet is the whole datagram. Before that, §10.2.3: we cannot know which
     * level the peer can still read, so the frame goes out at *every* level we
     * hold keys for, coalesced. Sending only the lowest one -- which is what
     * this did -- makes every handshake-time error invisible to a peer that has
     * already moved on and discarded those keys. h3spec sees the connection
     * simply stop; a real client sees a handshake that hangs to its timeout
     * with no reason given, which is the worst failure mode this protocol has. */
    size_t total = 0;

    /* "The peer can read 1-RTT" is not the same as "we can write it", and the
     * difference is a whole flight wide: a server holds 1-RTT keys from the
     * moment it sends its Finished, while the client cannot read them until it
     * has processed that flight. Choosing the level by our own keys sent every
     * handshake-time error into a packet the peer had no way to open. */
    if (conn->tls.handshake_complete && conn->tx[QUIC_ENC_APP].valid)
        total = __write_close_packet(conn, QUIC_ENC_APP, conn->close_packet,
                                     sizeof conn->close_packet);
    else {
        total = __write_close_packet(conn, QUIC_ENC_INITIAL, conn->close_packet,
                                     sizeof conn->close_packet);
        total += __write_close_packet(conn, QUIC_ENC_HANDSHAKE,
                                      conn->close_packet + total,
                                      sizeof conn->close_packet - total);
    }

    if (total == 0) return;

    conn->close_packet_len = total;
    atomic_store_explicit(&conn->want_write, 1, memory_order_release);
}

int quicconn_tick(quicconn_t* conn, uint64_t now_us) {
    if (conn == NULL) return 0;

    if (conn->state == QUICCONN_CLOSING || conn->state == QUICCONN_DRAINING) {
        if (now_us >= conn->close_deadline_us) {
            conn->state = QUICCONN_DEAD;
            return 0;
        }
        return 1;
    }

    /* §10.1: silence for longer than the negotiated timeout ends the
     * connection, with no close frame -- there is nobody to tell. */
    if (conn->idle_timeout_us > 0 &&
        now_us > conn->last_activity_us + conn->idle_timeout_us) {
        metrics_quic(METRICS_QUIC_CLOSED_IDLE);

        QLOG(conn->qlog, "connectivity", "connection_closed",
             "\"owner\":\"local\",\"trigger\":\"idle_timeout\","
             "\"idle_us\":%llu,\"handshake\":%s",
             (unsigned long long)(now_us - conn->last_activity_us),
             conn->state == QUICCONN_HANDSHAKE ? "true" : "false");

        /* Timing out mid-handshake is a different failure: the peer never got
         * far enough to say anything, which is what a blocked UDP path and a
         * rejected certificate both look like from here. */
        if (conn->state == QUICCONN_HANDSHAKE)
            metrics_quic(METRICS_QUIC_HANDSHAKE_FAILED_TIMEOUT);

        conn->state = QUICCONN_DEAD;
        return 0;
    }

    /* §10.1.2: hold a quiet connection open by asking the peer to acknowledge
     * something. Only in ACTIVE -- during the handshake there is always
     * something in flight, and loss recovery owns that case.
     *
     * The interval is measured from the last packet *received*, so an active
     * connection never gets one of these: any traffic at all pushes the
     * deadline out. */
    if (conn->state == QUICCONN_ACTIVE && conn->keepalive_us > 0 &&
        now_us >= conn->last_activity_us + conn->keepalive_us &&
        now_us >= conn->keepalive_next_us) {
        conn->keepalive_pending = 1;
        conn->keepalive_next_us = now_us + conn->keepalive_us;
        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
    }

    /* Repeat or abandon an outstanding path validation (§8.2.4). Abandoning is
     * not an error: the connection carries on where it was, which is exactly
     * what should happen when a spoofed address, or a NAT that closed again,
     * turns out not to answer. */
    if (conn->probe_active && !conn->probe_pending && now_us >= conn->probe_next_us) {
        if (conn->probe_attempts >= QUICCONN_PROBE_ATTEMPTS) {
            conn->probe_active = 0;
            metrics_quic(METRICS_QUIC_MIGRATION_REJECTED);
            log_info("quic: path validation abandoned after %u attempts\n",
                     conn->probe_attempts);
        }
        else {
            conn->probe_pending = 1;
            atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        }
    }

    /* A delayed acknowledgement that has come due (§13.2.1).
     *
     * quicconn_next_timeout already asks to be woken at this deadline, and the
     * endpoint's sweep only calls quicconn_send when want_write is set -- so
     * without this branch the wakeup arrived, found nothing to do, and the ACK
     * waited for an unrelated event to build a packet for it. On a busy
     * connection something always does, which is why this never showed; on a
     * quiet one under loss the peer is left retransmitting data we hold and
     * have simply not confirmed (docs/http3/08 §3x: nineteen ack-eliciting
     * packets, one acknowledgement, and a client that gave up).
     *
     * Only the flag is raised here: what to put in the packet, and whether the
     * ACK is due at all, stays quicack_should_send's decision at build time. */
    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        if (!quicack_should_send(&conn->ack[i], now_us)) continue;

        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        break;
    }

    const uint64_t timeout = quicloss_timeout(&conn->loss, now_us);
    if (timeout != 0 && now_us >= timeout) {
        quicframe_ref_t* lost = NULL;
        quic_enc_level_e level = QUIC_ENC_INITIAL;

        /* Returns 1 for a loss timer, 0 for a PTO -- and a PTO is the signal
         * that matters here: it means a whole round trip passed with nothing
         * acknowledged, which is what a path problem looks like before it
         * becomes packet loss. */
        if (!quicloss_on_timeout(&conn->loss, now_us, &lost, &level)) {
            metrics_quic(METRICS_QUIC_PTO_FIRED);

            QLOG(conn->qlog, "recovery", "loss_timer_expired",
                 "\"event_type\":\"pto\",\"packet_number_space\":\"%s\","
                 "\"pto_count\":%u,\"bytes_in_flight\":%llu",
                 __qlog_level(level), conn->loss.pto_count,
                 (unsigned long long)conn->cc.bytes_in_flight);

            /* §6.2.4 requires at least one ack-eliciting packet here, and two
             * is what the RFC suggests so that one loss does not cost another
             * whole PTO. The point is not the payload -- it is that the peer
             * acknowledges *something* newer, which is what lets the loss
             * detector finally declare the vanished packet lost and resend the
             * information it carried. */
            conn->pto_probes = 2;
            conn->pto_level = level;

            /* Repeated PTO after a raised PLPMTU is the RFC 8899 black-hole
             * signal: return to the safe base before retransmitting data. */
            if (level == QUIC_ENC_APP && conn->loss.pto_count >= 3 &&
                quicpmtud_on_blackhole(&conn->pmtud, now_us,
                                       quicloss_pto_us(&conn->loss, level))) {
                conn->cc.max_datagram_size = conn->pmtud.current;
                metrics_quic(METRICS_QUIC_PMTU_BLACKHOLES);
                metrics_quic_pmtu(conn->pmtud.current);
                QLOG(conn->qlog, "recovery", "mtu_updated",
                     "\"new\":%zu,\"ceiling\":%zu,\"trigger\":\"black_hole\"",
                     conn->pmtud.current, conn->pmtud.ceiling);
            }

            /* The five numbers that named the cause in §3g, at the moment they
             * are worth having: a stalled connection is diagnosed by what its
             * state says now, not by what happened. Cheap because a PTO is a
             * rare event by construction -- if it is not, that is the finding.
             *
             * Tagged with the original DCID, and that is not decoration: a
             * server under a multiconnect test interleaves these lines from
             * fifty connections, and without the tag they cannot be told apart
             * -- which is exactly the state the §3m residue was left in. */
            log_debug("quic: pto cid=%02x%02x%02x%02x level=%d count=%u "
                      "in_flight=%zu cwnd=%llu unsent=%llu srtt=%llu "
                      "amp=%llu validated=%d\n",
                      conn->odcid.data[0], conn->odcid.data[1],
                      conn->odcid.data[2], conn->odcid.data[3],
                      (int)level, conn->loss.pto_count,
                      conn->cc.bytes_in_flight,
                      (unsigned long long)conn->cc.cwnd,
                      (unsigned long long)quicconn_unsent_bytes(conn),
                      (unsigned long long)conn->loss.smoothed_rtt_us,
                      (unsigned long long)conn->amplification_budget,
                      conn->address_validated);

            /* §6.2.4: the probe should carry data, not just a PING. A PING only
             * asks the peer to acknowledge something so that loss detection can
             * finally act -- which costs a whole round trip, and during a
             * handshake where nothing is getting through there is no round trip
             * to spend. Queueing the outstanding bytes puts them in the probe
             * itself, and the probe is the one packet allowed past a full
             * congestion window (docs/http3/08 §3k). */
            if (!quicsendbuf_requeue_unacked(&conn->crypto_out[level]) &&
                level == QUIC_ENC_APP) {
                for (quicstream_t* s = conn->streams; s != NULL; s = s->next)
                    if (quicsendbuf_requeue_unacked(&s->send)) break;
            }
        }
        else
            __requeue_lost(conn, level, lost);

        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
    }

    if (conn->state == QUICCONN_ACTIVE) {
        const int pmtu_outcome = quicpmtud_on_timeout(&conn->pmtud, now_us);

        if (pmtu_outcome & QUICPMTUD_PROBE_LOST) {
            metrics_quic(METRICS_QUIC_PMTU_PROBES_LOST);
            QLOG(conn->qlog, "recovery", "mtu_probe_lost",
                 "\"current\":%zu,\"ceiling\":%zu,\"search_ended\":%s",
                 conn->pmtud.current, conn->pmtud.ceiling,
                 (pmtu_outcome & QUICPMTUD_CEILING_LOWERED) ? "true" : "false");
        }
        if (pmtu_outcome & QUICPMTUD_CEILING_LOWERED)
            metrics_quic(METRICS_QUIC_PMTU_SEARCH_CEILING_LOWERED);

        /* Same order as in the send path above, and for the same reason: the
         * tick runs per received datagram, not per timer. */
        if (quicpmtud_should_probe(&conn->pmtud, now_us) &&
            quicconn_unsent_bytes(conn) >= 4 * conn->pmtud.current)
            atomic_store_explicit(&conn->want_write, 1, memory_order_release);
    }

    return 1;
}

uint64_t quicconn_next_timeout(const quicconn_t* conn) {
    if (conn == NULL) return 0;

    if (conn->state == QUICCONN_CLOSING || conn->state == QUICCONN_DRAINING)
        return conn->close_deadline_us;

    uint64_t earliest = 0;

    if (conn->idle_timeout_us > 0)
        earliest = conn->last_activity_us + conn->idle_timeout_us;

    const uint64_t loss_timeout = quicloss_timeout(&conn->loss, 0);
    if (loss_timeout != 0 && (earliest == 0 || loss_timeout < earliest))
        earliest = loss_timeout;

    if (conn->pace_until_us != 0 &&
        (earliest == 0 || conn->pace_until_us < earliest))
        earliest = conn->pace_until_us;

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        const uint64_t ack_deadline = quicack_deadline(&conn->ack[i]);
        if (ack_deadline != 0 && (earliest == 0 || ack_deadline < earliest))
            earliest = ack_deadline;
    }

    const uint64_t pmtu_deadline = quicpmtud_deadline(&conn->pmtud);
    if (pmtu_deadline != 0 && (earliest == 0 || pmtu_deadline < earliest))
        earliest = pmtu_deadline;

    /* The keep-alive deadline, or the timer never fires: the endpoint arms its
     * timerfd from this function, and a connection with nothing else pending is
     * exactly the connection a keep-alive exists for. */
    if (conn->keepalive_us > 0 && conn->state == QUICCONN_ACTIVE) {
        uint64_t keepalive = conn->last_activity_us + conn->keepalive_us;
        if (keepalive < conn->keepalive_next_us) keepalive = conn->keepalive_next_us;
        if (earliest == 0 || keepalive < earliest) earliest = keepalive;
    }

    return earliest;
}

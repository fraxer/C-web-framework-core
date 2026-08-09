#define _GNU_SOURCE
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "metrics.h"
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
#define QUICCONN_MAX_PACKET QUIC_DEFAULT_UDP_PAYLOAD

/* Datagrams built per quicconn_send call. A cap rather than a loop to
 * exhaustion: one connection must not hold the worker while a large flight or
 * a large response goes out. Whatever is left keeps want_write raised. */
#define QUICCONN_SEND_ROUNDS 4

/* ---- Small helpers ---- */

static int __key_update_arm(quicconn_t* conn);
static void __cids_replenish(quicconn_t* conn);
static int __path_same(const quicpath_t* a, const quicpath_t* b);
static void __path_probe_succeed(quicconn_t* conn);

static quicconn_t* __conn_of(connection_t* connection) {
    /* Safe because conn is the first member of quicconn_t, which is also why
     * that placement is load-bearing rather than stylistic. */
    return (quicconn_t*)connection;
}

static void __touch(quicconn_t* conn, uint64_t now_us) {
    /* Only bytes *received* count as activity: a server talking to a peer that
     * has gone away must still time out, so our own sends cannot keep the
     * connection alive. */
    conn->last_activity_us = now_us;
}

static quicstream_t* __stream_find(quicconn_t* conn, uint64_t id) {
    for (quicstream_t* s = conn->streams; s != NULL; s = s->next)
        if (s->id == id) return s;

    return NULL;
}

/* Open a peer-initiated stream, and every stream of the same kind below it.
 *
 * §2.1: ids are a counter, and a peer may skip the ones it decided not to use.
 * Opening 12 without opening 0, 4 and 8 first would leave those ids permanently
 * unusable and the concurrency accounting wrong. */
static quicstream_t* __stream_open_peer(quicconn_t* conn, uint64_t id) {
    const uint64_t kind = id & 0x03;
    uint64_t* next = quic_stream_is_uni(id) ? &conn->next_peer_uni : &conn->next_peer_bidi;

    quicstream_t* result = NULL;

    while (*next <= id) {
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

            s->next = conn->streams;
            conn->streams = s;
            conn->stream_count++;
        }

        if (open_id == id) result = s;
    }

    return result != NULL ? result : __stream_find(conn, id);
}

quicstream_t* quicconn_stream_find(quicconn_t* conn, uint64_t id) {
    if (conn == NULL) return NULL;

    return __stream_find(conn, id);
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

size_t quicconn_write_room(const quicconn_t* conn) {
    const uint64_t unsent = quicconn_unsent_bytes(conn);
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

    s->next = conn->streams;
    conn->streams = s;
    conn->stream_count++;

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

    return 1;
}

static void __on_alert(void* ctx, uint8_t alert) {
    quicconn_t* conn = ctx;

    quicconn_close(conn, QUIC_CRYPTO_ERROR(alert), 0, quic_now_us());
}

static const quictls_ops_t __tls_ops = {
    .install_secret = __on_secret,
    .send_crypto = __on_crypto,
    .peer_params = __on_peer_params,
    .alert = __on_alert
};

/* ---- Frame handling ---- */

static int __on_crypto_frame(quicconn_t* conn, quic_enc_level_e level,
                             const quicframe_t* frame) {
    if (!quictls_recv_crypto(&conn->tls, level, frame->u.crypto.offset,
                             frame->u.crypto.data, (size_t)frame->u.crypto.len)) {
        quicconn_close(conn, QUIC_CRYPTO_BUFFER_EXCEEDED, 0, quic_now_us());
        return 0;
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

    quicframe_ref_t* lost = NULL;
    quicloss_on_ack(&conn->loss, level, &acked, delay, now_us, &lost);

    /* §6.5: the peer has read something we sent in the current key phase, so a
     * further update from it is no longer a way to make us derive key schedules
     * for free. */
    if (level == QUIC_ENC_APP && conn->key_update_unconfirmed &&
        quicrange_max(&acked) >= conn->key_update_tx_pn)
        conn->key_update_unconfirmed = 0;

    /* Put the lost frames' information back on the queues that produced it.
     * The frames themselves are rebuilt from current state, not replayed --
     * a retransmitted MAX_DATA must carry today's limit, not yesterday's. */
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
        /* Other control frames carry a limit and are not queued for
         * retransmission: the next packet carries the current value anyway,
         * which is both simpler and more correct than resending a stale one. */
    }

    quicframe_ref_free(lost);
    quicrange_free(&acked);

    atomic_store_explicit(&conn->want_write, 1, memory_order_release);

    return 1;
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
        const uint64_t limit = quic_stream_is_uni(id)
                               ? conn->local_params.initial_max_streams_uni
                               : conn->local_params.initial_max_streams_bidi;

        if (index >= limit) {
            quicconn_close(conn, QUIC_STREAM_LIMIT_ERROR, 0, now_us);
            return 0;
        }

        s = __stream_open_peer(conn, id);
        if (s == NULL) {
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

    const quicstream_err_t err =
        quicstream_on_data(s, frame->u.stream.offset, frame->u.stream.data,
                           (size_t)frame->u.stream.len, frame->u.stream.fin);

    if (err != QUICSTREAM_OK) {
        quicconn_close(conn, err, 0, now_us);
        return 0;
    }

    return 1;
}

static int __handle_frame(quicconn_t* conn, quic_enc_level_e level,
                          const quicframe_t* frame, uint64_t now_us) {
    /* §12.4: a frame in a packet number space that does not admit it is a
     * protocol violation -- a STREAM frame in an Initial packet, say. */
    if (!quicframe_allowed_in(frame->type, level)) {
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
        quicstream_t* s = __stream_find(conn, frame->u.reset_stream.id);
        if (s == NULL) return 1;

        metrics_quic(METRICS_QUIC_STREAMS_RESET_RECEIVED);

        const quicstream_err_t err =
            quicstream_on_reset(s, frame->u.reset_stream.error,
                                frame->u.reset_stream.final_size);
        if (err != QUICSTREAM_OK) {
            quicconn_close(conn, err, 0, now_us);
            return 0;
        }
        return 1;
    }

    case QUIC_FRAME_STOP_SENDING: {
        quicstream_t* s = __stream_find(conn, frame->u.stop_sending.id);
        if (s == NULL) return 1;

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
        quicstream_t* s = __stream_find(conn, frame->u.max_stream_data.id);
        if (s == NULL) return 1;

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

        /* §10.2.2: enter draining and send nothing further -- not even an
         * acknowledgement. Answering would keep the exchange alive after both
         * ends have finished with it. */
        conn->state = QUICCONN_DRAINING;
        conn->close_deadline_us = now_us + quicloss_pto_us(&conn->loss, level) * 3;
        return 1;

    case QUIC_FRAME_HANDSHAKE_DONE:
        /* Server-only frame; a client sending it is confused (§19.20). */
        quicconn_close(conn, QUIC_PROTOCOL_VIOLATION, 0, now_us);
        return 0;

    default:
        quicconn_close(conn, QUIC_FRAME_ENCODING_ERROR, 0, now_us);
        return 0;
    }
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
    quiccc_init(&conn->cc, QUICCONN_MAX_PACKET);

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

static int __process_packet(quicconn_t* conn, uint8_t* buf, size_t len,
                            const quicpkt_t* pkt, uint64_t now_us) {
    const quic_enc_level_e level = quicpkt_level(pkt->type);

    quickeys_t* keys = &conn->rx[level];
    if (!keys->valid) {
        /* Keys for this level do not exist yet -- a 1-RTT packet that overtook
         * the handshake, which is ordinary on a reordering path. Dropped rather
         * than buffered; the peer will retransmit. */
        return 1;
    }

    /* Header protection first: the packet number length and the key phase are
     * under it, and the AEAD needs the number to build its nonce. */
    size_t pn_len = 0;
    uint64_t truncated = 0;
    int key_phase = 0;

    if (!quichp_remove(keys, buf, len, pkt->pn_offset, &pn_len, &truncated, &key_phase))
        return 1;

    const uint64_t largest = conn->ack[level].any_received
                             ? conn->ack[level].largest : QUICPKT_NO_ACKED;
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

        if (quiccrypto_open_limit_reached(keys)) {
            metrics_quic(METRICS_QUIC_AEAD_LIMIT);
            quicconn_close(conn, QUIC_AEAD_LIMIT_REACHED, 0, now_us);
            return 0;
        }
        return 1;
    }

    /* A replayed packet is bit-identical to the original, so the AEAD cannot
     * tell them apart -- this check is the only thing that can. */
    if (quicack_is_duplicate(&conn->ack[level], pn)) return 1;

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
    const int newest = !conn->ack[level].any_received || pn > conn->ack[level].largest;

    quicack_on_received(&conn->ack[level], level, pn, ack_eliciting, now_us,
                        conn->local_params.max_ack_delay * 1000);

    if (level == QUIC_ENC_APP && non_probing && newest &&
        conn->recv_path != NULL && !__path_same(conn->recv_path, &conn->path))
        __path_probe_start(conn, conn->recv_path, now_us);

    if (ack_eliciting) atomic_store_explicit(&conn->want_write, 1, memory_order_release);

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

    while (quicpkt_next(copy, len, &off, QUIC_LOCAL_CID_LEN, &pkt, &st)) {
        if (!__process_packet(conn, copy + off - pkt.pkt_len, pkt.pkt_len, &pkt, now_us)) {
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
                quicconn_close(conn, QUIC_CRYPTO_ERROR(0x28), 0, now_us);
            return 0;
        }

        if (conn->tls.handshake_complete) {
            log_error("quic: handshake complete; peer streams_uni=%llu streams_bidi=%llu "
                      "max_data=%llu max_stream_data_uni=%llu\n",
                      (unsigned long long)conn->peer_params.initial_max_streams_uni,
                      (unsigned long long)conn->peer_params.initial_max_streams_bidi,
                      (unsigned long long)conn->peer_params.initial_max_data,
                      (unsigned long long)conn->peer_params.initial_max_stream_data_uni);

            metrics_quic(METRICS_QUIC_HANDSHAKE_COMPLETED);

            conn->state = QUICCONN_ACTIVE;

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

    return 1;
}

/* ---- Send path ---- */

/* Build one packet at `level` into `dst`, returning its length or 0. */
static size_t __build_packet(quicconn_t* conn, quic_enc_level_e level,
                             uint8_t* dst, size_t cap, uint64_t now_us,
                             int* out_ack_eliciting) {
    quickeys_t* keys = &conn->tx[level];
    if (!keys->valid) return 0;

    /* Leave room for the AEAD tag; everything below sizes against the payload. */
    if (cap < QUIC_AEAD_TAG_LEN + 32) return 0;

    uint8_t payload[QUICCONN_MAX_PACKET];
    size_t p = 0;
    int ack_eliciting = 0;
    quicframe_ref_t* refs = NULL;

    const size_t payload_cap =
        (cap - QUIC_AEAD_TAG_LEN > sizeof payload ? sizeof payload : cap - QUIC_AEAD_TAG_LEN)
        - 64;   /* header, conservatively */

    /* An ACK first: it is what unblocks the peer, and it is cheap. */
    if (quicack_should_send(&conn->ack[level], now_us)) {
        const size_t n = quicack_write(&conn->ack[level], payload + p, payload_cap - p,
                                       now_us,
                                       conn->peer_params.ack_delay_exponent);
        if (n > 0) {
            p += n;
            quicack_on_sent(&conn->ack[level]);
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
    if (quicsendbuf_pending(&conn->crypto_out[level]) && p + 16 < payload_cap) {
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
        }
    }

    /* Stream data, round-robin so one large response cannot starve the rest. */
    if (level == QUIC_ENC_APP) {
        for (quicstream_t* s = conn->streams; s != NULL && p + 32 < payload_cap;
             s = s->next) {
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
                f.u.reset_stream.final_size = s->send.write_off;

                const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
                if (n > 0) {
                    p += n;
                    ack_eliciting = 1;
                    s->send_reset_pending = 0;
                }
                continue;
            }

            if (!quicstream_wants_send(s)) continue;

            uint64_t offset = 0;
            const uint8_t* data = NULL;
            size_t dlen = 0;
            int fin = 0;

            /* Both windows apply, and so does the space left in the packet. */
            uint64_t allowed = quicflow_available(&s->send_flow);
            const uint64_t conn_allowed = quicflow_available(&conn->send_flow);
            if (conn_allowed < allowed) allowed = conn_allowed;

            size_t room = payload_cap - p - 24;
            if (allowed < room) room = (size_t)allowed;

            if (room == 0 && !(s->send.fin && !s->send.fin_sent)) {
                /* Only a closed window is counted, not a full packet: the
                 * second is the loop doing its job and would bury the first,
                 * which is a stall the peer has to end. */
                if (allowed == 0)
                    metrics_quic(conn_allowed == 0 ? METRICS_QUIC_FLOW_BLOCKED_CONN
                                                   : METRICS_QUIC_FLOW_BLOCKED_STREAM);
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

            quicsendbuf_mark_sent(&s->send, offset, dlen, fin);
            quicflow_consume(&s->send_flow, dlen);
            quicflow_consume(&conn->send_flow, dlen);

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

    if (p == 0) {
        quicframe_ref_free(refs);
        return 0;
    }

    /* An Initial packet must travel in a datagram of at least 1200 bytes
     * (§14.1), so short ones are padded. Padding also guarantees the header
     * protection sample exists. */
    const int needs_padding = (level == QUIC_ENC_INITIAL);

    const uint64_t pn = conn->loss.space[level].next_pn;
    const size_t pn_len = quicpkt_pn_length(pn, conn->loss.space[level].largest_acked);

    quiccid_t* dcid = conn->peer_cid_count > 0 ? &conn->peer_cids[0] : NULL;
    if (dcid == NULL) {
        quicframe_ref_free(refs);
        return 0;
    }

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
    hdr.payload_len = p + QUIC_AEAD_TAG_LEN;

    size_t pn_offset = 0;
    const size_t header_len = quicpkt_write_header(dst, cap, &hdr, &pn_offset);
    if (header_len == 0) {
        quicframe_ref_free(refs);
        return 0;
    }

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

    quicloss_on_sent(&conn->loss, level, pn, total, ack_eliciting, 1, refs, now_us);

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

    quicendpoint_send(conn->endpoint, datagram, total, &conn->probe_path);

    conn->probe_pending = 0;
    conn->probe_attempts++;
    conn->probe_next_us = now_us + quicloss_pto_us(&conn->loss, QUIC_ENC_APP);
}

int quicconn_send(quicconn_t* conn, uint64_t now_us) {
    if (conn == NULL) return 0;
    if (conn->state == QUICCONN_DRAINING || conn->state == QUICCONN_DEAD) return 1;

    if (conn->state == QUICCONN_CLOSING) {
        if (conn->close_packet_len > 0) {
            quicendpoint_send(conn->endpoint, conn->close_packet,
                              conn->close_packet_len, &conn->path);
        }
        atomic_store_explicit(&conn->want_write, 0, memory_order_release);
        return 1;
    }

    /* Ahead of the connection's own datagram: §8.2.2 will not have the answer
     * delayed, and the same urgency applies to the question. */
    if (conn->probe_active && conn->probe_pending)
        __path_probe_send(conn, now_us);

    uint8_t datagram[QUICCONN_MAX_PACKET];
    int sent_anything = 0;
    /* Whether the loop stopped with work still owed. Only "nothing left to
     * build" clears want_write; every other exit -- the round cap, the
     * congestion window, the anti-amplification budget -- means the rest of the
     * flight is still waiting and must be asked for again. */
    int more_pending = 0;

    for (int round = 0; round < QUICCONN_SEND_ROUNDS; round++) {
        size_t total = 0;

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
                break;
            }

            size_t room = sizeof datagram - total;
            if (!conn->address_validated) {
                const uint64_t budget = conn->amplification_budget > total
                                        ? conn->amplification_budget - total : 0;
                if (budget < room) room = (size_t)budget;
            }

            int eliciting = 0;
            const size_t n = __build_packet(conn, level, datagram + total, room,
                                            now_us, &eliciting);
            if (n == 0) continue;

            total += n;

            /* A short header has no length field, so nothing may follow it. */
            if (level == QUIC_ENC_APP) break;
        }

        if (total == 0) break;

        if (!conn->address_validated) {
            conn->amplification_budget = conn->amplification_budget > total
                                         ? conn->amplification_budget - total : 0;
        }

        if (quicendpoint_send(conn->endpoint, datagram, total, &conn->path) < 0)
            break;

        sent_anything = 1;

        if (quiccc_available(&conn->cc) < QUICCONN_MAX_PACKET) {
            more_pending = 1;
            break;
        }

        /* The last round produced a full datagram, so there may well be
         * another: a server flight carrying a certificate chain runs to six or
         * more, and clearing the flag here left the remainder waiting for the
         * peer to nudge us. */
        if (round + 1 == QUICCONN_SEND_ROUNDS) more_pending = 1;
    }

    if (!more_pending)
        atomic_store_explicit(&conn->want_write, 0, memory_order_release);

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

    quicstream_t* s = conn->streams;
    while (s != NULL) {
        quicstream_t* next = s->next;
        quicstream_free(s);
        s = next;
    }
    conn->streams = NULL;
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

    const uint64_t now = quic_now_us();
    conn->last_activity_us = now;

    /* §8.1: nothing may go back to an unvalidated address beyond three times
     * what came from it. The first Initial is at least 1200 bytes, so this
     * starts at 3600 -- enough for a certificate flight only if the chain is
     * short, which is why 07-integration.md tells operators to keep it so. */
    conn->amplification_budget = 0;

    /* The client's Source Connection ID is where our packets are addressed. */
    conn->peer_cids[0] = *peer_scid;
    conn->peer_cid_count = 1;

    /* Ours, which the client will use from its next packet onwards. Random so
     * that two connections of the same client cannot be linked by an observer
     * (§5.1). */
    conn->local_cids[0].cid.len = QUIC_LOCAL_CID_LEN;
    if (RAND_bytes(conn->local_cids[0].cid.data, QUIC_LOCAL_CID_LEN) != 1) {
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

    quiccc_init(&conn->cc, QUICCONN_MAX_PACKET);
    quicpacer_init(&conn->pacer, QUICCONN_MAX_PACKET, policy->pacing);
    quicloss_init(&conn->loss, &conn->cc, policy->ack_delay_ms * 1000);

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

    conn->idle_timeout_us = conn->local_params.max_idle_timeout * 1000;

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

    if (!quictls_init_server(&conn->tls, server->openssl->quic_ctx, &__tls_ops, conn,
                             &conn->local_params)) {
        quicconn_free(conn);
        return NULL;
    }

    /* The embedded connection_t, initialised in place: it has to live inside
     * this object rather than beside it, because the connection layer casts
     * between the two. The fd is the endpoint's shared socket -- kept for
     * diagnostics only, since nothing here ever reads or writes it directly. */
    const struct sockaddr_in* remote4 = (const struct sockaddr_in*)&path->remote;
    const in_addr_t remote_ip = path->remote.ss_family == AF_INET
                                ? remote4->sin_addr.s_addr : 0;
    const unsigned short remote_port = path->remote.ss_family == AF_INET
                                       ? ntohs(remote4->sin_port) : 0;

    /* The local address matters: httpparser_select_server picks the virtual
     * server by (ip, port), so a connection that reports 0/0 matches no vhost
     * and every request is a 421. TCP gets these from accept(); QUIC has to
     * take them from the endpoint it arrived on. */
    if (!connection_s_init(&conn->conn, quicendpoint_listener(endpoint),
                           quicendpoint_fd(endpoint),
                           quicendpoint_ip(endpoint), quicendpoint_port(endpoint),
                           remote_ip, remote_port, NULL, 0)) {
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

void quicconn_close(quicconn_t* conn, uint64_t error_code, int is_app,
                    uint64_t now_us) {
    if (conn == NULL) return;
    if (conn->state == QUICCONN_CLOSING || conn->state == QUICCONN_DRAINING ||
        conn->state == QUICCONN_DEAD) return;

    log_error("quic: closing, %s error 0x%llx\n",
              is_app ? "application" : "transport", (unsigned long long)error_code);

    metrics_quic(METRICS_QUIC_CLOSED_LOCAL);

    conn->state = QUICCONN_CLOSING;
    conn->error_code = error_code;
    conn->error_is_app = is_app;
    conn->close_deadline_us = now_us + quicloss_pto_us(&conn->loss, QUIC_ENC_APP) * 3;

    /* Build the close packet once and keep it: §10.2.1 has it re-sent in
     * answer to anything that arrives during the closing period, and rebuilding
     * it each time would need state we are about to stop maintaining. */
    const quic_enc_level_e level = conn->tx[QUIC_ENC_APP].valid
                                   ? QUIC_ENC_APP : QUIC_ENC_INITIAL;
    if (!conn->tx[level].valid) return;

    uint8_t payload[64];
    quicframe_t f;
    memset(&f, 0, sizeof f);
    /* An application error code cannot be sent before the handshake keys
     * exist, so it becomes APPLICATION_ERROR at the transport level (§10.2.3). */
    f.type = (is_app && level == QUIC_ENC_APP)
             ? QUIC_FRAME_CONNECTION_CLOSE_APP : QUIC_FRAME_CONNECTION_CLOSE;
    f.u.close.error = (is_app && level != QUIC_ENC_APP) ? QUIC_APPLICATION_ERROR
                                                        : error_code;

    const size_t plen = quicframe_write(payload, sizeof payload, &f);
    if (plen == 0) return;

    quiccid_t* dcid = conn->peer_cid_count > 0 ? &conn->peer_cids[0] : NULL;
    if (dcid == NULL) return;

    const uint64_t pn = conn->loss.space[level].next_pn;
    const size_t pn_len = quicpkt_pn_length(pn, conn->loss.space[level].largest_acked);

    quicpkt_hdr_out_t hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = level == QUIC_ENC_APP ? QUIC_PKT_SHORT : QUIC_PKT_INITIAL;
    hdr.version = QUIC_VERSION_1;
    hdr.dcid = dcid;
    hdr.scid = &conn->local_cids[0].cid;
    hdr.pn = pn;
    hdr.pn_len = pn_len;
    hdr.payload_len = plen + QUIC_AEAD_TAG_LEN;

    size_t pn_offset = 0;
    const size_t header_len = quicpkt_write_header(conn->close_packet,
                                                   sizeof conn->close_packet,
                                                   &hdr, &pn_offset);
    if (header_len == 0) return;

    size_t sealed = 0;
    if (!quiccrypto_seal(&conn->tx[level], pn, conn->close_packet, header_len,
                         payload, plen, conn->close_packet + header_len, &sealed))
        return;

    size_t total = header_len + sealed;

    /* Header protection needs a sample four bytes past the packet number, so a
     * short packet has to be padded to reach it. */
    if (total < pn_offset + QUICHP_MIN_AFTER_PN &&
        pn_offset + QUICHP_MIN_AFTER_PN <= sizeof conn->close_packet) {
        memset(conn->close_packet + total, 0, pn_offset + QUICHP_MIN_AFTER_PN - total);
        total = pn_offset + QUICHP_MIN_AFTER_PN;
    }

    if (!quichp_apply(&conn->tx[level], conn->close_packet, total, pn_offset, pn_len))
        return;

    conn->close_packet_len = total;
    conn->loss.space[level].next_pn++;
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

        /* Timing out mid-handshake is a different failure: the peer never got
         * far enough to say anything, which is what a blocked UDP path and a
         * rejected certificate both look like from here. */
        if (conn->state == QUICCONN_HANDSHAKE)
            metrics_quic(METRICS_QUIC_HANDSHAKE_FAILED_TIMEOUT);

        conn->state = QUICCONN_DEAD;
        return 0;
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

    const uint64_t timeout = quicloss_timeout(&conn->loss, now_us);
    if (timeout != 0 && now_us >= timeout) {
        quicframe_ref_t* lost = NULL;
        quic_enc_level_e level = QUIC_ENC_INITIAL;

        /* Returns 1 for a loss timer, 0 for a PTO -- and a PTO is the signal
         * that matters here: it means a whole round trip passed with nothing
         * acknowledged, which is what a path problem looks like before it
         * becomes packet loss. */
        if (!quicloss_on_timeout(&conn->loss, now_us, &lost, &level))
            metrics_quic(METRICS_QUIC_PTO_FIRED);
        else {
            for (quicframe_ref_t* ref = lost; ref != NULL; ref = ref->next) {
                if (ref->type == QUIC_FRAME_CRYPTO)
                    quicsendbuf_lost(&conn->crypto_out[level], ref->offset,
                                     (size_t)ref->len, 0);
                else if (ref->type >= QUIC_FRAME_STREAM &&
                         ref->type < QUIC_FRAME_STREAM + 8) {
                    quicstream_t* s = __stream_find(conn, ref->stream_id);
                    if (s != NULL)
                        quicsendbuf_lost(&s->send, ref->offset, (size_t)ref->len,
                                         ref->fin);
                }
            }
            quicframe_ref_free(lost);
        }

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

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        const uint64_t ack_deadline = quicack_deadline(&conn->ack[i]);
        if (ack_deadline != 0 && (earliest == 0 || ack_deadline < earliest))
            earliest = ack_deadline;
    }

    return earliest;
}

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

/* §8.1: three times what the peer has sent, until its address is validated. */
#define QUICCONN_AMPLIFICATION_FACTOR 3

/* Largest packet we build. Below the path MTU with room to spare -- phase 9
 * adds discovery; until then a conservative fixed size beats a datagram that
 * is silently dropped by a tunnel. */
#define QUICCONN_MAX_PACKET QUIC_DEFAULT_UDP_PAYLOAD

/* ---- Small helpers ---- */

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
        /* Control frames carrying a limit are not queued for retransmission:
         * the next packet carries the current value anyway, which is both
         * simpler and more correct than resending a stale one. */
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

    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        /* Phase 9 retires the id for real, after 3xPTO. Accepting it silently
         * is correct in the meantime: we simply keep using what we have. */
        return 1;

    case QUIC_FRAME_PATH_CHALLENGE:
        /* Must be answered on the path it arrived on (§8.2). Path validation
         * proper -- probing a new address before migrating to it -- is phase 9;
         * answering a challenge costs nothing and is required regardless. */
        atomic_store_explicit(&conn->want_write, 1, memory_order_release);
        return 1;

    case QUIC_FRAME_PATH_RESPONSE:
        return 1;

    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
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

    (void)key_phase;   /* key update is phase 9 */

    const uint64_t largest = conn->ack[level].any_received
                             ? conn->ack[level].largest : QUICPKT_NO_ACKED;
    const uint64_t pn = quicpkt_decode_pn(
        largest == QUICPKT_NO_ACKED ? 0 : largest, truncated, pn_len);

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
        if (quiccrypto_open_limit_reached(keys)) {
            quicconn_close(conn, QUIC_AEAD_LIMIT_REACHED, 0, now_us);
            return 0;
        }
        return 1;
    }

    /* A replayed packet is bit-identical to the original, so the AEAD cannot
     * tell them apart -- this check is the only thing that can. */
    if (quicack_is_duplicate(&conn->ack[level], pn)) return 1;

    /* §12.4: a packet with no frames at all is a protocol violation. */
    if (plain_len == 0) {
        quicconn_close(conn, QUIC_PROTOCOL_VIOLATION, 0, now_us);
        return 0;
    }

    int ack_eliciting = 0;
    size_t off = 0;
    quicframe_t frame;
    quicframe_status_e st;

    while ((st = quicframe_next(plain, plain_len, &off, &frame)) == QUICFRAME_OK) {
        if (quicframe_is_ack_eliciting(frame.type)) ack_eliciting = 1;

        if (!__handle_frame(conn, level, &frame, now_us)) return 0;
    }

    if (st != QUICFRAME_DONE && st != QUICFRAME_OK) {
        quicconn_close(conn, QUIC_FRAME_ENCODING_ERROR, 0, now_us);
        return 0;
    }

    quicack_on_received(&conn->ack[level], level, pn, ack_eliciting, now_us,
                        conn->local_params.max_ack_delay * 1000);

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
        conn->amplification_budget += (uint64_t)len * QUICCONN_AMPLIFICATION_FACTOR;

    (void)path;   /* migration is phase 9; the path is recorded at accept */

    /* A datagram may carry several packets (§12.2). The buffer is copied
     * because header protection and decryption work in place. */
    uint8_t copy[2048];
    if (len > sizeof copy) return 1;
    memcpy(copy, datagram, len);

    size_t off = 0;
    quicpkt_t pkt;
    quicpkt_status_e st;

    while (quicpkt_next(copy, len, &off, QUIC_LOCAL_CID_LEN, &pkt, &st)) {
        if (!__process_packet(conn, copy + off - pkt.pkt_len, pkt.pkt_len, &pkt, now_us))
            return 0;

        if (conn->state == QUICCONN_DRAINING) break;
    }

    /* Drive the handshake with whatever CRYPTO arrived. */
    if (conn->state == QUICCONN_HANDSHAKE) {
        if (!quictls_advance(&conn->tls)) {
            if (conn->state != QUICCONN_CLOSING)
                quicconn_close(conn, QUIC_CRYPTO_ERROR(0x28), 0, now_us);
            return 0;
        }

        if (conn->tls.handshake_complete) {
            conn->state = QUICCONN_ACTIVE;
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

            if (room == 0 && !(s->send.fin && !s->send.fin_sent)) continue;

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

    uint8_t datagram[QUICCONN_MAX_PACKET];
    int sent_anything = 0;

    for (int round = 0; round < 4; round++) {
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
                total >= conn->amplification_budget) break;

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

        if (quiccc_available(&conn->cc) < QUICCONN_MAX_PACKET) break;
    }

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
                            const quicpath_t* path, server_t* server) {
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

    quiccc_init(&conn->cc, QUICCONN_MAX_PACKET);
    quicpacer_init(&conn->pacer, QUICCONN_MAX_PACKET, 1);
    quicloss_init(&conn->loss, &conn->cc, 25000);

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        quicack_init(&conn->ack[i]);
        quicsendbuf_init(&conn->crypto_out[i]);
    }

    /* Our transport parameters. original_destination_connection_id and
     * initial_source_connection_id are mandatory for a server (§7.3): the
     * client checks them against the ids it actually saw, and that is what
     * binds this handshake to this connection. */
    quictp_defaults(&conn->local_params);
    conn->local_params.max_idle_timeout = 30000;
    conn->local_params.max_udp_payload_size = QUICCONN_MAX_PACKET;
    conn->local_params.initial_max_data = 1048576;
    conn->local_params.initial_max_stream_data_bidi_remote = 262144;
    conn->local_params.initial_max_stream_data_uni = 262144;
    conn->local_params.initial_max_streams_bidi = 100;
    conn->local_params.initial_max_streams_uni = 8;
    conn->local_params.active_connection_id_limit = 4;
    conn->local_params.has_original_dcid = 1;
    conn->local_params.original_dcid = *odcid;
    conn->local_params.has_initial_scid = 1;
    conn->local_params.initial_scid = conn->local_cids[0].cid;

    conn->idle_timeout_us = conn->local_params.max_idle_timeout * 1000;

    quicflow_init_recv(&conn->recv_flow, conn->local_params.initial_max_data,
                       conn->local_params.initial_max_data * 16);
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
        conn->state = QUICCONN_DEAD;
        return 0;
    }

    const uint64_t timeout = quicloss_timeout(&conn->loss, now_us);
    if (timeout != 0 && now_us >= timeout) {
        quicframe_ref_t* lost = NULL;
        quic_enc_level_e level = QUIC_ENC_INITIAL;

        if (quicloss_on_timeout(&conn->loss, now_us, &lost, &level)) {
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

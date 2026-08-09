#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "quicclient.h"
#include "quicframe.h"
#include "quichp.h"
#include "quicpacket.h"
#include "quictime.h"

#define CLIENT_MAX_PACKET 1400

static void __log(quicclient_t* c, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void __log(quicclient_t* c, const char* fmt, ...) {
    if (!c->verbose) return;

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/* ---- TLS bridge ---- */

static int __on_secret(void* ctx, quic_enc_level_e level, quictls_dir_e dir,
                       quic_aead_e suite, const uint8_t* secret, size_t len) {
    quicclient_t* c = ctx;

    quickeys_t* keys = dir == QUICTLS_DIR_READ ? &c->rx[level] : &c->tx[level];
    if (!quickeys_install(keys, suite, secret, len)) return 0;

    __log(c, "  [client] keys installed: level %d %s\n",
          (int)level, dir == QUICTLS_DIR_READ ? "read" : "write");

    return 1;
}

static int __on_crypto(void* ctx, quic_enc_level_e level,
                       const uint8_t* data, size_t len) {
    quicclient_t* c = ctx;

    return quicsendbuf_write(&c->crypto_out[level], data, len);
}

static int __on_params(void* ctx, const quictp_t* params) {
    quicclient_t* c = ctx;

    /* Every parameter the server takes from main.env (docs/http3/07 §1.2).
     * Printed in full because this is the only place they are observable: they
     * ride inside the encrypted handshake, so a key that never reached the wire
     * looks exactly like a key that was never read. */
    __log(c, "  [client] server transport parameters:\n"
             "  [client]   max_idle_timeout          %llu ms\n"
             "  [client]   max_udp_payload_size      %llu\n"
             "  [client]   initial_max_data          %llu\n"
             "  [client]   initial_max_stream_data   %llu bidi_remote / %llu uni\n"
             "  [client]   initial_max_streams       %llu bidi / %llu uni\n"
             "  [client]   active_connection_id_limit %llu\n"
             "  [client]   max_ack_delay             %llu ms\n",
          (unsigned long long)params->max_idle_timeout,
          (unsigned long long)params->max_udp_payload_size,
          (unsigned long long)params->initial_max_data,
          (unsigned long long)params->initial_max_stream_data_bidi_remote,
          (unsigned long long)params->initial_max_stream_data_uni,
          (unsigned long long)params->initial_max_streams_bidi,
          (unsigned long long)params->initial_max_streams_uni,
          (unsigned long long)params->active_connection_id_limit,
          (unsigned long long)params->max_ack_delay);

    return 1;
}

static void __on_alert(void* ctx, uint8_t alert) {
    (void)ctx;

    /* Always printed, whatever the verbosity: an alert is the reason a
     * handshake failed, and hiding it is hiding the answer. */
    printf("  [client] TLS alert %u\n", alert);
}

static const quictls_ops_t __ops = {
    .install_secret = __on_secret,
    .send_crypto = __on_crypto,
    .peer_params = __on_params,
    .alert = __on_alert
};

/* ---- Packet building ---- */

/* Build one packet at `level`, carrying an ACK if one is owed and as much
 * CRYPTO as fits. Returns its length. */
/* ---- Streams ---- */

static clientstream_t* __stream_get(quicclient_t* c, uint64_t id, int create) {
    for (size_t i = 0; i < CLIENT_MAX_STREAMS; i++)
        if (c->streams[i].used && c->streams[i].id == id) return &c->streams[i];

    if (!create) return NULL;

    for (size_t i = 0; i < CLIENT_MAX_STREAMS; i++) {
        clientstream_t* s = &c->streams[i];
        if (s->used) continue;

        s->used = 1;
        s->id = id;
        s->fin_queued = 0;
        s->in_fin = 0;
        quicsendbuf_init(&s->out);
        /* The window we advertised, which is what bounds what the peer may put
         * in here (quicclient_connect). */
        quicrecvbuf_init(&s->in, 32 * 1024 * 1024);

        return s;
    }

    return NULL;
}

int quicclient_stream_write(quicclient_t* client, uint64_t id,
                            const uint8_t* data, size_t len, int fin) {
    if (client == NULL) return 0;

    clientstream_t* s = __stream_get(client, id, 1);
    if (s == NULL) return 0;

    if (len > 0 && !quicsendbuf_write(&s->out, data, len)) return 0;
    if (fin) {
        quicsendbuf_finish(&s->out);
        s->fin_queued = 1;
    }

    return 1;
}

size_t quicclient_stream_readable(quicclient_t* client, uint64_t id) {
    clientstream_t* s = __stream_get(client, id, 0);

    return s == NULL ? 0 : quicrecvbuf_readable(&s->in);
}

size_t quicclient_stream_read(quicclient_t* client, uint64_t id,
                              uint8_t* dst, size_t cap) {
    clientstream_t* s = __stream_get(client, id, 0);

    return s == NULL ? 0 : quicrecvbuf_read(&s->in, dst, cap);
}

int quicclient_use_cid(quicclient_t* client, size_t index) {
    if (client == NULL || index >= client->server_cid_count) return 0;

    client->dcid = client->server_cids[index].cid;

    return 1;
}

int quicclient_retire_cid(quicclient_t* client, uint64_t seq) {
    if (client == NULL) return 0;

    client->retire_seq = seq;
    client->retire_queued = 1;

    return 1;
}

int quicclient_key_update(quicclient_t* client) {
    if (client == NULL) return 0;
    if (!client->tx[QUIC_ENC_APP].valid || !client->rx[QUIC_ENC_APP].valid) return 0;

    /* The generation we are leaving is retained: the server is still sending in
     * it until it sees a packet of ours in the new one. */
    quickeys_free(&client->rx_prev);
    client->rx_prev = client->rx[QUIC_ENC_APP];
    memset(&client->rx[QUIC_ENC_APP], 0, sizeof client->rx[QUIC_ENC_APP]);

    if (!quickeys_next(&client->rx[QUIC_ENC_APP], &client->rx_prev)) return 0;
    if (!quickeys_next(&client->tx[QUIC_ENC_APP], &client->tx[QUIC_ENC_APP])) return 0;

    client->key_phase = !client->key_phase;
    client->key_update_done = 1;

    __log(client, "  [client] key update -> phase %d\n", client->key_phase);

    return 1;
}

int quicclient_path_challenge(quicclient_t* client) {
    if (client == NULL || !client->tx[QUIC_ENC_APP].valid) return 0;
    if (client->path_challenge_queued || client->path_challenge_sent) return 0;

    if (RAND_bytes(client->path_challenge_data,
                   (int)sizeof client->path_challenge_data) != 1)
        return 0;

    client->path_challenge_queued = 1;

    return 1;
}

int quicclient_stream_fin(quicclient_t* client, uint64_t id) {
    clientstream_t* s = __stream_get(client, id, 0);

    return s != NULL && s->in_fin;
}

static size_t __build(quicclient_t* c, quic_enc_level_e level,
                      uint8_t* dst, size_t cap, int pad_to_minimum) {
    quickeys_t* keys = &c->tx[level];
    if (!keys->valid) return 0;

    uint8_t payload[CLIENT_MAX_PACKET];
    size_t p = 0;

    /* Acknowledge what has arrived at this level. The server's loss detection
     * depends on it, and without it the handshake stalls into retransmissions. */
    if (c->ack_pending[level] && !quicrange_empty(&c->received[level])) {
        quicack_block_t blocks[8];
        size_t count = quicrange_count(&c->received[level]);
        if (count > 8) count = 8;

        for (size_t i = 0; i < count; i++) {
            quicrange_span_t span;
            quicrange_at_desc(&c->received[level], i, &span);
            blocks[i].largest = span.end;
            blocks[i].smallest = span.start;
        }

        const size_t n = quicframe_write_ack(payload + p, sizeof payload - p,
                                             blocks, count, 0, NULL);
        if (n > 0) {
            p += n;
            c->ack_pending[level] = 0;
        }
    }

    if (level == QUIC_ENC_APP && c->retire_queued) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_RETIRE_CONNECTION_ID;
        f.u.retire_cid.seq = c->retire_seq;

        const size_t n = quicframe_write(payload + p, sizeof payload - p, &f);
        if (n > 0) {
            p += n;
            c->retire_queued = 0;
            __log(c, "  [client] -> RETIRE_CONNECTION_ID seq %llu\n",
                  (unsigned long long)c->retire_seq);
        }
    }

    /* A queued PATH_CHALLENGE, in the application space only: §12.4 does not
     * permit it at any earlier level, and the server would be right to close
     * the connection for one that arrived there. */
    if (level == QUIC_ENC_APP && c->path_challenge_queued) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_PATH_CHALLENGE;
        memcpy(f.u.path.data, c->path_challenge_data, sizeof f.u.path.data);

        const size_t n = quicframe_write(payload + p, sizeof payload - p, &f);
        if (n > 0) {
            p += n;
            c->path_challenge_queued = 0;
            c->path_challenge_sent = 1;
            __log(c, "  [client] -> PATH_CHALLENGE\n");
        }
    }

    if (quicsendbuf_pending(&c->crypto_out[level])) {
        uint64_t offset = 0;
        const uint8_t* data = NULL;
        size_t dlen = 0;
        int fin = 0;

        /* Leave room for the header, the packet number and the tag. */
        const size_t room = sizeof payload - p - 96;

        if (quicsendbuf_next(&c->crypto_out[level], room, &offset, &data, &dlen, &fin)
            && dlen > 0) {
            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_CRYPTO;
            f.u.crypto.offset = offset;
            f.u.crypto.len = dlen;
            f.u.crypto.data = data;

            const size_t n = quicframe_write(payload + p, sizeof payload - p, &f);
            if (n > 0) {
                p += n;
                quicsendbuf_mark_sent(&c->crypto_out[level], offset, dlen, 0);
            }
        }
    }

    /* Stream data, once the handshake keys exist. One frame per stream per
     * packet is enough for a test whose whole exchange is a few kilobytes. */
    if (level == QUIC_ENC_APP) {
        for (size_t i = 0; i < CLIENT_MAX_STREAMS && p + 64 < sizeof payload; i++) {
            clientstream_t* st = &c->streams[i];
            if (!st->used || !quicsendbuf_pending(&st->out)) continue;

            uint64_t offset = 0;
            const uint8_t* data = NULL;
            size_t dlen = 0;
            int fin = 0;

            const size_t room = sizeof payload - p - 96;
            if (!quicsendbuf_next(&st->out, room, &offset, &data, &dlen, &fin)) continue;

            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_STREAM | QUIC_STREAM_FLAG_LEN |
                     (offset > 0 ? QUIC_STREAM_FLAG_OFF : 0) |
                     (fin ? QUIC_STREAM_FLAG_FIN : 0);
            f.u.stream.id = st->id;
            f.u.stream.offset = offset;
            f.u.stream.len = dlen;
            f.u.stream.data = data;

            const size_t n = quicframe_write(payload + p, sizeof payload - p, &f);
            if (n == 0) continue;

            p += n;
            quicsendbuf_mark_sent(&st->out, offset, dlen, fin);

            __log(c, "  [client] -> STREAM %llu, %zu bytes%s\n",
                  (unsigned long long)st->id, dlen, fin ? " FIN" : "");
        }
    }

    if (p == 0) return 0;

    const uint64_t pn = c->next_pn[level]++;
    const size_t pn_len = 4;

    quicpkt_hdr_out_t hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = level == QUIC_ENC_INITIAL ? QUIC_PKT_INITIAL
             : level == QUIC_ENC_HANDSHAKE ? QUIC_PKT_HANDSHAKE
             : QUIC_PKT_SHORT;
    hdr.version = QUIC_VERSION_1;
    hdr.dcid = c->dcid.len > 0 ? &c->dcid : &c->odcid;
    hdr.scid = &c->scid;
    hdr.pn = pn;
    hdr.pn_len = pn_len;
    hdr.key_phase = c->key_phase;   /* ignored on long headers */

    /* An Initial that will be padded has to declare the padding in its Length,
     * or the server reads the padding as part of the ciphertext. So the padding
     * goes into the payload, before sealing. */
    if (pad_to_minimum && level == QUIC_ENC_INITIAL) {
        const size_t header_estimate = 7 + c->odcid.len + c->scid.len + 2 + pn_len;
        const size_t want = QUIC_MIN_INITIAL_DATAGRAM - header_estimate - QUIC_AEAD_TAG_LEN;
        if (want > p && want < sizeof payload) {
            memset(payload + p, 0, want - p);
            p = want;
        }
    }

    hdr.payload_len = p + QUIC_AEAD_TAG_LEN;

    size_t pn_offset = 0;
    const size_t header_len = quicpkt_write_header(dst, cap, &hdr, &pn_offset);
    if (header_len == 0) return 0;

    size_t sealed = 0;
    if (!quiccrypto_seal(keys, pn, dst, header_len, payload, p,
                         dst + header_len, &sealed))
        return 0;

    const size_t total = header_len + sealed;

    if (!quichp_apply(keys, dst, total, pn_offset, pn_len)) return 0;

    __log(c, "  [client] -> level %d, pn %llu, %zu bytes\n",
          (int)level, (unsigned long long)pn, total);

    return total;
}

static int __flush(quicclient_t* c) {
    uint8_t datagram[CLIENT_MAX_PACKET];
    size_t total = 0;

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        if (i == QUIC_ENC_EARLY) continue;

        const int pad = (i == QUIC_ENC_INITIAL && !c->got_server_handshake);
        const size_t n = __build(c, (quic_enc_level_e)i, datagram + total,
                                 sizeof datagram - total, pad);
        if (n == 0) continue;

        total += n;

        if (i == QUIC_ENC_APP) break;   /* a short header ends the datagram */
    }

    if (total == 0) return 1;

    if (sendto(c->fd, datagram, total, 0,
               (struct sockaddr*)&c->server, sizeof c->server) < 0) {
        printf("  [client] sendto failed: %s\n", strerror(errno));
        return 0;
    }

    return 1;
}

/* ---- Receive ---- */

static int __handle_frames(quicclient_t* c, quic_enc_level_e level,
                           const uint8_t* payload, size_t len,
                           int* out_ack_eliciting) {
    size_t off = 0;
    quicframe_t f;
    quicframe_status_e st;

    while ((st = quicframe_next(payload, len, &off, &f)) == QUICFRAME_OK) {
        if (quicframe_is_ack_eliciting(f.type)) *out_ack_eliciting = 1;

        if (f.type >= QUIC_FRAME_STREAM && f.type < QUIC_FRAME_STREAM + 8) {
            clientstream_t* s = __stream_get(c, f.u.stream.id, 1);
            if (s == NULL) return 0;

            if (quicrecvbuf_insert(&s->in, f.u.stream.offset, f.u.stream.data,
                                   (size_t)f.u.stream.len, f.u.stream.fin) != QUICRECVBUF_OK)
                return 0;

            if (f.u.stream.fin) s->in_fin = 1;

            __log(c, "  [client] <- STREAM %llu, %llu bytes at %llu%s\n",
                  (unsigned long long)f.u.stream.id,
                  (unsigned long long)f.u.stream.len,
                  (unsigned long long)f.u.stream.offset,
                  f.u.stream.fin ? " FIN" : "");
            continue;
        }

        switch (f.type) {
        case QUIC_FRAME_CRYPTO:
            if (!quictls_recv_crypto(&c->tls, level, f.u.crypto.offset,
                                     f.u.crypto.data, (size_t)f.u.crypto.len))
                return 0;
            __log(c, "  [client] <- CRYPTO %llu bytes at level %d\n",
                  (unsigned long long)f.u.crypto.len, (int)level);
            break;

        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_ECN:
            __log(c, "  [client] <- ACK (largest %llu)\n",
                  (unsigned long long)f.u.ack.largest);
            break;

        case QUIC_FRAME_RESET_STREAM:
            printf("  [client] <- RESET_STREAM %llu, error 0x%llx\n",
                   (unsigned long long)f.u.reset_stream.id,
                   (unsigned long long)f.u.reset_stream.error);
            break;

        case QUIC_FRAME_STOP_SENDING:
            __log(c, "  [client] <- STOP_SENDING %llu, error 0x%llx\n",
                  (unsigned long long)f.u.stop_sending.id,
                  (unsigned long long)f.u.stop_sending.error);
            break;

        case QUIC_FRAME_NEW_CONNECTION_ID:
            if (c->server_cid_count <
                sizeof c->server_cids / sizeof c->server_cids[0]) {
                const size_t i = c->server_cid_count++;
                c->server_cids[i].seq = f.u.new_cid.seq;
                c->server_cids[i].cid = f.u.new_cid.cid;
                memcpy(c->server_cids[i].token, f.u.new_cid.token, 16);
            }

            __log(c, "  [client] <- NEW_CONNECTION_ID seq %llu, %u bytes\n",
                  (unsigned long long)f.u.new_cid.seq, (unsigned)f.u.new_cid.cid.len);
            break;

        case QUIC_FRAME_HANDSHAKE_DONE:
            c->handshake_done_received = 1;
            __log(c, "  [client] <- HANDSHAKE_DONE\n");
            break;

        case QUIC_FRAME_PATH_RESPONSE:
            /* memcmp, not "we got one": §8.2.3 validates the path only on the
             * data it sent, so an echo of the wrong bytes is a failure that
             * would otherwise read as a success. */
            c->path_response_received = 1;
            c->path_response_matched =
                memcmp(f.u.path.data, c->path_challenge_data,
                       sizeof c->path_challenge_data) == 0;

            __log(c, "  [client] <- PATH_RESPONSE, data %s\n",
                  c->path_response_matched ? "matches the challenge" : "DOES NOT MATCH");
            break;

        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_APP:
            c->close_received = 1;
            c->close_error = f.u.close.error;
            printf("  [client] <- CONNECTION_CLOSE, error 0x%llx%s%.*s\n",
                   (unsigned long long)f.u.close.error,
                   f.u.close.reason_len > 0 ? ": " : "",
                   (int)f.u.close.reason_len,
                   f.u.close.reason != NULL ? f.u.close.reason : "");
            return 0;

        default:
            break;
        }
    }

    return st == QUICFRAME_DONE || st == QUICFRAME_OK;
}

static int __recv_datagram(quicclient_t* c, uint8_t* buf, size_t len) {
    size_t off = 0;
    quicpkt_t pkt;
    quicpkt_status_e st;

    while (quicpkt_next(buf, len, &off, QUIC_LOCAL_CID_LEN, &pkt, &st)) {
        uint8_t* start = buf + off - pkt.pkt_len;
        const quic_enc_level_e level = quicpkt_level(pkt.type);

        /* The server's first Initial tells us the connection id it wants us to
         * use from now on -- until then we address it by the random one we
         * invented, which is also what its Initial keys came from. */
        if (level == QUIC_ENC_INITIAL && !c->got_server_initial) {
            c->dcid = pkt.scid;
            c->got_server_initial = 1;
            __log(c, "  [client] server chose a connection id of %u bytes\n",
                  (unsigned)pkt.scid.len);
        }

        if (level == QUIC_ENC_HANDSHAKE) c->got_server_handshake = 1;

        quickeys_t* keys = &c->rx[level];
        if (!keys->valid) {
            __log(c, "  [client] no keys for level %d yet, dropping\n", (int)level);
            continue;
        }

        size_t pn_len = 0;
        uint64_t truncated = 0;
        int key_phase = 0;

        if (!quichp_remove(keys, start, pkt.pkt_len, pkt.pn_offset,
                           &pn_len, &truncated, &key_phase))
            continue;

        /* We are the side that initiates, so a differing phase means only one
         * thing: the server has not caught up yet and is still writing in the
         * generation before ours. Header protection is unaffected either way --
         * §5.4 keeps that key across updates -- so the bit is readable with the
         * current keys even when the payload is not. */
        int in_new_phase = 1;

        if (level == QUIC_ENC_APP && key_phase != c->key_phase) {
            if (!c->rx_prev.valid) continue;
            keys = &c->rx_prev;
            in_new_phase = 0;
        }

        const uint64_t largest = quicrange_empty(&c->received[level])
                                 ? 0 : quicrange_max(&c->received[level]);
        const uint64_t pn = quicpkt_decode_pn(largest, truncated, pn_len);

        const size_t header_len = pkt.pn_offset + pn_len;
        const size_t body_len = pkt.pkt_len - header_len;

        uint8_t plain[CLIENT_MAX_PACKET];
        size_t plain_len = 0;

        if (body_len > sizeof plain) continue;

        if (!quiccrypto_open(keys, pn, start, header_len, start + header_len,
                             body_len, plain, &plain_len)) {
            __log(c, "  [client] decryption failed at level %d\n", (int)level);
            continue;
        }

        /* The proof the server followed us: a packet it wrote with the next
         * generation of its own send keys. */
        if (level == QUIC_ENC_APP && c->key_update_done && in_new_phase)
            c->read_after_update = 1;

        quicrange_add(&c->received[level], pn, pn);

        int ack_eliciting = 0;
        if (!__handle_frames(c, level, plain, plain_len, &ack_eliciting))
            return 0;

        if (ack_eliciting) c->ack_pending[level] = 1;

        /* Advance TLS between packets of the same datagram, not just after it.
         *
         * A server flight arrives coalesced -- Initial then Handshake in one
         * datagram (§12.2) -- and the handshake keys only exist once TLS has
         * consumed the Initial's CRYPTO. Waiting until the end of the datagram
         * means the Handshake packet is undecryptable when it is reached, and
         * gets dropped: the handshake then limps along on retransmissions, or
         * fails outright when the flight does not survive being split. */
        if (!quictls_advance(&c->tls)) return 0;
    }

    return 1;
}

/* ---- Lifecycle ---- */

int quicclient_connect(quicclient_t* client, const char* host, uint16_t port,
                       const char* server_name, int verbose) {
    if (client == NULL) return 0;

    memset(client, 0, sizeof * client);
    client->verbose = verbose;
    client->fd = -1;

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        quicsendbuf_init(&client->crypto_out[i]);
        quicrange_init(&client->received[i], 0);
    }

    /* A random id of our own invention. The server has never seen it, which is
     * the point: the Initial keys of both ends are derived from it, so the
     * first packet is decryptable by a server that knows nothing yet (§5.2). */
    client->odcid.len = 8;
    client->scid.len = 8;
    if (RAND_bytes(client->odcid.data, 8) != 1 ||
        RAND_bytes(client->scid.data, 8) != 1)
        return 0;

    uint8_t client_secret[32];
    uint8_t server_secret[32];
    if (!quiccrypto_initial_secrets(&client->odcid, client_secret, server_secret))
        return 0;

    /* Mirror image of the server: we write with the client secret and read with
     * the server's. */
    const int keys_ok =
        quickeys_install(&client->tx[QUIC_ENC_INITIAL], QUIC_AEAD_AES_128_GCM,
                         client_secret, sizeof client_secret) &&
        quickeys_install(&client->rx[QUIC_ENC_INITIAL], QUIC_AEAD_AES_128_GCM,
                         server_secret, sizeof server_secret);

    explicit_bzero(client_secret, sizeof client_secret);
    explicit_bzero(server_secret, sizeof server_secret);

    if (!keys_ok) return 0;

    client->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (client->ssl_ctx == NULL) return 0;

    if (!quictls_configure_ctx(client->ssl_ctx)) return 0;
    /* This is a test client talking to a test certificate. */
    SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_NONE, NULL);

    quictp_t params;
    quictp_defaults(&params);
    /* Generous on purpose. This client never sends MAX_DATA or MAX_STREAM_DATA
     * -- see the note in quicclient.h -- so whatever it advertises here is all
     * the room a response will ever get. It has to exceed the server's
     * write-ahead budget several times over, or a large response would stall on
     * flow control and look like a server bug. */
    params.initial_max_data = 64 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 32 * 1024 * 1024;
    params.initial_max_stream_data_uni = 1024 * 1024;
    params.initial_max_streams_bidi = 16;
    params.initial_max_streams_uni = 16;
    params.max_idle_timeout = 30000;
    /* Above the RFC minimum of 2, so the server issuing spares is visible as a
     * count rather than as a single id that could be a coincidence. */
    params.active_connection_id_limit = 4;
    params.has_initial_scid = 1;
    params.initial_scid = client->scid;

    if (!quictls_init_client(&client->tls, client->ssl_ctx, &__ops, client,
                             &params, server_name))
        return 0;

    client->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (client->fd < 0) return 0;

    memset(&client->server, 0, sizeof client->server);
    client->server.sin_family = AF_INET;
    client->server.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &client->server.sin_addr) != 1) return 0;

    /* Produces the ClientHello, which lands in crypto_out via the callback. */
    if (!quictls_advance(&client->tls)) return 0;

    return __flush(client);
}

int quicclient_run(quicclient_t* client, int timeout_ms) {
    if (client == NULL) return 0;

    const uint64_t deadline = quic_now_us() + (uint64_t)timeout_ms * 1000;

    while (quic_now_us() < deadline) {
        struct pollfd pfd = { .fd = client->fd, .events = POLLIN };

        const int remaining = (int)((deadline - quic_now_us()) / 1000);
        const int r = poll(&pfd, 1, remaining > 100 ? 100 : remaining);
        if (r < 0) return 0;

        if (r > 0) {
            uint8_t buf[2048];
            const ssize_t n = recv(client->fd, buf, sizeof buf, 0);
            if (n <= 0) continue;

            if (!__recv_datagram(client, buf, (size_t)n)) return 0;

            if (!quictls_advance(&client->tls)) return 0;

            if (client->tls.handshake_complete && !client->handshake_complete) {
                client->handshake_complete = 1;
                __log(client, "  [client] handshake complete\n");
            }
        }

        if (!__flush(client)) return 0;

        /* The handshake is only truly finished once the server confirms it --
         * that is what HANDSHAKE_DONE is for (§7.5). */
        if (client->handshake_complete && client->handshake_done_received)
            return 1;
    }

    return client->handshake_complete;
}

int quicclient_pump(quicclient_t* client, int timeout_ms) {
    if (client == NULL) return 0;

    if (!__flush(client)) return 0;

    const uint64_t deadline = quic_now_us() + (uint64_t)timeout_ms * 1000;
    int got_anything = 0;

    /* Drains every datagram that is ready, not just the first. Reading one per
     * call was the whole reason a megabyte response arrived as sixty
     * kilobytes: at ~1200 bytes a datagram, fifty calls is sixty kilobytes, and
     * the response looked truncated by the server. */
    while (quic_now_us() < deadline) {
        struct pollfd pfd = { .fd = client->fd, .events = POLLIN };

        /* Wait only while nothing has arrived yet; once the burst starts, take
         * the rest of it without pausing between datagrams. */
        const int wait_ms = got_anything ? 0 : 20;
        const int r = poll(&pfd, 1, wait_ms);
        if (r < 0) return 0;
        if (r == 0) break;

        uint8_t buf[2048];
        const ssize_t n = recv(client->fd, buf, sizeof buf, 0);
        if (n <= 0) break;

        if (!__recv_datagram(client, buf, (size_t)n)) return 0;
        got_anything = 1;
    }

    /* Acknowledge the burst in one go rather than per datagram. */
    if (got_anything && !__flush(client)) return 0;

    return 1;
}

void quicclient_free(quicclient_t* client) {
    if (client == NULL) return;

    quictls_free(&client->tls);

    /* The generation a key update left behind. Its contexts are owned exactly
     * like the live ones, so forgetting it here leaks a key set per update. */
    quickeys_free(&client->rx_prev);

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        quickeys_free(&client->rx[i]);
        quickeys_free(&client->tx[i]);
        quicsendbuf_free(&client->crypto_out[i]);
        quicrange_free(&client->received[i]);
    }

    for (size_t i = 0; i < CLIENT_MAX_STREAMS; i++) {
        if (!client->streams[i].used) continue;
        quicsendbuf_free(&client->streams[i].out);
        quicrecvbuf_free(&client->streams[i].in);
    }

    if (client->ssl_ctx != NULL) SSL_CTX_free(client->ssl_ctx);
    if (client->fd >= 0) close(client->fd);
}

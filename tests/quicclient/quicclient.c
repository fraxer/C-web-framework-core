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

    /* §7.3: after a Retry the server must report both the id we invented for
     * the first Initial and the one it chose for the Retry. Checked here rather
     * than trusted, because reporting the current id as the original is the
     * classic way to get this wrong and it fails silently in both directions. */
    if (c->retry_seen) {
        c->retry_scid_confirmed =
            params->has_retry_scid &&
            params->retry_scid.len == c->retry_scid.len &&
            memcmp(params->retry_scid.data, c->retry_scid.data, c->retry_scid.len) == 0 &&
            params->has_original_dcid &&
            params->original_dcid.len == c->odcid.len &&
            memcmp(params->original_dcid.data, c->odcid.data, c->odcid.len) == 0;

        __log(c, "  [client] retry transport parameters %s\n",
              c->retry_scid_confirmed ? "match" : "DO NOT MATCH");
    }

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

/* ---- Network impairment ---- */

/* xorshift64*, inline: the sequence has to be reproducible from the seed alone,
 * which rules out rand() (process-global, and whatever else calls it changes
 * this test's outcome). */
static unsigned __net_roll(quicclient_t* c) {
    uint64_t x = c->net_rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    c->net_rng = x;

    return (unsigned)((x * 2685821657736338717ULL) >> 33) % 100u;
}

static int __net_impaired(const quicclient_t* c) {
    return c->net_loss_pct > 0 || c->net_dup_pct > 0 || c->net_reorder_pct > 0;
}

static ssize_t __net_write(quicclient_t* c, const uint8_t* buf, size_t len) {
    /* The in-process stand's emulator, when there is one: it never fails, it
     * only decides what the path does with the datagram. */
    if (c->out != NULL) {
        c->out(c->out_arg, buf, len);
        return (ssize_t)len;
    }

    return sendto(c->fd, buf, len, 0,
                  (struct sockaddr*)&c->server, sizeof c->server);
}

/* Send, or lose, or hold back, or send twice. */
static int __net_send(quicclient_t* c, const uint8_t* buf, size_t len) {
    if (!__net_impaired(c)) return __net_write(c, buf, len) >= 0;

    if (c->net_loss_pct > 0 && __net_roll(c) < c->net_loss_pct) {
        c->net_dropped_out++;
        __log(c, "  [net] dropped an outgoing datagram (%zu bytes)\n", len);
        return 1;   /* a lost packet is not an error; that is the point */
    }

    /* Held back, and released after the next one goes out -- which is what
     * "reordered" means from the receiver's side. */
    if (c->net_reorder_pct > 0 && c->net_held_len == 0 &&
        len <= sizeof c->net_held && __net_roll(c) < c->net_reorder_pct) {
        memcpy(c->net_held, buf, len);
        c->net_held_len = len;
        c->net_reordered++;
        __log(c, "  [net] holding a datagram back (%zu bytes)\n", len);
        return 1;
    }

    if (__net_write(c, buf, len) < 0) return 0;

    if (c->net_dup_pct > 0 && __net_roll(c) < c->net_dup_pct) {
        c->net_duplicated++;
        (void)__net_write(c, buf, len);
    }

    if (c->net_held_len > 0) {
        const size_t held = c->net_held_len;
        c->net_held_len = 0;
        if (__net_write(c, c->net_held, held) < 0) return 0;
    }

    return 1;
}

/* Receive, or pretend the datagram never arrived. Both directions are impaired
 * because they fail differently: a lost request stalls the peer's stream, a
 * lost response stalls ours, and only one of the two exercises our own ACK
 * and retransmission logic. */
static ssize_t __net_recv(quicclient_t* c, uint8_t* buf, size_t cap) {
    const ssize_t n = recv(c->fd, buf, cap, 0);
    if (n <= 0 || c->net_loss_in_pct == 0) return n;

    if (c->net_loss_in_pct > 0 && __net_roll(c) < c->net_loss_in_pct) {
        c->net_dropped_in++;
        __log(c, "  [net] dropped an incoming datagram (%zd bytes)\n", n);
        return -2;   /* distinct from an error: the caller keeps polling */
    }

    return n;
}

void quicclient_impair(quicclient_t* client, unsigned loss_out_pct, unsigned loss_in_pct,
                       unsigned reorder_pct, unsigned dup_pct, uint64_t seed) {
    if (client == NULL) return;

    client->net_loss_pct = loss_out_pct > 100 ? 100 : loss_out_pct;
    client->net_loss_in_pct = loss_in_pct > 100 ? 100 : loss_in_pct;
    client->net_reorder_pct = reorder_pct > 100 ? 100 : reorder_pct;
    client->net_dup_pct = dup_pct > 100 ? 100 : dup_pct;
    client->net_rng = seed != 0 ? seed : 0x9e3779b97f4a7c15ULL;
}

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

int quicclient_ping(quicclient_t* client) {
    if (client == NULL) return 0;

    client->ping_queued = 1;

    return 1;
}

int quicclient_rebind(quicclient_t* client) {
    if (client == NULL) return 0;

    /* In the in-process stand there is no port to change: the address the
     * server sees is the one the emulator reports, so a rebind there is the
     * emulator's move and only the connection id half belongs here. */
    if (client->out == NULL) {
        if (client->fd < 0) return 0;

        const int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return 0;

        /* Not bound explicitly: the first sendto picks an ephemeral port, and
         * any port different from the last one is what the test needs. */
        close(client->fd);
        client->fd = fd;
    }

    /* §9.5 asks a migrating endpoint to use a connection id the peer has not
     * seen on the old path, so that the two cannot be linked by an observer.
     * Done here rather than left to the caller because a rebind without it is
     * not the case anyone actually wants to test. */
    if (client->server_cid_count > 0)
        client->dcid = client->server_cids[client->server_cid_count - 1].cid;

    __log(client, "  [client] rebound to a new source port\n");

    return 1;
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
    if (client->path_challenge_queued) return 0;   /* one is already waiting */

    /* Already sent and still unanswered: queue the *same* data again rather
     * than refusing. §8.2.1 expects exactly this -- "an endpoint MAY send
     * multiple PATH_CHALLENGE frames to guard against packet loss" -- and the
     * data is reused so that whichever copy is answered still matches. */
    if (client->path_challenge_sent) {
        if (client->path_response_received) return 0;

        client->path_challenge_queued = 1;

        return 1;
    }

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

void quicclient_stream_release(quicclient_t* client, uint64_t id) {
    clientstream_t* s = __stream_get(client, id, 0);
    if (s == NULL) return;

    quicsendbuf_free(&s->out);
    quicrecvbuf_free(&s->in);
    memset(s, 0, sizeof * s);
}

static size_t __build(quicclient_t* c, quic_enc_level_e level,
                      uint8_t* dst, size_t cap, int pad_to_minimum) {
    quickeys_t* keys = &c->tx[level];
    if (!keys->valid) return 0;

    uint8_t payload[CLIENT_MAX_PACKET];
    size_t p = 0;

    /* What the payload may grow to, bounded by the caller's datagram and not
     * only by our own buffer. The header is sized conservatively: form byte,
     * version, two length-prefixed connection ids, the token an Initial carries
     * after a Retry, the length field and the packet number.
     *
     * Before Retry this was slack -- the token field was always a single zero
     * byte -- and the code got away with measuring against `payload` alone. A
     * hundred-byte token turned that slack negative, and the seal ran off the
     * end of the caller's buffer. */
    const size_t header_room = 7 + c->dcid.len + c->scid.len + 4 + 4 +
                               (c->retry_token_len > 0 ? c->retry_token_len + 2 : 1);

    if (cap < header_room + QUIC_AEAD_TAG_LEN + 32) return 0;

    size_t payload_cap = cap - header_room - QUIC_AEAD_TAG_LEN;
    if (payload_cap > sizeof payload) payload_cap = sizeof payload;

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

        const size_t n = quicframe_write_ack(payload + p, payload_cap - p,
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

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
        if (n > 0) {
            p += n;
            c->retire_queued = 0;
            __log(c, "  [client] -> RETIRE_CONNECTION_ID seq %llu\n",
                  (unsigned long long)c->retire_seq);
        }
    }

    if (level == QUIC_ENC_APP && c->path_response_queued) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_PATH_RESPONSE;
        memcpy(f.u.path.data, c->path_challenge_in, sizeof f.u.path.data);

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
        if (n > 0) {
            p += n;
            c->path_response_queued = 0;
            __log(c, "  [client] -> PATH_RESPONSE\n");
        }
    }

    if (level == QUIC_ENC_APP && c->ping_queued) {
        quicframe_t f;
        memset(&f, 0, sizeof f);
        f.type = QUIC_FRAME_PING;

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
        if (n > 0) {
            p += n;
            c->ping_queued = 0;
            __log(c, "  [client] -> PING\n");
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

        const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
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
        const size_t room = payload_cap - p - 96;

        if (quicsendbuf_next(&c->crypto_out[level], room, &offset, &data, &dlen, &fin)
            && dlen > 0) {
            quicframe_t f;
            memset(&f, 0, sizeof f);
            f.type = QUIC_FRAME_CRYPTO;
            f.u.crypto.offset = offset;
            f.u.crypto.len = dlen;
            f.u.crypto.data = data;

            const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
            if (n > 0) {
                p += n;
                quicsendbuf_mark_sent(&c->crypto_out[level], offset, dlen, 0);
            }
        }
    }

    /* Stream data, once the handshake keys exist. One frame per stream per
     * packet is enough for a test whose whole exchange is a few kilobytes. */
    if (level == QUIC_ENC_APP) {
        for (size_t i = 0; i < CLIENT_MAX_STREAMS && p + 64 < payload_cap; i++) {
            clientstream_t* st = &c->streams[i];
            if (!st->used || !quicsendbuf_pending(&st->out)) continue;

            uint64_t offset = 0;
            const uint8_t* data = NULL;
            size_t dlen = 0;
            int fin = 0;

            const size_t room = payload_cap - p - 96;
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

            const size_t n = quicframe_write(payload + p, payload_cap - p, &f);
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

    if (level == QUIC_ENC_INITIAL && c->retry_token_len > 0) {
        hdr.token = c->retry_token;
        hdr.token_len = c->retry_token_len;
    }

    /* An Initial that will be padded has to declare the padding in its Length,
     * or the server reads the padding as part of the ciphertext. So the padding
     * goes into the payload, before sealing. */
    if (pad_to_minimum && level == QUIC_ENC_INITIAL) {
        /* The token counts. Before Retry existed this estimate was always
         * right because the field was always one zero byte; with a token in it
         * the header grows by ~100 bytes, the padding overshoots by the same
         * amount, and the sealed packet runs past the caller's datagram --
         * which is exactly what ASan caught the first time a Retry arrived. */
        const size_t token_field = c->retry_token_len > 0 ? c->retry_token_len + 2 : 1;
        const size_t dcid_len = c->dcid.len > 0 ? c->dcid.len : c->odcid.len;
        const size_t header_estimate = 7 + dcid_len + c->scid.len + 2 + pn_len + token_field;

        if (QUIC_MIN_INITIAL_DATAGRAM > header_estimate + QUIC_AEAD_TAG_LEN) {
            const size_t want =
                QUIC_MIN_INITIAL_DATAGRAM - header_estimate - QUIC_AEAD_TAG_LEN;

            if (want > p && want < payload_cap) {
                memset(payload + p, 0, want - p);
                p = want;
            }
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

/* Is there handshake data still waiting for a packet to carry it?
 *
 * A ClientHello no longer fits in one packet: OpenSSL 3.5 offers a hybrid
 * post-quantum key share by default, which puts the message at ~1.3 KB. */
static int __crypto_pending(const quicclient_t* c) {
    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        if (i == QUIC_ENC_EARLY) continue;
        if (quicsendbuf_pending(&c->crypto_out[i])) return 1;
    }

    return 0;
}

static int __flush_one(quicclient_t* c, size_t* out_total) {
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

    *out_total = total;

    if (total == 0) {
        /* Nothing new to send, so the held datagram has waited as long as it
         * usefully can: release it. Without this, "reorder" quietly means
         * "drop" whenever the held packet is the last one the client had to
         * send -- which is precisely the request it is then waiting for a
         * response to, so the whole exchange deadlocks and looks like a server
         * that stopped answering. */
        if (c->net_held_len > 0) {
            const size_t held = c->net_held_len;
            c->net_held_len = 0;
            if (__net_write(c, c->net_held, held) < 0) return 0;
        }

        return 1;
    }

    if (!__net_send(c, datagram, total)) {
        printf("  [client] sendto failed: %s\n", strerror(errno));
        return 0;
    }

    return 1;
}

/* ---- Probe timer (RFC 9002 §6.2.2.1; see the header for why it exists) ---- */

/* Probes before giving up. Five doublings of the base is over ten seconds,
 * which is past any server's patience anyway. */
#define CLIENT_MAX_PROBES 5

/* kInitialRtt (RFC 9002 §6.2.2) doubled, which is what a PTO is with no RTT
 * sample. No estimator here on purpose: the client measures nothing, so a
 * pretend estimate would only be a fixed number wearing a costume. */
#define CLIENT_PTO_BASE_US 666000ULL

static void __pto_disarm(quicclient_t* c) {
    c->pto_deadline_us = 0;
    c->pto_count = 0;
}

/* Armed after sending, while the handshake is unconfirmed. Re-armed from
 * scratch rather than extended: this measures silence since our last packet,
 * which is the only thing the client can measure. */
static void __pto_arm(quicclient_t* c) {
    if (c->handshake_done_received) {
        __pto_disarm(c);
        return;
    }

    if (c->pto_count >= CLIENT_MAX_PROBES) {
        c->pto_deadline_us = 0;
        return;
    }

    c->pto_deadline_us = quic_now_us() + (CLIENT_PTO_BASE_US << c->pto_count);
}

uint64_t quicclient_next_timeout(const quicclient_t* client) {
    return client != NULL ? client->pto_deadline_us : 0;
}

static int __flush(quicclient_t* c);

int quicclient_tick(quicclient_t* client) {
    if (client == NULL) return 0;
    if (client->pto_deadline_us == 0) return 1;
    if (quic_now_us() < client->pto_deadline_us) return 1;

    client->pto_count++;
    client->pto_fired++;

    /* §6.2.4: a probe should carry data the peer is missing, not a bare PING.
     * For a client that is its handshake flight -- and during a handshake the
     * acknowledgement that would otherwise drive retransmission may never
     * arrive at all. */
    int requeued = 0;
    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        if (i == QUIC_ENC_EARLY) continue;
        if (!client->tx[i].valid) continue;
        if (quicsendbuf_requeue_unacked(&client->crypto_out[i])) requeued = 1;
    }

    /* Nothing to resend and no keys to say anything with: a PING at least makes
     * the peer answer, which is the minimum a probe owes (§6.2.4). */
    if (!requeued && client->tx[QUIC_ENC_APP].valid) client->ping_queued = 1;

    __log(client, "  [client] PTO %u, resending the flight\n", client->pto_count);

    return __flush(client);
}

static int __flush(quicclient_t* c) {
    /* Keep building datagrams while handshake data is left over.
     *
     * One datagram per flush was enough while a ClientHello fit in a packet.
     * It no longer does, and the half that stayed behind waited for the next
     * thing that happened to call this -- so the server sat on an incomplete
     * ClientHello, answered it with a bare ACK, and the handshake cost an
     * extra round trip. On a path that loses that ACK it cost the whole
     * connection: neither side had anything to retransmit, because neither
     * side had sent anything ack-eliciting. Found in the deterministic stand
     * (docs/http3/08-testing.md §2b), where it is visible in one trace.
     *
     * Bounded: a flight of eight datagrams is far beyond anything this client
     * has to say, and the loop stops as soon as a datagram comes out empty. */
    for (int datagram = 0; datagram < 8; datagram++) {
        size_t total = 0;

        if (!__flush_one(c, &total)) return 0;
        if (total == 0 || !__crypto_pending(c)) break;
    }

    /* We have spoken; the clock on the peer's silence starts here. Disarms
     * itself once the handshake is confirmed. */
    __pto_arm(c);

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

        case QUIC_FRAME_PING:
            __log(c, "  [client] <- PING\n");
            break;

        case QUIC_FRAME_NEW_TOKEN:
            c->new_token_received = 1;
            if (f.u.new_token.len > 0 && f.u.new_token.len <= sizeof c->new_token) {
                memcpy(c->new_token, f.u.new_token.data, (size_t)f.u.new_token.len);
                c->new_token_len = (size_t)f.u.new_token.len;
            }
            __log(c, "  [client] <- NEW_TOKEN, %llu bytes\n",
                  (unsigned long long)f.u.new_token.len);
            break;

        case QUIC_FRAME_PATH_CHALLENGE:
            memcpy(c->path_challenge_in, f.u.path.data, sizeof c->path_challenge_in);
            c->path_challenge_received = 1;
            c->path_response_queued = 1;
            __log(c, "  [client] <- PATH_CHALLENGE\n");
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
            /* Logged rather than printed: a close is a normal outcome for
             * several tests (they provoke one on purpose), and the stand runs
             * inside a test runner where an unexplained line is noise. What
             * happened is in close_received/close_error, which is what every
             * caller actually reads. */
            __log(c, "  [client] <- CONNECTION_CLOSE, error 0x%llx%s%.*s\n",
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

/* Everything derived from the Destination Connection ID, installed fresh.
 *
 * Called once at connect and again on a Retry: §5.2 derives the Initial keys
 * from the id the client addresses its Initial to, and a Retry changes that id,
 * so the whole handshake starts over -- keys, TLS session, packet numbers. */
static int __handshake_start(quicclient_t* c, const quiccid_t* dcid) {
    uint8_t client_secret[32];
    uint8_t server_secret[32];
    if (!quiccrypto_initial_secrets(dcid, client_secret, server_secret)) return 0;

    quickeys_free(&c->tx[QUIC_ENC_INITIAL]);
    quickeys_free(&c->rx[QUIC_ENC_INITIAL]);

    /* Mirror image of the server: we write with the client secret and read with
     * the server's. */
    const int keys_ok =
        quickeys_install(&c->tx[QUIC_ENC_INITIAL], QUIC_AEAD_AES_128_GCM,
                         client_secret, sizeof client_secret) &&
        quickeys_install(&c->rx[QUIC_ENC_INITIAL], QUIC_AEAD_AES_128_GCM,
                         server_secret, sizeof server_secret);

    explicit_bzero(client_secret, sizeof client_secret);
    explicit_bzero(server_secret, sizeof server_secret);

    if (!keys_ok) return 0;

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
    params.initial_scid = c->scid;

    quictls_free(&c->tls);

    return quictls_init_client(&c->tls, c->ssl_ctx, &__ops, c, &params, c->server_name);
}

/* A Retry: the server wants the address proven before it will keep any state
 * (§17.2.5). Everything so far is discarded and the handshake begins again,
 * addressed to the id the Retry chose and carrying the token it supplied. */
static int __on_retry(quicclient_t* c, const quicpkt_t* pkt) {
    /* §17.2.5.2: exactly one. A second Retry is discarded, or an attacker who
     * can inject them keeps the handshake restarting forever. */
    if (c->retry_seen) return 1;

    if (pkt->token_len == 0 || pkt->token_len > sizeof c->retry_token) return 1;

    c->retry_seen = 1;
    c->retry_scid = pkt->scid;
    memcpy(c->retry_token, pkt->token, pkt->token_len);
    c->retry_token_len = pkt->token_len;

    /* The id we address from now on. odcid is deliberately left alone: it is
     * what the server must report as original_destination_connection_id, and
     * checking that is half the point of the exercise. */
    c->dcid = pkt->scid;

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        quicsendbuf_free(&c->crypto_out[i]);
        quicsendbuf_init(&c->crypto_out[i]);
        quicrange_free(&c->received[i]);
        quicrange_init(&c->received[i], 0);
        c->next_pn[i] = 0;
        c->ack_pending[i] = 0;
    }

    /* The probe timer belongs to the flight that was just thrown away: a Retry
     * is an answer, so the backoff has no reason to carry over. */
    __pto_disarm(c);

    __log(c, "  [client] <- RETRY, %zu-byte token; restarting the handshake\n",
          pkt->token_len);

    return __handshake_start(c, &c->retry_scid);
}

/* Does this datagram end with a reset token the server gave us? */
static int __is_stateless_reset(const quicclient_t* c, const uint8_t* buf, size_t len) {
    if (len < 21) return 0;   /* §10.3: shorter cannot be one */

    for (size_t i = 0; i < c->server_cid_count; i++)
        if (memcmp(buf + len - 16, c->server_cids[i].token, 16) == 0) return 1;

    return 0;
}

static int __recv_datagram(quicclient_t* c, uint8_t* buf, size_t len) {
    c->datagrams_received++;

    /* Checked before parsing, not after failing to: a reset is *designed* to
     * parse as a short-header packet, so "it did not decrypt" is the only
     * symptom it ever has. */
    if (__is_stateless_reset(c, buf, len)) {
        c->reset_received = 1;
        __log(c, "  [client] <- STATELESS RESET (%zu bytes)\n", len);
        return 0;
    }

    size_t off = 0;
    quicpkt_t pkt;
    quicpkt_status_e st;

    while (quicpkt_next(buf, len, &off, QUIC_LOCAL_CID_LEN, &pkt, &st)) {
        uint8_t* start = buf + off - pkt.pkt_len;
        const quic_enc_level_e level = quicpkt_level(pkt.type);

        /* A Retry carries no packet number and no payload to decrypt: it is
         * handled whole, before any of the machinery below. */
        if (pkt.type == QUIC_PKT_RETRY) {
            if (!__on_retry(c, &pkt)) return 0;
            continue;
        }

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

    /* The peer is evidently not quiet, so the backoff starts over -- and once
     * this datagram was the HANDSHAKE_DONE, __pto_arm retires the timer for
     * good. */
    c->pto_count = 0;
    __pto_arm(c);

    return 1;
}

/* ---- Lifecycle ---- */

static int __connect(quicclient_t* client, const char* host, uint16_t port,
                     const char* server_name, int verbose,
                     const uint8_t* token, size_t token_len,
                     unsigned loss_out_pct, unsigned loss_in_pct,
                     unsigned reorder_pct, unsigned dup_pct, uint64_t seed,
                     void (*out)(void* arg, const uint8_t* data, size_t len),
                     void* out_arg);

int quicclient_connect(quicclient_t* client, const char* host, uint16_t port,
                       const char* server_name, int verbose) {
    return quicclient_connect_token(client, host, port, server_name, verbose, NULL, 0);
}

int quicclient_connect_impaired(quicclient_t* client, const char* host, uint16_t port,
                                const char* server_name, int verbose,
                                unsigned loss_out_pct, unsigned loss_in_pct,
                                unsigned reorder_pct, unsigned dup_pct, uint64_t seed) {
    if (client == NULL) return 0;

    /* The struct is zeroed inside, so the impairment cannot be set before the
     * call; it is installed at the one point in the sequence where the socket
     * exists and nothing has been sent yet. */
    return __connect(client, host, port, server_name, verbose, NULL, 0,
                     loss_out_pct, loss_in_pct, reorder_pct, dup_pct, seed,
                     NULL, NULL);
}

int quicclient_connect_inproc(quicclient_t* client, const char* server_name, int verbose,
                              void (*out)(void* arg, const uint8_t* data, size_t len),
                              void* out_arg) {
    if (client == NULL || out == NULL) return 0;

    return __connect(client, NULL, 0, server_name, verbose, NULL, 0,
                     0, 0, 0, 0, 0, out, out_arg);
}

size_t quicclient_take_token(const quicclient_t* client, uint8_t* out, size_t cap) {
    if (client == NULL || !client->new_token_received) return 0;
    if (client->new_token_len == 0 || client->new_token_len > cap) return 0;

    memcpy(out, client->new_token, client->new_token_len);

    return client->new_token_len;
}

int quicclient_connect_token(quicclient_t* client, const char* host, uint16_t port,
                             const char* server_name, int verbose,
                             const uint8_t* token, size_t token_len) {
    return __connect(client, host, port, server_name, verbose, token, token_len,
                     0, 0, 0, 0, 0, NULL, NULL);
}

static int __connect(quicclient_t* client, const char* host, uint16_t port,
                     const char* server_name, int verbose,
                     const uint8_t* token, size_t token_len,
                     unsigned loss_out_pct, unsigned loss_in_pct,
                     unsigned reorder_pct, unsigned dup_pct, uint64_t seed,
                     void (*out)(void* arg, const uint8_t* data, size_t len),
                     void* out_arg) {
    if (client == NULL) return 0;

    memset(client, 0, sizeof * client);
    client->verbose = verbose;
    client->fd = -1;
    client->out = out;
    client->out_arg = out_arg;

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

    client->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (client->ssl_ctx == NULL) return 0;

    if (!quictls_configure_ctx(client->ssl_ctx)) return 0;
    /* This is a test client talking to a test certificate. */
    SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_NONE, NULL);

    client->server_name = server_name;

    quicclient_impair(client, loss_out_pct, loss_in_pct, reorder_pct, dup_pct, seed);

    /* Presented on the very first Initial, before anything is negotiated: that
     * is the whole point of a NEW_TOKEN -- the server decides whether to ask
     * for proof before it has spent anything. */
    if (token != NULL && token_len > 0 && token_len <= sizeof client->retry_token) {
        memcpy(client->retry_token, token, token_len);
        client->retry_token_len = token_len;
    }

    if (!__handshake_start(client, &client->odcid)) return 0;

    /* No socket in the in-process mode, and no address either: where the peer
     * is, is the emulator's business. */
    if (out == NULL) {
        client->fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (client->fd < 0) return 0;

        memset(&client->server, 0, sizeof client->server);
        client->server.sin_family = AF_INET;
        client->server.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &client->server.sin_addr) != 1) return 0;
    }

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

        /* And the probe, which is what carries the handshake through a path
         * that loses the server's first flight -- or ours. */
        if (!quicclient_tick(client)) return 0;

        /* The handshake is only truly finished once the server confirms it --
         * that is what HANDSHAKE_DONE is for (§7.5). */
        if (client->handshake_complete && client->handshake_done_received)
            return 1;
    }

    return client->handshake_complete;
}

int quicclient_deliver(quicclient_t* client, const uint8_t* data, size_t len) {
    if (client == NULL || data == NULL) return 0;

    /* Copied because header protection is removed in place, and the caller's
     * buffer belongs to the emulator -- which may still have to deliver the
     * same bytes again as a duplicate. */
    uint8_t buf[2048];
    if (len == 0 || len > sizeof buf) return 0;
    memcpy(buf, data, len);

    if (!__recv_datagram(client, buf, len)) return 0;

    /* Every datagram, not every burst: a server flight arrives coalesced and
     * the handshake only moves when TLS has consumed it (see __recv_datagram). */
    if (!quictls_advance(&client->tls)) return 0;

    if (client->tls.handshake_complete && !client->handshake_complete) {
        client->handshake_complete = 1;
        __log(client, "  [client] handshake complete\n");
    }

    return 1;
}

int quicclient_flush(quicclient_t* client) {
    if (client == NULL) return 0;

    return __flush(client);
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
        const ssize_t n = __net_recv(client, buf, sizeof buf);
        if (n == -2) continue;   /* dropped on purpose */
        if (n <= 0) break;

        if (!__recv_datagram(client, buf, (size_t)n)) return 0;
        got_anything = 1;
    }

    /* Acknowledge the burst in one go rather than per datagram. */
    if (got_anything && !__flush(client)) return 0;

    /* A pump that heard nothing is exactly when the probe matters. */
    return quicclient_tick(client);
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

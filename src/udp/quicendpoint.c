#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "appconfig.h"
#include "log.h"
#include "metrics.h"
/* The full connection type: the header pair is deliberately opaque in both
 * directions (quicconn.h holds a `struct quicendpoint*`, quicendpoint.h a
 * `struct quicconn*`), so exactly one of the two .c files has to see both. */
#include "quicconn.h"
#include "quicendpoint.h"
#include "quicinvariants.h"
#include "quictime.h"
#include "h3conn.h"

/* Largest datagram we will accept. Above the largest we send
 * (QUIC_MAX_UDP_PAYLOAD_V4) so that an oversized one is visibly rejected as
 * oversized rather than silently truncated into a packet that fails to
 * decrypt for reasons nobody can see. */
#define QUIC_RX_DATAGRAM_SIZE 2048

/* One event drains at most this many batches. Level-triggered epoll will report
 * the socket again, so a busy endpoint cannot starve the rest of the worker. */
#define QUIC_RX_MAX_BATCHES 8

/* Smallest stateless reset that is indistinguishable from a real short-header
 * packet (RFC 9000 §10.3), and the largest we bother to send. */
#define QUIC_RESET_MIN_LEN 21
#define QUIC_RESET_MAX_LEN 64

#define QUIC_DEFAULT_MAX_CONNECTIONS 65536
#define QUIC_DEFAULT_VN_RATE         100
#define QUIC_DEFAULT_VN_BURST        200
#define QUIC_DEFAULT_RESET_RATE      100
#define QUIC_DEFAULT_RESET_BURST     200
/* New connections per second, and how many may arrive at once. A handshake is
 * the most expensive thing an unauthenticated peer can ask for -- a signature,
 * a certificate chain on the wire, and per-connection state that lives until
 * the idle timeout -- so it gets a bucket of its own, above and beyond the
 * ceiling on how many connections may exist at all. */
#define QUIC_DEFAULT_HANDSHAKE_RATE  500
#define QUIC_DEFAULT_HANDSHAKE_BURST 1000

/* Connection defaults. The same figures quicconn_accept used to hold inline,
 * kept as the fallback so a build with no config -- a unit test -- behaves as
 * it did before there were keys at all. */
#define QUIC_DEFAULT_IDLE_TIMEOUT_SEC   30
#define QUIC_DEFAULT_INITIAL_MAX_DATA   1048576
#define QUIC_DEFAULT_STREAM_DATA        262144
#define QUIC_DEFAULT_MAX_STREAMS_BIDI   100
#define QUIC_DEFAULT_MAX_STREAMS_UNI    8
#define QUIC_DEFAULT_ACTIVE_CID_LIMIT   4
#define QUIC_DEFAULT_ACK_DELAY_MS       25
#define QUIC_DEFAULT_AMPLIFICATION      3

/* ---- Process-wide policy ----
 *
 * Plain globals, read from every worker. Safe only because quic_policy_init()
 * runs before any worker thread exists -- the same contract h2_policy_init()
 * holds (moduleloader.c). */

static void __route(quicendpoint_t* ep, struct quicconn* conn, udp_datagram_t* dgram);

/* Called by the CID table under its shard lock, on the value it is about to
 * return. One atomic increment, which is what stops the connection being freed
 * between the lookup finding it and the caller using it. */
static void __table_acquire(void* value) {
    connection_s_inc(&((quicconn_t*)value)->conn);
}

static quiccidtable_t* __quic_table = NULL;
static size_t   __quic_max_connections = QUIC_DEFAULT_MAX_CONNECTIONS;
static uint8_t  __quic_reset_key[32];
static size_t   __quic_rx_batch = 32;
static int      __quic_rcvbuf = 0;
static int      __quic_sndbuf = 0;
static int64_t  __quic_vn_rate = QUIC_DEFAULT_VN_RATE;
static int64_t  __quic_vn_burst = QUIC_DEFAULT_VN_BURST;
static int64_t  __quic_reset_rate = QUIC_DEFAULT_RESET_RATE;
static int64_t  __quic_reset_burst = QUIC_DEFAULT_RESET_BURST;
static int64_t  __quic_handshake_rate = QUIC_DEFAULT_HANDSHAKE_RATE;
static int64_t  __quic_handshake_burst = QUIC_DEFAULT_HANDSHAKE_BURST;

static quic_conn_policy_t __quic_conn_policy = {
    .idle_timeout_ms        = QUIC_DEFAULT_IDLE_TIMEOUT_SEC * 1000,
    .max_udp_payload_size   = QUIC_DEFAULT_UDP_PAYLOAD,
    .initial_max_data       = QUIC_DEFAULT_INITIAL_MAX_DATA,
    .initial_max_stream_data = QUIC_DEFAULT_STREAM_DATA,
    .max_streams_bidi       = QUIC_DEFAULT_MAX_STREAMS_BIDI,
    .max_streams_uni        = QUIC_DEFAULT_MAX_STREAMS_UNI,
    .recv_window_max        = QUIC_DEFAULT_INITIAL_MAX_DATA * 16,
    .active_cid_limit       = QUIC_DEFAULT_ACTIVE_CID_LIMIT,
    .ack_delay_ms           = QUIC_DEFAULT_ACK_DELAY_MS,
    .pacing                 = 1,
    .amplification_factor   = QUIC_DEFAULT_AMPLIFICATION
};

const quic_conn_policy_t* quic_policy_conn(void) {
    return &__quic_conn_policy;
}

/* One key, clamped into a range it cannot break the protocol from. Every bound
 * here is a real limit of the code below it, not a taste: a receive window
 * under a packet stalls the connection on its first datagram, and a payload
 * size over the build's packet buffer would advertise room we cannot use. */
static uint64_t __policy_u64(const char* key, uint64_t fallback,
                             uint64_t min, uint64_t max) {
    /* env_get_llong, not env_get_int: these are byte counts, and a value past
     * 2^31 must clamp to the ceiling below rather than fall back to the default
     * because the parse overflowed. */
    const long long v = env_get_llong(key, (long long)fallback);

    if (v < 0 || (uint64_t)v < min) return min;
    if ((uint64_t)v > max) return max;

    return (uint64_t)v;
}

static void __conn_policy_init(void) {
    quic_conn_policy_t* p = &__quic_conn_policy;

    /* §10.1 puts no ceiling on the idle timeout, but the connection state it
     * keeps alive is ours, so an hour is where this one stops. */
    p->idle_timeout_ms =
        __policy_u64("http3_idle_timeout_sec", QUIC_DEFAULT_IDLE_TIMEOUT_SEC, 1, 3600) * 1000;

    /* The floor is §14's minimum; the ceiling is the packet buffer quicconn
     * builds into, and advertising more than that would promise room the code
     * does not have. */
    p->max_udp_payload_size =
        __policy_u64("http3_max_udp_payload_size", QUIC_DEFAULT_UDP_PAYLOAD,
                     QUIC_MIN_INITIAL_DATAGRAM, QUIC_DEFAULT_UDP_PAYLOAD);

    p->initial_max_data =
        __policy_u64("http3_initial_max_data", QUIC_DEFAULT_INITIAL_MAX_DATA,
                     QUIC_MIN_INITIAL_DATAGRAM, 1073741824ULL);

    p->initial_max_stream_data =
        __policy_u64("http3_initial_max_stream_data", QUIC_DEFAULT_STREAM_DATA,
                     QUIC_MIN_INITIAL_DATAGRAM, 1073741824ULL);

    /* Zero would be legal on the wire and useless here: a client that may open
     * no request stream has no way to ask for anything. */
    p->max_streams_bidi =
        __policy_u64("http3_max_streams_bidi", QUIC_DEFAULT_MAX_STREAMS_BIDI, 1, 65536);

    /* HTTP/3 needs three of these before a request can be served (control and
     * both QPACK streams), so the floor is what the protocol itself costs. */
    p->max_streams_uni =
        __policy_u64("http3_max_streams_uni", QUIC_DEFAULT_MAX_STREAMS_UNI, 3, 65536);

    p->recv_window_max =
        __policy_u64("http3_recv_window_max", QUIC_DEFAULT_INITIAL_MAX_DATA * 16,
                     p->initial_max_data, 1073741824ULL);

    p->active_cid_limit =
        __policy_u64("http3_active_cid_limit", QUIC_DEFAULT_ACTIVE_CID_LIMIT, 2, 8);

    /* §18.2 caps the parameter itself at 2^14 ms. */
    p->ack_delay_ms =
        __policy_u64("http3_ack_delay_ms", QUIC_DEFAULT_ACK_DELAY_MS, 0, 16383);

    p->pacing = env_get_int("http3_pacing", 1) != 0;

    p->amplification_factor =
        __policy_u64("http3_amplification_factor", QUIC_DEFAULT_AMPLIFICATION, 1, 16);

    if (p->amplification_factor != QUIC_DEFAULT_AMPLIFICATION)
        log_error("quic: http3_amplification_factor is %llu, not the %d RFC 9000 §8.1 "
                  "requires -- this server can be used to amplify traffic at a spoofed address\n",
                  (unsigned long long)p->amplification_factor, QUIC_DEFAULT_AMPLIFICATION);
}

int quic_policy_init(void) {
    /* A reload calls this again; drop the previous table rather than leak it.
     * Connections do not survive a reload, so nothing is orphaned. */
    quic_policy_free();

    int64_t max_connections = env_get_int("http3_max_connections", QUIC_DEFAULT_MAX_CONNECTIONS);
    if (max_connections < 64) max_connections = 64;
    if (max_connections > 4000000) max_connections = 4000000;
    __quic_max_connections = (size_t)max_connections;

    int64_t batch = env_get_int("http3_rx_batch", 32);
    if (batch < 1) batch = 1;
    if (batch > 256) batch = 256;
    __quic_rx_batch = (size_t)batch;

    __quic_rcvbuf = env_get_int("http3_so_rcvbuf", 0);
    __quic_sndbuf = env_get_int("http3_so_sndbuf", 0);

    __conn_policy_init();

    /* 0 disables a limit. Every one of these guesses a threshold, and an
     * operator needs a way to prove a limit is the cause of an incident --
     * the same reasoning as the HTTP/2 budgets (docs/http2/08, phase A). */
    __quic_vn_rate = env_get_int("http3_version_negotiation_rate", QUIC_DEFAULT_VN_RATE);
    if (__quic_vn_rate < 0) __quic_vn_rate = 0;
    __quic_vn_burst = env_get_int("http3_version_negotiation_burst", QUIC_DEFAULT_VN_BURST);
    if (__quic_vn_burst < 1) __quic_vn_burst = 1;

    __quic_reset_rate = env_get_int("http3_stateless_reset_rate", QUIC_DEFAULT_RESET_RATE);
    if (__quic_reset_rate < 0) __quic_reset_rate = 0;
    __quic_reset_burst = env_get_int("http3_stateless_reset_burst", QUIC_DEFAULT_RESET_BURST);
    if (__quic_reset_burst < 1) __quic_reset_burst = 1;

    /* RAND_bytes rather than misc/random.h: these two are security inputs --
     * the reset key authenticates tokens a peer can collect, and the table seed
     * is what stops a peer from choosing colliding connection ids -- and
     * RAND_bytes needs no initialisation call to have been made first. */
    uint64_t seed = 0;
    if (RAND_bytes((unsigned char*)&seed, sizeof seed) != 1) {
        log_error("quic_policy_init: RAND_bytes failed for the table seed\n");
        return 0;
    }

    if (RAND_bytes(__quic_reset_key, sizeof __quic_reset_key) != 1) {
        log_error("quic_policy_init: RAND_bytes failed for the reset key\n");
        return 0;
    }

    /* A connection holds several ids at once (its own plus every one it has
     * issued and not retired), so the table is sized above the connection
     * limit.
     *
     * The acquire hook is not optional. Without it a lookup hands back a
     * pointer with no reference held, and the matching release in __dispatch
     * drops the base one -- so the connection is freed after the first
     * datagram it ever receives, and every later one reads freed memory. That
     * failure is invisible without ASan: the handshake completes perfectly on
     * quarantined memory. */
    __quic_table = quiccidtable_create((size_t)max_connections * 4, 64, seed,
                                       __table_acquire);
    if (__quic_table == NULL) {
        log_error("quic_policy_init: cannot create the connection table\n");
        return 0;
    }

    return 1;
}

void quic_policy_free(void) {
    if (__quic_table != NULL) {
        quiccidtable_free(__quic_table);
        __quic_table = NULL;
    }

    explicit_bzero(__quic_reset_key, sizeof __quic_reset_key);
}

/* ---- Token buckets ----
 *
 * Milli-tokens, like the HTTP/2 budgets, so a rate below one per second is
 * still expressible. Endpoint-local: only the owning worker touches them. */
static int __budget_spend(int64_t* tokens, uint64_t* epoch_us,
                          int64_t rate, int64_t burst) {
    if (rate <= 0) return 1; /* limit disabled */

    const uint64_t now = quic_now_us();
    const int64_t ceiling = burst * 1000;

    if (*epoch_us == 0) {
        *epoch_us = now;
        *tokens = ceiling;
    }

    const uint64_t elapsed = now > *epoch_us ? now - *epoch_us : 0;
    *epoch_us = now;

    /* rate is tokens per second; elapsed is microseconds. Gained milli-tokens
     * are rate * elapsed / 1000. */
    *tokens += (int64_t)((elapsed * (uint64_t)rate) / 1000);
    if (*tokens > ceiling) *tokens = ceiling;

    if (*tokens < 1000) return 0;

    *tokens -= 1000;

    return 1;
}

/* ---- Replies that need no connection state ---- */

/* RFC 9000 §10.3. The token must be derivable without any per-connection state:
 * the whole point is to answer for a connection we no longer have. */
static int __reset_token(const quiccid_t* cid, uint8_t out[16]) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;

    if (HMAC(EVP_sha256(), __quic_reset_key, (int)sizeof __quic_reset_key,
             cid->data, cid->len, mac, &mac_len) == NULL || mac_len < 16)
        return 0;

    memcpy(out, mac, 16);

    return 1;
}

static void __send_stateless_reset(quicendpoint_t* ep, const udp_datagram_t* dgram,
                                   const quicinvariants_t* inv) {
    /* Must be strictly shorter than what provoked it, or the endpoint becomes
     * an amplifier for a spoofed source address. Below 22 bytes there is no
     * room for a reset that is both shorter and still indistinguishable from a
     * real packet, so the datagram is simply dropped. */
    if (dgram->len < QUIC_RESET_MIN_LEN + 1) {
        metrics_quic(METRICS_QUIC_DROP_UNKNOWN_CID);
        return;
    }

    if (!__budget_spend(&ep->reset_tokens, &ep->reset_epoch_us,
                        __quic_reset_rate, __quic_reset_burst)) {
        metrics_quic(METRICS_QUIC_DROP_NO_BUDGET);
        return;
    }

    size_t len = dgram->len - 1;
    if (len > QUIC_RESET_MAX_LEN) len = QUIC_RESET_MAX_LEN;

    uint8_t packet[QUIC_RESET_MAX_LEN];
    if (RAND_bytes(packet, (int)(len - 16)) != 1) {
        metrics_quic(METRICS_QUIC_DROP_UNKNOWN_CID);
        return;
    }

    /* Header form 0, fixed bit 1; the remaining six bits stay random so the
     * packet is indistinguishable from a 1-RTT packet with a short id. */
    packet[0] = (uint8_t)(0x40 | (packet[0] & 0x3f));

    if (!__reset_token(&inv->dcid, packet + len - 16)) {
        metrics_quic(METRICS_QUIC_DROP_UNKNOWN_CID);
        return;
    }

    const ssize_t sent = udp_send(ep->fd, packet, len,
                                  (const struct sockaddr*)&dgram->peer, dgram->peer_len,
                                  dgram->local_valid ? &dgram->local : NULL);
    if (sent < 0) {
        metrics_quic(METRICS_QUIC_SEND_ERROR);
        return;
    }

    metrics_quic(METRICS_QUIC_STATELESS_RESET);
    metrics_quic(METRICS_QUIC_DGRAM_SENT);
    metrics_quic_add(METRICS_QUIC_BYTES_SENT, (unsigned long long)sent);
}

static void __send_version_negotiation(quicendpoint_t* ep, const udp_datagram_t* dgram,
                                       const quicinvariants_t* inv) {
    if (!__budget_spend(&ep->vn_tokens, &ep->vn_epoch_us,
                        __quic_vn_rate, __quic_vn_burst)) {
        metrics_quic(METRICS_QUIC_DROP_NO_BUDGET);
        return;
    }

    /* Offer what we implement, plus a reserved version, so that a client cannot
     * come to depend on the exact list (RFC 9000 §6.3). */
    static const uint32_t versions[] = { QUIC_VERSION_1, QUIC_VERSION_GREASE };

    uint8_t unused = 0;
    if (RAND_bytes(&unused, 1) != 1) unused = 0;

    uint8_t packet[64];
    /* Swapped: our Destination is their Source. Passing them the other way
     * round produces a packet the client silently ignores. */
    const size_t len = quic_invariants_write_version_negotiation(
        packet, sizeof packet, &inv->scid, &inv->dcid, unused,
        versions, sizeof versions / sizeof versions[0]);

    if (len == 0 || len >= dgram->len) {
        metrics_quic(METRICS_QUIC_DROP_UNKNOWN_CID);
        return;
    }

    const ssize_t sent = udp_send(ep->fd, packet, len,
                                  (const struct sockaddr*)&dgram->peer, dgram->peer_len,
                                  dgram->local_valid ? &dgram->local : NULL);
    if (sent < 0) {
        metrics_quic(METRICS_QUIC_SEND_ERROR);
        return;
    }

    metrics_quic(METRICS_QUIC_VERSION_NEGOTIATION);
    metrics_quic(METRICS_QUIC_DGRAM_SENT);
    metrics_quic_add(METRICS_QUIC_BYTES_SENT, (unsigned long long)sent);
}

ssize_t quicendpoint_send(quicendpoint_t* endpoint, const uint8_t* data, size_t len,
                          const quicpath_t* path) {
    if (endpoint == NULL || data == NULL || path == NULL) return -1;
    if (endpoint->fd == -1) return -1;

    const ssize_t sent = udp_send(endpoint->fd, data, len,
                                  (const struct sockaddr*)&path->remote,
                                  path->remote_len,
                                  path->local_len > 0 ? &path->local : NULL);

    if (sent < 0) {
        metrics_quic(METRICS_QUIC_SEND_ERROR);
        return -1;
    }

    if (sent > 0) {
        metrics_quic(METRICS_QUIC_DGRAM_SENT);
        metrics_quic_add(METRICS_QUIC_BYTES_SENT, (unsigned long long)sent);
    }

    return sent;
}

void quicendpoint_wake(quicendpoint_t* endpoint, struct quicconn* conn) {
    if (endpoint == NULL || conn == NULL) return;

    /* A leaf lock held for a handful of instructions. It exists because this is
     * reachable from a handler thread, which must not be holding -- or waiting
     * for -- the connection lock at this point. */
    while (atomic_flag_test_and_set_explicit(&endpoint->tx_lock, memory_order_acquire))
        sched_yield();

    if (!conn->in_tx_queue) {
        conn->in_tx_queue = 1;
        conn->tx_next = NULL;

        if (endpoint->tx_tail != NULL) endpoint->tx_tail->tx_next = conn;
        else endpoint->tx_head = conn;

        endpoint->tx_tail = conn;
    }

    atomic_flag_clear_explicit(&endpoint->tx_lock, memory_order_release);
}

listener_t* quicendpoint_listener(quicendpoint_t* endpoint) {
    return endpoint != NULL ? &endpoint->listener : NULL;
}

int quicendpoint_fd(quicendpoint_t* endpoint) {
    return endpoint != NULL ? endpoint->fd : -1;
}

in_addr_t quicendpoint_ip(quicendpoint_t* endpoint) {
    if (endpoint == NULL || endpoint->local.ss_family != AF_INET) return 0;

    const struct sockaddr_in* in = (const struct sockaddr_in*)&endpoint->local;

    return in->sin_addr.s_addr;
}

unsigned short quicendpoint_port(quicendpoint_t* endpoint) {
    if (endpoint == NULL || endpoint->local.ss_family != AF_INET) return 0;

    const struct sockaddr_in* in = (const struct sockaddr_in*)&endpoint->local;

    return ntohs(in->sin_port);
}

void quicendpoint_detach(quicendpoint_t* endpoint, quicconn_t* conn) {
    if (endpoint == NULL || conn == NULL) return;

    /* Every id this connection answers to, so a datagram in flight cannot find
     * it after this returns. */
    for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++)
        if (conn->local_cids[i].active)
            quiccidtable_remove(endpoint->table, &conn->local_cids[i].cid);

    quiccidtable_remove(endpoint->table, &conn->odcid);

    quicconn_t** link = &endpoint->conns;
    while (*link != NULL) {
        if (*link == conn) {
            *link = conn->ep_next;
            if (endpoint->conn_count > 0) endpoint->conn_count--;
            break;
        }
        link = &(*link)->ep_next;
    }

    /* And out of the send queue, under its own lock: a handler thread may be
     * pushing onto it at this moment. */
    while (atomic_flag_test_and_set_explicit(&endpoint->tx_lock, memory_order_acquire))
        sched_yield();

    quicconn_t** tx = &endpoint->tx_head;
    quicconn_t* prev = NULL;
    while (*tx != NULL) {
        if (*tx == conn) {
            *tx = conn->tx_next;
            if (endpoint->tx_tail == conn) endpoint->tx_tail = prev;
            conn->in_tx_queue = 0;
            break;
        }
        prev = *tx;
        tx = &(*tx)->tx_next;
    }

    atomic_flag_clear_explicit(&endpoint->tx_lock, memory_order_release);
}

/* ---- Routing ---- */

/* Create a connection for a client's first Initial packet. */
static void __accept(quicendpoint_t* ep, udp_datagram_t* dgram,
                     const quicinvariants_t* inv) {
    server_t* server = NULL;
    cqueue_item_t* item = cqueue_first(&ep->listener.servers);
    if (item != NULL) server = item->data;

    if (server == NULL || server->openssl == NULL) {
        metrics_quic(METRICS_QUIC_DROP_UNKNOWN_CID);
        return;
    }

    quicpath_t path;
    memset(&path, 0, sizeof path);
    path.remote = dgram->peer;
    path.remote_len = dgram->peer_len;
    if (dgram->local_valid) {
        path.local = dgram->local;
        path.local_len = dgram->peer_len;
    }

    quicconn_t* conn = quicconn_accept(ep, &inv->dcid, &inv->scid, &path, server);
    if (conn == NULL) {
        metrics_quic(METRICS_QUIC_DROP_NO_BUDGET);
        return;
    }

    /* Both ids are registered: the client addresses its next packets to the id
     * we chose, but anything already in flight still carries the one it made
     * up, and dropping those would cost a retransmission on every connection. */
    if (quiccidtable_insert(ep->table, &conn->local_cids[0].cid, conn) != QUICCIDTABLE_OK ||
        quiccidtable_insert(ep->table, &conn->odcid, conn) != QUICCIDTABLE_OK) {
        quiccidtable_remove(ep->table, &conn->local_cids[0].cid);
        quiccidtable_remove(ep->table, &conn->odcid);
        quicconn_free(conn);
        metrics_quic(METRICS_QUIC_DROP_NO_BUDGET);
        return;
    }

    conn->ep_next = ep->conns;
    ep->conns = conn;
    ep->conn_count++;

    /* Into the worker's connection list and count, so the timer sweep and the
     * shutdown drain see it. For QUIC this does no epoll_ctl. */
    if (!ep->listener.api->control_add(&conn->conn, MPXIN)) {
        quicendpoint_detach(ep, conn);
        quicconn_free(conn);
        return;
    }

    metrics_quic(METRICS_QUIC_CONN_ACCEPTED);

    __route(ep, conn, dgram);
}


/* ---- The HTTP/3 layer ---- *
 *
 * The endpoint is where QUIC and HTTP/3 meet, and it is the right place for it:
 * quicconn knows nothing of HTTP, and h3conn knows nothing of datagrams. What
 * joins them is a fixed order that has to hold on every path that touches a
 * connection -- receive, then read the streams, then let the responses that are
 * ready write themselves, then build packets. Getting the last two the wrong way
 * round costs a round trip on every response, because the bytes would miss the
 * packet being built for them. */

/* Attach the HTTP/3 layer once the handshake is done, and send our SETTINGS.
 * Returns 0 if the connection cannot go on without them. */
static int __h3_attach(quicconn_t* conn) {
    connection_server_ctx_t* ctx = conn->conn.ctx;

    if (ctx->parser != NULL) return 1;
    if (conn->state != QUICCONN_ACTIVE) return 1;

    /* ALPN settled this at the handshake: the QUIC context offers `h3` and
     * nothing else (openssl.h), so an ACTIVE connection is an HTTP/3 one.
     *
     * Extended CONNECT is not advertised -- §8 is not implemented, and
     * advertising what we cannot serve is worse than staying quiet. */
    h3conn_t* c = h3conn_create(&conn->conn, h3_policy_max_field_section_size(), 0);
    if (c == NULL) return 0;

    ctx->parser = c;

    if (!h3conn_open_service_streams(c, conn)) {
        log_error("h3: could not open the service streams\n");
        return 0;
    }

    return 1;
}

/* Ask for another turn if a response is still only partly written. */
static void __h3_rearm(quicconn_t* conn) {
    const connection_server_ctx_t* ctx = conn->conn.ctx;
    if (ctx->parser == NULL) return;

    if (h3conn_has_pending(ctx->parser, conn)) quicconn_want_write(&conn->conn);
}

/* Read, dispatch and write for one connection. Called with the connection lock
 * held, which is what makes the dispatch inside reach the inline publish path
 * rather than the handler-thread one. Returns 0 if the connection must close. */
static int __h3_turn(quicconn_t* conn, uint64_t now) {
    if (!__h3_attach(conn)) {
        quicconn_close(conn, H3_INTERNAL_ERROR, 1, now);
        return 0;
    }

    connection_server_ctx_t* ctx = conn->conn.ctx;
    h3conn_t* c = ctx->parser;
    if (c == NULL) return 1;   /* handshake still running */

    uint64_t error = 0;
    if (!h3conn_read(c, conn, &error)) {
        quicconn_close(conn, error, 1, now);
        return 0;
    }

    h3conn_write(c, conn);

    return 1;
}

/* Hand a datagram to a connection and let it answer. */
static void __route(quicendpoint_t* ep, quicconn_t* conn, udp_datagram_t* dgram) {
    /* The connection reaches its endpoint through its own pointer; this one is
     * kept in the signature because migration (phase 9) will need to know which
     * endpoint the datagram arrived on, which need not be the same one. */
    (void)ep;

    quicpath_t path;
    memset(&path, 0, sizeof path);
    path.remote = dgram->peer;
    path.remote_len = dgram->peer_len;
    if (dgram->local_valid) {
        path.local = dgram->local;
        path.local_len = dgram->peer_len;
    }

    const uint64_t now = quic_now_us();

    /* The connection lock guards every field of the connection, exactly as it
     * does for HTTP/2 -- and here it also matters that a datagram of this
     * connection may land on a different worker, since the kernel hashes the
     * 4-tuple and QUIC does not (ADR-3). */
    connection_s_lock(&conn->conn, LOCK_SITE_QUIC_RECV);

    int alive = quicconn_recv(conn, dgram->data, dgram->len, &path, now);
    /* Streams first, packets after: a response produced here goes out in the
     * very packet this call builds instead of waiting for the next event. */
    if (alive) alive = __h3_turn(conn, now);

    /* The send path runs even when something above decided to close, because
     * that is where the CONNECTION_CLOSE quicconn_close staged actually goes
     * out (§10.2.1) -- it builds the packet and keeps it, it does not send it.
     * Skipping this left every protocol error hanging the peer up without a
     * word, to be discovered as an idle timeout half a minute later. */
    if (!quicconn_send(conn, now)) alive = 0;

    /* A response bigger than the write-ahead budget stopped mid-body; now that
     * the send path has taken what it could, ask for another turn. The tick
     * drains this queue once per cycle, so re-queueing here paces the response
     * to the network rather than spinning on it. */
    __h3_rearm(conn);

    if (!alive || conn->state == QUICCONN_DEAD) {
        conn->conn.close(&conn->conn);   /* releases the lock */
        return;
    }

    connection_s_unlock(&conn->conn);
}

static void __dispatch(quicendpoint_t* ep, udp_datagram_t* dgram) {
    /* udp_rx_batch_recv zeroes the length of a datagram that did not fit: QUIC
     * has no use for a partial one, since the AEAD tag is at the end. */
    if (dgram->len == 0) {
        metrics_quic(METRICS_QUIC_DROP_OVERSIZE);
        return;
    }

    metrics_quic(METRICS_QUIC_DGRAM_RECEIVED);
    metrics_quic_add(METRICS_QUIC_BYTES_RECEIVED, (unsigned long long)dgram->len);

    quicinvariants_t inv;
    switch (quic_invariants_parse(dgram->data, dgram->len, QUIC_LOCAL_CID_LEN, &inv)) {
    case QUICINV_OK:
        break;
    case QUICINV_TRUNCATED:
        metrics_quic(METRICS_QUIC_DROP_TRUNCATED);
        return;
    case QUICINV_CID_TOO_LONG:
        metrics_quic(METRICS_QUIC_DROP_CID_TOO_LONG);
        return;
    }

    /* A server never answers a Version Negotiation packet: two endpoints that
     * disagree would bounce them forever (RFC 9000 §6.1). Receiving one at all
     * means a broken or hostile peer, since we never send a packet with an
     * unknown version. */
    if (quic_invariants_is_version_negotiation(&inv)) {
        metrics_quic(METRICS_QUIC_DROP_PEER_VN);
        return;
    }

    quicconn_t* conn = quiccidtable_lookup_acquire(ep->table, &inv.dcid);
    if (conn != NULL) {
        __route(ep, conn, dgram);
        /* The reference the lookup took under the shard lock, which is what
         * stopped the connection being freed between finding it and using it. */
        connection_s_dec(&conn->conn);
        return;
    }

    if (!inv.long_header) {
        /* The peer believes it has a connection that we do not. Left alone it
         * would keep retransmitting into the void until its idle timeout;
         * a stateless reset ends it now. */
        __send_stateless_reset(ep, dgram, &inv);
        return;
    }

    /* Everything below opens, or tries to open, a connection.
     *
     * RFC 9000 §14.1: a datagram carrying an Initial must be at least 1200
     * bytes, and the server must discard smaller ones. That single rule is also
     * what keeps the endpoint from being an amplifier -- every reply below is
     * far smaller than the datagram that triggered it. */
    if (dgram->len < QUIC_MIN_INITIAL_DATAGRAM) {
        metrics_quic(METRICS_QUIC_DROP_SHORT_INITIAL);
        return;
    }

    if (inv.version != QUIC_VERSION_1) {
        __send_version_negotiation(ep, dgram, &inv);
        return;
    }

    /* Our version, big enough, no connection: a new one.
     *
     * The packet type is not inspected. A Handshake or 0-RTT packet for a
     * connection we never had would also land here, and quicconn_accept will
     * fail to make sense of it -- which is the right disposition for it
     * anyway, since without the Initial there are no keys to read it with. */
    if (ep->conn_count >= __quic_max_connections) {
        metrics_quic(METRICS_QUIC_DROP_NO_BUDGET);
        return;
    }

    __accept(ep, dgram, &inv);
}

static int __endpoint_read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    quicendpoint_t* ep = (quicendpoint_t*)ctx->listener;

    for (int round = 0; round < QUIC_RX_MAX_BATCHES; round++) {
        const int n = udp_rx_batch_recv(ep->rx, ep->fd);

        /* Never return 0: that would close the endpoint, and a datagram-level
         * failure must not take down the socket every connection shares. Same
         * reasoning as __listener_read for accept(). */
        if (n <= 0) break;

        metrics_quic(METRICS_QUIC_RECV_CALLS);

        for (int i = 0; i < n; i++)
            __dispatch(ep, udp_rx_batch_get(ep->rx, (size_t)i));

        /* A short batch means the socket is drained. */
        if ((size_t)n < __quic_rx_batch) break;
    }

    return 1;
}

static int __endpoint_close(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    /* Never NULL: __endpoint_create is the only thing that builds this
     * connection, and it always passes &ep->listener to connection_s_alloc.
     * (connection_s_alloc does accept a NULL listener -- connection_s_create_local
     * uses that -- but such a connection has no read/write/close and never
     * reaches here.) */
    quicendpoint_t* ep = (quicendpoint_t*)ctx->listener;

    connection_s_lock(connection, LOCK_SITE_CLOSE);

    /* Detach before freeing: the loop may close the endpoint socket directly
     * (shutdown, socket error), and without this ep->listener.connection would
     * dangle by the time quicendpoints_free runs. */
    if (ep->listener.connection == connection)
        ep->listener.connection = NULL;

    if (!ep->listener.api->control_del(connection))
        log_error("Quic endpoint: connection not removed from api\n");

    atomic_store(&ctx->detached, 1);

    close(connection->fd);
    ep->fd = -1;
    ep->listening = 0;

    atomic_store(&ctx->destroyed, 1);

    if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_s_unlock(connection);

    return 1;
}

/* ---- Lifecycle ---- */

static quicendpoint_t* __endpoint_get(quicendpoint_t* endpoints, in_addr_t ip,
                                      unsigned short int port) {
    while (endpoints != NULL) {
        const struct sockaddr_in* sa = (const struct sockaddr_in*)&endpoints->local;

        if (sa->sin_family == AF_INET && sa->sin_addr.s_addr == ip &&
            ntohs(sa->sin_port) == port)
            return endpoints;

        endpoints = endpoints->next;
    }

    return NULL;
}

static void __endpoint_free(quicendpoint_t* ep) {
    if (ep == NULL) return;

    if (ep->listener.connection != NULL) {
        if (ep->listening) {
            ep->listener.connection->close(ep->listener.connection);
        }
        else {
            /* Never registered (a failure partway through creation): release it
             * directly. Going through close() would call control_del on an fd
             * epoll never held. */
            connection_free(ep->listener.connection);
        }

        ep->listener.connection = NULL;
    }

    if (ep->fd != -1) {
        close(ep->fd);
        ep->fd = -1;
    }

    udp_rx_batch_free(ep->rx);
    cqueue_clear(&ep->listener.servers);
    free(ep);
}

static quicendpoint_t* __endpoint_create(mpxapi_t* api, server_t* server) {
    quicendpoint_t* ep = malloc(sizeof * ep);
    if (ep == NULL) return NULL;

    memset(ep, 0, sizeof * ep);
    ep->fd = -1;
    ep->table = __quic_table;
    ep->reset_key = __quic_reset_key;
    cqueue_init(&ep->listener.servers);

    int result = 0;

    struct sockaddr_in* sa = (struct sockaddr_in*)&ep->local;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = server->ip;
    sa->sin_port = htons(server->http3.port);
    ep->local_len = sizeof(struct sockaddr_in);

    const udp_socket_options_t options = {
        .reuseport = 1,
        .rcvbuf = __quic_rcvbuf,
        .sndbuf = __quic_sndbuf
    };

    ep->fd = udp_socket_create((const struct sockaddr*)&ep->local, ep->local_len, &options);
    if (ep->fd == -1) goto failed;

    ep->rx = udp_rx_batch_create(__quic_rx_batch, QUIC_RX_DATAGRAM_SIZE);
    if (ep->rx == NULL) goto failed;

    /* The endpoint's own connection carries no buffer: datagrams live in the
     * batch, not in the shared per-worker scratch that TCP connections use. */
    connection_t* connection = connection_s_alloc(&ep->listener, ep->fd, server->ip,
                                                  server->http3.port, server->ip,
                                                  server->http3.port, NULL, 0);
    if (connection == NULL) goto failed;

    connection->read = __endpoint_read;
    connection->write = NULL;
    connection->close = __endpoint_close;

    ep->listener.connection = connection;
    ep->listener.api = api;
    ep->listener.next = NULL;

    if (!cqueue_append(&ep->listener.servers, server)) goto failed;

    result = 1;

    failed:

    if (!result) {
        __endpoint_free(ep);
        ep = NULL;
    }

    return ep;
}

quicendpoint_t* quicendpoints_create(mpxapi_t* api, server_t* first_server, int* ok) {
    quicendpoint_t* head = NULL;
    quicendpoint_t* tail = NULL;

    if (ok != NULL) *ok = 1;

    if (__quic_table == NULL) {
        /* quic_policy_init() has not run or failed. Without the shared table
         * there is nothing to route to. */
        for (server_t* server = first_server; server != NULL; server = server->next) {
            if (server->http3.enabled) {
                log_error("Quic endpoint: http3 is configured but the QUIC policy is not initialised\n");
                if (ok != NULL) *ok = 0;
                return NULL;
            }
        }
        return NULL;
    }

    for (server_t* server = first_server; server != NULL; server = server->next) {
        if (!server->http3.enabled) continue;

        /* Several vhosts on one address share one endpoint, exactly as they
         * share one TCP listener; SNI picks the vhost inside the handshake. */
        quicendpoint_t* existing = __endpoint_get(head, server->ip, server->http3.port);
        if (existing != NULL) {
            if (!cqueue_append(&existing->listener.servers, server)) {
                if (ok != NULL) *ok = 0;
                goto failed;
            }
            continue;
        }

        quicendpoint_t* ep = __endpoint_create(api, server);
        if (ep == NULL) {
            log_error("Quic endpoint: cannot create endpoint on udp port %d\n",
                      server->http3.port);
            if (ok != NULL) *ok = 0;
            goto failed;
        }

        if (head == NULL) head = ep;
        if (tail != NULL) tail->next = ep;
        tail = ep;
    }

    return head;

    failed:

    quicendpoints_free(head);

    return NULL;
}

/* One endpoint's share of the worker tick: send what is queued, then age every
 * connection. Ordered that way so a connection that becomes dead in its tick is
 * closed after it has had the chance to put its CONNECTION_CLOSE on the wire. */
static void __endpoint_tick(quicendpoint_t* ep, int shutdown_now) {
    const uint64_t now = quic_now_us();

    /* Take the whole queue at once rather than popping under the lock per
     * connection: a handler thread pushing meanwhile simply starts a new one. */
    while (atomic_flag_test_and_set_explicit(&ep->tx_lock, memory_order_acquire))
        sched_yield();

    quicconn_t* pending = ep->tx_head;
    ep->tx_head = NULL;
    ep->tx_tail = NULL;

    atomic_flag_clear_explicit(&ep->tx_lock, memory_order_release);

    while (pending != NULL) {
        quicconn_t* next = pending->tx_next;
        pending->tx_next = NULL;
        pending->in_tx_queue = 0;

        connection_s_lock(&pending->conn, LOCK_SITE_QUIC_SEND);

        /* This is the path a handler thread's response arrives on: it set
         * need_write and queued the connection, and the filter chain has not
         * run yet. Running it here rather than in the handler thread keeps the
         * chain single-threaded per connection, as it is for h2. */
        connection_server_ctx_t* pctx = pending->conn.ctx;
        if (pctx->parser != NULL) h3conn_write(pctx->parser, pending);

        const int sent = quicconn_send(pending, now);
        if (sent) __h3_rearm(pending);

        if (!sent || pending->state == QUICCONN_DEAD)
            pending->conn.close(&pending->conn);
        else
            connection_s_unlock(&pending->conn);

        pending = next;
    }

    quicconn_t* conn = ep->conns;
    while (conn != NULL) {
        /* Captured first: the tick may close and free the connection. */
        quicconn_t* next = conn->ep_next;

        if (!connection_s_trylock(&conn->conn)) {
            conn = next;
            continue;
        }

        if (shutdown_now && conn->state == QUICCONN_ACTIVE)
            quicconn_close(conn, QUIC_NO_ERROR, 0, now);

        int alive = quicconn_tick(conn, now);
        if (alive && atomic_load_explicit(&conn->want_write, memory_order_acquire)) alive = quicconn_send(conn, now);

        if (!alive || conn->state == QUICCONN_DEAD) {
            metrics_quic(METRICS_QUIC_CONN_CLOSED);
            conn->conn.close(&conn->conn);
        }
        else {
            connection_s_unlock(&conn->conn);
        }

        conn = next;
    }
}

void quicendpoints_tick(quicendpoint_t* endpoints, int shutdown_now) {
    while (endpoints != NULL) {
        __endpoint_tick(endpoints, shutdown_now);
        endpoints = endpoints->next;
    }
}

int quicendpoints_listen(quicendpoint_t* endpoints) {
    while (endpoints != NULL) {
        if (endpoints->listener.connection == NULL) return 0;

        /* MPXIN only: a UDP socket has no peer to hang up, so MPXRDHUP would
         * never fire, and there is no write path here -- phase 1 answers a
         * datagram inline on the read path. */
        if (!endpoints->listener.api->control_add(endpoints->listener.connection,
                                                  MPXIN))
            return 0;

        endpoints->listening = 1;
        endpoints = endpoints->next;
    }

    return 1;
}

void quicendpoints_unlisten(quicendpoint_t* endpoints) {
    while (endpoints != NULL) {
        if (endpoints->listener.connection != NULL) {
            endpoints->listener.connection->close(endpoints->listener.connection);
            endpoints->listener.connection = NULL;
            endpoints->listening = 0;
        }

        endpoints = endpoints->next;
    }
}

void quicendpoints_free(quicendpoint_t* endpoints) {
    while (endpoints != NULL) {
        quicendpoint_t* next = endpoints->next;
        __endpoint_free(endpoints);
        endpoints = next;
    }
}

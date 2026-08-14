#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "appconfig.h"
#include "log.h"
#include "metrics.h"
#ifdef CWFR_HQ_INTEROP
#include "hq.h"
#include "quictls.h"
#endif
/* The full connection type: the header pair is deliberately opaque in both
 * directions (quicconn.h holds a `struct quicendpoint*`, quicendpoint.h a
 * `struct quicconn*`), so exactly one of the two .c files has to see both. */
#include "quicbeacon.h"
#include "quicconn.h"
#include "quiccrypto.h"
#include "quicendpoint.h"
#include "quichp.h"
#include "quicinvariants.h"
#include "quicpacket.h"
#include "quicretry.h"
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
/* Handshakes still in progress on one endpoint before Retry switches on in
 * `auto` mode. Below it a Retry would cost every honest client a round trip to
 * defend against an attack that is not happening. */
#define QUIC_DEFAULT_RETRY_THRESHOLD 1000
/* How long a token stays good. A Retry token is echoed back within a round
 * trip, so seconds is generous; a NEW_TOKEN is meant for the client's *next*
 * connection, which may be tomorrow. */
#define QUIC_RETRY_TOKEN_LIFETIME_US (10ULL * 1000000ULL)
#define QUIC_DEFAULT_TOKEN_LIFETIME_SEC 86400

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
static void __endpoint_tick(quicendpoint_t* ep, int shutdown_now);

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

/* Address validation (RFC 9000 §8.1). Its own key, not the stateless reset
 * one: the two authenticate different things to different audiences, and a
 * single key would make a token forgeable by anyone who could collect resets. */
static uint8_t  __quic_token_key[32];
typedef enum { QUIC_RETRY_AUTO = 0, QUIC_RETRY_ALWAYS, QUIC_RETRY_NEVER } quic_retry_mode_e;
static quic_retry_mode_e __quic_retry_mode = QUIC_RETRY_AUTO;
static size_t   __quic_retry_threshold = QUIC_DEFAULT_RETRY_THRESHOLD;
static uint64_t __quic_token_lifetime_us =
    (uint64_t)QUIC_DEFAULT_TOKEN_LIFETIME_SEC * 1000000ULL;
static int      __quic_new_token = 1;

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
    .initcwnd_packets       = QUICCC_INITIAL_WINDOW_PACKETS,
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

    /* RFC 9002 §7.2 has ten; the ceiling of 64 datagrams is where a burst
     * stops being a tuning choice and starts being an attack on the path. */
    p->initcwnd_packets =
        __policy_u64("http3_initcwnd_packets", QUICCC_INITIAL_WINDOW_PACKETS,
                     QUICCC_MIN_WINDOW_PACKETS, 64);

    if (p->initcwnd_packets != QUICCC_INITIAL_WINDOW_PACKETS)
        log_error("quic: http3_initcwnd_packets is %llu, not the %d RFC 9002 §7.2 "
                  "recommends -- every connection opens with a burst of that many datagrams\n",
                  (unsigned long long)p->initcwnd_packets, QUICCC_INITIAL_WINDOW_PACKETS);

    p->pacing = env_get_int("http3_pacing", 1) != 0;

    p->amplification_factor =
        __policy_u64("http3_amplification_factor", QUIC_DEFAULT_AMPLIFICATION, 1, 16);

    if (p->amplification_factor != QUIC_DEFAULT_AMPLIFICATION)
        log_error("quic: http3_amplification_factor is %llu, not the %d RFC 9000 §8.1 "
                  "requires -- this server can be used to amplify traffic at a spoofed address\n",
                  (unsigned long long)p->amplification_factor, QUIC_DEFAULT_AMPLIFICATION);
}

int quic_policy_init(void) {
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

    __quic_handshake_rate = env_get_int("http3_handshake_rate", QUIC_DEFAULT_HANDSHAKE_RATE);
    if (__quic_handshake_rate < 0) __quic_handshake_rate = 0;
    __quic_handshake_burst = env_get_int("http3_handshake_burst", QUIC_DEFAULT_HANDSHAKE_BURST);
    if (__quic_handshake_burst < 1) __quic_handshake_burst = 1;

    const char* retry = env_get_string("http3_retry", "auto");
    __quic_retry_mode = strcmp(retry, "always") == 0 ? QUIC_RETRY_ALWAYS
                      : strcmp(retry, "never") == 0  ? QUIC_RETRY_NEVER
                                                     : QUIC_RETRY_AUTO;

    int64_t threshold = env_get_int("http3_retry_threshold", QUIC_DEFAULT_RETRY_THRESHOLD);
    if (threshold < 0) threshold = 0;
    __quic_retry_threshold = (size_t)threshold;

    int64_t token_life = env_get_int("http3_token_lifetime_sec",
                                     QUIC_DEFAULT_TOKEN_LIFETIME_SEC);
    if (token_life < 1) token_life = 1;
    __quic_token_lifetime_us = (uint64_t)token_life * 1000000ULL;

    __quic_new_token = env_get_int("http3_new_token", 1) != 0;

    /* ---- Everything below is created once per process ---- *
     *
     * A reload calls this function again, and must not rebuild any of it.
     *
     * The keys are the reason §5 of docs/http3/07 asks for this: a stateless
     * reset token is HMAC(reset_key, cid) and a NEW_TOKEN is sealed under
     * token_key, both handed to peers that keep them. Rolling the keys turns
     * every token already in the world into noise -- a peer that gets a reset
     * no longer recognises one and retransmits into the void until its idle
     * timeout, and a client presenting a NEW_TOKEN pays the Retry round trip it
     * was given the token to avoid.
     *
     * The table is the reason it would have been a bug rather than a
     * degradation. Endpoints borrow the pointer at creation, and a soft reload
     * leaves the previous workers draining their connections through those
     * endpoints -- so freeing it here would have pulled the routing table out
     * from under live connections, and rebuilding it would have lost every
     * mapping in it besides.
     *
     * What this costs: http3_max_connections no longer takes effect on a
     * reload, because the table is sized from it. That is the honest trade --
     * resizing means rehashing a structure other threads are reading -- and it
     * is why nothing frees this. Process exit does not either: the shutdown
     * grace window can expire with a worker still inside the endpoint, and
     * freeing under that worker turns an orderly exit into a use-after-free.
     * A static pointer is not a leak by LSan's definition. */
    if (__quic_table != NULL) return 1;

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

    if (RAND_bytes(__quic_token_key, sizeof __quic_token_key) != 1) {
        log_error("quic_policy_init: RAND_bytes failed for the token key\n");
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

    /* Printed once per process, never on a reload. That is the observable form
     * of the paragraph above: seeing it twice would mean the keys rolled and
     * every token in the world went stale. */
    log_info("quic: connection table and keys created (%llu connections)\n",
             (unsigned long long)max_connections);

    return 1;
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
size_t quicendpoint_new_token(const struct sockaddr* peer, socklen_t peer_len,
                              uint8_t* out, size_t cap) {
    if (!__quic_new_token || peer == NULL || out == NULL) return 0;

    return quic_token_write(out, cap, __quic_token_key, QUIC_TOKEN_NEW_TOKEN,
                            peer, peer_len, NULL, quic_now_us());
}

int quicendpoint_cid_register(quicendpoint_t* endpoint, const quiccid_t* cid,
                              quicconn_t* conn) {
    if (endpoint == NULL || cid == NULL || conn == NULL) return 0;

    return quiccidtable_insert(endpoint->table, cid, conn) == QUICCIDTABLE_OK;
}

void quicendpoint_cid_forget(quicendpoint_t* endpoint, const quiccid_t* cid) {
    if (endpoint == NULL || cid == NULL) return;

    quiccidtable_remove(endpoint->table, cid);
}

int quicendpoint_reset_token(const quiccid_t* cid, uint8_t out[16]) {
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

    if (!quicendpoint_reset_token(&inv->dcid, packet + len - 16)) {
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

/* ---- Replies that create no connection but do need our keys ---- */

/* A Retry packet: "prove you can receive at this address, then come back"
 * (RFC 9000 §8.1.2).
 *
 * Costs the server nothing to remember -- the whole state is in the token the
 * client echoes back -- which is exactly why it is the answer to a flood of
 * spoofed Initials. It costs an honest client one round trip, so it is a
 * response to load rather than a default. */
static void __send_retry(quicendpoint_t* ep, const udp_datagram_t* dgram,
                         const quicinvariants_t* inv) {
    uint8_t token[QUIC_TOKEN_MAX_LEN];
    const size_t token_len =
        quic_token_write(token, sizeof token, __quic_token_key, QUIC_TOKEN_RETRY,
                         (const struct sockaddr*)&dgram->peer, dgram->peer_len,
                         &inv->dcid, quic_now_us());
    if (token_len == 0) return;

    /* Our new Source Connection ID. The client will address the retried
     * handshake to it, and it goes into retry_source_connection_id so the
     * client can check that the Retry was not injected. */
    quiccid_t scid;
    scid.len = QUIC_LOCAL_CID_LEN;
    if (RAND_bytes(scid.data, QUIC_LOCAL_CID_LEN) != 1) return;

    uint8_t packet[256];
    const size_t len = quicretry_write(packet, sizeof packet, &inv->dcid,
                                       &inv->scid, &scid, token, token_len);
    if (len == 0) return;

    const ssize_t sent = udp_send(ep->fd, packet, len,
                                  (const struct sockaddr*)&dgram->peer, dgram->peer_len,
                                  dgram->local_valid ? &dgram->local : NULL);
    if (sent < 0) {
        metrics_quic(METRICS_QUIC_SEND_ERROR);
        return;
    }

    metrics_quic(METRICS_QUIC_RETRY_SENT);
    metrics_quic(METRICS_QUIC_DGRAM_SENT);
    metrics_quic_add(METRICS_QUIC_BYTES_SENT, (unsigned long long)sent);
}

/* An Initial packet carrying nothing but CONNECTION_CLOSE.
 *
 * Used where the server will not open a connection for a reason the client can
 * act on -- it is full, or the token it presented is one of ours and no longer
 * valid. Silence would leave the client retransmitting into a void for its
 * whole handshake timeout; this way it fails at once and can go elsewhere.
 *
 * Deliberately not used against a flood: it derives keys and builds a packet
 * per datagram, which is work done for whoever is sending them. The rate
 * budget drops those without a word (docs/http3/07 §4). */
static void __send_initial_close(quicendpoint_t* ep, const udp_datagram_t* dgram,
                                 const quicinvariants_t* inv, uint64_t error) {
    uint8_t client_secret[32];
    uint8_t server_secret[32];
    if (!quiccrypto_initial_secrets(&inv->dcid, client_secret, server_secret)) return;

    quickeys_t keys;
    memset(&keys, 0, sizeof keys);

    if (!quickeys_install(&keys, QUIC_AEAD_AES_128_GCM, server_secret, sizeof server_secret)) {
        explicit_bzero(client_secret, sizeof client_secret);
        explicit_bzero(server_secret, sizeof server_secret);
        return;
    }

    quicframe_t f;
    memset(&f, 0, sizeof f);
    f.type = QUIC_FRAME_CONNECTION_CLOSE;
    f.u.close.error = error;

    uint8_t payload[64];
    const size_t plen = quicframe_write(payload, sizeof payload, &f);

    quicpkt_hdr_out_t hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = QUIC_PKT_INITIAL;
    hdr.version = QUIC_VERSION_1;
    /* Addressed to the id the client chose for itself, from the id it used for
     * us: the mirror of what it sent, since no connection exists to have ids of
     * its own. */
    hdr.dcid = (quiccid_t*)&inv->scid;
    hdr.scid = (quiccid_t*)&inv->dcid;
    hdr.pn = 0;
    hdr.pn_len = 1;
    hdr.payload_len = plen + QUIC_AEAD_TAG_LEN;

    uint8_t packet[256];
    size_t pn_offset = 0;
    const size_t header_len = quicpkt_write_header(packet, sizeof packet, &hdr, &pn_offset);

    size_t sealed = 0;
    const int ok = plen > 0 && header_len > 0 &&
                   quiccrypto_seal(&keys, 0, packet, header_len, payload, plen,
                                   packet + header_len, &sealed) &&
                   quichp_apply(&keys, packet, header_len + sealed, pn_offset, 1);

    if (ok) {
        const ssize_t sent = udp_send(ep->fd, packet, header_len + sealed,
                                      (const struct sockaddr*)&dgram->peer, dgram->peer_len,
                                      dgram->local_valid ? &dgram->local : NULL);
        if (sent < 0) metrics_quic(METRICS_QUIC_SEND_ERROR);
        else {
            metrics_quic(METRICS_QUIC_DGRAM_SENT);
            metrics_quic_add(METRICS_QUIC_BYTES_SENT, (unsigned long long)sent);
        }
    }

    quickeys_free(&keys);
    explicit_bzero(client_secret, sizeof client_secret);
    explicit_bzero(server_secret, sizeof server_secret);
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

    /* The in-process stand's network emulator, when there is one. Checked
     * before the descriptor because that endpoint has none (quicendpoint.h). */
    if (endpoint->send_hook != NULL)
        return endpoint->send_hook(endpoint->send_hook_arg, data, len, path);

    if (endpoint->fd == -1) return -1;

    const struct sockaddr* peer = (const struct sockaddr*)&path->remote;
    const struct sockaddr_storage* local = path->local_len > 0 ? &path->local : NULL;

    if (endpoint->tx_batch != NULL) {
        int queued = udp_tx_batch_add(endpoint->tx_batch, data, len, peer,
                                      path->remote_len, local);

        /* Full, or a datagram too big for a slot. The first is answered by
         * making room; the second never happens for QUIC (a slot is a whole
         * datagram) and falls through to the single send below, which reports
         * EMSGSIZE honestly. */
        if (queued == 0 && udp_tx_batch_count(endpoint->tx_batch) > 0) {
            quicendpoint_send_flush(endpoint);
            queued = udp_tx_batch_add(endpoint->tx_batch, data, len, peer,
                                      path->remote_len, local);
        }

        if (queued == 1) return (ssize_t)len;
    }

    const ssize_t sent = udp_send(endpoint->fd, data, len, peer,
                                  path->remote_len, local);

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

void quicendpoint_send_flush(quicendpoint_t* endpoint) {
    if (endpoint == NULL || endpoint->tx_batch == NULL || endpoint->fd == -1) return;

    const size_t queued = udp_tx_batch_count(endpoint->tx_batch);
    if (queued == 0) return;

    size_t bytes = 0;
    const int sent = udp_tx_batch_flush(endpoint->tx_batch, endpoint->fd, &bytes);

    if (sent < 0) {
        metrics_quic_add(METRICS_QUIC_SEND_ERROR, (unsigned long long)queued);
        return;
    }

    /* Counted here rather than at queue time, so the metric keeps meaning what
     * it always meant: datagrams the kernel took. What it refused is loss, and
     * loss recovery is what answers for it. */
    if (sent > 0) {
        metrics_quic_add(METRICS_QUIC_DGRAM_SENT, (unsigned long long)sent);
        metrics_quic_add(METRICS_QUIC_BYTES_SENT, (unsigned long long)bytes);
    }

    QUICBEACON("TX    datagrams=%d bytes=%zu", sent, bytes);

    if ((size_t)sent < queued)
        metrics_quic_add(METRICS_QUIC_SEND_ERROR,
                         (unsigned long long)(queued - (size_t)sent));
}

void quicendpoint_wake(quicendpoint_t* endpoint, struct quicconn* conn) {
    if (endpoint == NULL || conn == NULL) return;

    /* Already queued: nothing to add, and nothing to lock. This is the common
     * case by far -- a response asks to be sent once per chunk written -- and
     * taking the endpoint's queue lock to learn it cost more than the queueing
     * itself (docs/http3/08 §7f). */
    if (atomic_exchange_explicit(&conn->in_tx_queue, 1, memory_order_acq_rel) == 0) {
        /* A leaf lock held for a handful of instructions. It exists because
         * this is reachable from a handler thread, which must not be holding --
         * or waiting for -- the connection lock at this point. */
        while (atomic_flag_test_and_set_explicit(&endpoint->tx_lock, memory_order_acquire))
            sched_yield();

        conn->tx_next = NULL;

        if (endpoint->tx_tail != NULL) endpoint->tx_tail->tx_next = conn;
        else endpoint->tx_head = conn;

        endpoint->tx_tail = conn;

        atomic_flag_clear_explicit(&endpoint->tx_lock, memory_order_release);
    }

    /* And wake the worker -- once. Outside the lock: the write is a syscall,
     * and the queue must not be held across one.
     *
     * Only the producer that finds no wakeup outstanding pays for it. The
     * worker clears the flag before it drains the queue, so a response queued
     * after that clear finds the flag down and writes its own wakeup: a
     * response can be late by one turn, never lost. */
    if (endpoint->eventfd >= 0 &&
        !atomic_exchange_explicit(&endpoint->wake_pending, 1, memory_order_acq_rel)) {
        const uint64_t one = 1;
        if (write(endpoint->eventfd, &one, sizeof one) != (ssize_t)sizeof one) {
            /* Nothing was said, so nothing may be assumed: put the flag back or
             * the next response would stay silent too. EAGAIN here means the
             * counter is saturated, which already means a wakeup is coming, but
             * the cheap correct move is the same either way. */
            atomic_store_explicit(&endpoint->wake_pending, 0, memory_order_release);
        }
    }
}

listener_t* quicendpoint_listener(quicendpoint_t* endpoint) {
    return endpoint != NULL ? &endpoint->listener : NULL;
}

int quicendpoint_fd(quicendpoint_t* endpoint) {
    return endpoint != NULL ? endpoint->fd : -1;
}

uint32_t quicendpoint_kernel_drops(const quicendpoint_t* endpoint) {
    return endpoint != NULL ? endpoint->kernel_drops : 0;
}

void quicendpoint_recv_gap_reset(quicendpoint_t* endpoint) {
    if (endpoint == NULL) return;

    endpoint->max_recv_gap_us = 0;
    endpoint->last_recv_us = quic_now_us();

    endpoint->rx_dwell_max_us = 0;
    endpoint->rx_dwell_sum_us = 0;
    endpoint->rx_dwell_count = 0;
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

    /* Whatever this connection queued last -- and that is normally its
     * CONNECTION_CLOSE -- goes out before the state behind it disappears. The
     * turn would flush anyway; doing it here costs one syscall per closing
     * connection and removes a whole class of "the goodbye was built and never
     * left" from every future caller. */
    quicendpoint_send_flush(endpoint);

    /* One line per connection, at the only moment that can report the whole of
     * it (docs/http3/08 §7b).
     *
     * `rx_overflow` is what the kernel dropped on this socket while the
     * connection was alive. It is here rather than in the process-wide metric
     * because the question it answers -- does a big transfer starve the receive
     * path, and is that why the *next* connection fails to be accepted -- needs
     * it attributed to a connection and a duration. Sampling /metrics between
     * transfers cannot answer it: the pause that sampling introduces is enough
     * for the worker to drain the queue, and the effect disappears.
     *
     * At info, not debug: a line per connection is what a busy server can
     * afford, and 25 % of this server's CPU under a large transfer went to
     * debug-level formatting when that was left on by accident. */
    const uint32_t overflow = quicendpoint_kernel_drops(endpoint) - conn->rx_overflow_at_accept;
    const uint64_t now = quic_now_us();
    const uint64_t lived_ms = conn->accepted_us > 0 && now > conn->accepted_us
                              ? (now - conn->accepted_us) / 1000 : 0;

    const uint64_t dwell_avg = endpoint->rx_dwell_count > 0
        ? endpoint->rx_dwell_sum_us / endpoint->rx_dwell_count : 0;

    log_info("quic: conn cid=%02x%02x%02x%02x closed after %llu ms, "
             "rx_overflow=%u, max_rx_gap=%llu us, rx=%llu dgrams, "
             "rx_dwell=%llu/%llu us avg/max, "
             "streams=%zu, pto=%u, srtt=%llu us\n",
             conn->odcid.data[0], conn->odcid.data[1],
             conn->odcid.data[2], conn->odcid.data[3],
             (unsigned long long)lived_ms, overflow,
             (unsigned long long)endpoint->max_recv_gap_us,
             (unsigned long long)endpoint->rx_dwell_count,
             (unsigned long long)dwell_avg,
             (unsigned long long)endpoint->rx_dwell_max_us, conn->stream_count,
             conn->loss.pto_count,
             (unsigned long long)conn->loss.smoothed_rtt_us);

    /* Reset with the report: the next connection's figure has to be its own. */
    endpoint->max_recv_gap_us = 0;
    endpoint->rx_dwell_max_us = 0;
    endpoint->rx_dwell_sum_us = 0;
    endpoint->rx_dwell_count = 0;

    /* Every id this connection answers to, so a datagram in flight cannot find
     * it after this returns. */
    for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++)
        if (conn->local_cids[i].active)
            quiccidtable_remove(endpoint->table, &conn->local_cids[i].cid);

    quiccidtable_remove(endpoint->table, &conn->odcid);

    /* A connection that dies mid-handshake still leaves the count, or `auto`
     * would ratchet up to permanent Retry after enough failed handshakes. */
    if (conn->state == QUICCONN_HANDSHAKE && endpoint->handshakes_in_flight > 0)
        endpoint->handshakes_in_flight--;

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
            atomic_store_explicit(&conn->in_tx_queue, 0, memory_order_release);
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
                     const quicinvariants_t* inv,
                     int address_validated, const quiccid_t* retry_odcid) {
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

    quicconn_t* conn = quicconn_accept(ep, &inv->dcid, &inv->scid, &path, server,
                                       address_validated, retry_odcid);
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
    ep->handshakes_in_flight++;

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

#ifdef CWFR_HQ_INTEROP
    if (quictls_alpn_is_hq(&conn->tls)) {
        if (hq_has_pending(conn)) quicconn_want_write(&conn->conn);
        return;
    }
#endif

    if (ctx->parser == NULL) return;

    if (h3conn_has_pending(ctx->parser, conn)) quicconn_want_write(&conn->conn);
}

/* Read, dispatch and write for one connection. Called with the connection lock
 * held, which is what makes the dispatch inside reach the inline publish path
 * rather than the handler-thread one. Returns 0 if the connection must close. */
static int __h3_turn(quicconn_t* conn, uint64_t now) {
#ifdef CWFR_HQ_INTEROP
    /* The interop shim: a different application protocol on the same streams,
     * chosen by ALPN at the handshake. It keeps no connection object, so it
     * bypasses the attach above entirely -- and ctx->parser stays NULL, which
     * matters because that pointer's type is protocol-dependent and everything
     * that reads it assumes h3. */
    if (conn->state == QUICCONN_ACTIVE && quictls_alpn_is_hq(&conn->tls)) {
        uint64_t hq_error = 0;
        if (!hq_turn(conn, &hq_error)) {
            quicconn_close(conn, hq_error, 1, now);
            return 0;
        }
        return 1;
    }
#endif

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

    /* Handshakes still in progress are what `http3_retry: auto` watches, and
     * this is the one place that sees a connection leave that state. */
    const int was_handshaking = conn->state == QUICCONN_HANDSHAKE;

    int alive = quicconn_recv(conn, dgram->data, dgram->len, &path, now);

    if (was_handshaking && conn->state != QUICCONN_HANDSHAKE &&
        ep->handshakes_in_flight > 0)
        ep->handshakes_in_flight--;

    /* Run this connection's timers here as well as on the worker sweep.
     *
     * The sweep is a once-a-second walk of every connection; QUIC's timers are
     * a PTO, and on any real path that is tens of milliseconds. A deadline that
     * falls between two sweeps is a deadline that fires up to a second late --
     * measured, not supposed: a probe armed 27 ms out was still unfired when
     * the test gave up two seconds later, and the connection that was waiting
     * on it stalled for good.
     *
     * Doing it on the receive path costs nothing (the connection is locked and
     * being worked on already) and gives every connection that is exchanging
     * anything at all timer resolution equal to its traffic. A connection that
     * has gone completely silent still depends on the sweep -- closing that gap
     * needs the endpoint timerfd of docs/http3/01 §7, armed from
     * quicconn_next_timeout(). */
    if (alive) alive = quicconn_tick(conn, now);
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

    /* The kernel's own drop counter is cumulative, so what is reported is the
     * step since the last datagram that carried it. Wrap-around is handled by
     * unsigned arithmetic; a step that huge means something else is wrong
     * anyway. */
    if (dgram->drops_valid) {
        if (dgram->drops != ep->kernel_drops) {
            metrics_quic_add(METRICS_QUIC_DROP_KERNEL_OVERFLOW,
                             (uint32_t)(dgram->drops - ep->kernel_drops));
            ep->kernel_drops = dgram->drops;
        }
    }

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

        /* Counted and, at debug level, said out loud. The counter is the right
         * instrument in production, but it needs `/metrics`, and the one place
         * this question gets asked -- an interop endpoint serving no HTTP
         * routes -- has nowhere to serve it from. Without a line here, "the
         * server never saw that datagram" and "the server dropped it silently"
         * look identical in a log (docs/http3/08 §3n). */
        log_debug("quic: drop short_initial len=%zu\n", dgram->len);
        return;
    }

    if (inv.version != QUIC_VERSION_1) {
        __send_version_negotiation(ep, dgram, &inv);
        return;
    }

    /* The address validation token, if the client echoed one back. Only the
     * first packet of the datagram is looked at: a token rides on the Initial,
     * and an Initial is what starts a datagram that opens a connection. */
    const uint8_t* pkt_token = NULL;
    size_t pkt_token_len = 0;
    {
        size_t off = 0;
        quicpkt_t first;
        quicpkt_status_e pst;

        if (quicpkt_next(dgram->data, dgram->len, &off, QUIC_LOCAL_CID_LEN, &first, &pst) &&
            first.type == QUIC_PKT_INITIAL) {
            pkt_token = first.token;
            pkt_token_len = first.token_len;
        }
    }

    /* Our version, big enough, no connection: a new one.
     *
     * The packet type is not inspected. A Handshake or 0-RTT packet for a
     * connection we never had would also land here, and quicconn_accept will
     * fail to make sense of it -- which is the right disposition for it
     * anyway, since without the Initial there are no keys to read it with. */
    if (ep->draining) {
        /* §5 of docs/http3/07: a server on its way out says so rather than
         * going quiet, so the client can go elsewhere immediately instead of
         * retransmitting its Initial for a handshake timeout. */
        metrics_quic(METRICS_QUIC_AT_CAPACITY);
        __send_initial_close(ep, dgram, &inv, QUIC_CONNECTION_REFUSED);
        return;
    }

    if (ep->conn_count >= __quic_max_connections) {
        metrics_quic(METRICS_QUIC_AT_CAPACITY);
        /* Told, not dropped. Being full is not an attack, and a client that
         * knows can go elsewhere now instead of at its handshake timeout. */
        __send_initial_close(ep, dgram, &inv, QUIC_CONNECTION_REFUSED);
        return;
    }

    /* Address validation (§8.1). Three outcomes: the client presented a token
     * we issued, so its address is proven and it is accepted; it presented
     * nothing (or something stale) and the load says ask for proof, so it gets
     * a Retry; or it presented one of our Retry tokens that no longer holds,
     * which is the one case §8.1.3 answers with INVALID_TOKEN. */
    quiccid_t retry_odcid;
    int validated = 0;
    int have_retry_odcid = 0;

    if (pkt_token_len > 0) {
        const uint64_t now = quic_now_us();
        quic_token_status_e st =
            quic_token_read(pkt_token, pkt_token_len, __quic_token_key, QUIC_TOKEN_RETRY,
                            (const struct sockaddr*)&dgram->peer, dgram->peer_len,
                            now, QUIC_RETRY_TOKEN_LIFETIME_US, &retry_odcid);

        if (st == QUIC_TOKEN_OK) {
            validated = 1;
            have_retry_odcid = 1;
            metrics_quic(METRICS_QUIC_TOKEN_VALID);
        }
        else if (st == QUIC_TOKEN_EXPIRED || st == QUIC_TOKEN_WRONG_ADDR) {
            /* Ours, and no longer usable. §8.1.3 wants this said out loud
             * rather than turned into another Retry: a client looping on a
             * token it cannot fix would never get anywhere. */
            metrics_quic(METRICS_QUIC_TOKEN_INVALID);
            __send_initial_close(ep, dgram, &inv, QUIC_INVALID_TOKEN);
            return;
        }
        else {
            /* WRONG_KIND means a NEW_TOKEN from an earlier connection; BAD
             * means not ours at all -- a token from a server that restarted, or
             * noise. Neither is an error: the client simply has not proven this
             * address, and falls through to the Retry decision. */
            st = quic_token_read(pkt_token, pkt_token_len, __quic_token_key,
                                 QUIC_TOKEN_NEW_TOKEN,
                                 (const struct sockaddr*)&dgram->peer, dgram->peer_len,
                                 now, __quic_token_lifetime_us, NULL);

            if (st == QUIC_TOKEN_OK) {
                validated = 1;
                metrics_quic(METRICS_QUIC_TOKEN_VALID);
            }
            else
                metrics_quic(METRICS_QUIC_TOKEN_INVALID);
        }
    }

    if (!validated && __quic_retry_mode != QUIC_RETRY_NEVER &&
        (__quic_retry_mode == QUIC_RETRY_ALWAYS ||
         ep->handshakes_in_flight >= __quic_retry_threshold)) {
        __send_retry(ep, dgram, &inv);
        return;
    }

    /* Spent last, after every cheaper reason to drop this datagram: a packet
     * that was never going to open a connection must not consume the budget
     * that decides whether real ones can.
     *
     * Dropped, not refused: answering costs an Initial key derivation and a
     * packet per arriving datagram -- work performed for whoever is flooding
     * us, at an address we have not validated. The client's own
     * retransmissions handle the rest. */
    if (!__budget_spend(&ep->handshake_tokens, &ep->handshake_epoch_us,
                        __quic_handshake_rate, __quic_handshake_burst)) {
        metrics_quic(METRICS_QUIC_HANDSHAKE_RATE_LIMITED);
        log_debug("quic: drop handshake_rate_limited\n");
        return;
    }

    __accept(ep, dgram, &inv, validated, have_retry_odcid ? &retry_odcid : NULL);
}

/* Arm the endpoint's timer for the earliest deadline any of its connections
 * has, or disarm it when none has one.
 *
 * A walk of the connection list rather than a heap. The plan (`01` §6) calls
 * for a heap keyed by deadline, and at a hundred thousand connections it will
 * be needed; at the scale this has been run to, a walk over a list the worker
 * already owns costs less than maintaining the heap would, and it cannot go out
 * of step with the connections the way a cached key can. The moment to swap is
 * when this shows up in a profile, and the counter that would show it is the
 * lock-wait histogram on quic.send. */
static void __endpoint_timer_arm(quicendpoint_t* ep) {
    if (ep->timerfd < 0) return;

    uint64_t earliest = 0;

    for (quicconn_t* conn = ep->conns; conn != NULL; conn = conn->ep_next) {
        const uint64_t when = quicconn_next_timeout(conn);
        if (when != 0 && (earliest == 0 || when < earliest)) earliest = when;
    }

    if (earliest == ep->timer_deadline_us) return;   /* already armed for it */

    struct itimerspec its;
    memset(&its, 0, sizeof its);

    if (earliest != 0) {
        /* Absolute, on the same clock quic_now_us reads, so no drift creeps in
         * between computing the deadline and arming for it. A deadline already
         * in the past must still fire, and a zero it_value would disarm the
         * timer instead -- hence the one-nanosecond floor. */
        const uint64_t now = quic_now_us();
        const uint64_t delay_us = earliest > now ? earliest - now : 0;

        its.it_value.tv_sec = (time_t)(delay_us / 1000000ULL);
        its.it_value.tv_nsec = (long)((delay_us % 1000000ULL) * 1000ULL);
        if (its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0)
            its.it_value.tv_nsec = 1;
    }

    if (timerfd_settime(ep->timerfd, 0, &its, NULL) == -1) {
        log_error("quicendpoint: timerfd_settime failed (errno %d)\n", errno);
        return;
    }

    ep->timer_deadline_us = earliest;
}

/* The endpoint's timer fired: run every connection's timers, then re-arm. */
static int __endpoint_timer_read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    quicendpoint_t* ep = (quicendpoint_t*)ctx->listener;

    uint64_t expirations;
    while (read(ep->timerfd, &expirations, sizeof expirations) == sizeof expirations) {
        /* drain -- level-triggered, and an unread timerfd refires forever */
    }

    ep->timer_deadline_us = 0;
    __endpoint_tick(ep, 0);
    __endpoint_timer_arm(ep);

    return 1;
}

/* The same teardown __endpoint_close performs, for the same reason: the close
 * callback is what removes the connection from epoll, closes its descriptor and
 * drops the base reference. A callback that only forgets the pointer leaves the
 * reference held, and the worker's shutdown loop -- which waits for
 * connection_count to reach zero -- then runs out its whole grace window every
 * time. That is exactly what it did. */
/* A handler thread finished a response: drain the send queue now rather than at
 * the next timer. */
static int __endpoint_wake_read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    quicendpoint_t* ep = (quicendpoint_t*)ctx->listener;

    uint64_t ticks;
    while (read(ep->eventfd, &ticks, sizeof ticks) == sizeof ticks) {
        /* drain -- level-triggered */
    }

    /* Before the drain below, never after: a response queued between this store
     * and the drain still finds the flag down and writes its own wakeup, while
     * clearing afterwards would let one slip in unseen and unannounced -- and
     * it would then wait for the timer. */
    atomic_store_explicit(&ep->wake_pending, 0, memory_order_release);

    __endpoint_tick(ep, 0);
    __endpoint_timer_arm(ep);

    return 1;
}

static int __endpoint_wake_close(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    quicendpoint_t* ep = (quicendpoint_t*)ctx->listener;

    connection_s_lock(connection, LOCK_SITE_CLOSE);

    if (ep->wake_connection == connection) ep->wake_connection = NULL;

    if (!ep->listener.api->control_del(connection))
        log_error("Quic endpoint: wake not removed from api\n");

    atomic_store(&ctx->detached, 1);

    close(connection->fd);
    ep->eventfd = -1;

    atomic_store(&ctx->destroyed, 1);

    if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_s_unlock(connection);

    return 1;
}

static int __endpoint_timer_close(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    quicendpoint_t* ep = (quicendpoint_t*)ctx->listener;

    connection_s_lock(connection, LOCK_SITE_CLOSE);

    if (ep->timer_connection == connection) ep->timer_connection = NULL;

    if (!ep->listener.api->control_del(connection))
        log_error("Quic endpoint: timer not removed from api\n");

    atomic_store(&ctx->detached, 1);

    close(connection->fd);
    ep->timerfd = -1;
    ep->timer_deadline_us = 0;

    atomic_store(&ctx->destroyed, 1);

    if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_s_unlock(connection);

    return 1;
}

static int __endpoint_read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    quicendpoint_t* ep = (quicendpoint_t*)ctx->listener;

    /* Before the first read, not after the last: what is being measured is how
     * long the socket waited for us, and that interval ends here. */
    const uint64_t entered_us = quic_now_us();

    if (ep->last_recv_us != 0) {
        const uint64_t gap = entered_us - ep->last_recv_us;
        if (gap > ep->max_recv_gap_us) ep->max_recv_gap_us = gap;
    }

    ep->last_recv_us = entered_us;

    /* Realtime, because the kernel stamps datagrams with CLOCK_REALTIME and
     * quic_now_us() is monotonic. One reading per wakeup, not per datagram:
     * the batch is drained in microseconds, and the syscall is a vDSO call
     * either way. */
    struct timespec wall;
    const int wall_ok = clock_gettime(CLOCK_REALTIME, &wall) == 0;
    const uint64_t wall_us = wall_ok
        ? (uint64_t)wall.tv_sec * 1000000ULL + (uint64_t)wall.tv_nsec / 1000ULL : 0;

    for (int round = 0; round < QUIC_RX_MAX_BATCHES; round++) {
        const int n = udp_rx_batch_recv(ep->rx, ep->fd);

        /* Never return 0: that would close the endpoint, and a datagram-level
         * failure must not take down the socket every connection shares. Same
         * reasoning as __listener_read for accept(). */
        if (n <= 0) break;

        metrics_quic(METRICS_QUIC_RECV_CALLS);

        for (int i = 0; i < n; i++) {
            udp_datagram_t* dgram = udp_rx_batch_get(ep->rx, (size_t)i);

            if (wall_ok && dgram != NULL && dgram->stamp_valid &&
                wall_us > dgram->stamp_us) {
                const uint64_t dwell = wall_us - dgram->stamp_us;

                if (dwell > ep->rx_dwell_max_us) ep->rx_dwell_max_us = dwell;
                ep->rx_dwell_sum_us += dwell;
                ep->rx_dwell_count++;
            }

            __dispatch(ep, dgram);
        }

        /* A short batch means the socket is drained. */
        if ((size_t)n < __quic_rx_batch) break;
    }

    /* The answers to everything just dispatched, in one syscall (§7d). Before
     * arming the timer, because a deadline computed while a flight is still in
     * our own buffer would be measuring from the wrong moment. */
    quicendpoint_send_flush(ep);

    /* Deadlines move with every datagram -- an acknowledgement disarms a PTO, a
     * new packet arms one -- so the timer is re-armed once the batch is done
     * rather than per datagram. */
    __endpoint_timer_arm(ep);

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

    if (ep->wake_connection != NULL) {
        if (ep->listening) ep->wake_connection->close(ep->wake_connection);
        else               connection_free(ep->wake_connection);

        ep->wake_connection = NULL;
    }

    if (ep->eventfd != -1) {
        close(ep->eventfd);
        ep->eventfd = -1;
    }

    if (ep->timer_connection != NULL) {
        if (ep->listening) ep->timer_connection->close(ep->timer_connection);
        else               connection_free(ep->timer_connection);

        ep->timer_connection = NULL;
    }

    if (ep->timerfd != -1) {
        close(ep->timerfd);
        ep->timerfd = -1;
    }

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
        /* Last chance for anything still queued -- a CONNECTION_CLOSE from the
         * shutdown, most likely -- because after this there is no socket. */
        quicendpoint_send_flush(ep);

        close(ep->fd);
        ep->fd = -1;
    }

    udp_rx_batch_free(ep->rx);
    udp_tx_batch_free(ep->tx_batch);
    cqueue_clear(&ep->listener.servers);
    free(ep);
}

static quicendpoint_t* __endpoint_create(mpxapi_t* api, server_t* server) {
    quicendpoint_t* ep = malloc(sizeof * ep);
    if (ep == NULL) return NULL;

    memset(ep, 0, sizeof * ep);
    ep->fd = -1;
    ep->timerfd = -1;
    ep->eventfd = -1;
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

    /* Same depth as the receive batch: what arrives in one turn is roughly what
     * leaves in one, and both are bounded by the worker's visit rather than by
     * memory. */
    ep->tx_batch = udp_tx_batch_create(__quic_rx_batch, QUIC_RX_DATAGRAM_SIZE);
    if (ep->tx_batch == NULL) goto failed;

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

    /* The deadline timer, as a second connection on the same listener. Created
     * disarmed: there is nothing to wait for until a connection exists. */
    ep->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (ep->timerfd == -1) goto failed;

    ep->timer_connection = connection_s_alloc(&ep->listener, ep->timerfd,
                                              server->ip, server->http3.port,
                                              server->ip, server->http3.port, NULL, 0);
    if (ep->timer_connection == NULL) goto failed;

    ep->timer_connection->read = __endpoint_timer_read;
    ep->timer_connection->write = NULL;
    ep->timer_connection->close = __endpoint_timer_close;

    ep->eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ep->eventfd == -1) goto failed;

    ep->wake_connection = connection_s_alloc(&ep->listener, ep->eventfd,
                                             server->ip, server->http3.port,
                                             server->ip, server->http3.port, NULL, 0);
    if (ep->wake_connection == NULL) goto failed;

    ep->wake_connection->read = __endpoint_wake_read;
    ep->wake_connection->write = NULL;
    ep->wake_connection->close = __endpoint_wake_close;

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

        /* Before the work, never after: a response published between this store
         * and the turn below is served by that turn, while one published after
         * it finds the flag down and queues the connection afresh. Clearing it
         * afterwards would lose exactly the responses that arrive while we
         * work. */
        atomic_store_explicit(&pending->in_tx_queue, 0, memory_order_release);

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

        if (shutdown_now && conn->state == QUICCONN_ACTIVE) {
            connection_server_ctx_t* cctx = conn->conn.ctx;
            h3conn_t* h3 = cctx != NULL ? cctx->parser : NULL;

            if (h3 == NULL) {
                /* Bare QUIC with nothing above it: there is no request to
                 * finish, so there is nothing to wait for. */
                quicconn_close(conn, QUIC_NO_ERROR, 0, now);
            }
            else {
                /* Told once, then given time. h3session_accepts_request already
                 * refuses anything past the id in the GOAWAY, so the drain is
                 * bounded by the requests that were already running -- and by
                 * the worker's own grace window, which closes the socket under
                 * us if they take too long. */
                (void)h3conn_goaway(h3, conn);

                if (h3conn_requests_in_flight(h3, conn) == 0)
                    quicconn_close(conn, QUIC_NO_ERROR, 0, now);
                else
                    atomic_store_explicit(&conn->want_write, 1, memory_order_release);
            }
        }

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

    /* Everything the turn produced leaves here, in one syscall (§7d). Every
     * caller of this function ends its own turn with it, so this single line
     * covers the timer, the wake queue and the worker's sweep. */
    quicendpoint_send_flush(ep);
}

void quicendpoints_tick(quicendpoint_t* endpoints, int shutdown_now) {
    while (endpoints != NULL) {
        __endpoint_tick(endpoints, shutdown_now);
        __endpoint_timer_arm(endpoints);

        /* The drain is over for this endpoint: nothing is left to serve, so the
         * socket can go. Until it does the worker's connection_count cannot
         * reach zero, which is precisely what keeps the loop running long
         * enough for the drain to happen. */
        if (endpoints->draining && endpoints->conn_count == 0 &&
            endpoints->listener.connection != NULL) {
            if (endpoints->wake_connection != NULL) {
                endpoints->wake_connection->close(endpoints->wake_connection);
                endpoints->wake_connection = NULL;
            }

            if (endpoints->timer_connection != NULL) {
                endpoints->timer_connection->close(endpoints->timer_connection);
                endpoints->timer_connection = NULL;
            }

            endpoints->listener.connection->close(endpoints->listener.connection);
            endpoints->listener.connection = NULL;
            endpoints->listening = 0;
        }

        endpoints = endpoints->next;
    }
}

void quicendpoints_drain(quicendpoint_t* endpoints) {
    while (endpoints != NULL) {
        endpoints->draining = 1;
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

        if (endpoints->timer_connection != NULL &&
            !endpoints->listener.api->control_add(endpoints->timer_connection, MPXIN))
            return 0;

        if (endpoints->wake_connection != NULL &&
            !endpoints->listener.api->control_add(endpoints->wake_connection, MPXIN))
            return 0;

        endpoints->listening = 1;
        endpoints = endpoints->next;
    }

    return 1;
}

void quicendpoints_unlisten(quicendpoint_t* endpoints) {
    while (endpoints != NULL) {
        if (endpoints->wake_connection != NULL) {
            endpoints->wake_connection->close(endpoints->wake_connection);
            endpoints->wake_connection = NULL;
        }

        if (endpoints->timer_connection != NULL) {
            endpoints->timer_connection->close(endpoints->timer_connection);
            endpoints->timer_connection = NULL;
        }

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

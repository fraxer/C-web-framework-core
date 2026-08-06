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
#include "quicendpoint.h"
#include "quicinvariants.h"
#include "quictime.h"

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

/* ---- Process-wide policy ----
 *
 * Plain globals, read from every worker. Safe only because quic_policy_init()
 * runs before any worker thread exists -- the same contract h2_policy_init()
 * holds (moduleloader.c). */

static quiccidtable_t* __quic_table = NULL;
static uint8_t  __quic_reset_key[32];
static size_t   __quic_rx_batch = 32;
static int      __quic_rcvbuf = 0;
static int      __quic_sndbuf = 0;
static int64_t  __quic_vn_rate = QUIC_DEFAULT_VN_RATE;
static int64_t  __quic_vn_burst = QUIC_DEFAULT_VN_BURST;
static int64_t  __quic_reset_rate = QUIC_DEFAULT_RESET_RATE;
static int64_t  __quic_reset_burst = QUIC_DEFAULT_RESET_BURST;

int quic_policy_init(void) {
    /* A reload calls this again; drop the previous table rather than leak it.
     * Connections do not survive a reload, so nothing is orphaned. */
    quic_policy_free();

    int64_t max_connections = env_get_int("http3_max_connections", QUIC_DEFAULT_MAX_CONNECTIONS);
    if (max_connections < 64) max_connections = 64;
    if (max_connections > 4000000) max_connections = 4000000;

    int64_t batch = env_get_int("http3_rx_batch", 32);
    if (batch < 1) batch = 1;
    if (batch > 256) batch = 256;
    __quic_rx_batch = (size_t)batch;

    __quic_rcvbuf = env_get_int("http3_so_rcvbuf", 0);
    __quic_sndbuf = env_get_int("http3_so_sndbuf", 0);

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
     * limit. */
    __quic_table = quiccidtable_create((size_t)max_connections * 4, 64, seed, NULL);
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

/* ---- Routing ---- */

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

    void* connection = quiccidtable_lookup_acquire(ep->table, &inv.dcid);
    if (connection != NULL) {
        /* Phase 4 hands the datagram to the connection here. Nothing can reach
         * this branch yet: no code inserts into the table until connections
         * exist. */
        metrics_quic(METRICS_QUIC_DROP_UNKNOWN_CID);
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

    /* Our version, big enough, no connection: this would start one. Creating it
     * needs the TLS handshake, which arrives in phase 3. Counted rather than
     * silently dropped -- an h3 build before phase 3 is reachable but cannot
     * accept anyone, and this counter is what says so out loud.
     *
     * The packet type is not inspected: reading it means decoding a
     * version-1 header, which belongs to the v1 codec of phase 2. So a
     * Handshake or 0-RTT packet for a connection we never had lands here too,
     * which is the right disposition for it in any case. */
    metrics_quic(METRICS_QUIC_INITIAL_NO_TLS);
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

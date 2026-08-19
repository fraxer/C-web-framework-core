#include "framework.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "quicclient.h"
#include "quiccc.h"
#include "quiccidtable.h"
#include "quicconn.h"
#include "quicendpoint.h"
#include "quicinvariants.h"
#include "quicloss.h"
#include "quicqlog.h"
#include "quicstream.h"
#include "quictime.h"

/* The deterministic in-process stand (docs/http3/08-testing.md §2).
 *
 * ## What this is for
 *
 * A real server connection (quicconn_t, built by quicconn_accept, driven by
 * quicconn_recv / quicconn_tick / quicconn_send) and the test client of
 * tests/quicclient, in one process, with an emulated path between them and a
 * clock the test winds forward.
 *
 * The reason is arithmetic. Everything RFC 9002 defines -- the PTO and its
 * exponent, persistent congestion, the idle timeout, the 3xPTO periods -- is
 * defined in elapsed time, and against a live server those are seconds to
 * minutes each. Worse, a live path either loses nothing (loopback) or loses at
 * random, so the interesting cases are reproduced by waiting and hoping: one
 * evening of this project cost five hypotheses, each checked by a two-minute
 * run that reproduced one time in three, and four of the five were wrong.
 * Nothing about that is a property of QUIC; it is a property of testing it
 * through a socket and a wall clock.
 *
 * Here the clock is a variable and the path is a queue. A PTO exponent is six
 * assertions and a millisecond, and a failure repeats exactly.
 *
 * ## What is emulated, and what is real
 *
 * Real: the server's transport in full -- packet building, header protection,
 * the real TLS 1.3 handshake through OpenSSL, loss detection, congestion
 * control, the connection id table, the connection_t lifecycle including
 * close and free. The stand replicates the *ordering* of quicendpoint.c's
 * __route (recv, tick, send) and nothing else about it.
 *
 * Not real: HTTP/3. The endpoint attaches h3conn after the handshake, and that
 * pulls in the handler threads, the vhost and the response filter chain -- all
 * of which have their own tests, none of which has an opinion about a PTO. The
 * stand writes to a stream directly instead, which is what h3 would do anyway.
 *
 * Not real: the datagram's journey. There is no socket; quicendpoint_send and
 * the client's transport are both diverted into the queue below.
 *
 * ## Determinism
 *
 * Two sources of surprise are closed. The clock is injected
 * (quic_time_set_source), so nothing observes the machine's. The path's
 * decisions come from a seeded xorshift and from nothing else -- and the
 * seed is fixed per scenario, so a failure is a failure every time.
 *
 * Connection ids and TLS secrets are still drawn from the real RNG. They
 * change nothing: no scheduling decision here depends on their value, only on
 * datagram sizes and the order of calls, both of which are fixed. */

/* ---- Virtual time ---- */

static uint64_t __now_us = 0;

static uint64_t __clock(void) {
    return __now_us;
}

/* ---- The emulated path ---- */

#define STAND_MAX_DGRAM 2048
/* Deep enough for a congestion window's worth of datagrams in flight plus the
 * duplicates and held-back copies the emulator can add. */
#define STAND_MAX_QUEUE 1024

typedef struct standpkt {
    uint8_t  data[STAND_MAX_DGRAM];
    size_t   len;
    uint64_t due_us;
    /* When the bottleneck link starts putting this datagram on the wire. Until
     * then it is sitting in the queue, and that is what makes the queue's depth
     * a number rather than a guess. Equal to the moment it was sent when there
     * is no bandwidth limit. */
    uint64_t start_us;
    /* Total order among datagrams due at the same instant, so "which arrives
     * first" is never left to the queue's internal layout. */
    uint64_t seq;
    int      to_server;
    int      used;
} standpkt_t;

/* How many departures to remember, for the tests that assert on the *timing*
 * of what the server sent rather than on what arrived. A PTO exponent is
 * exactly that: the datagrams are dropped by definition, and the only evidence
 * is when they were handed to the path. */
#define STAND_MAX_MARKS 64

/* How many outgoing datagram lengths to remember. Enough for a transfer of a
 * couple of megabytes; the counter stops rather than wrapping, because a
 * wrapped sequence would report runs that never existed. */
#define STAND_MAX_DGRAM_LOG 4096

typedef struct stand {
    /* ---- path ---- */
    standpkt_t q[STAND_MAX_QUEUE];
    uint64_t   seq;
    uint64_t   rng;

    uint64_t delay_us;          /* one way */
    unsigned loss_to_server_pct;
    unsigned loss_to_client_pct;
    unsigned dup_pct;
    unsigned reorder_pct;
    uint64_t reorder_extra_us;  /* how late a reordered datagram is */

    /* ---- The bottleneck (0 = an infinitely fast path, as above) ---- *
     *
     * A link with a rate and a queue in front of it, which is a different thing
     * from a link that loses at random and tests different code. Random loss
     * asks "does recovery work"; a queue asks "does the sender stay inside the
     * path", and a sender that does not gets its own overflow back as loss --
     * congestion signal and consequence in one. That is the shape of the
     * interop path (`simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25`),
     * where this project has already been bitten twice: §3i's sender emptied a
     * whole flow-control window into a queue that held a twentieth of it, and
     * the peer received under a tenth of what was sent.
     *
     * One rate and one queue for both directions: the interop model is
     * symmetric, and two of each would be two more numbers to explain. */
    uint64_t bandwidth_bps;
    size_t   queue_pkts;
    /* When the link finishes what it is transmitting, per direction. A datagram
     * handed over before then waits. */
    uint64_t link_free_to_server;
    uint64_t link_free_to_client;

    /* Scripted, not random: "lose the server's first flight" is a scenario,
     * not a probability. */
    unsigned drop_next_to_client;
    unsigned drop_next_to_server;
    /* And "lose exactly the second datagram", by ordinal (1-based, 0 = never).
     * A ClientHello now spans two datagrams, and which of the two is lost makes
     * a different case: the first leaves the server with a hole it can do
     * nothing about, the second leaves it holding a prefix it cannot answer. */
    uint64_t drop_nth_to_server;
    /* Hold one datagram back by `reorder_extra_us`, again by ordinal, so a
     * flight can be made to arrive in the wrong order exactly once. A
     * percentage cannot express that: rolling on every datagram delays them
     * all equally and reorders nothing. */
    uint64_t delay_nth_to_server;
    int      blackhole_to_server;   /* everything, until cleared */
    int      blackhole_to_client;

    uint64_t sent_to_server, sent_to_client;
    uint64_t lost_to_server, lost_to_client;
    uint64_t delivered_to_server, delivered_to_client;
    /* Tail drops, counted apart from the losses above. The cause is different --
     * the sender's own overrun rather than the path's misfortune -- and a test
     * that could not tell them apart would report the sender's bug as bad luck. */
    uint64_t queue_dropped_to_server, queue_dropped_to_client;
    uint64_t overflowed;            /* the queue was full: a test bug, not a path */

    uint64_t marks[STAND_MAX_MARKS];   /* when the server handed over a datagram */
    size_t   mark_count;

    /* The length of every datagram the server handed to the path, in order.
     * A GSO run is built from exactly this sequence and ends at the first
     * change of size (udpsocket.c), so whether the sender can be offloaded at
     * all is a property visible here and nowhere else in the stand
     * (docs/http3/08 §12). */
    uint16_t dgram_len[STAND_MAX_DGRAM_LOG];
    size_t   dgram_logged;
    uint64_t ticks;                    /* server timer sweeps run */

    /* Print every event as it happens: what left, what arrived, what was
     * dropped, and every timer sweep, all stamped with the virtual clock.
     * Off by default, and the first thing to turn on when a scenario fails --
     * it is the whole log of the connection, in order, in one screen. */
    int trace;

    /* ---- server ---- */
    mpxapi_t        api;
    server_t        server;
    openssl_t       ossl;
    quicendpoint_t  ep;
    quiccidtable_t* table;
    quicconn_t*     conn;
    int             conn_gone;
    uint64_t        conn_gone_us;

    quicpath_t client_path;

    /* ---- client ---- */
    quicclient_t client;
    int          client_failed;
} stand_t;

static void __trace(stand_t* s, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void __trace(stand_t* s, const char* fmt, ...) {
    if (!s->trace) return;

    printf("      [%8llu] ", (unsigned long long)__now_us);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/* xorshift64*, like the client's: reproducible from the seed alone, and
 * untouched by whatever else in the process calls rand(). */
static unsigned __roll(stand_t* s) {
    uint64_t x = s->rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    s->rng = x;

    return (unsigned)((x * 2685821657736338717ULL) >> 33) % 100u;
}

static standpkt_t* __slot(stand_t* s) {
    for (size_t i = 0; i < STAND_MAX_QUEUE; i++)
        if (!s->q[i].used) return &s->q[i];

    return NULL;
}

static void __schedule(stand_t* s, const uint8_t* data, size_t len,
                       int to_server, uint64_t start_us, uint64_t due_us) {
    standpkt_t* p = __slot(s);
    if (p == NULL) {
        s->overflowed++;
        return;
    }

    memcpy(p->data, data, len);
    p->len = len;
    p->start_us = start_us;
    p->due_us = due_us;
    p->seq = s->seq++;
    p->to_server = to_server;
    p->used = 1;
}

/* Datagrams in this direction that the link has not begun transmitting: the
 * queue, exactly, rather than an estimate from the backlog in time. */
static size_t __backlog(const stand_t* s, int to_server) {
    size_t n = 0;

    for (size_t i = 0; i < STAND_MAX_QUEUE; i++) {
        const standpkt_t* p = &s->q[i];
        if (p->used && p->to_server == to_server && p->start_us > __now_us) n++;
    }

    return n;
}

/* One datagram enters the path. Whether it comes out the other end, when, and
 * how many times, is decided here and only here. */
static void __net_send(stand_t* s, const uint8_t* data, size_t len, int to_server) {
    if (len == 0 || len > STAND_MAX_DGRAM) return;

    if (to_server) s->sent_to_server++;
    else s->sent_to_client++;

    unsigned* scripted = to_server ? &s->drop_next_to_server : &s->drop_next_to_client;
    const int blackhole = to_server ? s->blackhole_to_server : s->blackhole_to_client;
    const unsigned loss = to_server ? s->loss_to_server_pct : s->loss_to_client_pct;

    const int nth_drop = to_server && s->drop_nth_to_server != 0 &&
                         s->sent_to_server == s->drop_nth_to_server;

    if (blackhole || *scripted > 0 || nth_drop) {
        if (*scripted > 0) (*scripted)--;
        if (to_server) s->lost_to_server++;
        else s->lost_to_client++;
        __trace(s, "%s %zu bytes DROPPED (scripted)\n",
                to_server ? "c->s" : "s->c", len);
        return;
    }

    /* The roll is taken only when the direction is lossy at all, so switching
     * loss on in one direction does not shift the other direction's sequence. */
    if (loss > 0 && __roll(s) < loss) {
        if (to_server) s->lost_to_server++;
        else s->lost_to_client++;
        __trace(s, "%s %zu bytes LOST\n", to_server ? "c->s" : "s->c", len);
        return;
    }

    /* Through the bottleneck, if there is one: wait for the link, then take the
     * time the bytes actually need on it, then fly. */
    uint64_t start = __now_us;
    uint64_t serialise = 0;

    if (s->bandwidth_bps > 0) {
        if (s->queue_pkts > 0 && __backlog(s, to_server) >= s->queue_pkts) {
            /* Tail drop, which is what a full queue does -- and the only
             * congestion signal the sender is going to get. */
            if (to_server) s->queue_dropped_to_server++;
            else s->queue_dropped_to_client++;

            __trace(s, "%s %zu bytes DROPPED (queue full)\n",
                    to_server ? "c->s" : "s->c", len);
            return;
        }

        uint64_t* link_free = to_server ? &s->link_free_to_server
                                        : &s->link_free_to_client;

        if (*link_free > start) start = *link_free;

        serialise = (uint64_t)len * 8 * 1000000ULL / s->bandwidth_bps;
        *link_free = start + serialise;
    }

    uint64_t due = start + serialise + s->delay_us;

    /* Reordering as extra delay rather than as a swap: a swap needs a
     * successor to swap with, so it silently does nothing to the last datagram
     * of a flight -- which is the one whose reordering matters. */
    if (s->reorder_pct > 0 && __roll(s) < s->reorder_pct)
        due += s->reorder_extra_us;

    if (to_server && s->delay_nth_to_server != 0 &&
        s->sent_to_server == s->delay_nth_to_server)
        due += s->reorder_extra_us;

    __schedule(s, data, len, to_server, start, due);
    __trace(s, "%s %zu bytes, due %llu%s\n", to_server ? "c->s" : "s->c", len,
            (unsigned long long)due,
            start > __now_us ? " (queued)" : "");

    /* A duplicate arrives just after the original, never before: that is what
     * a retransmitting middlebox does, and it keeps the order total. */
    if (s->dup_pct > 0 && __roll(s) < s->dup_pct)
        __schedule(s, data, len, to_server, start, due + 1);
}

/* The server's only way out (quicendpoint.h's send hook). */
static ssize_t __server_out(void* arg, const uint8_t* data, size_t len,
                            const struct quicpath* path) {
    stand_t* s = arg;

    (void)path;   /* one client, one path; migration moves client_path instead */

    /* One mark per instant, not per datagram: a flight of three leaves at the
     * same microsecond, and counting them separately would report a gap of
     * zero where nothing happened at all. */
    if (s->mark_count < STAND_MAX_MARKS &&
        (s->mark_count == 0 || s->marks[s->mark_count - 1] != __now_us))
        s->marks[s->mark_count++] = __now_us;

    if (s->dgram_logged < STAND_MAX_DGRAM_LOG)
        s->dgram_len[s->dgram_logged++] = (uint16_t)len;

    __net_send(s, data, len, 0);

    return (ssize_t)len;
}

/* And the client's. */
static void __client_out(void* arg, const uint8_t* data, size_t len) {
    __net_send((stand_t*)arg, data, len, 1);
}

/* ---- The server side ---- */

static int __control_add(connection_t* connection, int events) {
    (void)connection; (void)events;

    return 1;
}

static int __control_mod(connection_t* connection, int events) {
    (void)connection; (void)events;

    return 1;
}

static int __control_del(connection_t* connection) {
    (void)connection;

    return 1;
}

/* What the real table does under its shard lock: hold a reference so the
 * connection cannot be freed between the lookup and the use. */
static void __table_acquire(void* value) {
    connection_s_inc(&((quicconn_t*)value)->conn);
}

static void __conn_release(stand_t* s) {
    s->conn = NULL;
    s->conn_gone = 1;
    s->conn_gone_us = __now_us;
}

/* Route by connection id, exactly as the endpoint does -- not by "there is only
 * one connection". The difference is the whole point of a test that issues and
 * retires connection ids: an id that was announced but never registered routes
 * nowhere, and only a real lookup can tell. */
static quicconn_t* __lookup_or_accept(stand_t* s, const uint8_t* data, size_t len) {
    quicinvariants_t inv;
    if (quic_invariants_parse(data, len, QUIC_LOCAL_CID_LEN, &inv) != QUICINV_OK)
        return NULL;

    quicconn_t* conn = quiccidtable_lookup_acquire(s->table, &inv.dcid);
    if (conn != NULL) return conn;              /* holds a reference */

    if (!inv.long_header || len < QUIC_MIN_INITIAL_DATAGRAM) return NULL;
    if (s->conn != NULL) return NULL;           /* one connection per stand */

    conn = quicconn_accept(&s->ep, &inv.dcid, &inv.scid, &s->client_path,
                           &s->server, 0, NULL);
    if (conn == NULL) return NULL;

    /* Both ids, like __accept: the client addresses the id we chose from its
     * next packet on, but anything already in flight still carries its own. */
    if (quiccidtable_insert(s->table, &conn->local_cids[0].cid, conn) != QUICCIDTABLE_OK ||
        quiccidtable_insert(s->table, &conn->odcid, conn) != QUICCIDTABLE_OK) {
        quiccidtable_remove(s->table, &conn->local_cids[0].cid);
        quiccidtable_remove(s->table, &conn->odcid);
        quicconn_free(conn);
        return NULL;
    }

    conn->ep_next = s->ep.conns;
    s->ep.conns = conn;
    s->ep.conn_count++;

    s->conn = conn;

    /* The reference a lookup would have taken, so the caller's release is the
     * same on both paths. */
    connection_s_inc(&conn->conn);

    return conn;
}

static void __server_recv(stand_t* s, const uint8_t* data, size_t len) {
    quicconn_t* conn = __lookup_or_accept(s, data, len);
    if (conn == NULL) return;

    connection_s_lock(&conn->conn, LOCK_SITE_QUIC_RECV);

    int alive = quicconn_recv(conn, data, len, &s->client_path, __now_us);

    /* The order quicendpoint.c's __route holds: receive, run the timers (the
     * connection is locked and hot, so it is free), then build packets. The
     * h3 turn that sits between the last two is what the stand leaves out. */
    if (alive) alive = quicconn_tick(conn, __now_us);
    if (!quicconn_send(conn, __now_us)) alive = 0;

    if (!alive || conn->state == QUICCONN_DEAD) {
        conn->conn.close(&conn->conn);   /* releases the lock */
        __conn_release(s);
    }
    else
        connection_s_unlock(&conn->conn);

    if (s->conn != NULL)
        __trace(s, "server after recv: crypto in I len=%zu consumed=%zu; "
                   "crypto unsent I/H %zu/%zu, keys_hs %d, "
                   "state %d, in flight I/H/A %llu/%llu/%llu, "
                   "budget %llu, timer %llu\n",
                conn->tls.in[QUIC_ENC_INITIAL].len,
                conn->tls.in[QUIC_ENC_INITIAL].consumed,
                quicsendbuf_unsent_bytes(&conn->crypto_out[QUIC_ENC_INITIAL]),
                quicsendbuf_unsent_bytes(&conn->crypto_out[QUIC_ENC_HANDSHAKE]),
                conn->tx[QUIC_ENC_HANDSHAKE].valid,
                (int)conn->state,
                (unsigned long long)conn->loss.space[QUIC_ENC_INITIAL].ack_eliciting_in_flight,
                (unsigned long long)conn->loss.space[QUIC_ENC_HANDSHAKE].ack_eliciting_in_flight,
                (unsigned long long)conn->loss.space[QUIC_ENC_APP].ack_eliciting_in_flight,
                (unsigned long long)conn->amplification_budget,
                (unsigned long long)quicconn_next_timeout(conn));

    /* The lookup's reference. After a close this is the one that frees it. */
    connection_s_dec(&conn->conn);
}

/* The endpoint's send queue: what quicconn_want_write puts a connection on.
 *
 * In the server this is a queue plus an eventfd -- a handler thread finishes a
 * response, queues the connection and wakes the worker, which sends. Left out
 * of the stand, "the application produced something" is not an event at all,
 * and a response sits in the stream until an unrelated timer happens to fire:
 * the first version of this file waited out the 30-second idle timeout for
 * exactly that reason, and the transfer looked like a stalled congestion
 * window. */
static int __server_pending_tx(const stand_t* s) {
    return s->ep.tx_head != NULL;
}

static void __server_flush(stand_t* s) {
    quicconn_t* conn = s->ep.tx_head;
    if (conn == NULL) return;

    s->ep.tx_head = conn->tx_next;
    if (s->ep.tx_tail == conn) s->ep.tx_tail = NULL;
    conn->tx_next = NULL;
    conn->in_tx_queue = 0;

    __trace(s, "flush (want_write)\n");

    connection_s_lock(&conn->conn, LOCK_SITE_QUIC_SEND);

    const int sent = quicconn_send(conn, __now_us);

    if (!sent || conn->state == QUICCONN_DEAD) {
        conn->conn.close(&conn->conn);
        __conn_release(s);
    }
    else
        connection_s_unlock(&conn->conn);
}

/* The endpoint's timer path: no datagram, just the deadline that came due. */
static void __server_tick(stand_t* s) {
    quicconn_t* conn = s->conn;
    if (conn == NULL) return;

    s->ticks++;
    __trace(s, "tick (state %d, pto %u, cwnd %llu, inflight %llu)\n",
            (int)conn->state, conn->loss.pto_count,
            (unsigned long long)conn->cc.cwnd,
            (unsigned long long)conn->cc.bytes_in_flight);

    connection_s_lock(&conn->conn, LOCK_SITE_QUIC_SEND);

    int alive = quicconn_tick(conn, __now_us);
    if (!quicconn_send(conn, __now_us)) alive = 0;

    if (!alive || conn->state == QUICCONN_DEAD) {
        conn->conn.close(&conn->conn);
        __conn_release(s);
    }
    else
        connection_s_unlock(&conn->conn);
}

/* ---- The loop ---- */

static standpkt_t* __earliest(stand_t* s) {
    standpkt_t* best = NULL;

    for (size_t i = 0; i < STAND_MAX_QUEUE; i++) {
        standpkt_t* p = &s->q[i];
        if (!p->used) continue;

        if (best == NULL || p->due_us < best->due_us ||
            (p->due_us == best->due_us && p->seq < best->seq))
            best = p;
    }

    return best;
}

/* Is another datagram for the client due at this same instant? A burst is
 * acknowledged once, at its end -- acknowledging each datagram of a flight
 * separately is not what any real client does, and it hides exactly the
 * batching bugs that matter. */
static int __more_due_for_client(stand_t* s) {
    for (size_t i = 0; i < STAND_MAX_QUEUE; i++) {
        const standpkt_t* p = &s->q[i];
        if (p->used && !p->to_server && p->due_us <= __now_us) return 1;
    }

    return 0;
}

static void __deliver(stand_t* s, standpkt_t* p) {
    uint8_t data[STAND_MAX_DGRAM];
    const size_t len = p->len;
    const int to_server = p->to_server;

    memcpy(data, p->data, len);
    p->used = 0;

    if (to_server) {
        s->delivered_to_server++;
        __server_recv(s, data, len);
        return;
    }

    s->delivered_to_client++;

    if (!quicclient_deliver(&s->client, data, len)) {
        /* The client reports a close and a stateless reset the same way it
         * reports a failure -- by refusing to go on. Only the third one is a
         * failure of the stand; the other two are results a scenario may be
         * waiting for. */
        if (!s->client.close_received && !s->client.reset_received)
            s->client_failed = 1;
        return;
    }

    if (!__more_due_for_client(s) && !quicclient_flush(&s->client))
        s->client_failed = 1;
}

/* The next instant at which anything can happen: a datagram arriving or a
 * connection deadline coming due. 0 when the stand is quiet for good. */
static uint64_t __next_event(stand_t* s) {
    uint64_t t = 0;

    /* A woken endpoint has work now, not at a deadline. */
    if (__server_pending_tx(s)) return __now_us;

    const standpkt_t* p = __earliest(s);
    if (p != NULL) t = p->due_us;

    if (s->conn != NULL) {
        const uint64_t timer = quicconn_next_timeout(s->conn);
        if (timer != 0 && (t == 0 || timer < t)) t = timer;
    }

    /* The client has one timer of its own -- the probe that §6.2.2.1 makes its
     * responsibility. Without it in this list, a scenario that loses part of
     * the client's flight tests a client that cannot recover rather than a
     * server that has to. */
    const uint64_t client_timer = quicclient_next_timeout(&s->client);
    if (client_timer != 0 && (t == 0 || client_timer < t)) t = client_timer;

    /* "no connection" is spelled out rather than reported as a timer of zero.
     * The difference cost an hour: a zero here was read as "no probe timer is
     * armed" and sent the reader looking for a loss-recovery bug, when the
     * connection had simply been closed and freed two lines earlier. A trace
     * must print what tells the hypotheses apart. */
    if (s->conn == NULL)
        __trace(s, "next event at %llu (queued %s, connection gone)\n",
                (unsigned long long)t, p != NULL ? "yes" : "no");
    else
        __trace(s, "next event at %llu (queued %s, timer %llu)\n",
                (unsigned long long)t, p != NULL ? "yes" : "no",
                (unsigned long long)quicconn_next_timeout(s->conn));

    return t;
}

/* Advance to the next event and run it. Returns 0 when there is nothing
 * pending at all, or when `limit_us` would be passed -- in which case the
 * clock is moved to the limit, because "nothing happened for this long" is an
 * answer a test may be waiting for. */
static int __step(stand_t* s, uint64_t limit_us) {
    const uint64_t t = __next_event(s);

    if (t == 0 || t > limit_us) {
        if (limit_us > __now_us) __now_us = limit_us;
        return 0;
    }

    if (t > __now_us) __now_us = t;

    if (__server_pending_tx(s)) {
        __server_flush(s);
        return 1;
    }

    standpkt_t* p = __earliest(s);
    if (p != NULL && p->due_us <= __now_us) {
        __deliver(s, p);
        return 1;
    }

    /* The client's probe timer, before the server's: it is the side that has
     * been told to unblock the other. */
    const uint64_t client_timer = quicclient_next_timeout(&s->client);
    if (client_timer != 0 && client_timer <= __now_us) {
        __trace(s, "client PTO\n");

        if (!quicclient_tick(&s->client)) s->client_failed = 1;

        /* Same reason as the nudge below: a timer the tick did not move would
         * be reported at this instant forever. */
        if (quicclient_next_timeout(&s->client) == client_timer) __now_us = t + 1;

        return 1;
    }

    __server_tick(s);

    /* A deadline that survives its own sweep would be reported again at the
     * same instant, and the stand would step on it forever.
     *
     * Not a workaround: it is what a timerfd does. epoll_wait returns at or
     * after the deadline, never before, so a tick whose condition is `now >
     * deadline` sees a clock that has already moved on. The stand's clock only
     * moves when it is told to, so it is told to. */
    if (s->conn != NULL && quicconn_next_timeout(s->conn) == t) __now_us = t + 1;

    return 1;
}

/* Run for at most `horizon_us` of virtual time, stopping as soon as `done`
 * says so. Returns what `done` says at the end.
 *
 * The step budget is a deadlock guard, not a timeout: it fires only if the
 * stand keeps producing events without the clock moving, which is a bug in the
 * stand or a spin in the code under test. */
static int __run(stand_t* s, uint64_t horizon_us, int (*done)(stand_t*)) {
    const uint64_t limit = __now_us + horizon_us;

    for (int steps = 0; steps < 500000; steps++) {
        if (done != NULL && done(s)) return 1;
        if (s->client_failed) return 0;
        if (!__step(s, limit)) break;
    }

    return done == NULL ? 1 : done(s);
}

/* ---- Setup and teardown ---- */

static SSL_CTX* __server_ctx(void) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) return NULL;

    if (SSL_CTX_use_certificate_chain_file(ctx, TEST_QUIC_CERT) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, TEST_QUIC_KEY, SSL_FILETYPE_PEM) != 1 ||
        !SSL_CTX_check_private_key(ctx) ||
        !quictls_configure_ctx(ctx)) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

static void __addr(struct sockaddr_storage* ss, socklen_t* len,
                   const char* ip, uint16_t port) {
    struct sockaddr_in* in = (struct sockaddr_in*)ss;

    memset(ss, 0, sizeof * ss);
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
    inet_pton(AF_INET, ip, &in->sin_addr);
    *len = sizeof * in;
}

/* A stand with a clean 20 ms path (10 ms each way) and no impairment. Every
 * scenario starts here and then breaks exactly one thing. */
static stand_t* __stand_create(uint64_t seed) {
    stand_t* s = calloc(1, sizeof * s);
    if (s == NULL) return NULL;

    __now_us = 1000000;   /* not 0: a zero timestamp reads as "never" in places */
    quic_time_set_source(__clock);

    /* STAND_TRACE=1 in the environment turns the whole exchange into a log.
     * A switch rather than a rebuild because that is the difference between
     * asking the stand a question and editing it. */
    s->trace = getenv("STAND_TRACE") != NULL;

    s->rng = seed != 0 ? seed : 0x9e3779b97f4a7c15ULL;
    s->delay_us = 10000;
    s->reorder_extra_us = 25000;

    s->ossl.quic_ctx = __server_ctx();
    if (s->ossl.quic_ctx == NULL) {
        free(s);
        return NULL;
    }

    s->server.openssl = &s->ossl;

    s->api.control_add = __control_add;
    s->api.control_mod = __control_mod;
    s->api.control_del = __control_del;

    s->ep.fd = -1;
    s->ep.timerfd = -1;
    s->ep.eventfd = -1;
    s->ep.listener.api = &s->api;
    s->ep.send_hook = __server_out;
    s->ep.send_hook_arg = s;

    __addr(&s->ep.local, &s->ep.local_len, "127.0.0.1", 443);
    __addr(&s->client_path.remote, &s->client_path.remote_len, "127.0.0.1", 50000);
    s->client_path.local = s->ep.local;
    s->client_path.local_len = s->ep.local_len;

    /* Its own table, not the process-wide one: quic_policy_init needs a
     * configuration, and a test that shared the real table with another test
     * would be a test with state. */
    s->table = quiccidtable_create(64, 4, 0x5eed1234ULL, __table_acquire);
    if (s->table == NULL) {
        SSL_CTX_free(s->ossl.quic_ctx);
        free(s);
        return NULL;
    }

    s->ep.table = s->table;

    return s;
}

static void __stand_free(stand_t* s) {
    if (s == NULL) return;

    if (s->conn != NULL) {
        connection_s_lock(&s->conn->conn, LOCK_SITE_CLOSE);
        s->conn->conn.close(&s->conn->conn);
        s->conn = NULL;
    }

    quicclient_free(&s->client);
    quiccidtable_free(s->table);
    if (s->ossl.quic_ctx != NULL) SSL_CTX_free(s->ossl.quic_ctx);

    free(s);

    quic_time_set_source(NULL);
}

/* ---- Conditions ---- */

static int __handshake_done(stand_t* s) {
    return s->client.handshake_complete && s->client.handshake_done_received;
}

static int __conn_gone(stand_t* s) {
    return s->conn_gone;
}

static int __closed(stand_t* s) {
    return s->client.close_received;
}

static int __read_after_update(stand_t* s) {
    return s->client.read_after_update;
}

static int __challenged(stand_t* s) {
    return s->client.path_challenge_received;
}

static int __draining(stand_t* s) {
    return s->conn != NULL && s->conn->state == QUICCONN_DRAINING;
}

static int __stream0_reset(stand_t* s) {
    return quicclient_stream_reset(&s->client, 0, NULL, NULL);
}

/* The server has accepted the new address as the peer's. */
static int __migrated(stand_t* s) {
    if (s->conn == NULL) return 0;

    const struct sockaddr_in* in = (const struct sockaddr_in*)&s->conn->path.remote;

    return ntohs(in->sin_port) == 50001;
}

static int __start(stand_t* s) {
    /* The client's own log joins the trace when it is on: between the two,
     * every datagram is accounted for at both ends. */
    return quicclient_connect_inproc(&s->client, "localhost", s->trace, __client_out, s);
}

/* ---- Scenarios ---- */

TEST(test_quic_stand_handshake) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a handshake completes over a clean path");
    stand_t* s = __stand_create(1);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "the first Initial went out");

    const uint64_t began = __now_us;

    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete and confirmed");
    TEST_REQUIRE_NOT_NULL(s->conn, "the connection is still there");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "the server calls it active");
    TEST_ASSERT(s->conn->local_params.has_stateless_reset_token,
                "initial server CID has a reset token transport parameter");
    uint8_t expected_reset[16];
    TEST_ASSERT(quicendpoint_reset_token(&s->conn->local_cids[0].cid, expected_reset),
                "reset token derives from the process key");
    TEST_ASSERT(memcmp(expected_reset, s->conn->local_params.stateless_reset_token, 16) == 0,
                "advertised reset token matches the initial CID");

    /* Two round trips is the floor for a full handshake: ClientHello, the
     * server's flight, the client's Finished, HANDSHAKE_DONE. Asserting the
     * ceiling as well is what would catch a flight that only completes because
     * something retransmitted it. */
    const uint64_t elapsed = __now_us - began;
    TEST_ASSERT(elapsed >= 2 * 20000, "no faster than two round trips");
    TEST_ASSERT(elapsed <= 3 * 20000, "and no slower: nothing was retransmitted");

    TEST_ASSERT(s->lost_to_server == 0 && s->lost_to_client == 0, "a clean path lost nothing");

    __stand_free(s);
}

TEST(test_quic_stand_handshake_loss) {
    TEST_SUITE("quic_stand");

    TEST_CASE("the server's first flight is lost and the handshake still completes");
    /* The case a live path reproduces one time in three, and the one the
     * interop matrix calls `handshakeloss`. Here it is a scripted drop: the
     * server's first two datagrams -- its Initial and Handshake flight --
     * never arrive, and the only thing that can save the connection is the
     * server's own PTO, since the client has no loss recovery at all. */
    stand_t* s = __stand_create(2);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    s->drop_next_to_client = 2;

    TEST_ASSERT(__start(s), "the first Initial went out");

    const uint64_t began = __now_us;

    TEST_ASSERT(__run(s, 5000000, __handshake_done), "handshake completes anyway");
    TEST_ASSERT(s->lost_to_client >= 1, "the flight really was dropped");

    /* And it cost exactly one probe timeout, which is a number rather than an
     * impression: with no RTT sample yet, the first PTO is kInitialRtt (333 ms)
     * doubled -- 666 ms -- and the handshake itself is three one-way trips on
     * top. Anything under 600 ms would mean the flight was not really lost;
     * anything over 900 ms would mean a second probe was needed, and the first
     * one did not carry what it should have. */
    const uint64_t elapsed = __now_us - began;
    TEST_ASSERT(elapsed >= 600000 && elapsed <= 900000, "one initial PTO, no more");

    TEST_REQUIRE_NOT_NULL(s->conn, "the connection survived");

    __stand_free(s);
}

TEST(test_quic_stand_clienthello_split_loss) {
    TEST_SUITE("quic_stand");

    TEST_CASE("the second datagram of a ClientHello is lost and the client unblocks the server");
    /* The shape of the interop matrix's `handshakeloss`, and the one the stand
     * was built to reach.
     *
     * A ClientHello no longer fits in a packet -- OpenSSL 3.5 offers a hybrid
     * post-quantum key share by default, so it is ~1.5 KB over two datagrams.
     * Lose the second and the server holds a prefix it cannot answer: it has
     * nothing to say, therefore nothing ack-eliciting in flight, therefore no
     * probe timer of its own. RFC 9002 §6.2.2.1 gives that case to the client
     * by name, and this asserts that the division of labour actually works
     * end to end rather than in principle. */
    stand_t* s = __stand_create(10);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    s->drop_nth_to_server = 2;

    TEST_ASSERT(__start(s), "the ClientHello went out in two datagrams");
    TEST_ASSERT(s->sent_to_server == 2, "two, not one");
    TEST_ASSERT(s->lost_to_server == 1, "and the second never arrived");

    const uint64_t began = __now_us;

    TEST_ASSERT(__run(s, 5000000, __handshake_done), "the handshake completed anyway");

    /* By the client's probe, not the server's: with half a ClientHello the
     * server had nothing in flight to time out on. That is the assertion worth
     * having -- it says *whose* recovery saved the connection. */
    TEST_ASSERT(s->client.pto_fired >= 1, "the client probed");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");
    TEST_ASSERT(s->conn->loss.pto_count == 0, "the server never needed to");

    /* One probe at the client's base interval (kInitialRtt doubled), plus the
     * handshake itself. */
    const uint64_t elapsed = __now_us - began;
    TEST_ASSERT(elapsed >= 600000 && elapsed <= 900000, "one client PTO, no more");

    __stand_free(s);
}

TEST(test_quic_stand_clienthello_reordered) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a ClientHello whose halves arrive in the wrong order still completes");
    /* Nothing is lost here -- the two datagrams simply swap, which on any real
     * path is ordinary. It exercises the part of the CRYPTO reassembly that
     * only a reordering peer reaches: the second half arrives first and has to
     * wait in the hole until the first fills it, because handing TLS a spliced
     * message would fail in a way that looks like a broken codec. */
    stand_t* s = __stand_create(11);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    s->delay_nth_to_server = 1;   /* the first half arrives 25 ms late */

    TEST_ASSERT(__start(s), "the ClientHello went out");

    const uint64_t began = __now_us;

    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_ASSERT(s->lost_to_server == 0 && s->lost_to_client == 0, "nothing was lost");

    /* No probe on either side: reordering is not loss, and treating it as loss
     * is how a server turns a 25 ms hiccup into a 666 ms one. */
    TEST_ASSERT(s->client.pto_fired == 0, "the client did not probe");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");
    TEST_ASSERT(s->conn->loss.pto_count == 0, "nor did the server");

    /* Two round trips plus the swap itself, and nothing more. */
    const uint64_t elapsed = __now_us - began;
    TEST_ASSERT(elapsed <= 3 * 20000 + 25000, "it cost the reordering and no retransmission");

    __stand_free(s);
}

TEST(test_quic_stand_pto_backoff) {
    TEST_SUITE("quic_stand");

    TEST_CASE("PTO intervals double while nothing is acknowledged (RFC 9002 §6.2.1)");
    stand_t* s = __stand_create(3);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    /* A stream to answer on, opened the way a request opens one. */
    TEST_ASSERT(quicclient_stream_write(&s->client, 0, (const uint8_t*)"GET", 3, 0), "request");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");
    __run(s, 200000, NULL);

    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    quicstream_t* qs = quicconn_stream_find(s->conn, 0);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");

    /* Now the client vanishes -- one direction only. The server's data still
     * leaves (which is what the marks record) and nothing ever comes back, so
     * from the second departure on, every one of them is a probe. */
    s->blackhole_to_server = 1;

    uint8_t body[4096];
    memset(body, 'x', sizeof body);

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    quicstream_write(qs, body, sizeof body);
    connection_s_unlock(&s->conn->conn);
    quicconn_want_write(&s->conn->conn);

    s->mark_count = 0;

    /* Long enough for five or six probes at a 20 ms round trip, and short of
     * the idle timeout, which would end the connection for a different
     * reason and make the last gap meaningless. */
    __run(s, 15000000, NULL);

    TEST_ASSERT(s->mark_count >= 5, "the server kept probing");

    /* The last four gaps, each at least 1.7x the one before -- doubling, with
     * room for the acknowledgement timer that shares the same deadline. The
     * tail rather than the head because the first departures are the data
     * burst itself, spread by the pacer.
     *
     * A server that probes at a fixed interval hammers a dead path and passes
     * every "does it retransmit" test there is; this is the assertion that
     * tells the two apart. */
    int growing = 1;
    for (size_t i = s->mark_count > 4 ? s->mark_count - 4 : 2;
         i + 1 < s->mark_count; i++) {
        const uint64_t prev = s->marks[i] - s->marks[i - 1];
        const uint64_t next = s->marks[i + 1] - s->marks[i];

        if (prev == 0) continue;
        if (next * 10 < prev * 17) growing = 0;
    }

    if (!growing) {
        printf("      probe departures (us):");
        for (size_t i = 0; i < s->mark_count; i++)
            printf(" %llu", (unsigned long long)(s->marks[i] - s->marks[0]));
        printf("\n");
    }

    TEST_ASSERT(growing, "and backed off exponentially between probes");
    TEST_ASSERT(s->conn != NULL && s->conn->loss.pto_count >= 3, "the backoff was counted");

    __stand_free(s);
}

TEST(test_quic_stand_idle_timeout) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a silent connection dies at its idle timeout and not before");
    stand_t* s = __stand_create(4);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    const uint64_t idle = s->conn->idle_timeout_us;
    const uint64_t quiet_from = __now_us;
    TEST_ASSERT(idle > 0, "an idle timeout was negotiated");

    /* Half of it, in one jump. Minutes of a live server, and the reason this
     * was never a test before. */
    TEST_ASSERT(!__run(s, idle / 2, __conn_gone), "still alive halfway through");

    /* And then past it. The horizon is generous on purpose: what is being
     * asserted is that it dies, and that it did not die early. */
    const int gone = __run(s, idle, __conn_gone);
    if (!gone && s->conn != NULL)
        printf("      state=%d now=%llu last_activity=%llu idle=%llu timeout=%llu\n",
               (int)s->conn->state, (unsigned long long)__now_us,
               (unsigned long long)s->conn->last_activity_us,
               (unsigned long long)idle,
               (unsigned long long)quicconn_next_timeout(s->conn));

    TEST_ASSERT(gone, "gone once the timeout passed");
    TEST_ASSERT(s->conn_gone_us - quiet_from >= idle, "not one microsecond early");

    __stand_free(s);
}

TEST(test_quic_keepalive_interval) {
    TEST_SUITE("quic_stand");

    /* The rule of §10.1.2, apart from a connection. Half the *negotiated*
     * timeout is the ceiling, and the peer is what makes that interesting:
     * Chrome offers 30 s, so a server configured for 60 s of quiet against its
     * own 300 s timeout would otherwise ping long after the connection had
     * died at the other end. */
    TEST_CASE("the interval is clamped to half the negotiated idle timeout");
    TEST_ASSERT(quicconn_keepalive_interval(0, 30000000) == 0, "off stays off");
    TEST_ASSERT(quicconn_keepalive_interval(10000000, 30000000) == 10000000,
                "a value under half the timeout is used as configured");
    TEST_ASSERT(quicconn_keepalive_interval(60000000, 30000000) == 15000000,
                "a value over it is clamped to half");
    TEST_ASSERT(quicconn_keepalive_interval(60000000, 0) == 60000000,
                "no negotiated timeout, nothing to clamp to");

    TEST_CASE("and never drops below a second");
    TEST_ASSERT(quicconn_keepalive_interval(1, 30000000) == 1000000, "tiny configured");
    TEST_ASSERT(quicconn_keepalive_interval(10000000, 2000000) == 1000000,
                "or a timeout so short that half of it would be sub-second");
}

TEST(test_quic_stand_keepalive) {
    TEST_SUITE("quic_stand");

    TEST_CASE("keep-alive holds a silent connection past its idle timeout");
    stand_t* s = __stand_create(4);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    const uint64_t idle = s->conn->idle_timeout_us;
    TEST_ASSERT(idle > 0, "an idle timeout was negotiated");

    /* What the policy would have set at accept. Set here because the unit
     * runner has no main.env, so http3_keepalive_sec is at its default of
     * zero -- which is exactly what the case above this file's idle-timeout
     * test proves still happens. */
    s->conn->keepalive_conf_us = idle / 4;
    s->conn->keepalive_us = quicconn_keepalive_interval(idle / 4, idle);
    s->conn->keepalive_next_us = 0;

    /* Three idle timeouts of complete application silence. Nothing but the
     * keep-alive can carry this: only *received* bytes refresh the idle timer,
     * and the client answers only what elicits an acknowledgment. */
    const uint64_t started_at = __now_us;
    const uint64_t delivered_before = s->delivered_to_client;

    TEST_ASSERT(!__run(s, idle * 3, __conn_gone),
                "still alive after three idle timeouts of silence");
    TEST_REQUIRE_NOT_NULL(s->conn, "connection object intact");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "and still active");

    /* Both halves have to be asserted, and finding that out cost a control
     * experiment: "the connection is alive" alone also passes when the stand's
     * virtual clock never reached the timeout, which is precisely what happens
     * if the probes stop being sent. So: the clock really advanced past three
     * timeouts, and the client really received the packets that did it. */
    TEST_ASSERT(__now_us - started_at >= idle * 3,
                "the virtual clock really advanced three timeouts");
    TEST_ASSERT(s->delivered_to_client - delivered_before >= 3,
                "and the probes really reached the client");

    __stand_free(s);

    TEST_CASE("but a peer that has gone away still times out");
    /* The property that makes this safe to switch on: pinging cannot keep a
     * dead connection open, because our own sends never touch the idle timer
     * (quicconn.c, __touch). Without that, a server with keep-alive on would
     * accumulate connections for every client that vanished without closing. */
    s = __stand_create(4);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    const uint64_t idle2 = s->conn->idle_timeout_us;
    s->conn->keepalive_conf_us = idle2 / 4;
    s->conn->keepalive_us = quicconn_keepalive_interval(idle2 / 4, idle2);
    s->conn->keepalive_next_us = 0;

    const uint64_t quiet_from = __now_us;
    s->blackhole_to_server = 1;      /* the client's answers never arrive */

    TEST_ASSERT(__run(s, idle2 * 2, __conn_gone),
                "gone despite keep-alive, because nothing came back");
    TEST_ASSERT(s->conn_gone_us - quiet_from >= idle2, "not one microsecond early");

    __stand_free(s);
}

TEST(test_quic_stand_stream_under_loss) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a response crosses a 20% lossy path byte for byte");
    stand_t* s = __stand_create(5);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    /* The client opens stream 0 and says something, which is what makes the
     * server create its side of it. */
    TEST_ASSERT(quicclient_stream_write(&s->client, 0, (const uint8_t*)"GET", 3, 0), "request");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");
    __run(s, 200000, NULL);

    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    quicstream_t* qs = quicconn_stream_find(s->conn, 0);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");

    /* A pattern rather than zeroes: a truncation, a duplicated retransmission
     * and an offset applied twice all look identical in a buffer of zeroes. */
    const size_t total = 64 * 1024;
    uint8_t* body = malloc(total);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");
    for (size_t i = 0; i < total; i++) body[i] = (uint8_t)(i * 31 + (i >> 8));

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    const int written = quicstream_write(qs, body, total);
    quicstream_finish(qs);
    connection_s_unlock(&s->conn->conn);
    TEST_ASSERT(written, "queued on the stream");

    quicconn_want_write(&s->conn->conn);

    /* Now break the path, in both directions: losing acknowledgements is a
     * different failure from losing data, and a transfer has to survive both. */
    s->loss_to_client_pct = 20;
    s->loss_to_server_pct = 20;

    uint8_t* got = calloc(1, total);
    TEST_REQUIRE_NOT_NULL(got, "sink allocated");
    size_t have = 0;

    for (int round = 0; round < 4000 && have < total; round++) {
        /* One step at a time so the reads interleave with the exchange the way
         * an application's would; without reading, the connection-level window
         * closes and the transfer stalls for a reason that has nothing to do
         * with loss. */
        if (!__step(s, __now_us + 60000000)) break;

        const size_t ready = quicclient_stream_readable(&s->client, 0);
        if (ready == 0) continue;

        have += quicclient_stream_read(&s->client, 0, got + have,
                                       total - have < ready ? total - have : ready);
    }

    if (have != total)
        printf("      have=%zu of %zu, conn=%p state=%d lost_in=%llu lost_out=%llu now=%llu\n",
               have, total, (void*)s->conn,
               s->conn != NULL ? (int)s->conn->state : -1,
               (unsigned long long)s->lost_to_client,
               (unsigned long long)s->lost_to_server,
               (unsigned long long)__now_us);

    TEST_ASSERT(have == total, "every byte arrived");
    TEST_ASSERT(memcmp(got, body, total) == 0, "and in the right order, exactly once");
    TEST_ASSERT(s->lost_to_client > 0, "the path really did lose datagrams");
    TEST_ASSERT(s->overflowed == 0, "the emulator never dropped anything itself");

    free(got);
    free(body);
    __stand_free(s);
}

/* Stream 0, opened the way a request opens it -- with a FIN, because a request
 * without a body ends where it starts, and a stream whose receive side never
 * finishes can never be released. The server's side is found and returned. */
static quicstream_t* __open_request_stream(stand_t* s) {
    if (!quicclient_stream_write(&s->client, 0, (const uint8_t*)"GET", 3, 1)) return NULL;
    if (!quicclient_flush(&s->client)) return NULL;

    __run(s, 200000, NULL);

    return s->conn != NULL ? quicconn_stream_find(s->conn, 0) : NULL;
}

/* What an application does before answering: take the request off the stream.
 *
 * Not a formality. The transport releases a peer's stream only once the
 * application has read what arrived (recv_state DATA_READ), and the
 * connection-level window is credited here and nowhere else -- quicstream_read
 * credits the stream's own window, because a stream deliberately does not know
 * its connection. A stand that only wrote would leave both untested. */
static int __consume_request(stand_t* s, uint64_t id) {
    if (s->conn == NULL) return 0;

    quicstream_t* qs = quicconn_stream_find(s->conn, id);
    if (qs == NULL) return 0;

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);

    uint8_t sink[256];
    size_t taken = 0;
    for (;;) {
        const size_t n = quicstream_read(qs, sink, sizeof sink);
        if (n == 0) break;
        taken += n;
    }

    if (taken > 0) quicconn_consumed(s->conn, taken);

    connection_s_unlock(&s->conn->conn);

    return 1;
}

/* A body with a pattern rather than zeroes: a truncation, a duplicated
 * retransmission and an offset applied twice all look identical in a buffer of
 * zeroes. */
static uint8_t* __body_make(size_t total) {
    uint8_t* body = malloc(total);
    if (body == NULL) return NULL;

    for (size_t i = 0; i < total; i++) body[i] = (uint8_t)(i * 31 + (i >> 8));

    return body;
}

/* Put the whole body on the server's stream, ending it unless the caller is
 * about to cancel instead. The FIN matters as much as the bytes: §3t was two
 * deadlocks in which every byte arrived and the stream never finished. */
static int __respond_body(stand_t* s, quicstream_t* qs, const uint8_t* body,
                          size_t total, int fin) {
    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    const int written = quicstream_write(qs, body, total);
    if (fin) quicstream_finish(qs);
    connection_s_unlock(&s->conn->conn);

    quicconn_want_write(&s->conn->conn);

    return written;
}

static int __respond(stand_t* s, quicstream_t* qs, const uint8_t* body, size_t total) {
    return __respond_body(s, qs, body, total, 1);
}

/* Step the stand until the client has read `total` bytes, reading as it goes.
 * Reading is not optional: without it the connection-level window closes and the
 * transfer stalls for a reason that has nothing to do with the path. */
/* Waits for the FIN as well as for the bytes, and the difference is not
 * pedantry: since §3t the FIN does not ride on a retransmission -- a peer
 * discards the duplicate frame and the FIN with it -- so a lost final packet
 * makes the end of the stream arrive in a frame of its own, after the last
 * byte. A loop that stopped counting bytes would report that as "every byte
 * arrived but the stream never finished", which is what the impairment matrix
 * said the first time it ran. */
static size_t __drain(stand_t* s, uint8_t* got, size_t total) {
    size_t have = 0;

    for (int round = 0;
         round < 200000 && (have < total || !quicclient_stream_fin(&s->client, 0));
         round++) {
        /* Read before stepping: whatever is already waiting was put there by
         * the exchange so far, and a loop that steps first would jump the clock
         * to the next timer -- which, on a connection stalled against a closed
         * window, is the idle timeout. */
        const size_t ready = quicclient_stream_readable(&s->client, 0);

        if (ready == 0) {
            if (!__step(s, __now_us + 60000000)) break;
            continue;
        }

        have += quicclient_stream_read(&s->client, 0, got + have,
                                       total - have < ready ? total - have : ready);

        /* Reading earns the peer credit, and the frames that carry it need a
         * packet to leave in. Nothing else builds one here: a blocked server
         * sends nothing, so waiting for its next datagram to piggyback on is
         * waiting for the thing the credit is supposed to cause. */
        if (!quicclient_flush(&s->client)) break;
    }

    return have;
}

/* What an application does with a request stream, minus the HTTP: read what the
 * peer sent (which is what moves the stream to DATA_READ and lets the transport
 * release it), then answer and end it. Returns 0 if the stream is not there. */
static int __serve(stand_t* s, uint64_t id, const uint8_t* body, size_t len) {
    if (!__consume_request(s, id)) return 0;

    quicstream_t* qs = quicconn_stream_find(s->conn, id);
    if (qs == NULL) return 0;

    return __respond(s, qs, body, len);
}

TEST(test_quic_stand_parallel_streams) {
    TEST_SUITE("quic_stand");

    TEST_CASE("thirty-two streams in flight at once, each intact, through a lossy path");
    /* The send path shares one connection between all open streams by
     * round-robin, and until now nothing in the tests had more than one. What
     * that scheduling gets wrong is not "does data arrive" but "does *this*
     * stream's data arrive on this stream": an offset applied to the wrong
     * stream, or a frame built for one and accounted to another, produces a
     * connection where everything works and one response is subtly another's.
     * Hence a different body per stream, and every byte checked.
     *
     * Loss on top, because the interesting interaction is retransmission across
     * streams: the lost frames of thirty-two streams come back through one
     * congestion window. */
    stand_t* s = __stand_create(14);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

#define PARALLEL_STREAMS 32

    /* Client-initiated bidirectional ids are 0, 4, 8, ... (§2.1). */
    for (int i = 0; i < PARALLEL_STREAMS; i++) {
        const uint8_t request[4] = { 'G', 'E', 'T', (uint8_t)i };
        TEST_ASSERT(quicclient_stream_write(&s->client, (uint64_t)i * 4,
                                            request, sizeof request, 1),
                    "request queued");
    }

    TEST_ASSERT(quicclient_flush(&s->client), "sent");
    __run(s, 500000, NULL);

    /* Bodies of different lengths as well as different contents: a stream that
     * received another's data would otherwise still be the right size. */
    size_t lens[PARALLEL_STREAMS];
    uint8_t* bodies[PARALLEL_STREAMS];

    for (int i = 0; i < PARALLEL_STREAMS; i++) {
        lens[i] = 512 + (size_t)i * 137;
        bodies[i] = malloc(lens[i]);
        TEST_REQUIRE_NOT_NULL(bodies[i], "body allocated");
        for (size_t j = 0; j < lens[i]; j++)
            bodies[i][j] = (uint8_t)(j * 31 + i * 7 + 1);

        TEST_ASSERT(__serve(s, (uint64_t)i * 4, bodies[i], lens[i]), "answered");
    }

    /* "Parallel" as a fact rather than an intention: all of them are open on the
     * server at this moment, so what follows really is one window shared
     * between thirty-two streams. */
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");
    TEST_ASSERT(s->conn->stream_count >= PARALLEL_STREAMS, "all of them open at once");

    s->loss_to_client_pct = 15;
    s->loss_to_server_pct = 15;

    uint8_t* got[PARALLEL_STREAMS];
    size_t have[PARALLEL_STREAMS];

    for (int i = 0; i < PARALLEL_STREAMS; i++) {
        got[i] = calloc(1, lens[i]);
        TEST_REQUIRE_NOT_NULL(got[i], "sink allocated");
        have[i] = 0;
    }

    int complete = 0;

    for (int round = 0; round < 200000 && complete < PARALLEL_STREAMS; round++) {
        if (!__step(s, __now_us + 60000000)) break;

        complete = 0;
        for (int i = 0; i < PARALLEL_STREAMS; i++) {
            const uint64_t id = (uint64_t)i * 4;
            const size_t ready = quicclient_stream_readable(&s->client, id);

            if (ready > 0 && have[i] < lens[i]) {
                const size_t room = lens[i] - have[i];
                have[i] += quicclient_stream_read(&s->client, id, got[i] + have[i],
                                                  room < ready ? room : ready);
            }

            if (have[i] == lens[i] && quicclient_stream_fin(&s->client, id)) complete++;
        }
    }

    int intact = 0;
    for (int i = 0; i < PARALLEL_STREAMS; i++)
        if (have[i] == lens[i] && memcmp(got[i], bodies[i], lens[i]) == 0) intact++;

    if (complete != PARALLEL_STREAMS || intact != PARALLEL_STREAMS)
        printf("      %d of %d complete, %d intact; lost %llu/%llu\n",
               complete, PARALLEL_STREAMS, intact,
               (unsigned long long)s->lost_to_client,
               (unsigned long long)s->lost_to_server);

    TEST_ASSERT(complete == PARALLEL_STREAMS, "every stream finished");
    TEST_ASSERT(intact == PARALLEL_STREAMS, "and carried its own body, exactly");
    TEST_ASSERT(s->lost_to_client > 0, "the path really did lose datagrams");

    for (int i = 0; i < PARALLEL_STREAMS; i++) {
        free(bodies[i]);
        free(got[i]);
    }

    __stand_free(s);
}

TEST(test_quic_stand_uniform_datagrams) {
    TEST_SUITE("quic_stand");

    TEST_CASE("every datagram that fills the packet is the same length");
    /* The sender's own side of GSO. The kernel folds consecutive datagrams into
     * one send only while they are the same size, and stops at the first that
     * is not (udpsocket.c) -- so a builder that lands within a few bytes of the
     * path MTU instead of on it costs the send path its offload, whatever the
     * batch does.
     *
     * That is what happened: a flat 24-byte reserve for a STREAM frame header
     * that really costs three to twelve bytes left every packet short by a
     * varying amount, and the amount changed with the varint of the offset --
     * two bytes longer past 16 KB, four bytes shorter on a packet that starts a
     * stream at zero. Runs of sixty segments came out as eleven (docs/http3/08
     * §12). Nothing in the tests could see it: every byte arrived, in order, on
     * the right stream.
     *
     * Hence several streams and bodies past 16 KB: one stream would cross the
     * varint boundary once and prove nothing. */
    stand_t* s = __stand_create(31);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

#define UNIFORM_STREAMS 8
#define UNIFORM_BODY    (48 * 1024)

    for (int i = 0; i < UNIFORM_STREAMS; i++) {
        const uint8_t request[4] = { 'G', 'E', 'T', (uint8_t)i };
        TEST_ASSERT(quicclient_stream_write(&s->client, (uint64_t)i * 4,
                                            request, sizeof request, 1),
                    "request queued");
    }

    TEST_ASSERT(quicclient_flush(&s->client), "sent");
    __run(s, 500000, NULL);

    uint8_t* body = malloc(UNIFORM_BODY);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");
    for (size_t j = 0; j < UNIFORM_BODY; j++) body[j] = (uint8_t)(j * 17 + 3);

    for (int i = 0; i < UNIFORM_STREAMS; i++)
        TEST_ASSERT(__serve(s, (uint64_t)i * 4, body, UNIFORM_BODY), "answered");

    /* Only the sizes matter here, so the bytes are drained and dropped. */
    uint8_t sink[16 * 1024];
    size_t have[UNIFORM_STREAMS] = { 0 };
    int complete = 0;

    for (int round = 0; round < 200000 && complete < UNIFORM_STREAMS; round++) {
        if (!__step(s, __now_us + 60000000)) break;

        complete = 0;
        for (int i = 0; i < UNIFORM_STREAMS; i++) {
            const uint64_t id = (uint64_t)i * 4;
            const size_t ready = quicclient_stream_readable(&s->client, id);

            if (ready > 0)
                have[i] += quicclient_stream_read(&s->client, id, sink,
                                                  ready < sizeof sink ? ready : sizeof sink);

            if (have[i] == UNIFORM_BODY && quicclient_stream_fin(&s->client, id))
                complete++;
        }
    }

    TEST_ASSERT(complete == UNIFORM_STREAMS, "every response arrived");
    TEST_ASSERT(s->dgram_logged > 200, "and it took enough datagrams to judge by");

    /* The largest datagram the connection produced is the size a packet that
     * filled its capacity has; anything close to it was meant to be full. What
     * is far below is a genuinely short packet -- the end of a response, an
     * acknowledgement on its own -- and those may differ from each other. */
    size_t widest = 0;
    for (size_t i = 0; i < s->dgram_logged; i++)
        if (s->dgram_len[i] > widest) widest = s->dgram_len[i];

    const size_t full_floor = widest > 64 ? widest - 64 : 0;

    size_t full = 0;
    size_t wobbles = 0;

    for (size_t i = 0; i < s->dgram_logged; i++) {
        if (s->dgram_len[i] < full_floor) continue;

        full++;

        /* Two datagrams both meant to be full, one after the other, differing
         * in length: that is the run ending for no reason but arithmetic. */
        if (i > 0 && s->dgram_len[i - 1] >= full_floor &&
            s->dgram_len[i - 1] != s->dgram_len[i]) wobbles++;
    }

    if (wobbles > 0)
        printf("      %zu of %zu full datagrams (max %zu) differ from the one"
               " before them\n", wobbles, full, widest);

    TEST_ASSERT(full > 150, "most of the traffic was full-sized packets");
    TEST_ASSERT(wobbles == 0, "and no two consecutive full datagrams differed in size");

    free(body);
    __stand_free(s);

#undef UNIFORM_STREAMS
#undef UNIFORM_BODY
}

TEST(test_quic_stand_stream_credit) {
    TEST_SUITE("quic_stand");

    TEST_CASE("more streams than the initial allowance, one after another (§4.6)");
    /* The wall that a third-party client found and no test of ours could
     * (docs/http3/08 §7a): stream credit is granted per stream and never
     * renewed, so a connection is spent after initial_max_streams_bidi
     * requests -- a hundred here. Not a slow path, a wall.
     *
     * MAX_STREAMS renews it, but only for streams the transport has actually
     * released, and it releases a peer's stream only once both directions are
     * done *and* the application has read what arrived. That is why __serve
     * reads the request it is about to answer, and it is the part a stand that
     * only writes would silently not test. */
    stand_t* s = __stand_create(15);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    const uint64_t allowance = s->conn->local_params.initial_max_streams_bidi;
    TEST_ASSERT(allowance > 0, "an allowance was advertised");

    /* Half again as many as the allowance: enough that a connection with no
     * renewal fails, and few enough to stay a unit test. */
    const uint64_t wanted = allowance + allowance / 2;
    uint64_t served = 0;

    const uint8_t body[64] = { 0 };

    for (uint64_t i = 0; i < wanted; i++) {
        const uint64_t id = i * 4;

        if (!quicclient_stream_write(&s->client, id, (const uint8_t*)"GET", 3, 1)) break;
        if (!quicclient_flush(&s->client)) break;

        __run(s, 500000, NULL);

        if (!__serve(s, id, body, sizeof body)) break;

        /* Wait for the whole answer, then let go of the slot -- both halves of
         * the stream are finished, which is exactly the state that earns the
         * credit back. */
        for (int round = 0; round < 2000; round++) {
            if (quicclient_stream_readable(&s->client, id) >= sizeof body &&
                quicclient_stream_fin(&s->client, id))
                break;
            if (!__step(s, __now_us + 2000000)) break;
        }

        if (!quicclient_stream_fin(&s->client, id)) break;

        quicclient_stream_release(&s->client, id);
        served++;
    }

    if (served != wanted || s->trace)
        printf("      served %llu of %llu (allowance %llu), closed %llu, state %d\n",
               (unsigned long long)served, (unsigned long long)wanted,
               (unsigned long long)allowance,
               s->conn != NULL ? (unsigned long long)s->conn->peer_bidi_closed : 0,
               s->conn != NULL ? (int)s->conn->state : -1);

    TEST_ASSERT(served == wanted, "the connection kept accepting streams past the allowance");
    TEST_REQUIRE_NOT_NULL(s->conn, "and stayed alive");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "still active");

    /* The transport really did let them go, rather than accumulating them: the
     * per-packet walk over conn->streams is only short if this happens. */
    TEST_ASSERT(s->conn->stream_count < allowance, "and released the finished ones");

    __stand_free(s);
}

TEST(test_quic_stand_stream_cancel) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a stream abandoned mid-body ends as cancelled, not as truncated");
    /* The application changes its mind halfway through a response. What the
     * peer must be able to tell apart is "cancelled" from "stalled" and from
     * "truncated": RESET_STREAM carries both the reason and the final size, and
     * without the final size the receiver cannot even close its own accounting
     * of the flow-control window.
     *
     * The other half of the case is the transport's: a reset stream is finished
     * in both directions, so it must be released and its slot returned to the
     * concurrency limit -- the same credit machinery §2e exercises from the
     * other side, reached here by a path that never sends a FIN. */
    stand_t* s = __stand_create(16);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    quicstream_t* qs = __open_request_stream(s);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");
    TEST_ASSERT(__consume_request(s, 0), "the request was read");

    const size_t total = 128 * 1024;
    uint8_t* body = __body_make(total);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");

    /* No FIN: this response is going to be abandoned, and a stream that had
     * already declared its end would be a different case. */
    TEST_ASSERT(__respond_body(s, qs, body, total, 0), "queued on the stream");

    /* Let a little of it out, so the cancellation lands in the middle of a
     * transfer rather than before one.
     *
     * Short on purpose, and it had to get shorter: with the pacer's burst tied
     * to the rate rather than frozen at the initial window (quiccc.h), 60 ms of
     * this stand's path is enough for the whole 128 KB to leave the server, and
     * the case being tested -- a reset that arrives while bytes are still
     * queued -- stops happening at all. The assertion below is what noticed. */
    __run(s, 20000, NULL);

    const size_t before = quicclient_stream_readable(&s->client, 0);
    TEST_ASSERT(before > 0 && before < total, "part of the body is on its way");

    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    const size_t streams_before = s->conn->stream_count;

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    quicstream_reset(quicconn_stream_find(s->conn, 0), 0x10a);
    connection_s_unlock(&s->conn->conn);
    quicconn_want_write(&s->conn->conn);

    TEST_ASSERT(__run(s, 1000000, __stream0_reset), "the client was told it was cancelled");

    uint64_t error = 0;
    uint64_t final_size = 0;
    TEST_ASSERT(quicclient_stream_reset(&s->client, 0, &error, &final_size), "reset recorded");
    TEST_ASSERT(error == 0x10a, "with the code the application chose");

    if (s->trace)
        printf("      cancelled: final size %llu, %zu written, %zu already readable\n",
               (unsigned long long)final_size, total, before);

    /* The final size is what was actually sent, not what was queued: a receiver
     * that believed the queued figure would wait for bytes that were abandoned. */
    TEST_ASSERT(final_size < total, "the final size is what was sent, not what was written");
    TEST_ASSERT(final_size >= before, "and covers what already arrived");

    TEST_ASSERT(!quicclient_stream_fin(&s->client, 0), "it was cancelled, not finished");

    /* And the connection is unharmed: cancelling a stream is an ordinary event,
     * not an error. */
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "the connection carried on");
    TEST_ASSERT(s->conn->stream_count < streams_before || s->conn->peer_bidi_closed > 0,
                "and the stream was released");

    free(body);
    __stand_free(s);
}

TEST(test_quic_stand_stop_sending) {
    TEST_SUITE("quic_stand");

    TEST_CASE("STOP_SENDING stops the response and is answered with RESET_STREAM (§3.5)");
    /* The cancellation that comes from the *receiver*: the client is not going
     * to read this stream, and says so. §3.5 obliges us to give up sending and
     * answer with RESET_STREAM carrying the code it asked for -- an
     * implementation that merely stopped would leave the peer unable to tell
     * that from a stall, and one that kept sending would spend the window on
     * data nobody will read.
     *
     * Both halves are asserted, and the second is the one worth the trouble:
     * what the server sends *after* the request, counted. */
    stand_t* s = __stand_create(17);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    quicstream_t* qs = __open_request_stream(s);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");

    const size_t total = 256 * 1024;
    uint8_t* body = __body_make(total);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");

    TEST_ASSERT(__respond(s, qs, body, total), "queued on the stream");

    __run(s, 60000, NULL);
    TEST_ASSERT(quicclient_stream_readable(&s->client, 0) > 0, "the body started arriving");

    TEST_ASSERT(quicclient_stop_sending(&s->client, 0, 0x10c), "asking it to stop");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");

    TEST_ASSERT(__run(s, 1000000, __stream0_reset), "answered with RESET_STREAM");

    uint64_t error = 0;
    TEST_ASSERT(quicclient_stream_reset(&s->client, 0, &error, NULL), "reset recorded");
    TEST_ASSERT(error == 0x10c, "carrying the code the client asked for");

    /* And then it really stops. A PING keeps the exchange alive so that "quiet"
     * cannot be confused with "the connection died", and the datagram count is
     * what says the body is no longer flowing: whatever still arrives is
     * acknowledgements and the odd frame, not a quarter-megabyte of body. */
    const uint64_t sent_before = s->sent_to_client;

    TEST_ASSERT(quicclient_ping(&s->client), "poke it");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");
    __run(s, 500000, NULL);

    TEST_ASSERT(s->sent_to_client - sent_before < 10,
                "the response stopped rather than draining into the void");

    TEST_REQUIRE_NOT_NULL(s->conn, "connected");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "and the connection carried on");

    free(body);
    __stand_free(s);
}

TEST(test_quic_stand_peer_reset_accounting) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a peer's RESET_STREAM charges the connection window for what never arrived (§4.5)");
    /* The other side of §2f. The peer abandons a stream having sent more than
     * we received -- the ordinary case, since the tail was in flight when it
     * gave up -- and §4.5 makes the final size account for the whole stream in
     * the *connection-level* flow controller, missing bytes included.
     *
     * Skip it and nothing breaks loudly: the peer is the strict one, so it
     * simply believes it has less window than we think we gave it, and the
     * difference accumulates over every cancelled stream until it stalls
     * against a limit we thought was generous. That is a bug that arrives as
     * "the connection got slow after a while", which is why it is worth a test
     * that reads a counter rather than a symptom. */
    stand_t* s = __stand_create(18);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    /* A request stream with a body, so that some of it arrives before the rest
     * is lost. */
    const size_t chunk = 2048;
    uint8_t* body = __body_make(chunk);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");

    TEST_ASSERT(quicclient_stream_write(&s->client, 0, body, chunk, 0), "first half");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");
    __run(s, 200000, NULL);

    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    const uint64_t counted_before = s->conn->recv_flow.used;
    TEST_ASSERT(counted_before >= chunk, "what arrived was counted");

    /* Now the rest goes into a black hole, and the client gives up on the
     * stream. Its final size covers the lost part; ours has never seen it. */
    s->blackhole_to_server = 1;
    TEST_ASSERT(quicclient_stream_write(&s->client, 0, body, chunk, 0), "second half");
    TEST_ASSERT(quicclient_flush(&s->client), "sent into the void");
    s->blackhole_to_server = 0;

    TEST_ASSERT(quicclient_reset_stream(&s->client, 0, 0x11), "the client gives up");
    TEST_ASSERT(quicclient_flush(&s->client), "reset sent");

    __run(s, 500000, NULL);

    TEST_REQUIRE_NOT_NULL(s->conn, "the connection survived the reset");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "and carried on");

    const uint64_t counted_after = s->conn->recv_flow.used;

    if (s->trace)
        printf("      connection window: counted %llu -> %llu (stream final size %llu)\n",
               (unsigned long long)counted_before, (unsigned long long)counted_after,
               (unsigned long long)(chunk * 2));

    /* The whole stream, not just the part that made it: both halves were sent,
     * so the final size is 2 x chunk and the connection must have been charged
     * for all of it. */
    TEST_ASSERT(counted_after >= counted_before + chunk,
                "the abandoned tail was charged to the connection window");

    free(body);
    __stand_free(s);
}

TEST(test_quic_stand_reset_opens_stream) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a RESET_STREAM for a stream never seen opens it, limit and all (§3.2)");
    /* The extreme of the same case: everything the peer sent on the stream was
     * lost, so the first thing we ever hear about it is that it is over.
     *
     * Looking the id up and shrugging -- which is what this did -- loses two
     * things at once. The stream limit goes unenforced for any id that arrives
     * as a reset, and §4.5's accounting never happens at all, since there is no
     * stream to account it against. Both are invisible in every test that does
     * not lose a whole stream's worth of data. */
    stand_t* s = __stand_create(19);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    const uint64_t counted_before = s->conn->recv_flow.used;
    const size_t streams_before = s->conn->stream_count;

    /* Stream 4 exists only in the client's imagination as far as the server is
     * concerned: every datagram carrying it is dropped. */
    const size_t chunk = 1024;
    uint8_t* body = __body_make(chunk);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");

    s->blackhole_to_server = 1;
    TEST_ASSERT(quicclient_stream_write(&s->client, 4, body, chunk, 0), "a whole stream");
    TEST_ASSERT(quicclient_flush(&s->client), "sent into the void");
    s->blackhole_to_server = 0;

    TEST_ASSERT(quicclient_reset_stream(&s->client, 4, 0x12), "and then abandoned");
    TEST_ASSERT(quicclient_flush(&s->client), "reset sent");

    __run(s, 500000, NULL);

    TEST_REQUIRE_NOT_NULL(s->conn, "the connection survived");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "and carried on");

    /* The stream was opened by the reset -- which is what makes the id count
     * against the concurrency limit and its final size against the window. */
    TEST_ASSERT(s->conn->next_peer_bidi > 1, "the id was accounted as opened");
    TEST_ASSERT(s->conn->recv_flow.used >= counted_before + chunk,
                "and the whole stream was charged to the connection window");

    (void)streams_before;

    free(body);
    __stand_free(s);
}

/* ---- The impairment matrix ---- *
 *
 * One exchange, run under every combination of things a path does, with a
 * seed per run. This is what the socket-based client's matrix was
 * (docs/http3/08 §2a: 27 runs, minutes each, and a rebuild between them) --
 * except that here a run is milliseconds and a failure names the combination
 * and the seed that produced it, which is the difference between a matrix and
 * a lottery.
 *
 * It earns its place by covering what the hand-written scenarios cannot: they
 * each break one thing on purpose, and the interesting failures of this phase
 * -- the FIN inside a duplicate (§3t), the retransmission locked out by flow
 * control (§3i) -- needed two at once. */

typedef struct impairment {
    const char* name;
    unsigned loss_to_client;
    unsigned loss_to_server;
    unsigned reorder;
    unsigned dup;
    uint64_t bandwidth_bps;
    size_t   queue_pkts;
    /* 0 = the client's generous default, so flow control stays out of the way.
     * A window small enough to be reached puts the sender's blocked/unblocked
     * path into the same run as the losses, which is where a stall hides: the
     * credit that would unblock it travels on the same broken path. */
    uint64_t conn_window;
    uint64_t stream_window;
} impairment_t;

static const impairment_t __matrix[] = {
    /* The baseline is not a formality: if it ever fails, nothing below it means
     * anything. */
    { "clean",             0,  0,  0,  0,        0,  0,      0,     0 },
    { "loss 10%",         10, 10,  0,  0,        0,  0,      0,     0 },
    { "loss 25%",         25, 25,  0,  0,        0,  0,      0,     0 },
    /* One direction only, like the socket client's `--loss-in` (§2a). Forty per
     * cent both ways makes a round trip succeed 36 % of the time, and a
     * connection with a thirty-second idle timeout is then entitled to die --
     * asserting that it must not would be asserting against the protocol. This
     * way the server has to recover a response through a path that eats two
     * datagrams in five, while its acknowledgements come back. */
    { "loss 40% one way", 40,  0,  0,  0,        0,  0,      0,     0 },
    { "reorder 30%",       0,  0, 30,  0,        0,  0,      0,     0 },
    { "dup 20%",           0,  0,  0, 20,        0,  0,      0,     0 },
    { "loss + reorder",   15, 15, 30,  0,        0,  0,      0,     0 },
    { "loss + dup",       15, 15,  0, 20,        0,  0,      0,     0 },
    { "bottleneck",        0,  0,  0,  0, 10000000, 25,      0,     0 },
    { "bottleneck + loss", 5,  5,  0,  0, 10000000, 25,      0,     0 },
    { "tight window",      0,  0,  0,  0,        0,  0,  49152, 16384 },
    { "tight + loss",     15, 15,  0,  0,        0,  0,  49152, 16384 },
    { "tight + reorder",   0,  0, 30, 10,        0,  0,  49152, 16384 },
    { "everything",       10, 10, 20, 10, 10000000, 25,  49152, 16384 },
};

/* One request and one response through `imp`. Returns 1 if every byte arrived
 * in order, exactly once, with the FIN and a connection still up. */
static int __matrix_run(const impairment_t* imp, uint64_t seed, char* why, size_t why_cap) {
    stand_t* s = __stand_create(seed);
    if (s == NULL) return 0;

    s->delay_us = 15000;

    int ok = 0;
    uint8_t* body = NULL;
    uint8_t* got = NULL;

    const size_t total = 32 * 1024;

    if (!quicclient_connect_inproc_windowed(&s->client, "localhost", s->trace,
                                            __client_out, s,
                                            imp->conn_window, imp->stream_window)) {
        snprintf(why, why_cap, "could not start");
        goto done;
    }

    if (!__run(s, 5000000, __handshake_done)) {
        snprintf(why, why_cap, "handshake did not complete");
        goto done;
    }

    /* The request goes out on a clean path: this client cannot retransmit
     * stream data of its own (only its handshake flight), so losing the request
     * would test the harness rather than the server. Everything after this
     * point -- the response, and every acknowledgement of it -- is impaired. */
    quicstream_t* qs = __open_request_stream(s);
    if (qs == NULL || !__consume_request(s, 0)) {
        snprintf(why, why_cap, "the request did not arrive");
        goto done;
    }

    body = __body_make(total);
    got = calloc(1, total);
    if (body == NULL || got == NULL) {
        snprintf(why, why_cap, "out of memory");
        goto done;
    }

    if (!__respond(s, qs, body, total)) {
        snprintf(why, why_cap, "could not queue the response");
        goto done;
    }

    s->loss_to_client_pct = imp->loss_to_client;
    s->loss_to_server_pct = imp->loss_to_server;
    s->reorder_pct = imp->reorder;
    s->dup_pct = imp->dup;
    s->bandwidth_bps = imp->bandwidth_bps;
    s->queue_pkts = imp->queue_pkts;

    const size_t have = __drain(s, got, total);

    if (have != total) {
        snprintf(why, why_cap, "%zu of %zu bytes", have, total);
        goto done;
    }

    if (memcmp(got, body, total) != 0) {
        snprintf(why, why_cap, "the body came back altered");
        goto done;
    }

    if (!quicclient_stream_fin(&s->client, 0)) {
        snprintf(why, why_cap, "every byte arrived but the stream never finished");
        goto done;
    }

    if (s->conn == NULL || s->conn->state != QUICCONN_ACTIVE) {
        snprintf(why, why_cap, "the connection did not survive");
        goto done;
    }

    if (s->overflowed > 0) {
        snprintf(why, why_cap, "the emulator's own queue overflowed");
        goto done;
    }

    ok = 1;

    done:

    free(got);
    free(body);
    __stand_free(s);

    return ok;
}

TEST(test_quic_stand_impairment_matrix) {
    TEST_SUITE("quic_stand");

    TEST_CASE("one exchange survives every combination of loss, reordering, duplication and a bottleneck");

    const size_t cases = sizeof __matrix / sizeof __matrix[0];
    int failures = 0;

    /* Five seeds a case keeps the whole runner under two seconds, which is what
     * makes this a test rather than an errand. STAND_MATRIX_SEEDS=200 turns the
     * same table into a sweep when something is being hunted -- the two bugs
     * this found came out of seeds 2 and 4. */
    uint64_t seeds = 5;
    const char* env = getenv("STAND_MATRIX_SEEDS");
    if (env != NULL) {
        const long n = strtol(env, NULL, 10);
        if (n > 0) seeds = (uint64_t)n;
    }

    /* And one cell of it, by name, so a failure found by a sweep can be
     * reproduced with the trace on without drowning in the other hundreds. */
    const char* only = getenv("STAND_MATRIX_ONLY");

    for (size_t i = 0; i < cases; i++) {
        if (only != NULL && strstr(__matrix[i].name, only) == NULL) continue;

        for (uint64_t seed = 1; seed <= seeds; seed++) {
            char why[128] = { 0 };

            if (__matrix_run(&__matrix[i], seed * 7919, why, sizeof why)) continue;

            /* Named, and reproducible from the name: the seed is the whole
             * point of having one. */
            printf("      FAILED: %-18s seed %llu -- %s\n",
                   __matrix[i].name, (unsigned long long)(seed * 7919), why);
            failures++;
        }
    }

    TEST_ASSERT(failures == 0, "every combination completed");
}

TEST(test_quic_stand_flow_control) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a response stops at the receive window and resumes when credit arrives");
    /* The last of §2's list, and the one the client could not express: it
     * advertised 64 MB and never sent a MAX_DATA, so no window in the exchange
     * was ever reachable. A limit that is never met is a limit that is never
     * tested -- and the code that raises one is where three of this phase's
     * bugs were.
     *
     * Here it advertises 48 KB on the connection and 16 KB on the stream, and
     * the test reads nothing until it has checked that the server stopped. Both
     * limits are in play, and the smaller one has to bite first. */
    stand_t* s = __stand_create(20);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    const uint64_t conn_window = 48 * 1024;
    const uint64_t stream_window = 16 * 1024;

    TEST_ASSERT(quicclient_connect_inproc_windowed(&s->client, "localhost", s->trace,
                                                   __client_out, s,
                                                   conn_window, stream_window),
                "connecting with a window that can be reached");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    quicstream_t* qs = __open_request_stream(s);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");
    TEST_ASSERT(__consume_request(s, 0), "the request was read");

    const size_t total = 128 * 1024;
    uint8_t* body = __body_make(total);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");

    TEST_ASSERT(__respond(s, qs, body, total), "queued on the stream");

    /* Nothing is read here on purpose. */
    __run(s, 1000000, NULL);

    const size_t stalled_at = quicclient_stream_readable(&s->client, 0);

    if (s->trace)
        printf("      stalled at %zu bytes (stream window %llu), blocked frames %llu/%llu\n",
               stalled_at, (unsigned long long)stream_window,
               (unsigned long long)s->client.data_blocked_received,
               (unsigned long long)s->client.stream_data_blocked_received);

    /* It stopped, and it stopped at the smaller of the two limits rather than
     * wherever the congestion window happened to run out. */
    TEST_ASSERT(stalled_at >= stream_window, "the whole stream window was used");
    TEST_ASSERT(stalled_at <= stream_window + STAND_MAX_DGRAM,
                "and nothing beyond it");

    /* And it said so. A sender that stalls silently is indistinguishable from
     * one that has died, which is the whole reason §4.1 asks for the frame. */
    TEST_ASSERT(s->client.stream_data_blocked_received > 0, "and said it was blocked");

    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "and alive, not closed");

    /* Now read, which is what earns the credit -- and the rest arrives. */
    uint8_t* got = calloc(1, total);
    TEST_REQUIRE_NOT_NULL(got, "sink allocated");

    const size_t have = __drain(s, got, total);

    if (have != total || s->trace)
        printf("      after reading: %zu of %zu, blocked frames %llu/%llu\n",
               have, total,
               (unsigned long long)s->client.data_blocked_received,
               (unsigned long long)s->client.stream_data_blocked_received);

    TEST_ASSERT(have == total, "every byte arrived once the window opened");
    TEST_ASSERT(memcmp(got, body, total) == 0, "and in the right order, exactly once");
    TEST_ASSERT(quicclient_stream_fin(&s->client, 0), "and the stream finished");

    /* The connection-level limit was reached too -- 128 KB through a 48 KB
     * window cannot happen on one MAX_DATA. */
    TEST_ASSERT(s->client.conn_limit > conn_window, "the connection window was raised");

    free(got);
    free(body);
    __stand_free(s);
}

/* The body pattern, generated at an offset rather than held in memory: a
 * hundred megabytes of it would otherwise be two hundred, once to send and once
 * to compare. */
static void __pattern_fill(uint8_t* dst, size_t offset, size_t len) {
    for (size_t i = 0; i < len; i++) {
        const size_t j = offset + i;
        dst[i] = (uint8_t)(j * 31 + (j >> 8));
    }
}

TEST(test_quic_stand_stream_order) {
    TEST_SUITE("quic_stand");

    TEST_CASE("request streams are served oldest first, not newest first");
    /* REGRESSION. The list of streams was built by prepending, and the loop that
     * fills a packet with stream data walks it from the head and lets the first
     * stream that can send take as much of the packet as it will hold. Newest
     * first therefore meant strictly *reverse* order of arrival: four large
     * files asked for together came back last-requested-first, and the file the
     * client wanted first arrived only after all the others had finished. A page
     * blocked on its first stylesheet waited for the entire set.
     *
     * The order of this list is the scheduling policy, so this asserts the list
     * itself: unidirectional control streams (opened during the handshake) ahead
     * of any request, and request streams in ascending id. That is what RFC 9218
     * §7 recommends for equal-urgency, non-incremental responses. */
    stand_t* s = __stand_create(41);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_REQUIRE_GOTO(__start(s), "connecting", cleanup);
    TEST_REQUIRE_GOTO(__run(s, 2000000, __handshake_done), "handshake complete", cleanup);

    /* Opened in ascending order, which is the order a client makes requests in
     * -- the point is that the server must not reverse it. */
    const uint64_t ids[] = { 0, 4, 8 };

    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        TEST_REQUIRE_GOTO(quicclient_stream_write(&s->client, ids[i], (const uint8_t*)"GET", 3, 1),
                         "request written", cleanup);
        TEST_REQUIRE_GOTO(quicclient_flush(&s->client), "request flushed", cleanup);
        __run(s, 200000, NULL);
    }

    TEST_REQUIRE_NOT_NULL_GOTO(s->conn, "the connection is still up", cleanup);

    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++)
        TEST_REQUIRE_GOTO(quicconn_stream_find(s->conn, ids[i]) != NULL,
                         "the server has every request stream", cleanup);

    /* Walk the list the send loop walks. */
    int seen_bidi = 0;
    uint64_t previous_bidi = 0;
    int order_ok = 1;
    int uni_after_bidi = 0;

    for (const quicstream_t* qs = s->conn->streams; qs != NULL; qs = qs->next) {
        if (quic_stream_is_uni(qs->id)) {
            if (seen_bidi) uni_after_bidi = 1;
            continue;
        }

        if (seen_bidi && qs->id <= previous_bidi) order_ok = 0;

        previous_bidi = qs->id;
        seen_bidi = 1;
    }

    TEST_ASSERT(seen_bidi, "the request streams are on the list");
    TEST_ASSERT(order_ok, "request streams are in ascending id order, so the oldest is served first");
    TEST_ASSERT(!uni_after_bidi, "control streams stay ahead of any request");

    /* The head decides who gets the next packet, and it must be the first
     * request rather than the last. */
    const quicstream_t* first_bidi = NULL;
    for (const quicstream_t* qs = s->conn->streams; qs != NULL; qs = qs->next)
        if (!quic_stream_is_uni(qs->id)) { first_bidi = qs; break; }

    TEST_REQUIRE_NOT_NULL_GOTO(first_bidi, "a request stream is on the list", cleanup);
    TEST_ASSERT_EQUAL_UINT(0, first_bidi->id, "the first request asked for is the first one served");

    cleanup:
    __stand_free(s);
}

TEST(test_quic_stand_large_transfer) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a response far larger than any buffer arrives byte for byte");
    /* §2's "100 MB down one stream", which is a different test from the ones
     * above rather than a bigger one. What only size reaches: the send buffer's
     * compaction as acknowledgements retire its prefix, the packet number
     * growing past its short encodings, the congestion window in steady state
     * rather than in slow start, and the write-ahead budget -- the application
     * here refills through quicconn_write_room exactly as the h3 layer does,
     * so the buffer stays bounded while the stream does not.
     *
     * One megabyte by default, because the whole runner is two seconds and a
     * sanitised build moves about 2 MB a second (docs/http3/08 §7). The real
     * figure is a Release build and STAND_BIG_MB=100, which is where this was
     * measured; the small default keeps the path itself under test everywhere. */
    size_t megabytes = 1;
    const char* env = getenv("STAND_BIG_MB");
    if (env != NULL) {
        const long n = strtol(env, NULL, 10);
        if (n > 0) megabytes = (size_t)n;
    }

    const size_t total = megabytes * 1024 * 1024;

    stand_t* s = __stand_create(24);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    quicstream_t* qs = __open_request_stream(s);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");
    TEST_ASSERT(__consume_request(s, 0), "the request was read");

    uint8_t chunk[64 * 1024];
    uint8_t got[64 * 1024];

    size_t written = 0;
    size_t have = 0;
    int intact = 1;

    const uint64_t began = __now_us;
    const clock_t wall = clock();

    for (int round = 0; round < 20000000 && have < total; round++) {
        /* Top up as far as the write-ahead budget allows, which is what an
         * application is supposed to do and what nothing else here tests. */
        if (s->conn != NULL && written < total) {
            size_t before = written;

            connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);

            while (written < total) {
                const size_t room = quicconn_write_room(s->conn);
                if (room == 0) break;

                size_t take = room < sizeof chunk ? room : sizeof chunk;
                if (take > total - written) take = total - written;

                __pattern_fill(chunk, written, take);
                if (!quicstream_write(qs, chunk, take)) break;

                written += take;
            }

            if (written == total) quicstream_finish(qs);

            connection_s_unlock(&s->conn->conn);

            /* Only when something was actually produced. Waking the endpoint on
             * every turn of this loop keeps it permanently woken -- and since a
             * woken endpoint is an event due *now*, the stand's clock stops
             * advancing and the datagrams already in flight never arrive. The
             * first version of this test spun twenty million times at t=0. */
            if (written > before) quicconn_want_write(&s->conn->conn);
        }

        const size_t ready = quicclient_stream_readable(&s->client, 0);

        if (ready == 0) {
            if (!__step(s, __now_us + 120000000)) break;
            continue;
        }

        size_t want = ready < sizeof got ? ready : sizeof got;
        if (want > total - have) want = total - have;

        const size_t n = quicclient_stream_read(&s->client, 0, got, want);

        /* Verified against the generator as it arrives, so nothing has to be
         * kept: at this size the comparison buffer would be the memory. */
        __pattern_fill(chunk, have, n);
        if (memcmp(got, chunk, n) != 0) intact = 0;

        have += n;

        if (!quicclient_flush(&s->client)) break;
    }

    const uint64_t elapsed = __now_us - began;

    if (megabytes > 4 || have != total || s->trace) {
        const double cpu_ms = (double)(clock() - wall) * 1000.0 / CLOCKS_PER_SEC;

        /* Cost per megabyte, not total: the open question in §7 is whether it
         * grows with the size of the transfer, and a total tells you nothing
         * about that without arithmetic done by hand. */
        printf("      %zu MB: %zu bytes, %llu ms virtual, %.0f ms CPU"
               " (%.2f ms/MB, %.1f MB/s virtual)\n",
               megabytes, have, (unsigned long long)(elapsed / 1000), cpu_ms,
               cpu_ms / (double)megabytes,
               elapsed > 0 ? (double)have / (double)elapsed : 0.0);
    }

    TEST_ASSERT(have == total, "every byte arrived");
    TEST_ASSERT(intact, "and in the right order, exactly once");
    TEST_ASSERT(quicclient_stream_fin(&s->client, 0), "and the stream finished");

    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "and unharmed");

    /* The point of refilling through the budget: the send buffer never held the
     * whole response, however big the response was. */
    TEST_ASSERT(quicconn_unsent_bytes(s->conn) <= QUICCONN_WRITE_AHEAD_MAX,
                "the write-ahead budget was respected throughout");

    __stand_free(s);
}

TEST(test_quic_stand_bottleneck) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a transfer through a 10 Mbps link with a 25-packet queue stays inside the path");
    /* The interop path, in process: `simple-p2p --delay=15ms --bandwidth=10Mbps
     * --queue=25`. Nothing here loses at random -- every drop is the sender's
     * own overrun coming back to it, which is the only congestion signal the
     * path offers and the only one that matters.
     *
     * This is the regression test for §3i, where the send window was checked
     * after a packet had already gone out: the sender ran at line rate, emptied
     * a flow-control window into a queue that could hold a twentieth of it, and
     * the peer received under a tenth of what was sent. That failure is a ratio,
     * so the assertion is a ratio. */
    stand_t* s = __stand_create(12);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    s->delay_us = 15000;

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    quicstream_t* qs = __open_request_stream(s);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");

    const size_t total = 512 * 1024;
    uint8_t* body = __body_make(total);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");

    TEST_ASSERT(__respond(s, qs, body, total), "queued on the stream");

    /* The bottleneck switches on only now, so the handshake above is not part of
     * what is being measured. */
    s->bandwidth_bps = 10 * 1000 * 1000;
    s->queue_pkts = 25;

    const uint64_t began = __now_us;

    uint8_t* got = calloc(1, total);
    TEST_REQUIRE_NOT_NULL(got, "sink allocated");

    const size_t have = __drain(s, got, total);
    const uint64_t elapsed = __now_us - began;
    const uint64_t queue_drops = s->queue_dropped_to_client;

    if (have != total || s->trace)
        printf("      %zu of %zu bytes in %llu us; sent %llu, delivered %llu, "
               "queue drops %llu\n",
               have, total, (unsigned long long)elapsed,
               (unsigned long long)s->sent_to_client,
               (unsigned long long)s->delivered_to_client,
               (unsigned long long)queue_drops);

    TEST_ASSERT(have == total, "every byte arrived");
    TEST_ASSERT(memcmp(got, body, total) == 0, "and in the right order, exactly once");

    /* The queue was reached: without a drop somewhere, the transfer never found
     * the edge of the path and the test would be measuring an idle link. */
    TEST_ASSERT(queue_drops >= 1, "the bottleneck was actually reached");

    /* Three quarters of what was sent came out the other end. Measured: 426 of
     * 485, and §3i's sender managed under a tenth -- so the bar is set where it
     * separates those two rather than where it pins today's number.
     *
     * It cannot be set much higher, and that is a property of the path rather
     * than of the sender: the queue (25 packets) is smaller than the
     * bandwidth-delay product (10 Mbps x 30 ms is ~31), so a loss-based
     * controller has to overrun it to find it. Of the 59 drops measured, 57 fell
     * in one burst of ~57 ms -- two round trips, which is exactly how long it
     * takes to fill the queue and then hear about it -- and only 2 in the
     * remaining 380 ms. Textbook slow-start overshoot, written down here so the
     * next person to see a loss burst at the start of a transfer knows it is the
     * path talking. */
    TEST_ASSERT(s->delivered_to_client * 4 >= s->sent_to_client * 3,
                "most of what was sent was carried, so the sender was not blasting");

    /* 512 KB at 10 Mbps is 419 ms of pure serialisation, and the transfer took
     * 497 -- the link ran at 84 %. The ceiling is the assertion that matters:
     * a sender that stalls on a lost tail, or that spends a round trip per
     * window, fails here and nowhere else. */
    TEST_ASSERT(elapsed >= 419000, "no faster than the link allows");
    TEST_ASSERT(elapsed <= 700000, "and it kept the link busy rather than stalling");

    TEST_ASSERT(quicclient_stream_fin(&s->client, 0), "and the stream finished");

    free(got);
    free(body);
    __stand_free(s);
}

TEST(test_quic_stand_lossy_bottleneck) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a transfer finishes through a lossy bottleneck, FIN included");
    /* The same link with 2 % random loss on top -- the shape of the interop
     * `transferloss` case, and the closest this stand gets to the matrix.
     *
     * Two failure modes meet here and only here. Loss on top of a queue means a
     * retransmission has to get through a path that is already full, which is
     * where §3i's retransmission-blocked-by-flow-control deadlock lived. And the
     * FIN is asserted separately from the bytes because §3t was exactly that:
     * every byte arrived, the stream never ended, and the peer waited 420
     * seconds for a frame that was riding inside a duplicate. */
    stand_t* s = __stand_create(13);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    s->delay_us = 15000;

    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    quicstream_t* qs = __open_request_stream(s);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");

    const size_t total = 256 * 1024;
    uint8_t* body = __body_make(total);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");

    TEST_ASSERT(__respond(s, qs, body, total), "queued on the stream");

    s->bandwidth_bps = 10 * 1000 * 1000;
    s->queue_pkts = 25;
    s->loss_to_client_pct = 2;
    s->loss_to_server_pct = 2;

    uint8_t* got = calloc(1, total);
    TEST_REQUIRE_NOT_NULL(got, "sink allocated");

    const size_t have = __drain(s, got, total);

    if (have != total || s->trace)
        printf("      %zu of %zu bytes; lost %llu/%llu, queue drops %llu\n",
               have, total,
               (unsigned long long)s->lost_to_client,
               (unsigned long long)s->lost_to_server,
               (unsigned long long)s->queue_dropped_to_client);

    TEST_ASSERT(have == total, "every byte arrived");
    TEST_ASSERT(memcmp(got, body, total) == 0, "and in the right order, exactly once");
    TEST_ASSERT(s->lost_to_client > 0 && s->lost_to_server > 0, "both directions lost");
    TEST_ASSERT(quicclient_stream_fin(&s->client, 0), "and the stream finished");

    free(got);
    free(body);
    __stand_free(s);
}

TEST(test_quic_stand_connection_close) {
    TEST_SUITE("quic_stand");

    TEST_CASE("CONNECTION_CLOSE reaches the peer and the connection drains");
    stand_t* s = __stand_create(6);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    quicconn_close(s->conn, QUIC_APPLICATION_ERROR, 1, __now_us);
    connection_s_unlock(&s->conn->conn);

    quicconn_want_write(&s->conn->conn);

    TEST_ASSERT(__run(s, 1000000, __closed), "the client was told");
    TEST_ASSERT(s->client.close_error == QUIC_APPLICATION_ERROR, "with the code we sent");

    /* §10.2.1: the closing endpoint holds the packet for three PTOs so a lost
     * close is re-sent in answer to anything that arrives, and only then goes. */
    TEST_ASSERT(__run(s, 5000000, __conn_gone), "and the connection was reaped");

    __stand_free(s);
}

TEST(test_quic_stand_close_during_handshake) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a connection closed mid-handshake is readable by a peer that has no 1-RTT keys");
    /* The most expensive defect h3spec found (§3d.7), as a test.
     *
     * CONNECTION_CLOSE used to go out at one level, chosen by *our* keys -- and
     * a server owns 1-RTT keys from the moment it sends its Finished, a whole
     * flight before the client can read them. Every error found during a
     * handshake therefore travelled in a packet the peer could not open: the
     * server closed correctly and the peer saw silence until its timeout,
     * which is the worst failure mode the protocol has.
     *
     * So the assertion is not "it closed" but "the peer read the close", and
     * the moment is chosen to be exactly the one that used to fail: the client
     * has sent its ClientHello and nothing more. */
    stand_t* s = __stand_create(21);
    TEST_REQUIRE_NOT_NULL(s, "stand created");

    TEST_ASSERT(__start(s), "the ClientHello went out");

    /* One step: the server has the flight and has answered, and the client has
     * not yet processed the answer, so it holds Initial keys and nothing else. */
    __step(s, __now_us + 100000);

    TEST_REQUIRE_NOT_NULL(s->conn, "the server accepted the connection");
    TEST_ASSERT(s->conn->state == QUICCONN_HANDSHAKE, "and is still handshaking");
    TEST_ASSERT(!s->client.tx[QUIC_ENC_APP].valid, "the client has no 1-RTT keys yet");

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    quicconn_close(s->conn, QUIC_CONNECTION_REFUSED, 0, __now_us);
    connection_s_unlock(&s->conn->conn);
    quicconn_want_write(&s->conn->conn);

    TEST_ASSERT(__run(s, 1000000, __closed), "the client read the close");
    TEST_ASSERT(s->client.close_error == QUIC_CONNECTION_REFUSED, "with the reason");

    __stand_free(s);
}

TEST(test_quic_stand_closing_repeats) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a closing connection answers what arrives, and only that (§10.2.1)");
    /* §10.2.1 gives the closing state one job: re-send the close packet in
     * answer to an incoming packet, so a lost close does not leave the peer
     * waiting out its idle timeout. In answer to a packet -- not on a timer,
     * which is what makes a peer that keeps sending unable to turn this into an
     * amplifier.
     *
     * Both halves are asserted, and the second is the one a lazy implementation
     * gets wrong: silence when nothing arrives. */
    stand_t* s = __stand_create(22);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    quicconn_close(s->conn, QUIC_APPLICATION_ERROR, 1, __now_us);
    connection_s_unlock(&s->conn->conn);
    quicconn_want_write(&s->conn->conn);

    TEST_ASSERT(__run(s, 1000000, __closed), "the first close arrived");

    /* Quiet: nothing goes to a peer that says nothing. Kept short on purpose --
     * the closing period is three PTOs, and a longer look would be measuring
     * the connection's reaping instead. */
    const uint64_t after_first = s->sent_to_client;
    __run(s, 50000, NULL);
    TEST_ASSERT(s->sent_to_client == after_first, "and nothing is sent unprompted");
    TEST_REQUIRE_NOT_NULL(s->conn, "still closing, not yet reaped");

    /* Prompted: a packet arrives, an answer goes back. */
    TEST_ASSERT(quicclient_ping(&s->client), "poke it");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");
    __run(s, 500000, NULL);

    TEST_ASSERT(s->sent_to_client > after_first, "the close was repeated on demand");

    __stand_free(s);
}

TEST(test_quic_stand_draining) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a peer's CONNECTION_CLOSE puts us in draining: silent, then gone (§10.2.2)");
    /* The state nothing else here reaches. Told that the peer has closed, an
     * endpoint must send nothing at all -- not even an acknowledgement of what
     * it has just been told -- and wait the period out, so that a late packet
     * cannot provoke a stateless reset at a peer that has already gone.
     *
     * "Nothing at all" is the assertion, and it is worth making because the
     * natural implementation of a receive path is to answer. */
    stand_t* s = __stand_create(23);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    TEST_ASSERT(quicclient_close(&s->client, 0x99, 0), "the client closes");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");

    /* Stopped at the state rather than after a fixed window: the drain period
     * is three PTOs, and a window long enough to be safe is also long enough to
     * outlast it -- the connection would be gone before the assertion looked. */
    TEST_ASSERT(__run(s, 200000, __draining), "the peer's close put it in draining");

    /* Not a word, whatever arrives. */
    const uint64_t quiet_from = s->sent_to_client;

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(quicclient_ping(&s->client), "poke it");
        TEST_ASSERT(quicclient_flush(&s->client), "sent");
        __run(s, 200000, NULL);
    }

    TEST_ASSERT(s->sent_to_client == quiet_from, "and it said nothing at all");

    /* And then it goes, rather than sitting in the table for ever. */
    TEST_ASSERT(__run(s, 5000000, __conn_gone), "the connection was reaped");

    __stand_free(s);
}

TEST(test_quic_stand_cid_rotation) {
    TEST_SUITE("quic_stand");

    TEST_CASE("the peer may address us by any id we issued, and retire the rest");
    stand_t* s = __stand_create(7);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    /* The ids arrive in NEW_CONNECTION_ID frames after the handshake. */
    __run(s, 200000, NULL);
    TEST_ASSERT(s->client.server_cid_count > 1, "the server issued spare ids");

    TEST_ASSERT(quicclient_use_cid(&s->client, s->client.server_cid_count - 1),
                "address it by the newest one");
    TEST_ASSERT(quicclient_retire_cid(&s->client, 0), "and retire the original");
    TEST_ASSERT(quicclient_ping(&s->client), "with something ack-eliciting to carry it");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");

    const uint64_t before = s->client.datagrams_received;
    __run(s, 500000, NULL);

    TEST_ASSERT(s->client.datagrams_received > before,
                "the connection still answers on the new id");
    TEST_REQUIRE_NOT_NULL(s->conn, "and is alive");
    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "still active");

    /* The retired sequence number is gone -- not the slot, which §5.1.1 says
     * must be refilled at once, and which __cids_replenish does before the
     * retirement has finished being processed. What must not survive is
     * sequence 0 itself: while it is there, the id it names still routes. */
    int seq0_alive = 0;
    for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++)
        if (s->conn->local_cids[i].active && s->conn->local_cids[i].seq == 0)
            seq0_alive = 1;

    TEST_ASSERT(!seq0_alive, "the retired id was released");

    __stand_free(s);
}

TEST(test_quic_stand_key_update) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a key update is followed, and the old generation still opens what was in flight");
    stand_t* s = __stand_create(8);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    /* The server only ever answers an update (§6.1), so the client has to be
     * the one that starts it. */
    TEST_ASSERT(quicclient_key_update(&s->client), "client moved to the next generation");
    TEST_ASSERT(quicclient_ping(&s->client), "and said something in it");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");

    TEST_ASSERT(__run(s, 1000000, __read_after_update),
                "the server answered in the new phase");
    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    TEST_ASSERT(s->conn->key_phase == 1, "and flipped its own phase bit");

    /* The generation before is retained for a while (§6.3): a packet the server
     * sent before it noticed the update -- typically the acknowledgement of the
     * very packet that carried it -- can only be opened with the old keys, and
     * dropping it would cost a retransmission on every update. */
    TEST_ASSERT(s->conn->key_prev_expire_us > __now_us, "the old keys are still held");

    TEST_ASSERT(s->conn->state == QUICCONN_ACTIVE, "and the connection is unharmed");

    __stand_free(s);
}

TEST(test_quic_stand_migration) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a peer that moves is challenged before it is believed (RFC 9000 §9)");
    stand_t* s = __stand_create(9);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    __run(s, 200000, NULL);   /* let the spare connection ids arrive */
    TEST_REQUIRE_NOT_NULL(s->conn, "connected");

    const unsigned short old_port =
        ntohs(((struct sockaddr_in*)&s->conn->path.remote)->sin_port);

    /* A NAT rebinding: the same connection, arriving from a port the server has
     * never validated. The emulator owns the address, so this is where it
     * changes; the client's half is picking an id the old path never saw. */
    __addr(&s->client_path.remote, &s->client_path.remote_len, "127.0.0.1", 50001);
    TEST_ASSERT(quicclient_rebind(&s->client), "the client moved");
    TEST_ASSERT(quicclient_ping(&s->client), "and spoke from the new address");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");

    TEST_ASSERT(__run(s, 2000000, __challenged), "the server challenged the new path");

    /* And only after the answer does it move. Anything else would make a
     * spoofed source address a way to redirect a connection's output. */
    TEST_ASSERT(__run(s, 2000000, __migrated), "and moved once the answer came back");

    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    TEST_ASSERT(old_port == 50000, "it started on the old port");
    TEST_ASSERT(s->client.path_challenge_received, "the client was asked");

    __stand_free(s);
}


/* The qlog, against a real handshake rather than against the writer.
 *
 * The unit test in test_quic_common.c proves the file format; this proves the
 * part that actually fails in practice -- that the events are emitted from the
 * paths a connection really takes. A trace facility whose call sites are in the
 * wrong place produces a perfectly valid file that says nothing, and nothing
 * short of running a connection catches that. */
static int __qlog_find(const char* dir, char* out, size_t out_len) {
    DIR* d = opendir(dir);
    if (d == NULL) return 0;

    int found = 0;
    struct dirent* entry;

    while ((entry = readdir(d)) != NULL) {
        const size_t len = strlen(entry->d_name);
        if (len < 7 || strcmp(entry->d_name + len - 6, ".sqlog") != 0) continue;

        snprintf(out, out_len, "%s/%s", dir, entry->d_name);
        found = 1;
        break;
    }

    closedir(d);
    return found;
}

TEST(test_quic_stand_qlog) {
    TEST_SUITE("quic_stand");

    TEST_CASE("a handshake writes a readable trace");

    char dir[] = "/tmp/cwfr_qlog_standXXXXXX";
    TEST_REQUIRE_NOT_NULL(mkdtemp(dir), "temporary directory for the trace");
    TEST_ASSERT(quicqlog_configure(dir, 4), "qlog enabled for this test only");

    stand_t* s = __stand_create(1);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "the first Initial went out");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");
    TEST_REQUIRE_NOT_NULL(s->conn, "the connection is still there");
    TEST_ASSERT(s->conn->qlog != NULL, "the connection opened a trace");

    char path[512];
    TEST_ASSERT(__qlog_find(dir, path, sizeof path), "a .sqlog exists for it");

    static char body[262144];
    size_t len = 0;
    FILE* f = fopen(path, "rb");
    if (f != NULL) {
        len = fread(body, 1, sizeof body - 1, f);
        fclose(f);
    }
    body[len] = 0;

    TEST_ASSERT(len > 0, "and it has been written to while the connection runs");
    TEST_ASSERT(strstr(body, "\"name\":\"connectivity:connection_started\"") != NULL,
                "the connection announced itself");
    TEST_ASSERT(strstr(body, "\"name\":\"transport:packet_received\"") != NULL,
                "packets the client sent are in the trace");
    TEST_ASSERT(strstr(body, "\"name\":\"transport:packet_sent\"") != NULL,
                "so are the ones the server built");
    TEST_ASSERT(strstr(body, "\"name\":\"recovery:metrics_updated\"") != NULL,
                "recovery reported the window and the round trip");
    TEST_ASSERT(strstr(body, "\"name\":\"connectivity:connection_state_updated\"") != NULL,
                "and the handshake completing is an event of its own");

    /* Every record is one line and starts with the JSON-SEQ separator: a reader
     * splits on newlines, so an event that emitted one of its own would corrupt
     * the record after it rather than itself. */
    int records = 0;
    int malformed = 0;
    for (size_t i = 0; i < len; i++) {
        if (body[i] != 0x1e) continue;
        records++;
        if (i > 0 && body[i - 1] != '\n') malformed++;
    }

    TEST_ASSERT(records > 4, "the trace holds more than the header");
    TEST_ASSERT(malformed == 0, "and every record begins a line");

    __stand_free(s);

    /* Turned off before anything else runs in this process, and the file
     * removed: the suite runs under the sanitizers and in CI. */
    quicqlog_configure("", 0);
    unlink(path);
    rmdir(dir);
}


/* The search has finished: nothing outstanding, and the size has moved. */
static int __pmtu_settled(stand_t* s) {
    return s->conn != NULL && !s->conn->pmtud.outstanding &&
           s->conn->pmtud.current == s->conn->pmtud.ceiling;
}

TEST(test_quic_stand_dplpmtud) {
    TEST_SUITE("quic_stand");

    TEST_CASE("the packet size search finishes over a clean path");
    /* The counters this feature grew (pmtu.probes_*) reported three probes and
     * three timeouts against the live stand, and the qlog said the probes were
     * declared lost by the reordering threshold -- which on loopback means the
     * client's receive queue overflowed, not that the path is small. The
     * question that leaves open is whether the search can EVER finish, and only
     * a path with no queue to overflow can answer it. That is this stand. */
    stand_t* s = __stand_create(1);
    TEST_REQUIRE_NOT_NULL(s, "stand created");
    TEST_ASSERT(__start(s), "connecting");
    TEST_ASSERT(__run(s, 2000000, __handshake_done), "handshake complete");

    TEST_ASSERT(quicclient_stream_write(&s->client, 0, (const uint8_t*)"GET", 3, 1), "request");
    TEST_ASSERT(quicclient_flush(&s->client), "sent");
    __run(s, 200000, NULL);

    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");
    quicstream_t* qs = quicconn_stream_find(s->conn, 0);
    TEST_REQUIRE_NOT_NULL(qs, "the server has the stream");

    const size_t base = s->conn->pmtud.current;
    const size_t ceiling = s->conn->pmtud.ceiling;
    TEST_ASSERT(base == QUIC_DEFAULT_UDP_PAYLOAD, "the search starts at the safe base");
    TEST_ASSERT(ceiling > base, "and has somewhere to go over IPv4");

    /* A probe is only attempted when there is enough queued to make a larger
     * packet worth having -- four datagrams' worth (quicconn_send). */
    const size_t total = 256 * 1024;
    uint8_t* body = malloc(total);
    TEST_REQUIRE_NOT_NULL(body, "body allocated");
    memset(body, 'x', total);

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    const int written = quicstream_write(qs, body, total);
    quicstream_finish(qs);
    connection_s_unlock(&s->conn->conn);
    TEST_ASSERT(written, "queued on the stream");

    quicconn_want_write(&s->conn->conn);

    uint8_t* got = calloc(1, total);
    TEST_REQUIRE_NOT_NULL(got, "sink allocated");
    size_t have = 0;

    for (int round = 0; round < 40000 && have < total; round++) {
        if (!__step(s, __now_us + 60000000)) break;

        const size_t ready = quicclient_stream_readable(&s->client, 0);
        if (ready == 0) continue;

        have += quicclient_stream_read(&s->client, 0, got + have,
                                       total - have < ready ? total - have : ready);
    }

    TEST_ASSERT(have == total, "the whole body arrived");
    TEST_REQUIRE_NOT_NULL(s->conn, "still connected");

    /* On the *first* transfer, and that is the assertion.
     *
     * The search used to be held off for ten PTOs after the handshake, so this
     * same transfer ended at the base size and the test had to wait out the
     * window and send a second request to see a probe at all. A PTO is not a
     * small number on a loaded server -- most of it is the server's own receive
     * queue -- and ten of them outlived the connections that were paying for
     * them: measured on the profile of record, most of a hundred connections
     * never probed once and spent their whole life at 1350 bytes into a path
     * that takes 1472 (docs/http3/08 §13). The delay is gone, and with it the
     * property the old version of this test recorded: a connection that serves
     * one response and stops now does leave the base size.
     *
     * The probe rides the transfer, but its acknowledgement may arrive after
     * the last body byte the client reads -- so the search is given the round
     * trip it is waiting on rather than being judged at the moment the loop
     * above happens to end. */
    __run(s, 1000000, __pmtu_settled);

    TEST_ASSERT(s->conn->pmtud.current == ceiling,
                "the probe was acknowledged, so the packet size rose to the ceiling");
    TEST_ASSERT(s->conn->pmtud.current > base, "which is above where it started");
    TEST_ASSERT(s->conn->cc.max_datagram_size == s->conn->pmtud.current,
                "the congestion controller counts in the new size too");
    TEST_ASSERT(!s->conn->pmtud.outstanding, "no probe is left hanging");
    TEST_ASSERT(!quicpmtud_should_probe(&s->conn->pmtud, __now_us),
                "and the search is over: there is nowhere left to go");

    free(got);
    free(body);
    __stand_free(s);
}

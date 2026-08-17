#ifndef __METRICS__
#define __METRICS__

#include <stdatomic.h>
#include <stdint.h>

#include "json.h"

/* Runtime counters for the connection-concurrency work
 * (docs/concurrency/00-handler-concurrency.md, phase D).
 *
 * Three questions and nothing else:
 *   - how long a thread waits for connection_s_lock (§4.7, §5.1) — the lock is
 *     now supposed to be held for microseconds, and there is no other way to
 *     notice when something starts holding it across a handler again;
 *   - how many handlers of ONE connection run at once (§5) — the whole point of
 *     phases B and C, and the first thing a regression would silently undo;
 *   - how deep ctx->queue was when a worker took an item (§5.2) — a queue that
 *     stays deep means the fan-out is not fanning out.
 *
 * Off unless "metrics": true is set in the config's main.env block. The flag is
 * checked at every instrumented point, so with metrics off the cost is one
 * relaxed load — in particular no clock_gettime(), which is the only part
 * expensive enough to matter on the lock path.
 *
 * Counters are process-wide (workers and handlers are threads of one process)
 * and updated with relaxed atomics: they are statistics, not invariants, so
 * ordering between them buys nothing and the read-modify-write is what costs.
 */

/* Where connection_s_lock was taken (docs/concurrency/01, phase A).
 *
 * Phase D counted waits in one pile, which was enough to see that the
 * distribution has two humps but not to say what sits under the second one. A
 * tag per acquisition splits the same histogram by call site, so "publication
 * waits behind I/O" becomes something the counters state rather than something
 * the code review guesses. It is also what turned up the section that pile had
 * been hiding — an empty-for-h2 dispatch lock costing more than every I/O guard
 * together (`01` §6 A.4).
 *
 * Semantic names, not __FILE__:__LINE__: the phases of `01` are accepted per
 * tag ("the hump on the read/write tags is gone"), and a tag that moves with an
 * unrelated edit above it cannot carry that. LOCK_SITE_OTHER is the fallback for
 * paths nobody has looked at yet — a non-trivial count there means the split is
 * incomplete, so it is worth reading. */
typedef enum {
    LOCK_SITE_OTHER = 0,
    LOCK_SITE_H2_READ,          /* h2_server_guard_read  — recv + frame parse + dispatch */
    LOCK_SITE_H2_WRITE,         /* h2_server_guard_write — framing + send */
    LOCK_SITE_H2_PUBLISH,       /* handler thread publishing an h2 response */
    LOCK_SITE_H2_REARM,         /* handler thread re-arming epoll after pushing an h2 response */
    LOCK_SITE_HTTP_READ,        /* http_server_guard_read */
    LOCK_SITE_HTTP_WRITE,       /* http_server_guard_write */
    LOCK_SITE_HTTP_DISPATCH,    /* binding request/response before user code runs */
    LOCK_SITE_HTTP_PUBLISH,     /* handler thread publishing an h1.1 response */
    LOCK_SITE_WS_READ,          /* websockets_guard_read */
    LOCK_SITE_WS_WRITE,         /* websockets_guard_write */
    LOCK_SITE_WS_RESERVE,       /* reserving a place in the ws output order */
    LOCK_SITE_WS_PUBLISH,       /* filling a reserved ws slot + re-arm */
    LOCK_SITE_BROADCAST,        /* broadcast batch runner */
    LOCK_SITE_CLOSE,            /* connection_close / listener teardown */
    /* The timer sweep. Never counted as an acquisition — connection_s_trylock
     * does not wait, and folding a per-second sweep into the totals would dilute
     * the contention ratio — but it does hold the lock, so it has to be nameable
     * as a blocker. */
    LOCK_SITE_TICK,
    /* QUIC puts more under the connection lock than HTTP/2 did -- decryption,
     * reassembly and congestion control join the frame parsing that was
     * already there. These two tags are how that shows up as a number rather
     * than as a suspicion (docs/http3/01-udp-endpoint.md §8). */
    LOCK_SITE_QUIC_RECV,        /* endpoint handing a datagram to a connection */
    LOCK_SITE_QUIC_SEND,        /* endpoint building that connection's packets */
    /* The h3 counterparts of the two h2 publish tags. Measured apart from h2's
     * on purpose: the two protocols reach the same publish code by different
     * paths (epoll re-arm versus quicconn_want_write), and a shared tag would
     * make it impossible to tell which one is waiting. */
    LOCK_SITE_H3_PUBLISH,       /* handler thread publishing an h3 response */
    LOCK_SITE_H3_REARM,         /* handler thread waking the endpoint after it */
    LOCK_SITE__COUNT
} metrics_lock_site_t;

/* HTTP/2 abuse limits (docs/http2/08-spec-gaps.md, phase A).
 *
 * Every one of these ends a stream or a connection. Without a counter per limit
 * an operator sees only "clients keep getting disconnected" and cannot tell an
 * attack from a client this server has started rejecting wrongly — which is the
 * failure mode these limits actually have, since each one guesses a threshold.
 * They fire once per victim, so unlike the lock counters they are free. */
typedef enum {
    METRICS_H2_FLOW_CONN = 0,     /* peer overran the connection receive window */
    METRICS_H2_FLOW_STREAM,       /* peer overran a stream's receive window */
    METRICS_H2_RST_FLOOD,         /* stream-abort budget spent (Rapid Reset) */
    METRICS_H2_CONT_FLOOD,        /* too many CONTINUATION frames in one block */
    METRICS_H2_HEADER_LIST,       /* header list over the advertised limit → 431 */
    METRICS_H2_HEADER_LIST_HARD,  /* header list over the hard cap → connection */
    METRICS_H2_HEADER_LIST_FLOOD, /* 431s repeated until the abort budget ran out */
    METRICS_H2_CTRL_FLOOD,        /* PING/SETTINGS/empty DATA/PRIORITY budget spent */
    METRICS_H2_OUT_BACKLOG,       /* peer stopped reading and the queue hit its cap */
    METRICS_H2_ABUSE__COUNT
} metrics_h2_abuse_t;

#ifdef CWFR_HTTP3
/* QUIC endpoint counters (docs/http3/01-udp-endpoint.md §9).
 *
 * The UDP endpoint answers unauthenticated datagrams from anyone, so unlike TCP
 * there is no accept() to tell "a peer connected" from "a peer sent noise". The
 * only way to tell a firewall problem from a scanner from a real client is to
 * count why each datagram was dropped -- which is why the drop reasons are
 * separate counters and not one total. The first question asked of a silent h3
 * server is always "do datagrams arrive at all", and these answer it.
 *
 * Datagram counters sit on the per-datagram path; each is one relaxed
 * read-modify-write behind a relaxed load of the enable flag. */
typedef enum {
    METRICS_QUIC_DGRAM_RECEIVED = 0,
    METRICS_QUIC_DGRAM_SENT,
    METRICS_QUIC_BYTES_RECEIVED,
    METRICS_QUIC_BYTES_SENT,
    /* Datagrams received divided by this gives the average recvmmsg batch --
     * the number that says whether batching is earning anything. */
    METRICS_QUIC_RECV_CALLS,

    /* Transmit batching/offload. datagrams_sent alone cannot distinguish a
     * healthy GSO path from hundreds of thousands of one-packet messages. */
    METRICS_QUIC_SEND_BATCH_CALLS,
    METRICS_QUIC_SEND_BATCH_MESSAGES,
    METRICS_QUIC_SEND_GSO_MESSAGES,
    METRICS_QUIC_SEND_GSO_SEGMENTS,
    METRICS_QUIC_SEND_GSO_FALLBACKS,
    METRICS_QUIC_SEND_PARTIAL,

    /* Drops, by reason. */
    METRICS_QUIC_DROP_TRUNCATED,      /* buffer ended inside the invariant header */
    METRICS_QUIC_DROP_OVERSIZE,       /* larger than the receive buffer (MSG_TRUNC) */
    METRICS_QUIC_DROP_CID_TOO_LONG,   /* connection id past RFC 9000 §5.1's 20 bytes */
    METRICS_QUIC_DROP_SHORT_INITIAL,  /* long header in a datagram under 1200 bytes */
    METRICS_QUIC_DROP_UNKNOWN_CID,    /* no connection, and nothing owed in reply */
    METRICS_QUIC_DROP_NO_BUDGET,      /* a reply was owed but the rate limit said no */
    METRICS_QUIC_DROP_PEER_VN,
    /* Dropped by the kernel before we ever saw them, because the socket's
     * receive queue was full (SO_RXQ_OVFL). The only drop counter here that is
     * not our own decision, and the only one that says the machine, not the
     * peer, is the problem: raise http3_so_rcvbuf. */
    METRICS_QUIC_DROP_KERNEL_OVERFLOW,        /* a peer sent US a Version Negotiation packet */

    METRICS_QUIC_VERSION_NEGOTIATION, /* Version Negotiation packets sent */
    METRICS_QUIC_STATELESS_RESET,     /* stateless resets sent */

    /* A connection is created by the first Initial that gets that far, so this
     * is also "handshakes started" -- the denominator of everything below. A
     * second counter for it would only be a second name for the same event. */
    METRICS_QUIC_CONN_ACCEPTED,
    METRICS_QUIC_CONN_CLOSED,

    METRICS_QUIC_SEND_ERROR,

    /* ---- Connection-level counters (docs/http3/07-integration.md §3) ----
     *
     * The endpoint counters above say whether datagrams arrive. These say what
     * happens to them afterwards, and they exist because the debugging that
     * closed phase 6 had to be done without them: three unrelated causes all
     * showed as ERR_QUIC_PROTOCOL_ERROR in the browser, and telling them apart
     * took a byte count read off a log. `handshakes_failed.tls` alone would
     * have named the certificate rejection immediately (docs/http3/05 §10). */
    METRICS_QUIC_HANDSHAKE_COMPLETED,
    METRICS_QUIC_HANDSHAKE_FAILED_TLS,      /* the TLS stack refused the flight */
    METRICS_QUIC_HANDSHAKE_FAILED_TIMEOUT,  /* idle timeout before completion */

    /* 0-RTT (RFC 9001 §4.6). `offered` counts handshakes where a client
     * presented early data at all, `accepted` those where TLS took it -- the
     * gap is tickets refused, which is what a resumption context change or the
     * replay defence looks like from here. `packets` and `bytes` are what
     * actually arrived at the 0-RTT level, and are what says whether the
     * feature is doing anything: accepted handshakes with zero packets mean
     * clients are resuming but sending nothing early. */
    METRICS_QUIC_EARLY_DATA_OFFERED,
    METRICS_QUIC_EARLY_DATA_ACCEPTED,
    METRICS_QUIC_EARLY_DATA_PACKETS,
    METRICS_QUIC_EARLY_DATA_BYTES,

    METRICS_QUIC_DECRYPT_FAILURE,           /* AEAD open failed; usually harmless */
    METRICS_QUIC_AEAD_LIMIT,                /* §6.6 confidentiality limit reached */
    /* Key updates applied. Read next to decrypt_failures: before key updates
     * existed, a peer that performed one showed up only as that counter rising
     * while packets_lost stayed put. */
    METRICS_QUIC_KEY_UPDATE,

    METRICS_QUIC_PACKETS_LOST,
    METRICS_QUIC_PTO_FIRED,
    /* Probes actually put on the wire. Separate from pto_fired because the two
     * came apart in practice: a PTO that arms a probe which is then never built
     * leaves the connection stalled exactly as if nothing had fired, and the
     * first counter alone cannot tell the two apart (docs/http3/08 §2). */
    METRICS_QUIC_PTO_PROBE_SENT,
    /* Keep-alive PINGs sent (§10.1.2, http3_keepalive_sec). Worth its own
     * counter next to the PTO probes because the two look identical on the wire
     * and mean opposite things: a probe says the path stopped answering, a
     * keep-alive says nothing was happening and we chose to hold the connection
     * open. Zero here while the key is set means the interval never elapses --
     * either the connections are busy, or the clamp against the negotiated idle
     * timeout pushed the interval past their lifetime. */
    METRICS_QUIC_KEEPALIVE_SENT,
    METRICS_QUIC_PERSISTENT_CONGESTION,

    /* Why the send loop stopped short. Congestion is expected; the other two
     * are the ones that turn into "the server is slow" reports. */
    METRICS_QUIC_FLOW_BLOCKED_CONN,
    METRICS_QUIC_FLOW_BLOCKED_STREAM,
    METRICS_QUIC_AMPLIFICATION_LIMITED,

    /* Connection ids issued and announced. The two differ when an announcement
     * is lost and not retransmitted, which is invisible from either side
     * otherwise. */
    METRICS_QUIC_CIDS_ISSUED,
    METRICS_QUIC_CIDS_ANNOUNCED,

    METRICS_QUIC_STREAMS_OPENED,
    /* Released once finished in both directions. The gap against
     * streams_opened is how much of a connection's stream credit is stuck: the
     * peer cannot open more until the credit comes back as MAX_STREAMS. */
    METRICS_QUIC_STREAMS_RELEASED,
    METRICS_QUIC_STREAMS_RESET_SENT,
    METRICS_QUIC_STREAMS_RESET_RECEIVED,

    /* How connections end. Split because they mean opposite things: an idle
     * timeout is a client that walked away, a local error is our own refusal,
     * and a peer close is theirs. `connections_closed` is their total. */
    METRICS_QUIC_CLOSED_IDLE,
    METRICS_QUIC_CLOSED_LOCAL,
    METRICS_QUIC_CLOSED_PEER,

    /* Why a connection was not created. Split from the generic drop counters
     * because these two are the ones an operator acts on: at_capacity means
     * raise http3_max_connections (or add memory), rate_limited means either an
     * attack or a limit set below what this service actually sees. Reading them
     * as one number tells you neither. */
    METRICS_QUIC_AT_CAPACITY,
    METRICS_QUIC_HANDSHAKE_RATE_LIMITED,

    /* Peer address changes (§9). Three counters rather than one because they
     * are three different stories: attempted is how often clients move
     * (mobile networks, NAT rebinding), validated is how often that worked, and
     * the difference is either a broken path or someone spoofing addresses at
     * us -- and only the ratio distinguishes them. */
    /* Address validation (§8.1). retry_sent against token_valid is the pair
     * that says whether Retry is doing its job: every Retry should come back
     * as a valid token, and a gap means clients are giving up on the extra
     * round trip rather than completing it. */
    METRICS_QUIC_RETRY_SENT,
    METRICS_QUIC_TOKEN_VALID,
    METRICS_QUIC_TOKEN_INVALID,

    METRICS_QUIC_MIGRATION_ATTEMPTED,
    METRICS_QUIC_MIGRATION_VALIDATED,
    METRICS_QUIC_MIGRATION_REJECTED,

    /* Which worker a datagram was served on, relative to the worker that owns
     * the connection (docs/http3/09-options.md §2.6).
     *
     * The kernel picks the worker by hashing the 4-tuple; QUIC addresses a
     * connection by its id and survives the 4-tuple changing. So a datagram can
     * arrive at a worker that does not own the connection, and is then served
     * there -- correct, because the workers are threads of one process, but it
     * costs the connection's cache lines a trip between cores.
     *
     * These two are what tells the routing anomaly apart from the routine case:
     * `foreign` climbing while nothing migrates means a NAT is rewriting ports
     * under the connection, and `foreign` in proportion to `migrations.validated`
     * is simply what migration does here. */
    METRICS_QUIC_ROUTE_LOCAL,
    METRICS_QUIC_ROUTE_FOREIGN,
    /* Connections that followed their datagrams to another worker. One per
     * path move, so it tracks `migrations.validated` on a healthy server; a
     * count far above it means something is moving clients between workers
     * without a migration, and a count of zero while `foreign` climbs means
     * every attempt was refused (a reload draining, or the connection waiting
     * in the old worker's send queue). */
    METRICS_QUIC_ROUTE_REHOMED,

    /* What one packet costs to assemble (docs/http3/09-options.md §2.7).
     *
     * __build_packet walks conn->streams twice per packet -- once for
     * MAX_STREAM_DATA, once for the data frames -- and both walks stop only when
     * the packet is full, so N open streams cost O(N) node visits even when one
     * stream is doing all the sending. Whether that is worth a second list of
     * "streams with something to say" is a question about a *ratio*, and the
     * ratio is what these measure: visits per packet against stream_frames per
     * packet. If the first stays flat as N grows, the walk costs nothing and the
     * item closes on the measurement.
     *
     * The two walks are counted apart because they end differently. The data
     * walk stops as soon as the packet is full, so it usually gets no further
     * than the one stream that is sending; the MAX_STREAM_DATA walk writes
     * almost nothing and therefore runs the list to its end every time. Summed
     * into one number, the cheap walk hides which of the two is the cost.
     *
     * Counted per call, not per visit: __build_packet accumulates on the stack
     * and adds once, so a hundred visits cost one relaxed add and not a hundred.
     * `calls` counts every attempt that got as far as the stream sections,
     * `packets` only those that produced a packet -- the gap is work spent on
     * packets that were never built. */
    METRICS_QUIC_BUILD_CALLS,
    METRICS_QUIC_BUILD_PACKETS,
    METRICS_QUIC_BUILD_VISITS_FLOW,
    METRICS_QUIC_BUILD_VISITS_DATA,
    METRICS_QUIC_BUILD_STREAM_FRAMES,

    METRICS_QUIC__COUNT
} metrics_quic_t;

/* Checks metrics_enabled() itself, like metrics_h2_abuse: the call sites are
 * spread across the datagram path and would otherwise each repeat the test. */
void metrics_quic(metrics_quic_t kind);
void metrics_quic_add(metrics_quic_t kind, unsigned long long amount);

/* Path samples, one per acknowledgement that produced a new estimate.
 *
 * Reported as a histogram rather than as percentiles: exact quantiles need the
 * samples kept, and keeping them would mean either a bound that silently drops
 * the tail or an allocation on the ACK path. The questions these are asked --
 * "is the path slow" and "is the window stuck at the initial one" -- are
 * answered by which bucket the mass sits in, and that costs one add. */
void metrics_quic_rtt(uint64_t rtt_us);
void metrics_quic_cwnd(uint64_t bytes);
void metrics_quic_connections(size_t current, size_t limit);
void metrics_quic_handshakes(size_t inflight);
void metrics_quic_memory(size_t current, size_t limit, unsigned long long refused);
void metrics_quic_reload_handoff(int success);

/* HTTP/3 application counters (docs/http3/07-integration.md §3).
 *
 * Kept apart from the quic ones because they answer a different question: quic
 * says whether the transport works, these say what it is carrying. A request
 * that never becomes a response is visible only as the difference between the
 * first two. */
typedef enum {
    METRICS_H3_REQUESTS = 0,
    METRICS_H3_RESPONSE_1XX,
    METRICS_H3_RESPONSE_2XX,
    METRICS_H3_RESPONSE_3XX,
    METRICS_H3_RESPONSE_4XX,
    METRICS_H3_RESPONSE_5XX,

    METRICS_H3_STREAMS_CANCELLED,   /* peer RESET_STREAM on a request stream */
    METRICS_H3_REQUESTS_REJECTED,   /* arrived after our GOAWAY named it (§5.2) */
    METRICS_H3_GOAWAY_SENT,

    /* Limits that fired. As in HTTP/2, each one guesses a threshold, and
     * without a counter per limit an operator cannot tell an attack from a
     * client this server has started rejecting wrongly. */
    METRICS_H3_ABUSE_ABORT_BUDGET,
    METRICS_H3_ABUSE_CTRL_BUDGET,
    METRICS_H3_ABUSE_PRIORITY_BUDGET,    /* PRIORITY_UPDATE past its credit */
    METRICS_H3_FIELD_SECTION_TOO_LARGE,  /* → 431 */
    METRICS_H3_FIELD_SECTION_HARD,       /* → connection, decode abandoned */
    METRICS_H3_BODY_TOO_LARGE,           /* → 413 */

    /* :authority named a host this listener does not serve → 404. Its own
     * counter and not just a 4xx: a rising one means either a client addressing
     * the wrong name or a vhost whose `domains` list is missing something the
     * clients actually use, and neither is visible in responses.4xx next to
     * every 404 a handler produces. */
    METRICS_H3_MISDIRECTED,

    /* Priority signals that reached the send scheduler (RFC 9218): a
     * `priority` header field or a PRIORITY_UPDATE frame that named a stream we
     * could act on. Worth its own counter because "the client sends priorities"
     * and "the server acts on them" are different claims, and only this one
     * distinguishes them from outside. */
    METRICS_H3_PRIORITY_APPLIED,

    METRICS_H3_QPACK_INSERTS,
    METRICS_H3_QPACK_EVICTIONS,
    METRICS_H3_QPACK_BLOCKED_STREAMS,
    METRICS_H3_QPACK_LITERAL_FIELDS,
    METRICS_H3_QPACK_DYNAMIC_FIELDS,

    METRICS_H3_STREAM_ERROR,        /* malformed message; the stream is reset */
    METRICS_H3_CONN_ERROR,          /* an h3 error that ends the connection */
    METRICS_H3__COUNT
} metrics_h3_t;

void metrics_h3(metrics_h3_t kind);
void metrics_h3_add(metrics_h3_t kind, unsigned long long value);

/* One final response, counted by class. The mapping from status code to class
 * lives here so the call sites cannot disagree about where 1xx ends. */
void metrics_h3_status(int status_code);
#endif

/* Not for direct use — read it through metrics_enabled(). */
extern atomic_int __metrics_on;

static inline int metrics_enabled(void) {
    return atomic_load_explicit(&__metrics_on, memory_order_relaxed);
}

/* Called once per config load, before any worker or handler thread starts.
 * Enabling for the first time also starts the measurement window. */
void metrics_init(int enabled);

/* CLOCK_MONOTONIC nanoseconds. Only call it behind metrics_enabled(). */
uint64_t metrics_now_ns(void);

/* connection_s_lock acquired on the first CAS — no waiting. */
void metrics_lock_fast(metrics_lock_site_t site);

/* connection_s_lock acquired after contention: `wait_ns` is the time from the
 * failed first CAS to the successful one, `yields` how many times the waiter
 * gave up its slice in between (a non-zero count means someone held the lock for
 * longer than the spin budget).
 *
 * Two tags, because one does not answer the question: `site` is where the waiter
 * asked for the lock, `blocker` is the site whose acquisition was in the way when
 * the wait began. Waiter alone says which paths are slow to get in; blocker is
 * what names the section that has to be shortened. The holder may change while
 * the wait runs, so `blocker` is the first one observed — for a wait long enough
 * to matter, that is the one that caused it. */
void metrics_lock_slow(metrics_lock_site_t site, metrics_lock_site_t blocker, uint64_t wait_ns, unsigned yields);

/* One item taken from ctx->queue. `inflight` is how many handlers of that
 * connection are now running, this one included. */
void metrics_handler_begin(int inflight);
void metrics_handler_end(void);

/* A pop attempt on ctx->queue: `depth` is the size before the pop, so it counts
 * the item just taken. depth == 0 records an empty pop — the fan-out queued a
 * connection whose items another worker had already drained. */
void metrics_queue_pop(int depth);

/* One HTTP/2 abuse limit fired. Unlike the counters above this one checks
 * metrics_enabled() itself: the call sites are error paths where the caller
 * would otherwise have to wrap every one of them in the same test. */
void metrics_h2_abuse(metrics_h2_abuse_t kind);

/* Snapshot of every counter as a JSON object. Caller owns the document and
 * frees it with json_free(). Never blocks: the counters are read one by one, so
 * a snapshot taken under load is internally skewed by a few updates — that is
 * fine for the questions above and is why nothing here takes a lock. */
json_doc_t* metrics_snapshot_json(void);

/* Zero the counters and restart the measurement window. Meant to be called
 * between benchmark runs; the in-flight handler gauge is preserved, since
 * zeroing a gauge that has live holders would make it drift negative. */
void metrics_reset(void);

#endif

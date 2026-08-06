#ifndef __QUICCIDTABLE__
#define __QUICCIDTABLE__

#include <stddef.h>
#include <stdint.h>

#include "quic.h"

/* Connection id -> connection routing table (docs/http3/01-udp-endpoint.md §5,
 * ADR-3).
 *
 * QUIC connections are addressed by connection id, not by the 4-tuple, so the
 * demultiplexer needs this on every datagram. Two properties shape it:
 *
 *  - It is process-wide, not per worker. Workers here are threads of one
 *    process (src/thread/threadworker.c), so a datagram that SO_REUSEPORT hands
 *    to the "wrong" worker -- which happens as soon as a client migrates, since
 *    the kernel hashes the 4-tuple and QUIC does not -- can simply be handled
 *    where it landed. In a multi-process server that would need packet
 *    forwarding between processes; here it needs nothing.
 *
 *  - It is sharded. One lock over every connection on the box would be taken
 *    twice per datagram, on every worker, and would become the bottleneck long
 *    before the crypto did.
 *
 * A connection holds several ids at once (its original one plus every id it has
 * issued through NEW_CONNECTION_ID and not yet retired), so entries outnumber
 * connections by a small factor.
 *
 * Values are opaque. The table exists in phase 1, and quicconn_t only arrives in
 * phase 4; more usefully, keeping it untyped is what lets it be unit-tested
 * without standing up a connection. */

typedef struct quiccidtable quiccidtable_t;

/* Called with a shard lock held, so it must not block or take another lock.
 * The real one is connection_s_inc(), which is a single atomic increment. */
typedef void (*quiccidtable_acquire_fn)(void* value);

typedef enum {
    QUICCIDTABLE_OK = 0,
    /* The id is already mapped. Not an internal error: a peer can replay an
     * Initial, and the correct response is to route to the existing connection
     * rather than to create a second one. Kept distinct from OOM so the
     * counters can tell an attack from exhaustion. */
    QUICCIDTABLE_DUPLICATE,
    QUICCIDTABLE_OOM
} quiccidtable_status_e;

/* `expected_entries` sizes the buckets once, at creation, from the configured
 * connection limit. The table never rehashes: growing under a lock taken twice
 * per datagram is exactly the kind of latency spike QUIC has no way to hide,
 * and the entry count is bounded by configuration anyway
 * (docs/http3/07-integration.md §4). Chains simply lengthen past the limit.
 *
 * `seed` keys the hash. Connection ids we issue are random, but the id in a
 * client's first Initial is chosen by the client, so an unkeyed hash would let
 * a peer pile every handshake into one bucket. Supplied by the caller rather
 * than drawn here so that this module keeps no dependencies and tests stay
 * deterministic.
 *
 * `acquire` may be NULL, in which case lookups return the raw value. */
quiccidtable_t* quiccidtable_create(size_t expected_entries, size_t shard_count,
                                    uint64_t seed, quiccidtable_acquire_fn acquire);

/* Frees the table and its entries. Does NOT touch the values -- ownership of
 * those never belonged here. */
void quiccidtable_free(quiccidtable_t* table);

quiccidtable_status_e quiccidtable_insert(quiccidtable_t* table,
                                          const quiccid_t* cid, void* value);

/* Returns the value with `acquire` already applied to it, or NULL.
 *
 * The acquire happens under the shard lock, which is the whole point: without
 * it the value could be freed between the lookup returning and the caller
 * touching it, on a connection another worker is closing at that moment. */
void* quiccidtable_lookup_acquire(quiccidtable_t* table, const quiccid_t* cid);

/* Returns 1 if an entry was removed. */
int quiccidtable_remove(quiccidtable_t* table, const quiccid_t* cid);

size_t quiccidtable_count(const quiccidtable_t* table);

/* Longest chain in any shard. Diagnostics only: a number that climbs while the
 * count does not is the signature of a peer grinding the hash. */
size_t quiccidtable_max_chain(quiccidtable_t* table);

#endif

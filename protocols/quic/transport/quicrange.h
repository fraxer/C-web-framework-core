#ifndef __QUICRANGE__
#define __QUICRANGE__

#include <stddef.h>
#include <stdint.h>

/* A set of 64-bit integers stored as sorted, non-overlapping, non-adjacent
 * closed intervals.
 *
 * The same structure answers three questions in QUIC, which is why it is one
 * module rather than three: which packet numbers have been received (for
 * building ACK frames), which stream offsets have been acknowledged (for
 * sliding the send buffer), and which have been lost (for retransmission).
 *
 * Adjacency matters: [1,3] and [4,6] are stored as [1,6], never as two. The ACK
 * encoding has no way to express a gap of zero, so a set that kept them apart
 * would produce frames a peer rejects.
 *
 * Descending order is what ACK frames need, so `quicrange_at` indexes from the
 * highest interval down. */

typedef struct quicrange_span {
    uint64_t start;   /* inclusive */
    uint64_t end;     /* inclusive */
} quicrange_span_t;

typedef struct quicrange {
    quicrange_span_t* spans;   /* ascending */
    size_t count;
    size_t cap;
    /* Oldest intervals are dropped once this many are held. A peer can create
     * one interval per lost packet, so an unbounded set is a memory attack --
     * and an ACK frame listing hundreds of ranges is itself abusive. 0 = no
     * limit (used where the input is our own state rather than the peer's). */
    size_t max_spans;

    /* The highest value the cap above has ever dropped.
     *
     * A bounded set forgets, and a caller that uses it to reject duplicates
     * must know where its memory ends. Without this, a peer that sends a comb
     * of gaps pushes old packet numbers out of the set, and a replay of one of
     * those packets is then indistinguishable from a first arrival -- the
     * eviction becomes the way through the replay check rather than a defence
     * against a memory attack. Everything at or below the mark counts as seen:
     * it either was, or is old enough that treating it as such costs a packet
     * far outside any reordering window. */
    uint64_t evicted_upto;
    int      has_evicted;
} quicrange_t;

void quicrange_init(quicrange_t* r, size_t max_spans);
void quicrange_free(quicrange_t* r);

/* Add [start, end] inclusive, merging with any interval it touches. */
int quicrange_add(quicrange_t* r, uint64_t start, uint64_t end);

/* Remove [start, end], splitting intervals as needed. */
int quicrange_remove(quicrange_t* r, uint64_t start, uint64_t end);

int quicrange_contains(const quicrange_t* r, uint64_t value);

/* Highest value in the set, or 0 when empty (check quicrange_empty first). */
uint64_t quicrange_max(const quicrange_t* r);
/* Lowest value in the set. */
uint64_t quicrange_min(const quicrange_t* r);

int quicrange_empty(const quicrange_t* r);
size_t quicrange_count(const quicrange_t* r);

/* Interval `index` counting down from the highest -- the order ACK frames want.
 * Returns 0 if index is past the end. */
int quicrange_at_desc(const quicrange_t* r, size_t index, quicrange_span_t* out);

/* Interval `index` counting up from the lowest -- the order a subtraction over
 * the set wants, so that a walk can advance a cursor once per interval instead
 * of once per integer. Returns 0 if index is past the end. */
int quicrange_at_asc(const quicrange_t* r, size_t index, quicrange_span_t* out);

/* Whether `value` fell out of the set through the max_spans cap -- see
 * `evicted_upto`. A duplicate check must consult this as well as
 * quicrange_contains, or a bounded set silently accepts replays. */
int quicrange_evicted(const quicrange_t* r, uint64_t value);

/* Drop everything at or below `value`. Used to forget packet numbers a peer has
 * confirmed it will never ask about again. Deliberately does not move
 * `evicted_upto`: this is the owner choosing to forget, not the cap. */
void quicrange_trim_below(quicrange_t* r, uint64_t value);

void quicrange_clear(quicrange_t* r);

#endif

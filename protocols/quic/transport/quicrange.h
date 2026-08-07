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

/* Drop everything at or below `value`. Used to forget packet numbers a peer has
 * confirmed it will never ask about again. */
void quicrange_trim_below(quicrange_t* r, uint64_t value);

void quicrange_clear(quicrange_t* r);

#endif

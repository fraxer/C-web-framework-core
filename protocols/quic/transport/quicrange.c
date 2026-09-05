#include <stdlib.h>
#include <string.h>

#include "quicrange.h"

#define QUICRANGE_INITIAL_CAP 8

void quicrange_init(quicrange_t* r, size_t max_spans) {
    if (r == NULL) return;

    memset(r, 0, sizeof * r);
    r->max_spans = max_spans;
}

void quicrange_free(quicrange_t* r) {
    if (r == NULL) return;

    free(r->spans);
    r->spans = NULL;
    r->count = 0;
    r->cap = 0;
}

void quicrange_clear(quicrange_t* r) {
    if (r != NULL) r->count = 0;
}

static int __grow(quicrange_t* r) {
    if (r->count < r->cap) return 1;

    const size_t cap = r->cap == 0 ? QUICRANGE_INITIAL_CAP : r->cap * 2;
    quicrange_span_t* spans = realloc(r->spans, cap * sizeof * spans);
    if (spans == NULL) return 0;

    r->spans = spans;
    r->cap = cap;

    return 1;
}

int quicrange_add(quicrange_t* r, uint64_t start, uint64_t end) {
    if (r == NULL || start > end) return 0;

    /* Find the first interval that could touch this one. Adjacency counts:
     * [1,3] and [4,6] must become [1,6], since the ACK encoding cannot express
     * a gap of zero. The guard on start avoids underflow at 0. */
    size_t i = 0;
    while (i < r->count && r->spans[i].end + 1 < start &&
           !(start == 0 && r->spans[i].end + 1 == 0))
        i++;

    /* No overlap and no adjacency: a plain insert at i. */
    if (i == r->count || (end + 1 < r->spans[i].start && end != UINT64_MAX)) {
        if (!__grow(r)) return 0;

        memmove(&r->spans[i + 1], &r->spans[i],
                (r->count - i) * sizeof * r->spans);
        r->spans[i].start = start;
        r->spans[i].end = end;
        r->count++;
    }
    else {
        /* Merge this interval and every following one it reaches. */
        if (r->spans[i].start < start) start = r->spans[i].start;

        size_t j = i;
        while (j < r->count &&
               (r->spans[j].start <= end || (end != UINT64_MAX && r->spans[j].start == end + 1))) {
            if (r->spans[j].end > end) end = r->spans[j].end;
            j++;
        }

        r->spans[i].start = start;
        r->spans[i].end = end;

        if (j > i + 1) {
            memmove(&r->spans[i + 1], &r->spans[j],
                    (r->count - j) * sizeof * r->spans);
            r->count -= (j - i - 1);
        }
    }

    /* Over the cap: drop the lowest intervals. They are the oldest packet
     * numbers, which a peer is least likely to still care about -- and holding
     * every one of them is what an attacker sending a comb of gaps wants. */
    if (r->max_spans != 0 && r->count > r->max_spans) {
        const size_t drop = r->count - r->max_spans;

        /* Remember how far the set has forgotten, so a duplicate check can tell
         * "never seen" from "no longer remembered" (quicrange.h). */
        const uint64_t dropped_upto = r->spans[drop - 1].end;
        if (!r->has_evicted || dropped_upto > r->evicted_upto) {
            r->evicted_upto = dropped_upto;
            r->has_evicted = 1;
        }

        memmove(&r->spans[0], &r->spans[drop],
                (r->count - drop) * sizeof * r->spans);
        r->count -= drop;
    }

    return 1;
}

int quicrange_evicted(const quicrange_t* r, uint64_t value) {
    if (r == NULL || !r->has_evicted) return 0;

    return value <= r->evicted_upto;
}

int quicrange_remove(quicrange_t* r, uint64_t start, uint64_t end) {
    if (r == NULL || start > end) return 0;

    for (size_t i = 0; i < r->count; ) {
        quicrange_span_t* s = &r->spans[i];

        if (s->end < start || s->start > end) { i++; continue; }

        if (s->start >= start && s->end <= end) {
            /* Wholly removed. */
            memmove(&r->spans[i], &r->spans[i + 1],
                    (r->count - i - 1) * sizeof * r->spans);
            r->count--;
            continue;
        }

        if (s->start < start && s->end > end) {
            /* Split in two. */
            if (!__grow(r)) return 0;
            s = &r->spans[i];

            memmove(&r->spans[i + 1], &r->spans[i],
                    (r->count - i) * sizeof * r->spans);
            r->spans[i].end = start - 1;
            r->spans[i + 1].start = end + 1;
            r->count++;
            return 1;
        }

        if (s->start < start) s->end = start - 1;
        else s->start = end + 1;

        i++;
    }

    return 1;
}

int quicrange_contains(const quicrange_t* r, uint64_t value) {
    if (r == NULL) return 0;

    /* Binary search: this runs on every received packet, to reject duplicates. */
    size_t lo = 0;
    size_t hi = r->count;

    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;

        if (value < r->spans[mid].start) hi = mid;
        else if (value > r->spans[mid].end) lo = mid + 1;
        else return 1;
    }

    return 0;
}

uint64_t quicrange_max(const quicrange_t* r) {
    if (r == NULL || r->count == 0) return 0;

    return r->spans[r->count - 1].end;
}

uint64_t quicrange_min(const quicrange_t* r) {
    if (r == NULL || r->count == 0) return 0;

    return r->spans[0].start;
}

int quicrange_empty(const quicrange_t* r) {
    return r == NULL || r->count == 0;
}

size_t quicrange_count(const quicrange_t* r) {
    return r == NULL ? 0 : r->count;
}

int quicrange_at_desc(const quicrange_t* r, size_t index, quicrange_span_t* out) {
    if (r == NULL || out == NULL || index >= r->count) return 0;

    *out = r->spans[r->count - 1 - index];

    return 1;
}

int quicrange_at_asc(const quicrange_t* r, size_t index, quicrange_span_t* out) {
    if (r == NULL || out == NULL || index >= r->count) return 0;

    *out = r->spans[index];

    return 1;
}

void quicrange_trim_below(quicrange_t* r, uint64_t value) {
    if (r == NULL) return;

    size_t drop = 0;
    while (drop < r->count && r->spans[drop].end <= value) drop++;

    if (drop > 0) {
        memmove(&r->spans[0], &r->spans[drop],
                (r->count - drop) * sizeof * r->spans);
        r->count -= drop;
    }

    if (r->count > 0 && r->spans[0].start <= value)
        r->spans[0].start = value + 1;
}

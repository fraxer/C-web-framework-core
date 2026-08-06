#define _GNU_SOURCE
#include <stddef.h>
#include <time.h>

#include "metrics.h"

atomic_int __metrics_on = 0;

/* Counts (handlers per connection, queue depth) share one bucketing: the
 * interesting range is "1", "a few" and "more than the worker pool", and both
 * are compared against the same thread count. */
#define METRICS_COUNT_BUCKETS 8
static const char* const __count_bucket_name[METRICS_COUNT_BUCKETS] = {
    "1", "2", "3", "4", "5-8", "9-16", "17-32", "33+"
};

/* Lock waits are decades apart, not counts: an uncontended-ish wait is hundreds
 * of nanoseconds, a wait behind a preempted holder is milliseconds. */
#define METRICS_WAIT_BUCKETS 6
static const char* const __wait_bucket_name[METRICS_WAIT_BUCKETS] = {
    "<1us", "<10us", "<100us", "<1ms", "<10ms", ">=10ms"
};

/* Index-matched to metrics_h2_abuse_t. */
static const char* const __h2_abuse_name[METRICS_H2_ABUSE__COUNT] = {
    "flow_control.connection", "flow_control.stream",
    "rst_flood", "continuation_flood",
    "header_list_too_large", "header_list_hard_cap", "header_list_flood",
    "control_frame_flood", "output_backlog"
};

#ifdef CWFR_HTTP3
/* Index-matched to metrics_quic_t. */
static const char* const __quic_name[METRICS_QUIC__COUNT] = {
    "datagrams_received", "datagrams_sent",
    "bytes_received", "bytes_sent",
    "recv_calls",
    "drop.truncated", "drop.oversize", "drop.cid_too_long",
    "drop.short_initial", "drop.unknown_cid", "drop.no_budget", "drop.peer_version_negotiation",
    "version_negotiation_sent", "stateless_reset_sent", "initial_dropped_no_tls",
    "send_error"
};
#endif

/* Index-matched to metrics_lock_site_t. Kept next to the enum's comment, not
 * generated from it: the names go into JSON that benchmark notes quote verbatim,
 * so they are worth spelling out. */
static const char* const __lock_site_name[LOCK_SITE__COUNT] = {
    "other",
    "h2.read", "h2.write", "h2.publish", "h2.rearm",
    "http.read", "http.write", "http.dispatch", "http.publish",
    "ws.read", "ws.write", "ws.reserve", "ws.publish",
    "broadcast",
    "close",
    "tick"
};

/* One of these per call site. The totals reported under `lock` are summed from
 * them at snapshot time rather than kept in their own counters: a second set of
 * atomics would double the read-modify-writes on the lock path to save an
 * addition over a dozen slots on a path taken once per HTTP request. */
typedef struct {
    atomic_ullong acquired;
    atomic_ullong contended;
    atomic_ullong yields;
    atomic_ullong wait_ns;
    atomic_ullong wait_ns_max;
    atomic_ullong wait_hist[METRICS_WAIT_BUCKETS];
} lock_site_metrics_t;

typedef struct {
    lock_site_metrics_t lock_site[LOCK_SITE__COUNT];
    /* Same shape, different question: indexed by the site that was holding the
     * lock, so only the wait fields are filled — `acquired` stays zero and is
     * not reported for these. */
    lock_site_metrics_t lock_blocker[LOCK_SITE__COUNT];

    atomic_ullong handler_runs;
    atomic_int handler_inflight;
    atomic_int handler_inflight_max;
    atomic_int conn_inflight_max;
    atomic_ullong conn_inflight_hist[METRICS_COUNT_BUCKETS];

    atomic_ullong queue_pops;
    atomic_ullong queue_pops_empty;
    atomic_ullong queue_depth_sum;
    atomic_int queue_depth_max;
    atomic_ullong queue_depth_hist[METRICS_COUNT_BUCKETS];

    atomic_ullong h2_abuse[METRICS_H2_ABUSE__COUNT];

#ifdef CWFR_HTTP3
    atomic_ullong quic[METRICS_QUIC__COUNT];
#endif

    atomic_ullong window_started_ns;
} metrics_t;

static metrics_t __m;

static int __count_bucket(int value) {
    if (value <= 4) return value - 1;
    if (value <= 8) return 4;
    if (value <= 16) return 5;
    if (value <= 32) return 6;

    return METRICS_COUNT_BUCKETS - 1;
}

static int __wait_bucket(unsigned long long ns) {
    if (ns < 1000ULL) return 0;
    if (ns < 10000ULL) return 1;
    if (ns < 100000ULL) return 2;
    if (ns < 1000000ULL) return 3;
    if (ns < 10000000ULL) return 4;

    return METRICS_WAIT_BUCKETS - 1;
}

/* Peak counters: a plain store would let a smaller value from a slower thread
 * overwrite a larger one, so the update is a CAS that only ever moves up. */
static void __max_ull(atomic_ullong* slot, unsigned long long value) {
    unsigned long long prev = atomic_load_explicit(slot, memory_order_relaxed);

    while (value > prev)
        if (atomic_compare_exchange_weak_explicit(slot, &prev, value, memory_order_relaxed, memory_order_relaxed))
            return;
}

static void __max_int(atomic_int* slot, int value) {
    int prev = atomic_load_explicit(slot, memory_order_relaxed);

    while (value > prev)
        if (atomic_compare_exchange_weak_explicit(slot, &prev, value, memory_order_relaxed, memory_order_relaxed))
            return;
}

uint64_t metrics_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void metrics_init(int enabled) {
    atomic_store_explicit(&__metrics_on, enabled ? 1 : 0, memory_order_relaxed);

    if (enabled && atomic_load_explicit(&__m.window_started_ns, memory_order_relaxed) == 0)
        atomic_store_explicit(&__m.window_started_ns, metrics_now_ns(), memory_order_relaxed);
}

/* An out-of-range tag is folded into "other" instead of being trusted as an
 * index: the value crosses a library boundary, and a stray one would corrupt
 * neighbouring counters rather than announce itself. */
static lock_site_metrics_t* __site_slot(lock_site_metrics_t* array, metrics_lock_site_t site) {
    if (site < 0 || site >= LOCK_SITE__COUNT)
        return &array[LOCK_SITE_OTHER];

    return &array[site];
}

static lock_site_metrics_t* __lock_site(metrics_lock_site_t site) {
    return __site_slot(__m.lock_site, site);
}

void metrics_lock_fast(metrics_lock_site_t site) {
    atomic_fetch_add_explicit(&__lock_site(site)->acquired, 1, memory_order_relaxed);
}

void metrics_lock_slow(metrics_lock_site_t site, metrics_lock_site_t blocker, uint64_t wait_ns, unsigned yields) {
    const int bucket = __wait_bucket(wait_ns);

    lock_site_metrics_t* m = __lock_site(site);

    atomic_fetch_add_explicit(&m->acquired, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&m->contended, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&m->wait_ns, wait_ns, memory_order_relaxed);
    atomic_fetch_add_explicit(&m->wait_hist[bucket], 1, memory_order_relaxed);
    __max_ull(&m->wait_ns_max, wait_ns);

    if (yields > 0)
        atomic_fetch_add_explicit(&m->yields, yields, memory_order_relaxed);

    lock_site_metrics_t* b = __site_slot(__m.lock_blocker, blocker);

    atomic_fetch_add_explicit(&b->contended, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&b->wait_ns, wait_ns, memory_order_relaxed);
    atomic_fetch_add_explicit(&b->wait_hist[bucket], 1, memory_order_relaxed);
    __max_ull(&b->wait_ns_max, wait_ns);
}

void metrics_handler_begin(int inflight) {
    atomic_fetch_add_explicit(&__m.handler_runs, 1, memory_order_relaxed);

    const int global = atomic_fetch_add_explicit(&__m.handler_inflight, 1, memory_order_relaxed) + 1;
    __max_int(&__m.handler_inflight_max, global);

    if (inflight < 1) return;

    __max_int(&__m.conn_inflight_max, inflight);
    atomic_fetch_add_explicit(&__m.conn_inflight_hist[__count_bucket(inflight)], 1, memory_order_relaxed);
}

void metrics_handler_end(void) {
    atomic_fetch_sub_explicit(&__m.handler_inflight, 1, memory_order_relaxed);
}

void metrics_queue_pop(int depth) {
    if (depth < 1) {
        atomic_fetch_add_explicit(&__m.queue_pops_empty, 1, memory_order_relaxed);
        return;
    }

    atomic_fetch_add_explicit(&__m.queue_pops, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&__m.queue_depth_sum, (unsigned long long)depth, memory_order_relaxed);
    atomic_fetch_add_explicit(&__m.queue_depth_hist[__count_bucket(depth)], 1, memory_order_relaxed);
    __max_int(&__m.queue_depth_max, depth);
}

void metrics_h2_abuse(metrics_h2_abuse_t kind) {
    if (!metrics_enabled()) return;
    if (kind < 0 || kind >= METRICS_H2_ABUSE__COUNT) return;

    atomic_fetch_add_explicit(&__m.h2_abuse[kind], 1, memory_order_relaxed);
}

#ifdef CWFR_HTTP3
void metrics_quic(metrics_quic_t kind) {
    metrics_quic_add(kind, 1);
}

void metrics_quic_add(metrics_quic_t kind, unsigned long long amount) {
    if (!metrics_enabled()) return;
    if (kind < 0 || kind >= METRICS_QUIC__COUNT) return;

    atomic_fetch_add_explicit(&__m.quic[kind], amount, memory_order_relaxed);
}
#endif

static unsigned long long __load(atomic_ullong* slot) {
    return atomic_load_explicit(slot, memory_order_relaxed);
}

static json_token_t* __hist_json(atomic_ullong* values, const char* const* names, int count) {
    json_token_t* object = json_create_object();
    if (object == NULL) return NULL;

    for (int i = 0; i < count; i++)
        json_object_set(object, names[i], json_create_number((long double)__load(&values[i])));

    return object;
}

/* One lock object's numbers, loaded: a single site, a single blocker, or a sum
 * over either. */
typedef struct {
    unsigned long long acquired;
    unsigned long long contended;
    unsigned long long yields;
    unsigned long long wait_ns;
    unsigned long long wait_ns_max;
    unsigned long long wait_hist[METRICS_WAIT_BUCKETS];
} lock_totals_t;

static void __lock_totals_add(lock_totals_t* into, lock_site_metrics_t* from) {
    into->acquired += __load(&from->acquired);
    into->contended += __load(&from->contended);
    into->yields += __load(&from->yields);
    into->wait_ns += __load(&from->wait_ns);

    const unsigned long long max = __load(&from->wait_ns_max);
    if (max > into->wait_ns_max)
        into->wait_ns_max = max;

    for (int i = 0; i < METRICS_WAIT_BUCKETS; i++)
        into->wait_hist[i] += __load(&from->wait_hist[i]);
}

/* Values already loaded, so a site object and the totals object are built by the
 * same code and cannot drift in shape. `blocker` drops the acquisition-side
 * fields, which are meaningless for a slot indexed by who was holding: nobody
 * counted an acquisition there, only the waits it caused. Returns NULL on
 * allocation failure; the caller decides whether that is fatal. */
static json_token_t* __lock_json(const lock_totals_t* t, int blocker) {
    json_token_t* object = json_create_object();
    if (object == NULL) return NULL;

    if (blocker)
        json_object_set(object, "waits_caused", json_create_number((long double)t->contended));
    else {
        json_object_set(object, "acquisitions", json_create_number((long double)t->acquired));
        json_object_set(object, "contended", json_create_number((long double)t->contended));
        json_object_set(object, "contention_ratio", json_create_number(t->acquired == 0 ? 0.0L : (long double)t->contended / (long double)t->acquired));
        json_object_set(object, "yields", json_create_number((long double)t->yields));
    }

    json_object_set(object, "wait_ns_total", json_create_number((long double)t->wait_ns));
    json_object_set(object, "wait_ns_max", json_create_number((long double)t->wait_ns_max));
    /* Averaged over contended acquisitions only: mixing in the uncontended ones
     * would divide by a number so much larger that any real stall disappears. */
    json_object_set(object, "wait_ns_avg_contended", json_create_number(t->contended == 0 ? 0.0L : (long double)t->wait_ns / (long double)t->contended));

    json_token_t* hist = json_create_object();
    if (hist != NULL)
        for (int i = 0; i < METRICS_WAIT_BUCKETS; i++)
            json_object_set(hist, __wait_bucket_name[i], json_create_number((long double)t->wait_hist[i]));

    json_object_set(object, "wait_hist", hist);

    return object;
}

json_doc_t* metrics_snapshot_json(void) {
    json_doc_t* doc = json_root_create_object();
    if (doc == NULL) return NULL;

    const unsigned long long started_ns = __load(&__m.window_started_ns);
    const unsigned long long window_ns = started_ns == 0 ? 0 : metrics_now_ns() - started_ns;

    const unsigned long long pops = __load(&__m.queue_pops);
    const unsigned long long depth_sum = __load(&__m.queue_depth_sum);

    json_token_t* root = json_root(doc);
    json_object_set(root, "enabled", json_create_bool(metrics_enabled()));
    json_object_set(root, "window_ms", json_create_number((long double)window_ns / 1000000.0L));

    /* Every sub-object is checked before it is filled: json_object_set drops the
     * value token when the object is NULL, so filling a failed object would leak
     * one token per field. */
    lock_totals_t totals = {0};
    lock_totals_t site_totals[LOCK_SITE__COUNT] = {{0}};
    lock_totals_t blocker_totals[LOCK_SITE__COUNT] = {{0}};

    for (int i = 0; i < LOCK_SITE__COUNT; i++) {
        __lock_totals_add(&site_totals[i], &__m.lock_site[i]);
        __lock_totals_add(&totals, &__m.lock_site[i]);
        __lock_totals_add(&blocker_totals[i], &__m.lock_blocker[i]);
    }

    json_token_t* lock = __lock_json(&totals, 0);
    if (lock == NULL) {
        json_free(doc);
        return NULL;
    }

    /* Sites that never fired are left out: with a dozen tags and one protocol
     * under test, printing them all buries the three lines being read. */
    json_token_t* sites = json_create_object();
    if (sites != NULL)
        for (int i = 0; i < LOCK_SITE__COUNT; i++)
            if (site_totals[i].acquired != 0)
                json_object_set(sites, __lock_site_name[i], __lock_json(&site_totals[i], 0));

    json_object_set(lock, "sites", sites);

    json_token_t* blockers = json_create_object();
    if (blockers != NULL)
        for (int i = 0; i < LOCK_SITE__COUNT; i++)
            if (blocker_totals[i].contended != 0)
                json_object_set(blockers, __lock_site_name[i], __lock_json(&blocker_totals[i], 1));

    json_object_set(lock, "blocked_by", blockers);
    json_object_set(root, "lock", lock);

    json_token_t* handlers = json_create_object();
    if (handlers == NULL) {
        json_free(doc);
        return NULL;
    }

    json_object_set(handlers, "runs", json_create_number((long double)__load(&__m.handler_runs)));
    json_object_set(handlers, "inflight", json_create_number((long double)atomic_load_explicit(&__m.handler_inflight, memory_order_relaxed)));
    json_object_set(handlers, "inflight_max", json_create_number((long double)atomic_load_explicit(&__m.handler_inflight_max, memory_order_relaxed)));
    json_object_set(handlers, "per_connection_max", json_create_number((long double)atomic_load_explicit(&__m.conn_inflight_max, memory_order_relaxed)));
    json_object_set(handlers, "per_connection_hist", __hist_json(__m.conn_inflight_hist, __count_bucket_name, METRICS_COUNT_BUCKETS));
    json_object_set(root, "handlers", handlers);

    json_token_t* queue = json_create_object();
    if (queue == NULL) {
        json_free(doc);
        return NULL;
    }

    json_object_set(queue, "pops", json_create_number((long double)pops));
    json_object_set(queue, "pops_empty", json_create_number((long double)__load(&__m.queue_pops_empty)));
    json_object_set(queue, "depth_avg", json_create_number(pops == 0 ? 0.0L : (long double)depth_sum / (long double)pops));
    json_object_set(queue, "depth_max", json_create_number((long double)atomic_load_explicit(&__m.queue_depth_max, memory_order_relaxed)));
    json_object_set(queue, "depth_hist", __hist_json(__m.queue_depth_hist, __count_bucket_name, METRICS_COUNT_BUCKETS));
    json_object_set(root, "queue", queue);

    /* Limits that never fired are omitted, like the lock sites: a page of zeroes
     * is what an operator has to read past to find the one that did. */
    json_token_t* abuse = json_create_object();
    if (abuse != NULL)
        for (int i = 0; i < METRICS_H2_ABUSE__COUNT; i++) {
            const unsigned long long n = __load(&__m.h2_abuse[i]);
            if (n != 0)
                json_object_set(abuse, __h2_abuse_name[i], json_create_number((long double)n));
        }

    json_object_set(root, "http2_abuse", abuse);

#ifdef CWFR_HTTP3
    /* Unlike the abuse limits, zeroes are reported here. "No datagrams arrived"
     * and "no drops happened" are both answers an operator is looking for, and
     * an omitted key reads as "the build has no h3" rather than "the counter is
     * zero" -- the opposite of what is being asked. */
    json_token_t* quic = json_create_object();
    if (quic == NULL) {
        json_free(doc);
        return NULL;
    }

    for (int i = 0; i < METRICS_QUIC__COUNT; i++)
        json_object_set(quic, __quic_name[i], json_create_number((long double)__load(&__m.quic[i])));

    json_object_set(root, "quic", quic);
#endif

    return doc;
}

void metrics_reset(void) {
    for (int s = 0; s < LOCK_SITE__COUNT; s++) {
        lock_site_metrics_t* pair[2] = { &__m.lock_site[s], &__m.lock_blocker[s] };

        for (int p = 0; p < 2; p++) {
            lock_site_metrics_t* m = pair[p];

            atomic_store_explicit(&m->acquired, 0, memory_order_relaxed);
            atomic_store_explicit(&m->contended, 0, memory_order_relaxed);
            atomic_store_explicit(&m->yields, 0, memory_order_relaxed);
            atomic_store_explicit(&m->wait_ns, 0, memory_order_relaxed);
            atomic_store_explicit(&m->wait_ns_max, 0, memory_order_relaxed);

            for (int i = 0; i < METRICS_WAIT_BUCKETS; i++)
                atomic_store_explicit(&m->wait_hist[i], 0, memory_order_relaxed);
        }
    }

    atomic_store_explicit(&__m.handler_runs, 0, memory_order_relaxed);
    /* handler_inflight is a gauge with live holders — see the header. */
    atomic_store_explicit(&__m.handler_inflight_max, atomic_load_explicit(&__m.handler_inflight, memory_order_relaxed), memory_order_relaxed);
    atomic_store_explicit(&__m.conn_inflight_max, 0, memory_order_relaxed);

    for (int i = 0; i < METRICS_COUNT_BUCKETS; i++) {
        atomic_store_explicit(&__m.conn_inflight_hist[i], 0, memory_order_relaxed);
        atomic_store_explicit(&__m.queue_depth_hist[i], 0, memory_order_relaxed);
    }

    atomic_store_explicit(&__m.queue_pops, 0, memory_order_relaxed);
    atomic_store_explicit(&__m.queue_pops_empty, 0, memory_order_relaxed);
    atomic_store_explicit(&__m.queue_depth_sum, 0, memory_order_relaxed);
    atomic_store_explicit(&__m.queue_depth_max, 0, memory_order_relaxed);

    for (int i = 0; i < METRICS_H2_ABUSE__COUNT; i++)
        atomic_store_explicit(&__m.h2_abuse[i], 0, memory_order_relaxed);

#ifdef CWFR_HTTP3
    for (int i = 0; i < METRICS_QUIC__COUNT; i++)
        atomic_store_explicit(&__m.quic[i], 0, memory_order_relaxed);
#endif

    atomic_store_explicit(&__m.window_started_ns, metrics_now_ns(), memory_order_relaxed);
}

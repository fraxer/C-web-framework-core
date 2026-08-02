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

typedef struct {
    atomic_ullong lock_acquired;
    atomic_ullong lock_contended;
    atomic_ullong lock_yields;
    atomic_ullong lock_wait_ns;
    atomic_ullong lock_wait_ns_max;
    atomic_ullong lock_wait_hist[METRICS_WAIT_BUCKETS];

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

void metrics_lock_fast(void) {
    atomic_fetch_add_explicit(&__m.lock_acquired, 1, memory_order_relaxed);
}

void metrics_lock_slow(uint64_t wait_ns, unsigned yields) {
    atomic_fetch_add_explicit(&__m.lock_acquired, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&__m.lock_contended, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&__m.lock_wait_ns, wait_ns, memory_order_relaxed);
    atomic_fetch_add_explicit(&__m.lock_wait_hist[__wait_bucket(wait_ns)], 1, memory_order_relaxed);
    __max_ull(&__m.lock_wait_ns_max, wait_ns);

    if (yields > 0)
        atomic_fetch_add_explicit(&__m.lock_yields, yields, memory_order_relaxed);
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

json_doc_t* metrics_snapshot_json(void) {
    json_doc_t* doc = json_root_create_object();
    if (doc == NULL) return NULL;

    const unsigned long long started_ns = __load(&__m.window_started_ns);
    const unsigned long long window_ns = started_ns == 0 ? 0 : metrics_now_ns() - started_ns;

    const unsigned long long acquired = __load(&__m.lock_acquired);
    const unsigned long long contended = __load(&__m.lock_contended);
    const unsigned long long wait_ns = __load(&__m.lock_wait_ns);

    const unsigned long long pops = __load(&__m.queue_pops);
    const unsigned long long depth_sum = __load(&__m.queue_depth_sum);

    json_token_t* root = json_root(doc);
    json_object_set(root, "enabled", json_create_bool(metrics_enabled()));
    json_object_set(root, "window_ms", json_create_number((long double)window_ns / 1000000.0L));

    /* Every sub-object is checked before it is filled: json_object_set drops the
     * value token when the object is NULL, so filling a failed object would leak
     * one token per field. */
    json_token_t* lock = json_create_object();
    if (lock == NULL) {
        json_free(doc);
        return NULL;
    }

    json_object_set(lock, "acquisitions", json_create_number((long double)acquired));
    json_object_set(lock, "contended", json_create_number((long double)contended));
    json_object_set(lock, "contention_ratio", json_create_number(acquired == 0 ? 0.0L : (long double)contended / (long double)acquired));
    json_object_set(lock, "yields", json_create_number((long double)__load(&__m.lock_yields)));
    json_object_set(lock, "wait_ns_total", json_create_number((long double)wait_ns));
    json_object_set(lock, "wait_ns_max", json_create_number((long double)__load(&__m.lock_wait_ns_max)));
    /* Averaged over contended acquisitions only: mixing in the uncontended ones
     * would divide by a number so much larger that any real stall disappears. */
    json_object_set(lock, "wait_ns_avg_contended", json_create_number(contended == 0 ? 0.0L : (long double)wait_ns / (long double)contended));
    json_object_set(lock, "wait_hist", __hist_json(__m.lock_wait_hist, __wait_bucket_name, METRICS_WAIT_BUCKETS));
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

    return doc;
}

void metrics_reset(void) {
    atomic_store_explicit(&__m.lock_acquired, 0, memory_order_relaxed);
    atomic_store_explicit(&__m.lock_contended, 0, memory_order_relaxed);
    atomic_store_explicit(&__m.lock_yields, 0, memory_order_relaxed);
    atomic_store_explicit(&__m.lock_wait_ns, 0, memory_order_relaxed);
    atomic_store_explicit(&__m.lock_wait_ns_max, 0, memory_order_relaxed);

    for (int i = 0; i < METRICS_WAIT_BUCKETS; i++)
        atomic_store_explicit(&__m.lock_wait_hist[i], 0, memory_order_relaxed);

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

    atomic_store_explicit(&__m.window_started_ns, metrics_now_ns(), memory_order_relaxed);
}

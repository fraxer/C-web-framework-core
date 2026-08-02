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
void metrics_lock_fast(void);

/* connection_s_lock acquired after contention: `wait_ns` is the time from the
 * failed first CAS to the successful one, `yields` how many times the waiter
 * gave up its slice in between (a non-zero count means someone held the lock for
 * longer than the spin budget). */
void metrics_lock_slow(uint64_t wait_ns, unsigned yields);

/* One item taken from ctx->queue. `inflight` is how many handlers of that
 * connection are now running, this one included. */
void metrics_handler_begin(int inflight);
void metrics_handler_end(void);

/* A pop attempt on ctx->queue: `depth` is the size before the pop, so it counts
 * the item just taken. depth == 0 records an empty pop — the fan-out queued a
 * connection whose items another worker had already drained. */
void metrics_queue_pop(int depth);

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

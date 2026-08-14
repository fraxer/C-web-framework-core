#include <stdint.h>
#include <stdatomic.h>

#include "quicmemory.h"

static _Atomic size_t current_bytes;
static _Atomic size_t limit_bytes;
static _Atomic unsigned long long refused_count;
static _Atomic(quicmemory_observer_fn) observer_fn;

static void notify(void) {
    quicmemory_observer_fn observer =
        atomic_load_explicit(&observer_fn, memory_order_acquire);
    if (observer != NULL)
        observer(atomic_load_explicit(&current_bytes, memory_order_relaxed),
                 atomic_load_explicit(&limit_bytes, memory_order_relaxed),
                 atomic_load_explicit(&refused_count, memory_order_relaxed));
}

void quicmemory_configure(size_t limit, quicmemory_observer_fn observer) {
    atomic_store_explicit(&limit_bytes, limit, memory_order_release);
    atomic_store_explicit(&observer_fn, observer, memory_order_release);
    notify();
}

int quicmemory_reserve(size_t bytes) {
    if (bytes == 0) return 1;

    const size_t limit = atomic_load_explicit(&limit_bytes, memory_order_acquire);
    size_t current = atomic_load_explicit(&current_bytes, memory_order_relaxed);

    for (;;) {
        if (bytes > SIZE_MAX - current ||
            (limit != 0 && (current > limit || bytes > limit - current))) {
            atomic_fetch_add_explicit(&refused_count, 1, memory_order_relaxed);
            notify();
            return 0;
        }
        if (atomic_compare_exchange_weak_explicit(&current_bytes, &current, current + bytes,
                                                  memory_order_acq_rel,
                                                  memory_order_relaxed)) {
            notify();
            return 1;
        }
    }
}

void quicmemory_release(size_t bytes) {
    if (bytes == 0) return;
    const size_t previous = atomic_fetch_sub_explicit(&current_bytes, bytes,
                                                       memory_order_acq_rel);
    if (previous < bytes)
        atomic_store_explicit(&current_bytes, 0, memory_order_release);
    notify();
}

size_t quicmemory_current(void) { return atomic_load_explicit(&current_bytes, memory_order_acquire); }
size_t quicmemory_limit(void) { return atomic_load_explicit(&limit_bytes, memory_order_acquire); }
unsigned long long quicmemory_refused(void) {
    return atomic_load_explicit(&refused_count, memory_order_acquire);
}

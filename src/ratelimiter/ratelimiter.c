#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ratelimiter.h"
#include "log.h"

// =============================================================================
// Spinlock helpers
// =============================================================================

static inline void spinlock_lock(atomic_flag* lock) {
    while (atomic_flag_test_and_set_explicit(lock, memory_order_acquire)) {
        // Spin with pause hint for better performance
        #if defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__("pause");
        #endif
    }
}

static inline void spinlock_unlock(atomic_flag* lock) {
    atomic_flag_clear_explicit(lock, memory_order_release);
}

// =============================================================================
// Seqlock implementation
// =============================================================================

static inline void seqlock_init(ratelimiter_seqlock_t* sl) {
    atomic_init(&sl->seq, 0);
    atomic_flag_clear(&sl->write_lock);
}

// Начать чтение - возвращает sequence number
static inline uint64_t seqlock_read_begin(ratelimiter_seqlock_t* sl) {
    uint64_t seq;
    do {
        seq = atomic_load_explicit(&sl->seq, memory_order_acquire);
    } while (seq & 1);  // Ждём пока seq чётный (нет записи)
    return seq;
}

// Проверить валидность чтения - true если данные консистентны
static inline int seqlock_read_retry(ratelimiter_seqlock_t* sl, uint64_t start_seq) {
    atomic_thread_fence(memory_order_acquire);
    return atomic_load_explicit(&sl->seq, memory_order_relaxed) != start_seq;
}

// Захватить write lock
static inline void seqlock_write_lock(ratelimiter_seqlock_t* sl) {
    spinlock_lock(&sl->write_lock);
    atomic_fetch_add_explicit(&sl->seq, 1, memory_order_release);  // seq становится нечётным
}

// Освободить write lock
static inline void seqlock_write_unlock(ratelimiter_seqlock_t* sl) {
    atomic_fetch_add_explicit(&sl->seq, 1, memory_order_release);  // seq становится чётным
    spinlock_unlock(&sl->write_lock);
}

// =============================================================================
// Time functions
// =============================================================================

uint64_t ratelimiter_get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// =============================================================================
// Map helpers
// =============================================================================

static int compare_ip(const void* a, const void* b) {
    in_addr_t ip_a = (in_addr_t)(uintptr_t)a;
    in_addr_t ip_b = (in_addr_t)(uintptr_t)b;
    if (ip_a < ip_b) return -1;
    if (ip_a > ip_b) return 1;
    return 0;
}

static void bucket_free_fn(void* data) {
    free(data);
}

// =============================================================================
// Bucket operations
// =============================================================================

static ratelimiter_bucket_t* bucket_create(in_addr_t ip, uint32_t initial_tokens) {
    ratelimiter_bucket_t* bucket = malloc(sizeof(ratelimiter_bucket_t));
    if (!bucket) return NULL;

    bucket->ip = ip;
    atomic_init(&bucket->tokens, initial_tokens);
    atomic_init(&bucket->last_refill_ns, ratelimiter_get_time_ns());
    atomic_init(&bucket->last_access_ns, ratelimiter_get_time_ns());
    atomic_flag_clear(&bucket->locked);

    return bucket;
}

static void bucket_refill(ratelimiter_bucket_t* bucket, ratelimiter_config_t* config) {
    uint64_t now = ratelimiter_get_time_ns();
    uint64_t last_refill = atomic_load(&bucket->last_refill_ns);
    uint64_t elapsed_ns = now - last_refill;

    uint64_t tokens_to_add = (elapsed_ns * config->refill_rate) / 1000000000ULL;

    if (tokens_to_add > 0) {
        uint32_t current_tokens = atomic_load(&bucket->tokens);
        uint32_t new_tokens = current_tokens + (uint32_t)tokens_to_add;

        if (new_tokens > config->max_tokens) {
            new_tokens = config->max_tokens;
        }

        atomic_store(&bucket->tokens, new_tokens);
        atomic_store(&bucket->last_refill_ns, now);
    }
}

// =============================================================================
// Lock-free find with seqlock
// =============================================================================

static ratelimiter_bucket_t* find_bucket_lockfree(ratelimiter_t* limiter, in_addr_t ip) {
    ratelimiter_bucket_t* bucket;
    uint64_t seq;

    do {
        seq = seqlock_read_begin(&limiter->seqlock);
        bucket = map_find(limiter->buckets, (void*)(uintptr_t)ip);
    } while (seqlock_read_retry(&limiter->seqlock, seq));

    return bucket;
}

// Найти или создать bucket для IP
static ratelimiter_bucket_t* find_or_create_bucket(ratelimiter_t* limiter, in_addr_t ip) {
    // Сначала пробуем найти lock-free
    ratelimiter_bucket_t* bucket = find_bucket_lockfree(limiter, ip);
    if (bucket) {
        return bucket;
    }

    // Не найден - нужен write lock для создания
    seqlock_write_lock(&limiter->seqlock);

    // Повторная проверка (другой поток мог создать)
    bucket = map_find(limiter->buckets, (void*)(uintptr_t)ip);
    if (bucket) {
        seqlock_write_unlock(&limiter->seqlock);
        return bucket;
    }

    // Создание нового bucket
    bucket = bucket_create(ip, limiter->config.max_tokens);
    if (bucket) {
        map_insert(limiter->buckets, (void*)(uintptr_t)ip, bucket);
    }

    seqlock_write_unlock(&limiter->seqlock);

    return bucket;
}

// =============================================================================
// Cleanup
// =============================================================================

static void cleanup_old_buckets(ratelimiter_t* limiter) {
    uint64_t now = ratelimiter_get_time_ns();
    uint64_t last_cleanup = atomic_load(&limiter->last_cleanup_ns);

    uint64_t cleanup_interval_ns = (uint64_t)limiter->config.cleanup_interval_s * 1000000000ULL;
    if (now - last_cleanup < cleanup_interval_ns) {
        return;
    }

    // Атомарно обновляем время последней очистки
    if (!atomic_compare_exchange_strong(&limiter->last_cleanup_ns, &last_cleanup, now)) {
        return;
    }

    // Берём write lock для cleanup
    seqlock_write_lock(&limiter->seqlock);

    // Подсчитываем количество для удаления
    size_t to_delete_count = 0;
    for (map_iterator_t it = map_begin(limiter->buckets); map_iterator_valid(it); it = map_next(it)) {
        ratelimiter_bucket_t* bucket = map_iterator_value(it);
        uint64_t last_access = atomic_load(&bucket->last_access_ns);
        if (now - last_access > cleanup_interval_ns) {
            to_delete_count++;
        }
    }

    if (to_delete_count > 0) {
        in_addr_t* ips_to_delete = malloc(to_delete_count * sizeof(in_addr_t));
        if (ips_to_delete) {
            size_t idx = 0;
            for (map_iterator_t it = map_begin(limiter->buckets); map_iterator_valid(it); it = map_next(it)) {
                ratelimiter_bucket_t* bucket = map_iterator_value(it);
                uint64_t last_access = atomic_load(&bucket->last_access_ns);
                if (now - last_access > cleanup_interval_ns) {
                    ips_to_delete[idx++] = bucket->ip;
                }
            }

            for (size_t i = 0; i < to_delete_count; i++) {
                map_erase(limiter->buckets, (void*)(uintptr_t)ips_to_delete[i]);
            }

            free(ips_to_delete);
        }
    }

    seqlock_write_unlock(&limiter->seqlock);
}

// =============================================================================
// Public API
// =============================================================================

ratelimiter_t* ratelimiter_init(ratelimiter_config_t* config) {
    if (!config) return NULL;

    ratelimiter_t* limiter = malloc(sizeof(ratelimiter_t));
    if (!limiter) return NULL;

    limiter->config = *config;

    limiter->buckets = map_create_ex(compare_ip, NULL, NULL, NULL, bucket_free_fn);
    if (!limiter->buckets) {
        free(limiter);
        return NULL;
    }

    seqlock_init(&limiter->seqlock);
    atomic_init(&limiter->last_cleanup_ns, ratelimiter_get_time_ns());

    return limiter;
}

void ratelimiter_free(ratelimiter_t* limiter) {
    if (!limiter) return;

    map_free(limiter->buckets);
    free(limiter);
}

int ratelimiter_allow(ratelimiter_t* limiter, in_addr_t ip, uint32_t tokens_required) {
    if (!limiter) return 1;

    cleanup_old_buckets(limiter);
    
    if (limiter->config.refill_rate == 0)
        return 1;

    ratelimiter_bucket_t* bucket = find_or_create_bucket(limiter, ip);
    if (!bucket) {
        log_error("Failed to create rate limiter bucket");
        return 1;
    }

    spinlock_lock(&bucket->locked);

    bucket_refill(bucket, &limiter->config);
    atomic_store(&bucket->last_access_ns, ratelimiter_get_time_ns());

    uint32_t current_tokens = atomic_load(&bucket->tokens);
    int allowed = 0;

    if (current_tokens >= tokens_required) {
        atomic_store(&bucket->tokens, current_tokens - tokens_required);
        allowed = 1;
    }

    spinlock_unlock(&bucket->locked);

    return allowed;
}

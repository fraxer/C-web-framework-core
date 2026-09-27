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
// Time functions
// =============================================================================

static uint64_t __ratelimiter_clock_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t (*__ratelimiter_clock)(void) = __ratelimiter_clock_monotonic;

uint64_t ratelimiter_get_time_ns(void) {
    return __ratelimiter_clock();
}

void ratelimiter_set_time_source(uint64_t (*source)(void)) {
    __ratelimiter_clock = source != NULL ? source : __ratelimiter_clock_monotonic;
}

// =============================================================================
// Map helpers
// =============================================================================

static int compare_ip(const void* a, const void* b) {
    uintptr_t key_a = (uintptr_t)a;
    uintptr_t key_b = (uintptr_t)b;
    if (key_a < key_b) return -1;
    if (key_a > key_b) return 1;
    return 0;
}

/* Ключ клиента в том виде, в котором его хранит map_t (void*).
 *
 * На 64-битной цели это сам ключ; на 32-битной он складывается пополам, потому
 * что map_t хранит ключ в указателе, а молчаливое усечение старших бит свело бы
 * все IPv6-префиксы вида X:0:0:0 к одному bucket. */
static uintptr_t bucket_key(uint64_t key) {
    if (sizeof(uintptr_t) >= sizeof(uint64_t)) return (uintptr_t)key;
    return (uintptr_t)(key ^ (key >> 32));
}

static void bucket_free_fn(void* data) {
    free(data);
}

// =============================================================================
// Bucket operations
// =============================================================================

static ratelimiter_bucket_t* bucket_create(uint64_t key, uint32_t initial_tokens) {
    ratelimiter_bucket_t* bucket = malloc(sizeof(ratelimiter_bucket_t));
    if (!bucket) return NULL;

    bucket->key = key;
    atomic_init(&bucket->tokens, initial_tokens);
    atomic_init(&bucket->last_refill_ns, ratelimiter_get_time_ns());
    atomic_init(&bucket->last_access_ns, ratelimiter_get_time_ns());
    atomic_flag_clear(&bucket->locked);

    return bucket;
}

/* Сколько прошло от then до now; 0, если часы ушли назад. Без этого разность
 * беззнаковых заворачивается в ~584 года: корзина пополняется до максимума, а
 * очистка считает её давно заброшенной. */
static uint64_t elapsed_since(uint64_t now, uint64_t then) {
    return now > then ? now - then : 0;
}

static void bucket_refill(ratelimiter_bucket_t* bucket, ratelimiter_config_t* config) {
    uint64_t now = ratelimiter_get_time_ns();
    uint64_t elapsed_ns = elapsed_since(now, atomic_load(&bucket->last_refill_ns));

    /* elapsed_ns * refill_rate переполняет uint64_t после долгой паузы (2^60 нс
     * при 16/с дают ровно 2^64, то есть 0 токенов); такая пауза в любом случае
     * наполняет корзину целиком. */
    uint64_t tokens_to_add = elapsed_ns > UINT64_MAX / config->refill_rate
        ? UINT64_MAX
        : (elapsed_ns * config->refill_rate) / 1000000000ULL;

    if (tokens_to_add > 0) {
        uint32_t current_tokens = atomic_load(&bucket->tokens);
        uint32_t room = current_tokens < config->max_tokens ? config->max_tokens - current_tokens : 0;

        /* Сравнение до сложения: приведение tokens_to_add к uint32_t обнуляло
         * пополнение ровно в 2^32 токенов. */
        uint32_t new_tokens = tokens_to_add >= room ? config->max_tokens : current_tokens + (uint32_t)tokens_to_add;

        atomic_store(&bucket->tokens, new_tokens);
        atomic_store(&bucket->last_refill_ns, now);
    }
}

// Взять токены из корзины. Вызывается под limiter->lock (чтение или запись):
// пока он удержан, очистка не освободит корзину.
static int bucket_take(ratelimiter_bucket_t* bucket, ratelimiter_config_t* config, uint32_t tokens_required) {
    spinlock_lock(&bucket->locked);

    bucket_refill(bucket, config);
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

// =============================================================================
// Cleanup
// =============================================================================

static void cleanup_old_buckets(ratelimiter_t* limiter) {
    uint64_t now = ratelimiter_get_time_ns();
    uint64_t last_cleanup = atomic_load(&limiter->last_cleanup_ns);

    uint64_t cleanup_interval_ns = (uint64_t)limiter->config.cleanup_interval_s * 1000000000ULL;
    if (elapsed_since(now, last_cleanup) < cleanup_interval_ns) {
        return;
    }

    // Атомарно обновляем время последней очистки
    if (!atomic_compare_exchange_strong(&limiter->last_cleanup_ns, &last_cleanup, now)) {
        return;
    }

    /* Под блокировкой записи: ни один поток не держит корзину, которую мы
     * освободим. Время читаем заново -- пока ждали блокировку, читатели могли
     * обновить last_access_ns позже прежнего now. */
    pthread_rwlock_wrlock(&limiter->lock);
    now = ratelimiter_get_time_ns();

    // Подсчитываем количество для удаления
    size_t to_delete_count = 0;
    for (map_iterator_t it = map_begin(limiter->buckets); map_iterator_valid(it); it = map_next(it)) {
        ratelimiter_bucket_t* bucket = map_iterator_value(it);
        uint64_t last_access = atomic_load(&bucket->last_access_ns);
        if (elapsed_since(now, last_access) > cleanup_interval_ns) {
            to_delete_count++;
        }
    }

    if (to_delete_count > 0) {
        uint64_t* keys_to_delete = malloc(to_delete_count * sizeof(uint64_t));
        if (keys_to_delete) {
            size_t idx = 0;
            for (map_iterator_t it = map_begin(limiter->buckets); map_iterator_valid(it); it = map_next(it)) {
                ratelimiter_bucket_t* bucket = map_iterator_value(it);
                uint64_t last_access = atomic_load(&bucket->last_access_ns);
                if (elapsed_since(now, last_access) > cleanup_interval_ns) {
                    keys_to_delete[idx++] = bucket->key;
                }
            }

            for (size_t i = 0; i < to_delete_count; i++) {
                map_erase(limiter->buckets, (void*)bucket_key(keys_to_delete[i]));
            }

            free(keys_to_delete);
        }
    }

    pthread_rwlock_unlock(&limiter->lock);
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

    if (pthread_rwlock_init(&limiter->lock, NULL) != 0) {
        map_free(limiter->buckets);
        free(limiter);
        return NULL;
    }

    atomic_init(&limiter->last_cleanup_ns, ratelimiter_get_time_ns());

    return limiter;
}

void ratelimiter_free(ratelimiter_t* limiter) {
    if (!limiter) return;

    map_free(limiter->buckets);
    pthread_rwlock_destroy(&limiter->lock);
    free(limiter);
}

int ratelimiter_allow(ratelimiter_t* limiter, const ipaddr_t* ip, uint32_t tokens_required) {
    if (!limiter) return 1;

    cleanup_old_buckets(limiter);
    
    if (limiter->config.refill_rate == 0 || ip == NULL)
        return 1;

    const uint64_t key = ipaddr_client_key(ip);
    int allowed;

    pthread_rwlock_rdlock(&limiter->lock);
    ratelimiter_bucket_t* bucket = map_find(limiter->buckets, (void*)bucket_key(key));
    if (bucket) {
        allowed = bucket_take(bucket, &limiter->config, tokens_required);
        pthread_rwlock_unlock(&limiter->lock);
        return allowed;
    }
    pthread_rwlock_unlock(&limiter->lock);

    // Не найден - создаём под блокировкой записи (другой поток мог успеть раньше)
    pthread_rwlock_wrlock(&limiter->lock);
    bucket = map_find(limiter->buckets, (void*)bucket_key(key));
    if (!bucket) {
        bucket = bucket_create(key, limiter->config.max_tokens);
        if (bucket && map_insert(limiter->buckets, (void*)bucket_key(key), bucket) != 1) {
            free(bucket);
            bucket = NULL;
        }
    }
    if (!bucket) {
        pthread_rwlock_unlock(&limiter->lock);
        log_error("Failed to create rate limiter bucket");
        return 1;
    }

    allowed = bucket_take(bucket, &limiter->config, tokens_required);
    pthread_rwlock_unlock(&limiter->lock);

    return allowed;
}

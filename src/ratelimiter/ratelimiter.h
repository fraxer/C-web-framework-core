#ifndef __RATELIMITER__
#define __RATELIMITER__

#include <stdatomic.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#include "map.h"

/**
 * Rate Limiter - реализация Token Bucket алгоритма
 * Lock-free реализация с использованием seqlock для map_t (Red-Black Tree)
 */

// Конфигурация rate limiter
typedef struct ratelimiter_config {
    uint32_t max_tokens;           // Максимальное количество токенов (burst)
    uint32_t refill_rate;          // Количество токенов, добавляемых в секунду
    uint64_t time_window_ns;       // Временное окно в наносекундах
    uint32_t cleanup_interval_s;   // Интервал очистки старых записей (в секундах)
} ratelimiter_config_t;

// Bucket для одного IP адреса
typedef struct ratelimiter_bucket {
    in_addr_t ip;                          // IP адрес клиента
    atomic_uint_fast32_t tokens;           // Текущее количество токенов
    atomic_uint_fast64_t last_refill_ns;   // Время последнего пополнения (наносекунды)
    atomic_uint_fast64_t last_access_ns;   // Время последнего доступа
    atomic_flag locked;                    // Spinlock для bucket
} ratelimiter_bucket_t;

// Seqlock для lock-free чтения map
typedef struct ratelimiter_seqlock {
    atomic_uint_fast64_t seq;              // Sequence counter (чётный = стабильно)
    atomic_flag write_lock;                // Spinlock для писателей
} ratelimiter_seqlock_t;

typedef struct ratelimiter {
    ratelimiter_config_t config;
    map_t* buckets;                        // map_t: in_addr_t -> ratelimiter_bucket_t*
    ratelimiter_seqlock_t seqlock;         // Seqlock для lock-free доступа
    atomic_uint_fast64_t last_cleanup_ns;
} ratelimiter_t;

/**
 * Инициализация с детальной конфигурацией
 */
ratelimiter_t* ratelimiter_init(ratelimiter_config_t* config);

/**
 * Освобождение ресурсов rate limiter
 */
void ratelimiter_free(ratelimiter_t* limiter);

/**
 * Проверка, разрешён ли запрос от данного IP
 * @param limiter - rate limiter
 * @param ip - IP адрес клиента
 * @param tokens_required - сколько токенов требуется (обычно 1)
 * @return 1 если разрешено, 0 если превышен лимит
 */
int ratelimiter_allow(ratelimiter_t* limiter, in_addr_t ip, uint32_t tokens_required);

/**
 * Получить текущее время в наносекундах (монотонное время)
 */
uint64_t ratelimiter_get_time_ns(void);

#endif

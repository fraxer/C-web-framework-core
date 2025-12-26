#ifndef __THREADPOOL__
#define __THREADPOOL__

#include <stddef.h>
#include <stdint.h>

/**
 * Thread-local object pools for reducing memory fragmentation.
 * No locks required - each thread has its own pool set.
 *
 * Supported types (registered at runtime):
 * - connection_t
 * - connection_server_ctx_t
 * - cqueue_t
 * - httprequest_t
 * - httpresponse_t
 * - http_header_t (same as http_cookie_t)
 * - cqueue_item_t
 * - query_t
 * - http_payloadpart_t
 * - http_payloadfield_t
 */

/* Pool type identifiers */
typedef enum {
    POOL_CONNECTION = 0,
    POOL_CONNECTION_SERVER_CTX,
    POOL_CQUEUE,
    POOL_HTTPREQUEST,
    POOL_HTTPRESPONSE,
    POOL_HTTP_HEADER,       /* Also used for http_cookie_t */
    POOL_CQUEUE_ITEM,
    POOL_QUERY,
    POOL_HTTP_PAYLOADPART,
    POOL_HTTP_PAYLOADFIELD,
    POOL_TYPE_COUNT         /* Must be last */
} pool_type_e;

/* Single pool free list node */
typedef struct pool_node {
    struct pool_node* next;
} pool_node_t;

/* Single-type pool (lock-free, thread-local) */
typedef struct {
    pool_node_t* free_list;     /* Head of free list */
    size_t block_size;          /* Size of each block */
    size_t count;               /* Current free count */
    size_t max_cached;          /* Max blocks to cache */
    size_t total_allocs;        /* Stats: total allocations */
    size_t pool_hits;           /* Stats: allocations from pool */
} tpool_t;

/* Thread-local pool set (all pool types) */
typedef struct {
    tpool_t pools[POOL_TYPE_COUNT];
    uint8_t initialized;
} tpool_set_t;

/**
 * Register pool type configuration (call once at program start, before threads).
 *
 * @param type - pool type identifier
 * @param block_size - size of objects in this pool
 * @param max_cached - maximum blocks to cache per thread
 */
void tpool_register(pool_type_e type, size_t block_size, size_t max_cached);

/**
 * Initialize all pool types with default configurations.
 * Must be called once at program start, before creating worker threads.
 * Uses sizeof() of actual types - requires linking with protocol libraries.
 */
void tpool_global_init(void);

/**
 * Initialize thread-local pools for current thread.
 * Must be called once per thread before using pool functions.
 */
void tpool_thread_init(void);

/**
 * Destroy thread-local pools for current thread.
 * Frees all cached memory blocks.
 * Call before thread exit.
 */
void tpool_thread_destroy(void);

/**
 * Allocate object from thread-local pool.
 * Falls back to malloc if pool is empty.
 * Memory is NOT zeroed - caller must initialize.
 *
 * @param type - pool type identifier
 * @return allocated memory or NULL on failure
 */
void* tpool_alloc(pool_type_e type);

/**
 * Allocate zeroed object from thread-local pool.
 *
 * @param type - pool type identifier
 * @return zeroed allocated memory or NULL on failure
 */
void* tpool_zalloc(pool_type_e type);

/**
 * Return object to thread-local pool.
 * If pool is full, memory is freed via free().
 *
 * @param type - pool type identifier
 * @param ptr - pointer to return (can be NULL)
 */
void tpool_free(pool_type_e type, void* ptr);

/**
 * Get pool statistics for current thread.
 *
 * @param type - pool type identifier
 * @param total_allocs - output: total allocations (can be NULL)
 * @param pool_hits - output: allocations served from pool (can be NULL)
 * @param cached - output: currently cached blocks (can be NULL)
 */
void tpool_stats(pool_type_e type, size_t* total_allocs, size_t* pool_hits, size_t* cached);

/**
 * Print all pool statistics to stderr.
 */
void tpool_dump_stats(void);

/**
 * Check if thread pools are initialized for current thread.
 *
 * @return 1 if initialized, 0 otherwise
 */
int tpool_is_initialized(void);

/**
 * Get block size for pool type.
 *
 * @param type - pool type identifier
 * @return block size or 0 if not registered
 */
size_t tpool_block_size(pool_type_e type);

/**
 * Initialize all pool types with default sizes.
 * Defined in src/server/tpool_init.c
 * Must be called once at server startup, before creating worker threads.
 */
void tpool_init_defaults(void);

/* ============================================================================
 * Convenience macros for type-safe allocation
 * Usage: connection_t* conn = tpool_alloc_connection();
 * ============================================================================ */

#define tpool_alloc_connection() \
    ((connection_t*)tpool_alloc(POOL_CONNECTION))

#define tpool_alloc_connection_server_ctx() \
    ((connection_server_ctx_t*)tpool_alloc(POOL_CONNECTION_SERVER_CTX))

#define tpool_alloc_cqueue() \
    ((cqueue_t*)tpool_alloc(POOL_CQUEUE))

#define tpool_alloc_httprequest() \
    ((httprequest_t*)tpool_alloc(POOL_HTTPREQUEST))

#define tpool_alloc_httpresponse() \
    ((httpresponse_t*)tpool_alloc(POOL_HTTPRESPONSE))

#define tpool_alloc_http_header() \
    ((http_header_t*)tpool_alloc(POOL_HTTP_HEADER))

#define tpool_alloc_http_cookie() \
    ((http_cookie_t*)tpool_alloc(POOL_HTTP_HEADER))

#define tpool_alloc_cqueue_item() \
    ((cqueue_item_t*)tpool_alloc(POOL_CQUEUE_ITEM))

#define tpool_alloc_query() \
    ((query_t*)tpool_alloc(POOL_QUERY))

#define tpool_alloc_http_payloadpart() \
    ((http_payloadpart_t*)tpool_alloc(POOL_HTTP_PAYLOADPART))

#define tpool_alloc_http_payloadfield() \
    ((http_payloadfield_t*)tpool_alloc(POOL_HTTP_PAYLOADFIELD))

/* ============================================================================
 * Convenience macros for freeing
 * Usage: tpool_free_connection(conn);
 * ============================================================================ */

#define tpool_free_connection(ptr) \
    tpool_free(POOL_CONNECTION, (ptr))

#define tpool_free_connection_server_ctx(ptr) \
    tpool_free(POOL_CONNECTION_SERVER_CTX, (ptr))

#define tpool_free_cqueue(ptr) \
    tpool_free(POOL_CQUEUE, (ptr))

#define tpool_free_httprequest(ptr) \
    tpool_free(POOL_HTTPREQUEST, (ptr))

#define tpool_free_httpresponse(ptr) \
    tpool_free(POOL_HTTPRESPONSE, (ptr))

#define tpool_free_http_header(ptr) \
    tpool_free(POOL_HTTP_HEADER, (ptr))

#define tpool_free_http_cookie(ptr) \
    tpool_free(POOL_HTTP_HEADER, (ptr))

#define tpool_free_cqueue_item(ptr) \
    tpool_free(POOL_CQUEUE_ITEM, (ptr))

#define tpool_free_query(ptr) \
    tpool_free(POOL_QUERY, (ptr))

#define tpool_free_http_payloadpart(ptr) \
    tpool_free(POOL_HTTP_PAYLOADPART, (ptr))

#define tpool_free_http_payloadfield(ptr) \
    tpool_free(POOL_HTTP_PAYLOADFIELD, (ptr))

#endif /* __THREADPOOL__ */

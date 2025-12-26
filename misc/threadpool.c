#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "threadpool.h"

/* Thread-local storage for pool set */
static __thread tpool_set_t tls_pools = {0};

/* Global configuration (set once before threads start) */
typedef struct {
    size_t block_size;
    size_t max_cached;
} pool_config_t;

static pool_config_t global_configs[POOL_TYPE_COUNT] = {0};
static int global_initialized = 0;

/* Pool type names for debugging */
static const char* pool_names[POOL_TYPE_COUNT] = {
    [POOL_CONNECTION]           = "connection_t",
    [POOL_CONNECTION_SERVER_CTX]= "connection_server_ctx_t",
    [POOL_CQUEUE]               = "cqueue_t",
    [POOL_HTTPREQUEST]          = "httprequest_t",
    [POOL_HTTPRESPONSE]         = "httpresponse_t",
    [POOL_HTTP_HEADER]          = "http_header_t",
    [POOL_CQUEUE_ITEM]          = "cqueue_item_t",
    [POOL_QUERY]                = "query_t",
    [POOL_HTTP_PAYLOADPART]     = "http_payloadpart_t",
    [POOL_HTTP_PAYLOADFIELD]    = "http_payloadfield_t",
};

void tpool_register(pool_type_e type, size_t block_size, size_t max_cached) {
    if (type >= POOL_TYPE_COUNT) return;

    /* Ensure block is large enough to hold the free list pointer */
    if (block_size < sizeof(pool_node_t)) {
        block_size = sizeof(pool_node_t);
    }

    /* Align to 8 bytes */
    block_size = (block_size + 7) & ~((size_t)7);

    global_configs[type].block_size = block_size;
    global_configs[type].max_cached = max_cached;
    global_initialized = 1;
}

void tpool_global_init(void) {
    /* This function should be called from server initialization
     * where actual types are available. See tpool_init_defaults() example below.
     *
     * Example usage in server init:
     *   tpool_register(POOL_CONNECTION, sizeof(connection_t), 64);
     *   tpool_register(POOL_CONNECTION_SERVER_CTX, sizeof(connection_server_ctx_t), 64);
     *   ... etc
     */
    global_initialized = 1;
}

void tpool_thread_init(void) {
    if (tls_pools.initialized) return;

    for (int i = 0; i < POOL_TYPE_COUNT; i++) {
        tpool_t* pool = &tls_pools.pools[i];
        pool->free_list = NULL;
        pool->block_size = global_configs[i].block_size;
        pool->max_cached = global_configs[i].max_cached;
        pool->count = 0;
        pool->total_allocs = 0;
        pool->pool_hits = 0;
    }

    tls_pools.initialized = 1;
}

void tpool_thread_destroy(void) {
    if (!tls_pools.initialized) return;

    for (int i = 0; i < POOL_TYPE_COUNT; i++) {
        tpool_t* pool = &tls_pools.pools[i];
        pool_node_t* node = pool->free_list;

        while (node) {
            pool_node_t* next = node->next;
            free(node);
            node = next;
        }

        pool->free_list = NULL;
        pool->count = 0;
    }

    tls_pools.initialized = 0;
}

void* tpool_alloc(pool_type_e type) {
    if (type >= POOL_TYPE_COUNT) return NULL;

    /* Auto-initialize if needed */
    if (!tls_pools.initialized) {
        tpool_thread_init();
    }

    tpool_t* pool = &tls_pools.pools[type];

    /* Pool not configured */
    if (pool->block_size == 0) {
        return NULL;
    }

    pool->total_allocs++;

    /* Try to get from free list */
    if (pool->free_list) {
        pool_node_t* node = pool->free_list;
        pool->free_list = node->next;
        pool->count--;
        pool->pool_hits++;
        return node;
    }

    /* Fall back to malloc */
    return malloc(pool->block_size);
}

void* tpool_zalloc(pool_type_e type) {
    void* ptr = tpool_alloc(type);
    if (ptr && type < POOL_TYPE_COUNT) {
        memset(ptr, 0, tls_pools.pools[type].block_size);
    }
    return ptr;
}

void tpool_free(pool_type_e type, void* ptr) {
    if (ptr == NULL) return;
    if (type >= POOL_TYPE_COUNT) {
        free(ptr);
        return;
    }

    /* Auto-initialize if needed */
    if (!tls_pools.initialized) {
        tpool_thread_init();
    }

    tpool_t* pool = &tls_pools.pools[type];

    /* Pool not configured - just free */
    if (pool->block_size == 0) {
        free(ptr);
        return;
    }

    /* If pool is full, actually free the memory */
    if (pool->count >= pool->max_cached) {
        free(ptr);
        return;
    }

    /* Add to free list */
    pool_node_t* node = (pool_node_t*)ptr;
    node->next = pool->free_list;
    pool->free_list = node;
    pool->count++;
}

void tpool_stats(pool_type_e type, size_t* total_allocs, size_t* pool_hits, size_t* cached) {
    if (type >= POOL_TYPE_COUNT || !tls_pools.initialized) {
        if (total_allocs) *total_allocs = 0;
        if (pool_hits) *pool_hits = 0;
        if (cached) *cached = 0;
        return;
    }

    tpool_t* pool = &tls_pools.pools[type];
    if (total_allocs) *total_allocs = pool->total_allocs;
    if (pool_hits) *pool_hits = pool->pool_hits;
    if (cached) *cached = pool->count;
}

void tpool_dump_stats(void) {
    if (!tls_pools.initialized) {
        fprintf(stderr, "[tpool] Not initialized for this thread\n");
        return;
    }

    fprintf(stderr, "\n=== Thread Pool Statistics ===\n");
    fprintf(stderr, "%-25s %8s %8s %8s %8s %8s\n",
            "Pool", "Size", "Cached", "MaxCache", "Allocs", "Hits");
    fprintf(stderr, "%-25s %8s %8s %8s %8s %8s\n",
            "----", "----", "------", "--------", "------", "----");

    for (int i = 0; i < POOL_TYPE_COUNT; i++) {
        tpool_t* pool = &tls_pools.pools[i];

        if (pool->block_size == 0) continue;  /* Skip unconfigured pools */

        double hit_rate = pool->total_allocs > 0
            ? (100.0 * pool->pool_hits / pool->total_allocs)
            : 0.0;

        fprintf(stderr, "%-25s %8zu %8zu %8zu %8zu %7.1f%%\n",
                pool_names[i],
                pool->block_size,
                pool->count,
                pool->max_cached,
                pool->total_allocs,
                hit_rate);
    }
    fprintf(stderr, "==============================\n\n");
}

int tpool_is_initialized(void) {
    return tls_pools.initialized;
}

size_t tpool_block_size(pool_type_e type) {
    if (type >= POOL_TYPE_COUNT) return 0;
    return global_configs[type].block_size;
}

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pthread.h>

#include "log.h"
#include "broadcast.h"
#include "websocketsresponse.h"

// ============================================================================
// Object Pool Configuration
// ============================================================================

#define BROADCAST_POOL_SIZE 4096

typedef struct connection_queue_broadcast_data {
    connection_queue_item_data_t base;
    broadcast_payload_t* payload;
    void(*handler)(response_t*, const char*, size_t);
    connection_t* connection;
    int pool_index;  // -1 if allocated via malloc
} connection_queue_broadcast_data_t;

typedef struct broadcast_data_pool {
    connection_queue_broadcast_data_t items[BROADCAST_POOL_SIZE];
    atomic_int free_list[BROADCAST_POOL_SIZE];
    atomic_int free_head;
} broadcast_data_pool_t;

static broadcast_data_pool_t* g_broadcast_pool = NULL;

// ============================================================================
// Forward Declarations
// ============================================================================

void __broadcast_queue_request_handler(void*);
connection_queue_broadcast_data_t* __broadcast_queue_data_create(
    connection_t* connection,
    broadcast_payload_t* payload,
    void(*handle)(response_t*, const char*, size_t)
);
void __broadcast_queue_data_free(void*);
broadcast_list_t* __broadcast_create_list(const char* broadcast_name);
void __broadcast_free_list(broadcast_list_t* list);
broadcast_item_t* __broadcast_create_item(
    connection_t* connection,
    void* id,
    void(*response_handler)(response_t*, const char*, size_t)
);
void __broadcast_free_item(broadcast_item_t* item);

// ============================================================================
// Shared Payload with Reference Counting
// ============================================================================

broadcast_payload_t* broadcast_payload_create(const char* data, size_t size) {
    broadcast_payload_t* p = malloc(sizeof(broadcast_payload_t) + size);
    if (!p) return NULL;

    atomic_store(&p->ref_count, 1);
    p->size = size;
    memcpy(p->data, data, size);

    return p;
}

void broadcast_payload_ref(broadcast_payload_t* payload) {
    if (!payload) return;
    atomic_fetch_add(&payload->ref_count, 1);
}

void broadcast_payload_unref(broadcast_payload_t* payload) {
    if (!payload) return;
    if (atomic_fetch_sub(&payload->ref_count, 1) == 1) {
        free(payload);
    }
}

// ============================================================================
// Object Pool for Broadcast Data
// ============================================================================

int broadcast_pool_init(void) {
    g_broadcast_pool = malloc(sizeof(broadcast_data_pool_t));
    if (!g_broadcast_pool) return 0;

    for (int i = 0; i < BROADCAST_POOL_SIZE - 1; i++) {
        atomic_store(&g_broadcast_pool->free_list[i], i + 1);
    }
    atomic_store(&g_broadcast_pool->free_list[BROADCAST_POOL_SIZE - 1], -1);
    atomic_store(&g_broadcast_pool->free_head, 0);

    return 1;
}

void broadcast_pool_free(void) {
    if (g_broadcast_pool) {
        free(g_broadcast_pool);
        g_broadcast_pool = NULL;
    }
}

static connection_queue_broadcast_data_t* broadcast_pool_alloc(void) {
    if (!g_broadcast_pool) {
        // Pool not initialized, fallback to malloc
        connection_queue_broadcast_data_t* data = malloc(sizeof(connection_queue_broadcast_data_t));
        if (data) data->pool_index = -1;
        return data;
    }

    int head, next;
    do {
        head = atomic_load(&g_broadcast_pool->free_head);
        if (head == -1) {
            // Pool exhausted, fallback to malloc
            connection_queue_broadcast_data_t* data = malloc(sizeof(connection_queue_broadcast_data_t));
            if (data) data->pool_index = -1;
            return data;
        }
        next = atomic_load(&g_broadcast_pool->free_list[head]);
    } while (!atomic_compare_exchange_weak(&g_broadcast_pool->free_head, &head, next));

    connection_queue_broadcast_data_t* data = &g_broadcast_pool->items[head];
    data->pool_index = head;
    return data;
}

static void broadcast_pool_release(connection_queue_broadcast_data_t* data) {
    if (!data) return;

    // Only free if allocated via malloc (pool_index == -1)
    if (data->pool_index == -1) {
        free(data);
        return;
    }

    // Item was from pool - return to pool if pool still exists
    if (!g_broadcast_pool) {
        // Pool already freed (shutdown), item memory is already freed with pool
        // Just return without doing anything
        return;
    }

    int index = data->pool_index;
    int head;
    do {
        head = atomic_load(&g_broadcast_pool->free_head);
        atomic_store(&g_broadcast_pool->free_list[index], head);
    } while (!atomic_compare_exchange_weak(&g_broadcast_pool->free_head, &head, index));
}

// ============================================================================
// Broadcast List Management
// ============================================================================

broadcast_list_t* __broadcast_create_list(const char* broadcast_name) {
    broadcast_list_t* list = malloc(sizeof(broadcast_list_t));
    if (!list) return NULL;

    list->items = malloc(sizeof(broadcast_item_t*) * BROADCAST_LIST_INITIAL_CAPACITY);
    if (!list->items) {
        free(list);
        return NULL;
    }

    if (pthread_rwlock_init(&list->rwlock, NULL) != 0) {
        free(list->items);
        free(list);
        return NULL;
    }

    list->count = 0;
    list->capacity = BROADCAST_LIST_INITIAL_CAPACITY;
    list->next = NULL;
    list->name = strdup(broadcast_name);
    if (!list->name) {
        pthread_rwlock_destroy(&list->rwlock);
        free(list->items);
        free(list);
        return NULL;
    }

    return list;
}

void __broadcast_free_list(broadcast_list_t* list) {
    if (!list) return;

    // Free all items
    for (size_t i = 0; i < list->count; i++) {
        __broadcast_free_item(list->items[i]);
    }

    pthread_rwlock_destroy(&list->rwlock);
    free(list->items);
    free(list->name);
    free(list);
}

// ============================================================================
// Broadcast Item Management
// ============================================================================

broadcast_item_t* __broadcast_create_item(
    connection_t* connection,
    void* id,
    void(*response_handler)(response_t*, const char*, size_t)
) {
    broadcast_item_t* item = malloc(sizeof(broadcast_item_t));
    if (!item) return NULL;

    item->connection = connection;
    item->id = id;
    item->response_handler = response_handler;

    return item;
}

void __broadcast_free_item(broadcast_item_t* item) {
    if (!item) return;

    if (item->id && item->id->free) {
        item->id->free(item->id);
    }

    free(item);
}

// ============================================================================
// List Operations with Array
// ============================================================================

static int __broadcast_list_add_item(broadcast_list_t* list, broadcast_item_t* item) {
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        broadcast_item_t** new_items = realloc(list->items,
            sizeof(broadcast_item_t*) * new_capacity);
        if (!new_items) return 0;

        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = item;
    return 1;
}

static int __broadcast_list_remove_item(broadcast_list_t* list, connection_t* connection) {
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i]->connection == connection) {
            __broadcast_free_item(list->items[i]);

            // Move last element to this position (O(1) removal)
            if (i < list->count - 1) {
                list->items[i] = list->items[list->count - 1];
            }
            list->count--;
            return 1;
        }
    }
    return 0;
}

static int __broadcast_list_contains(broadcast_list_t* list, connection_t* connection) {
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i]->connection == connection) {
            return 1;
        }
    }
    return 0;
}

// ============================================================================
// Broadcast Channel Lookup
// ============================================================================

static broadcast_list_t* __broadcast_get_list_read(broadcast_t* broadcast, const char* name) {
    pthread_rwlock_rdlock(&broadcast->rwlock);

    broadcast_list_t* list = broadcast->list;
    while (list) {
        if (strcmp(list->name, name) == 0) {
            pthread_rwlock_rdlock(&list->rwlock);
            pthread_rwlock_unlock(&broadcast->rwlock);
            return list;
        }
        list = list->next;
    }

    pthread_rwlock_unlock(&broadcast->rwlock);
    return NULL;
}

static broadcast_list_t* __broadcast_get_or_create_list(broadcast_t* broadcast, const char* name) {
    // First try with read lock
    pthread_rwlock_rdlock(&broadcast->rwlock);

    broadcast_list_t* list = broadcast->list;
    while (list) {
        if (strcmp(list->name, name) == 0) {
            pthread_rwlock_wrlock(&list->rwlock);
            pthread_rwlock_unlock(&broadcast->rwlock);
            return list;
        }
        list = list->next;
    }

    pthread_rwlock_unlock(&broadcast->rwlock);

    // Not found, need write lock to create
    pthread_rwlock_wrlock(&broadcast->rwlock);

    // Double-check after acquiring write lock
    list = broadcast->list;
    while (list) {
        if (strcmp(list->name, name) == 0) {
            pthread_rwlock_wrlock(&list->rwlock);
            pthread_rwlock_unlock(&broadcast->rwlock);
            return list;
        }
        list = list->next;
    }

    // Create new list
    list = __broadcast_create_list(name);
    if (!list) {
        pthread_rwlock_unlock(&broadcast->rwlock);
        return NULL;
    }

    // Append to broadcast
    if (!broadcast->list) {
        broadcast->list = list;
    }
    if (broadcast->list_last) {
        broadcast->list_last->next = list;
    }
    broadcast->list_last = list;

    pthread_rwlock_wrlock(&list->rwlock);
    pthread_rwlock_unlock(&broadcast->rwlock);

    return list;
}

// ============================================================================
// Queue Data Management
// ============================================================================

void __broadcast_queue_add(
    connection_t* connection,
    broadcast_payload_t* payload,
    void(*handle)(response_t*, const char*, size_t)
) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (atomic_load(&ctx->destroyed))
        return;

    connection_queue_item_t* item = connection_queue_item_create();
    if (!item) return;

    item->run = __broadcast_queue_request_handler;
    item->handle = NULL;
    item->connection = connection;
    item->data = (connection_queue_item_data_t*)__broadcast_queue_data_create(connection, payload, handle);

    if (!item->data) {
        item->free(item);
        return;
    }

    cqueue_incrementlock(ctx->broadcast_queue);

    if (cqueue_size(ctx->broadcast_queue) > 3000) {
        cqueue_unlock(ctx->broadcast_queue);
        item->free(item);
        return;
    }

    cqueue_append(ctx->broadcast_queue, item);
    cqueue_unlock(ctx->broadcast_queue);

    int expected = 1;
    if (atomic_compare_exchange_strong(&ctx->broadcast_ref_count, &expected, 2)) {
        connection_queue_append_broadcast(connection);
    }
}

void __broadcast_queue_request_handler(void* arg) {
    connection_queue_item_t* item = arg;
    connection_queue_broadcast_data_t* data = (connection_queue_broadcast_data_t*)item->data;
    connection_server_ctx_t* conn_ctx = item->connection->ctx;

    websocketsresponse_t* response = websocketsresponse_create(item->connection);
    if (!response) {
        atomic_store(&conn_ctx->destroyed, 1);
        connection_after_read(item->connection);
        return;
    }

    if (conn_ctx->response)
        ((response_t*)conn_ctx->response)->free(conn_ctx->response);

    conn_ctx->response = response;

    data->handler(conn_ctx->response, data->payload->data, data->payload->size);

    connection_after_read(item->connection);
}

connection_queue_broadcast_data_t* __broadcast_queue_data_create(
    connection_t* connection,
    broadcast_payload_t* payload,
    void(*handle)(response_t*, const char*, size_t)
) {
    connection_queue_broadcast_data_t* data = broadcast_pool_alloc();
    if (!data) return NULL;

    data->base.free = __broadcast_queue_data_free;
    data->payload = payload;
    broadcast_payload_ref(payload);
    data->handler = handle;
    data->connection = connection;

    return data;
}

void __broadcast_queue_data_free(void* arg) {
    if (!arg) return;

    connection_queue_broadcast_data_t* data = arg;

    if (data->payload)
        broadcast_payload_unref(data->payload);

    broadcast_pool_release(data);
}

// ============================================================================
// Public API
// ============================================================================

broadcast_t* broadcast_init(void) {
    broadcast_t* broadcast = malloc(sizeof(broadcast_t));
    if (!broadcast) return NULL;

    if (pthread_rwlock_init(&broadcast->rwlock, NULL) != 0) {
        free(broadcast);
        return NULL;
    }

    broadcast->list = NULL;
    broadcast->list_last = NULL;

    return broadcast;
}

void broadcast_free(broadcast_t* broadcast) {
    if (!broadcast) return;

    pthread_rwlock_wrlock(&broadcast->rwlock);

    broadcast_list_t* list = broadcast->list;
    while (list) {
        broadcast_list_t* next = list->next;
        __broadcast_free_list(list);
        list = next;
    }

    pthread_rwlock_unlock(&broadcast->rwlock);
    pthread_rwlock_destroy(&broadcast->rwlock);

    free(broadcast);
}

static void __broadcast_free_id(void* id) {
    if (id && ((broadcast_id_t*)id)->free)
        ((broadcast_id_t*)id)->free(id);
}

int broadcast_add(
    const char* broadcast_name,
    connection_t* connection,
    void* id,
    void(*response_handler)(response_t*, const char*, size_t)
) {
    if (!broadcast_name || !connection || !response_handler) {
        __broadcast_free_id(id);
        return 0;
    }

    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_t* broadcast = ctx->server->broadcast;

    broadcast_list_t* list = __broadcast_get_or_create_list(broadcast, broadcast_name);
    if (!list) {
        __broadcast_free_id(id);
        return 0;
    }

    // list->rwlock is held for writing

    if (__broadcast_list_contains(list, connection)) {
        pthread_rwlock_unlock(&list->rwlock);
        __broadcast_free_id(id);
        return 0;
    }

    broadcast_item_t* item = __broadcast_create_item(connection, id, response_handler);
    if (!item) {
        pthread_rwlock_unlock(&list->rwlock);
        __broadcast_free_id(id);
        return 0;
    }

    int result = __broadcast_list_add_item(list, item);
    if (!result) {
        __broadcast_free_item(item);  // This frees id via __broadcast_free_item
    }

    pthread_rwlock_unlock(&list->rwlock);

    return result;
}

void broadcast_remove(const char* broadcast_name, connection_t* connection) {
    if (!broadcast_name || !connection) return;

    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_t* broadcast = ctx->server->broadcast;

    pthread_rwlock_rdlock(&broadcast->rwlock);

    broadcast_list_t* list = broadcast->list;
    while (list) {
        if (strcmp(list->name, broadcast_name) == 0) {
            pthread_rwlock_wrlock(&list->rwlock);
            __broadcast_list_remove_item(list, connection);
            pthread_rwlock_unlock(&list->rwlock);
            pthread_rwlock_unlock(&broadcast->rwlock);
            return;
        }
        list = list->next;
    }

    pthread_rwlock_unlock(&broadcast->rwlock);
}

void broadcast_clear(connection_t* connection) {
    if (!connection) return;

    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_t* broadcast = ctx->server->broadcast;

    pthread_rwlock_rdlock(&broadcast->rwlock);

    broadcast_list_t* list = broadcast->list;
    while (list) {
        pthread_rwlock_wrlock(&list->rwlock);
        __broadcast_list_remove_item(list, connection);
        pthread_rwlock_unlock(&list->rwlock);
        list = list->next;
    }

    pthread_rwlock_unlock(&broadcast->rwlock);
}

void broadcast_send_all(
    const char* broadcast_name,
    connection_t* connection,
    const char* payload,
    size_t size
) {
    broadcast_send(broadcast_name, connection, payload, size, NULL, NULL);
}

void broadcast_send(
    const char* broadcast_name,
    connection_t* connection,
    const char* payload,
    size_t size,
    void* id,
    int(*compare_handler)(void*, void*)
) {
    if (!broadcast_name || !connection) {
        if (id && ((broadcast_id_t*)id)->free)
            ((broadcast_id_t*)id)->free(id);
        return;
    }

    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_t* broadcast = ctx->server->broadcast;

    broadcast_list_t* list = __broadcast_get_list_read(broadcast, broadcast_name);
    if (!list) {
        if (id && ((broadcast_id_t*)id)->free)
            ((broadcast_id_t*)id)->free(id);
        return;
    }

    // list->rwlock is held for reading

    // Create shared payload once
    broadcast_payload_t* shared_payload = broadcast_payload_create(payload, size);
    if (!shared_payload) {
        pthread_rwlock_unlock(&list->rwlock);
        if (id && ((broadcast_id_t*)id)->free)
            ((broadcast_id_t*)id)->free(id);
        return;
    }

    // Iterate over array (better cache locality)
    for (size_t i = 0; i < list->count; i++) {
        broadcast_item_t* item = list->items[i];

        if (connection == item->connection)
            continue;

        if (id && compare_handler) {
            if (compare_handler(item->id, id))
                __broadcast_queue_add(item->connection, shared_payload, item->response_handler);
        } else {
            __broadcast_queue_add(item->connection, shared_payload, item->response_handler);
        }
    }

    pthread_rwlock_unlock(&list->rwlock);

    // Release our reference to the shared payload
    broadcast_payload_unref(shared_payload);

    if (id && ((broadcast_id_t*)id)->free)
        ((broadcast_id_t*)id)->free(id);
}

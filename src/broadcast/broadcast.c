#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>

#include "log.h"
#include "broadcast.h"
#include "websocketsresponse.h"

typedef struct connection_queue_broadcast_data {
    connection_queue_item_data_t base;
    char* payload;
    size_t size;
    void(*handler)(response_t*, const char*, size_t);
    connection_t* connection;
} connection_queue_broadcast_data_t;

void __broadcast_queue_request_handler(void*);
connection_queue_broadcast_data_t* __broadcast_queue_data_create(connection_t* connection, const char* payload, size_t size, void(*handle)(response_t*, const char*, size_t));
void __broadcast_queue_data_free(void*);

broadcast_list_t* __broadcast_create_list(const char* broadcast_name) {
    broadcast_list_t* list = malloc(sizeof * list);
    if (!list) return NULL;

    broadcast_list_t* result = NULL;

    list->item = NULL;
    list->item_last = NULL;
    atomic_store(&list->locked, 1);
    list->next = NULL;
    list->name = malloc(strlen(broadcast_name) + 1);
    if (!list->name) goto failed;
    strcpy(list->name, broadcast_name);

    result = list;

    failed:

    if (!result)
        free(list);

    return result;
}

void __broadcast_free_list(broadcast_list_t* list) {
    if (!list) return;

    list->item = NULL;
    list->item_last = NULL;
    list->locked = 0;
    list->next = NULL;

    if (list->name)
        free(list->name);

    list->name = NULL;

    free(list);
}

broadcast_item_t* __broadcast_create_item(connection_t* connection, void* id, void(*response_handler)(response_t*, const char*, size_t)) {
    broadcast_item_t* item = malloc(sizeof * item);
    if (!item) return NULL;

    item->connection = connection;
    atomic_store(&item->locked, 0);
    item->next = NULL;
    item->response_handler = response_handler;
    item->id = id;

    return item;
}

void __broadcast_free_item(broadcast_item_t* item) {
    if (item == NULL) return;

    if (item->id != NULL) {
        if (item->id->free)
            item->id->free(item->id);
    }

    free(item);
}

int __broadcast_lock(broadcast_t* broadcast) {
    if (broadcast == NULL) return 0;
    _Bool expected = 0;
    _Bool desired = 1;

    do {
        expected = 0;
    } while (!atomic_compare_exchange_strong(&broadcast->locked, &expected, desired));

    return 1;
}

void __broadcast_unlock(broadcast_t* broadcast) {
    if (broadcast == NULL) return;

    atomic_store(&broadcast->locked, 0);
}

broadcast_item_t* __broadcast_lock_item(broadcast_item_t* item) {
    if (item == NULL) return NULL;

    _Bool expected = 0;
    _Bool desired = 1;

    do {
        expected = 0;
        if (item == NULL) return NULL;
    } while (!atomic_compare_exchange_strong(&item->locked, &expected, desired));

    return item;
}

void __broadcast_unlock_item(broadcast_item_t* item) {
    if (item == NULL) return;

    atomic_store(&item->locked, 0);
}

broadcast_list_t* __broadcast_lock_list(broadcast_list_t* list) {
    if (list == NULL) return NULL;

    _Bool expected = 0;
    _Bool desired = 1;

    do {
        expected = 0;
        if (list == NULL) return NULL;
    } while (!atomic_compare_exchange_strong(&list->locked, &expected, desired));

    return list;
}

void __broadcast_unlock_list(broadcast_list_t* list) {
    if (list == NULL) return;

    atomic_store(&list->locked, 0);
}

broadcast_list_t* __broadcast_get_list(const char* broadcast_name, broadcast_list_t* broadcast_list) {
    broadcast_list_t* list = __broadcast_lock_list(broadcast_list);
    while (list) {
        if (strcmp(list->name, broadcast_name) == 0)
            return list; // return locked list

        broadcast_list_t* next = __broadcast_lock_list(list->next);

        __broadcast_unlock_list(list);

        list = next;
    }

    return NULL;
}

int __broadcast_list_contains(broadcast_list_t* list, connection_t* connection) {
    broadcast_item_t* item = __broadcast_lock_item(list->item);
    while (item) {
        if (item->connection == connection) {
            __broadcast_unlock_item(item);
            return 1;
        }

        broadcast_item_t* next = __broadcast_lock_item(item->next);

        __broadcast_unlock_item(item);

        item = next;
    }

    return 0;
}

void __broadcast_append_list(broadcast_t* broadcast, broadcast_list_t* list) {
    if (broadcast == NULL || list == NULL) return;
    if (!__broadcast_lock(broadcast)) return;

    if (broadcast->list == NULL)
        broadcast->list = list;

    broadcast_list_t* list_last = broadcast->list_last;

    __broadcast_lock_list(list_last);

    if (list_last)
        list_last->next = list;

    broadcast->list_last = list;

    __broadcast_unlock_list(list_last);
    __broadcast_unlock(broadcast);
}

void __broadcast_append_item(broadcast_list_t* list, broadcast_item_t* item) {
    if (list == NULL || item == NULL) return;

    if (list->item == NULL)
        list->item = item;

    broadcast_item_t* item_last = list->item_last;
    __broadcast_lock_item(item_last);

    if (list->item_last)
        list->item_last->next = item;

    list->item_last = item;

    __broadcast_unlock_item(item_last);
}

void __broadcast_queue_add(connection_t* connection, const char* payload, size_t size, void(*handle)(response_t* response, const char* payload, size_t size)) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (atomic_load(&ctx->destroyed))
        return;

    connection_queue_item_t* item = connection_queue_item_create();
    if (item == NULL) return;

    item->run = __broadcast_queue_request_handler;
    item->handle = NULL;
    item->connection = connection;
    item->data = (connection_queue_item_data_t*)__broadcast_queue_data_create(connection, payload, size, handle);

    if (item->data == NULL) {
        item->free(item);
        return;
    }

    // Добавляем сообщение в broadcast_queue
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
    if (response == NULL) {
        // TODO: close connection, return error
        atomic_store(&conn_ctx->destroyed, 1);
        connection_after_read(item->connection);
        return;
    }

    conn_ctx->response = response;

    data->handler(conn_ctx->response, data->payload, data->size);

    connection_after_read(item->connection);
}

connection_queue_broadcast_data_t* __broadcast_queue_data_create(connection_t* connection, const char* payload, size_t size, void(*handle)(response_t*, const char*, size_t)) {
    connection_queue_broadcast_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    data->base.free = __broadcast_queue_data_free;
    data->payload = malloc(size);
    data->size = size;
    data->handler = handle;
    data->connection = connection;

    if (data->payload == NULL) {
        data->base.free(data);
        return NULL;
    }

    memcpy(data->payload, payload, size);

    return data;
}

void __broadcast_queue_data_free(void* arg) {
    if (arg == NULL) return;

    connection_queue_broadcast_data_t* data = arg;

    if (data->payload) free(data->payload);

    free(data);
}

broadcast_t* broadcast_init() {
    broadcast_t* broadcast = malloc(sizeof * broadcast);
    if (!broadcast) return NULL;

    atomic_store(&broadcast->locked, 0);
    broadcast->list = NULL;
    broadcast->list_last = NULL;

    return broadcast;
}

void broadcast_free(broadcast_t* broadcast) {
    if (broadcast == NULL) return;

    broadcast_list_t* list = broadcast->list;
    while (list) {
        broadcast_list_t* next = list->next;
        broadcast_item_t* item = __broadcast_lock_item(list->item);
        while (item) {
            broadcast_item_t* next = __broadcast_lock_item(item->next);
            __broadcast_free_item(item);
            item = next;
        }

        __broadcast_free_list(list);
        list = next;
    }

    free(broadcast);
}

int broadcast_add(const char* broadcast_name, connection_t* connection, void* id, void(*response_handler)(response_t* response, const char* payload, size_t size)) {
    if (broadcast_name == NULL || connection == NULL || response_handler == NULL)
        return 0;

    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_t* broadcast = ctx->server->broadcast;

    int result = 0;
    broadcast_item_t* item = NULL;
    broadcast_list_t* list = __broadcast_get_list(broadcast_name, broadcast->list);
    if (!list) {
        list = __broadcast_create_list(broadcast_name); // already locked list
        if (!list) goto failed;

        __broadcast_append_list(broadcast, list);
    }
    else if (__broadcast_list_contains(list, connection))
        goto failed;

    item = __broadcast_create_item(connection, id, response_handler);
    if (!item) goto failed;

    __broadcast_append_item(list, item);

    result = 1;

    failed:

    __broadcast_unlock_list(list);

    return result;
}

void broadcast_remove(const char* broadcast_name, connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_list_t* list = __broadcast_lock_list(ctx->server->broadcast->list);
    while (list) {
        if (strcmp(list->name, broadcast_name) == 0) {
            broadcast_item_t* item = __broadcast_lock_item(list->item);

            if (item && item->connection == connection) {
                list->item = item->next;
                if (item == list->item_last)
                    list->item_last = NULL;

                __broadcast_free_item(item);
                __broadcast_unlock_list(list);
                return;
            }

            while (item) {
                broadcast_item_t* next_item = __broadcast_lock_item(item->next);

                if (next_item && next_item->connection == connection) {
                    item->next = next_item->next;
                    if (next_item == list->item_last)
                        list->item_last = item;
                    __broadcast_free_item(next_item);
                    __broadcast_unlock_item(item);
                    __broadcast_unlock_list(list);
                    return;
                }

                __broadcast_unlock_item(item);

                item = next_item;
            }

            __broadcast_unlock_list(list);
            return;
        }

        broadcast_list_t* next = __broadcast_lock_list(list->next);
        __broadcast_unlock_list(list);
        list = next;
    }
}

void broadcast_clear(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_list_t* list = __broadcast_lock_list(ctx->server->broadcast->list);
    while (list) {
        broadcast_item_t* item = __broadcast_lock_item(list->item);
        broadcast_list_t* next = NULL;

        if (item && item->connection == connection) {
            list->item = item->next;
            if (item == list->item_last)
                list->item_last = NULL;

            __broadcast_free_item(item);
            goto next;
        }

        while (item) {
            broadcast_item_t* next_item = __broadcast_lock_item(item->next);

            if (next_item && next_item->connection == connection) {
                item->next = next_item->next;
                if (next_item == list->item_last)
                    list->item_last = item;
                __broadcast_free_item(next_item);
                next_item = __broadcast_lock_item(item->next);
            }

            __broadcast_unlock_item(item);
            item = next_item;
        }

        next:

        next = __broadcast_lock_list(list->next);
        __broadcast_unlock_list(list);
        list = next;
    }
}

void broadcast_send_all(const char* broadcast_name, connection_t* connection, const char* payload, size_t size) {
    broadcast_send(broadcast_name, connection, payload, size, NULL, NULL);
}

void broadcast_send(const char* broadcast_name, connection_t* connection, const char* payload, size_t size, void* id, int(*compare_handler)(void* st1, void* st2)) {
    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_item_t* item = NULL;
    broadcast_list_t* list = __broadcast_get_list(broadcast_name, ctx->server->broadcast->list);
    if (list == NULL) goto done;

    item = __broadcast_lock_item(list->item);
    while (item) {
        if (connection != item->connection) {
            if (id && compare_handler && compare_handler(item->id, id))
                __broadcast_queue_add(item->connection, payload, size, item->response_handler);
            else if (!id && !compare_handler)
                __broadcast_queue_add(item->connection, payload, size, item->response_handler);
        }

        broadcast_item_t* next_item = __broadcast_lock_item(item->next);
        __broadcast_unlock_item(item);
        item = next_item;
    }

    done:

    if (id != NULL && ((broadcast_id_t*)id)->free)
        ((broadcast_id_t*)id)->free(id);

    __broadcast_unlock_list(list);
}

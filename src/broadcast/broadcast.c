#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <stdatomic.h>

#include "log.h"
#include "broadcast.h"
#include "websocketsresponse.h"

/*
 * Модель блокировок:
 *   broadcast->locked — защищает структуру списка каналов (list, list_last, next)
 *   list->locked      — защищает подписчиков канала (item, item_last, next)
 * Порядок захвата: broadcast -> list. Захватывать broadcast,
 * удерживая лок канала, запрещено.
 */

/**
 * Разделяемый буфер сообщения со счётчиком ссылок.
 * Создаётся один раз на рассылку и раздаётся всем получателям.
 */
typedef struct broadcast_payload {
    atomic_int ref_count;
    size_t size;
    char data[];
} broadcast_payload_t;

typedef struct connection_queue_broadcast_data {
    connection_queue_item_data_t base;
    broadcast_payload_t* payload;
    void(*handler)(response_t*, const char*, size_t);
    connection_t* connection;
} connection_queue_broadcast_data_t;

void __broadcast_queue_request_handler(void*);
connection_queue_broadcast_data_t* __broadcast_queue_data_create(connection_t* connection, broadcast_payload_t* payload, void(*handle)(response_t*, const char*, size_t));
void __broadcast_queue_data_free(void*);

void __broadcast_spin_lock(atomic_bool* locked) {
    _Bool expected = 0;

    while (!atomic_compare_exchange_weak(locked, &expected, 1)) {
        expected = 0;
        sched_yield();
    }
}

void __broadcast_spin_unlock(atomic_bool* locked) {
    atomic_store(locked, 0);
}

int __broadcast_lock(broadcast_t* broadcast) {
    if (broadcast == NULL) return 0;

    __broadcast_spin_lock(&broadcast->locked);

    return 1;
}

void __broadcast_unlock(broadcast_t* broadcast) {
    if (broadcast == NULL) return;

    __broadcast_spin_unlock(&broadcast->locked);
}

void __broadcast_lock_list(broadcast_list_t* list) {
    if (list == NULL) return;

    __broadcast_spin_lock(&list->locked);
}

void __broadcast_unlock_list(broadcast_list_t* list) {
    if (list == NULL) return;

    __broadcast_spin_unlock(&list->locked);
}

broadcast_payload_t* __broadcast_payload_create(const char* payload, size_t size) {
    broadcast_payload_t* shared_payload = malloc(sizeof * shared_payload + size);
    if (shared_payload == NULL) return NULL;

    atomic_store(&shared_payload->ref_count, 1);
    shared_payload->size = size;

    if (size > 0)
        memcpy(shared_payload->data, payload, size);

    return shared_payload;
}

broadcast_payload_t* __broadcast_payload_acquire(broadcast_payload_t* payload) {
    atomic_fetch_add(&payload->ref_count, 1);

    return payload;
}

void __broadcast_payload_release(broadcast_payload_t* payload) {
    if (payload == NULL) return;

    if (atomic_fetch_sub(&payload->ref_count, 1) == 1)
        free(payload);
}

broadcast_list_t* __broadcast_create_list(const char* broadcast_name) {
    broadcast_list_t* list = malloc(sizeof * list);
    if (!list) return NULL;

    broadcast_list_t* result = NULL;

    list->item = NULL;
    list->item_last = NULL;
    atomic_store(&list->locked, 0);
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

    if (list->name)
        free(list->name);

    free(list);
}

broadcast_item_t* __broadcast_create_item(connection_t* connection, void* id, void(*response_handler)(response_t*, const char*, size_t)) {
    broadcast_item_t* item = malloc(sizeof * item);
    if (!item) return NULL;

    item->connection = connection;
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

// требует захваченного broadcast->locked
broadcast_list_t* __broadcast_find_list(broadcast_t* broadcast, const char* broadcast_name) {
    for (broadcast_list_t* list = broadcast->list; list != NULL; list = list->next)
        if (strcmp(list->name, broadcast_name) == 0)
            return list;

    return NULL;
}

// требует захваченного broadcast->locked
void __broadcast_append_list(broadcast_t* broadcast, broadcast_list_t* list) {
    if (broadcast->list == NULL)
        broadcast->list = list;
    else
        broadcast->list_last->next = list;

    broadcast->list_last = list;
}

// требует захваченного broadcast->locked
void __broadcast_unlink_list(broadcast_t* broadcast, broadcast_list_t* list, broadcast_list_t* prev) {
    if (prev != NULL)
        prev->next = list->next;
    else
        broadcast->list = list->next;

    if (broadcast->list_last == list)
        broadcast->list_last = prev;
}

// требует захваченного list->locked
int __broadcast_list_contains(broadcast_list_t* list, connection_t* connection) {
    for (broadcast_item_t* item = list->item; item != NULL; item = item->next)
        if (item->connection == connection)
            return 1;

    return 0;
}

// требует захваченного list->locked
void __broadcast_append_item(broadcast_list_t* list, broadcast_item_t* item) {
    if (list->item == NULL)
        list->item = item;
    else
        list->item_last->next = item;

    list->item_last = item;
}

// требует захваченного list->locked
void __broadcast_list_remove_connection(broadcast_list_t* list, connection_t* connection) {
    broadcast_item_t* prev = NULL;
    broadcast_item_t* item = list->item;

    while (item != NULL) {
        if (item->connection == connection) {
            if (prev != NULL)
                prev->next = item->next;
            else
                list->item = item->next;

            if (list->item_last == item)
                list->item_last = prev;

            __broadcast_free_item(item);
            return; // соединение подписано на канал не более одного раза
        }

        prev = item;
        item = item->next;
    }
}

void __broadcast_queue_add(connection_t* connection, broadcast_payload_t* payload, void(*handle)(response_t* response, const char* payload, size_t size)) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (atomic_load(&ctx->destroyed))
        return;

    connection_queue_item_t* item = connection_queue_item_create();
    if (item == NULL) return;

    item->run = __broadcast_queue_request_handler;
    item->handle = NULL;
    item->connection = connection;
    item->data = (connection_queue_item_data_t*)__broadcast_queue_data_create(connection, payload, handle);

    if (item->data == NULL) {
        item->free(item);
        return;
    }

    // Добавляем сообщение в broadcast_queue
    cqueue_incrementlock(ctx->broadcast_queue);

    if (cqueue_size(ctx->broadcast_queue) > 3000) {
        cqueue_unlock(ctx->broadcast_queue);
        item->free(item);
        log_error("Broadcast error: connection queue overflow, message dropped\n");
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

    data->handler(conn_ctx->response, data->payload->data, data->payload->size);

    connection_after_read(item->connection);
}

connection_queue_broadcast_data_t* __broadcast_queue_data_create(connection_t* connection, broadcast_payload_t* payload, void(*handle)(response_t*, const char*, size_t)) {
    connection_queue_broadcast_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    data->base.free = __broadcast_queue_data_free;
    data->payload = __broadcast_payload_acquire(payload);
    data->handler = handle;
    data->connection = connection;

    return data;
}

void __broadcast_queue_data_free(void* arg) {
    if (arg == NULL) return;

    connection_queue_broadcast_data_t* data = arg;

    __broadcast_payload_release(data->payload);

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

    // вызывается при остановке сервера, когда конкурентного доступа уже нет
    broadcast_list_t* list = broadcast->list;
    while (list) {
        broadcast_list_t* next = list->next;

        broadcast_item_t* item = list->item;
        while (item) {
            broadcast_item_t* next_item = item->next;
            __broadcast_free_item(item);
            item = next_item;
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
    int created = 0;

    __broadcast_lock(broadcast);

    broadcast_list_t* list = __broadcast_find_list(broadcast, broadcast_name);
    if (list == NULL) {
        list = __broadcast_create_list(broadcast_name);
        if (list == NULL) goto done;
        created = 1;
    }

    __broadcast_lock_list(list);

    if (created || !__broadcast_list_contains(list, connection)) {
        broadcast_item_t* item = __broadcast_create_item(connection, id, response_handler);
        if (item != NULL) {
            __broadcast_append_item(list, item);
            result = 1;
        }
    }

    __broadcast_unlock_list(list);

    if (created) {
        if (result)
            __broadcast_append_list(broadcast, list);
        else
            __broadcast_free_list(list);
    }

    done:

    __broadcast_unlock(broadcast);

    return result;
}

void broadcast_remove(const char* broadcast_name, connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_t* broadcast = ctx->server->broadcast;

    __broadcast_lock(broadcast);

    broadcast_list_t* prev = NULL;
    broadcast_list_t* list = broadcast->list;
    while (list != NULL && strcmp(list->name, broadcast_name) != 0) {
        prev = list;
        list = list->next;
    }

    if (list != NULL) {
        __broadcast_lock_list(list);
        __broadcast_list_remove_connection(list, connection);
        const int empty = list->item == NULL;
        __broadcast_unlock_list(list);

        // пустой канал удаляем, иначе список каналов растёт бесконечно
        if (empty) {
            __broadcast_unlink_list(broadcast, list, prev);
            __broadcast_free_list(list);
        }
    }

    __broadcast_unlock(broadcast);
}

void broadcast_clear(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    // connection_close вызывает broadcast_clear безусловно: без гардов
    // соединение сервера без broadcast (server NULL или broadcast NULL)
    // разыменовывало NULL — __broadcast_lock(NULL) возвращает 0,
    // но его результат здесь игнорировался
    if (ctx->server == NULL || ctx->server->broadcast == NULL)
        return;

    broadcast_t* broadcast = ctx->server->broadcast;

    __broadcast_lock(broadcast);

    broadcast_list_t* prev = NULL;
    broadcast_list_t* list = broadcast->list;
    while (list != NULL) {
        broadcast_list_t* next = list->next;

        __broadcast_lock_list(list);
        __broadcast_list_remove_connection(list, connection);
        const int empty = list->item == NULL;
        __broadcast_unlock_list(list);

        if (empty) {
            __broadcast_unlink_list(broadcast, list, prev);
            __broadcast_free_list(list);
        }
        else
            prev = list;

        list = next;
    }

    __broadcast_unlock(broadcast);
}

void broadcast_send_all(const char* broadcast_name, connection_t* connection, const char* payload, size_t size) {
    broadcast_send(broadcast_name, connection, payload, size, NULL, NULL);
}

void broadcast_send(const char* broadcast_name, connection_t* connection, const char* payload, size_t size, void* id, int(*compare_handler)(void* st1, void* st2)) {
    connection_server_ctx_t* ctx = connection->ctx;
    broadcast_t* broadcast = ctx->server->broadcast;

    __broadcast_lock(broadcast);
    broadcast_list_t* list = __broadcast_find_list(broadcast, broadcast_name);
    __broadcast_lock_list(list);
    __broadcast_unlock(broadcast);

    if (list == NULL) goto done;

    broadcast_payload_t* shared_payload = __broadcast_payload_create(payload, size);
    if (shared_payload == NULL) {
        __broadcast_unlock_list(list);
        goto done;
    }

    for (broadcast_item_t* item = list->item; item != NULL; item = item->next) {
        if (connection == item->connection)
            continue;

        // фильтр применяется только когда заданы и id, и компаратор
        if (id != NULL && compare_handler != NULL && !compare_handler(item->id, id))
            continue;

        __broadcast_queue_add(item->connection, shared_payload, item->response_handler);
    }

    __broadcast_unlock_list(list);
    __broadcast_payload_release(shared_payload);

    done:

    if (id != NULL && ((broadcast_id_t*)id)->free)
        ((broadcast_id_t*)id)->free(id);
}

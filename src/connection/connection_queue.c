#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "log.h"
#include "connection_queue.h"
#include "cqueue.h"

static cqueue_t* queue = NULL;

static pthread_cond_t connection_queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t connection_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

void __connection_queue_append(connection_queue_item_t*);
int __connection_queue_empty(cqueue_t*);
connection_t* __connection_queue_pop();
void __connection_queue_item_free(connection_queue_item_t*);
int __connection_queue_append_item(cqueue_t* queue, void* data);


void __connection_queue_append(connection_queue_item_t* qitem) {
    connection_s_inc(qitem->connection);

    __connection_queue_append_item(queue, qitem->connection);
}


int __connection_queue_append_item(cqueue_t* queue, void* data) {
    cqueue_lock(queue);
    const int r = cqueue_append(queue, data);
    cqueue_unlock(queue);

    return r;
}

connection_t* __connection_queue_pop() {
    cqueue_lock(queue);
    connection_t* connection = cqueue_pop(queue);
    cqueue_unlock(queue);

    // queue is empty
    if (connection == NULL)
        return NULL;

    connection_s_lock(connection);

    connection_server_ctx_t* ctx = connection->ctx;

    if (atomic_load(&ctx->destroyed)) {
        if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
            connection_s_unlock(connection);

        return NULL;
    }

    return connection;
}

int __connection_queue_empty(cqueue_t* queue) {
    if (queue == NULL) return 1;

    cqueue_lock(queue);
    const int empty = cqueue_empty(queue);
    cqueue_unlock(queue);

    return empty;
}

void __connection_queue_item_free(connection_queue_item_t* item) {
    if (item == NULL) return;

    if (item->data != NULL)
        item->data->free(item->data);

    free(item);
}

int connection_queue_init() {
    if (queue != NULL) return 1;

    queue = cqueue_create();
    if (queue == NULL) return 0;

    return 1;
}

void connection_queue_guard_append_item(connection_queue_item_t* item) {
    pthread_mutex_lock(&connection_queue_mutex);
    __connection_queue_append(item);
    pthread_cond_signal(&connection_queue_cond);
    pthread_mutex_unlock(&connection_queue_mutex);
}

void connection_queue_guard_append(connection_t* connection) {
    pthread_mutex_lock(&connection_queue_mutex);

    connection_s_inc(connection);
    __connection_queue_append_item(queue, connection);

    pthread_cond_signal(&connection_queue_cond);
    pthread_mutex_unlock(&connection_queue_mutex);
}

connection_t* connection_queue_guard_pop() {
    struct timeval now;
    gettimeofday(&now, NULL);
    struct timespec timeToWait = {
        .tv_sec = now.tv_sec + 1,
        .tv_nsec = 0
    };

    if (__connection_queue_empty(queue)) {
        pthread_mutex_lock(&connection_queue_mutex);
        pthread_cond_timedwait(&connection_queue_cond, &connection_queue_mutex, &timeToWait);
        pthread_mutex_unlock(&connection_queue_mutex);
    }

    return __connection_queue_pop();
}

void connection_queue_broadcast() {
    pthread_mutex_lock(&connection_queue_mutex);
    pthread_cond_broadcast(&connection_queue_cond);
    pthread_mutex_unlock(&connection_queue_mutex);
}

connection_queue_item_t* connection_queue_item_create() {
    connection_queue_item_t* item = malloc(sizeof * item);
    if (item == NULL) return NULL;

    item->free = __connection_queue_item_free;
    item->run = NULL;
    item->handle = NULL;
    item->connection = NULL;
    item->data = NULL;

    return item;
}

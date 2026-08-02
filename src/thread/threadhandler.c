#define _GNU_SOURCE
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>

#include "log.h"
#include "json.h"
#include "metrics.h"
#include "signal/signal.h"
#include "threadhandler.h"
#include "connection_queue.h"

void* thread_handler(void* arg) {
    signal_block_usr1();

    appconfig_t* appconfig = arg;
    appconfg_threads_increment(appconfig);

    while (1) {
        if (atomic_load(&appconfig->shutdown))
            break;

        /* Handed over unlocked: taking connection_s_lock is the runner's job,
         * for the state it actually touches. Several workers may be holding the
         * same connection here at once — one per queued item — which is what
         * makes handlers of one HTTP/2 connection run in parallel
         * (docs/concurrency/00 §5). */
        connection_t* connection = connection_queue_guard_pop();
        if (connection == NULL)
            continue;

        connection_server_ctx_t* ctx = connection->ctx;

        /* Read once per iteration, not once per instrumented point: a config
         * reload could flip it between the begin and the end of a handler, and
         * a half-counted handler would leave the in-flight gauges drifting. */
        const int counted = metrics_enabled();

        /* cqueue_lock is now the only thing protecting these queues: it used to
         * be redundant next to connection_s_lock, and is not any more. */
        cqueue_lock(ctx->queue);
        const int depth = counted ? cqueue_size(ctx->queue) : 0;
        connection_queue_item_t* item = cqueue_pop(ctx->queue);
        cqueue_unlock(ctx->queue);

        if (counted)
            metrics_queue_pop(depth);

        /* An empty handler queue is normal, not an error: the fan-out appends
         * one queue entry per item, and connection_after_write may add one more
         * for a queue that a worker has meanwhile drained. Fall through to the
         * broadcast queue and, failing that, just drop the reference. */
        if (item == NULL) {
            cqueue_lock(ctx->broadcast_queue);
            item = cqueue_pop(ctx->broadcast_queue);
            cqueue_unlock(ctx->broadcast_queue);
        }

        if (item != NULL) {
            if (counted)
                metrics_handler_begin(atomic_fetch_add_explicit(&ctx->handlers_inflight, 1, memory_order_relaxed) + 1);

            item->run(item);
            item->free(item);

            if (counted) {
                atomic_fetch_sub_explicit(&ctx->handlers_inflight, 1, memory_order_relaxed);
                metrics_handler_end();
            }
        }

        /* Only the reference is dropped here. Releasing the lock is no longer
         * tied to it (§4.7): the runner that took the lock released it, and this
         * worker may not even have been the one holding it. */
        connection_s_dec(connection);
    }

    appconfg_threads_decrement(appconfig);
    json_manager_free();

    pthread_exit(NULL);
}

int thread_handler_run(appconfig_t* appconfig, int thread_count) {
    for (int i = 0; i < thread_count; i++) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_handler, appconfig) != 0) {
            log_error("thread_handler_run: unable to create thread handler\n");
            return 0;
        }

        pthread_detach(thread);
        pthread_setname_np(thread, "Server handler");
    }

    return 1;
}

void thread_handlers_wakeup() {
    connection_queue_broadcast();
}

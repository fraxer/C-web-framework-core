#include <unistd.h>
#include <errno.h>
#include <sched.h>

#include "log.h"
#include "metrics.h"
#include "openssl.h"
#include "connection_s.h"
#include "connection_queue.h"
#include "multiplexing.h"

void broadcast_clear(connection_t*);
void httpparser_free(void*);

static connection_server_ctx_t* __ctx_create(listener_t* listener);
static void __ctx_reset(void* arg);
static void __ctx_free(void* arg);

connection_t* connection_s_create(int fd, in_addr_t ip, unsigned short int port, connection_server_ctx_t* ctx, char* buffer, size_t buffer_size) {
    connection_t* result = NULL;
    struct sockaddr in_addr;
    socklen_t in_len = sizeof(in_addr);
    connection_t* connection = NULL;

    const int connfd = accept(fd, &in_addr, &in_len);
    if (connfd == -1)
        return NULL;

    // int size = 16384;
    // if (setsockopt(connfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == -1) goto failed;

    if (socket_set_keepalive(connfd) == -1) {
        log_error("Connection error: Error set keepalive\n");
        goto failed;
    }

    if (socket_set_nonblocking(connfd) == -1) {
        log_error("Connection error: Error make_socket_nonblocking failed\n");
        goto failed;
    }

    if (socket_set_nodelay(connfd) == -1) {
        log_error("Connection error: Error set TCP_NODELAY\n");
        goto failed;
    }

    struct sockaddr_in* remote_addr = (struct sockaddr_in*)&in_addr;
    in_addr_t remote_ip = remote_addr->sin_addr.s_addr;
    unsigned short remote_port = ntohs(remote_addr->sin_port);

    connection = connection_s_alloc(ctx->listener, connfd, ip, port, remote_ip, remote_port, buffer, buffer_size);
    if (connection == NULL) goto failed;

    connection->close = connection_close;

    result = connection;

    failed:

    if (result == NULL) {
        close(connfd);
    }

    return result;
}

connection_t* connection_s_alloc(listener_t* listener, int fd, in_addr_t ip, unsigned short int port, in_addr_t remote_ip, unsigned short int remote_port, char* buffer, size_t buffer_size) {
    connection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    connection_server_ctx_t* ctx = __ctx_create(listener);
    if (ctx == NULL) {
        free(connection);
        return NULL;
    }

    connection->fd = fd;
    connection->keepalive = 0;
    connection->ip = ip;
    connection->port = port;
    connection->remote_ip = remote_ip;
    connection->remote_port = remote_port;
    connection->ctx = ctx;
    connection->ssl = NULL;
    connection->ssl_ctx = NULL;
    connection->buffer = buffer;
    connection->buffer_size = buffer_size;
    connection->close = NULL;
    connection->read = NULL;
    connection->write = NULL;
    connection->prev = NULL;
    connection->next = NULL;

    return connection;
}

connection_t* connection_s_create_local(server_t* server) {
    connection_t* connection = connection_s_alloc(NULL, -1, inet_addr("127.0.0.1"), server->port, inet_addr("127.0.0.1"), server->port, NULL, 0);
    if (connection == NULL) return NULL;

    connection_server_ctx_t* ctx = connection->ctx;
    ctx->server = server;

    connection->close = NULL;
    connection->read = NULL;
    connection->write = NULL;

    return connection;
}

void connection_s_free_local(connection_t* connection) {
    if (connection == NULL) return;

    __ctx_free(connection->ctx);
    free(connection);
}

/* Hint to the core that it is in a spin-wait: on x86 PAUSE drains the pipeline
 * and cuts the memory-order-violation penalty on lock release, on ARM YIELD
 * hands the SMT sibling a turn. A no-op elsewhere — correctness never depends
 * on it. */
static inline void __cpu_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ __volatile__("yield" ::: "memory");
#endif
}

/* How long to spin before handing the CPU to the scheduler. The lock protects
 * short state updates, so the holder normally releases within a few hundred
 * cycles and spinning wins; anything longer means the holder was preempted (or
 * is running a handler, which is what docs/concurrency/00 is about), and then
 * burning a core is pure waste. */
#define CONNECTION_LOCK_SPINS 128

int connection_s_lock(connection_t* connection) {
    if (connection == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    _Bool expected = 0;
    if (atomic_compare_exchange_weak(&ctx->locked, &expected, 1)) {
        if (metrics_enabled())
            metrics_lock_fast();

        return 1;
    }

    /* Contended. The clock is read only on this path, and only when metrics are
     * on: on the fast path above an unconditional clock_gettime pair would cost
     * more than the lock itself (docs/concurrency/00, phase D). */
    const int counted = metrics_enabled();
    const uint64_t started_ns = counted ? metrics_now_ns() : 0;
    unsigned yields = 0;
    unsigned spins = 0;

    for (;;) {
        /* Re-test with a plain load before trying the CAS again: the CAS writes
         * to the cache line whether or not it succeeds, so a crowd of waiters
         * looping on it ping-pongs the line between cores and starves the
         * holder. Reading a shared line costs nothing by comparison. */
        while (atomic_load_explicit(&ctx->locked, memory_order_relaxed)) {
            if (++spins < CONNECTION_LOCK_SPINS) {
                __cpu_relax();
                continue;
            }

            spins = 0;
            yields++;
            sched_yield();
        }

        expected = 0;
        if (atomic_compare_exchange_weak(&ctx->locked, &expected, 1))
            break;
    }

    if (counted)
        metrics_lock_slow(metrics_now_ns() - started_ns, yields);

    return 1;
}

int connection_s_unlock(connection_t* connection) {
    if (connection == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    atomic_store(&ctx->locked, 0);

    return 1;
}

/* Non-blocking trylock for the timer sweep: a connection currently busy with a
 * handler or I/O is skipped this tick and revisited on the next one.
 *
 * Deliberately not counted in the lock metrics: it never waits, so it has no
 * wait time to report, and folding its attempts into the acquisition count
 * would skew the contention ratio with a per-tick sweep that is not contention. */
int connection_s_trylock(connection_t* connection) {
    if (connection == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    _Bool expected = 0;
    return atomic_compare_exchange_strong(&ctx->locked, &expected, 1);
}

void connection_s_inc(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    atomic_fetch_add(&ctx->ref_count, 1);
}

connection_dec_result_e connection_s_dec(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    // решение об освобождении принимается по значению, возвращённому fetch_sub:
    // отдельная проверка load после декремента позволяла двум потокам
    // одновременно увидеть ноль и дважды освободить соединение
    if (atomic_fetch_sub(&ctx->ref_count, 1) == 1) {
        connection_free(connection);
        return CONNECTION_DEC_RESULT_DESTROY;
    }

    return CONNECTION_DEC_RESULT_DECREMENT;
}

int connection_after_write(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (connection->keepalive == 0) {
        atomic_store(&ctx->destroyed, 1);
        return ctx->listener->api->control_mod(connection, MPXOUT | MPXIN | MPXHUP);
    }

    connection_reset(connection);

    if (ctx->switch_to_protocol.fn != NULL) {
        ctx->switch_to_protocol.fn(connection, ctx->switch_to_protocol.data);
        if (ctx->switch_to_protocol.data_free != NULL) {
            ctx->switch_to_protocol.data_free(ctx->switch_to_protocol.data);
        }
        ctx->switch_to_protocol.fn = NULL;
        ctx->switch_to_protocol.data = NULL;
        ctx->switch_to_protocol.data_free = NULL;
    }

    cqueue_lock(ctx->broadcast_queue);
    const int broadcast_empty = cqueue_empty(ctx->broadcast_queue);
    cqueue_unlock(ctx->broadcast_queue);

    cqueue_lock(ctx->queue);
    const int handlers_empty = cqueue_empty(ctx->queue);
    cqueue_unlock(ctx->queue);

    if (!handlers_empty || !broadcast_empty) {
        connection_queue_guard_append(connection);
        return ctx->listener->api->control_mod(connection, MPXONESHOT);
    }

    int expected = 2;
    atomic_compare_exchange_strong(&ctx->broadcast_ref_count, &expected, 1);

    // повторная проверка после сброса флага: отправитель мог добавить сообщение
    // между первой проверкой и CAS 2->1 — его собственный CAS 1->2 провалился,
    // и без этой проверки сообщение зависло бы в очереди до следующей активности
    cqueue_lock(ctx->broadcast_queue);
    const int broadcast_empty_recheck = cqueue_empty(ctx->broadcast_queue);
    cqueue_unlock(ctx->broadcast_queue);

    if (!broadcast_empty_recheck) {
        expected = 1;
        if (atomic_compare_exchange_strong(&ctx->broadcast_ref_count, &expected, 2)) {
            connection_queue_guard_append(connection);
            return ctx->listener->api->control_mod(connection, MPXONESHOT);
        }
    }

    return ctx->listener->api->control_mod(connection, MPXIN | MPXRDHUP);
}

/* Take the connection out of epoll for the duration of the queued work.
 *
 * broadcast_ref_count doubles as the parked flag: 1 = live in epoll, 2 = parked.
 * Idempotent — only the caller that wins the CAS issues the epoll_ctl, everyone
 * after it finds the connection already parked and has nothing to do. Returns 0
 * only when the epoll_ctl itself failed, and then leaves the flag as it was.
 *
 * Parking is deliberately separate from queueing (docs/concurrency/00 §5.2):
 * the fd is parked once, but the connection may be queued several times over,
 * once per pending item. */
static int __park(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    int expected = 1;
    if (!atomic_compare_exchange_strong(&ctx->broadcast_ref_count, &expected, 2))
        return 1; /* somebody else parked it already */

    if (!ctx->listener->api->control_mod(connection, MPXONESHOT)) {
        atomic_store(&ctx->broadcast_ref_count, 1);
        return 0;
    }

    return 1;
}

/* Serialized dispatch: park, and queue the connection only if it is not queued
 * already. One entry means one worker at a time, and the next item gets its turn
 * from the chain that connection_after_write / the runner drives. This is what
 * HTTP/1.1 and WebSocket want — both keep exactly one request in flight per
 * connection, and h1.1 responses have to leave in request order anyway. */
int connection_queue_append(connection_queue_item_t* item) {
    connection_server_ctx_t* ctx = item->connection->ctx;

    int expected = 1;
    if (!atomic_compare_exchange_strong(&ctx->broadcast_ref_count, &expected, 2)) {
        return 1;
    }

    if (!ctx->listener->api->control_mod(item->connection, MPXONESHOT)) {
        atomic_store(&ctx->broadcast_ref_count, 1);
        return 0;
    }

    connection_queue_guard_append_item(item);
    return 1;
}

/* Fan-out dispatch: park (once), then queue the connection for *this* item
 * regardless of whether it is queued already. N pending items become N queue
 * entries and go to N workers, which is the whole point of
 * docs/concurrency/00 §5.2 — without it, narrowing the connection lock buys
 * nothing, because a connection sitting in the queue once is only ever handed
 * to one worker at a time.
 *
 * HTTP/2 only. Handlers of one h2 connection are independent: request and
 * response live on the stream, and the write path serves whichever streams are
 * ready, in any order. */
int connection_queue_append_parallel(connection_queue_item_t* item) {
    if (!__park(item->connection))
        return 0;

    connection_queue_guard_append_item(item);
    return 1;
}

int connection_queue_append_broadcast(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (!ctx->listener->api->control_mod(connection, MPXONESHOT)) {
        atomic_store(&ctx->broadcast_ref_count, 1);
        return 0;
    }

    connection_queue_guard_append(connection);
    return 1;
}

int connection_after_read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    /* Called by handler threads, under connection_s_lock — the same lock
     * connection_close_locked holds while it detaches. Re-arming a detached
     * connection would push this pointer into some other connection's epoll
     * registration; see connection_server_ctx_t::detached. Reporting success is
     * deliberate: there is nothing left to do and nothing went wrong, and the
     * callers up the h2 stack turn a 0 into a connection error. */
    if (atomic_load(&ctx->detached))
        return 1;

    return ctx->listener->api->control_mod(connection, MPXOUT | MPXRDHUP);
}

int connection_close(connection_t* connection) {
    connection_s_lock(connection);
    return connection_close_locked(connection);
}

/* The teardown work, assuming the caller already holds connection_s_lock(). The
 * timer sweep and shutdown path take the lock themselves (via trylock/lock) and
 * must not re-enter connection_s_lock(), which is a non-recursive spinlock. */
int connection_close_locked(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (!ctx->listener->api->control_del(connection))
        log_error("Connection not removed from api\n");

    /* From here the fd number may be recycled by the next accept(), so no epoll
     * re-arm may reference this connection again. */
    atomic_store(&ctx->detached, 1);

    if (connection->ssl != NULL) {
        SSL_shutdown(connection->ssl);
        SSL_clear(connection->ssl);
    }

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    atomic_store(&ctx->destroyed, 1);
    broadcast_clear(connection);

    if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_s_unlock(connection);

    return 1;
}

connection_server_ctx_t* __ctx_create(listener_t* listener) {
    connection_server_ctx_t* ctx = malloc(sizeof * ctx);
    if (ctx == NULL) return NULL;

    ctx->base.reset = __ctx_reset;
    ctx->base.free = __ctx_free;
    atomic_store(&ctx->need_write, 0);
    ctx->is_http2 = 0;
    ctx->h2c_preface = 0;
    ctx->h2c_peeked = 0;
    atomic_store(&ctx->destroyed, 0);
    atomic_store(&ctx->detached, 0);
    atomic_store(&ctx->ref_count, 1);
    atomic_store(&ctx->broadcast_ref_count, 1);
    atomic_store(&ctx->locked, 0);
    atomic_store(&ctx->handlers_inflight, 0);
    ctx->listener = listener;
    ctx->parser = NULL;
    ctx->server = NULL;
    ctx->request = NULL;
    ctx->response = NULL;
    ctx->queue = cqueue_create();
    ctx->broadcast_queue = cqueue_create();
    ctx->write_queue = cqueue_create();
    ctx->switch_to_protocol.fn = NULL;
    ctx->switch_to_protocol.data = NULL;
    ctx->switch_to_protocol.data_free = NULL;

    if (listener != NULL) {
        cqueue_item_t* item = cqueue_first(&listener->servers);
        if (item)
            ctx->server = item->data;
    }

    if (ctx->queue == NULL || ctx->broadcast_queue == NULL || ctx->write_queue == NULL) {
        cqueue_free(ctx->queue);
        cqueue_free(ctx->broadcast_queue);
        cqueue_free(ctx->write_queue);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void __ctx_reset(void* arg) {
    connection_server_ctx_t* ctx = arg;

    atomic_store_explicit(&ctx->need_write, 0, memory_order_relaxed);

    /* When a protocol switch is pending (h2c Upgrade — see connection_after_write),
     * the switch callback adopts the request: the upgraded HTTP/1.1 request
     * becomes stream 1. Freeing it here would leave the callback a dangling
     * pointer, so it owns the request instead. (Websocket switches free it
     * themselves once their replacement parser is in place.) */
    if (ctx->switch_to_protocol.fn == NULL) {
        request_t* request = ctx->request;
        if (request != NULL) {
            request->free(request);
            ctx->request = NULL;
        }
    }

    response_t* response = ctx->response;
    if (response != NULL) {
        response->free(response);
        ctx->response = NULL;
    }
}

static void __ctx_queue_item_free_callback(void* data) {
    if (data == NULL) return;
    connection_queue_item_t* item = data;
    item->free(item);
}

/* Slots left in the output order when the connection died: some hold a response
 * nobody got to write, some were never filled because their handler was
 * discarded with the queue. Both are ours to release. */
static void __ctx_out_slot_free_callback(void* data) {
    if (data == NULL) return;

    connection_out_slot_t* slot = data;
    if (slot->response != NULL)
        slot->response->free(slot->response);

    free(slot);
}

void __ctx_free(void* arg) {
    connection_server_ctx_t* ctx = arg;

    if (ctx->parser != NULL)
        ((requestparser_t*)ctx->parser)->free(ctx->parser);

    // Освобождаем очереди с callback'ом для освобождения item'ов
    cqueue_freecb(ctx->queue, __ctx_queue_item_free_callback);
    cqueue_freecb(ctx->broadcast_queue, __ctx_queue_item_free_callback);
    cqueue_freecb(ctx->write_queue, __ctx_out_slot_free_callback);

    request_t* request = ctx->request;
    if (request != NULL) {
        request->free(request);
        ctx->request = NULL;
    }

    response_t* response = ctx->response;
    if (response != NULL) {
        response->free(response);
        ctx->response = NULL;
    }

    free(ctx);
}
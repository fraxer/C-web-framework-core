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

connection_t* connection_s_create(int fd, const ipaddr_t* ip, unsigned short int port, connection_server_ctx_t* ctx, char* buffer, size_t buffer_size) {
    connection_t* result = NULL;
    /* sockaddr_storage, not sockaddr: the latter is sixteen bytes, so an IPv6
     * peer address arrived truncated -- with the port intact and the address
     * cut in half, which is worse than not having it. */
    struct sockaddr_storage in_addr;
    socklen_t in_len = sizeof(in_addr);
    connection_t* connection = NULL;

    const int connfd = accept(fd, (struct sockaddr*)&in_addr, &in_len);
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

    ipaddr_t remote_ip;
    ipaddr_from_sockaddr(&remote_ip, (struct sockaddr*)&in_addr);

    const unsigned short remote_port =
        in_addr.ss_family == AF_INET6
        ? ntohs(((struct sockaddr_in6*)&in_addr)->sin6_port)
        : ntohs(((struct sockaddr_in*)&in_addr)->sin_port);

    connection = connection_s_alloc(ctx->listener, connfd, ip, port, &remote_ip, remote_port, buffer, buffer_size);
    if (connection == NULL) goto failed;

    connection->close = connection_close;

    result = connection;

    failed:

    if (result == NULL) {
        close(connfd);
    }

    return result;
}

int connection_s_init(connection_t* connection, listener_t* listener, int fd, const ipaddr_t* ip, unsigned short int port, const ipaddr_t* remote_ip, unsigned short int remote_port, char* buffer, size_t buffer_size) {
    if (connection == NULL) return 0;

    connection_server_ctx_t* ctx = __ctx_create(listener);
    if (ctx == NULL) return 0;

    connection->fd = fd;
    connection->keepalive = 0;
    memset(&connection->ip, 0, sizeof connection->ip);
    memset(&connection->remote_ip, 0, sizeof connection->remote_ip);
    if (ip != NULL) connection->ip = *ip;
    if (remote_ip != NULL) connection->remote_ip = *remote_ip;
    connection->port = port;
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
    connection->transport = CONN_TRANSPORT_TCP;

    return 1;
}

connection_t* connection_s_alloc(listener_t* listener, int fd, const ipaddr_t* ip, unsigned short int port, const ipaddr_t* remote_ip, unsigned short int remote_port, char* buffer, size_t buffer_size) {
    connection_t* connection = malloc(sizeof * connection);
    if (connection == NULL) return NULL;

    if (!connection_s_init(connection, listener, fd, ip, port, remote_ip,
                           remote_port, buffer, buffer_size)) {
        free(connection);
        return NULL;
    }

    return connection;
}

connection_t* connection_s_create_local(server_t* server) {
    const ipaddr_t loopback = ipaddr_from_v4(inet_addr("127.0.0.1"));
    connection_t* connection = connection_s_alloc(NULL, -1, &loopback, server->port, &loopback, server->port, NULL, 0);
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

int connection_s_lock(connection_t* connection, metrics_lock_site_t site) {
    if (connection == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;

    _Bool expected = 0;
    if (atomic_compare_exchange_weak(&ctx->locked, &expected, 1)) {
        if (metrics_enabled()) {
            atomic_store_explicit(&ctx->lock_site, site, memory_order_relaxed);
            metrics_lock_fast(site);
        }

        return 1;
    }

    /* Contended. The clock is read only on this path, and only when metrics are
     * on: on the fast path above an unconditional clock_gettime pair would cost
     * more than the lock itself (docs/concurrency/00, phase D). */
    const int counted = metrics_enabled();
    const uint64_t started_ns = counted ? metrics_now_ns() : 0;
    /* Who is in the way, sampled once at the start of the wait. Reading it again
     * later would name whoever happened to hold the lock at the end, which is not
     * the section that caused this wait. */
    const metrics_lock_site_t blocker = counted ?
        (metrics_lock_site_t)atomic_load_explicit(&ctx->lock_site, memory_order_relaxed) : LOCK_SITE_OTHER;
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

    if (counted) {
        atomic_store_explicit(&ctx->lock_site, site, memory_order_relaxed);
        metrics_lock_slow(site, blocker, metrics_now_ns() - started_ns, yields);
    }

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
    if (!atomic_compare_exchange_strong(&ctx->locked, &expected, 1))
        return 0;

    /* Not counted, but the sweep does hold the lock: without this a waiter that
     * piles up behind a tick would be charged to whichever site held it last. */
    if (metrics_enabled())
        atomic_store_explicit(&ctx->lock_site, LOCK_SITE_TICK, memory_order_relaxed);

    return 1;
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

        /* Lost the race: the producer that put the message there parked the
         * connection itself and queued its own worker. Arming for reading below
         * would undo that park and let a read event in while the connection is
         * supposed to be off the loop. */
        return 1;
    }

    return ctx->listener->api->control_mod(connection, MPXIN | MPXRDHUP);
}

/* The event set a parked connection keeps, by protocol (docs/concurrency/01,
 * phase E).
 *
 * h1.1 and WebSocket park deaf — a bare MPXONESHOT, no event bits, nothing is
 * delivered. Both keep exactly one request in flight, so reading the next one
 * before the current reply has left buys h1.1 nothing and would break the
 * WebSocket output order (`00` phase C).
 *
 * h2 parks still readable. Its handlers already run in parallel, so a request
 * that arrives in a later TCP segment has no reason to wait for the first
 * response to be written — which is exactly what it used to do, at a cost of
 * T + first-write instead of T. Two things make it safe, and neither is new:
 * the connection belongs to one worker (§2.1), so the read stays
 * single-threaded and the per-worker connection->buffer cannot be taken from
 * under it; and MPXONESHOT means the one event that is delivered disarms the
 * fd again, so the worker still decides when the next one may come (it re-arms
 * from h2_drain_and_rearm while the connection stays parked). */
static int __park_events(const connection_server_ctx_t* ctx) {
    return ctx->is_http2 ? (MPXIN | MPXRDHUP | MPXONESHOT) : MPXONESHOT;
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

    if (!ctx->listener->api->control_mod(connection, __park_events(ctx))) {
        atomic_store(&ctx->broadcast_ref_count, 1);
        return 0;
    }

    return 1;
}

/* Re-arm a connection that is still parked: the one-shot read it was parked
 * with has been spent, and more work may yet arrive before the handlers that
 * parked it are done. Only h2 asks for this — see __park_events. Returns 1 when
 * there was nothing to do, so callers can use it as a plain success. */
int connection_park_rearm(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (!ctx->is_http2) return 1;
    if (atomic_load(&ctx->broadcast_ref_count) != 2) return 1; /* not parked */

    /* Same guard as connection_after_read: never epoll_ctl a connection whose
     * fd is already closed and whose number may belong to somebody else. */
    if (atomic_load(&ctx->detached)) return 1;

    return ctx->listener->api->control_mod(connection, __park_events(ctx));
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
    connection_s_lock(connection, LOCK_SITE_CLOSE);
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
    /* malloc, not calloc: every field here is set explicitly, and these two are
     * read on the response path of every request — a garbage `cont_pending`
     * makes the write filter emit an interim status line nobody asked for
     * (docs/http2/10, T.2). */
    ctx->cont_pending = 0;
    ctx->cont_sent = 0;
    atomic_store(&ctx->destroyed, 0);
    atomic_store(&ctx->detached, 0);
    atomic_store(&ctx->ref_count, 1);
    atomic_store(&ctx->broadcast_ref_count, 1);
    atomic_store(&ctx->locked, 0);
    atomic_store(&ctx->lock_site, LOCK_SITE_OTHER);
    atomic_store(&ctx->handlers_inflight, 0);
    ctx->listener = listener;
    ctx->parser = NULL;
    ctx->server = NULL;
    ctx->request = NULL;
    ctx->response = NULL;
    ctx->response_cache = NULL;
    ctx->response_retire = NULL;
    ctx->queue = cqueue_create();
    ctx->broadcast_queue = cqueue_create();
    ctx->write_queue = cqueue_create();
    ctx->switch_to_protocol.fn = NULL;
    ctx->switch_to_protocol.data = NULL;
    ctx->switch_to_protocol.data_free = NULL;
    ctx->transport_data = NULL;
    ctx->transport_free = NULL;

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

    /* Owed to the request that is ending, not to the next one on the connection
     * (docs/http2/10, T.2). */
    ctx->cont_pending = 0;
    ctx->cont_sent = 0;

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
    else {
        /* The connection is becoming something else -- WebSocket, or HTTP/2 over
         * an h2c upgrade -- and the response that will sit here next belongs to
         * that protocol. Whoever installed the recycling hook spoke for HTTP/1.1
         * only, so it stops applying here, at the one moment the switch is
         * still ahead of us. */
        ctx->response_retire = NULL;

        /* And whatever HTTP/1.1 already parked there will never be asked for
         * again: nothing on the new protocol reads this. Freeing it now rather
         * than at teardown keeps a long-lived WebSocket connection from holding
         * an idle response object for its whole life. */
        response_t* cached = ctx->response_cache;
        if (cached != NULL) {
            cached->free(cached);
            ctx->response_cache = NULL;
        }
    }

    response_t* response = ctx->response;
    if (response != NULL) {
        ctx->response = NULL;

        if (ctx->response_retire != NULL)
            ctx->response_retire(ctx, response);
        else
            response->free(response);
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

    response_t* cached = ctx->response_cache;
    if (cached != NULL) {
        cached->free(cached);
        ctx->response_cache = NULL;
    }

    /* Last, so the transport's teardown can still reach anything above. It
     * releases the transport's own state only -- connection_free frees the
     * object itself. */
    if (ctx->transport_free != NULL) {
        ctx->transport_free(ctx->transport_data);
        ctx->transport_free = NULL;
        ctx->transport_data = NULL;
    }

    free(ctx);
}
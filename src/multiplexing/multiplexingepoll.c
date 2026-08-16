#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/timerfd.h>

#include "log.h"
#include "connection_s.h"
#include "multiplexingepoll.h"

#ifdef CWFR_HTTP3
#include "quicconn.h"
#endif

#define EPOLL_MAX_EVENTS 16

/* Worker timer tick: the idle/PING sweep runs this often. Coarse on purpose —
 * ±TICK_MS precision is fine for timeouts measured in seconds. */
#define MPX_TIMER_TICK_MS 500

int __mpx_epoll_init();
epoll_config_t* __mpx_epoll_config_init(int);
void __mpx_epoll_free(void*);
int __mpx_epoll_control_add(connection_t*, int);
int __mpx_epoll_control_mod(connection_t*, int);
int __mpx_epoll_control_del(connection_t*);
void __mpx_epoll_process_events(appconfig_t* appconfig, void* arg);
int __mpx_epoll_control(connection_t*, int, uint32_t);
void __mpx_epoll_config_free(epoll_config_t*);

static int __mpx_timer_create(mpxapi_epoll_t* api);
static void __mpx_conns_add(mpxapi_t* api, connection_t* connection);
static void __mpx_conns_remove(mpxapi_t* api, connection_t* connection);

void* mpx_epoll_init() {
    mpxapi_epoll_t* api = malloc(sizeof * api);
    if (api == NULL) {
        log_error("Epoll error: Epoll api alloc failed\n");
        return NULL;
    }

    const int fd = __mpx_epoll_init();
    if (fd == -1) {
        free(api);
        return NULL;
    }

    api->base.connection_count = 0;
    api->base.conns = NULL;
    api->base.config = __mpx_epoll_config_init(fd);
    api->base.free = __mpx_epoll_free;
    api->base.control_add = __mpx_epoll_control_add;
    api->base.control_del = __mpx_epoll_control_del;
    api->base.control_mod = __mpx_epoll_control_mod;
    api->base.process_events = __mpx_epoll_process_events;
    api->base.on_tick = NULL;
    api->fd = fd;
    api->timerfd = -1;

    if (api->base.config == NULL) {
        api->base.free(api);
        return NULL;
    }

    /* Failure to arm the timer is non-fatal: the worker simply has no idle/PING
     * sweep. Everything else (event dispatch, connection lifecycle) still works. */
    (void)__mpx_timer_create(api);

    return api;
}

int __mpx_epoll_init() {
    const int basefd = epoll_create1(0);
    if (basefd == -1) {
        log_error("Epoll error: Epoll create1 failed\n");
        return -1;
    }

    return basefd;
}

/* Create and arm the worker tick timer, then register it in this worker's epoll.
 * Registered with ev.data.ptr = &api->timer_tag, a unique address the dispatcher
 * compares against to tell a timer event from a connection event (whose ptr is
 * a heap connection_t). */
static int __mpx_timer_create(mpxapi_epoll_t* api) {
    api->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (api->timerfd == -1) {
        log_error("Epoll error: timerfd_create failed (errno %d)\n", errno);
        return 0;
    }

    const long ns = (long)MPX_TIMER_TICK_MS * 1000000L;
    const struct itimerspec its = {
        .it_interval = { .tv_sec = 0, .tv_nsec = ns },
        .it_value    = { .tv_sec = 0, .tv_nsec = ns },
    };
    if (timerfd_settime(api->timerfd, 0, &its, NULL) == -1) {
        log_error("Epoll error: timerfd_settime failed (errno %d)\n", errno);
        close(api->timerfd);
        api->timerfd = -1;
        return 0;
    }

    struct epoll_event ev = {
        .data = { .ptr = &api->timer_tag },
        .events = EPOLLIN,
    };

    if (epoll_ctl(api->fd, EPOLL_CTL_ADD, api->timerfd, &ev) == -1) {
        log_error("Epoll error: timer epoll_ctl failed (errno %d)\n", errno);
        close(api->timerfd);
        api->timerfd = -1;
        return 0;
    }

    return 1;
}

epoll_config_t* __mpx_epoll_config_init(int basefd) {
    epoll_config_t* iconfig = malloc(sizeof * iconfig);
    if (iconfig == NULL) return NULL;

    iconfig->basefd = basefd;
    iconfig->timeout = 1000;

    return iconfig;
}

void __mpx_epoll_free(void* arg) {
    mpxapi_epoll_t* api = arg;
    if (api == NULL) return;

    if (api->timerfd != -1)
        close(api->timerfd);

    if (api->fd != -1)
        close(api->fd);

    __mpx_epoll_config_free(api->base.config);

    free(api);
}

/* A QUIC connection has no registration of its own: it shares the endpoint's
 * one socket, and readiness for it is not something epoll can report. The
 * count still applies -- it is what keeps a draining worker alive until the
 * last connection is gone -- but the worker's connection *list* does not
 * (docs/http3/01-udp-endpoint.md §3).
 *
 * The list is deliberate, not an oversight. It has exactly one reader, the
 * worker tick, and that reader skips every QUIC connection: they are aged
 * through their endpoint's own list instead, because the send queue that has
 * to be drained with them belongs to the endpoint. So membership bought a QUIC
 * connection nothing -- and cost something, because `api->conns` is unlocked
 * on the premise that only the owning worker touches it, while a QUIC
 * connection can be closed by whichever worker the kernel handed its last
 * datagram to (docs/http3/09-options.md §2.6). Rehoming makes that no longer
 * rare, so the premise is restored here rather than defended with a lock the
 * TCP path would pay for. */
#ifdef CWFR_HTTP3
#define QUIC_CONNECTION(c) ((c)->transport == CONN_TRANSPORT_QUIC)
#else
#define QUIC_CONNECTION(c) (0)
#endif

int __mpx_epoll_control_add(connection_t* connection, int events) {
    const int result = QUIC_CONNECTION(connection)
        ? 1
        : __mpx_epoll_control(connection, EPOLL_CTL_ADD, events);

    connection_server_ctx_t* ctx = connection->ctx;
    if (result) {
        ctx->listener->api->connection_count++;
        if (!QUIC_CONNECTION(connection))
            __mpx_conns_add(ctx->listener->api, connection);
    }

    return result;
}

int __mpx_epoll_control_mod(connection_t* connection, int events) {
#ifdef CWFR_HTTP3
    if (QUIC_CONNECTION(connection)) {
        /* "This connection has something to send" -- the closest thing QUIC has
         * to arming EPOLLOUT. Anything else (a read re-arm, a park) is
         * meaningless here: the endpoint reads the socket unconditionally. */
        if (events & MPXOUT) quicconn_want_write(connection);
        return 1;
    }
#endif

    return __mpx_epoll_control(connection, EPOLL_CTL_MOD, events);
}

int __mpx_epoll_control_del(connection_t* connection) {
    const int result = QUIC_CONNECTION(connection)
        ? 1
        : __mpx_epoll_control(connection, EPOLL_CTL_DEL, 0);

    connection_server_ctx_t* ctx = connection->ctx;
    if (result) {
        ctx->listener->api->connection_count--;
        if (!QUIC_CONNECTION(connection))
            __mpx_conns_remove(ctx->listener->api, connection);
    }

    return result;
}

void __mpx_epoll_process_events(appconfig_t* appconfig, void* arg) {
    mpxapi_epoll_t* epi = arg;
    mpxapi_t* api = &epi->base;
    epoll_config_t* apiconfig = api->config;
    epoll_event_t events[EPOLL_MAX_EVENTS];
    const int config_shutdown = atomic_load(&appconfig->shutdown) && appconfig->env.main.reload == APPCONFIG_RELOAD_HARD;

    int n = epoll_wait(apiconfig->basefd, events, EPOLL_MAX_EVENTS, apiconfig->timeout);
    if (n == -1) {
        if (errno != EINTR)
            log_error("Epoll error: epoll_wait failed (errno %d)\n", errno);
        return;
    }

    /* Pin every connection in the batch before touching any of them.
     *
     * Handling one event can close a *different* connection in the same batch:
     * the timer sweep (__mpx_on_tick) walks the whole worker list and closes on
     * idle timeout, PING timeout or shutdown. Closing drops the base reference,
     * and if a handler thread finishing on another core then drops the last one,
     * the connection is freed while its event is still sitting in this array —
     * every later `ev->data.ptr` for it is dangling.
     *
     * This could not happen while handlers were serialized: a connection with
     * queued work was parked out of epoll (MPXONESHOT), so it had no event to be
     * in a batch with. Concurrent handlers re-arm it while other handlers are
     * still running, which is what opens the window. docs/concurrency/00 §4.6.
     *
     * Doing it up front is safe: the base reference is dropped only by a close,
     * and every close runs on this thread, so nothing in the array can be stale
     * before the loop starts. */
    for (int i = 0; i < n; i++) {
        if (events[i].data.ptr != &epi->timer_tag)
            connection_s_inc(events[i].data.ptr);
    }

    for (int i = 0; i < n; i++) {
        epoll_event_t* ev = &events[i];

        /* The worker timer: data.ptr is the sentinel &timer_tag, not a
         * connection. Drain the level-triggered fd (8-byte expiry count) and run
         * the sweep, then move on — it carries no connection state. */
        if (ev->data.ptr == &epi->timer_tag) {
            uint64_t expirations;
            while (read(epi->timerfd, &expirations, sizeof expirations) == sizeof expirations) {
                /* drain — level-triggered, must read or it refires forever */
            }

            if (api->on_tick != NULL)
                api->on_tick(api);

            continue;
        }

        connection_t* connection = ev->data.ptr;
        connection_server_ctx_t* ctx = connection->ctx;

        if (atomic_load(&ctx->destroyed) || (ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) || config_shutdown)
            goto close;

        if (ev->events & EPOLLIN)
            if (!connection->read(connection))
                goto close;

        /* Acquire: a handler thread set need_write after filling the response,
         * and everything it wrote must be visible here before write() reads it. */
        if ((ev->events & EPOLLOUT || atomic_load_explicit(&ctx->need_write, memory_order_acquire))
            && connection->write != NULL)
            if (!connection->write(connection))
                goto close;

        goto next;

        close:

        connection->close(connection);

        next:

        /* Drop the batch pin. This may well be the last reference — the
         * connection was closed just above, or by the sweep earlier in this
         * batch — in which case the free happens here rather than inside
         * close(), which is exactly the point: nothing reads the pointer after
         * this line. */
        connection_s_dec(connection);
    }
}

int __mpx_epoll_control(connection_t* connection, int action, uint32_t flags) {
    connection_server_ctx_t* ctx = connection->ctx;
    mpxapi_epoll_t* api = (mpxapi_epoll_t*)ctx->listener->api;
    epoll_event_t event = {
        .data = {
            .ptr = connection
        },
        .events = flags
    };
    epoll_event_t* pevent = &event;

    if (action == EPOLL_CTL_DEL) pevent = NULL;

    if (epoll_ctl(api->fd, action, connection->fd, pevent) == -1) {
        log_error("Epoll error: Epoll_ctl failed %d %d\n", connection->fd, action);
        return 0;
    }

    return 1;
}

void __mpx_epoll_config_free(epoll_config_t* config) {
    if (config == NULL) return;

    free(config);
}

/* O(1) head insertion. Called only from the worker thread that owns this epoll
 * (on control_add), so no synchronization is needed. A connection may be added
 * once; control_del always pairs with it. */
static void __mpx_conns_add(mpxapi_t* api, connection_t* connection) {
    connection->prev = NULL;
    connection->next = api->conns;
    if (api->conns != NULL)
        api->conns->prev = connection;
    api->conns = connection;
}

/* Unlink, leaving prev/next NULL so a stale reference is harmless. Called from
 * the worker thread (on control_del). */
static void __mpx_conns_remove(mpxapi_t* api, connection_t* connection) {
    if (connection->prev != NULL)
        connection->prev->next = connection->next;
    else
        api->conns = connection->next;

    if (connection->next != NULL)
        connection->next->prev = connection->prev;

    connection->prev = NULL;
    connection->next = NULL;
}


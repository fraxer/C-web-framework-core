/* Regression: a timer can close a connection whose readiness event is later
 * in the same epoll batch. The batch pin must be released without closing the
 * connection a second time (which would consume that pin and then use it). */
#include "framework.h"
#include "connection_s.h"
#include "multiplexingepoll.h"

#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

static int batch_close_calls;
static int batch_io_calls;
static int batch_tick_calls;

static int batch_close(connection_t* connection) {
    batch_close_calls++;
    return connection_close(connection);
}

static int batch_io(connection_t* connection) {
    (void)connection;
    batch_io_calls++;
    return 1;
}

static void batch_freed(void* data) {
    (*(int*)data)++;
}

static void batch_tick(mpxapi_t* api) {
    batch_tick_calls++;
    TEST_ASSERT_EQUAL(0, batch_io_calls, "timer precedes connection readiness");
    if (api->conns != NULL)
        api->conns->close(api->conns);
}

TEST(test_epoll_timer_closes_connection_in_same_batch) {
    TEST_CASE("timer-closed connection skips later readiness without a second close");

    mpxapi_epoll_t* epi = mpx_epoll_init();
    TEST_REQUIRE_NOT_NULL(epi, "epoll initialized");
    listener_t listener = { .api = &epi->base };
    appconfig_t config = {0};
    connection_t* connection = NULL;
    int sockets[2] = {-1, -1};
    int freed = 0;
    int registered = 0;
    batch_close_calls = batch_io_calls = batch_tick_calls = 0;

    /* Replace the periodic timer with an eventfd carrying the same uint64_t
     * payload, so the test queues the tick before readiness without sleeps.
     * epoll returns ready descriptors in their ready-list order. */
    TEST_REQUIRE_GOTO(epoll_ctl(epi->fd, EPOLL_CTL_DEL, epi->timerfd, NULL) == 0,
                      "remove periodic timer", cleanup);
    close(epi->timerfd);
    epi->timerfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    TEST_REQUIRE_GOTO(epi->timerfd != -1, "controlled tick fd", cleanup);
    struct epoll_event tick = { .events = EPOLLIN, .data.ptr = &epi->timer_tag };
    TEST_REQUIRE_GOTO(epoll_ctl(epi->fd, EPOLL_CTL_ADD, epi->timerfd, &tick) == 0,
                      "register controlled tick", cleanup);
    epi->base.on_tick = batch_tick;

    TEST_REQUIRE_GOTO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0,
                      "socketpair", cleanup);
    connection = connection_s_alloc(&listener, sockets[0], NULL, 0, NULL, 0, NULL, 0);
    TEST_REQUIRE_NOT_NULL_GOTO(connection, "connection allocated", cleanup);
    connection->close = batch_close;
    connection->read = batch_io;
    connection->write = batch_io;
    connection_server_ctx_t* ctx = connection->ctx;
    ctx->transport_data = &freed;
    ctx->transport_free = batch_freed;
    TEST_REQUIRE_GOTO(epi->base.control_add(connection, MPXIN | MPXRDHUP),
                      "register connection", cleanup);
    registered = 1;

    const uint64_t expiration = 1;
    TEST_REQUIRE_GOTO(write(epi->timerfd, &expiration, sizeof expiration) == sizeof expiration,
                      "queue tick first", cleanup);
    TEST_REQUIRE_GOTO(write(sockets[1], "x", 1) == 1, "queue readiness second", cleanup);
    epi->base.process_events(&config, epi);

    TEST_ASSERT_EQUAL(1, batch_tick_calls, "tick processed");
    TEST_ASSERT_EQUAL(1, batch_close_calls, "connection closed once");
    TEST_ASSERT_EQUAL(0, batch_io_calls, "no I/O after timer closed connection");
    TEST_ASSERT_EQUAL(1, freed, "last batch reference freed the connection");
    TEST_ASSERT_EQUAL(0, atomic_load(&epi->base.connection_count), "registration removed once");
    TEST_ASSERT_NULL(epi->base.conns, "worker list is empty");

    cleanup:
    if (connection != NULL && !freed) {
        if (registered)
            connection->close(connection);
        else
            connection_s_dec(connection);
    }
    if (sockets[0] != -1 && !registered) close(sockets[0]);
    if (sockets[1] != -1) close(sockets[1]);
    epi->base.free(epi);
}

TEST(test_epoll_closes_non_keepalive_connection_after_write) {
    TEST_CASE("destroyed requests closure until the descriptor is detached");

    mpxapi_epoll_t* epi = mpx_epoll_init();
    TEST_REQUIRE_NOT_NULL(epi, "epoll initialized");
    listener_t listener = { .api = &epi->base };
    appconfig_t config = {0};
    connection_t* connection = NULL;
    int sockets[2] = {-1, -1};
    int freed = 0;
    int registered = 0;
    batch_close_calls = batch_io_calls = 0;

    TEST_REQUIRE_GOTO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0,
                      "socketpair", cleanup);
    connection = connection_s_alloc(&listener, sockets[0], NULL, 0, NULL, 0, NULL, 0);
    TEST_REQUIRE_NOT_NULL_GOTO(connection, "connection allocated", cleanup);
    connection->close = batch_close;
    connection->read = batch_io;
    connection->write = batch_io;
    connection_server_ctx_t* ctx = connection->ctx;
    ctx->transport_data = &freed;
    ctx->transport_free = batch_freed;
    TEST_REQUIRE_GOTO(epi->base.control_add(connection, MPXIN | MPXRDHUP),
                      "register connection", cleanup);
    registered = 1;

    connection->keepalive = 0;
    connection_s_lock(connection, LOCK_SITE_OTHER);
    const int armed = connection_after_write(connection);
    connection_s_unlock(connection);
    TEST_REQUIRE_GOTO(armed, "non-keepalive response arms teardown", cleanup);
    TEST_ASSERT(atomic_load(&ctx->destroyed), "closure requested");
    TEST_ASSERT(!atomic_load(&ctx->detached), "socket still needs closing");

    epi->base.process_events(&config, epi);

    TEST_ASSERT_EQUAL(1, batch_close_calls, "pending closure closes the socket");
    TEST_ASSERT_EQUAL(0, batch_io_calls, "no I/O once closure is requested");
    TEST_ASSERT_EQUAL(1, freed, "base and batch references released");
    TEST_ASSERT_EQUAL(0, atomic_load(&epi->base.connection_count), "registration removed");
    TEST_ASSERT_NULL(epi->base.conns, "worker list is empty");

    cleanup:
    if (connection != NULL && !freed) {
        if (registered)
            connection->close(connection);
        else
            connection_s_dec(connection);
    }
    if (sockets[0] != -1 && !registered) close(sockets[0]);
    if (sockets[1] != -1) close(sockets[1]);
    epi->base.free(epi);
}

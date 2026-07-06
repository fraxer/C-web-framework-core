/*
 * Unit tests for src/connection: connection.c (generic dispatch and plain
 * socket I/O), connection_c.c (client connection + ctx lifecycle),
 * connection_s.c (server connection: refcount, lock, after_read/after_write
 * event transitions, queue/broadcast requeue protocol, close) and
 * connection_queue.c (global worker queue).
 *
 * The epoll api is replaced by stub control_mod/control_del so the state
 * machines can run without an event loop; I/O paths run over a real AF_UNIX
 * socketpair (ssl == NULL routes connection_data_{read,write} to recv/send).
 *
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - connection_s_alloc and connection_c_create left the close/read/write
 *     function pointers uninitialized (malloc garbage): any dispatch before
 *     the protocol was attached jumped to a random address.
 *   - __ctx_create leaked the already-created broadcast_queue when the
 *     allocation of ctx->queue failed (separate cleanup branches).
 *   - __connection_queue_append / connection_queue_guard_append incremented
 *     the connection refcount before cqueue_append and ignored its result:
 *     a failed append left ref_count permanently inflated, so the
 *     connection was never freed.
 *   - broadcast_clear (called unconditionally from connection_close)
 *     ignored the __broadcast_lock(NULL) failure and dereferenced a NULL
 *     broadcast: closing a connection whose server had no broadcast (or no
 *     server at all) crashed.
 */

#include "framework.h"
#include "connection_s.h"
#include "connection_c.h"
#include "connection_queue.h"
#include "cqueue.h"
#include "multiplexing.h"
#include "server.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/* Epoll api stub                                                             */
/* -------------------------------------------------------------------------- */

static int stub_control_mod_result = 1;
static int stub_control_mod_calls = 0;
static int stub_control_mod_last_events = 0;
static int stub_control_del_result = 1;
static int stub_control_del_calls = 0;

static int stub_control_mod(connection_t* connection, int events) {
    (void)connection;
    stub_control_mod_calls++;
    stub_control_mod_last_events = events;
    return stub_control_mod_result;
}

static int stub_control_del(connection_t* connection) {
    (void)connection;
    stub_control_del_calls++;
    return stub_control_del_result;
}

static void stub_api_reset(void) {
    stub_control_mod_result = 1;
    stub_control_mod_calls = 0;
    stub_control_mod_last_events = 0;
    stub_control_del_result = 1;
    stub_control_del_calls = 0;
}

/* -------------------------------------------------------------------------- */
/* request/response stubs (layout of protocols/request.h: {reset, free})     */
/* -------------------------------------------------------------------------- */

static int stub_request_reset_calls = 0;
static int stub_request_free_calls = 0;
static int stub_response_reset_calls = 0;
static int stub_response_free_calls = 0;

static void stub_request_reset(void* arg) { (void)arg; stub_request_reset_calls++; }
static void stub_request_free(void* arg) { (void)arg; stub_request_free_calls++; }
static void stub_response_reset(void* arg) { (void)arg; stub_response_reset_calls++; }
static void stub_response_free(void* arg) { (void)arg; stub_response_free_calls++; }

static request_t stub_request = { stub_request_reset, stub_request_free };
static response_t stub_response = { stub_response_reset, stub_response_free };

static void stub_reqresp_reset(void) {
    stub_request_reset_calls = 0;
    stub_request_free_calls = 0;
    stub_response_reset_calls = 0;
    stub_response_free_calls = 0;
}

/* -------------------------------------------------------------------------- */
/* Server-side harness: listener + api stub + real connection_s_alloc ctx     */
/* -------------------------------------------------------------------------- */

typedef struct {
    connection_t* conn;
    server_t server;
    listener_t listener;
    mpxapi_t api;

    int conn_fd;  /* conn->fd side of the socketpair (-1 if none) */
    int peer_fd;  /* the other end, driven by the test (-1 if none) */
} conn_harness_t;

static void safe_close(int* fd) {
    if (fd != NULL && *fd != -1) {
        close(*fd);
        *fd = -1;
    }
}

/* with_socket == 0 builds a connection with fd -1 (state-machine tests that
 * never touch the socket); with_socket == 1 wires a real non-blocking
 * AF_UNIX socketpair. */
static int conn_harness_init(conn_harness_t* h, int with_socket) {
    memset(h, 0, sizeof *h);
    h->conn_fd = -1;
    h->peer_fd = -1;

    if (!connection_queue_init())
        return 0;

    stub_api_reset();
    stub_reqresp_reset();

    if (with_socket) {
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
            return 0;

        fcntl(fds[0], F_SETFL, O_NONBLOCK);
        fcntl(fds[1], F_SETFL, O_NONBLOCK);

        h->conn_fd = fds[0];
        h->peer_fd = fds[1];
    }

    h->api.control_mod = stub_control_mod;
    h->api.control_del = stub_control_del;
    h->listener.api = &h->api;
    cqueue_init(&h->listener.servers);

    if (!cqueue_append(&h->listener.servers, &h->server)) {
        safe_close(&h->conn_fd);
        safe_close(&h->peer_fd);
        return 0;
    }

    h->conn = connection_s_alloc(&h->listener, h->conn_fd, 0, 80, 0, 0, NULL, 0);
    if (h->conn == NULL) {
        cqueue_clear(&h->listener.servers);
        safe_close(&h->conn_fd);
        safe_close(&h->peer_fd);
        return 0;
    }

    return 1;
}

/* Releases everything the tests may have left behind. The connection itself
 * is dropped through connection_s_dec so a test that transferred references
 * (queue append/pop) stays balanced by doing its own dec/unlock. */
static void conn_harness_free(conn_harness_t* h) {
    if (h->conn != NULL) {
        connection_s_dec(h->conn);
        h->conn = NULL;
    }

    cqueue_clear(&h->listener.servers);
    safe_close(&h->conn_fd);
    safe_close(&h->peer_fd);
}

/* Emulates a worker completing the queued job: pops the connection from the
 * global queue, releases the pop-side lock and the queue's reference.
 * Returns the popped connection (or NULL). */
static connection_t* conn_harness_drain_worker_queue(void) {
    connection_t* popped = connection_queue_guard_pop();
    if (popped == NULL) return NULL;

    connection_s_unlock(popped);
    connection_s_dec(popped);
    return popped;
}

/* -------------------------------------------------------------------------- */
/* connection.c: generic dispatch                                             */
/* -------------------------------------------------------------------------- */

TEST(test_connection_null_args) {
    TEST_CASE("connection_reset/connection_free tolerate NULL");

    connection_reset(NULL);
    connection_free(NULL);

    TEST_ASSERT(1, "NULL connection should be a no-op");
}

static int generic_ctx_reset_calls = 0;
static int generic_ctx_free_calls = 0;

static void generic_ctx_reset(void* arg) { (void)arg; generic_ctx_reset_calls++; }
static void generic_ctx_free(void* arg) { (void)arg; generic_ctx_free_calls++; }

TEST(test_connection_reset_and_free_dispatch) {
    TEST_CASE("connection_reset/connection_free dispatch to ctx callbacks");

    generic_ctx_reset_calls = 0;
    generic_ctx_free_calls = 0;

    connection_ctx_t ctx = { generic_ctx_free, generic_ctx_reset };

    connection_t* connection = calloc(1, sizeof(connection_t));
    TEST_REQUIRE_NOT_NULL(connection, "connection allocation");

    connection->ctx = &ctx;

    connection_reset(connection);
    TEST_ASSERT_EQUAL(1, generic_ctx_reset_calls, "ctx->reset called once");
    TEST_ASSERT_EQUAL(0, generic_ctx_free_calls, "ctx->free not called on reset");

    connection_free(connection); /* frees connection, ctx is stack-owned */
    TEST_ASSERT_EQUAL(1, generic_ctx_free_calls, "ctx->free called once");
    TEST_ASSERT_EQUAL(1, generic_ctx_reset_calls, "ctx->reset not called on free");
}

TEST(test_connection_data_write_read_roundtrip) {
    TEST_CASE("connection_data_write/connection_data_read over a socketpair");

    int fds[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    fcntl(fds[1], F_SETFL, O_NONBLOCK);

    char buffer[64] = {0};
    connection_t writer = {0};
    writer.fd = fds[0];

    connection_t reader = {0};
    reader.fd = fds[1];
    reader.buffer = buffer;
    reader.buffer_size = sizeof(buffer);

    const char payload[] = "connection payload";
    const ssize_t written = connection_data_write(&writer, payload, sizeof(payload));
    TEST_ASSERT_EQUAL(sizeof(payload), written, "write returns full payload size");

    const ssize_t readed = connection_data_read(&reader);
    TEST_ASSERT_EQUAL(sizeof(payload), readed, "read returns full payload size");
    TEST_ASSERT(memcmp(buffer, payload, sizeof(payload)) == 0, "payload round-trips intact");

    close(fds[0]);
    close(fds[1]);
}

TEST(test_connection_data_read_eof_and_eagain) {
    TEST_CASE("connection_data_read: EAGAIN on empty socket, 0 on peer close");

    int fds[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

    fcntl(fds[0], F_SETFL, O_NONBLOCK);

    char buffer[16];
    connection_t reader = {0};
    reader.fd = fds[0];
    reader.buffer = buffer;
    reader.buffer_size = sizeof(buffer);

    errno = 0;
    ssize_t r = connection_data_read(&reader);
    TEST_ASSERT_EQUAL(-1, r, "empty non-blocking socket returns -1");
    TEST_ASSERT(errno == EAGAIN || errno == EWOULDBLOCK, "errno is EAGAIN/EWOULDBLOCK");

    close(fds[1]);
    r = connection_data_read(&reader);
    TEST_ASSERT_EQUAL(0, r, "closed peer returns 0 (EOF)");

    close(fds[0]);
}

TEST(test_connection_data_write_closed_peer) {
    TEST_CASE("connection_data_write to a closed peer fails without SIGPIPE");

    int fds[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

    close(fds[1]);

    connection_t writer = {0};
    writer.fd = fds[0];

    /* MSG_NOSIGNAL: without it this send would raise SIGPIPE and kill the
     * runner instead of returning -1/EPIPE. */
    errno = 0;
    const ssize_t written = connection_data_write(&writer, "x", 1);
    TEST_ASSERT_EQUAL(-1, written, "send to closed peer returns -1");
    TEST_ASSERT_EQUAL(EPIPE, errno, "errno is EPIPE");

    close(fds[0]);
}

/* -------------------------------------------------------------------------- */
/* connection_c.c: client connection                                          */
/* -------------------------------------------------------------------------- */

TEST(test_connection_c_create_initializes_fields) {
    TEST_CASE("connection_c_create initializes every field");

    connection_t* conn = connection_c_create(7, 0x0100007f, 8080);
    TEST_REQUIRE_NOT_NULL(conn, "client connection created");

    TEST_ASSERT_EQUAL(7, conn->fd, "fd stored");
    TEST_ASSERT_EQUAL_UINT(0x0100007f, conn->ip, "ip stored");
    TEST_ASSERT_EQUAL(8080, conn->port, "port stored");
    TEST_ASSERT_EQUAL(0, conn->keepalive, "keepalive off by default");
    TEST_ASSERT_EQUAL_UINT(0, conn->remote_ip, "remote_ip zeroed");
    TEST_ASSERT_EQUAL(0, conn->remote_port, "remote_port zeroed");
    TEST_ASSERT_NULL(conn->ssl, "ssl NULL");
    TEST_ASSERT_NULL(conn->ssl_ctx, "ssl_ctx NULL");
    TEST_ASSERT_NULL(conn->buffer, "buffer NULL");
    TEST_ASSERT_EQUAL_SIZE(0, conn->buffer_size, "buffer_size 0");
    TEST_ASSERT_NOT_NULL(conn->ctx, "ctx created");

    /* REGRESSION: the vtable was left as malloc garbage — dispatching
     * before set_client_http/set_client_tls jumped to a random address. */
    TEST_ASSERT(conn->close == NULL, "close NULL until protocol attach");
    TEST_ASSERT(conn->read == NULL, "read NULL until protocol attach");
    TEST_ASSERT(conn->write == NULL, "write NULL until protocol attach");

    connection_client_ctx_t* ctx = conn->ctx;
    TEST_ASSERT_NULL(ctx->request, "ctx->request NULL");
    TEST_ASSERT_NULL(ctx->response, "ctx->response NULL");

    connection_free(conn);
}

TEST(test_connection_c_reset_dispatches_to_request_response) {
    TEST_CASE("client ctx reset calls request->reset/response->reset");

    connection_t* conn = connection_c_create(-1, 0, 0);
    TEST_REQUIRE_NOT_NULL(conn, "client connection created");

    stub_reqresp_reset();

    connection_client_ctx_t* ctx = conn->ctx;
    ctx->request = &stub_request;
    ctx->response = &stub_response;

    connection_reset(conn);
    TEST_ASSERT_EQUAL(1, stub_request_reset_calls, "request->reset called once");
    TEST_ASSERT_EQUAL(1, stub_response_reset_calls, "response->reset called once");
    TEST_ASSERT_EQUAL(0, stub_request_free_calls, "request->free not called on reset");
    TEST_ASSERT_EQUAL(0, stub_response_free_calls, "response->free not called on reset");

    /* Reset must be repeatable: a keepalive connection resets between
     * requests, gzip_free inside must stay idempotent. */
    connection_reset(conn);
    TEST_ASSERT_EQUAL(2, stub_request_reset_calls, "second reset dispatches again");

    connection_free(conn);
    TEST_ASSERT_EQUAL(1, stub_request_free_calls, "request->free called once on free");
    TEST_ASSERT_EQUAL(1, stub_response_free_calls, "response->free called once on free");
}

TEST(test_connection_c_reset_free_tolerate_null_request) {
    TEST_CASE("client ctx reset/free with NULL request/response");

    connection_t* conn = connection_c_create(-1, 0, 0);
    TEST_REQUIRE_NOT_NULL(conn, "client connection created");

    connection_reset(conn);
    connection_free(conn);

    TEST_ASSERT(1, "NULL request/response handled");
}

/* -------------------------------------------------------------------------- */
/* connection_s.c: alloc / local / lock / refcount                            */
/* -------------------------------------------------------------------------- */

TEST(test_connection_s_alloc_initializes_fields) {
    TEST_CASE("connection_s_alloc initializes fields and server ctx");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    connection_t* conn = h.conn;
    TEST_ASSERT_EQUAL(-1, conn->fd, "fd stored");
    TEST_ASSERT_EQUAL(80, conn->port, "port stored");
    TEST_ASSERT_EQUAL(0, conn->keepalive, "keepalive off by default");
    TEST_ASSERT_NULL(conn->ssl, "ssl NULL");
    TEST_ASSERT_NULL(conn->buffer, "buffer as passed (NULL)");

    /* REGRESSION: the vtable was left as malloc garbage until
     * __set_protocol ran. */
    TEST_ASSERT(conn->close == NULL, "close NULL after alloc");
    TEST_ASSERT(conn->read == NULL, "read NULL after alloc");
    TEST_ASSERT(conn->write == NULL, "write NULL after alloc");

    connection_server_ctx_t* ctx = conn->ctx;
    TEST_REQUIRE_NOT_NULL(ctx, "server ctx created");
    TEST_ASSERT(ctx->listener == &h.listener, "listener stored");
    TEST_ASSERT(ctx->server == &h.server, "server taken from listener's first server");
    TEST_ASSERT_NOT_NULL(ctx->queue, "per-connection queue created");
    TEST_ASSERT_NOT_NULL(ctx->broadcast_queue, "broadcast queue created");
    TEST_ASSERT_NULL(ctx->parser, "parser NULL");
    TEST_ASSERT_NULL(ctx->request, "request NULL");
    TEST_ASSERT_NULL(ctx->response, "response NULL");
    TEST_ASSERT(ctx->switch_to_protocol.fn == NULL, "switch_to_protocol.fn NULL");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "ref_count starts at 1");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->broadcast_ref_count), "broadcast_ref_count starts at 1");
    TEST_ASSERT_EQUAL(0, atomic_load(&ctx->destroyed), "destroyed off");
    TEST_ASSERT_EQUAL(0, atomic_load(&ctx->locked), "unlocked");

    conn_harness_free(&h);
}

TEST(test_connection_s_alloc_null_listener) {
    TEST_CASE("connection_s_alloc with NULL listener leaves server NULL");

    connection_t* conn = connection_s_alloc(NULL, -1, 0, 0, 0, 0, NULL, 0);
    TEST_REQUIRE_NOT_NULL(conn, "connection created");

    connection_server_ctx_t* ctx = conn->ctx;
    TEST_ASSERT_NULL(ctx->listener, "listener NULL");
    TEST_ASSERT_NULL(ctx->server, "server NULL without listener");

    connection_free(conn);
}

TEST(test_connection_s_create_local_and_free_local) {
    TEST_CASE("connection_s_create_local builds a detached local connection");

    server_t server;
    memset(&server, 0, sizeof(server));
    server.port = 8080;

    connection_t* conn = connection_s_create_local(&server);
    TEST_REQUIRE_NOT_NULL(conn, "local connection created");

    TEST_ASSERT_EQUAL(-1, conn->fd, "no real socket: fd is -1 sentinel");
    TEST_ASSERT_EQUAL(8080, conn->port, "port from server");
    TEST_ASSERT(conn->close == NULL, "close NULL");
    TEST_ASSERT(conn->read == NULL, "read NULL");
    TEST_ASSERT(conn->write == NULL, "write NULL");

    connection_server_ctx_t* ctx = conn->ctx;
    TEST_ASSERT(ctx->server == &server, "server attached to ctx");
    TEST_ASSERT_NULL(ctx->listener, "no listener for local connection");

    connection_s_free_local(conn);
    connection_s_free_local(NULL); /* NULL-safe */
    TEST_ASSERT(1, "free_local handled connection and NULL");
}

TEST(test_connection_s_lock_unlock) {
    TEST_CASE("connection_s_lock/unlock toggle ctx->locked, NULL-safe");

    TEST_ASSERT_EQUAL(0, connection_s_lock(NULL), "lock(NULL) returns 0");
    TEST_ASSERT_EQUAL(0, connection_s_unlock(NULL), "unlock(NULL) returns 0");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    connection_server_ctx_t* ctx = h.conn->ctx;

    TEST_ASSERT_EQUAL(1, connection_s_lock(h.conn), "lock returns 1");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->locked), "locked flag set");

    TEST_ASSERT_EQUAL(1, connection_s_unlock(h.conn), "unlock returns 1");
    TEST_ASSERT_EQUAL(0, atomic_load(&ctx->locked), "locked flag cleared");

    conn_harness_free(&h);
}

TEST(test_connection_s_inc_dec) {
    TEST_CASE("connection_s_inc/dec: DECREMENT above zero, DESTROY at zero");

    connection_t* conn = connection_s_alloc(NULL, -1, 0, 0, 0, 0, NULL, 0);
    TEST_REQUIRE_NOT_NULL(conn, "connection created");

    connection_server_ctx_t* ctx = conn->ctx;

    connection_s_inc(conn);
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "inc raises ref_count to 2");

    TEST_ASSERT_EQUAL(CONNECTION_DEC_RESULT_DECREMENT, connection_s_dec(conn), "first dec only decrements");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "ref_count back to 1");

    /* Last reference: frees the connection (leak/double-free is caught by
     * ASan in Debug builds). */
    TEST_ASSERT_EQUAL(CONNECTION_DEC_RESULT_DESTROY, connection_s_dec(conn), "last dec destroys");
}

/* -------------------------------------------------------------------------- */
/* connection_s.c: after_read / after_write state transitions                 */
/* -------------------------------------------------------------------------- */

TEST(test_connection_after_read_events) {
    TEST_CASE("connection_after_read rearms MPXOUT|MPXRDHUP");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    TEST_ASSERT_EQUAL(1, connection_after_read(h.conn), "returns control_mod result");
    TEST_ASSERT_EQUAL(1, stub_control_mod_calls, "control_mod called once");
    TEST_ASSERT_EQUAL(MPXOUT | MPXRDHUP, stub_control_mod_last_events, "events are MPXOUT|MPXRDHUP");

    stub_control_mod_result = 0;
    TEST_ASSERT_EQUAL(0, connection_after_read(h.conn), "propagates control_mod failure");

    conn_harness_free(&h);
}

TEST(test_connection_after_write_no_keepalive) {
    TEST_CASE("after_write without keepalive marks destroyed and waits for HUP");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    h.conn->keepalive = 0;
    connection_server_ctx_t* ctx = h.conn->ctx;

    TEST_ASSERT_EQUAL(1, connection_after_write(h.conn), "returns control_mod result");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->destroyed), "destroyed flag set");
    TEST_ASSERT_EQUAL(MPXOUT | MPXIN | MPXHUP, stub_control_mod_last_events, "events are MPXOUT|MPXIN|MPXHUP");

    conn_harness_free(&h);
}

TEST(test_connection_after_write_keepalive_idle) {
    TEST_CASE("after_write with keepalive and empty queues resets and rearms MPXIN");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    h.conn->keepalive = 1;
    connection_server_ctx_t* ctx = h.conn->ctx;
    ctx->request = &stub_request;
    ctx->response = &stub_response;

    TEST_ASSERT_EQUAL(1, connection_after_write(h.conn), "returns control_mod result");

    /* The server-side reset frees the staged request/response. */
    TEST_ASSERT_EQUAL(1, stub_request_free_calls, "request freed by reset");
    TEST_ASSERT_EQUAL(1, stub_response_free_calls, "response freed by reset");
    TEST_ASSERT_NULL(ctx->request, "request detached");
    TEST_ASSERT_NULL(ctx->response, "response detached");

    TEST_ASSERT_EQUAL(0, atomic_load(&ctx->destroyed), "connection stays alive");
    TEST_ASSERT_EQUAL(MPXIN | MPXRDHUP, stub_control_mod_last_events, "rearmed for reading");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "no reference transferred");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->broadcast_ref_count), "broadcast_ref_count stays 1");

    conn_harness_free(&h);
}

TEST(test_connection_after_write_keepalive_pending_queue) {
    TEST_CASE("after_write with a pending queue item requeues the connection");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    h.conn->keepalive = 1;
    connection_server_ctx_t* ctx = h.conn->ctx;

    connection_queue_item_t* item = connection_queue_item_create();
    TEST_REQUIRE_NOT_NULL_GOTO(item, "queue item created", cleanup);
    item->connection = h.conn;

    TEST_REQUIRE_GOTO(cqueue_append(ctx->queue, item), "item staged in ctx->queue", cleanup);

    TEST_ASSERT_EQUAL(1, connection_after_write(h.conn), "returns control_mod result");
    TEST_ASSERT_EQUAL(MPXONESHOT, stub_control_mod_last_events, "connection parked as ONESHOT");
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "worker queue holds a reference");

    TEST_ASSERT(conn_harness_drain_worker_queue() == h.conn, "worker queue yields this connection");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "reference released after drain");

    cleanup:
    /* the staged item is released by __ctx_free through conn_harness_free */
    conn_harness_free(&h);
}

static int switch_protocol_calls = 0;
static void* switch_protocol_last_data = NULL;
static int switch_protocol_data_free_calls = 0;

static int stub_switch_protocol(connection_t* connection, void* data) {
    (void)connection;
    switch_protocol_calls++;
    switch_protocol_last_data = data;
    return 1;
}

static void stub_switch_protocol_data_free(void* data) {
    (void)data;
    switch_protocol_data_free_calls++;
}

TEST(test_connection_after_write_switch_to_protocol) {
    TEST_CASE("after_write runs the deferred protocol switch exactly once");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    switch_protocol_calls = 0;
    switch_protocol_last_data = NULL;
    switch_protocol_data_free_calls = 0;

    h.conn->keepalive = 1;
    connection_server_ctx_t* ctx = h.conn->ctx;

    int marker = 0;
    ctx->switch_to_protocol.fn = stub_switch_protocol;
    ctx->switch_to_protocol.data = &marker;
    ctx->switch_to_protocol.data_free = stub_switch_protocol_data_free;

    TEST_ASSERT_EQUAL(1, connection_after_write(h.conn), "returns control_mod result");
    TEST_ASSERT_EQUAL(1, switch_protocol_calls, "switch fn called once");
    TEST_ASSERT(switch_protocol_last_data == &marker, "switch fn received its data");
    TEST_ASSERT_EQUAL(1, switch_protocol_data_free_calls, "data_free called once");
    TEST_ASSERT(ctx->switch_to_protocol.fn == NULL, "switch fn cleared");
    TEST_ASSERT(ctx->switch_to_protocol.data == NULL, "switch data cleared");
    TEST_ASSERT(ctx->switch_to_protocol.data_free == NULL, "switch data_free cleared");

    /* Second write must not re-run the consumed switch. */
    connection_after_write(h.conn);
    TEST_ASSERT_EQUAL(1, switch_protocol_calls, "switch fn not called again");

    conn_harness_free(&h);
}

TEST(test_connection_after_write_broadcast_recheck) {
    TEST_CASE("after_write re-queues when a broadcast slipped in during the CAS window");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    h.conn->keepalive = 1;
    connection_server_ctx_t* ctx = h.conn->ctx;

    /* A sender bumped broadcast_ref_count to 2 and its message is already
     * staged: after_write must fold 2->1, notice the non-empty broadcast
     * queue and re-park the connection ONESHOT instead of dropping the
     * message until the next activity. */
    atomic_store(&ctx->broadcast_ref_count, 2);

    connection_queue_item_t* item = connection_queue_item_create();
    TEST_REQUIRE_NOT_NULL_GOTO(item, "broadcast item created", cleanup);
    item->connection = h.conn;
    TEST_REQUIRE_GOTO(cqueue_append(ctx->broadcast_queue, item), "broadcast staged", cleanup);

    TEST_ASSERT_EQUAL(1, connection_after_write(h.conn), "returns control_mod result");
    TEST_ASSERT_EQUAL(MPXONESHOT, stub_control_mod_last_events, "parked as ONESHOT for the worker");
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->broadcast_ref_count), "broadcast_ref_count re-armed to 2");
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "worker queue holds a reference");

    TEST_ASSERT(conn_harness_drain_worker_queue() == h.conn, "worker queue yields this connection");

    cleanup:
    /* the staged broadcast item is released by __ctx_free */
    conn_harness_free(&h);
}

TEST(test_connection_after_write_broadcast_flag_folds_back) {
    TEST_CASE("after_write folds broadcast_ref_count 2->1 when nothing is staged");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    h.conn->keepalive = 1;
    connection_server_ctx_t* ctx = h.conn->ctx;
    atomic_store(&ctx->broadcast_ref_count, 2);

    TEST_ASSERT_EQUAL(1, connection_after_write(h.conn), "returns control_mod result");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->broadcast_ref_count), "flag folded back to 1");
    TEST_ASSERT_EQUAL(MPXIN | MPXRDHUP, stub_control_mod_last_events, "rearmed for reading");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "no reference transferred");

    conn_harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* connection_s.c: queue append protocol                                      */
/* -------------------------------------------------------------------------- */

TEST(test_connection_queue_append_success) {
    TEST_CASE("connection_queue_append parks the connection and queues it");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    connection_server_ctx_t* ctx = h.conn->ctx;

    connection_queue_item_t* item = connection_queue_item_create();
    TEST_REQUIRE_NOT_NULL_GOTO(item, "queue item created", cleanup);
    item->connection = h.conn;

    TEST_ASSERT_EQUAL(1, connection_queue_append(item), "append succeeds");
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->broadcast_ref_count), "broadcast_ref_count raised to 2");
    TEST_ASSERT_EQUAL(1, stub_control_mod_calls, "control_mod called once");
    TEST_ASSERT_EQUAL(MPXONESHOT, stub_control_mod_last_events, "parked as ONESHOT");
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "worker queue holds a reference");

    /* Second append while already parked: nothing new happens. */
    TEST_ASSERT_EQUAL(1, connection_queue_append(item), "repeat append is a no-op success");
    TEST_ASSERT_EQUAL(1, stub_control_mod_calls, "control_mod not called again");
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "no extra reference taken");

    TEST_ASSERT(conn_harness_drain_worker_queue() == h.conn, "worker queue yields this connection");

    item->free(item);

    cleanup:
    conn_harness_free(&h);
}

TEST(test_connection_queue_append_control_mod_failure) {
    TEST_CASE("connection_queue_append rolls back when control_mod fails");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    connection_server_ctx_t* ctx = h.conn->ctx;

    connection_queue_item_t* item = connection_queue_item_create();
    TEST_REQUIRE_NOT_NULL_GOTO(item, "queue item created", cleanup);
    item->connection = h.conn;

    stub_control_mod_result = 0;
    TEST_ASSERT_EQUAL(0, connection_queue_append(item), "append fails");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->broadcast_ref_count), "broadcast_ref_count rolled back to 1");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "no reference leaked");

    item->free(item);

    cleanup:
    conn_harness_free(&h);
}

TEST(test_connection_queue_append_broadcast_paths) {
    TEST_CASE("connection_queue_append_broadcast: success and control_mod failure");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    connection_server_ctx_t* ctx = h.conn->ctx;

    TEST_ASSERT_EQUAL(1, connection_queue_append_broadcast(h.conn), "append succeeds");
    TEST_ASSERT_EQUAL(MPXONESHOT, stub_control_mod_last_events, "parked as ONESHOT");
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "worker queue holds a reference");

    TEST_ASSERT(conn_harness_drain_worker_queue() == h.conn, "worker queue yields this connection");

    stub_control_mod_result = 0;
    atomic_store(&ctx->broadcast_ref_count, 2);
    TEST_ASSERT_EQUAL(0, connection_queue_append_broadcast(h.conn), "append fails on control_mod");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->broadcast_ref_count), "broadcast_ref_count reset to 1");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "no reference leaked");

    conn_harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* connection_s.c: close                                                      */
/* -------------------------------------------------------------------------- */

TEST(test_connection_close) {
    TEST_CASE("connection_close removes from epoll, closes fd, drops its reference");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 1), "harness init");

    connection_server_ctx_t* ctx = h.conn->ctx;

    /* REGRESSION: broadcast_clear dereferenced server->broadcast without a
     * NULL check — closing a connection on a server that never initialized
     * broadcasts crashed. The harness server has broadcast == NULL. */
    TEST_REQUIRE(ctx->server->broadcast == NULL, "server without broadcast");

    /* Hold an extra reference so close's dec does not destroy the
     * connection and its post-state stays observable. */
    connection_s_inc(h.conn);

    const int fd = h.conn->fd;
    TEST_ASSERT_EQUAL(1, connection_close(h.conn), "close returns 1");

    TEST_ASSERT_EQUAL(1, stub_control_del_calls, "control_del called once");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->destroyed), "destroyed flag set");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "close dropped its reference");
    TEST_ASSERT_EQUAL(0, atomic_load(&ctx->locked), "lock released on the decrement path");

    errno = 0;
    TEST_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD), "fd is closed");
    TEST_ASSERT_EQUAL(EBADF, errno, "fcntl reports EBADF");

    h.conn_fd = -1; /* already closed by connection_close */
    conn_harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* connection_queue.c: global worker queue                                    */
/* -------------------------------------------------------------------------- */

TEST(test_connection_queue_init_idempotent) {
    TEST_CASE("connection_queue_init is idempotent");

    TEST_ASSERT_EQUAL(1, connection_queue_init(), "first init succeeds");
    TEST_ASSERT_EQUAL(1, connection_queue_init(), "repeated init succeeds");
}

static int stub_item_data_free_calls = 0;

static void stub_item_data_free(void* data) {
    stub_item_data_free_calls++;
    free(data);
}

TEST(test_connection_queue_item_create_and_free) {
    TEST_CASE("connection_queue_item_create defaults and item->free contract");

    connection_queue_item_t* item = connection_queue_item_create();
    TEST_REQUIRE_NOT_NULL(item, "item created");

    TEST_ASSERT(item->free != NULL, "free callback set");
    TEST_ASSERT(item->run == NULL, "run NULL");
    TEST_ASSERT(item->handle == NULL, "handle NULL");
    TEST_ASSERT_NULL(item->connection, "connection NULL");
    TEST_ASSERT_NULL(item->data, "data NULL");

    /* free with NULL data must not crash */
    item->free(item);

    /* free must release attached data through data->free */
    stub_item_data_free_calls = 0;

    item = connection_queue_item_create();
    TEST_REQUIRE_NOT_NULL(item, "second item created");

    connection_queue_item_data_t* data = malloc(sizeof *data);
    TEST_REQUIRE_NOT_NULL_GOTO(data, "item data allocated", cleanup);
    data->free = stub_item_data_free;

    item->data = data;
    item->free(item);
    item = NULL;
    TEST_ASSERT_EQUAL(1, stub_item_data_free_calls, "data->free called once");

    cleanup:
    if (item != NULL)
        item->free(item);
}

TEST(test_connection_queue_guard_append_pop_roundtrip) {
    TEST_CASE("guard_append/guard_pop transfer a reference and return the connection locked");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    connection_server_ctx_t* ctx = h.conn->ctx;

    connection_queue_guard_append(h.conn);
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "queue holds a reference");

    connection_t* popped = connection_queue_guard_pop();
    TEST_ASSERT(popped == h.conn, "pop returns the appended connection");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->locked), "connection returned locked");
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "reference still held by the worker");

    connection_s_unlock(h.conn);
    connection_s_dec(h.conn);
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "worker released its reference");

    conn_harness_free(&h);
}

TEST(test_connection_queue_guard_append_item_queues_connection) {
    TEST_CASE("guard_append_item enqueues item->connection for the worker");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    connection_server_ctx_t* ctx = h.conn->ctx;

    connection_queue_item_t* item = connection_queue_item_create();
    TEST_REQUIRE_NOT_NULL_GOTO(item, "item created", cleanup);
    item->connection = h.conn;

    connection_queue_guard_append_item(item);
    TEST_ASSERT_EQUAL(2, atomic_load(&ctx->ref_count), "queue holds a reference");

    /* The global queue carries connections, not items: the item stays owned
     * by ctx->queue in production (by the test here). */
    TEST_ASSERT(conn_harness_drain_worker_queue() == h.conn, "pop yields the connection");

    item->free(item);

    cleanup:
    conn_harness_free(&h);
}

TEST(test_connection_queue_pop_skips_destroyed) {
    TEST_CASE("guard_pop drops destroyed connections and releases the queue reference");

    conn_harness_t h;
    TEST_REQUIRE(conn_harness_init(&h, 0), "harness init");

    connection_server_ctx_t* ctx = h.conn->ctx;

    connection_queue_guard_append(h.conn);
    atomic_store(&ctx->destroyed, 1);

    TEST_ASSERT_NULL(connection_queue_guard_pop(), "destroyed connection is not handed out");
    TEST_ASSERT_EQUAL(1, atomic_load(&ctx->ref_count), "queue reference released");
    TEST_ASSERT_EQUAL(0, atomic_load(&ctx->locked), "lock released");

    conn_harness_free(&h);
}

TEST(test_connection_queue_broadcast_no_waiters) {
    TEST_CASE("connection_queue_broadcast without waiters is a no-op");

    connection_queue_broadcast();
    TEST_ASSERT(1, "broadcast with no waiters returned");
}

TEST(test_connection_queue_pop_empty) {
    TEST_CASE("guard_pop on an empty queue returns NULL after the wait window");

    TEST_REQUIRE(connection_queue_init(), "queue initialized");

    /* Waits up to 1 second on the condvar — keep this the only empty-pop. */
    TEST_ASSERT_NULL(connection_queue_guard_pop(), "empty queue yields NULL");
}

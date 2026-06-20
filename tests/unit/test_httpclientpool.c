#include "framework.h"
#include "httpclientpool.h"

#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "connection_c.h"
#include "connection.h"
#include "map.h"

// ============================================================================
// Helpers
// ============================================================================
//
// connection_c_create не устанавливает vtable (close/read/write) — это
// ответственность вызывающего. Пул в discard-fallback вызывает connection->close,
// поэтому тестовые соединения получают простую заглушку закрытия fd.

static int test_conn_close(connection_t* conn) {
    if (conn == NULL) return 0;
    if (conn->fd > 0) {
        shutdown(conn->fd, SHUT_RDWR);
        close(conn->fd);
        conn->fd = -1;
    }
    return 0;
}

// socketpair даёт пару fd: conn владеет fds[0], peer (fds[1]) держит тест и
// закрывает вручную. Пока peer открыт, recv(MSG_PEEK) на fds[0] вернёт EAGAIN
// → соединение считается живым; после close(peer) → recv вернёт 0 → мёртвое.
static connection_t* make_connection(unsigned short port, int* peer_fd) {
    *peer_fd = -1;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return NULL;

    connection_t* conn = connection_c_create(fds[0], 0, port);
    if (conn == NULL) {
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }

    conn->close = test_conn_close;
    *peer_fd = fds[1];
    return conn;
}

// Ключ пула имеет формат "host:port" (__make_host_key в httpclientpool.c).
static host_connections_t* pool_find_host(connection_pool_t* pool, const char* host, unsigned short port) {
    char key[256];
    snprintf(key, sizeof(key), "%s:%d", host, (int)port);
    return (host_connections_t*)map_find(pool->hosts, key);
}

// ============================================================================
// Lifecycle
// ============================================================================

TEST(test_pool_create_free) {
    TEST_SUITE("lifecycle");
    TEST_CASE("create + free empty pool, free(NULL) is safe");

    connection_pool_t* pool = httpclientpool_create();
    TEST_ASSERT_NOT_NULL(pool, "pool should be created");

    httpclientpool_free(pool);
    httpclientpool_free(NULL);  // null-safe
}

// ============================================================================
// acquire / release
// ============================================================================

TEST(test_acquire_empty_returns_null) {
    TEST_SUITE("acquire / release");
    TEST_CASE("acquire on empty pool returns NULL");

    connection_pool_t* pool = httpclientpool_create();
    connection_t* got = httpclientpool_acquire(pool, "host", 80, 0);
    TEST_ASSERT_NULL(got, "empty pool returns NULL");

    httpclientpool_free(pool);
}

TEST(test_release_then_acquire_reuses) {
    TEST_SUITE("acquire / release");
    TEST_CASE("released connection is reused by acquire");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(8080, &peer);
    TEST_ASSERT_NOT_NULL(conn, "connection created");

    httpclientpool_release(pool, "host", 8080, conn, 0);

    connection_t* got = httpclientpool_acquire(pool, "host", 8080, 0);
    TEST_ASSERT_NOT_NULL(got, "acquire should return pooled connection");
    TEST_ASSERT_EQUAL((intptr_t)conn, (intptr_t)got, "same connection reused");

    httpclientpool_free(pool);
    if (peer >= 0) close(peer);
}

TEST(test_busy_connection_not_reused) {
    TEST_SUITE("acquire / release");
    TEST_CASE("busy (acquired) connection is not handed out again");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(80, &peer);
    httpclientpool_release(pool, "h", 80, conn, 0);

    connection_t* first = httpclientpool_acquire(pool, "h", 80, 0);
    TEST_ASSERT_NOT_NULL(first, "first acquire should succeed");

    connection_t* second = httpclientpool_acquire(pool, "h", 80, 0);
    TEST_ASSERT_NULL(second, "busy connection must not be reused");

    httpclientpool_free(pool);
    if (peer >= 0) close(peer);
}

// ============================================================================
// discard
// ============================================================================

TEST(test_discard_removes_from_pool) {
    TEST_SUITE("discard");
    TEST_CASE("discard removes a pooled connection");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(80, &peer);
    httpclientpool_release(pool, "h", 80, conn, 0);

    httpclientpool_discard(pool, "h", 80, conn);

    host_connections_t* hc = pool_find_host(pool, "h", 80);
    TEST_ASSERT(hc == NULL || hc->count == 0, "pooled connection removed by discard");

    httpclientpool_free(pool);
    if (peer >= 0) close(peer);
}

TEST(test_discard_not_in_pool_closes_anyway) {
    TEST_SUITE("discard");
    TEST_CASE("discard of a connection not in pool still closes it (fallback path)");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(80, &peer);
    TEST_ASSERT_NOT_NULL(conn, "connection created");

    // Не release'им — conn не в пуле. discard пойдёт по fallback-ветке и
    // вызовет connection->close (test_conn_close) + connection_free.
    httpclientpool_discard(pool, "h", 80, conn);

    httpclientpool_free(pool);
    if (peer >= 0) close(peer);
}

// ============================================================================
// SSL filter
// ============================================================================

TEST(test_ssl_filter_excludes_mismatched) {
    TEST_SUITE("ssl filter");
    TEST_CASE("ssl-pooled connection is not returned for a non-ssl request");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(443, &peer);
    httpclientpool_release(pool, "h", 443, conn, 1);  // stored as ssl

    connection_t* got = httpclientpool_acquire(pool, "h", 443, 0);  // wants non-ssl
    TEST_ASSERT_NULL(got, "ssl connection must not serve a non-ssl request");

    httpclientpool_free(pool);
    if (peer >= 0) close(peer);
}

// ============================================================================
// TTL cleanup
// ============================================================================

TEST(test_cleanup_expired_removes_stale) {
    TEST_SUITE("TTL");
    TEST_CASE("cleanup_expired removes connections past their TTL");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(80, &peer);
    httpclientpool_release(pool, "h", 80, conn, 0);

    host_connections_t* hc = pool_find_host(pool, "h", 80);
    TEST_ASSERT_NOT_NULL(hc, "host entry should exist");
    TEST_ASSERT_EQUAL(1, hc->count, "one pooled connection");
    hc->connections->expires_at = 1;  // simulate elapsed TTL (in the past)

    httpclientpool_cleanup_expired(pool);

    // hc is freed once the last connection expires (cleanup reaps the now-empty
    // host entry), so re-resolve instead of dereferencing the stale pointer.
    TEST_ASSERT_NULL(pool_find_host(pool, "h", 80), "expired connection removed and empty host reaped");

    httpclientpool_free(pool);
    if (peer >= 0) close(peer);
}

// ============================================================================
// Liveness check
// ============================================================================

TEST(test_acquire_drops_dead_connection) {
    TEST_SUITE("liveness");
    TEST_CASE("acquire removes a connection whose peer has closed");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(80, &peer);
    httpclientpool_release(pool, "h", 80, conn, 0);

    // Close the peer end: poll(fd) reports POLLHUP → reported dead.
    close(peer);
    peer = -1;

    connection_t* got = httpclientpool_acquire(pool, "h", 80, 0);
    TEST_ASSERT_NULL(got, "dead connection must not be returned");

    host_connections_t* hc = pool_find_host(pool, "h", 80);
    TEST_ASSERT(hc == NULL || hc->count == 0, "dead connection removed by acquire");

    httpclientpool_free(pool);
}

// ============================================================================
// Per-host cap
// ============================================================================

TEST(test_pool_max_per_host_cap) {
    TEST_SUITE("per-host cap");
    TEST_CASE("release beyond POOL_MAX_CONNECTIONS_PER_HOST closes the excess");

    connection_pool_t* pool = httpclientpool_create();

    enum { N = POOL_MAX_CONNECTIONS_PER_HOST + 1 };
    int peers[N];
    for (int i = 0; i < N; i++) {
        connection_t* conn = make_connection(80, &peers[i]);
        TEST_ASSERT_NOT_NULL(conn, "connection created");
        httpclientpool_release(pool, "host", 80, conn, 0);
    }

    host_connections_t* hc = pool_find_host(pool, "host", 80);
    TEST_ASSERT_NOT_NULL(hc, "host entry exists");
    TEST_ASSERT_EQUAL(POOL_MAX_CONNECTIONS_PER_HOST, hc->count, "pool capped at POOL_MAX");

    for (int i = 0; i < N; i++)
        if (peers[i] >= 0) close(peers[i]);

    httpclientpool_free(pool);
}

// ============================================================================
// SSL liveness (Bug C: must not corrupt the SSL state machine)
// ============================================================================

TEST(test_acquire_drops_dead_ssl_connection) {
    TEST_SUITE("ssl liveness");
    TEST_CASE("an ssl-flagged pooled connection whose peer closed is not reused");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(443, &peer);
    // use_ssl=1, ssl=NULL: poll-based liveness never dereferences ssl. Ставить
    // dummy ssl нельзя — __close_pooled_connection звал бы SSL_*(ssl) и упал.
    httpclientpool_release(pool, "h", 443, conn, 1);

    close(peer);
    peer = -1;

    connection_t* got = httpclientpool_acquire(pool, "h", 443, 1);
    TEST_ASSERT_NULL(got, "dead ssl-flagged connection must not be returned");

    host_connections_t* hc = pool_find_host(pool, "h", 443);
    TEST_ASSERT(hc == NULL || hc->count == 0, "dead ssl connection removed by acquire");

    httpclientpool_free(pool);
}

TEST(test_release_then_acquire_reuses_ssl) {
    TEST_SUITE("ssl liveness");
    TEST_CASE("a live ssl-flagged connection is reused");

    connection_pool_t* pool = httpclientpool_create();
    int peer = -1;
    connection_t* conn = make_connection(443, &peer);
    httpclientpool_release(pool, "h", 443, conn, 1);

    connection_t* got = httpclientpool_acquire(pool, "h", 443, 1);
    TEST_ASSERT_NOT_NULL(got, "live ssl connection reused");
    TEST_ASSERT_EQUAL((intptr_t)conn, (intptr_t)got, "same connection reused");

    httpclientpool_free(pool);
    if (peer >= 0) close(peer);
}


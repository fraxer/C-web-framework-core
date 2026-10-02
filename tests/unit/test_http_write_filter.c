/*
 * Unit tests for protocols/http/server/filters/http_write_filter.c
 *
 * The write filter is the terminal filter of the response chain: it renders
 * the status line + header block into its own buffer (http_write_header) and
 * pushes bytes from the parent buffer into the connection (http_write_body).
 * The tests drive it against a real AF_UNIX socketpair, so partial writes,
 * EAGAIN and EPIPE come from the kernel rather than from mocks.
 *
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - __build_head treated bufo_append() == 0 as failure, so a header with an
 *     empty value (legal per RFC 7230, e.g. add_header("X-Empty", "")) made
 *     http_write_header return CWF_ERROR and the connection was dropped
 *     without a response;
 *   - an unknown status code (httpresponse_status_string() == NULL) failed
 *     through the same accidental path with nothing logged; it is now
 *     rejected explicitly before anything is buffered, instead of relying on
 *     bufo_append(NULL, 0) happening to return 0;
 *   - __wr treated only writed == -1 as an error: a 0 return (SSL_write on a
 *     closed connection) advanced the buffer by 0 bytes and busy-looped the
 *     event thread forever (not directly testable without an SSL seam; the
 *     EPIPE case below covers the sibling "peer gone" path for send(2));
 *   - send(2) interrupted by a signal (EINTR) was treated as a fatal error
 *     and killed the connection instead of retrying the write.
 */

#include "framework.h"
#include "httpresponse.h"
#include "http_write_filter.h"
#include "connection_s.h"
#include "http_data_filter.h"
#include "http_range_filter.h"
#include "httpserverhandlers.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#define WRITE_BUF_SIZE 16384

// ============================================================================
// Fixture: write filter wired to a real nonblocking socketpair
// ============================================================================

static connection_server_ctx_t test_write_ctx;

typedef struct {
    connection_t* conn;
    httpresponse_t* response;
    http_filter_t* filter;
    http_module_write_t* module;
    int wr_fd;                /* connection->fd, the filter writes here */
    int rd_fd;                /* capture side of the socketpair */
    char* captured;
    size_t captured_size;
    size_t captured_capacity;
} write_fixture_t;

static int set_nonblock(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return 0;

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

/* SOCK_SEQPACKET preserves write boundaries, so a test can count how many
 * write(2) calls a response took — which is what §10.1 is about. SOCK_STREAM
 * is the default because everything else here cares about bytes, not calls. */
static int fixture_setup_type(write_fixture_t* fx, size_t capture_capacity, int sock_type) {
    memset(fx, 0, sizeof(*fx));
    fx->wr_fd = -1;
    fx->rd_fd = -1;

    int sv[2];
    if (socketpair(AF_UNIX, sock_type, 0, sv) != 0)
        return 0;

    fx->wr_fd = sv[0];
    fx->rd_fd = sv[1];

    if (!set_nonblock(fx->wr_fd) || !set_nonblock(fx->rd_fd))
        goto failed;

    fx->conn = calloc(1, sizeof(connection_t));
    if (fx->conn == NULL)
        goto failed;

    memset(&test_write_ctx, 0, sizeof(test_write_ctx));
    fx->conn->ctx = &test_write_ctx;
    fx->conn->fd = fx->wr_fd;
    fx->conn->ssl = NULL;

    fx->response = httpresponse_create(fx->conn);
    fx->filter = http_write_filter_create();
    fx->captured = malloc(capture_capacity);
    if (fx->response == NULL || fx->filter == NULL || fx->captured == NULL)
        goto failed;

    fx->captured_capacity = capture_capacity;
    fx->module = fx->filter->module;

    return 1;

    failed:
    if (fx->filter != NULL) {
        http_module_t* module = fx->filter->module;
        module->free(fx->filter->module);
        free(fx->filter);
    }
    free(fx->captured);
    if (fx->response != NULL) httpresponse_free(fx->response);
    free(fx->conn);
    close(fx->wr_fd);
    close(fx->rd_fd);
    return 0;
}

static int fixture_setup(write_fixture_t* fx, size_t capture_capacity) {
    return fixture_setup_type(fx, capture_capacity, SOCK_STREAM);
}

static void fixture_teardown(write_fixture_t* fx) {
    if (fx->filter != NULL) {
        http_module_t* module = fx->filter->module;
        module->free(fx->filter->module);
        free(fx->filter);
    }

    free(fx->captured);

    if (fx->response != NULL)
        httpresponse_free(fx->response);

    free(fx->conn);

    if (fx->wr_fd != -1) close(fx->wr_fd);
    if (fx->rd_fd != -1) close(fx->rd_fd);
}

/* Pull everything currently queued in the socketpair into fx->captured. */
static int fixture_drain(write_fixture_t* fx) {
    char tmp[8192];

    while (1) {
        const ssize_t r = recv(fx->rd_fd, tmp, sizeof(tmp), 0);
        if (r < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK;
        if (r == 0)
            return 1;

        if (fx->captured_size + (size_t)r > fx->captured_capacity)
            return 0;

        memcpy(fx->captured + fx->captured_size, tmp, (size_t)r);
        fx->captured_size += (size_t)r;
    }
}

/* Shrink the send buffer so a large head/body hits EAGAIN deterministically. */
static int fixture_shrink_sndbuf(write_fixture_t* fx) {
    const int size = 4096;
    return setsockopt(fx->wr_fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0;
}

static int run_header(write_fixture_t* fx) {
    fx->response->cur_filter = fx->filter;
    return fx->filter->handler_header(NULL, fx->response);
}

static int run_body(write_fixture_t* fx, bufo_t* parent) {
    fx->response->cur_filter = fx->filter;
    return fx->filter->handler_body(NULL, fx->response, parent);
}

/* The head is held back until something can be joined to it, so a test that
 * only runs the header pass has to flush — exactly as __run_flush_filters does
 * after the body filters. */
static int run_flush(write_fixture_t* fx) {
    fx->response->cur_filter = fx->filter;
    return fx->filter->handler_flush(NULL, fx->response);
}

static int run_header_and_flush(write_fixture_t* fx) {
    const int r = run_header(fx);
    if (r != CWF_OK) return r;
    return run_flush(fx);
}

static void parent_init(bufo_t* parent, char* data, size_t size, int is_last) {
    parent->data = data;
    parent->capacity = size;
    parent->size = size;
    parent->pos = 0;
    parent->is_proxy = 1;
    parent->is_last = is_last ? 1 : 0;
}

static int captured_equals(write_fixture_t* fx, const char* expected, size_t expected_size) {
    return fx->captured_size == expected_size
        && memcmp(fx->captured, expected, expected_size) == 0;
}

// ============================================================================
// Construction
// ============================================================================

TEST(test_write_filter_create_defaults) {
    TEST_SUITE("http_write_filter: construction");
    TEST_CASE("filter and module are initialized with clean defaults");

    http_filter_t* filter = http_write_filter_create();
    TEST_REQUIRE_NOT_NULL(filter, "filter should be created");

    TEST_ASSERT(filter->handler_header == http_write_header, "handler_header should be set");
    TEST_ASSERT(filter->handler_body == http_write_body, "handler_body should be set");
    TEST_ASSERT_NULL(filter->next, "next filter should be NULL");
    TEST_REQUIRE_NOT_NULL(filter->module, "module should be created");

    http_module_write_t* module = filter->module;
    TEST_ASSERT_EQUAL_UINT(0, module->base.cont, "cont should be 0");
    TEST_ASSERT_EQUAL_UINT(0, module->base.done, "done should be 0");
    TEST_ASSERT_NULL(module->base.parent_buf, "parent_buf should be NULL");
    TEST_ASSERT(module->base.free == http_write_free, "free callback should be set");
    TEST_ASSERT(module->base.reset != NULL, "reset callback should be set");
    TEST_ASSERT_NOT_NULL(module->buf, "output buffer should be created");
    TEST_ASSERT_NULL(module->buf->data, "output buffer should not be allocated yet");

    module->base.free(module);
    free(filter);
}

// ============================================================================
// http_write_header
// ============================================================================

TEST(test_write_header_basic) {
    TEST_SUITE("http_write_filter: header");
    TEST_CASE("status line and headers are rendered and sent byte-exact");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Type", "text/plain"),
                      "Content-Type should be added", cleanup);
    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Length", "5"),
                      "Content-Length should be added", cleanup);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header pass should finish with CWF_OK");

    const char expected[] = "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: 5\r\n"
                            "\r\n";
    const size_t expected_size = sizeof(expected) - 1;

    /* §10.1: the header pass renders, it does not write. The head waits for a
     * body chunk to ride along with. */
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT_EQUAL_SIZE(0, fx.captured_size, "header pass alone should send nothing");

    TEST_ASSERT_EQUAL(CWF_OK, run_flush(&fx), "flush should finish with CWF_OK");
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);

    TEST_ASSERT(captured_equals(&fx, expected, expected_size),
                "head on the wire should match byte for byte");

    /* __head_size() accounting must agree with what __build_head appends: the
     * buffer is the predicted head plus the join reserve, so any drift shows
     * up here as a capacity/size mismatch. */
    TEST_ASSERT_EQUAL_SIZE(expected_size + HTTP_WRITE_JOIN_MAX, fx.module->buf->capacity,
                           "buffer should be the head size plus the join reserve");
    TEST_ASSERT_EQUAL_SIZE(expected_size, fx.module->buf->size,
                           "buffer size should equal the head size");
    TEST_ASSERT_EQUAL_SIZE(fx.module->buf->size, fx.module->buf->pos,
                           "head should be fully flushed (pos == size)");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_header_no_headers) {
    TEST_SUITE("http_write_filter: header");
    TEST_CASE("response without headers renders a minimal head");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    const int r = run_header_and_flush(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header pass should finish with CWF_OK");

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT(captured_equals(&fx, "HTTP/1.1 200 OK\r\n\r\n", 19),
                "head should be the status line plus the empty line");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_header_empty_header_value) {
    TEST_SUITE("http_write_filter: header");
    TEST_CASE("REGRESSION: header with an empty value does not break the response");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "X-Empty", ""),
                      "empty-valued header should be added", cleanup);

    const int r = run_header_and_flush(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "empty header value should not fail the head");

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT(captured_equals(&fx, "HTTP/1.1 200 OK\r\nX-Empty: \r\n\r\n", 30),
                "empty value should render as 'X-Empty: ' with no payload");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_header_unknown_status_code) {
    TEST_SUITE("http_write_filter: header");
    TEST_CASE("REGRESSION: unknown status code fails cleanly before buffering");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    fx.response->status_code = 599;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_ERROR, r, "unknown status code should yield CWF_ERROR");

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT_EQUAL_SIZE(0, fx.captured_size, "nothing should reach the wire");
    TEST_ASSERT_NULL(fx.module->buf->data,
                     "status code should be rejected before the buffer is allocated");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_header_eagain_resume) {
    TEST_SUITE("http_write_filter: header");
    TEST_CASE("EAGAIN mid-head resumes from the same position without rebuilding");

    enum { value_size = 65536 };

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, value_size + 4096), "fixture should be created");
    TEST_REQUIRE_GOTO(fixture_shrink_sndbuf(&fx), "send buffer should be shrunk", cleanup);

    char* value = malloc(value_size + 1);
    char* expected = malloc(value_size + 64);
    TEST_REQUIRE_GOTO(value != NULL && expected != NULL, "test buffers should be allocated",
                      cleanup_buffers);

    memset(value, 'a', value_size);
    value[value_size] = '\0';

    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "X-Big", value),
                      "large header should be added", cleanup_buffers);

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should render the head",
                      cleanup_buffers);

    /* The head is written by the flush pass now, so that is where a head too
     * big for the send buffer runs into EAGAIN. */
    int r = run_flush(&fx);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "head larger than the send buffer should hit EAGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.response->event_again, "event_again should be set");
    TEST_ASSERT(fx.module->buf->pos < fx.module->buf->size,
                "part of the head should still be pending");

    int guard = 0;
    while (r == CWF_EVENT_AGAIN && guard++ < 1000) {
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained between resumes",
                          cleanup_buffers);
        /* Both passes are re-run on resume, as the engine does: the header pass
         * must not rebuild the head over the bytes already in flight. */
        TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass stays a no-op on resume",
                          cleanup_buffers);
        r = run_flush(&fx);
    }

    TEST_ASSERT_EQUAL(CWF_OK, r, "resumed flush should finish with CWF_OK");
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup_buffers);

    const int expected_size = snprintf(expected, value_size + 64,
                                       "HTTP/1.1 200 OK\r\nX-Big: %s\r\n\r\n", value);
    TEST_REQUIRE_GOTO(expected_size > 0, "expected head should be rendered", cleanup_buffers);

    TEST_ASSERT(captured_equals(&fx, expected, (size_t)expected_size),
                "resumed head should be complete, in order and built exactly once");

    cleanup_buffers:
    free(value);
    free(expected);

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_header_second_call_is_noop) {
    TEST_SUITE("http_write_filter: header");
    TEST_CASE("second header pass after completion sends nothing");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    TEST_REQUIRE_GOTO(run_header_and_flush(&fx) == CWF_OK, "first header pass should succeed", cleanup);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);

    const size_t first_size = fx.captured_size;
    TEST_REQUIRE_GOTO(first_size > 0, "the head should be on the wire by now", cleanup);

    const int r = run_header_and_flush(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "second header pass should still report CWF_OK");

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT_EQUAL_SIZE(first_size, fx.captured_size, "no extra bytes should be sent");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// http_write_body
// ============================================================================

TEST(test_write_body_simple) {
    TEST_SUITE("http_write_filter: body");
    TEST_CASE("parent buffer is written to the connection and fully consumed");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    char data[] = "Hello";
    bufo_t parent;
    parent_init(&parent, data, 5, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "drained parent should report CWF_DATA_AGAIN");
    TEST_ASSERT_EQUAL_SIZE(5, parent.pos, "parent should be fully consumed");
    TEST_ASSERT(fx.module->base.parent_buf == &parent, "parent_buf should be stored");

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT(captured_equals(&fx, "Hello", 5), "payload should reach the wire unmodified");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_body_empty_parent) {
    TEST_SUITE("http_write_filter: body");
    TEST_CASE("empty parent buffer writes nothing and reports CWF_DATA_AGAIN");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    bufo_t parent;
    parent_init(&parent, NULL, 0, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "empty parent should report CWF_DATA_AGAIN");

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT_EQUAL_SIZE(0, fx.captured_size, "nothing should be sent");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_body_large_parent_multiple_chunks) {
    TEST_SUITE("http_write_filter: body");
    TEST_CASE("parent larger than BUF_SIZE is sent in 16K chunks without loss");

    enum { data_size = 40000 };

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, data_size + 4096), "fixture should be created");

    /* Make sure the whole payload fits into the kernel buffer so the single
     * run_body() pass exercises the chunk loop, not the EAGAIN path. */
    const int sndbuf = 131072;
    TEST_REQUIRE_GOTO(setsockopt(fx.wr_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == 0,
                      "send buffer should be enlarged", cleanup);

    char* data = malloc(data_size);
    TEST_REQUIRE_NOT_NULL_GOTO(data, "payload should be allocated", cleanup);

    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('a' + i % 26);

    bufo_t parent;
    parent_init(&parent, data, data_size, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body pass should report CWF_DATA_AGAIN");
    TEST_ASSERT_EQUAL_SIZE(data_size, parent.pos, "parent should be fully consumed");

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup_data);
    TEST_ASSERT(captured_equals(&fx, data, data_size),
                "payload should arrive complete and in order");

    cleanup_data:
    free(data);

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_body_eagain_partial_resume) {
    TEST_SUITE("http_write_filter: body");
    TEST_CASE("EAGAIN mid-body resumes from parent->pos without loss or repeats");

    enum { data_size = 65536 };

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, data_size + 4096), "fixture should be created");
    TEST_REQUIRE_GOTO(fixture_shrink_sndbuf(&fx), "send buffer should be shrunk", cleanup);

    char* data = malloc(data_size);
    TEST_REQUIRE_NOT_NULL_GOTO(data, "payload should be allocated", cleanup);

    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('A' + i % 26);

    bufo_t parent;
    parent_init(&parent, data, data_size, 1);

    int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "payload larger than the send buffer should hit EAGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.response->event_again, "event_again should be set");
    TEST_ASSERT(parent.pos > 0, "some bytes should have been written before EAGAIN");
    TEST_ASSERT(parent.pos < data_size, "not all bytes should fit before EAGAIN");

    int guard = 0;
    while (r == CWF_EVENT_AGAIN && guard++ < 1000) {
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained between resumes",
                          cleanup_data);
        r = run_body(&fx, &parent);
    }

    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "resumed body pass should finish with CWF_DATA_AGAIN");
    TEST_ASSERT_EQUAL_SIZE(data_size, parent.pos, "parent should be fully consumed");

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup_data);
    TEST_ASSERT(captured_equals(&fx, data, data_size),
                "payload should arrive complete, without loss or repeats");

    cleanup_data:
    free(data);

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_body_peer_closed_epipe) {
    TEST_SUITE("http_write_filter: body");
    TEST_CASE("REGRESSION: write to a closed peer fails with CWF_ERROR, not SIGPIPE");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    /* Close the capture side: send(2) must return EPIPE. Without MSG_NOSIGNAL
     * the kernel would raise SIGPIPE instead and kill the test runner — the
     * test passing at all proves the flag is in place. */
    close(fx.rd_fd);
    fx.rd_fd = -1;

    char data[] = "Hello";
    bufo_t parent;
    parent_init(&parent, data, 5, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_ERROR, r, "EPIPE should map to CWF_ERROR");
    TEST_ASSERT_EQUAL_SIZE(0, parent.pos, "no bytes should be consumed on a dead connection");

    fixture_teardown(&fx);
}

// ============================================================================
// Reset and reuse
// ============================================================================

TEST(test_write_reset_allows_reuse) {
    TEST_SUITE("http_write_filter: reset");
    TEST_CASE("reset releases the head buffer and the module can serve again");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "X-Key", "value"),
                      "header should be added", cleanup);
    TEST_REQUIRE_GOTO(run_header_and_flush(&fx) == CWF_OK, "first header pass should succeed", cleanup);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);

    const char expected[] = "HTTP/1.1 200 OK\r\nX-Key: value\r\n\r\n";
    const size_t expected_size = sizeof(expected) - 1;
    TEST_REQUIRE_GOTO(captured_equals(&fx, expected, expected_size),
                      "first head should be correct", cleanup);

    fx.module->base.reset(fx.module);

    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.done, "done should be cleared");
    TEST_ASSERT_NULL(fx.module->base.parent_buf, "parent_buf should be cleared");
    TEST_ASSERT_NULL(fx.module->buf->data, "head buffer should be released");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->buf->size, "buffer size should be cleared");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->buf->pos, "buffer pos should be cleared");

    fx.captured_size = 0;

    TEST_REQUIRE_GOTO(run_header_and_flush(&fx) == CWF_OK, "header pass should work after reset", cleanup);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT(captured_equals(&fx, expected, expected_size),
                "head should be rebuilt correctly after reset");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// Header + body together
// ============================================================================

TEST(test_write_header_then_body) {
    TEST_SUITE("http_write_filter: integration");
    TEST_CASE("head and body form a complete HTTP response on the wire");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Length", "5"),
                      "Content-Length should be added", cleanup);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    char data[] = "Hello";
    bufo_t parent;
    parent_init(&parent, data, 5, 1);

    TEST_REQUIRE_GOTO(run_body(&fx, &parent) == CWF_DATA_AGAIN, "body pass should succeed", cleanup);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);

    const char expected[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
    TEST_ASSERT(captured_equals(&fx, expected, sizeof(expected) - 1),
                "wire bytes should form the complete response");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// Joining the head to the first body chunk (docs/http2/10-performance.md §10.1)
// ============================================================================

TEST(test_write_join_small_body_is_one_write) {
    TEST_SUITE("http_write_filter: join");
    TEST_CASE("a small response leaves in a single write(2)");

    write_fixture_t fx;
    /* SEQPACKET keeps write boundaries, so one recv == one write. */
    TEST_REQUIRE(fixture_setup_type(&fx, 4096, SOCK_SEQPACKET), "fixture should be created");

    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Length", "5"),
                      "Content-Length should be added", cleanup);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    char data[] = "Hello";
    bufo_t parent;
    parent_init(&parent, data, 5, 1);

    TEST_REQUIRE_GOTO(run_body(&fx, &parent) == CWF_DATA_AGAIN, "body pass should succeed", cleanup);
    TEST_ASSERT_EQUAL(CWF_OK, run_flush(&fx), "flush should have nothing left to do");

    const char expected[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
    char packet[256];
    const ssize_t first = recv(fx.rd_fd, packet, sizeof(packet), 0);
    TEST_ASSERT_EQUAL((long long)(sizeof(expected) - 1), (long long)first,
                      "head and body should arrive as ONE datagram, i.e. one write");
    TEST_ASSERT(first > 0 && memcmp(packet, expected, (size_t)first) == 0,
                "the single write should carry the whole response");

    const ssize_t second = recv(fx.rd_fd, packet, sizeof(packet), 0);
    TEST_ASSERT(second < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
                "there should be no second write");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_join_large_body_stays_two_writes) {
    TEST_SUITE("http_write_filter: join");
    TEST_CASE("a body over the join threshold keeps head and body separate");

    const size_t body_size = HTTP_WRITE_JOIN_MAX + 1;

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup_type(&fx, 8192 + body_size, SOCK_SEQPACKET), "fixture should be created");

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);
    const size_t head_size = fx.module->buf->size;

    char* data = malloc(body_size);
    TEST_REQUIRE_NOT_NULL_GOTO(data, "payload should be allocated", cleanup);
    memset(data, 'x', body_size);

    bufo_t parent;
    parent_init(&parent, data, body_size, 1);

    TEST_REQUIRE_GOTO(run_body(&fx, &parent) == CWF_DATA_AGAIN, "body pass should succeed",
                      cleanup_data);

    /* Copying a large chunk costs more than the write it saves, so the head
     * goes out by itself and the body follows. */
    char packet[8192];
    const ssize_t first = recv(fx.rd_fd, packet, sizeof(packet), 0);
    TEST_ASSERT_EQUAL((long long)head_size, (long long)first, "first write should be the head alone");

    const ssize_t second = recv(fx.rd_fd, packet, sizeof(packet), 0);
    TEST_ASSERT_EQUAL((long long)body_size, (long long)second, "second write should be the body");

    cleanup_data:
    free(data);

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_join_partial_write_does_not_duplicate) {
    TEST_SUITE("http_write_filter: join");
    TEST_CASE("EAGAIN after a join resumes without repeating the joined bytes");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 262144), "fixture should be created");
    TEST_REQUIRE_GOTO(fixture_shrink_sndbuf(&fx), "send buffer should be shrunk", cleanup);

    /* A head big enough that the joined body cannot fit in the send buffer:
     * the write stops mid-way with the body already copied out of parent. */
    char value[8192];
    memset(value, 'h', sizeof(value) - 1);
    value[sizeof(value) - 1] = '\0';
    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "X-Big", value),
                      "large header should be added", cleanup);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    char body[64];
    memset(body, 'b', sizeof(body));
    bufo_t parent;
    parent_init(&parent, body, sizeof(body), 1);

    int r = run_body(&fx, &parent);
    TEST_REQUIRE_GOTO(r == CWF_EVENT_AGAIN, "the oversized head should hit EAGAIN", cleanup);
    TEST_ASSERT_EQUAL_SIZE(sizeof(body), parent.pos,
                           "the joined bytes are owned by the write stage, so parent is consumed");

    int guard = 0;
    while (r == CWF_EVENT_AGAIN && guard++ < 1000) {
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained between resumes", cleanup);
        r = run_body(&fx, &parent);
    }
    TEST_REQUIRE_GOTO(r == CWF_DATA_AGAIN, "the resumed response should complete", cleanup);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);

    /* The body must appear exactly once, at the very end: a resume that
     * re-joined it would send it twice, and one that dropped it would end the
     * response short. */
    TEST_ASSERT_EQUAL_SIZE(fx.module->buf->size, fx.captured_size,
                           "the wire should carry the head plus the joined body exactly once");
    TEST_ASSERT(fx.captured_size >= sizeof(body) &&
                memcmp(fx.captured + fx.captured_size - sizeof(body), body, sizeof(body)) == 0,
                "the joined body should be the tail of the response");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_flush_sends_bodiless_head) {
    TEST_SUITE("http_write_filter: join");
    TEST_CASE("a response with no body pass still gets its head out");

    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 4096), "fixture should be created");

    /* 304/HEAD/204: http_data_filter returns CWF_OK without calling the write
     * stage at all, so the head would sit in the buffer forever without flush. */
    fx.response->status_code = 304;
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT_EQUAL_SIZE(0, fx.captured_size, "nothing goes out before the flush");

    TEST_ASSERT_EQUAL(CWF_OK, run_flush(&fx), "flush should send the head");
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT(captured_equals(&fx, "HTTP/1.1 304 Not Modified\r\n\r\n", 29),
                "the bodiless head should be complete on the wire");

    TEST_ASSERT_EQUAL(CWF_OK, run_flush(&fx), "a second flush is a no-op");
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);
    TEST_ASSERT_EQUAL_SIZE(29, fx.captured_size, "and sends nothing extra");

    cleanup:
    fixture_teardown(&fx);
}

/* Exercise the real header/body chain, including the data filter's choice of
 * transport and the terminal writer's deferred header. */
static int sendfile_stage_file(write_fixture_t* fx, const void* data, size_t size) {
    char path[] = "/tmp/cwfr-sendfile-XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0) return 0;
    unlink(path);
    size_t done = 0;
    while (done < size) {
        const ssize_t n = write(fd, (const char*)data + done, size - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return 0; }
        done += (size_t)n;
    }
    fx->response->file_.fd = fd;
    fx->response->file_.size = size;
    return 1;
}

static int sendfile_probe_unsupported(write_fixture_t* fx, size_t start, size_t end) {
    http_filter_t* writer = http_file_writer(fx->response, fx->response->filter);
    if (writer == NULL) return CWF_ERROR;
    fx->response->cur_filter = writer;
    off_t offset = (off_t)start;
    return http_write_file_span(NULL, fx->response, &offset, end);
}

static http_module_data_t* sendfile_data_module(write_fixture_t* fx) {
    return fx->response->filter->next->next->module;
}

static size_t sendfile_head_size(write_fixture_t* fx) {
    http_filter_t* writer = fx->response->filter;
    while (writer->next != NULL) writer = writer->next;
    http_module_write_t* module = writer->module;
    return module->buf->size;
}

TEST(test_sendfile_chain_partial_head_body_and_reuse) {
    TEST_SUITE("http_write_filter: sendfile");
    TEST_CASE("partial head and file resume with exact bytes and keep-alive reset");
    const size_t size = 2 * 1024 * 1024 + 73;
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, size + 32768), "fixture created");
    char* payload = malloc(size);
    TEST_REQUIRE_GOTO(payload != NULL, "payload allocated", cleanup);
    for (size_t i = 0; i < size; ++i) payload[i] = (char)(i * 31);
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, payload, size), "file staged", cleanup_payload);
    TEST_REQUIRE_GOTO(fixture_shrink_sndbuf(&fx), "small socket buffer", cleanup_payload);
    char value[16384];
    memset(value, 'h', sizeof(value) - 1);
    value[sizeof(value) - 1] = 0;
    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "X-Large", value), "large head", cleanup_payload);
    TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "headers prepared", cleanup_payload);
    const size_t head_size = sendfile_head_size(&fx);
    int r = __run_body_filters(NULL, fx.response);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "partial header yields");
    TEST_ASSERT_EQUAL_SIZE(0, fx.response->body_bytes_sent, "no file before full header");
    int guard = 0;
    while (r == CWF_EVENT_AGAIN && guard++ < 4000) {
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "drain between resumes", cleanup_payload);
        r = __run_body_filters(NULL, fx.response);
    }
    TEST_REQUIRE_GOTO(r == CWF_OK, "file completes", cleanup_payload);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "final drain", cleanup_payload);
    TEST_ASSERT_EQUAL_SIZE(head_size + size, fx.captured_size, "exact wire length");
    TEST_ASSERT(memcmp(fx.captured + head_size, payload, size) == 0, "exact file bytes");
    TEST_ASSERT_EQUAL_SIZE(size, fx.response->body_bytes_sent, "actual byte counter");
    TEST_ASSERT(fx.response->body.data == NULL, "no userspace file buffer");
    TEST_ASSERT_EQUAL((long long)size, (long long)lseek(fx.response->file_.fd, 0, SEEK_CUR),
                      "explicit offset leaves shared file position unchanged");

    fx.response->base.reset(fx.response);
    fx.captured_size = 0;
    TEST_ASSERT(sendfile_data_module(&fx)->file_offset == 0, "offset resets");
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "second", 6), "second file staged", cleanup_payload);
    TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "second head", cleanup_payload);
    const size_t second_head = sendfile_head_size(&fx);
    TEST_REQUIRE_GOTO(__run_body_filters(NULL, fx.response) == CWF_OK, "second body", cleanup_payload);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "second drain", cleanup_payload);
    TEST_ASSERT_EQUAL_SIZE(second_head + 6, fx.captured_size, "second wire length");
    TEST_ASSERT(memcmp(fx.captured + second_head, "second", 6) == 0, "second file starts at zero");
    TEST_ASSERT_EQUAL_SIZE(6, fx.response->body_bytes_sent, "counter resets");

    cleanup_payload:
    free(payload);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_chain_bodiless_and_precompressed) {
    TEST_SUITE("http_write_filter: sendfile");
    TEST_CASE("HEAD, 304, 204 and empty files send only headers; precompressed files use sendfile");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    httprequest_t request = {0};
    for (int i = 0; i < 5; ++i) {
        const size_t size = i == 3 ? 0 : 7;
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "content", size), "file staged", cleanup);
        fx.response->status_code = i == 1 ? 304 : i == 2 ? 204 : 200;
        fx.response->gzip_precompressed = i == 4;
        request.method = i == 0 ? ROUTE_HEAD : ROUTE_GET;
        TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "head prepared", cleanup);
        const size_t head_size = sendfile_head_size(&fx);
        TEST_REQUIRE_GOTO(__run_body_filters(&request, fx.response) == CWF_OK, "body handled", cleanup);
        TEST_REQUIRE_GOTO(__run_flush_filters(NULL, fx.response) == CWF_OK, "head flushed", cleanup);
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "wire captured", cleanup);
        TEST_ASSERT_EQUAL_SIZE(head_size + (i == 4 ? size : 0), fx.captured_size, "body presence");
        TEST_ASSERT((fx.response->body.data != NULL) == (i == 4), "only the small precompressed body uses a read buffer");
        fx.response->base.reset(fx.response);
        fx.captured_size = 0;
    }
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_write_chain_informational_and_bodiless_statuses) {
    TEST_SUITE("http_write_filter: bodiless statuses");
    TEST_CASE("1xx, 204 and 304 flush only headers despite staged memory or file data");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    const int statuses[] = {100, 101, 102, 103, 204, 304};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        for (int file = 0; file < 2; ++file) {
            if (file) {
                TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "file", 4), "file staged", cleanup);
            }
            else {
                TEST_REQUIRE_GOTO(bufo_alloc(&fx.response->body, 4), "body allocated", cleanup);
                memcpy(fx.response->body.data, "body", 4);
                fx.response->body.size = 4;
            }
            fx.response->status_code = statuses[i];
            TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "headers prepared", cleanup);
            const size_t head = sendfile_head_size(&fx);
            TEST_ASSERT(fx.response->get_header(fx.response, "Content-Length") == NULL, "no body length");
            TEST_REQUIRE_GOTO(__run_body_filters(NULL, fx.response) == CWF_OK, "body suppressed", cleanup);
            TEST_ASSERT_EQUAL_SIZE(0, fx.response->body_bytes_sent, "no body bytes counted");
            TEST_ASSERT_EQUAL_SIZE(0, fx.response->body.pos, "memory cursor untouched");
            TEST_ASSERT(sendfile_data_module(&fx)->file_offset == 0, "file cursor untouched");
            TEST_REQUIRE_GOTO(__run_flush_filters(NULL, fx.response) == CWF_OK, "head flushed", cleanup);
            TEST_REQUIRE_GOTO(fixture_drain(&fx), "wire captured", cleanup);
            TEST_ASSERT_EQUAL_SIZE(head, fx.captured_size, "wire contains only the head");
            TEST_ASSERT(head >= 4 && memcmp(fx.captured + head - 4, "\r\n\r\n", 4) == 0, "response ends at empty line");
            fx.response->base.reset(fx.response);
            fx.captured_size = 0;
        }
    }
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_chain_fallback_proc_file) {
    TEST_SUITE("http_write_filter: sendfile");
    TEST_CASE("procfs rejects sendfile but buffered fallback sends exact bytes and resets");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    const int fd = open("/proc/self/cmdline", O_RDONLY);
    TEST_REQUIRE_GOTO(fd >= 0, "proc file opened", cleanup);
    fx.response->file_.fd = fd;
    char expected[4096];
    const ssize_t size = pread(fd, expected, sizeof(expected), 0);
    TEST_REQUIRE_GOTO(size > 0, "proc bytes read", cleanup);
    fx.response->file_.size = (size_t)size;
    TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "head prepared", cleanup);
    const size_t head_size = sendfile_head_size(&fx);
    TEST_REQUIRE_GOTO(sendfile_probe_unsupported(&fx, 0, (size_t)size) == CWF_DATA_AGAIN,
                      "procfs writer requests fallback", cleanup);
    sendfile_data_module(&fx)->sendfile_disabled = 1;
    TEST_REQUIRE_GOTO(__run_body_filters(NULL, fx.response) == CWF_OK, "fallback completes", cleanup);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "wire captured", cleanup);
    TEST_ASSERT(sendfile_data_module(&fx)->sendfile_disabled, "unsupported descriptor disables sendfile");
    TEST_ASSERT_EQUAL_SIZE(head_size + (size_t)size, fx.captured_size, "fallback wire length");
    TEST_ASSERT(memcmp(fx.captured + head_size, expected, (size_t)size) == 0, "fallback exact bytes");
    TEST_ASSERT_EQUAL_SIZE((size_t)size, fx.response->body_bytes_sent, "fallback byte counter");
    fx.response->base.reset(fx.response);
    TEST_ASSERT(!sendfile_data_module(&fx)->sendfile_disabled, "fallback choice resets");
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_chain_transforms_use_buffers) {
    TEST_SUITE("http_write_filter: sendfile");
    TEST_CASE("dynamic gzip and chunked files stay in the body filter chain");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 32768), "fixture created");
    char payload[4096];
    memset(payload, 'x', sizeof(payload));
    for (int i = 0; i < 2; ++i) {
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, payload, sizeof(payload)), "file staged", cleanup);
        if (i == 0) fx.response->content_encoding = CE_GZIP;
        else fx.response->transfer_encoding = TE_CHUNKED;
        TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "head prepared", cleanup);
        TEST_REQUIRE_GOTO(__run_body_filters(NULL, fx.response) == CWF_OK, "transformed body sent", cleanup);
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "wire captured", cleanup);
        TEST_ASSERT(fx.response->body.data != NULL, "buffered path used");
        TEST_ASSERT(fx.response->transfer_encoding == TE_CHUNKED, "chunk framing retained");
        TEST_ASSERT(fx.captured_size >= 5 && memcmp(fx.captured + fx.captured_size - 5, "0\r\n\r\n", 5) == 0,
                    "chunk stream terminated");
        fx.response->base.reset(fx.response);
        fx.captured_size = 0;
    }
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_chain_truncated_and_closed_peer) {
    TEST_SUITE("http_write_filter: sendfile");
    TEST_CASE("truncated files and disconnected clients fail without hanging");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    for (int mode = 0; mode < 3; ++mode) {
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "short", 5), "file staged", cleanup);
        fx.response->file_.size = mode == 0 ? 10 : HTTP_FILE_BUFFER_MAX + 10;
        sendfile_data_module(&fx)->sendfile_disabled = mode == 2;
        TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "head prepared", cleanup);
        TEST_ASSERT_EQUAL(CWF_ERROR, __run_body_filters(NULL, fx.response), "premature EOF closes response");
        TEST_ASSERT_EQUAL_SIZE(5, fx.response->body_bytes_sent, "only actual bytes counted");
        TEST_ASSERT((fx.response->body.data == NULL) == (mode == 1), "small, sendfile and forced buffered paths exercised");
        fx.response->base.reset(fx.response);
    }
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "file", 4), "next file staged", cleanup);
    fx.response->file_.size = HTTP_FILE_BUFFER_MAX + 4;
    TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "next head", cleanup);
    TEST_REQUIRE_GOTO(__run_flush_filters(NULL, fx.response) == CWF_OK, "head sent before disconnect", cleanup);
    close(fx.rd_fd);
    fx.rd_fd = -1;
    /* Production signal_init ignores SIGPIPE. Restore the runner's disposition
     * afterwards: sendfile has no MSG_NOSIGNAL argument. */
    struct sigaction ignored = {.sa_handler = SIG_IGN}, previous;
    sigemptyset(&ignored.sa_mask);
    TEST_REQUIRE_GOTO(sigaction(SIGPIPE, &ignored, &previous) == 0, "ignore SIGPIPE", cleanup);
    const int result = __run_body_filters(NULL, fx.response);
    sigaction(SIGPIPE, &previous, NULL);
    TEST_ASSERT_EQUAL(CWF_ERROR, result, "disconnected client fails");
    TEST_ASSERT_EQUAL_SIZE(0, fx.response->body_bytes_sent, "no file bytes sent");
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_buffered_continuation_bounds) {
    TEST_SUITE("http_write_filter: sendfile");
    TEST_CASE("buffered continuation starts at the saved offset and obeys the promised length");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", 10), "file staged", cleanup);
    fx.response->file_.size = 7;
    http_module_data_t* data = sendfile_data_module(&fx);
    /* Model fallback after an initial prefix has already been sent. The file
     * now has bytes beyond the advertised length; they must not leak into the
     * following keep-alive response. */
    data->sendfile_disabled = 1;
    data->file_offset = 3;
    fx.response->body_bytes_sent = 3;
    TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "head prepared", cleanup);
    const size_t head_size = sendfile_head_size(&fx);
    TEST_REQUIRE_GOTO(__run_flush_filters(NULL, fx.response) == CWF_OK, "head flushed", cleanup);
    TEST_REQUIRE_GOTO(send(fx.wr_fd, "012", 3, MSG_NOSIGNAL) == 3, "initial prefix sent", cleanup);
    TEST_REQUIRE_GOTO(__run_body_filters(NULL, fx.response) == CWF_OK, "continuation sent", cleanup);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "wire captured", cleanup);
    TEST_ASSERT_EQUAL_SIZE(head_size + 7, fx.captured_size, "advertised length respected");
    TEST_ASSERT(memcmp(fx.captured + head_size, "0123456", 7) == 0, "no repeated prefix or extra suffix");
    TEST_ASSERT_EQUAL_SIZE(7, fx.response->body_bytes_sent, "counter includes both paths");
    fx.response->base.reset(fx.response);
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "short", 5), "short file staged", cleanup);
    fx.response->file_.size = 10;
    sendfile_data_module(&fx)->sendfile_disabled = 1;
    TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "next head prepared", cleanup);
    TEST_ASSERT_EQUAL(CWF_ERROR, __run_body_filters(NULL, fx.response), "buffered premature EOF also fails");
    TEST_ASSERT_EQUAL_SIZE(5, fx.response->body_bytes_sent, "buffered actual bytes counted");
    cleanup:
    fixture_teardown(&fx);
}

static http_module_range_t* sendfile_range_module(write_fixture_t* fx) {
    return fx->response->filter->next->module;
}

static int sendfile_request_range(httprequest_t* request, ssize_t start, ssize_t end) {
    http_ranges_free(request->ranges);
    request->ranges = httpresponse_init_ranges();
    if (request->ranges == NULL) return 0;
    request->ranges->start = start;
    request->ranges->end = end;
    return 1;
}

TEST(test_sendfile_single_range_forms_and_bodiless) {
    TEST_SUITE("http_write_filter: range sendfile");
    TEST_CASE("resolved, open, suffix and clamped ranges send only their selected bytes");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    struct { ssize_t start, end; size_t first, length, file_size; int head, status; const char* cr; } cases[] = {
        {2, 5, 2, 4, 10, 0, 206, "bytes 2-5/10"},
        {5, -1, 5, 5, 10, 0, 206, "bytes 5-9/10"},
        {-1, 4, 6, 4, 10, 0, 206, "bytes 6-9/10"},
        {8, 100, 8, 2, 10, 0, 206, "bytes 8-9/10"},
        {4, 4, 4, 1, 10, 0, 206, "bytes 4-4/10"},
        {10, 99, 0, 0, 10, 0, 416, "bytes */10"},
        {0, 0, 0, 0, 0, 0, 416, "bytes */0"},
        {2, 5, 2, 4, 10, 1, 206, "bytes 2-5/10"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", cases[i].file_size), "file staged", cleanup_request);
        request->method = cases[i].head ? ROUTE_HEAD : ROUTE_GET;
        TEST_REQUIRE_GOTO(sendfile_request_range(request, cases[i].start, cases[i].end), "range staged", cleanup_request);
        TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "headers prepared", cleanup_request);
        TEST_ASSERT_EQUAL(cases[i].status, fx.response->status_code, "range status");
        http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
        http_header_t* cl = fx.response->get_header(fx.response, "Content-Length");
        TEST_REQUIRE_GOTO(cr != NULL && cl != NULL, "range framing headers present", cleanup_request);
        TEST_ASSERT_STR_EQUAL(cases[i].cr, cr->value, "content range unchanged");
        TEST_ASSERT_EQUAL_SIZE(cases[i].length, strtoull(cl->value, NULL, 10), "advertised range length");
        const size_t head = sendfile_head_size(&fx);
        TEST_REQUIRE_GOTO(__run_body_filters(request, fx.response) == CWF_OK, "body completes", cleanup_request);
        TEST_REQUIRE_GOTO(__run_flush_filters(request, fx.response) == CWF_OK, "head flushed", cleanup_request);
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "wire captured", cleanup_request);
        const size_t body = cases[i].head ? 0 : cases[i].length;
        TEST_ASSERT_EQUAL_SIZE(head + body, fx.captured_size, "exact wire length");
        TEST_ASSERT(memcmp(fx.captured + head, "0123456789" + cases[i].first, body) == 0, "exact selected bytes");
        TEST_ASSERT_EQUAL_SIZE(body, fx.response->body_bytes_sent, "range bytes counted");
        TEST_ASSERT(body > 0 ? sendfile_range_module(&fx)->buf->data != NULL : sendfile_range_module(&fx)->buf->size == 0, "small ranges use a buffer; HEAD and 416 do not read");
        TEST_ASSERT(fx.response->body.data == NULL, "no data read buffer");
        fx.response->base.reset(fx.response);
        fx.captured_size = 0;
    }
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_single_range_partial_and_reuse) {
    TEST_SUITE("http_write_filter: range sendfile");
    TEST_CASE("partial head and multi-megabyte range resume at the right offset; reset permits a new range");
    const size_t start = 777, length = 2 * 1024 * 1024 + 73, size = start + length + 97;
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, size + 32768), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    char* payload = malloc(size);
    TEST_REQUIRE_GOTO(payload != NULL, "payload allocated", cleanup_request);
    for (size_t i = 0; i < size; ++i) payload[i] = (char)(i * 31);
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, payload, size), "file staged", cleanup_payload);
    request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(sendfile_request_range(request, start, start + length - 1), "range staged", cleanup_payload);
    TEST_REQUIRE_GOTO(fixture_shrink_sndbuf(&fx), "small socket buffer", cleanup_payload);
    char value[16384];
    memset(value, 'h', sizeof(value) - 1); value[sizeof(value) - 1] = 0;
    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "X-Large", value), "large header", cleanup_payload);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "headers prepared", cleanup_payload);
    const size_t head = sendfile_head_size(&fx);
    int r = __run_body_filters(request, fx.response);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "partial head yields");
    TEST_ASSERT_EQUAL_SIZE(0, sendfile_range_module(&fx)->range_pos, "range waits for complete head");
    int guard = 0;
    while (r == CWF_EVENT_AGAIN && guard++ < 4000) {
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "drain between resumes", cleanup_payload);
        r = __run_body_filters(request, fx.response);
    }
    TEST_REQUIRE_GOTO(r == CWF_OK, "range completes", cleanup_payload);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "final drain", cleanup_payload);
    TEST_ASSERT_EQUAL_SIZE(head + length, fx.captured_size, "no suffix beyond range");
    TEST_ASSERT(memcmp(fx.captured + head, payload + start, length) == 0, "no repeated or missing range bytes");
    TEST_ASSERT_EQUAL_SIZE(length, fx.response->body_bytes_sent, "selected length counted");
    TEST_ASSERT_EQUAL_SIZE(length, sendfile_range_module(&fx)->range_pos, "range progress complete");
    TEST_ASSERT(sendfile_range_module(&fx)->buf->data == NULL, "no range buffer");
    TEST_ASSERT_EQUAL((long long)size, (long long)lseek(fx.response->file_.fd, 0, SEEK_CUR), "descriptor position unchanged");
    fx.response->base.reset(fx.response); fx.captured_size = 0;
    TEST_ASSERT_EQUAL_SIZE(0, sendfile_range_module(&fx)->range_pos, "range progress reset");
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "second", 6), "second file", cleanup_payload);
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 1, 3), "second range", cleanup_payload);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "second header", cleanup_payload);
    const size_t second_head = sendfile_head_size(&fx);
    TEST_REQUIRE_GOTO(__run_body_filters(request, fx.response) == CWF_OK, "second range sent", cleanup_payload);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "second drain", cleanup_payload);
    TEST_ASSERT_EQUAL_SIZE(second_head + 3, fx.captured_size, "second response length");
    TEST_ASSERT(memcmp(fx.captured + second_head, "eco", 3) == 0, "second range starts independently");
    cleanup_payload:
    free(payload);
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_single_range_fallback_and_continuation) {
    TEST_SUITE("http_write_filter: range sendfile");
    TEST_CASE("unsupported file falls back within the range; a saved prefix is not repeated");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 16384), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    request->method = ROUTE_GET;
    const int fd = open("/proc/self/cmdline", O_RDONLY);
    TEST_REQUIRE_GOTO(fd >= 0, "proc opened", cleanup_request);
    fx.response->file_.fd = fd;
    char expected[4096];
    const ssize_t size = pread(fd, expected, sizeof(expected), 0);
    TEST_REQUIRE_GOTO(size > 6, "proc bytes read", cleanup_request);
    fx.response->file_.size = (size_t)size;
    const size_t length = (size_t)size - 4;
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 2, size - 3), "proc range", cleanup_request);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "proc header", cleanup_request);
    const size_t head = sendfile_head_size(&fx);
    TEST_REQUIRE_GOTO(sendfile_probe_unsupported(&fx, 2, (size_t)size - 2) == CWF_DATA_AGAIN,
                      "procfs range writer requests fallback", cleanup_request);
    sendfile_range_module(&fx)->sendfile_disabled = 1;
    TEST_REQUIRE_GOTO(__run_body_filters(request, fx.response) == CWF_OK, "fallback completes", cleanup_request);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "proc drain", cleanup_request);
    TEST_ASSERT(sendfile_range_module(&fx)->sendfile_disabled, "sendfile rejected for this response");
    TEST_ASSERT_EQUAL_SIZE(head + length, fx.captured_size, "fallback exact length");
    TEST_ASSERT(memcmp(fx.captured + head, expected + 2, length) == 0, "fallback selected bytes");
    fx.response->base.reset(fx.response); fx.captured_size = 0;
    TEST_ASSERT(!sendfile_range_module(&fx)->sendfile_disabled, "fallback flag resets");
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", 10), "next file", cleanup_request);
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 2, 7), "next range", cleanup_request);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "next header", cleanup_request);
    const size_t second_head = sendfile_head_size(&fx);
    TEST_REQUIRE_GOTO(__run_flush_filters(request, fx.response) == CWF_OK, "head sent", cleanup_request);
    TEST_REQUIRE_GOTO(send(fx.wr_fd, "23", 2, MSG_NOSIGNAL) == 2, "prefix sent", cleanup_request);
    sendfile_range_module(&fx)->sendfile_disabled = 1;
    sendfile_range_module(&fx)->range_pos = 2;
    fx.response->body_bytes_sent = 2;
    TEST_REQUIRE_GOTO(__run_body_filters(request, fx.response) == CWF_OK, "continuation completes", cleanup_request);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "continuation drain", cleanup_request);
    TEST_ASSERT_EQUAL_SIZE(second_head + 6, fx.captured_size, "continuation exact length");
    TEST_ASSERT(memcmp(fx.captured + second_head, "234567", 6) == 0, "prefix neither skipped nor repeated");
    TEST_ASSERT_EQUAL_SIZE(6, fx.response->body_bytes_sent, "both paths counted");
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_single_range_truncated) {
    TEST_SUITE("http_write_filter: range sendfile");
    TEST_CASE("EOF before range end fails on sendfile and on buffered fallback");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    request->method = ROUTE_GET;
    for (int mode = 0; mode < 3; ++mode) {
        bufo_clear(sendfile_range_module(&fx)->buf);
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", 10), "file staged", cleanup_request);
        fx.response->file_.size = mode == 0 ? 10 : HTTP_FILE_BUFFER_MAX + 10;
        TEST_REQUIRE_GOTO(sendfile_request_range(request, 2, mode == 0 ? 7 : HTTP_FILE_BUFFER_MAX + 7), "range staged", cleanup_request);
        TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "headers prepared", cleanup_request);
        TEST_REQUIRE_GOTO(ftruncate(fx.response->file_.fd, 5) == 0, "file truncated after headers", cleanup_request);
        sendfile_range_module(&fx)->sendfile_disabled = mode == 2;
        TEST_ASSERT_EQUAL(CWF_ERROR, __run_body_filters(request, fx.response), "short range fails");
        TEST_ASSERT_EQUAL_SIZE(3, fx.response->body_bytes_sent, "only available range bytes counted");
        TEST_ASSERT((sendfile_range_module(&fx)->buf->data == NULL) == (mode == 1), "small, sendfile and forced buffered range paths exercised");
        fx.response->base.reset(fx.response);
    }
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_single_range_if_range) {
    TEST_SUITE("http_write_filter: range sendfile");
    TEST_CASE("If-Range matches only a valid strong ETag; other validators select the full response");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    const char* conditions[] = {"\"v1\"", "\"other\"", "W/\"v1\"", "Sun, 06 Nov 1994 08:49:37 GMT", "\"v1\", \"other\"", "\"v1\"", "\"v1\""};
    for (size_t i = 0; i < sizeof(conditions) / sizeof(conditions[0]); ++i) {
        httprequest_t* request = httprequest_create(fx.conn);
        TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
        request->method = ROUTE_GET;
        int ok = sendfile_stage_file(&fx, "0123456789", 10) &&
                 sendfile_request_range(request, 2, 5) &&
                 request->add_header(request, "If-Range", conditions[i]) == 0;
        if (i != 6) ok = ok && fx.response->add_header(fx.response, "ETag", i == 5 ? "W/\"v1\"" : "\"v1\"");
        if (i == 3) ok = ok && fx.response->add_header(fx.response, "Last-Modified", conditions[i]);
        TEST_ASSERT(ok, "request and validator staged");
        if (!ok) { httprequest_free(request); goto cleanup; }
        TEST_ASSERT_EQUAL(CWF_OK, __run_header_filters(request, fx.response), "header condition evaluated");
        const size_t head = sendfile_head_size(&fx);
        TEST_ASSERT_EQUAL(i == 0 ? 206 : 200, fx.response->status_code, "strong comparison selects status");
        TEST_ASSERT_EQUAL(CWF_OK, __run_body_filters(request, fx.response), "selected body sent");
        TEST_ASSERT(fixture_drain(&fx), "wire drained");
        const size_t size = i == 0 ? 4 : 10;
        TEST_ASSERT_EQUAL_SIZE(head + size, fx.captured_size, "selected body length");
        TEST_ASSERT(memcmp(fx.captured + head, i == 0 ? "2345" : "0123456789", size) == 0, "selected representation bytes");
        httprequest_free(request);
        fx.response->base.reset(fx.response); fx.captured_size = 0;
    }
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_writer_selection_and_multipart) {
    TEST_SUITE("http_write_filter: range sendfile");
    TEST_CASE("TLS and HTTP/2 cannot select the raw writer; small multipart keeps its framing");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", 10), "file staged", cleanup);
    TEST_ASSERT(http_file_writer(fx.response, fx.response->filter) != NULL, "cleartext HTTP/1 writer selected");
    fx.conn->ssl = (SSL*)1; /* selection only; no TLS I/O with the sentinel */
    TEST_ASSERT(http_file_writer(fx.response, fx.response->filter) == NULL, "TLS excluded");
    fx.conn->ssl = NULL;
    http_filter_t* h2 = filters_create_h2();
    TEST_REQUIRE_GOTO(h2 != NULL, "HTTP/2 chain created", cleanup);
    TEST_ASSERT(http_file_writer(fx.response, h2) == NULL, "h2c excluded by terminal writer");
    filters_free(h2);
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 2, 3), "first range", cleanup_request);
    request->ranges->next = httpresponse_init_ranges();
    TEST_REQUIRE_GOTO(request->ranges->next != NULL, "second range", cleanup_request);
    request->ranges->next->start = 6; request->ranges->next->end = 7;
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "multipart header", cleanup_request);
    http_module_range_t* range = sendfile_range_module(&fx);
    TEST_ASSERT(range->mp_active, "multipart mode preserved");
    const size_t head = sendfile_head_size(&fx);
    char expected[1024];
    const int length = snprintf(expected, sizeof(expected),
        "--%s\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes 2-3/10\r\n\r\n23\r\n"
        "--%s\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes 6-7/10\r\n\r\n67\r\n"
        "--%s--\r\n", range->boundary, range->boundary, range->boundary);
    TEST_REQUIRE_GOTO(length > 0 && (size_t)length < sizeof(expected), "expected multipart built", cleanup_request);
    TEST_REQUIRE_GOTO(__run_body_filters(request, fx.response) == CWF_OK, "multipart body", cleanup_request);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "multipart drain", cleanup_request);
    TEST_ASSERT(range->buf->data != NULL, "small multipart uses the combined buffered path");
    TEST_ASSERT_EQUAL_SIZE(head + (size_t)length, fx.captured_size, "multipart wire length");
    TEST_ASSERT(memcmp(fx.captured + head, expected, (size_t)length) == 0, "multipart framing unchanged");
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

static int sendfile_append_range(httprequest_t* request, ssize_t start, ssize_t end) {
    http_ranges_t** tail = &request->ranges;
    while (*tail != NULL) tail = &(*tail)->next;
    *tail = httpresponse_init_ranges();
    if (*tail == NULL) return 0;
    (*tail)->start = start; (*tail)->end = end;
    return 1;
}

/* Independent wire oracle: each header, selected source bytes, CRLF, and the
 * closing boundary. Content-Length is checked against the resulting bytes. */
static char* sendfile_multipart_expected(write_fixture_t* fx, const char* source, size_t* length) {
    http_module_range_t* m = sendfile_range_module(fx);
    const http_header_t* cl = fx->response->get_header(fx->response, "Content-Length");
    if (cl == NULL) return NULL;
    const size_t capacity = strtoull(cl->value, NULL, 10) + 1;
    char* expected = malloc(capacity);
    if (expected == NULL) return NULL;
    size_t pos = 0;
    for (size_t i = 0; i < m->parts_count; ++i) {
        const http_range_part_t* p = &m->parts[i];
        const int n = snprintf(expected + pos, capacity - pos,
            "--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zu-%zu/%zu\r\n\r\n",
            m->boundary, m->part_ctype, p->start, p->start + p->size - 1, m->mp_total);
        if (n < 0 || (size_t)n >= capacity - pos) goto failed;
        pos += (size_t)n;
        if (p->size + 2 >= capacity - pos) goto failed;
        memcpy(expected + pos, source + p->start, p->size); pos += p->size;
        memcpy(expected + pos, "\r\n", 2); pos += 2;
    }
    const int n = snprintf(expected + pos, capacity - pos, "--%s--\r\n", m->boundary);
    if (n < 0 || (size_t)n >= capacity - pos) goto failed;
    *length = pos + (size_t)n;
    return expected;
    failed:
    free(expected);
    return NULL;
}

TEST(test_sendfile_multipart_partial_and_midpart_fallback) {
    TEST_SUITE("http_write_filter: multipart sendfile");
    TEST_CASE("partial HTTP and part headers, file spans and fallback preserve the exact multipart wire body");
    const size_t size = 2 * 1024 * 1024 + 211;
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 3 * size), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    char* payload = malloc(size);
    TEST_REQUIRE_GOTO(payload != NULL, "payload allocated", cleanup_request);
    for (size_t i = 0; i < size; ++i) payload[i] = (char)(i * 31);
    TEST_REQUIRE_GOTO(fixture_shrink_sndbuf(&fx), "small socket buffer", cleanup_payload);
    char ctype[20001];
    memset(ctype, 'a', sizeof(ctype) - 1); ctype[sizeof(ctype) - 1] = 0;
    request->method = ROUTE_GET;
    for (int fallback = 0; fallback < 2; ++fallback) {
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, payload, size), "file staged", cleanup_payload);
        TEST_REQUIRE_GOTO(sendfile_request_range(request, 777, size - 100), "large first part", cleanup_payload);
        TEST_REQUIRE_GOTO(sendfile_append_range(request, 0, 31), "earlier second part", cleanup_payload);
        TEST_REQUIRE_GOTO(sendfile_append_range(request, 999, 1040), "overlapping third part", cleanup_payload);
        TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Type", ctype), "long part header", cleanup_payload);
        TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "X-Large", ctype), "long HTTP head", cleanup_payload);
        TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "headers prepared", cleanup_payload);
        const size_t head = sendfile_head_size(&fx);
        size_t expected_size;
        char* expected = sendfile_multipart_expected(&fx, payload, &expected_size);
        TEST_REQUIRE_GOTO(expected != NULL, "wire oracle built", cleanup_payload);
        http_module_range_t* m = sendfile_range_module(&fx);
        int r = __run_body_filters(request, fx.response);
        TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "HTTP head pauses");
        TEST_ASSERT_EQUAL_SIZE(0, m->text_pos, "no multipart text before full HTTP head");
        int guard = 0, switched = 0, partial_text = 0, partial_data = 0;
        while (r == CWF_EVENT_AGAIN && guard++ < 5000) {
            if (m->text_pos > 0 && m->text_pos < m->text_len) partial_text = 1;
            if (m->data_pos > 0 && m->part_index == 0 && m->data_pos < m->parts[0].size) {
                partial_data = 1;
                if (fallback && !switched) { m->sendfile_disabled = 1; switched = 1; }
            }
            if (!fixture_drain(&fx)) { r = CWF_ERROR; break; }
            r = __run_body_filters(request, fx.response);
        }
        TEST_ASSERT_EQUAL(CWF_OK, r, "multipart completes");
        TEST_ASSERT(partial_text, "EAGAIN inside part text exercised");
        TEST_ASSERT(partial_data, "EAGAIN inside file part exercised");
        TEST_ASSERT(!fallback || switched, "buffered continuation starts after file progress");
        TEST_ASSERT(fixture_drain(&fx), "final drain");
        TEST_ASSERT_EQUAL_SIZE(head + expected_size, fx.captured_size, "exact framed length");
        TEST_ASSERT(memcmp(fx.captured + head, expected, expected_size) == 0, "boundaries, data and order match");
        TEST_ASSERT_EQUAL_SIZE(expected_size, fx.response->body_bytes_sent, "actual multipart bytes counted once");
        TEST_ASSERT(fallback || m->buf->data == NULL, "sendfile does not allocate a read buffer");
        TEST_ASSERT_EQUAL((long long)size, (long long)lseek(fx.response->file_.fd, 0, SEEK_CUR), "shared file offset unchanged");
        free(expected);
        fx.response->base.reset(fx.response); fx.captured_size = 0;
        TEST_ASSERT(!m->sendfile_disabled && m->part_index == 0 && m->data_pos == 0 && m->text_pos == 0,
                    "keep-alive resets multipart progress and fallback");
    }
    cleanup_payload:
    free(payload);
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_multipart_proc_fallback_head_and_if_range) {
    TEST_SUITE("http_write_filter: multipart sendfile");
    TEST_CASE("procfs fallback does not repeat the first part header; HEAD and If-Range retain semantics");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 16384), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    request->method = ROUTE_GET;
    const int fd = open("/proc/self/cmdline", O_RDONLY);
    TEST_REQUIRE_GOTO(fd >= 0, "proc opened", cleanup_request);
    fx.response->file_.fd = fd;
    char source[4096];
    const ssize_t size = pread(fd, source, sizeof(source), 0);
    TEST_REQUIRE_GOTO(size > 10, "proc bytes read", cleanup_request);
    fx.response->file_.size = (size_t)size;
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 2, 8), "first part", cleanup_request);
    TEST_REQUIRE_GOTO(sendfile_append_range(request, 0, 1), "second part", cleanup_request);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "proc header", cleanup_request);
    const size_t head = sendfile_head_size(&fx);
    size_t expected_size;
    char* expected = sendfile_multipart_expected(&fx, source, &expected_size);
    TEST_REQUIRE_GOTO(expected != NULL, "wire oracle built", cleanup_request);
    TEST_REQUIRE_GOTO(sendfile_probe_unsupported(&fx, 2, 9) == CWF_DATA_AGAIN,
                      "procfs multipart source rejects sendfile", cleanup_request);
    sendfile_range_module(&fx)->sendfile_disabled = 1;
    TEST_ASSERT_EQUAL(CWF_OK, __run_body_filters(request, fx.response), "fallback completes");
    TEST_ASSERT(fixture_drain(&fx), "fallback drain");
    TEST_ASSERT(sendfile_range_module(&fx)->sendfile_disabled, "unsupported descriptor disables sendfile");
    TEST_ASSERT_EQUAL_SIZE(head + expected_size, fx.captured_size, "fallback framed length");
    TEST_ASSERT(memcmp(fx.captured + head, expected, expected_size) == 0, "first header appears exactly once");
    TEST_ASSERT_EQUAL_SIZE(expected_size, fx.response->body_bytes_sent, "fallback counter");
    free(expected);
    fx.response->base.reset(fx.response); fx.captured_size = 0;
    for (int mode = 0; mode < 3; ++mode) {
        request->method = mode == 0 ? ROUTE_HEAD : ROUTE_GET;
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", 10), "next file", cleanup_request);
        if (mode != 0) {
            request->remove_header(request, "If-Range");
            TEST_REQUIRE_GOTO(request->add_header(request, "If-Range", mode == 1 ? "\"match\"" : "\"other\"") == 0,
                              "If-Range set", cleanup_request);
            TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "ETag", "\"match\""), "strong ETag", cleanup_request);
        }
        TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "next header", cleanup_request);
        const size_t next_head = sendfile_head_size(&fx);
        TEST_ASSERT_EQUAL(mode == 2 ? 200 : 206, fx.response->status_code, "conditional status");
        TEST_ASSERT_EQUAL(CWF_OK, __run_body_filters(request, fx.response), "next body");
        TEST_ASSERT_EQUAL(CWF_OK, __run_flush_filters(request, fx.response), "flush HEAD");
        TEST_ASSERT(fixture_drain(&fx), "next drain");
        if (mode == 0) {
            TEST_ASSERT_EQUAL_SIZE(next_head, fx.captured_size, "HEAD sends no multipart body");
            TEST_ASSERT(sendfile_range_module(&fx)->buf->size == 0, "HEAD reads no file data");
        }
        else if (mode == 2) {
            TEST_ASSERT_EQUAL_SIZE(next_head + 10, fx.captured_size, "mismatched If-Range sends full file");
            TEST_ASSERT(memcmp(fx.captured + next_head, "0123456789", 10) == 0, "full representation");
        }
        else {
            expected = sendfile_multipart_expected(&fx, "0123456789", &expected_size);
            TEST_ASSERT(expected != NULL, "conditional multipart oracle");
            if (expected != NULL) {
                TEST_ASSERT_EQUAL_SIZE(next_head + expected_size, fx.captured_size, "conditional multipart length");
                TEST_ASSERT(memcmp(fx.captured + next_head, expected, expected_size) == 0, "matching If-Range sends multipart");
                free(expected);
            }
        }
        fx.response->base.reset(fx.response); fx.captured_size = 0;
    }
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_sendfile_multipart_truncated_and_one_surviving_part) {
    TEST_SUITE("http_write_filter: multipart sendfile");
    TEST_CASE("one surviving range keeps multipart framing; a later truncated part fails on both paths");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", 10), "file staged", cleanup_request);
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 99, 100), "unsatisfiable part", cleanup_request);
    TEST_REQUIRE_GOTO(sendfile_append_range(request, 2, 4), "surviving part", cleanup_request);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "multipart header", cleanup_request);
    const size_t head = sendfile_head_size(&fx);
    size_t expected_size;
    char* expected = sendfile_multipart_expected(&fx, "0123456789", &expected_size);
    TEST_REQUIRE_GOTO(expected != NULL, "surviving part oracle", cleanup_request);
    TEST_ASSERT_EQUAL_SIZE(1, sendfile_range_module(&fx)->parts_count, "one range survives");
    TEST_ASSERT_EQUAL(CWF_OK, __run_body_filters(request, fx.response), "one-part multipart sent");
    TEST_ASSERT(fixture_drain(&fx), "multipart drain");
    TEST_ASSERT_EQUAL_SIZE(head + expected_size, fx.captured_size, "one-part multipart length");
    TEST_ASSERT(memcmp(fx.captured + head, expected, expected_size) == 0, "one-part multipart framed correctly");
    free(expected);
    fx.response->base.reset(fx.response); fx.captured_size = 0;
    char ctype[HTTP_MULTIPART_BUFFER_MAX / 2 + 1];
    memset(ctype, 'x', sizeof(ctype) - 1); ctype[sizeof(ctype) - 1] = 0;
    for (int buffered = 0; buffered < 2; ++buffered) {
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", 10), "next file", cleanup_request);
        TEST_REQUIRE_GOTO(sendfile_request_range(request, 0, 1), "first available part", cleanup_request);
        TEST_REQUIRE_GOTO(sendfile_append_range(request, 7, 9), "later part", cleanup_request);
        bufo_clear(sendfile_range_module(&fx)->buf);
        TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Type", ctype), "large framing selects sendfile", cleanup_request);
        TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "next header", cleanup_request);
        TEST_REQUIRE_GOTO(ftruncate(fx.response->file_.fd, 8) == 0, "truncate after framing", cleanup_request);
        sendfile_range_module(&fx)->sendfile_disabled = buffered;
        TEST_ASSERT_EQUAL(CWF_ERROR, __run_body_filters(request, fx.response), "truncated multipart fails");
        TEST_ASSERT((sendfile_range_module(&fx)->buf->data != NULL) == buffered, "both multipart transports exercised");
        fx.response->base.reset(fx.response); fx.captured_size = 0;
    }
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

static void* sendfile_multipart_reader(void* arg) {
    write_fixture_t* fx = arg;
    while (fx->captured_size < fx->captured_capacity) {
        const ssize_t n = recv(fx->rd_fd, fx->captured + fx->captured_size,
                               fx->captured_capacity - fx->captured_size, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        fx->captured_size += (size_t)n;
    }
    return NULL;
}

TEST(test_sendfile_multipart_budget_across_parts) {
    TEST_SUITE("http_write_filter: multipart sendfile");
    TEST_CASE("one worker pass sends at most 1 MiB of file data across several parts");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 2 * 1024 * 1024), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    const size_t part_size = 400 * 1024;
    char* payload = malloc(part_size);
    TEST_REQUIRE_GOTO(payload != NULL, "payload allocated", cleanup_request);
    memset(payload, 'x', part_size);
    request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, payload, part_size), "file staged", cleanup_payload);
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 0, part_size - 1), "first part", cleanup_payload);
    for (int i = 0; i < 3; ++i)
        TEST_REQUIRE_GOTO(sendfile_append_range(request, 0, part_size - 1), "another part", cleanup_payload);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "headers prepared", cleanup_payload);
    const size_t head = sendfile_head_size(&fx);
    size_t expected_size;
    char* expected = sendfile_multipart_expected(&fx, payload, &expected_size);
    TEST_REQUIRE_GOTO(expected != NULL, "wire oracle", cleanup_payload);
    /* Blocking sockets and a concurrent reader remove EAGAIN as a source of
     * yields, so the first pause must come from the shared file budget. */
    TEST_REQUIRE_GOTO(fcntl(fx.wr_fd, F_SETFL, fcntl(fx.wr_fd, F_GETFL) & ~O_NONBLOCK) == 0,
                      "blocking writer", cleanup_expected);
    TEST_REQUIRE_GOTO(fcntl(fx.rd_fd, F_SETFL, fcntl(fx.rd_fd, F_GETFL) & ~O_NONBLOCK) == 0,
                      "blocking reader", cleanup_expected);
    pthread_t reader;
    TEST_REQUIRE_GOTO(pthread_create(&reader, NULL, sendfile_multipart_reader, &fx) == 0,
                      "reader started", cleanup_expected);
    http_module_range_t* m = sendfile_range_module(&fx);
    int result = CWF_EVENT_AGAIN, passes = 0;
    size_t previous_data = 0;
    while (result == CWF_EVENT_AGAIN && passes++ < 10) {
        result = __run_body_filters(request, fx.response);
        size_t data = 0;
        for (size_t i = 0; i < m->part_index; ++i) data += m->parts[i].size;
        if (m->part_index < m->parts_count) data += m->data_pos;
        TEST_ASSERT(data - previous_data <= 1024 * 1024, "aggregate file budget respected");
        if (passes == 1) TEST_ASSERT_EQUAL_SIZE(1024 * 1024, data, "first pass stops inside third part");
        previous_data = data;
    }
    shutdown(fx.wr_fd, SHUT_WR);
    pthread_join(reader, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, result, "multipart completes");
    TEST_ASSERT_EQUAL(2, passes, "shared budget requires exactly two passes");
    TEST_ASSERT_EQUAL_SIZE(head + expected_size, fx.captured_size, "budget resumes preserve wire length");
    TEST_ASSERT(memcmp(fx.captured + head, expected, expected_size) == 0, "budget resumes preserve all boundaries and bytes");
    TEST_ASSERT_EQUAL_SIZE(expected_size, fx.response->body_bytes_sent, "budget counter exact");
    cleanup_expected:
    free(expected);
    cleanup_payload:
    free(payload);
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_file_hybrid_boundary_and_keepalive) {
    TEST_SUITE("http_write_filter: hybrid files");
    TEST_CASE("small files join the head; the threshold boundary resets on keep-alive");
    write_fixture_t fx;
    const size_t limit = HTTP_FILE_BUFFER_MAX;
    TEST_REQUIRE(fixture_setup(&fx, limit + 8192), "fixture created");
    char* payload = malloc(limit + 1);
    TEST_REQUIRE_GOTO(payload != NULL, "payload allocated", cleanup);
    for (size_t i = 0; i <= limit; i++) payload[i] = (char)(i * 13);
    const size_t sizes[] = {limit, limit + 1, 200, 0};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, payload, sizes[i]), "file staged", cleanup_payload);
        TEST_REQUIRE_GOTO(__run_header_filters(NULL, fx.response) == CWF_OK, "head prepared", cleanup_payload);
        const size_t head = sendfile_head_size(&fx);
        TEST_REQUIRE_GOTO(__run_body_filters(NULL, fx.response) == CWF_OK, "body sent", cleanup_payload);
        TEST_REQUIRE_GOTO(__run_flush_filters(NULL, fx.response) == CWF_OK, "empty head flushed", cleanup_payload);
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "wire captured", cleanup_payload);
        TEST_ASSERT_EQUAL_SIZE(head + sizes[i], fx.captured_size, "exact wire length");
        TEST_ASSERT(memcmp(fx.captured + head, payload, sizes[i]) == 0, "exact bytes");
        TEST_ASSERT((fx.response->body.data != NULL) == (sizes[i] > 0 && sizes[i] <= limit), "transport follows selected body size");
        TEST_ASSERT_EQUAL_SIZE(sizes[i], fx.response->body_bytes_sent, "body bytes counted once");
        fx.response->base.reset(fx.response);
        fx.captured_size = 0;
    }
    cleanup_payload:
    free(payload);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_small_range_uses_selected_length_and_one_write) {
    TEST_SUITE("http_write_filter: hybrid files");
    TEST_CASE("a short range of a large file is joined to the header in one socket write");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup_type(&fx, 8192, SOCK_SEQPACKET), "packet fixture created");
    const size_t size = HTTP_FILE_BUFFER_MAX + 1024;
    char* payload = malloc(size);
    TEST_REQUIRE_GOTO(payload != NULL, "payload allocated", cleanup);
    for (size_t i = 0; i < size; i++) payload[i] = (char)i;
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, payload, size), "large file staged", cleanup_payload);
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup_payload);
    request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 777, 976), "short range selected", cleanup_request);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "head prepared", cleanup_request);
    const size_t head = sendfile_head_size(&fx);
    TEST_REQUIRE_GOTO(__run_body_filters(request, fx.response) == CWF_OK, "range sent", cleanup_request);
    const ssize_t bytes = recv(fx.rd_fd, fx.captured, fx.captured_capacity, 0);
    TEST_ASSERT_EQUAL_SIZE(head + 200, bytes > 0 ? (size_t)bytes : 0, "head and range share one write");
    TEST_ASSERT(bytes > 0 && memcmp(fx.captured + head, payload + 777, 200) == 0, "correct range offset");
    TEST_ASSERT(recv(fx.rd_fd, fx.captured, fx.captured_capacity, 0) == -1 && errno == EAGAIN, "no second write");
    TEST_ASSERT(fx.response->body.data == NULL, "whole file was not read");
    cleanup_request:
    httprequest_free(request);
    cleanup_payload:
    free(payload);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_small_multipart_join_and_partial_resume) {
    TEST_SUITE("http_write_filter: hybrid files");
    TEST_CASE("small multipart shares one write with the head and resumes a partial joined head exactly");
    char payload[200];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (char)(i * 17);
    for (int partial = 0; partial < 2; ++partial) {
        write_fixture_t fx;
        TEST_REQUIRE(fixture_setup_type(&fx, 32768, partial ? SOCK_STREAM : SOCK_SEQPACKET), "fixture created");
        httprequest_t* request = httprequest_create(fx.conn);
        TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
        request->method = ROUTE_GET;
        TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, payload, sizeof(payload)), "small file staged", cleanup_request);
        TEST_REQUIRE_GOTO(sendfile_request_range(request, 0, 49), "first part", cleanup_request);
        TEST_REQUIRE_GOTO(sendfile_append_range(request, 150, 199), "second part", cleanup_request);
        if (partial) {
            char value[20001];
            memset(value, 'x', sizeof(value) - 1); value[sizeof(value) - 1] = 0;
            TEST_REQUIRE_GOTO(fixture_shrink_sndbuf(&fx), "small send buffer", cleanup_request);
            TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "X-Large", value), "long head staged", cleanup_request);
        }
        TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "head prepared", cleanup_request);
        const size_t head = sendfile_head_size(&fx);
        size_t expected_size;
        char* expected = sendfile_multipart_expected(&fx, payload, &expected_size);
        TEST_REQUIRE_GOTO(expected != NULL, "multipart oracle built", cleanup_request);
        TEST_ASSERT_EQUAL_SIZE(expected_size, sendfile_range_module(&fx)->mp_size, "threshold includes multipart framing");
        int r = __run_body_filters(request, fx.response);
        TEST_ASSERT_EQUAL(partial ? CWF_EVENT_AGAIN : CWF_OK, r, "joined write outcome");
        if (partial) {
            int guard = 0;
            while (r == CWF_EVENT_AGAIN && guard++ < 128) {
                if (!fixture_drain(&fx)) { r = CWF_ERROR; break; }
                r = __run_body_filters(request, fx.response);
            }
            TEST_ASSERT_EQUAL(CWF_OK, r, "partial multipart completes");
            TEST_ASSERT(fixture_drain(&fx), "remaining bytes captured");
        }
        else {
            const ssize_t n = recv(fx.rd_fd, fx.captured, fx.captured_capacity, 0);
            fx.captured_size = n > 0 ? (size_t)n : 0;
            char extra;
            TEST_ASSERT(recv(fx.rd_fd, &extra, 1, 0) == -1 && errno == EAGAIN, "one packet contains the entire response");
        }
        TEST_ASSERT_EQUAL_SIZE(head + expected_size, fx.captured_size, "exact wire length");
        TEST_ASSERT(fx.captured_size == head + expected_size && memcmp(fx.captured + head, expected, expected_size) == 0, "parts and boundaries sent once");
        TEST_ASSERT_EQUAL_SIZE(expected_size, fx.response->body_bytes_sent, "multipart bytes counted once");
        free(expected);
        cleanup_request:
        httprequest_free(request);
        cleanup:
        fixture_teardown(&fx);
    }
}

TEST(test_multipart_threshold_includes_part_headers) {
    TEST_SUITE("http_write_filter: hybrid files");
    TEST_CASE("large multipart framing selects sendfile even when selected file bytes are tiny");
    write_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, HTTP_MULTIPART_BUFFER_MAX * 3), "fixture created");
    httprequest_t* request = httprequest_create(fx.conn);
    TEST_REQUIRE_GOTO(request != NULL, "request created", cleanup);
    char* ctype = malloc(HTTP_MULTIPART_BUFFER_MAX / 2 + 1);
    TEST_REQUIRE_GOTO(ctype != NULL, "large content type allocated", cleanup_request);
    memset(ctype, 'x', HTTP_MULTIPART_BUFFER_MAX / 2); ctype[HTTP_MULTIPART_BUFFER_MAX / 2] = 0;
    request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(sendfile_stage_file(&fx, "0123456789", 10), "source staged", cleanup_ctype);
    TEST_REQUIRE_GOTO(sendfile_request_range(request, 0, 1), "first part", cleanup_ctype);
    TEST_REQUIRE_GOTO(sendfile_append_range(request, 8, 9), "second part", cleanup_ctype);
    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Type", ctype), "large part field staged", cleanup_ctype);
    TEST_REQUIRE_GOTO(__run_header_filters(request, fx.response) == CWF_OK, "head prepared", cleanup_ctype);
    http_module_range_t* m = sendfile_range_module(&fx);
    TEST_ASSERT(m->mp_size > HTTP_MULTIPART_BUFFER_MAX, "framed response exceeds the threshold");
    TEST_REQUIRE_GOTO(__run_body_filters(request, fx.response) == CWF_OK, "multipart sent", cleanup_ctype);
    TEST_ASSERT(m->buf->data == NULL, "large framing retains the sendfile path");
    TEST_ASSERT_EQUAL_SIZE(m->mp_size, fx.response->body_bytes_sent, "framed body fully counted");
    cleanup_ctype:
    free(ctype);
    cleanup_request:
    httprequest_free(request);
    cleanup:
    fixture_teardown(&fx);
}

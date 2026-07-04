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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static int fixture_setup(write_fixture_t* fx, size_t capture_capacity) {
    memset(fx, 0, sizeof(*fx));
    fx->wr_fd = -1;
    fx->rd_fd = -1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
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

    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);

    const char expected[] = "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: 5\r\n"
                            "\r\n";
    const size_t expected_size = sizeof(expected) - 1;

    TEST_ASSERT(captured_equals(&fx, expected, expected_size),
                "head on the wire should match byte for byte");

    /* __head_size() accounting must agree with what __build_head appends:
     * the buffer is allocated to the exact predicted size, so any drift
     * would show up here as a capacity/size mismatch. */
    TEST_ASSERT_EQUAL_SIZE(expected_size, fx.module->buf->capacity,
                           "buffer should be allocated to the exact head size");
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

    const int r = run_header(&fx);
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

    const int r = run_header(&fx);
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

    int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "head larger than the send buffer should hit EAGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.response->event_again, "event_again should be set");
    TEST_ASSERT(fx.module->buf->pos < fx.module->buf->size,
                "part of the head should still be pending");

    int guard = 0;
    while (r == CWF_EVENT_AGAIN && guard++ < 1000) {
        TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained between resumes",
                          cleanup_buffers);
        r = run_header(&fx);
    }

    TEST_ASSERT_EQUAL(CWF_OK, r, "resumed header pass should finish with CWF_OK");
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

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "first header pass should succeed", cleanup);
    TEST_REQUIRE_GOTO(fixture_drain(&fx), "socket should be drained", cleanup);

    const size_t first_size = fx.captured_size;

    const int r = run_header(&fx);
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
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "first header pass should succeed", cleanup);
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

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should work after reset", cleanup);
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

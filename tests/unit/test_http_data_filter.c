/*
 * Unit tests for protocols/http/server/filters/http_data_filter.c
 *
 * Covers filter/module construction, __header (Content-Length and
 * Cache-Control negotiation, 304/range/chunked pass-through, CWF_EVENT_AGAIN
 * resume) and __body (body path chunking through the proxy buffer, file path
 * read loop, HEAD/304 short-circuits, range forwarding, reset/reuse).
 *
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - __reset cleared the proxy buffer with bufo_clear(), which on a proxy
 *     re-runs bufo_init() and zeroes capacity. body_next_chunk_data caps the
 *     chunk via bufo_set_size() (clamped to capacity), so a zero capacity made
 *     every reuse produce size == 0 and __body returned CWF_OK at once — the
 *     body of the second response on a keep-alive connection was dropped;
 *   - file_next_chunk_data set **ok = 1 and returned NULL on a read() failure,
 *     so __body skipped the "all data sent" check and forwarded NULL to the
 *     next filter (NULL deref / corrupted stream); EINTR was also not retried;
 *   - on a CWF_EVENT_AGAIN resume __body re-initialized buf to &response->body
 *     instead of the buffer that was mid-flight. body_next_chunk_data advances
 *     response->body.pos by the whole chunk up front, so the re-fetch pointed
 *     the proxy past the bytes the downstream still owed (proxy.data past the
 *     end, stale pos < size) and the next sink pass read out of bounds /
 *     delivered garbage. parent_buf now holds the in-progress buffer.
 */

#include "framework.h"
#include "httpresponse.h"
#include "httprequest.h"
#include "http_data_filter.h"
#include "connection_s.h"
#include "bufo.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define DATA_BUF_SIZE 16384

// ============================================================================
// Fixture: data filter chained into a capturing sink filter
// ============================================================================

static connection_server_ctx_t test_data_ctx;

static connection_t* make_connection(void) {
    connection_t* conn = calloc(1, sizeof(connection_t));
    if (conn == NULL) return NULL;

    memset(&test_data_ctx, 0, sizeof(test_data_ctx));
    conn->ctx = &test_data_ctx;
    conn->keepalive = 0;

    return conn;
}

/* Sink filter: captures everything the data filter emits and mimics the write
 * filter contract — consumes buf from buf->pos, returns CWF_DATA_AGAIN when
 * drained and CWF_EVENT_AGAIN after a scripted partial consume. A NULL buf is
 * recorded (not dereferenced) so a "data filter passed NULL" regression fails
 * the assertion instead of aborting the runner. */
typedef struct {
    http_module_t base;
    char* data;
    size_t size;
    size_t capacity;
    size_t max_take_once;   /* one-shot partial consume -> CWF_EVENT_AGAIN */
    int header_again_once;  /* one-shot CWF_EVENT_AGAIN from handler_header */
    int header_calls;
    int body_calls;
    int got_null_body;      /* set if sink_body ever received a NULL buffer */
} sink_module_t;

static void sink_noop(void* arg) { (void)arg; }

static int sink_header(httprequest_t* request, httpresponse_t* response) {
    (void)request;
    sink_module_t* sink = response->cur_filter->module;
    sink->header_calls++;

    if (sink->header_again_once) {
        sink->header_again_once = 0;
        return CWF_EVENT_AGAIN;
    }

    return CWF_OK;
}

static int sink_body(httprequest_t* request, httpresponse_t* response, bufo_t* buf) {
    (void)request;
    sink_module_t* sink = response->cur_filter->module;
    sink->body_calls++;

    if (buf == NULL) {
        sink->got_null_body = 1;
        return CWF_ERROR;
    }

    size_t take = buf->size > buf->pos ? buf->size - buf->pos : 0;
    if (sink->max_take_once > 0) {
        if (take > sink->max_take_once)
            take = sink->max_take_once;

        sink->max_take_once = 0;
    }

    if (take > 0) {
        if (sink->size + take > sink->capacity)
            return CWF_ERROR;

        memcpy(sink->data + sink->size, bufo_data(buf), take);
        sink->size += take;
        bufo_move_front_pos(buf, take);
    }

    if (buf->pos < buf->size)
        return CWF_EVENT_AGAIN;

    return CWF_DATA_AGAIN;
}

typedef struct {
    connection_t* conn;
    httpresponse_t* response;
    http_filter_t* data;
    http_filter_t sink_filter;
    sink_module_t sink;
    http_module_data_t* module;
} data_fixture_t;

static int fixture_setup(data_fixture_t* fx, size_t sink_capacity) {
    memset(fx, 0, sizeof(*fx));

    fx->conn = make_connection();
    if (fx->conn == NULL) return 0;

    fx->response = httpresponse_create(fx->conn);
    if (fx->response == NULL) {
        free(fx->conn);
        return 0;
    }

    fx->data = http_data_filter_create();
    fx->sink.data = malloc(sink_capacity);
    if (fx->data == NULL || fx->sink.data == NULL) {
        if (fx->data != NULL) {
            http_module_t* module = fx->data->module;
            module->free(fx->data->module);
            free(fx->data);
        }
        free(fx->sink.data);
        httpresponse_free(fx->response);
        free(fx->conn);
        return 0;
    }

    fx->sink.capacity = sink_capacity;
    fx->sink.base.free = sink_noop;
    fx->sink.base.reset = sink_noop;

    fx->sink_filter.module = &fx->sink;
    fx->sink_filter.handler_header = sink_header;
    fx->sink_filter.handler_body = sink_body;
    fx->sink_filter.next = NULL;

    fx->data->next = &fx->sink_filter;
    fx->module = fx->data->module;

    return 1;
}

static void fixture_teardown(data_fixture_t* fx) {
    if (fx->data != NULL) {
        http_module_t* module = fx->data->module;
        module->free(fx->data->module);
        free(fx->data);
    }

    free(fx->sink.data);

    if (fx->response != NULL)
        httpresponse_free(fx->response);

    free(fx->conn);
}

static int run_header(data_fixture_t* fx) {
    fx->response->cur_filter = fx->data;
    return fx->data->handler_header(NULL, fx->response);
}

static int run_body(data_fixture_t* fx, httprequest_t* request, bufo_t* parent) {
    fx->response->cur_filter = fx->data;
    return fx->data->handler_body(request, fx->response, parent);
}

/* Load `data`/`size` into the response body buffer (the body path reads from
 * response->body directly, not from the parent buffer argument). */
static int body_set(httpresponse_t* response, const void* data, size_t size) {
    if (!bufo_ensure_capacity(&response->body, size ? size : 1))
        return 0;

    if (size)
        memcpy(response->body.data, data, size);

    response->body.size = size;
    response->body.pos = 0;
    response->body.is_last = 0;
    return 1;
}

/* Stage `data` in an unlinked tmpfile positioned at offset 0 so the file path
 * (read + lseek) exercises a real descriptor. Returns the fd, or -1. */
static int file_set(httpresponse_t* response, const void* data, size_t size) {
    char tmpl[] = "/tmp/cwfr_data_filter_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;

    unlink(tmpl);

    if (size) {
        const char* p = data;
        while (size > 0) {
            ssize_t w = write(fd, p, size);
            if (w < 0) { close(fd); return -1; }
            p += w;
            size -= (size_t)w;
        }
    }

    if (lseek(fd, 0, SEEK_SET) != 0) { close(fd); return -1; }

    response->file_.fd = fd;
    response->file_.size = response->body.size;  /* size set by body_set, or 0 */
    response->file_.size = size ? size : (size_t)0;
    return fd;
}

static int header_count(httpresponse_t* response, const char* key) {
    int count = 0;
    for (http_header_t* h = response->header_; h != NULL; h = h->next)
        if (strcmp(h->key, key) == 0)
            count++;
    return count;
}

static int sink_equals(data_fixture_t* fx, const void* expected, size_t expected_size) {
    return fx->sink.size == expected_size && memcmp(fx->sink.data, expected, expected_size) == 0;
}

// ============================================================================
// Construction
// ============================================================================

TEST(test_data_filter_create_defaults) {
    TEST_SUITE("http_data_filter: construction");
    TEST_CASE("filter and module are initialized with clean defaults");

    http_filter_t* filter = http_data_filter_create();
    TEST_REQUIRE_NOT_NULL(filter, "filter should be created");

    TEST_ASSERT(filter->handler_header != NULL, "handler_header should be set");
    TEST_ASSERT(filter->handler_body != NULL, "handler_body should be set");
    TEST_ASSERT_NULL(filter->next, "next filter should be NULL");
    TEST_REQUIRE_NOT_NULL(filter->module, "module should be created");

    http_module_data_t* module = filter->module;
    TEST_ASSERT_EQUAL_UINT(0, module->base.cont, "cont should be 0");
    TEST_ASSERT_EQUAL_UINT(0, module->base.done, "done should be 0");
    TEST_ASSERT_NULL(module->base.parent_buf, "parent_buf should be NULL");
    TEST_ASSERT(module->base.free != NULL, "free callback should be set");
    TEST_ASSERT(module->base.reset != NULL, "reset callback should be set");

    TEST_REQUIRE_NOT_NULL(module->proxy_body_buf, "proxy buffer should be created");
    TEST_ASSERT_EQUAL_UINT(1, module->proxy_body_buf->is_proxy, "proxy buffer should be marked as proxy");
    TEST_ASSERT_EQUAL_SIZE(DATA_BUF_SIZE, module->proxy_body_buf->capacity,
                           "proxy buffer capacity should be BUF_SIZE for bufo_set_size");
    TEST_ASSERT(module->file_offset == 0, "file_offset should start at 0");

    module->base.free(module);
    free(filter);
}

// ============================================================================
// __header
// ============================================================================

TEST(test_data_header_body_adds_content_length) {
    TEST_SUITE("http_data_filter: header");
    TEST_CASE("a body response with TE_NONE gets a Content-Length");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->transfer_encoding = TE_NONE;
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello", 5), "body should be set", cleanup);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(1, fx.sink.header_calls, "next filter should be called once");

    http_header_t* h = fx.response->get_header(fx.response, "Content-Length");
    TEST_REQUIRE_NOT_NULL_GOTO(h, "Content-Length should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("5", h->value, "Content-Length should match body size");

    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Cache-Control"),
                     "Cache-Control should not be added for a body response");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_data_header_file_adds_cache_control_and_content_length) {
    TEST_SUITE("http_data_filter: header");
    TEST_CASE("a file response gets Cache-Control and Content-Length");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->transfer_encoding = TE_NONE;
    fx.response->file_.fd = 5;       /* any > -1 value selects the file path */
    fx.response->file_.size = 4321;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");

    http_header_t* cc = fx.response->get_header(fx.response, "Cache-Control");
    TEST_REQUIRE_NOT_NULL(cc, "Cache-Control should be added for a file");
    TEST_ASSERT_STR_EQUAL("no-cache", cc->value, "Cache-Control should be no-cache");

    http_header_t* cl = fx.response->get_header(fx.response, "Content-Length");
    TEST_REQUIRE_NOT_NULL(cl, "Content-Length should be added for a file");
    TEST_ASSERT_STR_EQUAL("4321", cl->value, "Content-Length should match file size, not body size");

    fixture_teardown(&fx);
}

TEST(test_data_header_chunked_no_content_length) {
    TEST_SUITE("http_data_filter: header");
    TEST_CASE("TE_CHUNKED responses defer length to the chunked filter");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->transfer_encoding = TE_CHUNKED;
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello", 5), "body should be set", cleanup);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Length"),
                     "Content-Length should not be added for chunked responses");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_data_header_304_no_content_length) {
    TEST_SUITE("http_data_filter: header");
    TEST_CASE("304 responses must not carry a Content-Length (RFC 7232)");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->transfer_encoding = TE_NONE;
    fx.response->status_code = 304;
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello", 5), "body should be set", cleanup);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Length"),
                     "Content-Length should not be added for 304");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_data_header_range_no_content_length) {
    TEST_SUITE("http_data_filter: header");
    TEST_CASE("range responses defer length to the range filter");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->transfer_encoding = TE_NONE;
    fx.response->range = 1;
    fx.response->file_.fd = 5;
    fx.response->file_.size = 1000;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Length"),
                     "Content-Length should not be added for range responses");
    /* Cache-Control is gated on file_.fd, not on range, so it is still added. */
    http_header_t* cc = fx.response->get_header(fx.response, "Cache-Control");
    TEST_ASSERT_NOT_NULL(cc, "Cache-Control should still be added for a range file");
    TEST_ASSERT_STR_EQUAL("no-cache", cc->value, "Cache-Control should be no-cache");

    fixture_teardown(&fx);
}

TEST(test_data_header_event_again_resume) {
    TEST_SUITE("http_data_filter: header");
    TEST_CASE("CWF_EVENT_AGAIN sets cont and the retry does not re-add headers");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->transfer_encoding = TE_NONE;
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello", 5), "body should be set", cleanup);
    fx.sink.header_again_once = 1;

    int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "first pass should propagate CWF_EVENT_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.cont, "cont should be set for resume");

    r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "second pass should finish with CWF_OK");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT_EQUAL(2, fx.sink.header_calls, "next filter should be called twice");
    TEST_ASSERT_EQUAL(1, header_count(fx.response, "Content-Length"),
                      "Content-Length should be added exactly once");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// __body: body path
// ============================================================================

TEST(test_data_body_single_chunk) {
    TEST_SUITE("http_data_filter: body");
    TEST_CASE("a body smaller than BUF_SIZE is delivered in one pass");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello world", 11), "body should be set", cleanup);

    const int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "body should finish with CWF_OK");
    TEST_ASSERT(sink_equals(&fx, "Hello world", 11), "sink should hold the whole body");
    TEST_ASSERT_EQUAL_SIZE(11, fx.response->body.pos, "body should be fully consumed");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_data_body_multi_chunk_large) {
    TEST_SUITE("http_data_filter: body");
    TEST_CASE("a body larger than BUF_SIZE is reassembled across chunks");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 17), "fixture should be created");

    enum { data_size = 40000 };
    char* data = malloc(data_size);
    TEST_REQUIRE_GOTO(data != NULL, "data buffer should be allocated", cleanup);

    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('a' + i % 26);

    TEST_REQUIRE_GOTO(body_set(fx.response, data, data_size), "body should be set", cleanup);

    const int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "body should finish with CWF_OK");
    TEST_ASSERT_EQUAL_SIZE(data_size, fx.sink.size, "sink should hold the whole body");
    TEST_ASSERT_EQUAL_SIZE(data_size, fx.response->body.pos, "body should be fully consumed");
    TEST_ASSERT(sink_equals(&fx, data, data_size), "reassembled payload should match the input");
    TEST_ASSERT(fx.sink.body_calls >= 3, "a 40000-byte body should span several BUF_SIZE chunks");

    free(data);

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_data_body_empty) {
    TEST_SUITE("http_data_filter: body");
    TEST_CASE("an empty body completes without invoking the downstream filter");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");
    TEST_REQUIRE_GOTO(body_set(fx.response, "", 0), "body should be set empty", cleanup);

    const int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "empty body should finish with CWF_OK at once");
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "nothing should be emitted");
    TEST_ASSERT_EQUAL(0, fx.sink.body_calls, "downstream body should not be called");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_data_body_head_request_no_body) {
    TEST_SUITE("http_data_filter: body");
    TEST_CASE("HEAD responses short-circuit without a body (RFC 7231)");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello world", 11), "body should be set", cleanup);

    httprequest_t* request = calloc(1, sizeof *request);
    TEST_REQUIRE_GOTO(request != NULL, "request should be allocated", req_cleanup);
    request->method = ROUTE_HEAD;

    const int r = run_body(&fx, request, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "HEAD should finish with CWF_OK without a body");
    TEST_ASSERT_EQUAL(0, fx.sink.body_calls, "downstream body should not be called");
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "nothing should be emitted for HEAD");

    free(request);

    req_cleanup:
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_data_body_304_no_body) {
    TEST_SUITE("http_data_filter: body");
    TEST_CASE("304 responses short-circuit without a body (RFC 7232)");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello world", 11), "body should be set", cleanup);

    fx.response->status_code = 304;

    const int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "304 should finish with CWF_OK without a body");
    TEST_ASSERT_EQUAL(0, fx.sink.body_calls, "downstream body should not be called");
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "nothing should be emitted for 304");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_data_body_partial_write_resume) {
    TEST_SUITE("http_data_filter: body");
    TEST_CASE("REGRESSION: a partial downstream write resumes without losing or repeating bytes");

    /* First pass: proxy points at body+0, sink takes 4 bytes ("Hell") and the
     * write filter stalls (CWF_EVENT_AGAIN). body.pos is already advanced to
     * the end (body_next_chunk_data moves it by the whole chunk up front), so
     * on resume the data filter must re-offer the SAME proxy (pos=4) — not
     * re-fetch, which would point the proxy past body end with a stale pos and
     * read out of bounds. */
    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello world", 11), "body should be set", cleanup);

    fx.sink.max_take_once = 4;

    int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "partial write should propagate CWF_EVENT_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.cont, "cont should be set for resume");
    TEST_ASSERT_EQUAL_SIZE(4, fx.sink.size, "only the consumed prefix should be captured");

    r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "resumed pass should complete");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT(sink_equals(&fx, "Hello world", 11),
                "resumed stream should be complete and in order, no garbage");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// __body: file path
// ============================================================================

TEST(test_data_body_file_full) {
    TEST_SUITE("http_data_filter: file");
    TEST_CASE("a file smaller than BUF_SIZE is read and delivered in one pass");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    const char* payload = "Hello file";
    int fd = file_set(fx.response, payload, 10);
    TEST_REQUIRE_GOTO(fd > -1, "tmpfile should be staged", cleanup);

    const int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "file body should finish with CWF_OK");
    TEST_ASSERT(sink_equals(&fx, payload, 10), "sink should hold the file contents");

    cleanup:
    if (fd > -1) close(fd);
    fixture_teardown(&fx);
}

TEST(test_data_body_file_multi_chunk_large) {
    TEST_SUITE("http_data_filter: file");
    TEST_CASE("a file larger than BUF_SIZE is reassembled across read() calls");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 17), "fixture should be created");

    enum { data_size = 40000 };
    char* data = malloc(data_size);
    TEST_REQUIRE_GOTO(data != NULL, "data buffer should be allocated", cleanup_buffers);

    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('A' + i % 26);

    int fd = file_set(fx.response, data, data_size);
    TEST_REQUIRE_GOTO(fd > -1, "tmpfile should be staged", cleanup_buffers);

    const int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "file body should finish with CWF_OK");
    TEST_ASSERT_EQUAL_SIZE(data_size, fx.sink.size, "sink should hold the whole file");
    TEST_ASSERT(sink_equals(&fx, data, data_size), "reassembled file should match the input");

    if (fd > -1) close(fd);

    cleanup_buffers:
    free(data);
    fixture_teardown(&fx);
}

TEST(test_data_body_file_empty) {
    TEST_SUITE("http_data_filter: file");
    TEST_CASE("an empty file completes without invoking the downstream filter");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    int fd = file_set(fx.response, "", 0);
    TEST_REQUIRE_GOTO(fd > -1, "tmpfile should be staged", cleanup);

    const int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "empty file should finish with CWF_OK");
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "nothing should be emitted");

    cleanup:
    if (fd > -1) close(fd);
    fixture_teardown(&fx);
}

TEST(test_data_body_file_read_error) {
    TEST_SUITE("http_data_filter: file");
    TEST_CASE("REGRESSION: a read() failure yields CWF_ERROR, not a NULL buffer downstream");

    /* pread() on a closed descriptor fails with EBADF. The old code set ok = 1
     * and returned NULL, so __body forwarded NULL to the next filter. The fix
     * leaves ok = 0, mapping the failure to CWF_ERROR before any sink call. */
    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    int fd = open("/dev/null", O_RDONLY);
    TEST_REQUIRE_GOTO(fd > -1, "probe descriptor should be opened", cleanup);
    close(fd);
    /* fd is now closed -> read() in file_next_chunk_data returns -1 (EBADF) */

    fx.response->file_.fd = fd;
    fx.response->file_.size = 256;

    const int r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_ERROR, r, "read failure should surface as CWF_ERROR");
    TEST_ASSERT_EQUAL(0, fx.sink.body_calls, "downstream body should not be called");
    TEST_ASSERT_EQUAL_UINT(0, fx.sink.got_null_body, "no NULL buffer should reach the sink");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// __body: range forwarding
// ============================================================================

TEST(test_data_body_range_forwards_parent) {
    TEST_SUITE("http_data_filter: range");
    TEST_CASE("range responses forward the parent buffer straight to the next filter");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->range = 1;

    char payload[] = "range-bytes";
    bufo_t parent;
    parent.data = payload;
    parent.capacity = sizeof(payload);
    parent.size = sizeof(payload) - 1;
    parent.pos = 0;
    parent.is_proxy = 1;
    parent.is_last = 1;

    const int r = run_body(&fx, NULL, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "range path should forward the sink result");
    TEST_ASSERT_EQUAL(1, fx.sink.body_calls, "downstream body should be called once");
    TEST_ASSERT(sink_equals(&fx, "range-bytes", sizeof(payload) - 1),
                "parent payload should be forwarded verbatim");

    fixture_teardown(&fx);
}

// ============================================================================
// Reset and reuse
// ============================================================================

TEST(test_data_reset_state_cleared) {
    TEST_SUITE("http_data_filter: reset");
    TEST_CASE("reset clears module state and keeps the proxy usable");

    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    /* Dirty the module so the reset is observable. */
    fx.module->base.cont = 1;
    fx.module->base.done = 1;
    fx.module->base.parent_buf = (bufo_t*)0x1234;
    fx.module->proxy_body_buf->size = 100;
    fx.module->proxy_body_buf->pos = 50;
    fx.module->proxy_body_buf->is_last = 1;
    fx.module->file_offset = 99999;

    fx.module->base.reset(fx.module);

    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.done, "done should be cleared");
    TEST_ASSERT_NULL(fx.module->base.parent_buf, "parent_buf should be cleared");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->proxy_body_buf->is_proxy, "proxy flag should be restored");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->proxy_body_buf->size, "proxy size should be cleared");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->proxy_body_buf->pos, "proxy pos should be cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->proxy_body_buf->is_last, "is_last should be cleared");
    TEST_ASSERT_EQUAL_SIZE(DATA_BUF_SIZE, fx.module->proxy_body_buf->capacity,
                           "proxy capacity should survive reset (bufo_set_size clamps to it)");
    TEST_ASSERT(fx.module->file_offset == 0, "file_offset should be cleared for the next file response");

    fixture_teardown(&fx);
}

TEST(test_data_reset_allows_reuse) {
    TEST_SUITE("http_data_filter: reset");
    TEST_CASE("REGRESSION: after reset the proxy can still deliver a second body");

    /* bufo_clear() on the proxy re-runs bufo_init() and zeroes capacity; the
     * old reset restored is_proxy but left capacity at 0, so bufo_set_size()
     * clamped every chunk to 0 and the second response was dropped. */
    data_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");
    TEST_REQUIRE_GOTO(body_set(fx.response, "Hello", 5), "first body should be set", cleanup);

    int r = run_body(&fx, NULL, NULL);
    TEST_REQUIRE_GOTO(r == CWF_OK, "first response should complete", cleanup);
    TEST_ASSERT(sink_equals(&fx, "Hello", 5), "first body should be delivered");

    fx.module->base.reset(fx.module);
    fx.sink.size = 0;
    fx.sink.body_calls = 0;

    TEST_REQUIRE_GOTO(body_set(fx.response, "Hi", 2), "second body should be set", cleanup);

    r = run_body(&fx, NULL, NULL);
    TEST_ASSERT_EQUAL(CWF_OK, r, "second response should complete after reset");
    TEST_ASSERT_EQUAL_SIZE(2, fx.sink.size, "second body should not be dropped");
    TEST_ASSERT(sink_equals(&fx, "Hi", 2), "second body should be delivered correctly");

    cleanup:
    fixture_teardown(&fx);
}

/*
 * Unit tests for protocols/http/server/filters/http_range_filter.c
 *
 * The range filter runs right after not_modified (chain: not_modified ->
 * range -> data -> gzip -> chunked -> write). For a satisfiable single range
 * it sets status 206, Content-Range, Content-Length, forces TE_NONE/CE_NONE
 * (so chunked/gzip pass through and the write filter consumes its output
 * directly), and slices the chosen byte range out of either the response body
 * or the file backing the response.
 *
 * Driven black-box through the public handler_header/handler_body pointers,
 * like test_http_gzip_filter.c: the filter under test is chained into a
 * capturing sink so its output is observable in isolation. The sink mimics the
 * write-filter contract — it consumes buf from buf->pos, returns
 * CWF_EVENT_AGAIN on a partial consume (so the cont/resume path is exercised)
 * and CWF_DATA_AGAIN once the buffer is drained.
 *
 * Covers:
 *   - construction defaults;
 *   - __header: pass-throughs (no Range / non-2xx / last_modified);
 *   - __header: 206 framing for normal / open-ended / suffix / whole-range /
 *     end-clamped-to-EOF / single-byte / file-size forms, with exact
 *     Content-Range and Content-Length values;
 *   - __header: validation (start beyond EOF -> CWF_ERROR), cont resume;
 *   - __body: body-data slicing for normal / suffix / open-ended ranges;
 *   - __body: multi-chunk delivery for ranges larger than the 16K buffer;
 *   - __body: partial-write resume still produces the exact slice;
 *   - __body: file-backed slicing via pread (real temp fd), multi-chunk file;
 *   - __body: HEAD short-circuit (headers framed, no body), inactive
 *     pass-through (range == 0 forwards the parent buffer untouched);
 *   - __header: malformed range specs and oversized range sets ignore the
 *     Range header without mutating the response (status/TE/CE/range flag);
 *   - multipart/byteranges: framing, exact Content-Length, streaming,
 *     partial-write resume, file-backed parts, unsatisfiable part handling;
 *   - reset: module state cleared, keep-alive reuse (multipart -> single,
 *     416 -> 206) leaves no stale plan behind.
 *
 * REGRESSION (marked below): range_handler_header mutated response state
 * (content_encoding / transfer_encoding / range / status_code / range_size)
 * BEFORE finishing validation. A bad range therefore left the response
 * half-converted (range=1, status 206) even though the function returned
 * CWF_ERROR. The fix defers all mutation until every check has passed; the
 * case asserts a bad range leaves response->range == 0 and status == 200.
 */

#include "framework.h"
#include "httpresponse.h"
#include "httprequest.h"
#include "http_range_filter.h"
#include "http_filter.h"
#include "route.h"
#include "bufo.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define RANGE_BUF_SIZE 16384

/* Build a single range spec on the request (start/end as ssize_t; -1 means
 * "open" for that side, matching http_ranges_t). The filter only consumes the
 * first range node, so a single node is enough. */
static http_ranges_t* add_range(httprequest_t* request, ssize_t start, ssize_t end) {
    http_ranges_t* r = httpresponse_init_ranges();
    if (r == NULL) return NULL;
    r->start = start;
    r->end = end;
    request->ranges = r;
    return r;
}

// ============================================================================
// Fixture: range filter chained into a capturing sink filter
// ============================================================================

/* Sink: accumulates everything the range filter emits. Consumes buf from
 * buf->pos (mimicking the write filter's __wr/bufo_move_front_pos). When
 * max_take_once > 0 each call consumes at most that many bytes and returns
 * CWF_EVENT_AGAIN until the buffer is drained, exercising the cont/resume
 * path. Returns CWF_DATA_AGAIN once the buffer is fully consumed. is_last on
 * a fully-consumed buffer is counted so the "exactly one final chunk" contract
 * is observable. */
typedef struct {
    http_module_t base;
    char* data;
    size_t size;
    size_t capacity;
    size_t max_take_once;
    int header_again_once;
    int header_calls;
    int body_calls;
    int got_null_body;
    int saw_last;
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

    size_t avail = buf->size > buf->pos ? buf->size - buf->pos : 0;
    size_t take = avail;
    if (sink->max_take_once > 0 && take > sink->max_take_once)
        take = sink->max_take_once;

    if (take > 0) {
        if (sink->size + take > sink->capacity)
            return CWF_ERROR;

        memcpy(sink->data + sink->size, bufo_data(buf), take);
        sink->size += take;
        bufo_move_front_pos(buf, take);
    }

    if (buf->pos < buf->size)
        return CWF_EVENT_AGAIN;

    if (buf->is_last)
        sink->saw_last++;

    return CWF_DATA_AGAIN;
}

typedef struct {
    httpresponse_t* response;
    httprequest_t* request;
    http_filter_t* range;
    http_filter_t sink_filter;
    sink_module_t sink;
    http_module_range_t* module;
    int file_fd;        /* -1 unless a temp file is attached */
    char file_path[64];
} range_fixture_t;

static int fixture_setup(range_fixture_t* fx, size_t sink_capacity) {
    memset(fx, 0, sizeof(*fx));
    fx->file_fd = -1;

    fx->response = httpresponse_create(NULL);
    if (fx->response == NULL) return 0;

    fx->request = httprequest_create(NULL);
    if (fx->request == NULL) {
        httpresponse_free(fx->response);
        fx->response = NULL;
        return 0;
    }

    fx->range = http_range_filter_create();
    fx->sink.data = malloc(sink_capacity);
    if (fx->range == NULL || fx->sink.data == NULL) {
        if (fx->range != NULL) {
            http_module_t* m = fx->range->module;
            m->free(fx->range->module);
            free(fx->range);
            fx->range = NULL;
        }
        free(fx->sink.data);
        fx->sink.data = NULL;
        httprequest_free(fx->request);
        fx->request = NULL;
        httpresponse_free(fx->response);
        fx->response = NULL;
        return 0;
    }

    fx->sink.capacity = sink_capacity;
    fx->sink.base.free = sink_noop;
    fx->sink.base.reset = sink_noop;

    fx->sink_filter.module = &fx->sink;
    fx->sink_filter.handler_header = sink_header;
    fx->sink_filter.handler_body = sink_body;
    fx->sink_filter.next = NULL;

    fx->range->next = &fx->sink_filter;
    fx->module = fx->range->module;

    return 1;
}

static void fixture_teardown(range_fixture_t* fx) {
    if (fx->range != NULL) {
        http_module_t* m = fx->range->module;
        m->free(fx->range->module);
        free(fx->range);
    }

    free(fx->sink.data);

    if (fx->request != NULL)
        httprequest_free(fx->request);

    if (fx->response != NULL) {
        /* Detach any temp fd so __file_close() in the free path does not
         * double-close / unlink it; we own it. */
        fx->response->file_.fd = -1;
        fx->response->file_.tmp = 0;
        httpresponse_free(fx->response);
    }

    if (fx->file_fd > -1) {
        close(fx->file_fd);
        if (fx->file_path[0] != '\0')
            unlink(fx->file_path);
    }
}

/* Point the response body at an externally-owned buffer (mark it proxy so the
 * response free path does not free it). */
static void body_set(range_fixture_t* fx, char* data, size_t size) {
    fx->response->body.data = data;
    fx->response->body.size = size;
    fx->response->body.capacity = size;
    fx->response->body.pos = 0;
    fx->response->body.is_proxy = 1;
}

/* Attach a temp file with the given content; the file path backs the file_.fd
 * data path. Returns the fd or -1 on failure. */
static int file_set(range_fixture_t* fx, const char* content, size_t size) {
    strcpy(fx->file_path, "/tmp/cwfr_range_XXXXXX");
    int fd = mkstemp(fx->file_path);
    if (fd < 0) return -1;

    if (size > 0 && write(fd, content, size) != (ssize_t)size) {
        close(fd);
        unlink(fx->file_path);
        fx->file_path[0] = '\0';
        return -1;
    }

    fx->file_fd = fd;
    fx->response->file_.fd = fd;
    fx->response->file_.size = size;
    return fd;
}

static int run_header(range_fixture_t* fx) {
    fx->response->cur_filter = fx->range;
    return fx->range->handler_header(fx->request, fx->response);
}

/* Drive the body handler to completion, re-invoking on CWF_EVENT_AGAIN (the
 * event-loop resume). Returns the terminal status (CWF_OK / CWF_ERROR). */
static int run_body_to_done(range_fixture_t* fx) {
    int guard = 0;
    int r;
    do {
        fx->response->cur_filter = fx->range;
        r = fx->range->handler_body(fx->request, fx->response, NULL);
        if (++guard > 2000000)
            return CWF_ERROR;
    } while (r == CWF_EVENT_AGAIN);
    return r;
}

static int header_count(httpresponse_t* response, const char* key) {
    int count = 0;
    for (http_header_t* h = response->header_; h != NULL; h = h->next)
        if (strcmp(h->key, key) == 0)
            count++;
    return count;
}

static int sink_equals(range_fixture_t* fx, const char* expected, size_t expected_size) {
    return fx->sink.size == expected_size
        && (expected_size == 0 || memcmp(fx->sink.data, expected, expected_size) == 0);
}

// ============================================================================
// Construction
// ============================================================================

TEST(test_range_filter_create_defaults) {
    TEST_SUITE("http_range_filter: construction");
    TEST_CASE("filter and module are initialized with clean defaults");

    http_filter_t* filter = http_range_filter_create();
    TEST_REQUIRE_NOT_NULL(filter, "filter should be created");
    TEST_ASSERT_NOT_NULL(filter->module, "module should be created");
    TEST_ASSERT_NULL(filter->next, "next filter should be NULL");

    http_module_range_t* module = filter->module;
    TEST_ASSERT_EQUAL_UINT(0, module->base.cont, "cont should be 0");
    TEST_ASSERT_EQUAL_UINT(0, module->base.done, "done should be 0");
    TEST_ASSERT_NULL(module->base.parent_buf, "parent_buf should be NULL");
    TEST_ASSERT_EQUAL_SIZE(0, module->range_size, "range_size should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, module->range_pos, "range_pos should be 0");
    TEST_ASSERT_NOT_NULL(module->buf, "buf should be created");
    TEST_ASSERT_NULL(module->buf->data, "buf->data should not be allocated yet");
    TEST_ASSERT(module->base.free != NULL, "free callback should be set");
    TEST_ASSERT(module->base.reset != NULL, "reset callback should be set");

    module->base.free(module);
    free(filter);
}

// ============================================================================
// __header: pass-throughs
// ============================================================================

TEST(test_range_header_no_ranges_passthrough) {
    TEST_SUITE("http_range_filter: header passthrough");
    TEST_CASE("no Range header on the request -> forwards untouched");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.request->method = ROUTE_GET;
    /* request->ranges stays NULL. */

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "status should stay 200");
    TEST_ASSERT_EQUAL_UINT(0, fx.response->range, "range flag should stay 0");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Range"),
                     "no Content-Range without a Range header");

    fixture_teardown(&fx);
}

TEST(test_range_header_non_2xx_passthrough) {
    TEST_SUITE("http_range_filter: header passthrough");
    TEST_CASE("a non-2xx response ignores the Range header");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, 499), "range should be set");
    fx.response->status_code = 404;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(404, fx.response->status_code, "status should stay 404");
    TEST_ASSERT_EQUAL_UINT(0, fx.response->range, "range flag should stay 0");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Range"),
                     "no Content-Range for non-2xx");

    fixture_teardown(&fx);
}

TEST(test_range_header_last_modified_passthrough) {
    TEST_SUITE("http_range_filter: header passthrough");
    TEST_CASE("a 304 (last_modified) response skips range framing");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, 499), "range should be set");
    fx.response->last_modified = 1;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL_UINT(0, fx.response->range, "range flag should stay 0");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Range"),
                     "no Content-Range for last_modified responses");

    fixture_teardown(&fx);
}

// ============================================================================
// __header: 206 framing
// ============================================================================

TEST(test_range_header_normal_range) {
    TEST_SUITE("http_range_filter: header framing");
    TEST_CASE("bytes=0-499 on a 1000-byte body -> 206 with the right framing");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, 499), "range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "status should be 206");
    TEST_ASSERT_EQUAL_UINT(1, fx.response->range, "range flag should be set");
    TEST_ASSERT_EQUAL(TE_NONE, fx.response->transfer_encoding, "TE forced to NONE");
    TEST_ASSERT_EQUAL(CE_NONE, fx.response->content_encoding, "CE forced to NONE");

    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL_GOTO(cr, "Content-Range should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("bytes 0-499/1000", cr->value, "Content-Range value");

    http_header_t* cl = fx.response->get_header(fx.response, "Content-Length");
    TEST_REQUIRE_NOT_NULL_GOTO(cl, "Content-Length should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("500", cl->value, "Content-Length value");

    TEST_ASSERT_EQUAL_SIZE(500, fx.module->range_size, "range_size = 500 bytes");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_header_open_ended) {
    TEST_SUITE("http_range_filter: header framing");
    TEST_CASE("bytes=500- -> Content-Range bytes 500-999/1000");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 500, -1), "range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL(cr, "Content-Range should be added");
    TEST_ASSERT_STR_EQUAL("bytes 500-999/1000", cr->value, "open-ended Content-Range");
    TEST_ASSERT_EQUAL_SIZE(500, fx.module->range_size, "range_size = last 500 bytes");

    fixture_teardown(&fx);
}

TEST(test_range_header_suffix) {
    TEST_SUITE("http_range_filter: header framing");
    TEST_CASE("bytes=-500 (suffix) -> Content-Range bytes 500-999/1000");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, -1, 500), "suffix range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL(cr, "Content-Range should be added");
    TEST_ASSERT_STR_EQUAL("bytes 500-999/1000", cr->value, "suffix Content-Range");
    TEST_ASSERT_EQUAL_SIZE(500, fx.module->range_size, "range_size = last 500 bytes");

    fixture_teardown(&fx);
}

TEST(test_range_header_whole_range) {
    TEST_SUITE("http_range_filter: header framing");
    TEST_CASE("bytes=0- -> Content-Range bytes 0-999/1000 (whole resource)");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, -1), "whole range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL(cr, "Content-Range should be added");
    TEST_ASSERT_STR_EQUAL("bytes 0-999/1000", cr->value, "whole-resource Content-Range");
    TEST_ASSERT_EQUAL_SIZE(1000, fx.module->range_size, "range_size = whole body");

    fixture_teardown(&fx);
}

TEST(test_range_header_end_clamped_to_eof) {
    TEST_SUITE("http_range_filter: header framing");
    TEST_CASE("bytes=900-2000 -> end clamped to EOF -> bytes 900-999/1000");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 900, 2000), "range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL(cr, "Content-Range should be added");
    TEST_ASSERT_STR_EQUAL("bytes 900-999/1000", cr->value, "clamped Content-Range");
    TEST_ASSERT_EQUAL_SIZE(100, fx.module->range_size, "range_size = last 100 bytes");

    fixture_teardown(&fx);
}

TEST(test_range_header_single_byte) {
    TEST_SUITE("http_range_filter: header framing");
    TEST_CASE("bytes=0-0 -> Content-Range bytes 0-0/1000, length 1");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, 0), "single-byte range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL(cr, "Content-Range should be added");
    TEST_ASSERT_STR_EQUAL("bytes 0-0/1000", cr->value, "single-byte Content-Range");
    TEST_ASSERT_EQUAL_SIZE(1, fx.module->range_size, "range_size = 1 byte");

    fixture_teardown(&fx);
}

TEST(test_range_header_file_uses_file_size) {
    TEST_SUITE("http_range_filter: header framing");
    TEST_CASE("a file response derives data_size from file_.size, not body.size");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, 49), "range should be set");
    /* body.size left at 0; file_.size carries the real length. */
    char content[2000];
    TEST_REQUIRE_GOTO(file_set(&fx, content, 2000) > -1, "temp file should be created", cleanup);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL_GOTO(cr, "Content-Range should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("bytes 0-49/2000", cr->value, "Content-Range uses file_.size as total");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// __header: validation + resume
// ============================================================================

TEST(test_range_header_start_beyond_eof_416) {
    TEST_SUITE("http_range_filter: header validation");
    TEST_CASE("a start beyond EOF yields 416 with bytes */<size>, no body framing");

    /* Previously this returned CWF_ERROR (-> 5xx) or, for start == size, a
     * malformed 206 with Content-Range "bytes 1000-999/1000". RFC 7233 §4.4
     * requires 416 Range Not Satisfiable. */
    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 2000, -1), "range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK (416 is a valid response)");
    TEST_ASSERT_EQUAL(416, fx.response->status_code, "start beyond EOF -> 416");
    TEST_ASSERT_EQUAL_UINT(1, fx.response->range, "range flag set (body is suppressed by the filter)");
    TEST_ASSERT_EQUAL(CE_NONE, fx.response->content_encoding, "CE forced to NONE");
    TEST_ASSERT_EQUAL(TE_NONE, fx.response->transfer_encoding, "TE forced to NONE");

    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL_GOTO(cr, "Content-Range should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("bytes */1000", cr->value, "416 Content-Range form");

    http_header_t* cl = fx.response->get_header(fx.response, "Content-Length");
    TEST_REQUIRE_NOT_NULL_GOTO(cl, "Content-Length should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("0", cl->value, "416 has no body");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_header_start_at_eof_416) {
    TEST_SUITE("http_range_filter: header validation");
    TEST_CASE("bytes=<size>- (start == size) is unsatisfiable -> 416");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 1000, -1), "range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(416, fx.response->status_code, "start == size -> 416");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL(cr, "Content-Range should be added");
    TEST_ASSERT_STR_EQUAL("bytes */1000", cr->value, "416 Content-Range form");

    fixture_teardown(&fx);
}

TEST(test_range_header_end_below_start_416) {
    TEST_SUITE("http_range_filter: header validation");
    TEST_CASE("an inverted range (end < start) is unsatisfiable -> 416");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 5, 3), "inverted range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(416, fx.response->status_code, "end < start -> 416");

    fixture_teardown(&fx);
}

TEST(test_range_header_suffix_zero_416) {
    TEST_SUITE("http_range_filter: header validation");
    TEST_CASE("bytes=-0 (zero-length suffix) is unsatisfiable -> 416");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    /* The parser turns bytes=-0 into {start=-1, end=-1}; a suffix needs N>=1. */
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, -1, -1), "degenerate suffix range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(416, fx.response->status_code, "bytes=-0 -> 416, not the whole resource");

    fixture_teardown(&fx);
}

TEST(test_range_header_empty_resource_416) {
    TEST_SUITE("http_range_filter: header validation");
    TEST_CASE("a range against an empty resource is unsatisfiable -> 416");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, -1), "range should be set");
    char body[1];
    body_set(&fx, body, 0);   /* data_size == 0; body.data is never read (416) */

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(416, fx.response->status_code, "range on empty resource -> 416");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL(cr, "Content-Range should be added");
    TEST_ASSERT_STR_EQUAL("bytes */0", cr->value, "416 Content-Range with zero total");

    fixture_teardown(&fx);
}

TEST(test_range_body_416_has_no_body) {
    TEST_SUITE("http_range_filter: header validation");
    TEST_CASE("a 416 response produces no message body");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 2000, -1), "unsatisfiable range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(416, fx.response->status_code, "should be 416");

    const int r = run_body_to_done(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "body phase should finish cleanly with no body");
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "416 must not deliver any body bytes");
    TEST_ASSERT_EQUAL_UINT(0, fx.sink.saw_last, "no body chunk should be marked final");
    TEST_ASSERT_EQUAL_UINT(0, fx.sink.got_null_body, "no NULL buffer should reach the sink");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_header_cont_resume) {
    TEST_SUITE("http_range_filter: header validation");
    TEST_CASE("CWF_EVENT_AGAIN sets cont and the resume does not re-add Content-Range");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, 499), "range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));
    fx.sink.header_again_once = 1;

    int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "first pass should propagate CWF_EVENT_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.cont, "cont should be set while suspended");

    r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "second pass should finish with CWF_OK");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared on resume");
    TEST_ASSERT_EQUAL(2, fx.sink.header_calls, "next filter should be called twice");
    TEST_ASSERT_EQUAL(1, header_count(fx.response, "Content-Range"),
                      "Content-Range added exactly once across resume");

    fixture_teardown(&fx);
}

// ============================================================================
// __body: body-data slicing
// ============================================================================

TEST(test_range_body_normal_slice) {
    TEST_SUITE("http_range_filter: body (data path)");
    TEST_CASE("bytes=0-499 delivers exactly body[0..499]");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, 499), "range should be set");
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    const int r = run_body_to_done(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "body should drain to completion");
    TEST_ASSERT(sink_equals(&fx, body, 500), "sink should hold exactly body[0..499]");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "exactly one final chunk should be marked");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_body_suffix_slice) {
    TEST_SUITE("http_range_filter: body (data path)");
    TEST_CASE("bytes=-300 delivers exactly body[700..999]");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, -1, 300), "suffix range should be set");
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(CWF_OK, run_body_to_done(&fx), "body should drain to completion");
    TEST_ASSERT(sink_equals(&fx, body + 700, 300), "sink should hold exactly body[700..999]");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_body_open_ended_slice) {
    TEST_SUITE("http_range_filter: body (data path)");
    TEST_CASE("bytes=500- delivers exactly body[500..999]");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 500, -1), "open range should be set");
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(CWF_OK, run_body_to_done(&fx), "body should drain to completion");
    TEST_ASSERT(sink_equals(&fx, body + 500, 500), "sink should hold exactly body[500..999]");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_body_multi_chunk) {
    TEST_SUITE("http_range_filter: body (data path)");
    TEST_CASE("a range larger than the 16K buffer is delivered across multiple chunks");

    range_fixture_t fx;
    enum { data_size = 50000 };
    TEST_REQUIRE(fixture_setup(&fx, data_size), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, data_size - 1), "whole range should be set");
    char* body = malloc(data_size);
    TEST_REQUIRE_GOTO(body != NULL, "body buffer should be allocated", cleanup);
    for (size_t i = 0; i < data_size; i++) body[i] = (char)(i % 253);
    body_set(&fx, body, data_size);

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup_buf);
    const int r = run_body_to_done(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "body should drain to completion");
    TEST_ASSERT(fx.sink.body_calls >= (int)(data_size / RANGE_BUF_SIZE),
                "a 50000-byte range in 16K chunks spans several sink calls");
    TEST_ASSERT(sink_equals(&fx, body, data_size), "reassembled range should match the slice");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "exactly one final chunk should be marked");

    cleanup_buf:
    free(body);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_body_partial_write_resume) {
    TEST_SUITE("http_range_filter: body (data path)");
    TEST_CASE("a partial downstream write resumes and still delivers the exact slice");

    range_fixture_t fx;
    enum { data_size = 40000 };
    TEST_REQUIRE(fixture_setup(&fx, data_size), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, data_size - 1), "whole range should be set");
    char* body = malloc(data_size);
    TEST_REQUIRE_GOTO(body != NULL, "body buffer should be allocated", cleanup);
    for (size_t i = 0; i < data_size; i++) body[i] = (char)((i * 7) % 251);
    body_set(&fx, body, data_size);

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup_buf);
    fx.sink.max_take_once = 4000;   /* force many CWF_EVENT_AGAIN resumes */

    const int r = run_body_to_done(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "body should drain to completion despite partial writes");
    TEST_ASSERT(fx.sink.body_calls > 1, "partial writes should require several sink calls");
    TEST_ASSERT_EQUAL_UINT(0, fx.sink.got_null_body, "no NULL buffer should reach the sink");
    TEST_ASSERT(sink_equals(&fx, body, data_size), "resumed stream should match the slice exactly");

    cleanup_buf:
    free(body);
    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// __body: file-backed slicing (pread)
// ============================================================================

TEST(test_range_body_file_slice) {
    TEST_SUITE("http_range_filter: body (file path)");
    TEST_CASE("a file-backed range is sliced via pread");

    range_fixture_t fx;
    enum { data_size = 40000 };
    TEST_REQUIRE(fixture_setup(&fx, data_size), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 100, 10999), "range 100..10999 should be set");

    char* content = malloc(data_size);
    TEST_REQUIRE_GOTO(content != NULL, "content buffer should be allocated", cleanup);
    for (size_t i = 0; i < data_size; i++) content[i] = (char)((i * 3) % 250);
    TEST_REQUIRE_GOTO(file_set(&fx, content, data_size) > -1, "temp file should be created", cleanup_buf);

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup_buf);
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "file range should be 206");

    const int r = run_body_to_done(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "body should drain to completion");
    TEST_ASSERT_EQUAL_SIZE(10900, fx.module->range_size, "range_size = 11000-100 bytes");
    TEST_ASSERT(sink_equals(&fx, content + 100, 10900), "sink should hold file bytes [100..10999]");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "exactly one final chunk should be marked");

    cleanup_buf:
    free(content);
    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// Reset
// ============================================================================

TEST(test_range_reset_clears_state) {
    TEST_SUITE("http_range_filter: reset");
    TEST_CASE("reset clears cont/done/parent_buf/range_pos/range_size and flushes buf");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.module->base.cont = 1;
    fx.module->base.done = 1;
    fx.module->base.parent_buf = (bufo_t*)0x1234;
    fx.module->range_pos = 12345;
    fx.module->range_size = 67890;
    fx.module->buf->is_last = 1;

    fx.module->base.reset(fx.module);

    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.done, "done cleared");
    TEST_ASSERT_NULL(fx.module->base.parent_buf, "parent_buf cleared");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->range_pos, "range_pos cleared");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->range_size, "range_size cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->buf->is_last, "buf is_last cleared");

    fixture_teardown(&fx);
}

// ============================================================================
// multipart/byteranges (RFC 7233 §4.1)
// ============================================================================

/* Append a range node to the request's ranges list (multi-range requests). */
static http_ranges_t* ranges_append(httprequest_t* request, ssize_t start, ssize_t end) {
    http_ranges_t* r = httpresponse_init_ranges();
    if (r == NULL) return NULL;
    r->start = start;
    r->end = end;

    if (request->ranges == NULL) {
        request->ranges = r;
    }
    else {
        http_ranges_t* t = request->ranges;
        while (t->next != NULL) t = t->next;
        t->next = r;
    }
    return r;
}

typedef struct {
    size_t start;
    size_t end_incl;
} rspec_t;

/* Extract the boundary token from a "multipart/byteranges; boundary=<B>"
 * Content-Type value, or NULL if absent. */
static const char* extract_boundary(httpresponse_t* response) {
    http_header_t* h = response->get_header(response, "Content-Type");
    if (h == NULL) return NULL;
    const char* p = strstr(h->value, "boundary=");
    return p ? p + 9 : NULL;   /* 9 == strlen("boundary=") */
}

/* Build the expected multipart/byteranges body into a heap buffer using the
 * same framing the filter emits, so the two can be compared byte-for-byte.
 * ranges[] are [start, end_incl] pairs. Caller frees the result. */
static char* build_expected_multipart(const char* boundary, const char* ctype,
                                      const char* body, size_t total,
                                      const rspec_t* ranges, size_t n, size_t* out_len) {
    size_t cap = total + n * 512 + 256;
    char* buf = malloc(cap);
    if (buf == NULL) return NULL;
    size_t len = 0;

    for (size_t i = 0; i < n; i++) {
        size_t s = ranges[i].start;
        size_t e = ranges[i].end_incl;
        int hl = snprintf(buf + len, cap - len,
                          "--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zu-%zu/%zu\r\n\r\n",
                          boundary, ctype, s, e, total);
        if (hl < 0 || (size_t)hl >= cap - len) { free(buf); return NULL; }
        len += (size_t)hl;

        size_t dlen = e - s + 1;
        if (len + dlen + 2 > cap) { free(buf); return NULL; }
        memcpy(buf + len, body + s, dlen);
        len += dlen;
        buf[len++] = '\r';
        buf[len++] = '\n';
    }

    int cl = snprintf(buf + len, cap - len, "--%s--\r\n", boundary);
    if (cl < 0 || (size_t)cl >= cap - len) { free(buf); return NULL; }
    len += (size_t)cl;

    *out_len = len;
    return buf;
}

TEST(test_range_multipart_two_ranges) {
    TEST_SUITE("http_range_filter: multipart/byteranges");
    TEST_CASE("two ranges produce a well-formed multipart body");

    range_fixture_t fx;
    char* exp = NULL;
    size_t explen = 0;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 0, 9) != NULL, "first range", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 20, 29) != NULL, "second range", cleanup);
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "status should be 206");
    http_header_t* ct = fx.response->get_header(fx.response, "Content-Type");
    TEST_REQUIRE_NOT_NULL_GOTO(ct, "Content-Type should be set", cleanup);
    TEST_ASSERT(strstr(ct->value, "multipart/byteranges") != NULL,
                "Content-Type is multipart/byteranges");

    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body should drain", cleanup);

    const char* b = extract_boundary(fx.response);
    TEST_REQUIRE_NOT_NULL_GOTO(b, "boundary should be present", cleanup);
    rspec_t rs[2] = { {0, 9}, {20, 29} };
    exp = build_expected_multipart(b, "application/octet-stream", body, 1000, rs, 2, &explen);
    TEST_REQUIRE_NOT_NULL_GOTO(exp, "expected buffer should be allocated", cleanup);
    TEST_ASSERT_EQUAL_SIZE(explen, fx.sink.size, "emitted body length matches expected");
    TEST_ASSERT(fx.sink.size == 0 || memcmp(fx.sink.data, exp, explen) == 0,
                "multipart body matches expected structure");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "exactly one final chunk");

    http_header_t* cl = fx.response->get_header(fx.response, "Content-Length");
    TEST_REQUIRE_NOT_NULL_GOTO(cl, "Content-Length should be set", cleanup);
    TEST_ASSERT_EQUAL_SIZE(explen, (size_t)strtoull(cl->value, NULL, 10),
                           "Content-Length == emitted body length");

    cleanup:
    free(exp);
    fixture_teardown(&fx);
}

TEST(test_range_multipart_three_ranges) {
    TEST_SUITE("http_range_filter: multipart/byteranges");
    TEST_CASE("three ranges, including a suffix range, frame correctly");

    range_fixture_t fx;
    char* exp = NULL;
    size_t explen = 0;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 0, 0) != NULL, "range 0-0", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 100, 199) != NULL, "range 100-199", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, -1, 50) != NULL, "suffix -50", cleanup);
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "status should be 206");

    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body should drain", cleanup);

    const char* b = extract_boundary(fx.response);
    TEST_REQUIRE_NOT_NULL_GOTO(b, "boundary should be present", cleanup);
    /* suffix -50 on a 1000-byte body = bytes 950-999. */
    rspec_t rs[3] = { {0, 0}, {100, 199}, {950, 999} };
    exp = build_expected_multipart(b, "application/octet-stream", body, 1000, rs, 3, &explen);
    TEST_REQUIRE_NOT_NULL_GOTO(exp, "expected buffer should be allocated", cleanup);
    TEST_ASSERT_EQUAL_SIZE(explen, fx.sink.size, "emitted body length matches expected");
    TEST_ASSERT(fx.sink.size == 0 || memcmp(fx.sink.data, exp, explen) == 0,
                "multipart body matches expected structure");

    cleanup:
    free(exp);
    fixture_teardown(&fx);
}

TEST(test_range_multipart_replays_content_type) {
    TEST_SUITE("http_range_filter: multipart/byteranges");
    TEST_CASE("the original Content-Type is replayed in each part");

    range_fixture_t fx;
    char* exp = NULL;
    size_t explen = 0;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 0, 4) != NULL, "range 0-4", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 10, 14) != NULL, "range 10-14", cleanup);
    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Type", "text/plain; charset=utf-8"),
                      "original Content-Type should be set", cleanup);
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)('a' + i % 26);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    /* Top-level Content-Type is now multipart; the original moved into parts. */
    http_header_t* ct = fx.response->get_header(fx.response, "Content-Type");
    TEST_REQUIRE_NOT_NULL_GOTO(ct, "Content-Type should be set", cleanup);
    TEST_ASSERT(strstr(ct->value, "multipart/byteranges") != NULL, "top-level is multipart");
    TEST_ASSERT(strstr(ct->value, "text/plain") == NULL, "original type is not in the top-level header");

    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body should drain", cleanup);

    const char* b = extract_boundary(fx.response);
    TEST_REQUIRE_NOT_NULL_GOTO(b, "boundary should be present", cleanup);
    rspec_t rs[2] = { {0, 4}, {10, 14} };
    exp = build_expected_multipart(b, "text/plain; charset=utf-8", body, 1000, rs, 2, &explen);
    TEST_REQUIRE_NOT_NULL_GOTO(exp, "expected buffer should be allocated", cleanup);
    TEST_ASSERT_EQUAL_SIZE(explen, fx.sink.size, "emitted body length matches expected");
    TEST_ASSERT(fx.sink.size == 0 || memcmp(fx.sink.data, exp, explen) == 0,
                "each part carries the original Content-Type");

    cleanup:
    free(exp);
    fixture_teardown(&fx);
}

TEST(test_range_multipart_multi_chunk) {
    TEST_SUITE("http_range_filter: multipart/byteranges");
    TEST_CASE("a multipart body larger than the 16K buffer streams across chunks");

    range_fixture_t fx;
    char* body = NULL;
    char* exp = NULL;
    size_t explen = 0;
    enum { data_size = 50000 };
    TEST_REQUIRE(fixture_setup(&fx, data_size + 4096), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 0, 20000) != NULL, "range 0-20000", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 30000, 49999) != NULL, "range 30000-49999", cleanup);
    body = malloc(data_size);
    TEST_REQUIRE_GOTO(body != NULL, "body should be allocated", cleanup);
    for (size_t i = 0; i < data_size; i++) body[i] = (char)((i * 7) % 251);
    body_set(&fx, body, data_size);

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body should drain", cleanup);

    const char* b = extract_boundary(fx.response);
    TEST_REQUIRE_NOT_NULL_GOTO(b, "boundary should be present", cleanup);
    rspec_t rs[2] = { {0, 20000}, {30000, 49999} };
    exp = build_expected_multipart(b, "application/octet-stream", body, data_size, rs, 2, &explen);
    TEST_REQUIRE_NOT_NULL_GOTO(exp, "expected buffer should be allocated", cleanup);
    TEST_ASSERT_EQUAL_SIZE(explen, fx.sink.size, "streamed length matches expected");
    TEST_ASSERT(memcmp(fx.sink.data, exp, explen) == 0, "reassembled multipart body is byte-exact");
    TEST_ASSERT(fx.sink.body_calls > 1, "the body should span more than one buffer");

    cleanup:
    free(exp);
    free(body);
    fixture_teardown(&fx);
}

TEST(test_range_multipart_partial_write_resume) {
    TEST_SUITE("http_range_filter: multipart/byteranges");
    TEST_CASE("a partial downstream write resumes and still yields the exact body");

    range_fixture_t fx;
    char* exp = NULL;
    size_t explen = 0;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 0, 99) != NULL, "range 0-99", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 200, 299) != NULL, "range 200-299", cleanup);
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    fx.sink.max_take_once = 64;   /* force many CWF_EVENT_AGAIN resumes */

    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body should drain", cleanup);

    const char* b = extract_boundary(fx.response);
    TEST_REQUIRE_NOT_NULL_GOTO(b, "boundary should be present", cleanup);
    rspec_t rs[2] = { {0, 99}, {200, 299} };
    exp = build_expected_multipart(b, "application/octet-stream", body, 1000, rs, 2, &explen);
    TEST_REQUIRE_NOT_NULL_GOTO(exp, "expected buffer should be allocated", cleanup);
    TEST_ASSERT_EQUAL_SIZE(explen, fx.sink.size, "resumed length matches expected");
    TEST_ASSERT(memcmp(fx.sink.data, exp, explen) == 0, "resumed multipart body is byte-exact");
    TEST_ASSERT_EQUAL_UINT(0, fx.sink.got_null_body, "no NULL buffer should reach the sink");

    cleanup:
    free(exp);
    fixture_teardown(&fx);
}

TEST(test_range_multipart_file_backed) {
    TEST_SUITE("http_range_filter: multipart/byteranges");
    TEST_CASE("a file-backed multi-range response slices each range via pread");

    range_fixture_t fx;
    char* content = NULL;
    char* exp = NULL;
    size_t explen = 0;
    enum { data_size = 40000 };
    TEST_REQUIRE(fixture_setup(&fx, data_size + 4096), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 10, 19) != NULL, "range 10-19", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 1000, 1020) != NULL, "range 1000-1020", cleanup);
    content = malloc(data_size);
    TEST_REQUIRE_GOTO(content != NULL, "content should be allocated", cleanup);
    for (size_t i = 0; i < data_size; i++) content[i] = (char)((i * 3) % 250);
    TEST_REQUIRE_GOTO(file_set(&fx, content, data_size) > -1, "temp file should be created", cleanup);

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "status should be 206");
    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body should drain", cleanup);

    const char* b = extract_boundary(fx.response);
    TEST_REQUIRE_NOT_NULL_GOTO(b, "boundary should be present", cleanup);
    rspec_t rs[2] = { {10, 19}, {1000, 1020} };
    exp = build_expected_multipart(b, "application/octet-stream", content, data_size, rs, 2, &explen);
    TEST_REQUIRE_NOT_NULL_GOTO(exp, "expected buffer should be allocated", cleanup);
    TEST_ASSERT_EQUAL_SIZE(explen, fx.sink.size, "file multipart length matches expected");
    TEST_ASSERT(memcmp(fx.sink.data, exp, explen) == 0, "file multipart body is byte-exact");

    cleanup:
    free(exp);
    free(content);
    fixture_teardown(&fx);
}

TEST(test_range_multipart_unsatisfiable_range_omitted) {
    TEST_SUITE("http_range_filter: multipart/byteranges");
    TEST_CASE("an unsatisfiable range within a multi-range request is omitted");

    range_fixture_t fx;
    char* exp = NULL;
    size_t explen = 0;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 0, 9) != NULL, "range 0-9 (satisfiable)", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 2000, 3000) != NULL, "range 2000-3000 (beyond EOF)", cleanup);
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "still 206 multipart (1 satisfiable part)");
    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body should drain", cleanup);

    const char* b = extract_boundary(fx.response);
    TEST_REQUIRE_NOT_NULL_GOTO(b, "boundary should be present", cleanup);
    /* Only the satisfiable range 0-9 appears; the beyond-EOF range is dropped. */
    rspec_t rs[1] = { {0, 9} };
    exp = build_expected_multipart(b, "application/octet-stream", body, 1000, rs, 1, &explen);
    TEST_REQUIRE_NOT_NULL_GOTO(exp, "expected buffer should be allocated", cleanup);
    TEST_ASSERT_EQUAL_SIZE(explen, fx.sink.size, "only the satisfiable part is emitted");
    TEST_ASSERT(memcmp(fx.sink.data, exp, explen) == 0, "body matches the single-part multipart");

    cleanup:
    free(exp);
    fixture_teardown(&fx);
}

TEST(test_range_multipart_all_unsatisfiable_416) {
    TEST_SUITE("http_range_filter: multipart/byteranges");
    TEST_CASE("all ranges unsatisfiable -> 416, no body");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 2000, 3000) != NULL, "range 2000-3000", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 4000, 5000) != NULL, "range 4000-5000", cleanup);
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(416, fx.response->status_code, "all unsatisfiable -> 416");
    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL_GOTO(cr, "416 carries Content-Range", cleanup);
    TEST_ASSERT_STR_EQUAL("bytes */1000", cr->value, "416 Content-Range form");

    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body phase should finish", cleanup);
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "416 produces no body");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// HEAD / inactive pass-through
// ============================================================================

TEST(test_range_body_head_request_no_body) {
    TEST_SUITE("http_range_filter: HEAD");
    TEST_CASE("HEAD + Range frames the 206 headers but must not emit a body");

    /* REGRESSION: the body handler generated and forwarded range chunks for
     * HEAD requests. The data filter could not catch it either — its range
     * branch forwards the parent buffer before its own HEAD check. */
    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_HEAD;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 0, 499), "range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "HEAD still gets the 206 framing");

    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL_GOTO(cr, "Content-Range should be present for HEAD", cleanup);
    TEST_ASSERT_STR_EQUAL("bytes 0-499/1000", cr->value, "Content-Range value");

    const int r = run_body_to_done(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "HEAD body phase should finish at once");
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "no body bytes for HEAD");
    TEST_ASSERT_EQUAL(0, fx.sink.body_calls, "downstream body should not be called");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_body_passthrough_when_inactive) {
    TEST_SUITE("http_range_filter: body passthrough");
    TEST_CASE("range == 0 forwards the parent buffer to the next filter untouched");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.request->method = ROUTE_GET;
    /* No Range header ran through __header: response->range stays 0. */

    char payload[] = "range-off-bytes";
    bufo_t parent;
    parent.data = payload;
    parent.capacity = sizeof(payload);
    parent.size = sizeof(payload) - 1;
    parent.pos = 0;
    parent.is_proxy = 1;
    parent.is_last = 1;

    fx.response->cur_filter = fx.range;
    const int r = fx.range->handler_body(fx.request, fx.response, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "the sink's result should be forwarded");
    TEST_ASSERT_EQUAL(1, fx.sink.body_calls, "downstream body should be called once");
    TEST_ASSERT(sink_equals(&fx, payload, sizeof(payload) - 1),
                "parent payload should be forwarded verbatim");

    fixture_teardown(&fx);
}

// ============================================================================
// __header: ignored Range sets (malformed / oversized)
// ============================================================================

TEST(test_range_header_malformed_node_passthrough) {
    TEST_SUITE("http_range_filter: header ignore");
    TEST_CASE("REGRESSION: a malformed range spec leaves the response untouched");

    /* range_handler_header used to stomp content/transfer encoding, set the
     * range flag and status 206 BEFORE validating the spec, then return
     * CWF_ERROR (connection close) for client-controlled input. A malformed
     * spec must instead ignore the Range header: plain 200, nothing mutated. */
    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, -2, 5), "malformed range should be set");
    char body[1000];
    body_set(&fx, body, sizeof(body));
    fx.response->transfer_encoding = TE_CHUNKED;   /* mutation canary */

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "status should stay 200");
    TEST_ASSERT_EQUAL_UINT(0, fx.response->range, "range flag should stay 0");
    TEST_ASSERT_EQUAL(TE_CHUNKED, fx.response->transfer_encoding,
                      "transfer encoding must not be stomped for an ignored Range");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Range"),
                     "no Content-Range for an ignored Range header");

    fixture_teardown(&fx);
}

TEST(test_range_header_malformed_second_node_passthrough) {
    TEST_SUITE("http_range_filter: header ignore");
    TEST_CASE("a malformed spec anywhere in the set ignores the whole header");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 0, 9) != NULL, "valid first range", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 20, -3) != NULL, "malformed second range", cleanup);
    char body[1000];
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "status should stay 200");
    TEST_ASSERT_EQUAL_UINT(0, fx.response->range, "range flag should stay 0");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Type"),
                     "no multipart framing for an ignored Range header");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_header_too_many_ranges_passthrough) {
    TEST_SUITE("http_range_filter: header ignore");
    TEST_CASE("more than RANGE_MAX_PARTS ranges are ignored (no amplification)");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.request->method = ROUTE_GET;

    int appended = 1;
    for (ssize_t i = 0; i < 65; i++)
        if (ranges_append(fx.request, i * 10, i * 10 + 5) == NULL)
            appended = 0;
    TEST_REQUIRE_GOTO(appended, "65 ranges should be appended", cleanup);

    char body[1000];
    body_set(&fx, body, sizeof(body));

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "status should stay 200 (full response)");
    TEST_ASSERT_EQUAL_UINT(0, fx.response->range, "range flag should stay 0");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Range"),
                     "no Content-Range when the set is ignored");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Type"),
                     "no multipart Content-Type when the set is ignored");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_header_suffix_longer_than_resource) {
    TEST_SUITE("http_range_filter: header framing");
    TEST_CASE("bytes=-5000 on a 1000-byte body serves the whole representation");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 2048), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, -1, 5000), "oversized suffix should be set");
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "status should be 206");

    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL_GOTO(cr, "Content-Range should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("bytes 0-999/1000", cr->value, "suffix clamped to the whole resource");

    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "body should drain", cleanup);
    TEST_ASSERT(sink_equals(&fx, body, 1000), "the whole body should be delivered");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// __body: file path, multi-chunk
// ============================================================================

TEST(test_range_body_file_multi_chunk) {
    TEST_SUITE("http_range_filter: body (file path)");
    TEST_CASE("a file-backed range larger than 16K streams across pread chunks");

    range_fixture_t fx;
    char* content = NULL;
    enum { data_size = 40000 };
    TEST_REQUIRE(fixture_setup(&fx, data_size), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(add_range(fx.request, 0, -1) != NULL, "open range should be set", cleanup);

    content = malloc(data_size);
    TEST_REQUIRE_GOTO(content != NULL, "content buffer should be allocated", cleanup);
    for (size_t i = 0; i < data_size; i++) content[i] = (char)((i * 11) % 251);
    TEST_REQUIRE_GOTO(file_set(&fx, content, data_size) > -1, "temp file should be created", cleanup);

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header should succeed", cleanup);

    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL_GOTO(cr, "Content-Range should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("bytes 0-39999/40000", cr->value, "whole-file Content-Range");

    const int r = run_body_to_done(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "body should drain to completion");
    TEST_ASSERT(fx.sink.body_calls >= 3, "40000 bytes should span several 16K chunks");
    TEST_ASSERT(sink_equals(&fx, content, data_size), "reassembled file should be byte-exact");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "exactly one final chunk should be marked");

    cleanup:
    free(content);
    fixture_teardown(&fx);
}

// ============================================================================
// Reset: keep-alive reuse
// ============================================================================

/* Rewind the fixture the way a keep-alive connection does between requests:
 * reset the response (headers, status, flags), reset the module under test
 * and clear the sink capture. */
static void fixture_next_request(range_fixture_t* fx) {
    fx->response->base.reset(fx->response);
    fx->module->base.reset(fx->module);

    http_ranges_free(fx->request->ranges);
    fx->request->ranges = NULL;

    fx->sink.size = 0;
    fx->sink.header_calls = 0;
    fx->sink.body_calls = 0;
    fx->sink.saw_last = 0;
    fx->sink.got_null_body = 0;
    fx->sink.max_take_once = 0;
}

TEST(test_range_reset_reuse_multipart_then_single) {
    TEST_SUITE("http_range_filter: reset reuse");
    TEST_CASE("after a multipart response, reset serves a clean single range");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 8192), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 0, 9) != NULL, "first range", cleanup);
    TEST_REQUIRE_GOTO(ranges_append(fx.request, 20, 29) != NULL, "second range", cleanup);
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "multipart header should succeed", cleanup);
    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "multipart body should drain", cleanup);
    TEST_REQUIRE_GOTO(fx.sink.size > 20, "multipart body should not be empty", cleanup);

    /* Second request on the same (keep-alive) connection: single range. */
    fixture_next_request(&fx);
    TEST_ASSERT_EQUAL_UINT(0, fx.module->mp_active, "multipart mode should be cleared by reset");

    TEST_REQUIRE_GOTO(add_range(fx.request, 10, 19) != NULL, "second-request range", cleanup);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "second header should succeed", cleanup);
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "second response should be 206");

    http_header_t* cr = fx.response->get_header(fx.response, "Content-Range");
    TEST_REQUIRE_NOT_NULL_GOTO(cr, "second Content-Range should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("bytes 10-19/1000", cr->value, "second Content-Range value");

    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "second body should drain", cleanup);
    TEST_ASSERT(sink_equals(&fx, body + 10, 10),
                "second response must be the plain slice with no leftover multipart framing");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "exactly one final chunk on the second response");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_range_reset_reuse_after_416) {
    TEST_SUITE("http_range_filter: reset reuse");
    TEST_CASE("after a 416, reset serves a normal 206 with a body again");

    range_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.request->method = ROUTE_GET;
    TEST_REQUIRE_NOT_NULL(add_range(fx.request, 2000, -1), "unsatisfiable range should be set");
    char body[1000];
    for (int i = 0; i < 1000; i++) body[i] = (char)(i % 251);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "416 header should succeed", cleanup);
    TEST_REQUIRE_GOTO(fx.response->status_code == 416, "should be 416", cleanup);
    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "416 body phase should finish", cleanup);

    /* Second request: a stale unsatisfiable flag would suppress this body. */
    fixture_next_request(&fx);

    TEST_REQUIRE_GOTO(add_range(fx.request, 0, 9) != NULL, "second-request range", cleanup);
    body_set(&fx, body, sizeof(body));

    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "second header should succeed", cleanup);
    TEST_ASSERT_EQUAL(206, fx.response->status_code, "second response should be 206");

    TEST_REQUIRE_GOTO(run_body_to_done(&fx) == CWF_OK, "second body should drain", cleanup);
    TEST_ASSERT(sink_equals(&fx, body, 10), "second response should deliver body[0..9]");

    cleanup:
    fixture_teardown(&fx);
}

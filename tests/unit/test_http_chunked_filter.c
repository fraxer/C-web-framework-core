/*
 * Unit tests for protocols/http/server/filters/http_chunked_filter.c
 *
 * Covers module/filter construction, http_chunked_header (Transfer-Encoding
 * negotiation, buffer allocation, pass-through and CWF_EVENT_AGAIN resume) and
 * http_chunked_body (framing, hex chunk heads, multi-parent bodies, parents
 * larger than the 16K output buffer, partial-write resume and reset/reuse).
 * The chunked stream captured by the sink filter is verified with a small
 * chunked decoder.
 *
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - an empty last parent buffer was framed as a zero-size data chunk, so the
 *     stream ended with a double terminator "0\r\n\r\n0\r\n\r\n" (the extra
 *     bytes desync keep-alive framing);
 *   - an empty intermediate parent buffer emitted "0\r\n\r\n" mid-stream,
 *     terminating the response early;
 *   - when the parent buffer was exhausted but the trailing "\r\n"/"0\r\n\r\n"
 *     had not fit into the output buffer, http_chunked_body returned without
 *     flushing the trailer, truncating the response;
 *   - HTTP_MODULE_CHUNKED_DATA appended the whole parent remainder instead of
 *     clamping to the announced chunk size; a parent buffer swapped/refilled
 *     mid-chunk pushed state_pos past current_chunk_size and chunked_process
 *     span forever (infinite busy loop);
 *   - chunked_process ignored bufo_append's -1 (unallocated output buffer):
 *     state_pos underflowed to SIZE_MAX and the next pass memcpy'd from a wild
 *     pointer; allocation failures were swallowed the same way, turning OOM
 *     into an infinite loop instead of CWF_ERROR.
 */

#include "framework.h"
#include "httpresponse.h"
#include "http_chunked_filter.h"
#include "connection_s.h"

#include <string.h>
#include <stdlib.h>

#define CHUNKED_BUF_SIZE 16384

// ============================================================================
// Fixture: chunked filter chained into a capturing sink filter
// ============================================================================

static connection_server_ctx_t test_chunked_ctx;

static connection_t* make_connection(void) {
    connection_t* conn = calloc(1, sizeof(connection_t));
    if (conn == NULL) return NULL;

    memset(&test_chunked_ctx, 0, sizeof(test_chunked_ctx));
    conn->ctx = &test_chunked_ctx;
    conn->keepalive = 0;

    return conn;
}

/* Sink filter: captures everything the chunked filter emits and mimics the
 * write filter contract — consumes buf from buf->pos, returns CWF_DATA_AGAIN
 * when drained and CWF_EVENT_AGAIN after a scripted partial consume. */
typedef struct {
    http_module_t base;
    char* data;
    size_t size;
    size_t capacity;
    size_t max_take_once;   /* one-shot partial consume -> CWF_EVENT_AGAIN */
    int header_again_once;  /* one-shot CWF_EVENT_AGAIN from handler_header */
    int header_calls;
    int body_calls;
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
    http_filter_t* chunked;
    http_filter_t sink_filter;
    sink_module_t sink;
    http_module_chunked_t* module;
} chunked_fixture_t;

static int fixture_setup(chunked_fixture_t* fx, size_t sink_capacity) {
    memset(fx, 0, sizeof(*fx));

    fx->conn = make_connection();
    if (fx->conn == NULL) return 0;

    fx->response = httpresponse_create(fx->conn);
    if (fx->response == NULL) {
        free(fx->conn);
        return 0;
    }

    fx->chunked = http_chunked_filter_create();
    fx->sink.data = malloc(sink_capacity);
    if (fx->chunked == NULL || fx->sink.data == NULL) {
        if (fx->chunked != NULL) {
            http_module_t* module = fx->chunked->module;
            module->free(fx->chunked->module);
            free(fx->chunked);
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

    fx->chunked->next = &fx->sink_filter;
    fx->module = fx->chunked->module;

    fx->response->transfer_encoding = TE_CHUNKED;

    return 1;
}

static void fixture_teardown(chunked_fixture_t* fx) {
    if (fx->chunked != NULL) {
        http_module_t* module = fx->chunked->module;
        module->free(fx->chunked->module);
        free(fx->chunked);
    }

    free(fx->sink.data);

    if (fx->response != NULL)
        httpresponse_free(fx->response);

    free(fx->conn);
}

static int run_header(chunked_fixture_t* fx) {
    fx->response->cur_filter = fx->chunked;
    return fx->chunked->handler_header(NULL, fx->response);
}

static int run_body(chunked_fixture_t* fx, bufo_t* parent) {
    fx->response->cur_filter = fx->chunked;
    return fx->chunked->handler_body(NULL, fx->response, parent);
}

static void parent_init(bufo_t* parent, char* data, size_t size, int is_last) {
    parent->data = data;
    parent->capacity = size;
    parent->size = size;
    parent->pos = 0;
    parent->is_proxy = 1;
    parent->is_last = is_last ? 1 : 0;
}

/* Strict chunked-transfer decoder: requires well-formed heads/separators and
 * the terminating "0\r\n\r\n" exactly at the end of the input. Returns the
 * decoded size or -1 on malformed input. */
static ssize_t chunked_decode(const char* in, size_t in_size, char* out, size_t out_capacity) {
    size_t i = 0;
    size_t o = 0;

    while (1) {
        size_t size = 0;
        int digits = 0;

        while (i < in_size && in[i] != '\r') {
            const char c = in[i];
            int value;

            if (c >= '0' && c <= '9') value = c - '0';
            else if (c >= 'a' && c <= 'f') value = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') value = c - 'A' + 10;
            else return -1;

            size = size * 16 + value;
            digits++;
            i++;
        }

        if (digits == 0 || i + 2 > in_size || in[i] != '\r' || in[i + 1] != '\n')
            return -1;

        i += 2;

        if (size == 0) {
            if (i + 2 != in_size || in[i] != '\r' || in[i + 1] != '\n')
                return -1;

            return (ssize_t)o;
        }

        if (i + size + 2 > in_size || o + size > out_capacity)
            return -1;

        memcpy(out + o, in + i, size);
        o += size;
        i += size;

        if (in[i] != '\r' || in[i + 1] != '\n')
            return -1;

        i += 2;
    }
}

static int sink_content_equals(chunked_fixture_t* fx, const char* expected, size_t expected_size) {
    return fx->sink.size == expected_size
        && memcmp(fx->sink.data, expected, expected_size) == 0;
}

// ============================================================================
// Construction
// ============================================================================

TEST(test_chunked_filter_create_defaults) {
    TEST_SUITE("http_chunked_filter: construction");
    TEST_CASE("filter and module are initialized with clean defaults");

    http_filter_t* filter = http_chunked_filter_create();
    TEST_REQUIRE_NOT_NULL(filter, "filter should be created");

    TEST_ASSERT(filter->handler_header == http_chunked_header, "handler_header should be set");
    TEST_ASSERT(filter->handler_body == http_chunked_body, "handler_body should be set");
    TEST_ASSERT_NULL(filter->next, "next filter should be NULL");
    TEST_REQUIRE_NOT_NULL(filter->module, "module should be created");

    http_module_chunked_t* module = filter->module;
    TEST_ASSERT_EQUAL_UINT(0, module->base.cont, "cont should be 0");
    TEST_ASSERT_EQUAL_UINT(0, module->base.done, "done should be 0");
    TEST_ASSERT_NULL(module->base.parent_buf, "parent_buf should be NULL");
    TEST_ASSERT(module->base.free == http_chunked_free, "free callback should be set");
    TEST_ASSERT_NOT_NULL(module->buf, "output buffer should be created");
    TEST_ASSERT_NULL(module->buf->data, "output buffer should not be allocated yet");
    TEST_ASSERT_EQUAL(HTTP_MODULE_CHUNKED_SIZE, module->state, "state should start at SIZE");
    TEST_ASSERT_EQUAL_SIZE(0, module->state_pos, "state_pos should be 0");
    TEST_ASSERT_NULL(module->chunk_head, "chunk_head should be lazy");
    TEST_ASSERT_EQUAL_SIZE(0, module->chunk_head_size, "chunk_head_size should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, module->current_chunk_size, "current_chunk_size should be 0");

    module->base.free(module);
    free(filter);
}

// ============================================================================
// http_chunked_header
// ============================================================================

TEST(test_chunked_header_adds_te_and_allocates) {
    TEST_SUITE("http_chunked_filter: header");
    TEST_CASE("chunked encoding adds Transfer-Encoding and allocates the buffer");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(1, fx.sink.header_calls, "next filter should be called once");

    http_header_t* header = fx.response->get_header(fx.response, "Transfer-Encoding");
    TEST_REQUIRE_NOT_NULL_GOTO(header, "Transfer-Encoding header should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("chunked", header->value, "Transfer-Encoding should be chunked");

    TEST_ASSERT_NOT_NULL(fx.module->buf->data, "output buffer should be allocated");
    TEST_ASSERT_EQUAL_SIZE(CHUNKED_BUF_SIZE, fx.module->buf->capacity, "output buffer should be 16K");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_header_keeps_existing_te) {
    TEST_SUITE("http_chunked_filter: header");
    TEST_CASE("existing Transfer-Encoding header is not duplicated");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Transfer-Encoding", "gzip, chunked"),
                      "precondition header should be added", cleanup);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");

    int count = 0;
    for (http_header_t* header = fx.response->header_; header != NULL; header = header->next)
        if (strcmp(header->key, "Transfer-Encoding") == 0)
            count++;

    TEST_ASSERT_EQUAL(1, count, "Transfer-Encoding should stay unique");

    http_header_t* header = fx.response->get_header(fx.response, "Transfer-Encoding");
    TEST_REQUIRE_NOT_NULL_GOTO(header, "Transfer-Encoding header should exist", cleanup);
    TEST_ASSERT_STR_EQUAL("gzip, chunked", header->value, "existing value should be kept");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_header_te_none_passthrough) {
    TEST_SUITE("http_chunked_filter: header");
    TEST_CASE("TE_NONE passes through without header or allocation");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.response->transfer_encoding = TE_NONE;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(1, fx.sink.header_calls, "next filter should be called once");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Transfer-Encoding"),
                     "no Transfer-Encoding header should be added");
    TEST_ASSERT_NULL(fx.module->buf->data, "output buffer should not be allocated");

    fixture_teardown(&fx);
}

TEST(test_chunked_header_last_modified_passthrough) {
    TEST_SUITE("http_chunked_filter: header");
    TEST_CASE("last_modified responses pass through untouched");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.response->last_modified = 1;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Transfer-Encoding"),
                     "no Transfer-Encoding header should be added");
    TEST_ASSERT_NULL(fx.module->buf->data, "output buffer should not be allocated");

    fixture_teardown(&fx);
}

TEST(test_chunked_header_event_again_resume) {
    TEST_SUITE("http_chunked_filter: header");
    TEST_CASE("CWF_EVENT_AGAIN sets cont and the retry does not re-add the header");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.sink.header_again_once = 1;

    int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "first pass should propagate CWF_EVENT_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.cont, "cont should be set for resume");

    r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "second pass should finish with CWF_OK");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT_EQUAL(2, fx.sink.header_calls, "next filter should be called twice");

    int count = 0;
    for (http_header_t* header = fx.response->header_; header != NULL; header = header->next)
        if (strcmp(header->key, "Transfer-Encoding") == 0)
            count++;

    TEST_ASSERT_EQUAL(1, count, "Transfer-Encoding should be added exactly once");

    fixture_teardown(&fx);
}

// ============================================================================
// http_chunked_body: framing
// ============================================================================

TEST(test_chunked_body_single_chunk_last) {
    TEST_SUITE("http_chunked_filter: body");
    TEST_CASE("single last parent produces one chunk and the terminator");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    char data[] = "Hello";
    bufo_t parent;
    parent_init(&parent, data, 5, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should report CWF_DATA_AGAIN");
    TEST_ASSERT(sink_content_equals(&fx, "5\r\nHello\r\n0\r\n\r\n", 15),
                "output should be a single framed chunk plus terminator");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.done, "module should be done");
    TEST_ASSERT_EQUAL_SIZE(5, parent.pos, "parent should be fully consumed");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_body_two_parents) {
    TEST_SUITE("http_chunked_filter: body");
    TEST_CASE("two parent buffers produce two chunks, terminator after the last");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    char first[] = "Hello";
    bufo_t parent;
    parent_init(&parent, first, 5, 0);

    int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "first body pass should report CWF_DATA_AGAIN");
    TEST_ASSERT(sink_content_equals(&fx, "5\r\nHello\r\n", 10),
                "intermediate parent should not emit a terminator");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.done, "module should not be done yet");

    char second[] = "World!";
    parent_init(&parent, second, 6, 1);

    r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "second body pass should report CWF_DATA_AGAIN");
    TEST_ASSERT(sink_content_equals(&fx, "5\r\nHello\r\n6\r\nWorld!\r\n0\r\n\r\n", 26),
                "second chunk should be appended with the terminator");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.done, "module should be done");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_body_hex_head) {
    TEST_SUITE("http_chunked_filter: body");
    TEST_CASE("chunk size is written in lower-case hex");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    char data[255];
    memset(data, 'x', sizeof(data));

    bufo_t parent;
    parent_init(&parent, data, sizeof(data), 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should report CWF_DATA_AGAIN");
    TEST_REQUIRE_GOTO(fx.sink.size > 4, "output should not be empty", cleanup);
    TEST_ASSERT(memcmp(fx.sink.data, "ff\r\n", 4) == 0, "chunk head should be 'ff\\r\\n'");

    char decoded[512];
    const ssize_t decoded_size = chunked_decode(fx.sink.data, fx.sink.size, decoded, sizeof(decoded));
    TEST_ASSERT_EQUAL(255, decoded_size, "decoded size should match the input");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_body_te_none_passthrough) {
    TEST_SUITE("http_chunked_filter: body");
    TEST_CASE("TE_NONE passes the parent buffer through unframed");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    fx.response->transfer_encoding = TE_NONE;

    char data[] = "raw body";
    bufo_t parent;
    parent_init(&parent, data, 8, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "sink result should be forwarded");
    TEST_ASSERT(sink_content_equals(&fx, "raw body", 8), "payload should be unmodified");
    TEST_ASSERT_EQUAL(1, fx.sink.body_calls, "sink should be called once");

    fixture_teardown(&fx);
}

TEST(test_chunked_body_large_parent_spans_buffers) {
    TEST_SUITE("http_chunked_filter: body");
    TEST_CASE("parent larger than the 16K output buffer is framed as one chunk");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 17), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    enum { data_size = 40000 };
    char* data = malloc(data_size);
    char* decoded = malloc(data_size);
    TEST_REQUIRE_GOTO(data != NULL && decoded != NULL, "test buffers should be allocated", cleanup_buffers);

    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('a' + i % 26);

    bufo_t parent;
    parent_init(&parent, data, data_size, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should report CWF_DATA_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.done, "module should be done");
    TEST_ASSERT(fx.sink.body_calls > 1, "output should span several sink flushes");
    TEST_ASSERT_EQUAL_SIZE(data_size, parent.pos, "parent should be fully consumed");

    const ssize_t decoded_size = chunked_decode(fx.sink.data, fx.sink.size, decoded, data_size);
    TEST_ASSERT_EQUAL(data_size, decoded_size, "stream should decode to the input size");
    TEST_ASSERT(decoded_size == data_size && memcmp(decoded, data, data_size) == 0,
                "decoded payload should match the input");

    cleanup_buffers:
    free(data);
    free(decoded);

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_body_event_again_resume) {
    TEST_SUITE("http_chunked_filter: body");
    TEST_CASE("partial downstream write resumes without losing or repeating bytes");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    char data[] = "Hello world";
    bufo_t parent;
    parent_init(&parent, data, 11, 1);

    fx.sink.max_take_once = 4;

    int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "partial write should propagate CWF_EVENT_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.cont, "cont should be set for resume");
    TEST_ASSERT_EQUAL_SIZE(4, fx.sink.size, "only the consumed prefix should be captured");

    r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "resumed pass should report CWF_DATA_AGAIN");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT(sink_content_equals(&fx, "b\r\nHello world\r\n0\r\n\r\n", 21),
                "resumed stream should be complete and correct");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// http_chunked_body: regression guards
// ============================================================================

TEST(test_chunked_body_empty_last_parent_single_terminator) {
    TEST_SUITE("http_chunked_filter: regressions");
    TEST_CASE("REGRESSION: empty last parent emits exactly one terminator");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    bufo_t parent;
    parent_init(&parent, NULL, 0, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should report CWF_DATA_AGAIN");
    TEST_ASSERT(sink_content_equals(&fx, "0\r\n\r\n", 5),
                "output should be the terminator only, not a zero-size data chunk");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.done, "module should be done");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_body_empty_intermediate_parent_no_terminator) {
    TEST_SUITE("http_chunked_filter: regressions");
    TEST_CASE("REGRESSION: empty intermediate parent emits nothing");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    bufo_t parent;
    parent_init(&parent, NULL, 0, 0);

    int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should report CWF_DATA_AGAIN");
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "no bytes should be emitted mid-stream");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.done, "module should not be done");

    char data[] = "Hi";
    parent_init(&parent, data, 2, 1);

    r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "follow-up body pass should report CWF_DATA_AGAIN");
    TEST_ASSERT(sink_content_equals(&fx, "2\r\nHi\r\n0\r\n\r\n", 12),
                "stream should continue normally after the empty flush");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_body_trailer_flushed_when_parent_exhausted) {
    TEST_SUITE("http_chunked_filter: regressions");
    TEST_CASE("REGRESSION: terminator split across output buffers is still flushed");

    /* 32760 bytes: the second 16K output pass ends exactly at the chunk
     * separator, leaving "0\r\n\r\n" for a third pass after the parent is
     * already exhausted — the old code returned without flushing it. */
    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 17), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    enum { data_size = 32760 };
    char* data = malloc(data_size);
    char* decoded = malloc(data_size);
    TEST_REQUIRE_GOTO(data != NULL && decoded != NULL, "test buffers should be allocated", cleanup_buffers);

    memset(data, 'z', data_size);

    bufo_t parent;
    parent_init(&parent, data, data_size, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should report CWF_DATA_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.done, "module should be done");

    const ssize_t decoded_size = chunked_decode(fx.sink.data, fx.sink.size, decoded, data_size);
    TEST_ASSERT_EQUAL(data_size, decoded_size, "stream should decode fully, terminator included");

    cleanup_buffers:
    free(data);
    free(decoded);

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_body_parent_swap_mid_chunk_no_infinite_loop) {
    TEST_SUITE("http_chunked_filter: regressions");
    TEST_CASE("REGRESSION: parent buffer swapped mid-chunk does not loop forever");

    /* Reproduces the data filter's cont path handing a different (larger)
     * buffer to a filter that is mid-chunk: the old DATA state appended the
     * whole parent remainder, state_pos jumped past current_chunk_size and
     * chunked_process span forever. The fixed code clamps to the announced
     * chunk size and completes the frame. */
    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 17), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    enum { first_size = 20000, second_size = 30000, first_take = 16378 };
    char* first = malloc(first_size);
    char* second = malloc(second_size);
    char* decoded = malloc(first_size);
    TEST_REQUIRE_GOTO(first != NULL && second != NULL && decoded != NULL,
                      "test buffers should be allocated", cleanup_buffers);

    memset(first, 'A', first_size);
    memset(second, 'B', second_size);

    /* Stall the downstream mid-chunk: 16384-byte output flushed only partially. */
    bufo_t parent;
    parent_init(&parent, first, first_size, 0);
    fx.sink.max_take_once = 10000;

    int r = run_body(&fx, &parent);
    TEST_REQUIRE_GOTO(r == CWF_EVENT_AGAIN, "first pass should stall with CWF_EVENT_AGAIN", cleanup_buffers);

    /* Resume with a different parent buffer while the 20000-byte chunk is
     * still open; only 20000 - 16378 bytes of it belong to that chunk. */
    bufo_t swapped;
    parent_init(&swapped, second, second_size, 1);

    r = run_body(&fx, &swapped);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "swapped pass should finish, not hang");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.done, "module should be done");
    TEST_ASSERT_EQUAL_SIZE(first_size - first_take, swapped.pos,
                           "only the open chunk's remainder should be consumed");

    const ssize_t decoded_size = chunked_decode(fx.sink.data, fx.sink.size, decoded, first_size);
    TEST_ASSERT_EQUAL(first_size, decoded_size, "frame should honor the announced chunk size");
    if (decoded_size == first_size) {
        TEST_ASSERT(memcmp(decoded, first, first_take) == 0,
                    "chunk should start with the first parent's bytes");
        TEST_ASSERT(memcmp(decoded + first_take, second, first_size - first_take) == 0,
                    "chunk should be completed from the swapped parent");
    }

    cleanup_buffers:
    free(first);
    free(second);
    free(decoded);

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_chunked_body_without_allocated_buffer_errors) {
    TEST_SUITE("http_chunked_filter: regressions");
    TEST_CASE("REGRESSION: body without an allocated output buffer fails cleanly");

    /* The old code fed bufo_append's -1 into a size_t: state_pos underflowed
     * and the next pass read from chunk_head + SIZE_MAX. */
    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");

    char data[] = "Hi";
    bufo_t parent;
    parent_init(&parent, data, 2, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_ERROR, r, "unallocated output buffer should yield CWF_ERROR");
    TEST_ASSERT_EQUAL_SIZE(0, fx.sink.size, "nothing should be emitted");

    fixture_teardown(&fx);
}

// ============================================================================
// Reset and reuse
// ============================================================================

TEST(test_chunked_reset_allows_reuse) {
    TEST_SUITE("http_chunked_filter: reset");
    TEST_CASE("reset clears the state machine and the module can be reused");

    chunked_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1024), "fixture should be created");
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    char first[] = "Hello";
    bufo_t parent;
    parent_init(&parent, first, 5, 1);

    TEST_REQUIRE_GOTO(run_body(&fx, &parent) == CWF_DATA_AGAIN, "first response should complete", cleanup);
    TEST_REQUIRE_GOTO(fx.module->base.done == 1, "first response should be done", cleanup);

    fx.module->base.reset(fx.module);

    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.done, "done should be cleared");
    TEST_ASSERT_NULL(fx.module->base.parent_buf, "parent_buf should be cleared");
    TEST_ASSERT_EQUAL(HTTP_MODULE_CHUNKED_SIZE, fx.module->state, "state should return to SIZE");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->state_pos, "state_pos should be cleared");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->chunk_head_size, "chunk_head_size should be cleared");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->current_chunk_size, "current_chunk_size should be cleared");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->buf->size, "output buffer should be flushed");
    TEST_ASSERT_EQUAL_SIZE(0, fx.module->buf->pos, "output buffer pos should be flushed");
    TEST_ASSERT_NOT_NULL(fx.module->buf->data, "output allocation should be kept for reuse");

    fx.sink.size = 0;

    char second[] = "Hi";
    parent_init(&parent, second, 2, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "module should work again after reset");
    TEST_ASSERT(sink_content_equals(&fx, "2\r\nHi\r\n0\r\n\r\n", 12),
                "second response should be framed correctly");

    cleanup:
    fixture_teardown(&fx);
}

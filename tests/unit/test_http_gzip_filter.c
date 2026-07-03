/*
 * Unit tests for protocols/http/server/filters/http_gzip_filter.c
 *
 * Covers filter/module construction, __header (Content-Encoding / TE_CHUNKED
 * negotiation, CE_NONE / small / last_modified / file pass-throughs,
 * CWF_EVENT_AGAIN resume) and __body (gzip deflate round-trip across single
 * and multiple parent buffers, incompressible input that overruns the 16K
 * output buffer, partial-write resume, pass-throughs). The compressed bytes
 * captured by the sink are validated with a real zlib inflate (gzip mode).
 *
 * Several cases are regression guards for bugs found by this audit (each is
 * marked REGRESSION below):
 *
 *   - __header switched transfer_encoding to TE_CHUNKED and added
 *     Content-Encoding: gzip but did NOT remove the Content-Length the
 *     upstream data filter had already added (the data filter runs first in
 *     the chain and adds Content-Length while transfer_encoding is still
 *     TE_NONE). The response then carried both Content-Length and
 *     Transfer-Encoding, forbidden by RFC 7230 §3.3.1, with a length that no
 *     longer matched the compressed body;
 *   - __process decided "more output pending" from gzip_want_continue()
 *     (avail_out == 0) alone and never checked gzip_is_end(). If the final
 *     Z_FINISH call filled the output buffer exactly while returning
 *     Z_STREAM_END, the loop deflated a finished stream and surfaced a
 *     spurious "compress error" / CWF_ERROR. A finished stream must not ask
 *     for another turn;
 *   - the deflate error path printed "compress error" to stdout instead of
 *     routing through log_error, polluting production logs;
 *   - the unconditional `return CWF_ERROR` after the while(1) in __body was
 *     unreachable dead code.
 */

#include "framework.h"
#include "httpresponse.h"
#include "httprequest.h"
#include "http_gzip_filter.h"
#include "connection_s.h"
#include "bufo.h"

#include <zlib.h>
#include <string.h>
#include <stdlib.h>

#define GZIP_BUF_SIZE 16384
#define GZIP_MIN_SIZE 1024   /* bodies smaller than this are not compressed */

// ============================================================================
// Fixture: gzip filter chained into a capturing sink filter
// ============================================================================

static connection_server_ctx_t test_gzip_ctx;

static connection_t* make_connection(void) {
    connection_t* conn = calloc(1, sizeof(connection_t));
    if (conn == NULL) return NULL;

    memset(&test_gzip_ctx, 0, sizeof(test_gzip_ctx));
    conn->ctx = &test_gzip_ctx;
    conn->keepalive = 0;

    return conn;
}

/* Sink filter: captures everything the gzip filter emits and mimics the
 * chunked/write-filter contract — consumes buf from buf->pos, returns
 * CWF_DATA_AGAIN when drained and CWF_EVENT_AGAIN after a scripted partial
 * consume. is_last on the received buffer is counted so the "gzip marked its
 * final output buffer as last" contract is observable. A NULL buf is recorded
 * (not dereferenced). */
typedef struct {
    http_module_t base;
    char* data;
    size_t size;
    size_t capacity;
    size_t max_take_once;   /* one-shot partial consume -> CWF_EVENT_AGAIN */
    int header_again_once;  /* one-shot CWF_EVENT_AGAIN from handler_header */
    int header_calls;
    int body_calls;
    int got_null_body;
    int saw_last;           /* incremented once per received buffer with is_last */
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

    if (buf->is_last)
        sink->saw_last++;

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
    http_filter_t* gzip;
    http_filter_t sink_filter;
    sink_module_t sink;
    http_module_gzip_t* module;
} gzip_fixture_t;

static int fixture_setup(gzip_fixture_t* fx, size_t sink_capacity) {
    memset(fx, 0, sizeof(*fx));

    fx->conn = make_connection();
    if (fx->conn == NULL) return 0;

    fx->response = httpresponse_create(fx->conn);
    if (fx->response == NULL) {
        free(fx->conn);
        return 0;
    }

    fx->gzip = http_gzip_filter_create();
    fx->sink.data = malloc(sink_capacity);
    if (fx->gzip == NULL || fx->sink.data == NULL) {
        if (fx->gzip != NULL) {
            http_module_t* module = fx->gzip->module;
            module->free(fx->gzip->module);
            free(fx->gzip);
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

    fx->gzip->next = &fx->sink_filter;
    fx->module = fx->gzip->module;

    fx->response->content_encoding = CE_GZIP;

    return 1;
}

static void fixture_teardown(gzip_fixture_t* fx) {
    if (fx->gzip != NULL) {
        http_module_t* module = fx->gzip->module;
        module->free(fx->gzip->module);
        free(fx->gzip);
    }

    free(fx->sink.data);

    if (fx->response != NULL)
        httpresponse_free(fx->response);

    free(fx->conn);
}

static int run_header(gzip_fixture_t* fx) {
    fx->response->cur_filter = fx->gzip;
    return fx->gzip->handler_header(NULL, fx->response);
}

static int run_body(gzip_fixture_t* fx, bufo_t* parent) {
    fx->response->cur_filter = fx->gzip;
    return fx->gzip->handler_body(NULL, fx->response, parent);
}

static void parent_init(bufo_t* parent, char* data, size_t size, int is_last) {
    parent->data = data;
    parent->capacity = size;
    parent->size = size;
    parent->pos = 0;
    parent->is_proxy = 1;
    parent->is_last = is_last ? 1 : 0;
}

/* The threshold check reads response->body.size (or file_.size); the actual
 * bytes come from the parent buffer argument. Point the response body at the
 * same payload and set its size so the >= 1024 gate engages. */
static void body_set_size(httpresponse_t* response, size_t size) {
    response->body.size = size;
    response->body.pos = 0;
}

/* Strict gzip decoder. Returns the decoded size or -1 on malformed input. */
static ssize_t inflate_gzip(const char* in, size_t in_size, char* out, size_t out_capacity) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    stream.next_in = (Bytef*)in;
    stream.avail_in = (uInt)in_size;
    stream.next_out = (Bytef*)out;
    stream.avail_out = (uInt)out_capacity;

    if (inflateInit2(&stream, MAX_WBITS + 16) != Z_OK)
        return -1;

    const int r = inflate(&stream, Z_FINISH);
    const uLong produced = stream.total_out;
    inflateEnd(&stream);

    if (r != Z_STREAM_END)
        return -1;

    return (ssize_t)produced;
}

/* Drive the gzip body path by feeding `data` in chunks of `chunk_size`, the
 * last chunk marked is_last. Handles CWF_EVENT_AGAIN resumes by re-offering
 * the same parent. Returns the last status from the filter (CWF_DATA_AGAIN on
 * a clean finish) or CWF_ERROR. */
static int feed_chunks(gzip_fixture_t* fx, const char* data, size_t data_size, size_t chunk_size) {
    size_t off = 0;

    while (1) {
        const size_t remaining = data_size - off;
        const size_t chunk = remaining < chunk_size ? remaining : chunk_size;
        const int is_last = (off + chunk) >= data_size;

        bufo_t parent;
        parent_init(&parent, (char*)(data + off), chunk, is_last);

        int r;
        while (1) {
            r = run_body(fx, &parent);
            if (r == CWF_EVENT_AGAIN)
                continue;  /* downstream partial write — re-offer same parent */
            break;
        }

        if (r == CWF_ERROR)
            return CWF_ERROR;

        off += chunk;

        if (is_last)
            return r;
    }
}

static int sink_inflates_to(gzip_fixture_t* fx, const void* expected, size_t expected_size) {
    char* out = malloc(expected_size ? expected_size : 1);
    if (out == NULL)
        return 0;

    const ssize_t decoded = inflate_gzip(fx->sink.data, fx->sink.size, out, expected_size);
    const int ok = decoded == (ssize_t)expected_size
        && memcmp(out, expected, expected_size) == 0;

    free(out);
    return ok;
}

static int header_count(httpresponse_t* response, const char* key) {
    int count = 0;
    for (http_header_t* h = response->header_; h != NULL; h = h->next)
        if (strcmp(h->key, key) == 0)
            count++;
    return count;
}

// ============================================================================
// Construction
// ============================================================================

TEST(test_gzip_filter_create_defaults) {
    TEST_SUITE("http_gzip_filter: construction");
    TEST_CASE("filter and module are initialized with clean defaults");

    http_filter_t* filter = http_gzip_filter_create();
    TEST_REQUIRE_NOT_NULL(filter, "filter should be created");

    TEST_ASSERT(filter->handler_header != NULL, "handler_header should be set");
    TEST_ASSERT(filter->handler_body != NULL, "handler_body should be set");
    TEST_ASSERT_NULL(filter->next, "next filter should be NULL");
    TEST_REQUIRE_NOT_NULL(filter->module, "module should be created");

    http_module_gzip_t* module = filter->module;
    TEST_ASSERT_EQUAL_UINT(0, module->base.cont, "cont should be 0");
    TEST_ASSERT_EQUAL_UINT(0, module->base.done, "done should be 0");
    TEST_ASSERT_NULL(module->base.parent_buf, "parent_buf should be NULL");
    TEST_ASSERT(module->base.free != NULL, "free callback should be set");
    TEST_ASSERT(module->base.reset != NULL, "reset callback should be set");

    TEST_REQUIRE_NOT_NULL(module->buf, "output buffer should be created");
    TEST_ASSERT_NULL(module->buf->data, "output buffer should not be allocated yet");
    TEST_ASSERT_EQUAL_SIZE(0, module->buf->capacity, "output buffer capacity should be 0 until __header allocates");

    module->base.free(module);
    free(filter);
}

// ============================================================================
// __header
// ============================================================================

TEST(test_gzip_header_ce_none_passthrough) {
    TEST_SUITE("http_gzip_filter: header");
    TEST_CASE("CE_NONE responses pass through untouched");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->content_encoding = CE_NONE;
    body_set_size(fx.response, 4096);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(1, fx.sink.header_calls, "next filter should be called once");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Encoding"),
                     "no Content-Encoding header should be added");
    TEST_ASSERT_EQUAL(TE_NONE, fx.response->transfer_encoding, "transfer_encoding should stay TE_NONE");
    TEST_ASSERT_NULL(fx.module->buf->data, "output buffer should not be allocated");

    fixture_teardown(&fx);
}

TEST(test_gzip_header_small_passthrough) {
    TEST_SUITE("http_gzip_filter: header");
    TEST_CASE("bodies smaller than 1024 bytes pass through (not worth compressing)");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    body_set_size(fx.response, 1023);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Encoding"),
                     "no Content-Encoding for small bodies");
    TEST_ASSERT_EQUAL(TE_NONE, fx.response->transfer_encoding, "transfer_encoding should stay TE_NONE");
    TEST_ASSERT_NULL(fx.module->buf->data, "output buffer should not be allocated");

    fixture_teardown(&fx);
}

TEST(test_gzip_header_last_modified_passthrough) {
    TEST_SUITE("http_gzip_filter: header");
    TEST_CASE("last_modified responses pass through untouched");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->last_modified = 1;
    body_set_size(fx.response, 4096);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Encoding"),
                     "no Content-Encoding for last_modified responses");
    TEST_ASSERT_EQUAL(TE_NONE, fx.response->transfer_encoding, "transfer_encoding should stay TE_NONE");

    fixture_teardown(&fx);
}

TEST(test_gzip_header_file_uses_file_size) {
    TEST_SUITE("http_gzip_filter: header");
    TEST_CASE("file responses gate compression on file_.size, not body.size");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->file_.fd = 5;        /* any > -1 selects the file path */
    fx.response->file_.size = 4096;   /* large enough to compress */
    body_set_size(fx.response, 0);    /* body.size is ignored on the file path */

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");

    http_header_t* h = fx.response->get_header(fx.response, "Content-Encoding");
    TEST_REQUIRE_NOT_NULL(h, "Content-Encoding should be added for a large file");
    TEST_ASSERT_STR_EQUAL("gzip", h->value, "Content-Encoding should be gzip");
    TEST_ASSERT_EQUAL(TE_CHUNKED, fx.response->transfer_encoding, "file response should switch to chunked");

    fixture_teardown(&fx);
}

TEST(test_gzip_header_adds_content_encoding_and_chunked) {
    TEST_SUITE("http_gzip_filter: header");
    TEST_CASE("a large gzip response gets Content-Encoding, TE_CHUNKED and an allocated buffer");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    body_set_size(fx.response, 4096);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(1, fx.sink.header_calls, "next filter should be called once");

    http_header_t* h = fx.response->get_header(fx.response, "Content-Encoding");
    TEST_REQUIRE_NOT_NULL_GOTO(h, "Content-Encoding header should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("gzip", h->value, "Content-Encoding should be gzip");

    TEST_ASSERT_EQUAL(TE_CHUNKED, fx.response->transfer_encoding, "transfer_encoding should become TE_CHUNKED");
    TEST_ASSERT_NOT_NULL(fx.module->buf->data, "output buffer should be allocated");
    TEST_ASSERT_EQUAL_SIZE(GZIP_BUF_SIZE, fx.module->buf->capacity, "output buffer should be 16K");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_gzip_header_keeps_existing_content_encoding) {
    TEST_SUITE("http_gzip_filter: header");
    TEST_CASE("an existing Content-Encoding header is not duplicated");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    TEST_REQUIRE_GOTO(fx.response->add_header(fx.response, "Content-Encoding", "gzip"),
                      "precondition header should be added", cleanup);
    body_set_size(fx.response, 4096);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(1, header_count(fx.response, "Content-Encoding"),
                      "Content-Encoding should stay unique");

    fixture_teardown(&fx);
    return;

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_gzip_header_removes_stale_content_length) {
    TEST_SUITE("http_gzip_filter: header");
    TEST_CASE("REGRESSION: switching to chunked removes the stale Content-Length");

    /* The upstream data filter runs before gzip and adds Content-Length while
     * transfer_encoding is still TE_NONE. gzip then switches to TE_CHUNKED;
     * RFC 7230 §3.3.1 forbids Content-Length together with Transfer-Encoding,
     * and the uncompressed length is wrong for the compressed body anyway. */
    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    TEST_REQUIRE_GOTO(fx.response->add_content_length(fx.response, 4096),
                      "precondition Content-Length should be added", cleanup);
    body_set_size(fx.response, 4096);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(TE_CHUNKED, fx.response->transfer_encoding, "transfer_encoding should become TE_CHUNKED");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Length"),
                     "Content-Length must be removed when switching to chunked+gzip");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_gzip_header_event_again_resume) {
    TEST_SUITE("http_gzip_filter: header");
    TEST_CASE("CWF_EVENT_AGAIN sets cont and the retry does not re-add Content-Encoding");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    body_set_size(fx.response, 4096);
    fx.sink.header_again_once = 1;

    int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "first pass should propagate CWF_EVENT_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.cont, "cont should be set for resume");

    r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "second pass should finish with CWF_OK");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT_EQUAL(2, fx.sink.header_calls, "next filter should be called twice");
    TEST_ASSERT_EQUAL(1, header_count(fx.response, "Content-Encoding"),
                      "Content-Encoding should be added exactly once");

    fixture_teardown(&fx);
}

// ============================================================================
// __body: round-trips
// ============================================================================

TEST(test_gzip_body_single_chunk_roundtrip) {
    TEST_SUITE("http_gzip_filter: body");
    TEST_CASE("a compressible body in one parent buffer round-trips through gzip");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 16), "fixture should be created");

    enum { data_size = 2048 };
    char data[data_size];
    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('a' + i % 16);  /* repeating -> compresses well */

    body_set_size(fx.response, data_size);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    const int r = feed_chunks(&fx, data, data_size, data_size);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should drain and ask for more");
    TEST_ASSERT(fx.sink.size > 0, "compressed output should be produced");
    TEST_ASSERT(fx.sink.size < data_size, "repeating input should compress smaller");
    TEST_ASSERT(((unsigned char)fx.sink.data[0] == 0x1f && (unsigned char)fx.sink.data[1] == 0x8b),
                "output should start with the gzip magic 1f 8b");
    TEST_ASSERT(sink_inflates_to(&fx, data, data_size), "decompressed output should match the input");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "the final output buffer should be marked is_last");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_gzip_body_multi_chunk_roundtrip) {
    TEST_SUITE("http_gzip_filter: body");
    TEST_CASE("a body split across many parent buffers round-trips as one gzip stream");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 17), "fixture should be created");

    enum { data_size = 60000 };
    char* data = malloc(data_size);
    TEST_REQUIRE_GOTO(data != NULL, "data buffer should be allocated", cleanup);

    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('a' + i % 26);

    body_set_size(fx.response, data_size);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup_buf);

    const int r = feed_chunks(&fx, data, data_size, 7000);  /* ~9 chunks */
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should drain and ask for more");
    TEST_ASSERT(fx.sink.body_calls >= 9, "a 60000-byte body in 7000-byte chunks spans several calls");
    TEST_ASSERT(sink_inflates_to(&fx, data, data_size), "reassembled stream should match the input");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "exactly one final buffer should be marked is_last");

    cleanup_buf:
    free(data);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_gzip_body_incompressible_roundtrip) {
    TEST_SUITE("http_gzip_filter: body");
    TEST_CASE("incompressible input that overruns the 16K output buffer still round-trips");

    /* Random data does not compress; a full 16K parent must spill past the
     * 16K output buffer (deflate returns to want_continue), exercising the
     * multi-__process flush path. Seed a PRNG so the case is deterministic. */
    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 17), "fixture should be created");

    enum { data_size = 40000 };
    char* data = malloc(data_size);
    TEST_REQUIRE_GOTO(data != NULL, "data buffer should be allocated", cleanup);

    unsigned int seed = 0x1234abcd;
    for (size_t i = 0; i < data_size; i++) {
        seed = seed * 1103515245u + 12345u;
        data[i] = (char)(seed >> 16);
    }

    body_set_size(fx.response, data_size);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup_buf);

    const int r = feed_chunks(&fx, data, data_size, GZIP_BUF_SIZE);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should drain and ask for more");
    TEST_ASSERT(fx.sink.size > data_size, "incompressible input should grow past its size (gzip framing)");
    TEST_ASSERT(sink_inflates_to(&fx, data, data_size), "random input should still round-trip exactly");

    cleanup_buf:
    free(data);
    cleanup:
    fixture_teardown(&fx);
}

TEST(test_gzip_body_partial_write_resume) {
    TEST_SUITE("http_gzip_filter: body");
    TEST_CASE("a partial downstream write resumes and still produces a valid stream");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 16), "fixture should be created");

    enum { data_size = 8192 };
    char data[data_size];
    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('a' + i % 10);

    body_set_size(fx.response, data_size);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "header pass should succeed", cleanup);

    fx.sink.max_take_once = 100;  /* force many CWF_EVENT_AGAIN resumes */

    const int r = feed_chunks(&fx, data, data_size, 4000);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should drain and ask for more");
    TEST_ASSERT(fx.sink.body_calls > 1, "partial writes should require several sink calls");
    TEST_ASSERT_EQUAL_UINT(0, fx.sink.got_null_body, "no NULL buffer should reach the sink");
    TEST_ASSERT(sink_inflates_to(&fx, data, data_size),
                "resumed stream should be complete and in order, no garbage");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// __body: pass-throughs (must mirror __header)
// ============================================================================

TEST(test_gzip_body_ce_none_forwards_parent) {
    TEST_SUITE("http_gzip_filter: body passthrough");
    TEST_CASE("CE_NONE forwards the parent buffer verbatim");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->content_encoding = CE_NONE;
    body_set_size(fx.response, 4096);

    char payload[] = "passthrough-bytes";
    bufo_t parent;
    parent_init(&parent, payload, sizeof(payload) - 1, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "passthrough should forward the sink result");
    TEST_ASSERT_EQUAL(1, fx.sink.body_calls, "downstream body should be called once");
    TEST_ASSERT_EQUAL_SIZE(sizeof(payload) - 1, fx.sink.size, "parent payload should be forwarded verbatim");
    TEST_ASSERT(memcmp(fx.sink.data, payload, sizeof(payload) - 1) == 0, "bytes should match");

    fixture_teardown(&fx);
}

TEST(test_gzip_body_small_forwards_parent) {
    TEST_SUITE("http_gzip_filter: body passthrough");
    TEST_CASE("a body smaller than 1024 bytes is forwarded verbatim");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    body_set_size(fx.response, 512);

    char payload[] = "small-payload";
    bufo_t parent;
    parent_init(&parent, payload, sizeof(payload) - 1, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "small body should forward the sink result");
    TEST_ASSERT_EQUAL_SIZE(sizeof(payload) - 1, fx.sink.size, "parent payload should be forwarded verbatim");

    fixture_teardown(&fx);
}

TEST(test_gzip_body_last_modified_forwards_parent) {
    TEST_SUITE("http_gzip_filter: body passthrough");
    TEST_CASE("last_modified forwards the parent buffer verbatim");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    fx.response->last_modified = 1;
    body_set_size(fx.response, 4096);

    char payload[] = "static-bytes";
    bufo_t parent;
    parent_init(&parent, payload, sizeof(payload) - 1, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "last_modified should forward the sink result");
    TEST_ASSERT_EQUAL_SIZE(sizeof(payload) - 1, fx.sink.size, "parent payload should be forwarded verbatim");

    fixture_teardown(&fx);
}

// ============================================================================
// Reset and reuse
// ============================================================================

TEST(test_gzip_reset_state_cleared) {
    TEST_SUITE("http_gzip_filter: reset");
    TEST_CASE("reset clears module state and finishes the deflate stream");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 64), "fixture should be created");

    /* Dirty the module so the reset is observable. */
    fx.module->base.cont = 1;
    fx.module->base.done = 1;
    fx.module->base.parent_buf = (bufo_t*)0x1234;
    fx.module->buf->is_last = 1;

    fx.module->base.reset(fx.module);

    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont should be cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.done, "done should be cleared");
    TEST_ASSERT_NULL(fx.module->base.parent_buf, "parent_buf should be cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->buf->is_last, "is_last should be cleared");

    fixture_teardown(&fx);
}

TEST(test_gzip_reset_allows_reuse) {
    TEST_SUITE("http_gzip_filter: reset");
    TEST_CASE("after reset a second response still compresses and round-trips");

    gzip_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx, 1 << 16), "fixture should be created");

    enum { data_size = 2048 };
    char data[data_size];
    for (size_t i = 0; i < data_size; i++)
        data[i] = (char)('a' + i % 16);

    body_set_size(fx.response, data_size);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "first header should succeed", cleanup);
    TEST_REQUIRE_GOTO(feed_chunks(&fx, data, data_size, data_size) == CWF_DATA_AGAIN,
                      "first body should drain", cleanup);
    TEST_ASSERT(sink_inflates_to(&fx, data, data_size), "first response should round-trip");

    /* Re-init the filter chain as filters_reset would, then serve a second
     * response on the same filter instance. */
    fx.module->base.reset(fx.module);
    fx.sink.size = 0;
    fx.sink.body_calls = 0;
    fx.sink.saw_last = 0;
    fx.response->transfer_encoding = TE_NONE;
    fx.response->content_encoding = CE_GZIP;

    body_set_size(fx.response, data_size);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "second header should succeed", cleanup);
    const int r = feed_chunks(&fx, data, data_size, data_size);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "second body should drain after reset");
    TEST_ASSERT_EQUAL_UINT(1, fx.sink.saw_last, "second response should mark a final buffer");
    TEST_ASSERT(sink_inflates_to(&fx, data, data_size), "second response should round-trip");

    cleanup:
    fixture_teardown(&fx);
}

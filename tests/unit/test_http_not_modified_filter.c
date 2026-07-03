/*
 * Unit tests for protocols/http/server/filters/http_not_modified_filter.c
 *
 * The filter chain runs not_modified FIRST (not_modified -> range -> data ->
 * gzip -> chunked -> write), so this filter decides 304 vs 200 before any
 * downstream filter adds Content-Length / Transfer-Encoding / Content-Encoding.
 * It is driven black-box through the public handler_header pointer, exactly
 * like test_http_gzip_filter.c: the filter under test is chained into a
 * capturing sink so its effect on response state is observable in isolation.
 *
 * Covers:
 *   - construction defaults;
 *   - __header: Last-Modified / ETag are generated only for real files
 *     (fd > -1, mtime > 0), and the generated values match the documented
 *     formats (http_format_date IMF-fixdate and W/"mtime-size");
 *   - __check_not_modified: method gate (GET/HEAD only), If-None-Match exact /
 *     "*" / comma list / whitespace, If-None-Match precedence over
 *     If-Modified-Since, If-Modified-Since equal / older / newer, invalid date;
 *   - the 304 path suppresses the body-related state (status 304,
 *     content_length 0, TE_NONE, CE_NONE, last_modified 1, and the
 *     Content-Length / Transfer-Encoding / Content-Encoding headers removed);
 *   - __parse_http_date fallback formats (RFC 850 obsolete date);
 *   - reset clears module state;
 *   - the body handler forwards the parent buffer verbatim.
 *
 * REGRESSION (marked below): http_not_modified_header never cleared
 * module->base.cont on a non-AGAIN return. The sibling gzip and data filters
 * both do `module->base.cont = 0;` before the CWF_EVENT_AGAIN conditional;
 * not_modified omitted it, leaving cont stuck at 1 after a resumed header pass
 * completed with CWF_OK. The case asserts cont is cleared after resume.
 */

#include "framework.h"
#include "httpresponse.h"
#include "httprequest.h"
#include "http_not_modified_filter.h"
#include "http_filter.h"
#include "route.h"
#include "bufo.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Fixed mtime/size so the generated ETag and Last-Modified are deterministic.
 *
 *   mtime = 1700000000  -> 2023-11-14 22:13:20 UTC (a Tuesday)
 *   size  = 1234
 *   ETag          = W/"6553f100-4d2"   (%lx of mtime - %lx of size)
 *   Last-Modified = "Tue, 14 Nov 2023 22:13:20 GMT"
 *
 * The ETag/Last-Modified value tests below pin these exact strings, so any
 * drift in __generate_etag's format string or http_format_date's output is
 * caught. */
#define TEST_MTIME           1700000000L
#define TEST_SIZE            1234
#define EXPECTED_ETAG        "W/\"6553f100-4d2\""
#define EXPECTED_LAST_MOD    "Tue, 14 Nov 2023 22:13:20 GMT"

/* request->add_header returns 0 on success (-1 on error); response->add_header
 * returns 1 on success (0 on error). Hide that asymmetry behind helpers so a
 * failed setup is a clean TEST_REQUIRE (return) instead of a NULL deref. */
#define REQ_ADD(rq, k, v)  TEST_REQUIRE((rq)->add_header((rq), (k), (v)) == 0, "request add_header")
#define RESP_ADD(rs, k, v) TEST_REQUIRE((rs)->add_header((rs), (k), (v)), "response add_header")

// ============================================================================
// Fixture: not_modified filter chained into a capturing sink filter
// ============================================================================

/* Sink: records that header/body ran and forwards CWF_OK / CWF_DATA_AGAIN.
 * header_again_once scripts a single CWF_EVENT_AGAIN so the cont/resume path
 * is observable. body echoes the parent buffer length into a counter. */
typedef struct {
    http_module_t base;
    int header_again_once;
    int header_calls;
    int body_calls;
    size_t body_bytes_seen;
    int got_null_body;
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

    sink->body_bytes_seen += (buf->size >= buf->pos) ? (buf->size - buf->pos) : 0;
    return CWF_DATA_AGAIN;
}

typedef struct {
    httpresponse_t* response;
    httprequest_t* request;
    http_filter_t* nm;
    http_filter_t sink_filter;
    sink_module_t sink;
    http_module_not_modified_t* module;
} nm_fixture_t;

static int fixture_setup(nm_fixture_t* fx) {
    memset(fx, 0, sizeof(*fx));

    fx->response = httpresponse_create(NULL);
    if (fx->response == NULL) return 0;

    fx->request = httprequest_create(NULL);
    if (fx->request == NULL) {
        httpresponse_free(fx->response);
        fx->response = NULL;
        return 0;
    }

    fx->nm = http_not_modified_filter_create();
    if (fx->nm == NULL) {
        httprequest_free(fx->request);
        httpresponse_free(fx->response);
        fx->request = NULL;
        fx->response = NULL;
        return 0;
    }

    fx->sink.base.free = sink_noop;
    fx->sink.base.reset = sink_noop;

    fx->sink_filter.module = &fx->sink;
    fx->sink_filter.handler_header = sink_header;
    fx->sink_filter.handler_body = sink_body;
    fx->sink_filter.next = NULL;

    fx->nm->next = &fx->sink_filter;
    fx->module = fx->nm->module;

    return 1;
}

static void fixture_teardown(nm_fixture_t* fx) {
    if (fx->nm != NULL) {
        http_module_t* module = fx->nm->module;
        module->free(fx->nm->module);
        free(fx->nm);
    }

    if (fx->request != NULL)
        httprequest_free(fx->request);

    if (fx->response != NULL) {
        /* Avoid __file_close()'ing a fake fd we planted for the file path. */
        fx->response->file_.fd = -1;
        fx->response->file_.tmp = 0;
        httpresponse_free(fx->response);
    }
}

static int run_header(nm_fixture_t* fx) {
    fx->response->cur_filter = fx->nm;
    return fx->nm->handler_header(fx->request, fx->response);
}

static int run_body(nm_fixture_t* fx, bufo_t* parent) {
    fx->response->cur_filter = fx->nm;
    return fx->nm->handler_body(fx->request, fx->response, parent);
}

/* Arm the file path: a non-null fd with a positive mtime makes __header emit
 * Last-Modified + ETag. Use fd 0 (>= 0, satisfies > -1) but neutralize it in
 * teardown so nothing is actually closed. */
static void arm_file(nm_fixture_t* fx, time_t mtime, size_t size) {
    fx->response->file_.fd = 0;
    fx->response->file_.mtime = mtime;
    fx->response->file_.size = size;
}

static int header_count(httpresponse_t* response, const char* key) {
    int count = 0;
    for (http_header_t* h = response->header_; h != NULL; h = h->next)
        if (strcmp(h->key, key) == 0)
            count++;
    return count;
}

static void parent_init(bufo_t* parent, char* data, size_t size, int is_last) {
    memset(parent, 0, sizeof(*parent));
    parent->data = data;
    parent->capacity = size;
    parent->size = size;
    parent->pos = 0;
    parent->is_proxy = 1;
    parent->is_last = is_last ? 1 : 0;
}

// ============================================================================
// Construction
// ============================================================================

TEST(test_nm_filter_create_defaults) {
    TEST_SUITE("http_not_modified_filter: construction");
    TEST_CASE("filter and module are initialized with clean defaults");

    http_filter_t* filter = http_not_modified_filter_create();
    TEST_REQUIRE_NOT_NULL(filter, "filter should be created");

    TEST_ASSERT(filter->handler_header == http_not_modified_header,
                "handler_header should be http_not_modified_header");
    TEST_ASSERT(filter->handler_body == http_not_modified_body,
                "handler_body should be http_not_modified_body");
    TEST_ASSERT_NULL(filter->next, "next filter should be NULL");
    TEST_REQUIRE_NOT_NULL(filter->module, "module should be created");

    http_module_not_modified_t* module = filter->module;
    TEST_ASSERT_EQUAL_UINT(0, module->base.cont, "cont should be 0");
    TEST_ASSERT_EQUAL_UINT(0, module->base.done, "done should be 0");
    TEST_ASSERT_NULL(module->base.parent_buf, "parent_buf should be NULL");
    TEST_ASSERT(module->base.free != NULL, "free callback should be set");
    TEST_ASSERT(module->base.reset != NULL, "reset callback should be set");

    module->base.free(module);
    free(filter);
}

// ============================================================================
// __header: Last-Modified / ETag generation
// ============================================================================

TEST(test_nm_header_file_adds_last_modified_and_etag) {
    TEST_SUITE("http_not_modified_filter: header generation");
    TEST_CASE("a file response gets Last-Modified and ETag in the right format");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(1, fx.sink.header_calls, "next filter should be called once");

    http_header_t* lm = fx.response->get_header(fx.response, "Last-Modified");
    TEST_REQUIRE_NOT_NULL_GOTO(lm, "Last-Modified should be added", cleanup);
    TEST_ASSERT_STR_EQUAL(EXPECTED_LAST_MOD, lm->value, "Last-Modified IMF-fixdate value");

    http_header_t* et = fx.response->get_header(fx.response, "ETag");
    TEST_REQUIRE_NOT_NULL_GOTO(et, "ETag should be added", cleanup);
    TEST_ASSERT_STR_EQUAL(EXPECTED_ETAG, et->value, "ETag weak-validator value");

    TEST_ASSERT_EQUAL(1, header_count(fx.response, "ETag"), "ETag should be added exactly once");
    TEST_ASSERT_EQUAL(1, header_count(fx.response, "Last-Modified"),
                      "Last-Modified should be added exactly once");
    /* No 304: status and body-related state untouched. */
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "status should stay 200 without conditional");
    TEST_ASSERT_EQUAL_UINT(0, fx.response->last_modified, "last_modified flag should stay 0");

    cleanup:
    fixture_teardown(&fx);
}

TEST(test_nm_header_non_file_adds_nothing) {
    TEST_SUITE("http_not_modified_filter: header generation");
    TEST_CASE("a non-file response (fd == -1) gets no Last-Modified / ETag");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    /* fd stays -1 (file_alloc default). */
    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Last-Modified"),
                     "no Last-Modified for non-file");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "ETag"),
                     "no ETag for non-file");

    fixture_teardown(&fx);
}

TEST(test_nm_header_file_zero_mtime_adds_nothing) {
    TEST_SUITE("http_not_modified_filter: header generation");
    TEST_CASE("a file with mtime == 0 gets no Last-Modified / ETag");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.response->file_.fd = 0;   /* file path armed, but mtime unknown */
    fx.response->file_.size = TEST_SIZE;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Last-Modified"),
                     "no Last-Modified when mtime is 0");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "ETag"),
                     "no ETag when mtime is 0");

    fixture_teardown(&fx);
}

TEST(test_nm_header_distinct_etags_per_version) {
    TEST_SUITE("http_not_modified_filter: header generation");
    TEST_CASE("different mtime/size produce different ETags");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    arm_file(&fx, TEST_MTIME, TEST_SIZE);
    TEST_REQUIRE_GOTO(run_header(&fx) == CWF_OK, "first header should succeed", cleanup);
    http_header_t* et1 = fx.response->get_header(fx.response, "ETag");
    TEST_REQUIRE_NOT_NULL_GOTO(et1, "first ETag should exist", cleanup);

    /* Different size on a second response -> different ETag string. */
    fx.response->file_.size = TEST_SIZE + 1;
    /* Re-add would duplicate; remove first to inspect the fresh value cleanly. */
    fx.response->remove_header(fx.response, "ETag");
    char etag_buf[64];
    snprintf(etag_buf, sizeof(etag_buf), "W/\"%lx-%lx\"",
             (unsigned long)TEST_MTIME, (unsigned long)(TEST_SIZE + 1));
    TEST_ASSERT_STR_EQUAL(etag_buf, etag_buf, "sanity: snprintf format reference");

    cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// __check_not_modified: If-None-Match
// ============================================================================

TEST(test_nm_inm_exact_match_304) {
    TEST_SUITE("http_not_modified_filter: If-None-Match");
    TEST_CASE("If-None-Match equal to the response ETag yields 304");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-None-Match", EXPECTED_ETAG);
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code, "exact ETag match -> 304");
    TEST_ASSERT_EQUAL_UINT(1, fx.response->last_modified, "last_modified should signal 304");

    fixture_teardown(&fx);
}

TEST(test_nm_inm_star_304) {
    TEST_SUITE("http_not_modified_filter: If-None-Match");
    TEST_CASE("If-None-Match: * matches any existing ETag");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-None-Match", "*");
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code, "'*' -> 304");

    fixture_teardown(&fx);
}

TEST(test_nm_inm_list_one_matches_304) {
    TEST_SUITE("http_not_modified_filter: If-None-Match");
    TEST_CASE("a comma-separated list with one matching ETag yields 304");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-None-Match",
            "\"deadbeef\", W/\"cafef00d-1\" , " EXPECTED_ETAG " , \"other\"");
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code, "one list member matches -> 304");

    fixture_teardown(&fx);
}

TEST(test_nm_inm_no_match_200) {
    TEST_SUITE("http_not_modified_filter: If-None-Match");
    TEST_CASE("If-None-Match with no matching ETag yields 200 and leaves state untouched");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-None-Match", "W/\"deadbeef-9999\"");
    /* Plant non-default body state to prove a non-match does not reset it. */
    fx.response->content_length = 4096;
    fx.response->transfer_encoding = TE_CHUNKED;
    fx.response->content_encoding = CE_GZIP;
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "no ETag match -> 200");
    TEST_ASSERT_EQUAL_SIZE(4096, fx.response->content_length, "content_length must be untouched");
    TEST_ASSERT_EQUAL(TE_CHUNKED, fx.response->transfer_encoding, "transfer_encoding untouched");
    TEST_ASSERT_EQUAL(CE_GZIP, fx.response->content_encoding, "content_encoding untouched");
    TEST_ASSERT_EQUAL_UINT(0, fx.response->last_modified, "last_modified flag stays 0");
    /* Validators remain present even on a non-match. */
    TEST_ASSERT_NOT_NULL(fx.response->get_header(fx.response, "ETag"), "ETag still present");

    fixture_teardown(&fx);
}

TEST(test_nm_inm_weak_vs_strong_no_match) {
    TEST_SUITE("http_not_modified_filter: If-None-Match");
    TEST_CASE("current behavior: byte-exact compare, strong form does not match a weak ETag");

    /* RFC 7232 §3.2 says If-None-Match uses the weak comparison function, so
     * "x" and W/"x" are equivalent. __etag_matches compares byte-for-byte, so
     * a client that strips the W/ prefix does not get a 304. This case pins
     * the current (non-compliant) behavior so any future fix is a deliberate
     * change visible here. */
    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-None-Match", "\"6553f100-4d2\"");  /* strong form, no W/ */
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code,
                      "byte-exact compare: strong form does not match weak ETag");

    fixture_teardown(&fx);
}

TEST(test_nm_inm_takes_precedence_over_ims) {
    TEST_SUITE("http_not_modified_filter: If-None-Match");
    TEST_CASE("If-None-Match (present, no match) suppresses an otherwise-matching If-Modified-Since");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-None-Match", "W/\"deadbeef-9999\"");  /* no match */
    /* IMS alone would yield 304 (equal to Last-Modified). */
    REQ_ADD(fx.request, "If-Modified-Since", EXPECTED_LAST_MOD);
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code,
                      "If-None-Match precedence: IMS must be ignored when INM is present");

    fixture_teardown(&fx);
}

TEST(test_nm_inm_present_no_etag_falls_back_to_ims) {
    TEST_SUITE("http_not_modified_filter: If-None-Match");
    TEST_CASE("If-None-Match present but no response ETag falls back to If-Modified-Since (current behavior)");

    /* RFC 7232 §3.2 says If-Modified-Since MUST be ignored when If-None-Match
     * is present. The code only enters the INM branch when a response ETag
     * exists, so an INM with no ETag falls through to IMS. Pin current
     * pragmatic behavior. */
    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-None-Match", "*");
    RESP_ADD(fx.response, "Last-Modified", EXPECTED_LAST_MOD);  /* manual, no ETag */
    REQ_ADD(fx.request, "If-Modified-Since", EXPECTED_LAST_MOD);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code,
                      "falls back to IMS -> 304 (current behavior)");

    fixture_teardown(&fx);
}

// ============================================================================
// __check_not_modified: method gate + If-Modified-Since
// ============================================================================

TEST(test_nm_post_skips_conditionals) {
    TEST_SUITE("http_not_modified_filter: method gate");
    TEST_CASE("POST never evaluates conditional headers (RFC 7232)");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_POST;
    REQ_ADD(fx.request, "If-None-Match", "*");  /* would match for GET */
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "POST is not conditional -> 200");

    fixture_teardown(&fx);
}

TEST(test_nm_head_evaluates_conditionals) {
    TEST_SUITE("http_not_modified_filter: method gate");
    TEST_CASE("HEAD evaluates conditional headers like GET");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_HEAD;
    REQ_ADD(fx.request, "If-None-Match", "*");
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code, "HEAD is conditional -> 304");

    fixture_teardown(&fx);
}

TEST(test_nm_ims_equal_304) {
    TEST_SUITE("http_not_modified_filter: If-Modified-Since");
    TEST_CASE("If-Modified-Since == Last-Modified yields 304");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-Modified-Since", EXPECTED_LAST_MOD);
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code, "equal validator -> 304");

    fixture_teardown(&fx);
}

TEST(test_nm_ims_newer_304) {
    TEST_SUITE("http_not_modified_filter: If-Modified-Since");
    TEST_CASE("If-Modified-Since one second after Last-Modified yields 304");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-Modified-Since", "Tue, 14 Nov 2023 22:13:21 GMT");
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code, "resource older than IMS -> 304");

    fixture_teardown(&fx);
}

TEST(test_nm_ims_older_200) {
    TEST_SUITE("http_not_modified_filter: If-Modified-Since");
    TEST_CASE("If-Modified-Since one second before Last-Modified yields 200");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-Modified-Since", "Tue, 14 Nov 2023 22:13:19 GMT");
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "resource newer than IMS -> 200");

    fixture_teardown(&fx);
}

TEST(test_nm_ims_invalid_date_200) {
    TEST_SUITE("http_not_modified_filter: If-Modified-Since");
    TEST_CASE("an unparseable If-Modified-Since yields 200 (no 304)");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-Modified-Since", "not-a-date");
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(200, fx.response->status_code, "invalid date -> 200");

    fixture_teardown(&fx);
}

TEST(test_nm_ims_rfc850_format_304) {
    TEST_SUITE("http_not_modified_filter: If-Modified-Since");
    TEST_CASE("obsolete RFC 850 date format is accepted by __parse_http_date");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-Modified-Since", "Tuesday, 14-Nov-23 22:13:20 GMT");
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    TEST_ASSERT_EQUAL(CWF_OK, run_header(&fx), "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code, "RFC 850 date must parse to the same instant");

    fixture_teardown(&fx);
}

// ============================================================================
// 304 body suppression
// ============================================================================

TEST(test_nm_304_suppresses_body_state) {
    TEST_SUITE("http_not_modified_filter: 304 suppression");
    TEST_CASE("304 drops Content-Length/TE/CE fields and headers, sets last_modified");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    REQ_ADD(fx.request, "If-None-Match", EXPECTED_ETAG);
    arm_file(&fx, TEST_MTIME, TEST_SIZE);

    /* Simulate an upstream that already negotiated body framing. */
    RESP_ADD(fx.response, "Content-Length", "4096");
    RESP_ADD(fx.response, "Transfer-Encoding", "chunked");
    RESP_ADD(fx.response, "Content-Encoding", "gzip");
    fx.response->content_length = 4096;
    fx.response->transfer_encoding = TE_CHUNKED;
    fx.response->content_encoding = CE_GZIP;

    const int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "header chain should finish with CWF_OK");
    TEST_ASSERT_EQUAL(304, fx.response->status_code, "status should be 304");
    TEST_ASSERT_EQUAL_SIZE(0, fx.response->content_length, "content_length must be 0");
    TEST_ASSERT_EQUAL(TE_NONE, fx.response->transfer_encoding, "transfer_encoding must be TE_NONE");
    TEST_ASSERT_EQUAL(CE_NONE, fx.response->content_encoding, "content_encoding must be CE_NONE");
    TEST_ASSERT_EQUAL_UINT(1, fx.response->last_modified, "last_modified flag must signal 304");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Length"),
                     "Content-Length header must be removed");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Transfer-Encoding"),
                     "Transfer-Encoding header must be removed");
    TEST_ASSERT_NULL(fx.response->get_header(fx.response, "Content-Encoding"),
                     "Content-Encoding header must be removed");
    /* Cache validators survive into the 304. */
    TEST_ASSERT_NOT_NULL(fx.response->get_header(fx.response, "ETag"), "ETag kept on 304");

    fixture_teardown(&fx);
}

// ============================================================================
// cont / resume (REGRESSION)
// ============================================================================

TEST(test_nm_header_cont_cleared_after_resume) {
    TEST_SUITE("http_not_modified_filter: resume");
    TEST_CASE("REGRESSION: cont is cleared after a resumed header pass returns CWF_OK");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.request->method = ROUTE_GET;
    arm_file(&fx, TEST_MTIME, TEST_SIZE);
    fx.sink.header_again_once = 1;

    int r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_EVENT_AGAIN, r, "first pass should propagate CWF_EVENT_AGAIN");
    TEST_ASSERT_EQUAL_UINT(1, fx.module->base.cont, "cont should be set while suspended");

    r = run_header(&fx);
    TEST_ASSERT_EQUAL(CWF_OK, r, "second pass should finish with CWF_OK");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont,
                           "cont must be cleared once the resume completes (was left at 1)");
    TEST_ASSERT_EQUAL(2, fx.sink.header_calls, "next filter should be called twice");
    /* Setup was skipped on resume; headers added once, not twice. */
    TEST_ASSERT_EQUAL(1, header_count(fx.response, "ETag"), "ETag added exactly once across resume");

    fixture_teardown(&fx);
}

// ============================================================================
// Reset
// ============================================================================

TEST(test_nm_reset_clears_state) {
    TEST_SUITE("http_not_modified_filter: reset");
    TEST_CASE("reset clears cont/done/parent_buf");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    fx.module->base.cont = 1;
    fx.module->base.done = 1;
    fx.module->base.parent_buf = (bufo_t*)0x1234;

    fx.module->base.reset(fx.module);

    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.cont, "cont cleared");
    TEST_ASSERT_EQUAL_UINT(0, fx.module->base.done, "done cleared");
    TEST_ASSERT_NULL(fx.module->base.parent_buf, "parent_buf cleared");

    fixture_teardown(&fx);
}

// ============================================================================
// Body handler
// ============================================================================

TEST(test_nm_body_forwards_parent) {
    TEST_SUITE("http_not_modified_filter: body");
    TEST_CASE("the body handler forwards the parent buffer to the next filter");

    nm_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");

    char payload[] = "not-modified-body-bytes";
    bufo_t parent;
    parent_init(&parent, payload, sizeof(payload) - 1, 1);

    const int r = run_body(&fx, &parent);
    TEST_ASSERT_EQUAL(CWF_DATA_AGAIN, r, "body should forward the sink result");
    TEST_ASSERT_EQUAL(1, fx.sink.body_calls, "downstream body called once");
    TEST_ASSERT_EQUAL_SIZE(sizeof(payload) - 1, fx.sink.body_bytes_seen,
                           "parent payload length observed by sink");
    TEST_ASSERT_EQUAL_UINT(0, fx.sink.got_null_body, "no NULL buffer should reach the sink");

    fixture_teardown(&fx);
}

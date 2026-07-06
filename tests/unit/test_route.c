#include "framework.h"
#include "route.h"
#include <string.h>

// ============================================================================
// Route $-anchor tests — ensures routes with params match exactly,
// not by prefix (e.g. /users/{id} must NOT match /users/42/extra)
//
// In cwfr, named params require a regex alternative: {name|pattern}
// ============================================================================

TEST(test_route_param_exact_match) {
    TEST_CASE("/users/{id|[0-9]+} matches exact path but not prefix");

    route_t* r = route_create("/users/{id|[0-9]+}");
    TEST_ASSERT_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(0, r->is_primitive, "Route with params should not be primitive");
    TEST_ASSERT_EQUAL(1, r->params_count, "Should have 1 parameter");

    int ovector[30];

    // Exact match
    int rc = pcre_exec(r->location, NULL, "/users/42", 9, 0, 0, ovector, 30);
    TEST_ASSERT(rc >= 0, "/users/42 should match /users/{id|[0-9]+}");

    // Prefix match should fail ($-anchor prevents this)
    rc = pcre_exec(r->location, NULL, "/users/42/extra", 15, 0, 0, ovector, 30);
    TEST_ASSERT(rc < 0, "/users/42/extra should NOT match /users/{id|[0-9]+}");

    routes_free(r);
}

TEST(test_route_param_multiple_segments) {
    TEST_CASE("/users/{id|[0-9]+}/posts/{pid|[0-9]+} matches exact but not prefix");

    route_t* r = route_create("/users/{id|[0-9]+}/posts/{pid|[0-9]+}");
    TEST_ASSERT_NOT_NULL(r, "route_create should succeed");
    TEST_ASSERT_EQUAL(2, r->params_count, "Should have 2 parameters");

    int ovector[30];

    int rc = pcre_exec(r->location, NULL, "/users/1/posts/99", 16, 0, 0, ovector, 30);
    TEST_ASSERT(rc >= 0, "/users/1/posts/99 should match");

    rc = pcre_exec(r->location, NULL, "/users/1/posts/99/comments", 25, 0, 0, ovector, 30);
    TEST_ASSERT(rc < 0, "/users/1/posts/99/comments should NOT match");

    routes_free(r);
}

TEST(test_route_primitive_exact_match) {
    TEST_CASE("Primitive route /health matches by exact length");

    route_t* r = route_create("/health");
    TEST_ASSERT_NOT_NULL(r, "route_create should succeed");
    TEST_ASSERT_EQUAL(1, r->is_primitive, "Static path should be primitive");
    TEST_ASSERT_EQUAL(0, r->params_count, "Should have no parameters");

    int rc = route_compare_primitive(r, "/health", 7);
    TEST_ASSERT_EQUAL(1, rc, "Exact path should match");

    rc = route_compare_primitive(r, "/health/extra", 13);
    TEST_ASSERT_EQUAL(0, rc, "Path with extra segments should not match");

    routes_free(r);
}

TEST(test_route_root_param) {
    TEST_CASE("/{action|[a-z]+} matches /hello but not /hello/world");

    route_t* r = route_create("/{action|[a-z]+}");
    TEST_ASSERT_NOT_NULL(r, "route_create should succeed");
    TEST_ASSERT_EQUAL(1, r->params_count, "Should have 1 parameter");

    int ovector[30];

    int rc = pcre_exec(r->location, NULL, "/hello", 6, 0, 0, ovector, 30);
    TEST_ASSERT(rc >= 0, "/hello should match /{action|[a-z]+}");

    rc = pcre_exec(r->location, NULL, "/hello/world", 12, 0, 0, ovector, 30);
    TEST_ASSERT(rc < 0, "/hello/world should NOT match /{action|[a-z]+}");

    routes_free(r);
}

TEST(test_route_param_with_slash_in_pattern) {
    TEST_CASE("/files/{path|.+} matches path with segments but $ prevents longer prefix");

    route_t* r = route_create("/files/{path|.+}");
    TEST_ASSERT_NOT_NULL(r, "route_create should succeed");

    int ovector[30];

    // Exact match with file path
    int rc = pcre_exec(r->location, NULL, "/files/docs/readme.txt", 22, 0, 0, ovector, 30);
    TEST_ASSERT(rc >= 0, "/files/docs/readme.txt should match /files/{path|.+}");

    routes_free(r);
}

// ============================================================================
// route_create input validation and parse errors
// ============================================================================

TEST(test_route_create_invalid_input) {
    TEST_CASE("route_create rejects NULL and empty path");

    TEST_ASSERT_NULL(route_create(NULL), "NULL path should be rejected");
    TEST_ASSERT_NULL(route_create(""), "Empty path should be rejected");
}

TEST(test_route_create_parse_errors) {
    TEST_CASE("route_create rejects malformed token syntax");

    TEST_ASSERT_NULL(route_create("/x/}"), "Unopened token should be rejected");
    TEST_ASSERT_NULL(route_create("/x/{"), "Unclosed token should be rejected");
    TEST_ASSERT_NULL(route_create("/x/{id|[0-9]+"), "Unclosed token with expression should be rejected");
    TEST_ASSERT_NULL(route_create("/x/{}"), "Empty token should be rejected");
    TEST_ASSERT_NULL(route_create("/x/{|[0-9]+}"), "Empty param name should be rejected");
    TEST_ASSERT_NULL(route_create("/x/{id|}"), "Empty param expression should be rejected");
    TEST_ASSERT_NULL(route_create("/x/{id name|[0-9]+}"), "Multi-word param name should be rejected");
    TEST_ASSERT_NULL(route_create("/{id|[0-9]+}/files/*"), "Regex symbols mixed with params should be rejected");
}

TEST(test_route_param_name_stored) {
    TEST_CASE("Param names are extracted in declaration order");

    route_t* r = route_create("/users/{id|[0-9]+}/posts/{pid|[a-z]+}");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");
    TEST_ASSERT_EQUAL(2, r->params_count, "Should have 2 parameters");

    TEST_REQUIRE_NOT_NULL_GOTO(r->param, "First param should exist", cleanup);
    TEST_ASSERT_STR_EQUAL("id", r->param->string, "First param name should be 'id'");
    TEST_ASSERT_EQUAL_SIZE(2, r->param->string_len, "First param name length");

    TEST_REQUIRE_NOT_NULL_GOTO(r->param->next, "Second param should exist", cleanup);
    TEST_ASSERT_STR_EQUAL("pid", r->param->next->string, "Second param name should be 'pid'");
    TEST_ASSERT_NULL(r->param->next->next, "No third param expected");

    cleanup:
    routes_free(r);
}

TEST(test_route_param_alternation_in_expression) {
    TEST_CASE("{action|create|delete} keeps full alternation and correct param name");

    route_t* r = route_create("/{action|create|delete}");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");
    TEST_ASSERT_EQUAL(1, r->params_count, "Should have 1 parameter");

    TEST_REQUIRE_NOT_NULL_GOTO(r->param, "Param should exist", cleanup);
    TEST_ASSERT_STR_EQUAL("action", r->param->string, "Param name should be 'action', not garbage");

    int ovector[30];

    int rc = pcre_exec(r->location, NULL, "/create", 7, 0, 0, ovector, 30);
    TEST_ASSERT(rc >= 0, "/create should match first alternative");

    rc = pcre_exec(r->location, NULL, "/delete", 7, 0, 0, ovector, 30);
    TEST_ASSERT(rc >= 0, "/delete should match second alternative");

    rc = pcre_exec(r->location, NULL, "/update", 7, 0, 0, ovector, 30);
    TEST_ASSERT(rc < 0, "/update should NOT match");

    rc = pcre_exec(r->location, NULL, "/create/x", 9, 0, 0, ovector, 30);
    TEST_ASSERT(rc < 0, "/create/x should NOT match");

    cleanup:
    routes_free(r);
}

TEST(test_route_nested_braces_quantifier) {
    TEST_CASE("Regex quantifier braces inside expression are preserved");

    route_t* r = route_create("/n/{code|[0-9]{2}}");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    int ovector[30];

    int rc = pcre_exec(r->location, NULL, "/n/42", 5, 0, 0, ovector, 30);
    TEST_ASSERT(rc >= 0, "/n/42 should match [0-9]{2}");

    rc = pcre_exec(r->location, NULL, "/n/4", 4, 0, 0, ovector, 30);
    TEST_ASSERT(rc < 0, "/n/4 should NOT match [0-9]{2}");

    rc = pcre_exec(r->location, NULL, "/n/423", 6, 0, 0, ovector, 30);
    TEST_ASSERT(rc < 0, "/n/423 should NOT match [0-9]{2}");

    routes_free(r);
}

TEST(test_route_escaped_braces) {
    TEST_CASE("Escaped braces do not start token parsing");

    route_t* r = route_create("/lit/\\{x\\}");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed for escaped braces");
    TEST_ASSERT_EQUAL(0, r->params_count, "Escaped braces should not create params");
    TEST_ASSERT_NULL(r->param, "No param list expected");

    routes_free(r);
}

// ============================================================================
// route_set_* handler registration
// ============================================================================

static void route_test_handler_a(void* arg) { (void)arg; }
static void route_test_handler_b(void* arg) { (void)arg; }

TEST(test_route_set_http_handler_methods) {
    TEST_CASE("route_set_http_handler validates method and keeps first handler");

    route_t* r = route_create("/api");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(0, route_set_http_handler(r, "FETCH", route_test_handler_a, NULL), "Unknown method should be rejected");
    TEST_ASSERT_EQUAL(0, route_set_http_handler(r, "get", route_test_handler_a, NULL), "Lowercase method should be rejected");

    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "GET", route_test_handler_a, NULL), "GET should be accepted");
    TEST_ASSERT(r->handler[ROUTE_GET] == route_test_handler_a, "GET handler should be stored");

    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "GET", route_test_handler_b, NULL), "Duplicate GET should report success");
    TEST_ASSERT(r->handler[ROUTE_GET] == route_test_handler_a, "Duplicate GET should not overwrite handler");

    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "POST", route_test_handler_b, NULL), "POST should be accepted");
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "PUT", route_test_handler_b, NULL), "PUT should be accepted");
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "DELETE", route_test_handler_b, NULL), "DELETE should be accepted");
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "OPTIONS", route_test_handler_b, NULL), "OPTIONS should be accepted");
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "PATCH", route_test_handler_b, NULL), "PATCH should be accepted");
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "HEAD", route_test_handler_b, NULL), "HEAD should be accepted");

    routes_free(r);
}

TEST(test_route_set_http_handler_ratelimiter_ownership) {
    TEST_CASE("Ratelimiter ownership: no leaks, no NULL overwrite");

    ratelimiter_config_t cfg = {
        .max_tokens = 10,
        .refill_rate = 1,
        .time_window_ns = 1000000000ULL,
        .cleanup_interval_s = 60
    };

    route_t* r = route_create("/api");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    ratelimiter_t* rl1 = ratelimiter_init(&cfg);
    TEST_REQUIRE_NOT_NULL_GOTO(rl1, "ratelimiter_init should succeed", cleanup);
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "GET", route_test_handler_a, rl1), "GET with limiter should be accepted");
    TEST_ASSERT(r->ratelimiter == rl1, "Route should own the first ratelimiter");

    // Second method with its own limiter: the old one must be freed (LSan
    // verifies), the new one stored.
    ratelimiter_t* rl2 = ratelimiter_init(&cfg);
    TEST_REQUIRE_NOT_NULL_GOTO(rl2, "ratelimiter_init should succeed", cleanup);
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "POST", route_test_handler_a, rl2), "POST with limiter should be accepted");
    TEST_ASSERT(r->ratelimiter == rl2, "Route should own the replacement ratelimiter");

    // Method without a limiter must not discard the configured one.
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "PUT", route_test_handler_a, NULL), "PUT without limiter should be accepted");
    TEST_ASSERT(r->ratelimiter == rl2, "NULL ratelimiter should not overwrite the stored one");

    // Duplicate method: incoming limiter is not stored and must be freed
    // (LSan verifies).
    ratelimiter_t* rl3 = ratelimiter_init(&cfg);
    TEST_REQUIRE_NOT_NULL_GOTO(rl3, "ratelimiter_init should succeed", cleanup);
    TEST_ASSERT_EQUAL(1, route_set_http_handler(r, "GET", route_test_handler_b, rl3), "Duplicate GET should report success");
    TEST_ASSERT(r->ratelimiter == rl2, "Duplicate registration should not replace the ratelimiter");

    // Unknown method: incoming limiter must be freed (LSan verifies).
    ratelimiter_t* rl4 = ratelimiter_init(&cfg);
    TEST_REQUIRE_NOT_NULL_GOTO(rl4, "ratelimiter_init should succeed", cleanup);
    TEST_ASSERT_EQUAL(0, route_set_http_handler(r, "BOGUS", route_test_handler_a, rl4), "Unknown method should be rejected");
    TEST_ASSERT(r->ratelimiter == rl2, "Rejected registration should not replace the ratelimiter");

    cleanup:
    routes_free(r);
}

TEST(test_route_set_http_static) {
    TEST_CASE("route_set_http_static copies path and keeps first file");

    route_t* r = route_create("/index.html");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(0, route_set_http_static(r, "BOGUS", "/var/www/a.html", NULL), "Unknown method should be rejected");

    char source[] = "/var/www/a.html";
    TEST_ASSERT_EQUAL(1, route_set_http_static(r, "GET", source, NULL), "GET static file should be accepted");
    TEST_ASSERT_STR_EQUAL("/var/www/a.html", r->static_file[ROUTE_GET], "Static file path should be stored");
    TEST_ASSERT(r->static_file[ROUTE_GET] != source, "Static file path should be copied, not aliased");

    TEST_ASSERT_EQUAL(1, route_set_http_static(r, "GET", "/var/www/b.html", NULL), "Duplicate GET should report success");
    TEST_ASSERT_STR_EQUAL("/var/www/a.html", r->static_file[ROUTE_GET], "Duplicate GET should not overwrite static file");

    routes_free(r);
}

TEST(test_route_set_websockets_handler_methods) {
    TEST_CASE("route_set_websockets_handler matches methods exactly");

    route_t* r = route_create("/ws");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(1, route_set_websockets_handler(r, "GET", route_test_handler_a, NULL), "GET should be accepted");
    TEST_ASSERT(r->handler[ROUTE_GET] == route_test_handler_a, "GET handler should be stored");

    TEST_ASSERT_EQUAL(0, route_set_websockets_handler(r, "GETX", route_test_handler_b, NULL), "GETX must not match GET by prefix");
    TEST_ASSERT_EQUAL(0, route_set_websockets_handler(r, "DELETEX", route_test_handler_b, NULL), "DELETEX must not match DELETE by prefix");
    TEST_ASSERT_EQUAL(0, route_set_websockets_handler(r, "PUT", route_test_handler_b, NULL), "PUT is not supported for websockets");
    TEST_ASSERT_EQUAL(0, route_set_websockets_handler(r, "OPTIONS", route_test_handler_b, NULL), "OPTIONS is not supported for websockets");
    TEST_ASSERT_EQUAL(0, route_set_websockets_handler(r, "HEAD", route_test_handler_b, NULL), "HEAD is not supported for websockets");

    TEST_ASSERT_EQUAL(1, route_set_websockets_handler(r, "POST", route_test_handler_b, NULL), "POST should be accepted");
    TEST_ASSERT_EQUAL(1, route_set_websockets_handler(r, "DELETE", route_test_handler_b, NULL), "DELETE should be accepted");
    TEST_ASSERT_EQUAL(1, route_set_websockets_handler(r, "PATCH", route_test_handler_b, NULL), "PATCH should be accepted");

    TEST_ASSERT_EQUAL(1, route_set_websockets_handler(r, "GET", route_test_handler_b, NULL), "Duplicate GET should report success");
    TEST_ASSERT(r->handler[ROUTE_GET] == route_test_handler_a, "Duplicate GET should not overwrite handler");

    routes_free(r);
}

// ============================================================================
// route_compare_primitive
// ============================================================================

TEST(test_route_compare_primitive_cases) {
    TEST_CASE("route_compare_primitive compares length and content");

    route_t* r = route_create("/health");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(1, route_compare_primitive(r, "/health", 7), "Identical path should match");
    TEST_ASSERT_EQUAL(0, route_compare_primitive(r, "/health", 6), "Shorter length should not match");
    TEST_ASSERT_EQUAL(0, route_compare_primitive(r, "/healtz", 7), "Same length, different content should not match");
    TEST_ASSERT_EQUAL(0, route_compare_primitive(r, "", 0), "Empty path should not match");

    routes_free(r);
}

TEST(test_route_multiple_routes_free) {
    TEST_CASE("routes_free releases a whole chain");

    route_t* a = route_create("/a");
    route_t* b = route_create("/b/{id|[0-9]+}");
    TEST_REQUIRE_NOT_NULL(a, "route_create /a should succeed");
    TEST_REQUIRE_NOT_NULL_GOTO(b, "route_create /b should succeed", cleanup);

    a->next = b;
    route_set_http_static(b, "GET", "/var/www/b.html", NULL);
    route_set_http_handler(a, "GET", route_test_handler_a, NULL);

    routes_free(a); // LSan verifies both routes and their internals are freed
    return;

    cleanup:
    routes_free(a);
}

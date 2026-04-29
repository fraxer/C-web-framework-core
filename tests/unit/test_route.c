#include "framework.h"
#include "route.h"
#include <string.h>

// ============================================================================
// Route $-anchor tests — ensures routes with params match exactly,
// not by prefix (e.g. /users/{id} must NOT match /users/42/extra)
//
// In cpdy, named params require a regex alternative: {name|pattern}
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

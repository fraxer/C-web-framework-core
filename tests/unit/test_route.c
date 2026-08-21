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

// The stored static_file is a template now, so its value is read back by
// expanding it; a path without {N} expands to itself whatever the vector says.
static char* route_test_static_path(route_t* r, int method) {
    return strtemplate_expand(r->static_file[method], "", NULL);
}

TEST(test_route_set_http_static) {
    TEST_CASE("route_set_http_static copies path and keeps first file");

    route_t* r = route_create("/index.html");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(0, route_set_http_static(r, "BOGUS", "/var/www/a.html", NULL), "Unknown method should be rejected");

    char source[] = "/var/www/a.html";
    TEST_ASSERT_EQUAL(1, route_set_http_static(r, "GET", source, NULL), "GET static file should be accepted");

    char* stored = route_test_static_path(r, ROUTE_GET);
    TEST_ASSERT_STR_EQUAL("/var/www/a.html", stored, "Static file path should be stored");
    TEST_ASSERT((void*)stored != (void*)source, "Static file path should be copied, not aliased");
    free(stored);

    TEST_ASSERT_EQUAL(1, route_set_http_static(r, "GET", "/var/www/b.html", NULL), "Duplicate GET should report success");
    stored = route_test_static_path(r, ROUTE_GET);
    TEST_ASSERT_STR_EQUAL("/var/www/a.html", stored, "Duplicate GET should not overwrite static file");
    free(stored);

    routes_free(r);
}

TEST(test_route_static_file_template) {
    TEST_CASE("static_file expands {N} from the location's capture groups");

    route_t* r = route_create("/assets/(.*)");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");
    TEST_ASSERT_EQUAL(1, route_set_http_static(r, "GET", "/assets/{1}", NULL), "Template should be accepted");

    const char* path = "/assets/app/style.css";
    int vector[30];
    memset(vector, -1, sizeof(vector));

    int rc = pcre_exec(r->location, NULL, path, strlen(path), 0, 0, vector, 30);
    TEST_ASSERT(rc > 1, "Location should match with a capture group");

    char* expanded = strtemplate_expand(r->static_file[ROUTE_GET], path, vector);
    TEST_ASSERT_STR_EQUAL("/assets/app/style.css", expanded, "{1} should carry the captured tail");
    free(expanded);

    routes_free(r);
}

TEST(test_route_set_http_cache_control) {
    TEST_CASE("route_set_http_cache_control stores per method and keeps the first value");

    route_t* r = route_create("/index.html");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(0, route_set_http_cache_control(r, "BOGUS", "no-store"), "Unknown method should be rejected");
    TEST_ASSERT_NULL(r->cache_control[ROUTE_GET], "Nothing should be stored yet");

    TEST_ASSERT_EQUAL(1, route_set_http_cache_control(r, "GET", "public, max-age=31536000, immutable"), "GET should be accepted");
    TEST_ASSERT_STR_EQUAL("public, max-age=31536000, immutable", r->cache_control[ROUTE_GET], "Value should be stored");
    TEST_ASSERT_NULL(r->cache_control[ROUTE_POST], "Other methods should be untouched");

    TEST_ASSERT_EQUAL(1, route_set_http_cache_control(r, "GET", "no-store"), "Duplicate GET should report success");
    TEST_ASSERT_STR_EQUAL("public, max-age=31536000, immutable", r->cache_control[ROUTE_GET], "Duplicate GET should not overwrite");

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

// ============================================================================
// The primitive shortcut — the dispatcher answers a primitive location with
// route_compare_primitive alone and never runs its pattern. That is only sound
// while the two agree, so what decides `is_primitive` is exactly "does the
// pattern mean anything beyond this string".
// ============================================================================

/* The compiled pattern, asked directly. */
static int route_pattern_matches(route_t* route, const char* path) {
    int ovector[30];
    return pcre_exec(route->location, NULL, path, (int)strlen(path), 0, 0, ovector, 30) >= 0;
}

TEST(test_route_primitive_flag_excludes_metacharacters) {
    TEST_CASE("a location PCRE reads as more than itself is not primitive");

    static const struct { const char* location; int primitive; } cases[] = {
        {"/health", 1},
        {"/api/v1/items", 1},
        {"/a-b_c~d", 1},
        /* REGRESSION: '.' and '?' were not counted, so "/api/v1.0" was called
         * primitive while its pattern also matched "/api/v1x0" — the shortcut
         * and the pattern disagreed on exactly those paths. */
        {"/api/v1.0", 0},
        {"/maybe?", 0},
        {"/back\\slash", 0},
        {"/wild*", 0},
        {"/either|or", 0},
        {"/group(a)", 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        route_t* r = route_create(cases[i].location);
        TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

        TEST_ASSERT_EQUAL(cases[i].primitive, r->is_primitive, cases[i].location);

        routes_free(r);
    }
}

TEST(test_route_primitive_shortcut_agrees_with_pattern) {
    TEST_CASE("for a primitive location the comparison and the pattern answer identically");

    static const char* locations[] = {
        "/health", "/api/v1/items", "/", "/a-b_c~d",
    };

    static const char* paths[] = {
        "/health", "/healtz", "/health/", "/api/v1/items", "/api/v1/items/2",
        "/", "/a-b_c~d", "/a-b_c~dx", "", "/HEALTH",
    };

    for (size_t i = 0; i < sizeof(locations) / sizeof(locations[0]); i++) {
        route_t* r = route_create(locations[i]);
        TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");
        TEST_REQUIRE(r->is_primitive == 1, "the location under test is primitive");

        for (size_t j = 0; j < sizeof(paths) / sizeof(paths[0]); j++) {
            const int shortcut = route_compare_primitive(r, paths[j], strlen(paths[j]));
            if (shortcut != route_pattern_matches(r, paths[j])) {
                TEST_FAIL("the primitive shortcut disagreed with the pattern");
                break;
            }
        }

        routes_free(r);
    }

    TEST_ASSERT(1, "shortcut and pattern agree on every location/path pair");
}

TEST(test_route_dotted_location_still_matches_as_a_pattern) {
    TEST_CASE("a location with a dot keeps its old regex behaviour, it just loses the shortcut");

    route_t* r = route_create("/api/v1.0");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(0, r->is_primitive, "not eligible for the shortcut");
    /* Unchanged on purpose: the dot is still a regex any-char here, as it has
     * always been. Making it literal would be a change of routing behaviour and
     * belongs to its own decision, not to a performance shortcut. */
    TEST_ASSERT(route_pattern_matches(r, "/api/v1.0"), "the literal path matches");
    TEST_ASSERT(route_pattern_matches(r, "/api/v1x0"), "and so does any-char, as before");

    routes_free(r);
}

TEST(test_route_dot_with_named_param_is_still_allowed) {
    TEST_CASE("'.' next to a named param is an ordinary route, not a regex/params clash");

    /* The dot must not be counted as "regex symbols", or this route — a
     * perfectly ordinary one — would be refused at config load. */
    route_t* r = route_create("/files/{name|[a-z]+}.json");
    TEST_REQUIRE_NOT_NULL(r, "route_create should succeed");

    TEST_ASSERT_EQUAL(0, r->is_primitive, "a param makes it non-primitive anyway");
    TEST_ASSERT_EQUAL(1, r->params_count, "the param is still parsed");
    TEST_ASSERT(route_pattern_matches(r, "/files/report.json"), "and the route matches");

    routes_free(r);
}

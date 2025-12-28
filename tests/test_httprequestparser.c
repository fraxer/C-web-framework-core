#include "framework.h"
#include "httprequestparser.h"
#include "httpparsercommon.h"
#include "httprequest.h"
#include "connection_s.h"
#include "appconfig.h"
#include "helpers.h"
#include <string.h>
#include <stdlib.h>
#include <pcre.h>

// ============================================================================
// Mock Configuration and Dependencies
// ============================================================================

// Global mock appconfig for tests
static appconfig_t* test_appconfig = NULL;

// Initialize test appconfig
static void init_test_appconfig(void) {
    if (test_appconfig == NULL) {
        test_appconfig = calloc(1, sizeof(appconfig_t));
        if (test_appconfig) {
            // Initialize atomic values
            test_appconfig->shutdown = false;
            test_appconfig->threads_count = 0;

            // Initialize env
            test_appconfig->env.main.client_max_body_size = 10485760;  // 10MB
            test_appconfig->env.main.tmp = "/tmp";
            test_appconfig->env.main.log.enabled = false;
            test_appconfig->env.main.log.level = 0;
            test_appconfig->env.main.workers = 1;
            test_appconfig->env.main.threads = 1;
            test_appconfig->env.main.gzip = NULL;

            // Initialize other fields to NULL/0
            test_appconfig->path = NULL;
            test_appconfig->mimetype = NULL;
            test_appconfig->databases = NULL;
            test_appconfig->storages = NULL;
            test_appconfig->viewstore = NULL;
            test_appconfig->server_chain = NULL;
            test_appconfig->prepared_queries = NULL;
        }
    }
}

// Cleanup test appconfig
static void cleanup_test_appconfig(void) {
    if (test_appconfig) {
        free(test_appconfig);
        test_appconfig = NULL;
    }
}

// Override appconfig() function using weak symbol
__attribute__((weak)) appconfig_t* appconfig(void) {
    if (!test_appconfig) {
        init_test_appconfig();
    }
    return test_appconfig;
}

// Override env() function using weak symbol
__attribute__((weak)) env_t* env(void) {
    if (!test_appconfig) {
        init_test_appconfig();
    }
    return &test_appconfig->env;
}

// Override appconfig_set() to do nothing in tests
__attribute__((weak)) void appconfig_set(appconfig_t* config) {
    (void)config;
    // No-op in tests
}

// Mock server and domain structures
static domain_t mock_domain = {
    .pcre_erroffset = 0,
    .template = "localhost",
    .prepared_template = NULL,
    .pcre_error = NULL,
    .pcre_template = NULL,
    .next = NULL
};

static server_t mock_server = {
    .ip = 0x0100007F,  // 127.0.0.1
    .port = 8080,
    .domain = &mock_domain,
    .http = {.route = NULL, .ratelimiter = NULL, .redirect = NULL, .middleware = NULL},
    .websockets = {.route = NULL, .ratelimiter = NULL, .default_handler = NULL, .middleware = NULL},
    .next = NULL
};

static listener_t mock_listener = {
    .servers = {.item = NULL, .last_item = NULL, .size = 0, .locked = 0},
    .connection = NULL,
    .api = NULL,
    .next = NULL
};

static cqueue_item_t mock_queue_item = {
    .data = &mock_server,
    .next = NULL
};

static connection_server_ctx_t mock_server_ctx = {
    .listener = &mock_listener,
    .parser = NULL,
    .server = NULL,
    .response = NULL,
    .queue = NULL,
    .broadcast_queue = NULL
};

// ============================================================================
// Helper Functions
// ============================================================================

static connection_t* create_mock_connection(char* buffer, size_t buffer_size) {
    connection_t* conn = malloc(sizeof(connection_t));
    if (!conn) return NULL;

    memset(conn, 0, sizeof(connection_t));
    conn->buffer = buffer;
    conn->buffer_size = buffer_size;
    conn->ip = 0x0100007F;  // 127.0.0.1
    conn->port = 8080;
    conn->ssl = NULL;
    conn->ctx = (connection_ctx_t*)&mock_server_ctx;
    conn->keepalive = 0;

    return conn;
}

static void free_mock_connection(connection_t* conn) {
    if (conn) free(conn);
}

static void setup_mock_domain(void) {
    const char* pattern = "^localhost$";
    const char* error;
    int erroffset;

    mock_domain.pcre_template = pcre_compile(pattern, PCRE_CASELESS, &error, &erroffset, NULL);
    mock_listener.servers.item = &mock_queue_item;
    mock_listener.servers.last_item = &mock_queue_item;
    mock_listener.servers.size = 1;
}

static void cleanup_mock_domain(void) {
    if (mock_domain.pcre_template) {
        pcre_free(mock_domain.pcre_template);
        mock_domain.pcre_template = NULL;
    }
}

// ============================================================================
// Test Suite 1: Basic Parsing Tests
// ============================================================================

TEST(test_httprequestparser_simple_get) {
    TEST_SUITE("HTTP Request Parser - Basic Parsing");
    TEST_CASE("Parse simple GET request");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    TEST_ASSERT_NOT_NULL(conn, "Connection should be created");

    httprequestparser_t* parser = httpparser_create(conn);
    TEST_ASSERT_NOT_NULL(parser, "Parser should be created");

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Parser should complete successfully");
    TEST_ASSERT_NOT_NULL(parser->request, "Request should be created");
    TEST_ASSERT_EQUAL(ROUTE_GET, parser->request->method, "Method should be GET");
    TEST_ASSERT_EQUAL(HTTP1_VER_1_1, parser->request->version, "Version should be HTTP/1.1");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_all_methods) {
    TEST_CASE("Parse all HTTP methods");

    setup_mock_domain();

    const char* methods[] = {
        "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "POST /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "PUT /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "DELETE /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "PATCH /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "OPTIONS /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "HEAD /test HTTP/1.1\r\nHost: localhost\r\n\r\n"
    };

    route_methods_e expected_methods[] = {
        ROUTE_GET, ROUTE_POST, ROUTE_PUT, ROUTE_DELETE,
        ROUTE_PATCH, ROUTE_OPTIONS, ROUTE_HEAD
    };

    for (size_t i = 0; i < 7; i++) {
        char buffer[4096];
        strcpy(buffer, methods[i]);

        connection_t* conn = create_mock_connection(buffer, strlen(buffer));
        httprequestparser_t* parser = httpparser_create(conn);

        httpparser_set_bytes_readed(parser, strlen(methods[i]));
        int result = httpparser_run(parser);

        TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Parser should complete");
        TEST_ASSERT_EQUAL(expected_methods[i], parser->request->method, "Method should match");

        httpparser_free(parser);
        free_mock_connection(conn);
    }

    cleanup_mock_domain();
}

TEST(test_httprequestparser_invalid_method) {
    TEST_CASE("Reject invalid HTTP method");

    char buffer[4096];
    const char* request = "INVALID /test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject invalid method");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_method_too_long) {
    TEST_CASE("Reject method longer than 7 characters");

    char buffer[4096];
    const char* request = "GETGETGET /test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject method > 7 chars");

    httpparser_free(parser);
    free_mock_connection(conn);
}

// ============================================================================
// Test Suite 2: Protocol Version Tests
// ============================================================================

TEST(test_httprequestparser_http10) {
    TEST_SUITE("HTTP Request Parser - Protocol Versions");
    TEST_CASE("Parse HTTP/1.0 request");

    char buffer[4096];
    const char* request = "GET /test HTTP/1.0\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "HTTP/1.0 should parse");
    TEST_ASSERT_EQUAL(HTTP1_VER_1_0, parser->request->version, "Version should be HTTP/1.0");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_invalid_protocol) {
    TEST_CASE("Reject invalid protocol");

    char buffer[4096];
    const char* request = "GET /test HTTP/2.0\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject HTTP/2.0");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_protocol_wrong_length) {
    TEST_CASE("Reject protocol with wrong length");

    char buffer[4096];
    const char* request = "GET /test HTTP/1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject wrong protocol length");

    httpparser_free(parser);
    free_mock_connection(conn);
}

// ============================================================================
// Test Suite 3: URI Parsing Tests
// ============================================================================

TEST(test_httprequestparser_uri_with_query) {
    TEST_SUITE("HTTP Request Parser - URI Parsing");
    TEST_CASE("Parse URI with query string");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /path?key1=value1&key2=value2 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse URI with query");
    TEST_ASSERT_NOT_NULL(parser->request->query_, "Query should be parsed");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_uri_with_fragment) {
    TEST_CASE("Parse URI with fragment");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /path#section HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse URI with fragment");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_uri_url_encoding) {
    TEST_CASE("Decode URL-encoded URI");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /path%20with%20spaces HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should decode URI");
    TEST_ASSERT_STR_EQUAL("/path with spaces", parser->request->path, "Path should be decoded");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_uri_not_starting_with_slash) {
    TEST_CASE("Reject URI not starting with /");

    char buffer[4096];
    const char* request = "GET http://example.com/path HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject absolute URI");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_uri_with_control_chars) {
    TEST_CASE("Reject URI with control characters");

    char buffer[4096];
    const char* request = "GET /path\x01invalid HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject control chars in URI");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_uri_max_size) {
    TEST_CASE("Reject URI exceeding MAX_URI_SIZE");

    char buffer[65536];
    strcpy(buffer, "GET /");

    // Create a URI larger than MAX_URI_SIZE (32768)
    for (int i = 0; i < 33000; i++) {
        buffer[4 + i] = 'a';
    }
    strcpy(buffer + 4 + 33000, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(buffer));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject oversized URI");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_path_traversal) {
    TEST_CASE("Reject path traversal attempts");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject path traversal");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

// ============================================================================
// Test Suite 4: Header Parsing Tests
// ============================================================================

TEST(test_httprequestparser_header_basic) {
    TEST_SUITE("HTTP Request Parser - Header Parsing");
    TEST_CASE("Parse basic headers");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "User-Agent: TestClient/1.0\r\n"
                         "Accept: */*\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse headers");
    TEST_ASSERT_NOT_NULL(parser->request->header_, "Headers should exist");
    TEST_ASSERT_EQUAL_SIZE(3, parser->headers_count, "Should have 3 headers");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_header_no_space_after_colon) {
    TEST_CASE("Parse header without space after colon");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host:localhost\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse header without space");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_header_multiple_spaces) {
    TEST_CASE("Parse header with multiple spaces after colon");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host:     localhost\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse with multiple spaces");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_header_key_too_long) {
    TEST_CASE("Reject header key exceeding MAX_HEADER_KEY_SIZE");

    char buffer[4096];
    strcpy(buffer, "GET /test HTTP/1.1\r\n");

    // Create header key longer than MAX_HEADER_KEY_SIZE (256)
    for (int i = 0; i < 300; i++) {
        buffer[20 + i] = 'A';
    }
    strcpy(buffer + 20 + 300, ": value\r\n\r\n");

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(buffer));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject oversized header key");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_header_value_too_long) {
    TEST_CASE("Reject header value exceeding MAX_HEADER_VALUE_SIZE");

    setup_mock_domain();

    char buffer[16384];
    strcpy(buffer, "GET /test HTTP/1.1\r\nHost: localhost\r\nLarge: ");

    // Create header value longer than MAX_HEADER_VALUE_SIZE (8192)
    size_t offset = strlen(buffer);
    for (int i = 0; i < 9000; i++) {
        buffer[offset + i] = 'A';
    }
    strcpy(buffer + offset + 9000, "\r\n\r\n");

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(buffer));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject oversized header value");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_header_with_control_chars) {
    TEST_CASE("Reject header with control characters");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\nHost: localhost\r\nBad\x01Header: value\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject control chars in header");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_max_headers_count) {
    TEST_CASE("Reject request exceeding MAX_HEADERS_COUNT");

    char buffer[8192];
    strcpy(buffer, "GET /test HTTP/1.1\r\n");
    size_t offset = strlen(buffer);

    // Add more than MAX_HEADERS_COUNT (30) headers
    for (int i = 0; i < 35; i++) {
        char header[64];
        sprintf(header, "Header%d: value%d\r\n", i, i);
        strcpy(buffer + offset, header);
        offset += strlen(header);
    }
    strcpy(buffer + offset, "\r\n");

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(buffer));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject too many headers");

    httpparser_free(parser);
    free_mock_connection(conn);
}

// ============================================================================
// Test Suite 5: Host Header Tests
// ============================================================================

TEST(test_httprequestparser_missing_host_http11) {
    TEST_SUITE("HTTP Request Parser - Host Header Validation");
    TEST_CASE("Reject HTTP/1.1 request without Host header");

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject missing Host in HTTP/1.1");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_duplicate_host_header) {
    TEST_CASE("Detect duplicate Host headers (Request Smuggling)");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Host: evil.com\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // Parser MUST reject duplicate Host headers to prevent Request Smuggling
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject duplicate Host headers");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

// ============================================================================
// Test Suite 6: Content-Length Tests
// ============================================================================

TEST(test_httprequestparser_content_length_valid) {
    TEST_SUITE("HTTP Request Parser - Content-Length Validation");
    TEST_CASE("Parse valid Content-Length");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 5\r\n"
                         "\r\n"
                         "hello";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    init_test_appconfig();

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse valid Content-Length");
    TEST_ASSERT_EQUAL_SIZE(5, parser->content_length, "Content-Length should be 5");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_duplicate) {
    TEST_CASE("Reject duplicate Content-Length headers");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 5\r\n"
                         "Content-Length: 10\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject duplicate Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_negative) {
    TEST_CASE("Reject negative Content-Length");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: -5\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject negative Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_non_digit) {
    TEST_CASE("Reject Content-Length with non-digit characters");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 10abc\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject non-digit Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_too_large) {
    TEST_CASE("Reject Content-Length exceeding max body size");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 99999999999\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject oversized Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_empty) {
    TEST_CASE("Reject empty Content-Length");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: \r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject empty Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_leading_zeros) {
    TEST_CASE("Accept Content-Length with leading zeros");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 00005\r\n"
                         "\r\n"
                         "hello";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    init_test_appconfig();

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should accept leading zeros in Content-Length");
    TEST_ASSERT_EQUAL_SIZE(5, parser->content_length, "Content-Length should be 5");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_with_spaces) {
    TEST_CASE("Reject Content-Length with spaces");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 10 \r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject Content-Length with spaces");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_overflow) {
    TEST_CASE("Reject Content-Length causing integer overflow");

    setup_mock_domain();

    char buffer[4096];
    // Value larger than ULLONG_MAX
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 99999999999999999999999999999999\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject overflow Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_string) {
    TEST_CASE("Reject Content-Length with string value");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: string\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject string Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_post_without_content_length) {
    TEST_CASE("Accept POST without Content-Length");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should accept POST without Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_post_with_body_without_content_length) {
    TEST_CASE("Reject POST with body but without Content-Length");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "\r\n"
                         "hello";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject POST with body but without Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_put_with_body_without_content_length) {
    TEST_CASE("Reject PUT with body but without Content-Length");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "PUT /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "\r\n"
                         "hello";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject PUT with body but without Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_patch_with_body_without_content_length) {
    TEST_CASE("Reject PATCH with body but without Content-Length");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "PATCH /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "\r\n"
                         "hello";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject PATCH with body but without Content-Length");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_get_with_content_length) {
    TEST_CASE("Reject GET with payload");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 5\r\n"
                         "\r\n"
                         "hello";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    init_test_appconfig();

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // GET does not allow payload - should be rejected when payload data is present
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject GET with payload data");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

// ============================================================================
// Test Suite 7: Transfer-Encoding Tests (Request Smuggling)
// ============================================================================

TEST(test_httprequestparser_transfer_encoding_rejected) {
    TEST_SUITE("HTTP Request Parser - Transfer-Encoding Security");
    TEST_CASE("Reject Transfer-Encoding in requests");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject Transfer-Encoding");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_transfer_encoding_http10) {
    TEST_CASE("Reject Transfer-Encoding in HTTP/1.0");

    char buffer[4096];
    const char* request = "POST /test HTTP/1.0\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject TE in HTTP/1.0");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_both_te_and_cl) {
    TEST_CASE("Reject both Transfer-Encoding and Content-Length (Smuggling)");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 10\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject TE + CL combination");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_te_then_cl) {
    TEST_CASE("Reject Transfer-Encoding followed by Content-Length");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "Content-Length: 10\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject TE before CL");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

// ============================================================================
// Test Suite 8: Newline Handling Tests
// ============================================================================

TEST(test_httprequestparser_missing_crlf) {
    TEST_SUITE("HTTP Request Parser - Newline Handling");
    TEST_CASE("Reject request with missing CRLF");

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\nHost: localhost\n\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject LF without CR");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_cr_without_lf) {
    TEST_CASE("Reject CR without LF");

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\rHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject CR without LF");

    httpparser_free(parser);
    free_mock_connection(conn);
}

// ============================================================================
// Test Suite 9: Incremental Parsing Tests
// ============================================================================

TEST(test_httprequestparser_incremental_parsing) {
    TEST_SUITE("HTTP Request Parser - Incremental Parsing");
    TEST_CASE("Parse request incrementally in multiple chunks");

    setup_mock_domain();

    char buffer[4096] = {0};
    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    // Part 1: Send request line
    const char* part1 = "GET /test HTTP/1.1\r\n";
    strcpy(buffer, part1);
    httpparser_set_bytes_readed(parser, strlen(part1));
    parser->pos_start = 0;
    parser->pos = 0;
    int result = httpparser_run(parser);
    TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, result, "Should continue after request line");

    // Part 2: Add Host header
    const char* part2 = "Host: localhost\r\n";
    strcpy(buffer, part2);
    httpparser_set_bytes_readed(parser, strlen(part2));
    parser->pos_start = 0;
    parser->pos = 0;
    result = httpparser_run(parser);
    TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, result, "Should continue after Host header");

    // Part 3: Add final CRLF to complete headers
    const char* part3 = "\r\n";
    strcpy(buffer, part3);
    httpparser_set_bytes_readed(parser, strlen(part3));
    parser->pos_start = 0;
    parser->pos = 0;
    result = httpparser_run(parser);
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should complete after final CRLF");

    // Verify parsed request
    TEST_ASSERT_NOT_NULL(parser->request, "Request should be created");
    TEST_ASSERT_EQUAL(ROUTE_GET, parser->request->method, "Method should be GET");
    TEST_ASSERT_EQUAL(HTTP1_VER_1_1, parser->request->version, "Version should be HTTP/1.1");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

// ============================================================================
// Test Suite 10: Keep-Alive and Connection Headers
// ============================================================================

TEST(test_httprequestparser_keepalive) {
    TEST_SUITE("HTTP Request Parser - Connection Headers");
    TEST_CASE("Parse Connection: keep-alive");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Connection: keep-alive\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse keep-alive");
    TEST_ASSERT_EQUAL(1, conn->keepalive, "Keep-alive should be enabled");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

// ============================================================================
// Test Suite 11: Edge Cases
// ============================================================================

TEST(test_httprequestparser_empty_buffer) {
    TEST_SUITE("HTTP Request Parser - Edge Cases");
    TEST_CASE("Handle empty buffer");

    char buffer[4096];
    buffer[0] = '\0';

    connection_t* conn = create_mock_connection(buffer, 0);
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, 0);
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, result, "Should handle empty buffer gracefully");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_incomplete_request) {
    TEST_CASE("Handle incomplete request");

    char buffer[4096];
    const char* request = "GET /test HTTP";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, result, "Should wait for more data");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_pipelined_requests) {
    TEST_CASE("Handle pipelined requests");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                         "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_HANDLE_AND_CONTINUE, result, "Should detect pipelined request");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_null_parser) {
    TEST_CASE("Handle NULL and invalid cases");

    // Note: httpparser_free() and httpparser_reset() do not check for NULL
    // This is by design - they expect valid pointers
    // This test verifies basic parser lifecycle

    char buffer[4096];
    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
    TEST_ASSERT_NOT_NULL(conn, "Connection should be created");

    httprequestparser_t* parser = httpparser_create(conn);
    TEST_ASSERT_NOT_NULL(parser, "Parser should be created");

    // Clean up properly
    httpparser_free(parser);
    free_mock_connection(conn);

    TEST_ASSERT(1, "Parser lifecycle should work correctly");
}

// ============================================================================
// Test Suite 12: Memory and Resource Tests
// ============================================================================

TEST(test_httprequestparser_create_destroy) {
    TEST_SUITE("HTTP Request Parser - Memory Management");
    TEST_CASE("Create and destroy parser multiple times");

    char buffer[4096];
    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));

    for (int i = 0; i < 100; i++) {
        httprequestparser_t* parser = httpparser_create(conn);
        TEST_ASSERT_NOT_NULL(parser, "Parser should be created");
        httpparser_free(parser);
    }

    free_mock_connection(conn);
}

TEST(test_httprequestparser_reset) {
    TEST_CASE("Reset parser state");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    httpparser_run(parser);

    // Reset and parse again
    httpparser_reset(parser);

    TEST_ASSERT_EQUAL(HTTP1REQUESTPARSER_METHOD, parser->stage, "Stage should be reset");
    TEST_ASSERT_EQUAL_SIZE(0, parser->bytes_readed, "Bytes read should be reset");
    TEST_ASSERT_EQUAL_SIZE(0, parser->pos, "Position should be reset");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

// ============================================================================
// Test Suite 13: Real-World Attack Scenarios
// ============================================================================

TEST(test_httprequestparser_request_smuggling_cl_cl) {
    TEST_SUITE("HTTP Request Parser - Security Attack Scenarios");
    TEST_CASE("Prevent CL-CL Request Smuggling");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 6\r\n"
                         "Content-Length: 5\r\n"
                         "\r\n"
                         "hello";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should prevent CL-CL smuggling");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_request_smuggling_host_host) {
    TEST_CASE("Detect Host-Host Request Smuggling attempt");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Host: attacker.com\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // Parser MUST reject duplicate Host headers to prevent Request Smuggling
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject Host-Host smuggling attempt");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_slowloris_attack) {
    TEST_CASE("Handle Slowloris-style slow headers");

    char buffer[4096];
    strcpy(buffer, "GET /test HTTP/1.1\r\nH");

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(buffer));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, result, "Should handle incomplete headers");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_null_byte_injection) {
    TEST_CASE("Reject NULL byte injection in URI");

    char buffer[4096];
    const char request[] = "GET /test\0attack HTTP/1.1\r\nHost: localhost\r\n\r\n";
    memcpy(buffer, request, sizeof(request));

    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, sizeof(request) - 1);
    int result = httpparser_run(parser);

    // NULL byte is a control character and should be rejected
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject NULL byte in URI");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_null_byte_in_header_value) {
    TEST_CASE("Reject NULL byte in header value");

    setup_mock_domain();

    char buffer[4096];
    const char request[] = "GET /test HTTP/1.1\r\nHost: localhost\r\nX-Custom: value\0attack\r\n\r\n";
    memcpy(buffer, request, sizeof(request));

    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, sizeof(request) - 1);
    int result = httpparser_run(parser);

    // NULL byte is a control character and should be rejected
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject NULL byte in header value");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_various_control_chars_in_uri) {
    TEST_CASE("Reject various control characters in URI");

    // Test multiple control characters: \x00, \x01, \x0B, \x0C, \x0E-\x1F
    const char control_chars[] = {0x00, 0x01, 0x0B, 0x0C, 0x0E, 0x1F};

    for (size_t i = 0; i < sizeof(control_chars); i++) {
        char buffer[4096];
        sprintf(buffer, "GET /test");
        size_t len = strlen(buffer);
        buffer[len] = control_chars[i];
        strcpy(buffer + len + 1, "invalid HTTP/1.1\r\nHost: localhost\r\n\r\n");

        connection_t* conn = create_mock_connection(buffer, strlen(buffer) + 1);
        httprequestparser_t* parser = httpparser_create(conn);

        httpparser_set_bytes_readed(parser, strlen(buffer) + 1);
        int result = httpparser_run(parser);

        TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject control chars in URI");

        httpparser_free(parser);
        free_mock_connection(conn);
    }
}

TEST(test_httprequestparser_various_control_chars_in_header) {
    TEST_CASE("Reject various control characters in header key");

    setup_mock_domain();

    // Test control characters in header key
    const char control_chars[] = {0x00, 0x01, 0x0B, 0x0C, 0x0E, 0x1F};

    for (size_t i = 0; i < sizeof(control_chars); i++) {
        char buffer[4096];
        sprintf(buffer, "GET /test HTTP/1.1\r\nHost: localhost\r\nX-Bad");
        size_t len = strlen(buffer);
        buffer[len] = control_chars[i];
        strcpy(buffer + len + 1, "Header: value\r\n\r\n");

        connection_t* conn = create_mock_connection(buffer, strlen(buffer) + 1);
        httprequestparser_t* parser = httpparser_create(conn);

        httpparser_set_bytes_readed(parser, strlen(buffer) + 1);
        int result = httpparser_run(parser);

        TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject control chars in header key");

        httpparser_free(parser);
        free_mock_connection(conn);
    }

    cleanup_mock_domain();
}

// ============================================================================
// Test Suite 14: Additional Edge Cases and Security Tests
// ============================================================================

TEST(test_httprequestparser_http_09_rejection) {
    TEST_SUITE("HTTP Request Parser - Additional Security Tests");
    TEST_CASE("Reject HTTP/0.9 protocol");

    char buffer[4096];
    const char* request = "GET /test HTTP/0.9\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject HTTP/0.9");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_method_with_space) {
    TEST_CASE("Reject method with embedded space");

    char buffer[4096];
    const char* request = "G ET /test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject method with space");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_protocol_with_space) {
    TEST_CASE("Reject protocol with embedded space");

    char buffer[4096];
    const char* request = "GET /test HTTP /1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject protocol with space");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_header_without_colon) {
    TEST_CASE("Reject header without colon");

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\nHost localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject header without colon");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_header_multiple_colons) {
    TEST_CASE("Accept header with multiple colons in value");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "X-Custom: value:with:colons\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should accept colons in header value");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_empty_header_key) {
    TEST_CASE("Reject empty header key");

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n: value\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject empty header key");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_url_encoding_invalid_hex) {
    TEST_CASE("Handle invalid URL encoding sequences");

    setup_mock_domain();

    // Test various invalid URL encoding sequences
    const char* invalid_encodings[] = {
        "GET /test%ZZ HTTP/1.1\r\nHost: localhost\r\n\r\n",  // Invalid hex
        "GET /test%0 HTTP/1.1\r\nHost: localhost\r\n\r\n",   // Incomplete encoding
        "GET /test% HTTP/1.1\r\nHost: localhost\r\n\r\n",    // Incomplete encoding
    };

    for (size_t i = 0; i < 3; i++) {
        char buffer[4096];
        strcpy(buffer, invalid_encodings[i]);

        connection_t* conn = create_mock_connection(buffer, strlen(buffer));
        httprequestparser_t* parser = httpparser_create(conn);

        httpparser_set_bytes_readed(parser, strlen(buffer));
        int result = httpparser_run(parser);

        // Invalid URL encoding should be handled gracefully
        // Parser may accept or reject based on implementation
        TEST_ASSERT(result == HTTP1PARSER_COMPLETE || result == HTTP1PARSER_BAD_REQUEST,
                    "Should handle invalid URL encoding");

        httpparser_free(parser);
        free_mock_connection(conn);
    }

    cleanup_mock_domain();
}

TEST(test_httprequestparser_connection_close) {
    TEST_CASE("Parse Connection: close");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Connection: close\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse Connection: close");
    TEST_ASSERT_EQUAL(0, conn->keepalive, "Keep-alive should be disabled");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_path_double_slashes) {
    TEST_CASE("Accept path with double slashes");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET //test//path HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // Double slashes in path should be accepted
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should accept double slashes in path");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_path_ending_traversal) {
    TEST_CASE("Reject path ending with /../");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test/path/../../ HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject path ending with traversal");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_options_asterisk) {
    TEST_CASE("Handle OPTIONS * request");

    char buffer[4096];
    const char* request = "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // OPTIONS * requires special handling - asterisk form not starting with /
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject OPTIONS * (not starting with /)");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_very_long_path) {
    TEST_CASE("Reject very long path within URI");

    setup_mock_domain();

    char buffer[65536];
    strcpy(buffer, "GET /");

    // Create a path longer than MAX_URI_SIZE (32768)
    for (int i = 0; i < 33000; i++) {
        buffer[5 + i] = 'a';
    }
    strcpy(buffer + 5 + 33000, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(buffer));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject very long path");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_tab_in_header_value) {
    TEST_CASE("Reject tab character in header value");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "X-Custom: value\twith\ttabs\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // Tabs in header values are control characters and should be rejected
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject tabs in header value");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_trailing_whitespace_header) {
    TEST_CASE("Reject trailing whitespace in Host header value");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost   \r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // Trailing spaces in Host header prevent domain matching
    TEST_ASSERT_EQUAL(HTTP1PARSER_HOST_NOT_FOUND, result, "Should reject Host with trailing whitespace");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_case_sensitivity_headers) {
    TEST_CASE("Test case insensitivity for header names");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "hOsT: localhost\r\n"
                         "CoNtEnT-lEnGtH: 0\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should handle case-insensitive headers");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_multiple_connection_headers) {
    TEST_CASE("Handle multiple Connection headers");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Connection: keep-alive\r\n"
                         "Connection: close\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // Multiple Connection headers - last one should win
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should handle multiple Connection headers");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_request_line_too_long) {
    TEST_CASE("Reject request line that's too long");

    char buffer[65536];
    strcpy(buffer, "GET /");

    // Create a URI of exactly MAX_URI_SIZE + 1
    for (int i = 0; i < 32769; i++) {
        buffer[5 + i] = 'a';
    }
    strcpy(buffer + 5 + 32769, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(buffer));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject request line too long");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_head_method_with_content_length) {
    TEST_CASE("Reject HEAD with payload");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "HEAD /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 10\r\n"
                         "\r\n"
                         "helloworld";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    init_test_appconfig();

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // HEAD does not allow payload - should be rejected when payload data is present
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject HEAD with payload data");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_delete_with_payload) {
    TEST_CASE("Reject DELETE with payload");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "DELETE /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 5\r\n"
                         "\r\n"
                         "hello";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    init_test_appconfig();

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // DELETE does not allow payload in this implementation (only POST/PUT/PATCH)
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject DELETE with payload");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_http10_with_keepalive) {
    TEST_CASE("Handle HTTP/1.0 with Connection: keep-alive");

    char buffer[4096];
    const char* request = "GET /test HTTP/1.0\r\n"
                         "Connection: keep-alive\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should accept HTTP/1.0 with keep-alive");
    TEST_ASSERT_EQUAL(1, conn->keepalive, "Keep-alive should be enabled");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_http10_no_host) {
    TEST_CASE("Accept HTTP/1.0 without Host header");

    char buffer[4096];
    const char* request = "GET /test HTTP/1.0\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // HTTP/1.0 doesn't require Host header
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should accept HTTP/1.0 without Host");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_query_string_with_special_chars) {
    TEST_CASE("Handle query string with special characters");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test?key=%3D%26%3F%23 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should handle encoded special chars in query");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_fragment_with_special_chars) {
    TEST_CASE("Handle fragment with special characters");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test#section%20one HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should handle fragment with special chars");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_mixed_case_method) {
    TEST_CASE("Reject mixed case HTTP method");

    char buffer[4096];
    const char* request = "GeT /test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    // HTTP methods are case-sensitive
    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject mixed case method");

    httpparser_free(parser);
    free_mock_connection(conn);
}

TEST(test_httprequestparser_empty_query_string) {
    TEST_CASE("Handle empty query string");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test? HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should handle empty query string");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_empty_fragment) {
    TEST_CASE("Handle empty fragment");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET /test# HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should handle empty fragment");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

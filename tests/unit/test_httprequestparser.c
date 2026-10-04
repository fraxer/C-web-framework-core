#include "bodystore.h"
#include "framework.h"
#include "httprequestparser.h"
#include "httpparsercommon.h"
#include "httprequest.h"
#include "connection_s.h"
#include "appconfig.h"
#include "helpers.h"
#include <string.h>
#include <stdlib.h>
#include <pcre2.h>
#include <fcntl.h>
#include <unistd.h>

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
            test_appconfig->env.main.body_store.file_threshold = BODY_STORE_DEFAULT_FILE_THRESHOLD;
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
        }
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
    .ip = {.family = AF_INET, .u = {.v4 = {.s_addr = 0x0100007F}}},  // 127.0.0.1
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
    conn->ip = ipaddr_from_v4(0x0100007F);  // 127.0.0.1
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
    int errorcode;
    PCRE2_SIZE erroffset;

    mock_domain.pcre_template = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS, &errorcode, &erroffset, NULL);
    mock_listener.servers.item = &mock_queue_item;
    mock_listener.servers.last_item = &mock_queue_item;
    mock_listener.servers.size = 1;
}

static void cleanup_mock_domain(void) {
    if (mock_domain.pcre_template) {
        pcre2_code_free(mock_domain.pcre_template);
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
    TEST_CASE("Trim trailing OWS in Content-Length value");

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

    // RFC 7230 (3.2.4): field value excludes trailing OWS, so "10 " is valid;
    // the parser then waits for the 10-byte body
    TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, result, "Should trim trailing OWS and accept Content-Length");
    TEST_ASSERT_EQUAL_SIZE(10, parser->content_length, "Content-Length should be 10");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_content_length_inner_space) {
    TEST_CASE("Reject Content-Length with inner space");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "POST /test HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 1 0\r\n"
                         "\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "Should reject Content-Length with inner space");

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
    TEST_CASE("POST without Content-Length has empty body, remaining bytes are pipelined");

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

    // RFC 7230 (3.3.3): without Content-Length the request has no body;
    // the trailing bytes belong to the next (here: malformed) pipelined request
    TEST_ASSERT_EQUAL(HTTP1PARSER_HANDLE_AND_CONTINUE, result, "Should complete POST with empty body and continue with pipelined data");
    TEST_ASSERT_EQUAL_SIZE(0, parser->content_length, "Content-Length should be 0");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_put_with_body_without_content_length) {
    TEST_CASE("PUT without Content-Length has empty body, remaining bytes are pipelined");

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

    TEST_ASSERT_EQUAL(HTTP1PARSER_HANDLE_AND_CONTINUE, result, "Should complete PUT with empty body and continue with pipelined data");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_patch_with_body_without_content_length) {
    TEST_CASE("PATCH without Content-Length has empty body, remaining bytes are pipelined");

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

    TEST_ASSERT_EQUAL(HTTP1PARSER_HANDLE_AND_CONTINUE, result, "Should complete PATCH with empty body and continue with pipelined data");

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
    if (conn == NULL) { cleanup_mock_domain(); return; }
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse keep-alive");
    TEST_ASSERT_EQUAL(1, parser->request->keepalive, "Keep-alive should be enabled");

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

    httprequest_t* req = parser->request;

    // Reset and parse again
    httpparser_reset(parser);

    TEST_ASSERT_EQUAL(HTTP1REQUESTPARSER_METHOD, parser->stage, "Stage should be reset");
    TEST_ASSERT_EQUAL_SIZE(0, parser->bytes_readed, "Bytes read should be reset");
    TEST_ASSERT_EQUAL_SIZE(0, parser->pos, "Position should be reset");

    parser->request = req;

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
    if (conn == NULL) { cleanup_mock_domain(); return; }
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should parse Connection: close");
    TEST_ASSERT_EQUAL(0, parser->request->keepalive, "Keep-alive should be disabled");

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

/* asterisk-form (RFC 9112 §3.2.4) — docs/http2/10, S.2.
 *
 * This case used to assert the opposite: that "OPTIONS *" is rejected because
 * the target does not start with "/". That was the bug, written down as an
 * expectation — the form is legal, and only for OPTIONS. */
TEST(test_httprequestparser_options_asterisk) {
    TEST_CASE("Handle OPTIONS * request");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "OPTIONS * should parse");
    TEST_ASSERT_EQUAL(ROUTE_OPTIONS, parser->request->method, "Method should be OPTIONS");
    TEST_ASSERT_EQUAL(1, parser->request->asterisk_form, "Request should be marked asterisk-form");
    TEST_ASSERT_EQUAL((size_t)1, parser->request->path_length, "Path should be one character");
    TEST_ASSERT(parser->request->path != NULL && parser->request->path[0] == '*',
                "Path should be the literal \"*\", which no route matches");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

/* The other half of the rule: "*" is a target for OPTIONS and nothing else. */
TEST(test_httprequestparser_get_asterisk_rejected) {
    TEST_CASE("Reject GET * request");

    setup_mock_domain();

    char buffer[4096];
    const char* request = "GET * HTTP/1.1\r\nHost: localhost\r\n\r\n";
    strcpy(buffer, request);

    connection_t* conn = create_mock_connection(buffer, strlen(buffer));
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_BAD_REQUEST, result, "asterisk-form is for OPTIONS only");

    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
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
    TEST_CASE("Trim trailing whitespace in Host header value");

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

    // RFC 7230 (3.2.4): trailing OWS is not part of the field value,
    // so the Host still matches the configured domain
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should trim trailing whitespace and match Host");

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
    if (conn == NULL) return;
    httprequestparser_t* parser = httpparser_create(conn);

    httpparser_set_bytes_readed(parser, strlen(request));
    int result = httpparser_run(parser);

    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, result, "Should accept HTTP/1.0 with keep-alive");
    TEST_ASSERT_EQUAL(1, parser->request->keepalive, "Keep-alive should be enabled");

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

TEST(test_httprequestparser_memory_json_without_tmp) {
    TEST_SUITE("HTTP Request Parser - memory body");
    setup_mock_domain();
    char* old_tmp = env()->main.tmp;
    env()->main.tmp = "/cwfr-nonexistent-temp-directory";
    char buffer[] = "POST /db HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"value\":42}";
    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    httpparser_set_bytes_readed(parser, strlen(buffer));
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, httpparser_run(parser), "small JSON requires no temp directory");
    httprequest_t* request = parser->request;
    TEST_REQUIRE_NOT_NULL(request, "parsed request");
    TEST_ASSERT_EQUAL(BODY_STORE_MEMORY, request->payload_.incoming.state, "memory selected");
    TEST_ASSERT_EQUAL(13, request->payload_.incoming.capacity, "reserve declared bytes plus NUL");
    TEST_ASSERT_EQUAL(-1, request->payload_.incoming.fd, "no incoming fd");
    TEST_ASSERT_EQUAL(-1, request->payload_.file.fd, "no legacy fd");
    char* copy = request->get_payload(request);
    TEST_ASSERT_NOT_NULL(copy, "owned text copy");
    if (copy) TEST_ASSERT_STR_EQUAL("{\"value\":42}", copy, "text bytes");
    json_doc_t* first = request->get_payload_json(request);
    json_doc_t* second = request->get_payload_json(request);
    TEST_ASSERT_NOT_NULL(first, "JSON from memory");
    TEST_ASSERT_NOT_NULL(second, "independent JSON document");
    if (first && second) TEST_ASSERT(first != second, "no JSON document caching");
    request->base.reset(request);
    TEST_ASSERT_NULL(request->payload_.incoming.data, "reset releases memory");
    TEST_ASSERT_EQUAL(0, request->payload_.incoming.size, "reset clears size");
    if (copy) TEST_ASSERT_STR_EQUAL("{\"value\":42}", copy, "text copy survives reset");
    if (first) {
        TEST_ASSERT_EQUAL(42, json_int(json_object_get(json_root(first), "value"), NULL), "JSON owns its bytes");
        json_free(first);
    }
    if (second) json_free(second);
    free(copy);
    httpparser_free(parser);
    free_mock_connection(conn);
    env()->main.tmp = old_tmp;
    cleanup_mock_domain();
}

TEST(test_httprequestparser_body_storage_boundaries) {
    TEST_SUITE("HTTP Request Parser - body storage boundaries");
    setup_mock_domain();
    const size_t sizes[] = {1, 200, 20480, BODY_STORE_DEFAULT_FILE_THRESHOLD - 1,
        BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_DEFAULT_FILE_THRESHOLD + 1};
    char buffer[8192];
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
        httprequestparser_t* parser = httpparser_create(conn);
        int header = snprintf(buffer, sizeof(buffer),
            "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: %zu\r\n\r\n", sizes[i]);
        httpparser_set_bytes_readed(parser, (size_t)header);
        TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, httpparser_run(parser), "headers alone do not complete body");
        size_t sent = 0;
        while (sent < sizes[i]) {
            size_t n = sizes[i] - sent;
            if (n > sizeof(buffer)) n = sizeof(buffer);
            for (size_t j = 0; j < n; ++j) buffer[j] = (char)((sent + j) % 251);
            parser->pos = 0;
            httpparser_set_bytes_readed(parser, n);
            int result = httpparser_run(parser);
            sent += n;
            TEST_ASSERT_EQUAL(sent == sizes[i] ? HTTP1PARSER_COMPLETE : HTTP1PARSER_CONTINUE,
                result, "dispatch only after last byte");
        }
        httprequest_t* request = parser->request;
        TEST_REQUIRE_NOT_NULL(request, "request retained");
        TEST_ASSERT_EQUAL(sizes[i] < BODY_STORE_DEFAULT_FILE_THRESHOLD ? BODY_STORE_MEMORY : BODY_STORE_FILE,
            request->payload_.incoming.state, "storage matches declared length");
        TEST_ASSERT_EQUAL(sizes[i], request->payload_.incoming.size, "received bytes counted");
        char* copy = request->get_payload(request);
        TEST_ASSERT_NOT_NULL(copy, "binary copy");
        if (copy) {
            int same = 1;
            for (size_t j = 0; j < sizes[i]; ++j)
                if (copy[j] != (char)(j % 251)) { same = 0; break; }
            TEST_ASSERT(same, "binary bytes preserved across network buffers");
            TEST_ASSERT_EQUAL(0, copy[sizes[i]], "copy terminator");
        }
        free(copy);
        int fd = request->payload_.incoming.fd;
        char* path = request->payload_.incoming.path ? strdup(request->payload_.incoming.path) : NULL;
        httpparser_free(parser);
        if (fd >= 0) TEST_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD), "request retirement closes body fd");
        if (path) TEST_ASSERT_EQUAL(-1, access(path, F_OK), "request retirement removes body file");
        free(path);
        free_mock_connection(conn);
    }
    cleanup_mock_domain();
}

TEST(test_httprequestparser_memory_pipeline) {
    TEST_SUITE("HTTP Request Parser - body pipeline and reuse");
    setup_mock_domain();
    char buffer[] = "POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc"
                    "POST /second HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nxyz";
    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    httpparser_set_bytes_readed(parser, strlen(buffer));
    TEST_ASSERT_EQUAL(HTTP1PARSER_HANDLE_AND_CONTINUE, httpparser_run(parser), "first body completes before next request");
    httprequest_t* first = parser->request;
    char* copy = first->get_payload(first);
    if (copy) TEST_ASSERT_STR_EQUAL("abc", copy, "first body range");
    free(copy);
    mock_server_ctx.request_retire(&mock_server_ctx, first);
    httpparser_prepare_continue(parser);
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, httpparser_run(parser), "second request completes");
    TEST_ASSERT(parser->request == first, "retired request reused");
    copy = parser->request->get_payload(parser->request);
    TEST_ASSERT_NOT_NULL(copy, "second body");
    if (copy) TEST_ASSERT_STR_EQUAL("xyz", copy, "no retained previous bytes");
    free(copy);
    httpparser_free(parser);
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_memory_form_compatibility) {
    TEST_SUITE("HTTP Request Parser - memory form compatibility");
    setup_mock_domain();
    const char* bodies[] = {"name=john", "--test\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\njohn\r\n--test--\r\n"};
    const char* types[] = {"application/x-www-form-urlencoded", "multipart/form-data; boundary=test"};
    char buffer[1024];
    for (int i = 0; i < 2; ++i) {
        int n = snprintf(buffer, sizeof(buffer), "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n%s", types[i], strlen(bodies[i]), bodies[i]);
        connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
        httprequestparser_t* parser = httpparser_create(conn);
        httpparser_set_bytes_readed(parser, (size_t)n);
        TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, httpparser_run(parser), "form received");
        TEST_ASSERT_EQUAL(BODY_STORE_MEMORY, parser->request->payload_.incoming.state, "form initially in memory");
        char* value = parser->request->get_payloadf(parser->request, "name");
        TEST_ASSERT_NOT_NULL(value, "legacy form reader works");
        if (value) TEST_ASSERT_STR_EQUAL("john", value, "form field");
        free(value);
        TEST_ASSERT_EQUAL(-1, parser->request->payload_.file.fd, "form accessor creates no file");
        TEST_ASSERT_EQUAL(-1, parser->request->payload_.incoming.fd, "form remains in memory");
        int fd = parser->request->payload_.file.fd;
        value = parser->request->get_payloadf(parser->request, "name");
        free(value);
        TEST_ASSERT_EQUAL(fd, parser->request->payload_.file.fd, "repeat access creates no fd");
        httpparser_free(parser);
        TEST_ASSERT_EQUAL(BODY_STORE_EMPTY, ((httprequest_t*)mock_server_ctx.request_cache)->payload_.incoming.state, "retired form buffer freed");
        free_mock_connection(conn);
    }
    cleanup_mock_domain();
}

TEST(test_httprequestparser_memory_body_errors) {
    TEST_SUITE("HTTP Request Parser - body errors and cleanup");
    setup_mock_domain();
    char* old_tmp = env()->main.tmp;
    size_t old_limit = env()->main.client_max_body_size;
    char buffer[256];
    for (int large = 0; large < 2; ++large) {
        env()->main.tmp = "/cwfr-nonexistent-temp-directory";
        env()->main.client_max_body_size = large ? 2 * BODY_STORE_DEFAULT_FILE_THRESHOLD : 5;
        int n = snprintf(buffer, sizeof(buffer), "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: %zu\r\n\r\na", large ? BODY_STORE_DEFAULT_FILE_THRESHOLD : (size_t)6);
        connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
        httprequestparser_t* parser = httpparser_create(conn);
        httpparser_set_bytes_readed(parser, (size_t)n);
        TEST_ASSERT_EQUAL(large ? HTTP1PARSER_ERROR : HTTP1PARSER_BAD_REQUEST, httpparser_run(parser), "large temp error or maximum rejected");
        TEST_ASSERT_NULL(parser->request, "failed request retired");
        TEST_ASSERT_NULL(((httprequest_t*)mock_server_ctx.request_cache)->payload_.incoming.data, "failed request releases buffer");
        TEST_ASSERT_NULL(((httprequest_t*)mock_server_ctx.request_cache)->payload_.incoming.path, "failed request releases path");
        httpparser_free(parser);
        free_mock_connection(conn);
    }
    env()->main.tmp = old_tmp;
    env()->main.client_max_body_size = old_limit;
    cleanup_mock_domain();
}

TEST(test_httprequestparser_lazy_plain_file) {
    TEST_SUITE("HTTP Request Parser - explicit file API");
    setup_mock_domain();
    char buffer[] = "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"value\":42}";
    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    httpparser_set_bytes_readed(parser, strlen(buffer));
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, httpparser_run(parser), "request complete");
    httprequest_t* request = parser->request;
    TEST_ASSERT_EQUAL(-1, request->payload_.file.fd, "no file before explicit request");
    file_content_t file = request->get_payload_file(request);
    TEST_ASSERT(file.ok, "file materialized on request");
    TEST_ASSERT_EQUAL(12, file.size, "whole body size");
    TEST_ASSERT_EQUAL(0, file.offset, "whole body offset");
    TEST_ASSERT_NULL(request->payload_.incoming.data, "materialization releases memory");
    file_content_t again = request->get_payload_filef(request, NULL);
    TEST_ASSERT(again.ok, "repeat file access");
    TEST_ASSERT_EQUAL(file.fd, again.fd, "same owned file");
    char* copy = request->get_payload(request);
    TEST_ASSERT_NOT_NULL(copy, "text after materialization");
    if (copy) TEST_ASSERT_STR_EQUAL("{\"value\":42}", copy, "same bytes");
    free(copy);
    json_doc_t* json = request->get_payload_json(request);
    TEST_ASSERT_NOT_NULL(json, "JSON after materialization");
    if (json) {
        TEST_ASSERT_EQUAL(42, json_int(json_object_get(json_root(json), "value"), NULL), "same JSON");
        json_free(json);
    }
    httpparser_free(parser);
    TEST_ASSERT_EQUAL(-1, fcntl(file.fd, F_GETFD), "file owned by request");
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequestparser_aborted_body_storage) {
    TEST_SUITE("HTTP Request Parser - aborted body storage");
    setup_mock_domain();
    char buffer[256];
    for (int large = 0; large < 2; ++large) {
        int n = snprintf(buffer, sizeof(buffer), "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: %zu\r\n\r\na",
            large ? BODY_STORE_DEFAULT_FILE_THRESHOLD : (size_t)12);
        connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
        httprequestparser_t* parser = httpparser_create(conn);
        httpparser_set_bytes_readed(parser, (size_t)n);
        TEST_ASSERT_EQUAL(HTTP1PARSER_CONTINUE, httpparser_run(parser), "partial body cannot dispatch");
        body_store_t* incoming = &parser->request->payload_.incoming;
        TEST_ASSERT_EQUAL(1, incoming->size, "partial byte received");
        int fd = incoming->fd;
        char* path = incoming->path ? strdup(incoming->path) : NULL;
        httpparser_free(parser);
        httprequest_t* retired = mock_server_ctx.request_cache;
        TEST_ASSERT_NULL(retired->payload_.incoming.data, "disconnect frees buffer");
        TEST_ASSERT_NULL(retired->payload_.incoming.path, "disconnect frees path");
        TEST_ASSERT_EQUAL(BODY_STORE_EMPTY, retired->payload_.incoming.state, "disconnect clears storage");
        if (fd >= 0) TEST_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD), "disconnect closes fd");
        if (path) TEST_ASSERT_EQUAL(-1, access(path, F_OK), "disconnect removes file");
        free(path);
        free_mock_connection(conn);
    }
    cleanup_mock_domain();
}

TEST(test_httprequestparser_memory_forms_without_tmp) {
    TEST_SUITE("HTTP Request Parser - forms without file I/O");
    setup_mock_domain();
    char* old_tmp = env()->main.tmp;
    env()->main.tmp = "/cwfr-nonexistent-temp-directory";
    const char* bodies[] = {"name=John+Doe&bytes=%00%FF&empty=",
        "--test\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nJohn Doe\r\n--test\r\nContent-Disposition: form-data; name=\"empty\"\r\n\r\n\r\n--test--\r\n"};
    const char* types[] = {"application/x-www-form-urlencoded", "multipart/form-data; boundary=test"};
    char buffer[1024];
    for (int i = 0; i < 2; ++i) {
        int n = snprintf(buffer, sizeof(buffer), "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n%s", types[i], strlen(bodies[i]), bodies[i]);
        connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
        httprequestparser_t* parser = httpparser_create(conn);
        httpparser_set_bytes_readed(parser, (size_t)n);
        TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, httpparser_run(parser), "form received without temp directory");
        char* value = parser->request->get_payloadf(parser->request, "name");
        TEST_ASSERT_NOT_NULL(value, "decoded name");
        if (value) TEST_ASSERT_STR_EQUAL("John Doe", value, "name bytes");
        free(value);
        value = parser->request->get_payloadf(parser->request, "empty");
        TEST_ASSERT_NOT_NULL(value, "empty field present");
        if (value) TEST_ASSERT_STR_EQUAL("", value, "empty field value");
        free(value);
        if (i == 0) {
            value = parser->request->get_payloadf(parser->request, "bytes");
            TEST_ASSERT_NOT_NULL(value, "binary decoded field");
            if (value) {
                TEST_ASSERT_EQUAL(0, value[0], "decoded NUL");
                TEST_ASSERT_EQUAL(255, (unsigned char)value[1], "decoded byte");
            }
            free(value);
        }
        TEST_ASSERT_EQUAL(BODY_STORE_MEMORY, parser->request->payload_.incoming.state, "form stays memory-backed");
        TEST_ASSERT_EQUAL(-1, parser->request->payload_.file.fd, "no legacy fd");
        TEST_ASSERT_EQUAL(-1, parser->request->payload_.incoming.fd, "no store fd");
        httpparser_free(parser);
        free_mock_connection(conn);
    }
    env()->main.tmp = old_tmp;
    cleanup_mock_domain();
}

TEST(test_httprequestparser_memory_multipart_file) {
    TEST_SUITE("HTTP Request Parser - multipart offsets and materialization");
    setup_mock_domain();
    const char body[] = "--test\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\njohn\r\n"
        "--test\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"data.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        "a\0bc\r\n--test--\r\n";
    char buffer[1024];
    int header = snprintf(buffer, sizeof(buffer), "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=test\r\nContent-Length: %zu\r\n\r\n", sizeof(body) - 1);
    memcpy(buffer + header, body, sizeof(body) - 1);
    connection_t* conn = create_mock_connection(buffer, sizeof(buffer));
    httprequestparser_t* parser = httpparser_create(conn);
    httpparser_set_bytes_readed(parser, (size_t)header + sizeof(body) - 1);
    TEST_ASSERT_EQUAL(HTTP1PARSER_COMPLETE, httpparser_run(parser), "binary multipart received");
    httprequest_t* request = parser->request;
    char* data = request->get_payloadf(request, "upload");
    TEST_ASSERT_NOT_NULL(data, "file part in memory");
    if (data) TEST_ASSERT(memcmp(data, "a\0bc", 4) == 0, "binary bytes before materialization");
    free(data);
    TEST_ASSERT_EQUAL(BODY_STORE_MEMORY, request->payload_.incoming.state, "ordinary file part read stays in memory");
    file_content_t file = request->get_payload_filef(request, "upload");
    TEST_ASSERT(file.ok, "explicit file part materialized");
    TEST_ASSERT_EQUAL(4, file.size, "part length excludes framing");
    TEST_ASSERT_STR_EQUAL("data.bin", file.filename, "part filename");
    char bytes[4];
    TEST_ASSERT_EQUAL(4, pread(file.fd, bytes, sizeof(bytes), file.offset), "part range accessible");
    TEST_ASSERT(memcmp(bytes, "a\0bc", 4) == 0, "part offset preserved");
    file_content_t again = request->get_payload_filef(request, "upload");
    TEST_ASSERT_EQUAL(file.fd, again.fd, "repeat materialization uses same file");
    data = request->get_payloadf(request, "upload");
    TEST_ASSERT_NOT_NULL(data, "part after materialization");
    if (data) TEST_ASSERT(memcmp(data, "a\0bc", 4) == 0, "binary bytes after materialization");
    free(data);
    data = request->get_payloadf(request, "name");
    TEST_ASSERT_NOT_NULL(data, "other part after materialization");
    if (data) TEST_ASSERT_STR_EQUAL("john", data, "other part offset preserved");
    free(data);
    httpparser_free(parser);
    TEST_ASSERT_EQUAL(-1, fcntl(file.fd, F_GETFD), "materialized file freed");
    free_mock_connection(conn);
    cleanup_mock_domain();
}

TEST(test_httprequest_memory_form_thresholds) {
    TEST_SUITE("HTTP forms - ranges across parser blocks and file threshold");
    const char* prefixes[] = {"name=", "--test\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n"};
    const char* suffixes[] = {"&empty=", "\r\n--test--\r\n"};
    const char* types[] = {"application/x-www-form-urlencoded", "multipart/form-data; boundary=test"};
    const size_t sizes[] = {20480, BODY_STORE_DEFAULT_FILE_THRESHOLD - 1, BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_DEFAULT_FILE_THRESHOLD + 1};
    for (int kind = 0; kind < 2; ++kind) {
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
            char label[96];
            snprintf(label, sizeof(label), "%s body of %zu bytes", kind ? "multipart" : "URL-encoded", sizes[i]);
            TEST_CASE(label);
            size_t prefix = strlen(prefixes[kind]), suffix = strlen(suffixes[kind]);
            size_t length = sizes[i] - prefix - suffix;
            char* body = malloc(sizes[i]);
            TEST_REQUIRE_NOT_NULL(body, "form fixture");
            memcpy(body, prefixes[kind], prefix);
            memset(body + prefix, 'x', length);
            memcpy(body + prefix + length, suffixes[kind], suffix);
            httprequest_t* request = httprequest_create(NULL);
            TEST_REQUIRE_NOT_NULL(request, "request");
            request->method = ROUTE_POST;
            request->add_header(request, "Content-Type", types[kind]);
            TEST_ASSERT(body_store_prepare(&request->payload_.incoming, sizes[i], "/tmp"), "reserve form");
            TEST_ASSERT(body_store_append(&request->payload_.incoming, body, sizes[i], "/tmp"), "store form");
            free(body);
            char* value = request->get_payloadf(request, "name");
            TEST_ASSERT_NOT_NULL(value, "field spans parser blocks");
            if (value) {
                TEST_ASSERT_EQUAL(length, strlen(value), "full field length");
                TEST_ASSERT_EQUAL('x', value[0], "field first byte");
                TEST_ASSERT_EQUAL('x', value[length - 1], "field last byte");
            }
            free(value);
            TEST_ASSERT_EQUAL(sizes[i] < BODY_STORE_DEFAULT_FILE_THRESHOLD ? BODY_STORE_MEMORY : BODY_STORE_FILE,
                request->payload_.incoming.state, "form parsing preserves chosen storage");
            TEST_ASSERT_EQUAL(-1, request->payload_.file.fd, "no legacy materialization while reading");
            TEST_ASSERT(httprequest_create_payload_file(&request->payload_), "explicit materialization");
            value = request->get_payloadf(request, "name");
            TEST_ASSERT_NOT_NULL(value, "same field after materialization");
            if (value) TEST_ASSERT_EQUAL(length, strlen(value), "field length preserved");
            free(value);
            httprequest_free(request);
        }
    }
}

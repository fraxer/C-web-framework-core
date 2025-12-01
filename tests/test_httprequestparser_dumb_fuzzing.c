#include "framework.h"
#include "httprequestparser.h"
#include "httpparsercommon.h"
#include "httprequest.h"
#include "connection_s.h"
#include "appconfig.h"
#include "cqueue.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

// ============================================================================
// Mock Configuration and Dependencies
// ============================================================================

extern appconfig_t* appconfig(void);
extern env_t* env(void);

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

// ============================================================================
// Helper Functions for Fuzzing
// ============================================================================

// Simple PRNG for deterministic fuzzing
static unsigned int fuzz_seed = 0;

static void fuzz_seed_init(unsigned int seed) {
    fuzz_seed = seed;
}

static unsigned int fuzz_rand(void) {
    fuzz_seed = fuzz_seed * 1103515245 + 12345;
    return (fuzz_seed / 65536) % 32768;
}

// Fill buffer with random bytes
static void fill_random_bytes(char* buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (char)(fuzz_rand() % 256);
    }
}

// Mock listener and queue
__attribute__((unused))
static cqueue_item_t mock_queue_item = {
    .data = &mock_server,
    .next = NULL
};

static listener_t mock_listener = {
    .servers = {.item = NULL, .last_item = NULL, .size = 0, .locked = 0},
    .connection = NULL,
    .api = NULL,
    .next = NULL
};

// Mock server context
static connection_server_ctx_t mock_server_ctx = {
    .listener = &mock_listener,
    .parser = NULL,
    .server = NULL,
    .response = NULL,
    .queue = NULL,
    .broadcast_queue = NULL
};

// Setup parser with fuzzing data
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-use-of-uninitialized-value"
static httprequestparser_t* setup_parser_with_data(const char* data, size_t data_len) {
    connection_t* conn = calloc(1, sizeof(connection_t));
    if (!conn) return NULL;

    conn->buffer = calloc(1, data_len + 1);
    if (!conn->buffer) {
        free(conn);
        return NULL;
    }

    memcpy(conn->buffer, data, data_len);
    conn->buffer_size = data_len;
    conn->ip = 0x0100007F;  // 127.0.0.1
    conn->port = 8080;
    conn->ssl = NULL;
    conn->ctx = (connection_ctx_t*)&mock_server_ctx;
    conn->keepalive = 0;

    httprequestparser_t* parser = httpparser_create(conn);
    if (!parser) {
        free(conn->buffer);
        free(conn);
        return NULL;
    }

    httpparser_set_bytes_readed(parser, data_len);
    return parser;
}
#pragma GCC diagnostic pop

// Cleanup parser and connection
static void cleanup_parser(httprequestparser_t* parser) {
    if (!parser) return;

    connection_t* conn = parser->connection;
    httpparser_free(parser);

    if (conn) {
        if (conn->buffer) free(conn->buffer);
        free(conn);
    }
}

// ============================================================================
// Dumb Fuzzing Tests - Completely Random Data
// ============================================================================

TEST(test_dumb_fuzzing_tiny_random_inputs) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Tiny random inputs (1-16 bytes)");

    fuzz_seed_init(12345);
    int crashes = 0;
    int iterations = 100;

    for (int i = 0; i < iterations; i++) {
        size_t size = 1 + (fuzz_rand() % 16);
        char* buffer = malloc(size);
        if (!buffer) continue;

        fill_random_bytes(buffer, size);

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            // Just run the parser - we expect it not to crash
            int result = httpparser_run(parser);
            (void)result; // Result doesn't matter, we just check for crashes
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on tiny random inputs");
}

TEST(test_dumb_fuzzing_small_random_inputs) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Small random inputs (16-256 bytes)");

    fuzz_seed_init(23456);
    int crashes = 0;
    int iterations = 100;

    for (int i = 0; i < iterations; i++) {
        size_t size = 16 + (fuzz_rand() % 240);
        char* buffer = malloc(size);
        if (!buffer) continue;

        fill_random_bytes(buffer, size);

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on small random inputs");
}

TEST(test_dumb_fuzzing_medium_random_inputs) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Medium random inputs (256-4096 bytes)");

    fuzz_seed_init(34567);
    int crashes = 0;
    int iterations = 50;

    for (int i = 0; i < iterations; i++) {
        size_t size = 256 + (fuzz_rand() % 3840);
        char* buffer = malloc(size);
        if (!buffer) continue;

        fill_random_bytes(buffer, size);

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on medium random inputs");
}

TEST(test_dumb_fuzzing_large_random_inputs) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Large random inputs (4KB-64KB)");

    fuzz_seed_init(45678);
    int crashes = 0;
    int iterations = 20;

    for (int i = 0; i < iterations; i++) {
        size_t size = 4096 + (fuzz_rand() % (65536 - 4096));
        char* buffer = malloc(size);
        if (!buffer) continue;

        fill_random_bytes(buffer, size);

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on large random inputs");
}

TEST(test_dumb_fuzzing_null_bytes) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Random inputs with embedded null bytes");

    fuzz_seed_init(56789);
    int crashes = 0;
    int iterations = 100;

    for (int i = 0; i < iterations; i++) {
        size_t size = 32 + (fuzz_rand() % 224);
        char* buffer = malloc(size);
        if (!buffer) continue;

        fill_random_bytes(buffer, size);

        // Randomly insert null bytes
        for (size_t j = 0; j < size / 10; j++) {
            size_t pos = fuzz_rand() % size;
            buffer[pos] = '\0';
        }

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on inputs with null bytes");
}

TEST(test_dumb_fuzzing_repeated_bytes) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Inputs with repeated byte patterns");

    fuzz_seed_init(67890);
    int crashes = 0;
    int iterations = 50;

    unsigned char repeat_bytes[] = {0x00, 0xFF, 0x0A, 0x0D, 0x20, 0x7F, 'A', 'Z', '0', '9'};

    for (int i = 0; i < iterations; i++) {
        size_t size = 64 + (fuzz_rand() % 448);
        char* buffer = malloc(size);
        if (!buffer) continue;

        char repeat_byte = repeat_bytes[fuzz_rand() % (sizeof(repeat_bytes))];
        memset(buffer, repeat_byte, size);

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on repeated byte patterns");
}

TEST(test_dumb_fuzzing_high_ascii) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Random high-ASCII and non-ASCII bytes");

    fuzz_seed_init(78901);
    int crashes = 0;
    int iterations = 100;

    for (int i = 0; i < iterations; i++) {
        size_t size = 32 + (fuzz_rand() % 224);
        char* buffer = malloc(size);
        if (!buffer) continue;

        // Fill with high-ASCII bytes (128-255)
        for (size_t j = 0; j < size; j++) {
            buffer[j] = (char)(128 + (fuzz_rand() % 128));
        }

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on high-ASCII bytes");
}

TEST(test_dumb_fuzzing_control_characters) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Random control characters (0x00-0x1F)");

    fuzz_seed_init(89012);
    int crashes = 0;
    int iterations = 100;

    for (int i = 0; i < iterations; i++) {
        size_t size = 32 + (fuzz_rand() % 224);
        char* buffer = malloc(size);
        if (!buffer) continue;

        // Fill with control characters
        for (size_t j = 0; j < size; j++) {
            buffer[j] = (char)(fuzz_rand() % 32);
        }

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on control characters");
}

TEST(test_dumb_fuzzing_alternating_patterns) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Alternating byte patterns");

    fuzz_seed_init(90123);
    int crashes = 0;
    int iterations = 50;

    for (int i = 0; i < iterations; i++) {
        size_t size = 64 + (fuzz_rand() % 448);
        char* buffer = malloc(size);
        if (!buffer) continue;

        // Create alternating patterns
        char byte1 = (char)(fuzz_rand() % 256);
        char byte2 = (char)(fuzz_rand() % 256);
        for (size_t j = 0; j < size; j++) {
            buffer[j] = (j % 2 == 0) ? byte1 : byte2;
        }

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on alternating patterns");
}

TEST(test_dumb_fuzzing_edge_case_lengths) {
    TEST_SUITE("HTTP Parser Dumb Fuzzing");
    TEST_CASE("Edge case input lengths");

    fuzz_seed_init(11111);
    int crashes = 0;

    // Test various edge case lengths
    size_t edge_lengths[] = {0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
                             511, 512, 1023, 1024, 2047, 2048, 4095, 4096, 8191, 8192};

    for (size_t i = 0; i < sizeof(edge_lengths) / sizeof(edge_lengths[0]); i++) {
        size_t size = edge_lengths[i];
        if (size == 0) {
            // Test empty input
            httprequestparser_t* parser = setup_parser_with_data("", 0);
            if (parser) {
                int result = httpparser_run(parser);
                (void)result;
                cleanup_parser(parser);
            }
            continue;
        }

        char* buffer = malloc(size);
        if (!buffer) continue;

        fill_random_bytes(buffer, size);

        httprequestparser_t* parser = setup_parser_with_data(buffer, size);
        if (parser) {
            int result = httpparser_run(parser);
            (void)result;
            cleanup_parser(parser);
        }

        free(buffer);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on edge case lengths");
}

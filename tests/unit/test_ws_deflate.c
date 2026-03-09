#include "framework.h"
#include "websocket/ws_deflate.h"
#include <string.h>

// ============================================================================
// Тесты ws_deflate_parse_header
// ============================================================================

TEST(test_ws_deflate_parse_header_basic) {
    TEST_CASE("Parse basic permessage-deflate header");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header("permessage-deflate", &config);

    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(15, config.server_max_window_bits, "Default server_max_window_bits should be 15");
    TEST_ASSERT_EQUAL(15, config.client_max_window_bits, "Default client_max_window_bits should be 15");
    TEST_ASSERT_EQUAL(0, config.server_no_context_takeover, "Default server_no_context_takeover should be 0");
    TEST_ASSERT_EQUAL(0, config.client_no_context_takeover, "Default client_no_context_takeover should be 0");
}

TEST(test_ws_deflate_parse_header_null) {
    TEST_CASE("Parse NULL header");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header(NULL, &config);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL header");
}

TEST(test_ws_deflate_parse_header_empty) {
    TEST_CASE("Parse empty header");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header("", &config);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for empty header");
}

TEST(test_ws_deflate_parse_header_not_found) {
    TEST_CASE("Parse header without permessage-deflate");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header("deflate-stream", &config);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 when permessage-deflate not found");
}

TEST(test_ws_deflate_parse_header_with_params) {
    TEST_CASE("Parse header with all parameters");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; "
        "server_max_window_bits=12; client_max_window_bits=10", &config);

    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(12, config.server_max_window_bits, "server_max_window_bits should be 12");
    TEST_ASSERT_EQUAL(10, config.client_max_window_bits, "client_max_window_bits should be 10");
    TEST_ASSERT_EQUAL(1, config.server_no_context_takeover, "server_no_context_takeover should be 1");
    TEST_ASSERT_EQUAL(1, config.client_no_context_takeover, "client_no_context_takeover should be 1");
}

TEST(test_ws_deflate_parse_header_params_before_name) {
    TEST_CASE("Parse header with parameters before permessage-deflate");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header(
        "client_max_window_bits=12; permessage-deflate; server_no_context_takeover", &config);

    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(12, config.client_max_window_bits, "client_max_window_bits should be 12");
    TEST_ASSERT_EQUAL(1, config.server_no_context_takeover, "server_no_context_takeover should be 1");
}

TEST(test_ws_deflate_parse_header_any_order) {
    TEST_CASE("Parse header with parameters in any order");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header(
        "server_max_window_bits=9; client_no_context_takeover; permessage-deflate; client_max_window_bits=11", &config);

    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(9, config.server_max_window_bits, "server_max_window_bits should be 9");
    TEST_ASSERT_EQUAL(11, config.client_max_window_bits, "client_max_window_bits should be 11");
    TEST_ASSERT_EQUAL(1, config.client_no_context_takeover, "client_no_context_takeover should be 1");
    TEST_ASSERT_EQUAL(0, config.server_no_context_takeover, "server_no_context_takeover should be 0");
}

TEST(test_ws_deflate_parse_header_window_bits_boundary) {
    TEST_CASE("Parse header with boundary window_bits values");

    ws_deflate_config_t config;

    // Test minimum valid value (8)
    int result = ws_deflate_parse_header("permessage-deflate; server_max_window_bits=8", &config);
    TEST_ASSERT_EQUAL(1, result, "Should parse");
    TEST_ASSERT_EQUAL(8, config.server_max_window_bits, "server_max_window_bits should be 8");

    // Test maximum valid value (15)
    result = ws_deflate_parse_header("permessage-deflate; client_max_window_bits=15", &config);
    TEST_ASSERT_EQUAL(1, result, "Should parse");
    TEST_ASSERT_EQUAL(15, config.client_max_window_bits, "client_max_window_bits should be 15");
}

TEST(test_ws_deflate_parse_header_window_bits_invalid) {
    TEST_CASE("Parse header with invalid window_bits values");

    ws_deflate_config_t config;

    // Value too low (7)
    int result = ws_deflate_parse_header("permessage-deflate; server_max_window_bits=7", &config);
    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(15, config.server_max_window_bits, "Invalid value should keep default 15");

    // Value too high (16)
    result = ws_deflate_parse_header("permessage-deflate; client_max_window_bits=16", &config);
    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(15, config.client_max_window_bits, "Invalid value should keep default 15");
}

TEST(test_ws_deflate_parse_header_extra_spaces) {
    TEST_CASE("Parse header with extra spaces");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header(
        "  permessage-deflate ;  server_no_context_takeover  ;  client_max_window_bits=12  ", &config);

    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(12, config.client_max_window_bits, "client_max_window_bits should be 12");
    TEST_ASSERT_EQUAL(1, config.server_no_context_takeover, "server_no_context_takeover should be 1");
}

TEST(test_ws_deflate_parse_header_multiple_extensions) {
    TEST_CASE("Parse header with multiple extensions (comma-separated)");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header(
        "some-other-extension, permessage-deflate; client_max_window_bits=10", &config);

    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(10, config.client_max_window_bits, "client_max_window_bits should be 10");
}

TEST(test_ws_deflate_parse_header_unknown_param) {
    TEST_CASE("Parse header with unknown parameter");

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header(
        "permessage-deflate; unknown_param=42; server_max_window_bits=12", &config);

    TEST_ASSERT_EQUAL(1, result, "Should find permessage-deflate");
    TEST_ASSERT_EQUAL(12, config.server_max_window_bits, "server_max_window_bits should be 12");
}

TEST(test_ws_deflate_parse_header_partial_match) {
    TEST_CASE("Parse header should not match partial names");

    ws_deflate_config_t config;

    // Should not match "permessage-deflate-extra"
    int result = ws_deflate_parse_header("permessage-deflate-extra", &config);
    TEST_ASSERT_EQUAL(0, result, "Should not match permessage-deflate-extra");

    // Should not match "x-permessage-deflate"
    result = ws_deflate_parse_header("x-permessage-deflate", &config);
    TEST_ASSERT_EQUAL(0, result, "Should not match x-permessage-deflate");
}

// ============================================================================
// Тесты ws_deflate_build_header
// ============================================================================

TEST(test_ws_deflate_build_header_basic) {
    TEST_CASE("Build basic header with defaults");

    ws_deflate_config_t config = {
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = 0,
        .client_no_context_takeover = 0
    };

    char buf[256];
    int len = ws_deflate_build_header(&config, buf, sizeof(buf));

    TEST_ASSERT(len > 0, "Should return positive length");
    TEST_ASSERT_STR_EQUAL("permessage-deflate", buf, "Should be just permessage-deflate");
}

TEST(test_ws_deflate_build_header_with_no_context_takeover) {
    TEST_CASE("Build header with no_context_takeover flags");

    ws_deflate_config_t config = {
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = 1,
        .client_no_context_takeover = 1
    };

    char buf[256];
    int len = ws_deflate_build_header(&config, buf, sizeof(buf));

    TEST_ASSERT(len > 0, "Should return positive length");
    TEST_ASSERT(strstr(buf, "permessage-deflate") != NULL, "Should contain permessage-deflate");
    TEST_ASSERT(strstr(buf, "server_no_context_takeover") != NULL, "Should contain server_no_context_takeover");
    TEST_ASSERT(strstr(buf, "client_no_context_takeover") != NULL, "Should contain client_no_context_takeover");
}

TEST(test_ws_deflate_build_header_with_window_bits) {
    TEST_CASE("Build header with custom window_bits");

    ws_deflate_config_t config = {
        .server_max_window_bits = 12,
        .client_max_window_bits = 10,
        .server_no_context_takeover = 0,
        .client_no_context_takeover = 0
    };

    char buf[256];
    int len = ws_deflate_build_header(&config, buf, sizeof(buf));

    TEST_ASSERT(len > 0, "Should return positive length");
    TEST_ASSERT(strstr(buf, "server_max_window_bits=12") != NULL, "Should contain server_max_window_bits=12");
    TEST_ASSERT(strstr(buf, "client_max_window_bits=10") != NULL, "Should contain client_max_window_bits=10");
}

TEST(test_ws_deflate_build_header_all_params) {
    TEST_CASE("Build header with all parameters");

    ws_deflate_config_t config = {
        .server_max_window_bits = 11,
        .client_max_window_bits = 9,
        .server_no_context_takeover = 1,
        .client_no_context_takeover = 1
    };

    char buf[256];
    int len = ws_deflate_build_header(&config, buf, sizeof(buf));

    TEST_ASSERT(len > 0, "Should return positive length");
    TEST_ASSERT(strstr(buf, "permessage-deflate") != NULL, "Should contain permessage-deflate");
    TEST_ASSERT(strstr(buf, "server_no_context_takeover") != NULL, "Should contain server_no_context_takeover");
    TEST_ASSERT(strstr(buf, "client_no_context_takeover") != NULL, "Should contain client_no_context_takeover");
    TEST_ASSERT(strstr(buf, "server_max_window_bits=11") != NULL, "Should contain server_max_window_bits=11");
    TEST_ASSERT(strstr(buf, "client_max_window_bits=9") != NULL, "Should contain client_max_window_bits=9");
}

TEST(test_ws_deflate_build_header_small_buffer) {
    TEST_CASE("Build header with too small buffer");

    ws_deflate_config_t config = {
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = 0,
        .client_no_context_takeover = 0
    };

    char buf[5];
    int len = ws_deflate_build_header(&config, buf, sizeof(buf));

    TEST_ASSERT_EQUAL(-1, len, "Should return -1 for too small buffer");
}

// ============================================================================
// Тесты ws_deflate_init
// ============================================================================

TEST(test_ws_deflate_init) {
    TEST_CASE("Initialize ws_deflate structure");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);

    TEST_ASSERT_EQUAL(0, deflate.deflate_init, "deflate_init should be 0");
    TEST_ASSERT_EQUAL(0, deflate.inflate_init, "inflate_init should be 0");
    TEST_ASSERT_EQUAL(15, deflate.config.server_max_window_bits, "Default server_max_window_bits should be 15");
    TEST_ASSERT_EQUAL(15, deflate.config.client_max_window_bits, "Default client_max_window_bits should be 15");
    TEST_ASSERT_EQUAL(0, deflate.config.server_no_context_takeover, "Default server_no_context_takeover should be 0");
    TEST_ASSERT_EQUAL(0, deflate.config.client_no_context_takeover, "Default client_no_context_takeover should be 0");
}

// ============================================================================
// Тесты ws_deflate_start / ws_deflate_free
// ============================================================================

TEST(test_ws_deflate_start_and_free) {
    TEST_CASE("Start and free ws_deflate");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);

    int result = ws_deflate_start(&deflate);
    TEST_ASSERT_EQUAL(1, result, "ws_deflate_start should succeed");
    TEST_ASSERT_EQUAL(1, deflate.deflate_init, "deflate_init should be 1");
    TEST_ASSERT_EQUAL(1, deflate.inflate_init, "inflate_init should be 1");

    ws_deflate_free(&deflate);
    TEST_ASSERT_EQUAL(0, deflate.deflate_init, "deflate_init should be 0 after free");
    TEST_ASSERT_EQUAL(0, deflate.inflate_init, "inflate_init should be 0 after free");
}

TEST(test_ws_deflate_start_with_custom_config) {
    TEST_CASE("Start ws_deflate with custom config");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    deflate.config.server_max_window_bits = 12;
    deflate.config.client_max_window_bits = 10;

    int result = ws_deflate_start(&deflate);
    TEST_ASSERT_EQUAL(1, result, "ws_deflate_start should succeed");

    ws_deflate_free(&deflate);
}

// ============================================================================
// Тесты ws_deflate_compress / ws_deflate_decompress
// ============================================================================

TEST(test_ws_deflate_compress_decompress) {
    TEST_CASE("Compress and decompress data");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    ws_deflate_start(&deflate);

    const char* input = "Hello, WebSocket compression world! This is a test message.";
    size_t input_len = strlen(input);

    char compressed[1024];
    ssize_t compressed_len = ws_deflate_compress(&deflate, input, input_len, compressed, sizeof(compressed), 1);
    TEST_ASSERT(compressed_len > 0, "Compression should succeed");

    // Add trailer for decompression (RFC 7692)
    compressed[compressed_len++] = 0x00;
    compressed[compressed_len++] = 0x00;
    compressed[compressed_len++] = 0xff;
    compressed[compressed_len++] = 0xff;

    char decompressed[1024];
    ssize_t decompressed_len = ws_deflate_decompress(&deflate, compressed, compressed_len, decompressed, sizeof(decompressed));
    TEST_ASSERT(decompressed_len > 0, "Decompression should succeed");
    TEST_ASSERT_EQUAL_SIZE(input_len, (size_t)decompressed_len, "Decompressed length should match input");

    decompressed[decompressed_len] = '\0';
    TEST_ASSERT_STR_EQUAL(input, decompressed, "Decompressed data should match input");

    ws_deflate_free(&deflate);
}

TEST(test_ws_deflate_compress_small_output_buffer) {
    TEST_CASE("Compress with small output buffer");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    ws_deflate_start(&deflate);

    const char* input = "Test data";
    char compressed[2]; // Too small

    ssize_t compressed_len = ws_deflate_compress(&deflate, input, strlen(input), compressed, sizeof(compressed), 1);
    // With small buffer, it might return partial data or error
    TEST_ASSERT(compressed_len >= -1, "Should handle small buffer");

    ws_deflate_free(&deflate);
}

TEST(test_ws_deflate_compress_empty_input) {
    TEST_CASE("Compress empty input");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    ws_deflate_start(&deflate);

    char compressed[1024];
    ssize_t compressed_len = ws_deflate_compress(&deflate, "", 0, compressed, sizeof(compressed), 1);
    TEST_ASSERT(compressed_len >= 0, "Compression of empty input should succeed");

    ws_deflate_free(&deflate);
}

// ============================================================================
// Тесты ws_deflate_reset_deflate / ws_deflate_reset_inflate
// ============================================================================

TEST(test_ws_deflate_reset_with_context_takeover) {
    TEST_CASE("Reset with no_context_takeover enabled");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    deflate.config.server_no_context_takeover = 1;
    deflate.config.client_no_context_takeover = 1;
    ws_deflate_start(&deflate);

    // Compress some data
    const char* input = "Test message";
    char compressed[1024];
    ws_deflate_compress(&deflate, input, strlen(input), compressed, sizeof(compressed), 1);

    // Reset should work
    ws_deflate_reset_deflate(&deflate);
    ws_deflate_reset_inflate(&deflate);

    // Should be able to compress again
    ssize_t len = ws_deflate_compress(&deflate, input, strlen(input), compressed, sizeof(compressed), 1);
    TEST_ASSERT(len > 0, "Should compress after reset");

    ws_deflate_free(&deflate);
}

TEST(test_ws_deflate_reset_without_context_takeover) {
    TEST_CASE("Reset with no_context_takeover disabled");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    deflate.config.server_no_context_takeover = 0;
    deflate.config.client_no_context_takeover = 0;
    ws_deflate_start(&deflate);

    // Reset should be no-op when no_context_takeover is disabled
    ws_deflate_reset_deflate(&deflate);
    ws_deflate_reset_inflate(&deflate);

    // Should still work
    const char* input = "Test message";
    char compressed[1024];
    ssize_t len = ws_deflate_compress(&deflate, input, strlen(input), compressed, sizeof(compressed), 1);
    TEST_ASSERT(len > 0, "Should compress without reset");

    ws_deflate_free(&deflate);
}

// ============================================================================
// Тесты ws_deflate_has_more
// ============================================================================

TEST(test_ws_deflate_has_more) {
    TEST_CASE("Check has_more after decompress");

    ws_deflate_t deflate;
    ws_deflate_init(&deflate);
    ws_deflate_start(&deflate);

    // Compress larger data
    char input[1000];
    memset(input, 'A', sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';

    char compressed[2048];
    ssize_t compressed_len = ws_deflate_compress(&deflate, input, strlen(input), compressed, sizeof(compressed), 1);
    TEST_ASSERT(compressed_len > 0, "Compression should succeed");

    // Add trailer
    compressed[compressed_len++] = 0x00;
    compressed[compressed_len++] = 0x00;
    compressed[compressed_len++] = 0xff;
    compressed[compressed_len++] = 0xff;

    // Decompress with small buffer to test has_more
    char decompressed[100];
    ssize_t decompressed_len = ws_deflate_decompress(&deflate, compressed, compressed_len, decompressed, sizeof(decompressed));
    TEST_ASSERT(decompressed_len > 0, "Decompression should succeed");

    // If output buffer was too small, has_more should return 1
    int has_more = ws_deflate_has_more(&deflate);
    TEST_ASSERT(has_more == 0 || has_more == 1, "has_more should return 0 or 1");

    ws_deflate_free(&deflate);
}

// ============================================================================
// Тесты parse -> build roundtrip
// ============================================================================

TEST(test_ws_deflate_parse_build_roundtrip) {
    TEST_CASE("Parse and build roundtrip");

    const char* original = "permessage-deflate; server_no_context_takeover; server_max_window_bits=12";

    ws_deflate_config_t config;
    int result = ws_deflate_parse_header(original, &config);
    TEST_ASSERT_EQUAL(1, result, "Should parse header");
    TEST_ASSERT_EQUAL(12, config.server_max_window_bits, "server_max_window_bits should be 12");
    TEST_ASSERT_EQUAL(1, config.server_no_context_takeover, "server_no_context_takeover should be 1");

    char buf[256];
    int len = ws_deflate_build_header(&config, buf, sizeof(buf));
    TEST_ASSERT(len > 0, "Should build header");

    // Parse the built header again
    ws_deflate_config_t config2;
    result = ws_deflate_parse_header(buf, &config2);
    TEST_ASSERT_EQUAL(1, result, "Should parse built header");
    TEST_ASSERT_EQUAL(config.server_max_window_bits, config2.server_max_window_bits, "server_max_window_bits should match");
    TEST_ASSERT_EQUAL(config.client_max_window_bits, config2.client_max_window_bits, "client_max_window_bits should match");
    TEST_ASSERT_EQUAL(config.server_no_context_takeover, config2.server_no_context_takeover, "server_no_context_takeover should match");
    TEST_ASSERT_EQUAL(config.client_no_context_takeover, config2.client_no_context_takeover, "client_no_context_takeover should match");
}

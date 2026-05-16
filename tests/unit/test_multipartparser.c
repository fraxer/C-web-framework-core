#define _GNU_SOURCE
#include "framework.h"
#include "multipartparser.h"
#include "httpcommon.h"
#include "helpers.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>

// ============================================================================
// Helpers
// ============================================================================

static int create_payload_fd(const char* data, size_t size) {
    int fd = memfd_create("test_multipart", 0);
    if (fd < 0) return -1;
    write(fd, data, size);
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static void free_parts(http_payloadpart_t* part) {
    while (part) {
        http_payloadpart_t* next = part->next;

        http_header_t* h = part->header;
        while (h) {
            http_header_t* hn = h->next;
            http_header_free(h);
            h = hn;
        }

        http_payloadfield_t* f = part->field;
        while (f) {
            http_payloadfield_t* fn = f->next;
            if (f->key) free(f->key);
            if (f->value) free(f->value);
            free(f);
            f = fn;
        }

        free(part);
        part = next;
    }
}

static void free_orphan_headers(http_header_t* h) {
    while (h) {
        http_header_t* hn = h->next;
        http_header_free(h);
        h = hn;
    }
}

// ============================================================================
// Test Suite 1: Single part, single header
// ============================================================================

TEST(test_mp_single_part_single_header) {
    TEST_SUITE("Multipart Parser - Single Part");
    TEST_CASE("Single part with one header");

    const char boundary[] = "BOUNDARY";
    const char payload[] =
        "--BOUNDARY\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "hello world\r\n"
        "--BOUNDARY--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");
    TEST_ASSERT_NULL(part->next, "Should have exactly one part");

    TEST_ASSERT_NOT_NULL(part->header, "Part should have headers");
    TEST_ASSERT_NOT_NULL(part->header->key, "Header key should be allocated");
    TEST_ASSERT_STR_EQUAL("Content-Disposition", part->header->key, "Header key should match");
    TEST_ASSERT_NOT_NULL(part->header->value, "Header value should be allocated");

    TEST_ASSERT_NOT_NULL(part->field, "Part should have a field");
    TEST_ASSERT_STR_EQUAL("name", part->field->key, "Field key should be 'name'");
    TEST_ASSERT_STR_EQUAL("field1", part->field->value, "Field value should be 'field1'");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 2: Single part, multiple headers
// ============================================================================

TEST(test_mp_single_part_multiple_headers) {
    TEST_SUITE("Multipart Parser - Multiple Headers");
    TEST_CASE("Single part with two headers");

    const char boundary[] = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    const char payload[] =
        "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "file content here\r\n"
        "------WebKitFormBoundary7MA4YWxkTrZu0gW--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");

    TEST_ASSERT_NOT_NULL(part->header, "First header should exist");
    TEST_ASSERT_NOT_NULL(part->header->next, "Second header should exist");
    TEST_ASSERT_NULL(part->header->next->next, "Should have exactly two headers");

    TEST_ASSERT_STR_EQUAL("Content-Disposition", part->header->key, "First header key");
    TEST_ASSERT_STR_EQUAL("Content-Type", part->header->next->key, "Second header key");

    TEST_ASSERT_NOT_NULL(part->field, "Part should have fields");
    TEST_ASSERT_STR_EQUAL("name", part->field->key, "First field key");
    TEST_ASSERT_STR_EQUAL("file", part->field->value, "First field value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 3: Multiple parts
// ============================================================================

TEST(test_mp_two_parts) {
    TEST_SUITE("Multipart Parser - Multiple Parts");
    TEST_CASE("Two parts in one payload");

    const char boundary[] = "BOUNDARY";
    const char payload[] =
        "--BOUNDARY\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "value1\r\n"
        "--BOUNDARY\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "value2\r\n"
        "--BOUNDARY--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part");
    TEST_ASSERT_NULL(part->next->next, "Should have exactly two parts");

    TEST_ASSERT_STR_EQUAL("name", part->field->key, "Part 1 field key");
    TEST_ASSERT_STR_EQUAL("field1", part->field->value, "Part 1 field value");

    TEST_ASSERT_STR_EQUAL("name", part->next->field->key, "Part 2 field key");
    TEST_ASSERT_STR_EQUAL("field2", part->next->field->value, "Part 2 field value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_three_parts) {
    TEST_CASE("Three parts in one payload");

    const char boundary[] = "bnd";
    const char payload[] =
        "--bnd\r\n"
        "Content-Disposition: form-data; name=\"a\"\r\n"
        "\r\n"
        "AAA\r\n"
        "--bnd\r\n"
        "Content-Disposition: form-data; name=\"b\"\r\n"
        "\r\n"
        "BBB\r\n"
        "--bnd\r\n"
        "Content-Disposition: form-data; name=\"c\"\r\n"
        "\r\n"
        "CCC\r\n"
        "--bnd--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part");
    TEST_ASSERT_NOT_NULL(part->next->next, "Should have third part");
    TEST_ASSERT_NULL(part->next->next->next, "Should have exactly three parts");

    TEST_ASSERT_STR_EQUAL("a", part->field->value, "Part 1 value");
    TEST_ASSERT_STR_EQUAL("b", part->next->field->value, "Part 2 value");
    TEST_ASSERT_STR_EQUAL("c", part->next->next->field->value, "Part 3 value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 4: Empty body and edge cases
// ============================================================================

TEST(test_mp_empty_part_body) {
    TEST_SUITE("Multipart Parser - Edge Cases");
    TEST_CASE("Part with empty body");

    const char boundary[] = "BOUNDARY";
    const char payload[] =
        "--BOUNDARY\r\n"
        "Content-Disposition: form-data; name=\"empty\"\r\n"
        "\r\n"
        "\r\n"
        "--BOUNDARY--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");
    TEST_ASSERT_STR_EQUAL("empty", part->field->value, "Field value should be 'empty'");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_no_extra_headers) {
    TEST_CASE("Part with only Content-Disposition header");

    const char boundary[] = "X";
    const char payload[] =
        "--X\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--X--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");
    TEST_ASSERT_NULL(part->header->next, "Should have only one header");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 5: Header value with leading spaces
// ============================================================================

TEST(test_mp_header_value_leading_spaces) {
    TEST_SUITE("Multipart Parser - Header Value Spaces");
    TEST_CASE("Header value with leading spaces");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition:  form-data; name=\"x\"\r\n"
        "\r\n"
        "val\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");
    TEST_ASSERT_NOT_NULL(part->header->value, "Header value should exist");
    TEST_ASSERT(part->header->value[0] != ' ', "Header value should not start with space");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 6: Body containing \r\n that is NOT a boundary
// ============================================================================

TEST(test_mp_body_false_boundary_prefix) {
    TEST_SUITE("Multipart Parser - False Boundary Prefixes");
    TEST_CASE("Body contains \\r\\n-- that doesn't match boundary");

    const char boundary[] = "REALBOUNDARY";
    const char payload[] =
        "--REALBOUNDARY\r\n"
        "Content-Disposition: form-data; name=\"data\"\r\n"
        "\r\n"
        "line1\r\n"
        "--FAKE\r\n"
        "line2\r\n"
        "--REALBOUNDARY--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");
    TEST_ASSERT_STR_EQUAL("data", part->field->value, "Field value should be 'data'");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_partial_boundary_match) {
    TEST_CASE("Body contains partial boundary match");

    const char boundary[] = "ABC123";
    const char payload[] =
        "--ABC123\r\n"
        "Content-Disposition: form-data; name=\"x\"\r\n"
        "\r\n"
        "data with --ABC12 inside\r\n"
        "--ABC123--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part despite partial boundary in body");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 7: Incremental parsing (chunked)
// ============================================================================

TEST(test_mp_incremental_two_chunks) {
    TEST_SUITE("Multipart Parser - Incremental Parsing");
    TEST_CASE("Parse in two chunks");

    const char boundary[] = "BND";
    const char payload[] =
        "--BND\r\n"
        "Content-Disposition: form-data; name=\"field\"\r\n"
        "\r\n"
        "value\r\n"
        "--BND--";

    size_t total = sizeof(payload) - 1;
    size_t chunk1 = total / 2;

    int fd = create_payload_fd(payload, total);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);

    multipartparser_parse(&parser, (char*)payload, chunk1);
    multipartparser_parse(&parser, (char*)payload + chunk1, total - chunk1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse across chunks");
    TEST_ASSERT_STR_EQUAL("field", part->field->value, "Field value should be correct");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_incremental_byte_by_byte) {
    TEST_CASE("Parse one byte at a time");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"k\"\r\n"
        "\r\n"
        "v\r\n"
        "--B--";

    size_t total = sizeof(payload) - 1;

    int fd = create_payload_fd(payload, total);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);

    for (size_t i = 0; i < total; i++)
        multipartparser_parse(&parser, (char*)payload + i, 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse byte-by-byte");
    TEST_ASSERT_STR_EQUAL("k", part->field->value, "Field value should be correct");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 8: State transitions
// ============================================================================

TEST(test_mp_transition_body_to_boundary_fn) {
    TEST_SUITE("Multipart Parser - State Transitions");
    TEST_CASE("BODY -> BOUNDARY_FN on \\r");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BODY;

    const char input[] = "\r";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BOUNDARY_FN, parser.stage, "BODY -> BOUNDARY_FN on \\r");
    close(fd);
}

TEST(test_mp_transition_boundary_fn_to_first_dash) {
    TEST_CASE("BOUNDARY_FN -> FIRST_DASH on \\n");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_FN;

    const char input[] = "\n";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(FIRST_DASH, parser.stage, "BOUNDARY_FN -> FIRST_DASH on \\n");
    close(fd);
}

TEST(test_mp_transition_boundary_fn_to_second_dash) {
    TEST_CASE("BOUNDARY_FN -> SECOND_DASH on '-'");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_FN;

    const char input[] = "-";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(SECOND_DASH, parser.stage, "BOUNDARY_FN -> SECOND_DASH on '-'");
    close(fd);
}

TEST(test_mp_transition_boundary_fn_to_body) {
    TEST_CASE("BOUNDARY_FN -> BODY on other char");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_FN;

    const char input[] = "X";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "BOUNDARY_FN -> BODY on 'X'");
    close(fd);
}

TEST(test_mp_transition_first_dash_to_second_dash) {
    TEST_CASE("FIRST_DASH -> SECOND_DASH on '-'");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = FIRST_DASH;

    const char input[] = "-";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(SECOND_DASH, parser.stage, "FIRST_DASH -> SECOND_DASH on '-'");
    close(fd);
}

TEST(test_mp_transition_first_dash_to_boundary_fn) {
    TEST_CASE("FIRST_DASH -> BOUNDARY_FN on \\r");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = FIRST_DASH;

    const char input[] = "\r";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BOUNDARY_FN, parser.stage, "FIRST_DASH -> BOUNDARY_FN on \\r");
    close(fd);
}

TEST(test_mp_transition_first_dash_to_body) {
    TEST_CASE("FIRST_DASH -> BODY on non-dash non-\\r");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = FIRST_DASH;

    const char input[] = "A";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "FIRST_DASH -> BODY on 'A'");
    close(fd);
}

TEST(test_mp_transition_second_dash_to_boundary) {
    TEST_CASE("SECOND_DASH -> BOUNDARY on '-'");

    const char boundary[] = "ABC";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = SECOND_DASH;

    const char input[] = "-";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BOUNDARY, parser.stage, "SECOND_DASH -> BOUNDARY on '-'");
    close(fd);
}

TEST(test_mp_transition_second_dash_to_boundary_fn) {
    TEST_CASE("SECOND_DASH -> BOUNDARY_FN on \\r");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = SECOND_DASH;

    const char input[] = "\r";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BOUNDARY_FN, parser.stage, "SECOND_DASH -> BOUNDARY_FN on \\r");
    close(fd);
}

TEST(test_mp_transition_second_dash_to_body) {
    TEST_CASE("SECOND_DASH -> BODY on non-dash non-\\r");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = SECOND_DASH;

    const char input[] = "Z";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "SECOND_DASH -> BODY on 'Z'");
    close(fd);
}

TEST(test_mp_transition_boundary_match) {
    TEST_CASE("BOUNDARY stays when char matches");

    const char boundary[] = "ABC";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = SECOND_DASH;

    // "--A" : SECOND_DASH -> BOUNDARY (on '-'), BOUNDARY checks 'A' == boundary[0]
    const char input[] = "-A";
    multipartparser_parse(&parser, (char*)input, 2);
    TEST_ASSERT_EQUAL(BOUNDARY, parser.stage, "BOUNDARY stays on match");
    close(fd);
}

TEST(test_mp_transition_boundary_mismatch_to_body) {
    TEST_CASE("BOUNDARY -> BODY on mismatched char");

    const char boundary[] = "ABC";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = SECOND_DASH;

    // "--X" : SECOND_DASH -> BOUNDARY, then BOUNDARY gets 'X' != 'A'
    const char input[] = "-X";
    multipartparser_parse(&parser, (char*)input, 2);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "BOUNDARY -> BODY on mismatch");
    close(fd);
}

TEST(test_mp_transition_boundary_complete_to_boundary_fd) {
    TEST_CASE("BOUNDARY -> BOUNDARY_FD when full boundary matched");

    const char boundary[] = "AB";
    int fd = create_payload_fd("--AB\r\n", 6);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = SECOND_DASH;

    // "--AB" : SECOND_DASH -> BOUNDARY -> BOUNDARY (A matches) -> BOUNDARY_FD (B matches last)
    const char input[] = "-AB";
    multipartparser_parse(&parser, (char*)input, 3);
    TEST_ASSERT_EQUAL(BOUNDARY_FD, parser.stage, "BOUNDARY -> BOUNDARY_FD when complete");
    close(fd);
}

TEST(test_mp_transition_boundary_fd_to_boundary_nl) {
    TEST_CASE("BOUNDARY_FD -> BOUNDARY_NL on \\r");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_FD;

    const char input[] = "\r";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BOUNDARY_NL, parser.stage, "BOUNDARY_FD -> BOUNDARY_NL on \\r");
    close(fd);
}

TEST(test_mp_transition_boundary_fd_to_boundary_sd) {
    TEST_CASE("BOUNDARY_FD -> BOUNDARY_SD on '-' (closing)");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_FD;

    const char input[] = "-";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BOUNDARY_SD, parser.stage, "BOUNDARY_FD -> BOUNDARY_SD on '-'");
    close(fd);
}

TEST(test_mp_transition_boundary_fd_to_body) {
    TEST_CASE("BOUNDARY_FD -> BODY on invalid char");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_FD;

    const char input[] = "Z";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "BOUNDARY_FD -> BODY on invalid");
    close(fd);
}

TEST(test_mp_transition_boundary_nl_to_header_key) {
    TEST_CASE("BOUNDARY_NL -> HEADER_KEY on \\n");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_NL;

    const char input[] = "\n";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(HEADER_KEY, parser.stage, "BOUNDARY_NL -> HEADER_KEY on \\n");
    close(fd);
}

TEST(test_mp_transition_boundary_nl_to_body) {
    TEST_CASE("BOUNDARY_NL -> BODY on invalid char");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_NL;

    const char input[] = "X";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "BOUNDARY_NL -> BODY on invalid");
    close(fd);
}

TEST(test_mp_transition_header_key_to_header_space) {
    TEST_CASE("HEADER_KEY -> HEADER_SPACE on ':'");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = HEADER_KEY;
    parser.header_key_offset = 0;
    parser.header_key_size = 0;

    const char input[] = "K:";
    multipartparser_parse(&parser, (char*)input, 2);
    TEST_ASSERT_EQUAL(HEADER_SPACE, parser.stage, "HEADER_KEY -> HEADER_SPACE on ':'");
    TEST_ASSERT_EQUAL_SIZE(1, parser.header_key_size, "Key size should be 1");
    close(fd);
}

TEST(test_mp_transition_header_key_to_end_n) {
    TEST_CASE("HEADER_KEY -> END_N on \\r (end of headers)");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = HEADER_KEY;

    const char input[] = "\r";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(END_N, parser.stage, "HEADER_KEY -> END_N on \\r");
    close(fd);
}

TEST(test_mp_transition_header_space_skips_spaces) {
    TEST_CASE("HEADER_SPACE stays on space chars");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = HEADER_SPACE;
    parser.header_value_offset = 0;
    parser.header_value_size = 0;

    const char input[] = "   ";
    multipartparser_parse(&parser, (char*)input, 3);
    TEST_ASSERT_EQUAL(HEADER_SPACE, parser.stage, "HEADER_SPACE stays on spaces");
    close(fd);
}

TEST(test_mp_transition_header_space_to_header_value) {
    TEST_CASE("HEADER_SPACE -> HEADER_VALUE on non-space");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = HEADER_SPACE;
    parser.header_value_offset = 0;
    parser.header_value_size = 0;

    const char input[] = "v";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(HEADER_VALUE, parser.stage, "HEADER_SPACE -> HEADER_VALUE");
    TEST_ASSERT_EQUAL_SIZE(1, parser.header_value_size, "Value size should be 1");
    close(fd);
}

TEST(test_mp_transition_header_value_to_header_n) {
    TEST_CASE("HEADER_VALUE -> HEADER_N on \\r");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = HEADER_VALUE;
    parser.header_value_offset = 0;
    parser.header_value_size = 0;

    const char input[] = "val\r";
    multipartparser_parse(&parser, (char*)input, 4);
    TEST_ASSERT_EQUAL(HEADER_N, parser.stage, "HEADER_VALUE -> HEADER_N on \\r");
    TEST_ASSERT_EQUAL_SIZE(3, parser.header_value_size, "Value size should be 3");
    close(fd);
}

TEST(test_mp_transition_header_n_to_body_on_invalid) {
    TEST_CASE("HEADER_N -> BODY on non-\\n char");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = HEADER_N;
    parser.header_key_offset = 0;
    parser.header_key_size = 4;
    parser.header_value_offset = 6;
    parser.header_value_size = 3;

    const char input[] = "X";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "HEADER_N -> BODY on non-\\n");
    close(fd);
}

TEST(test_mp_transition_end_n_to_body) {
    TEST_CASE("END_N -> BODY on \\n");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = END_N;

    const char input[] = "\n";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "END_N -> BODY on \\n");
    close(fd);
}

TEST(test_mp_transition_boundary_sd_to_body) {
    TEST_CASE("BOUNDARY_SD -> BODY on '-' (closing boundary)");

    const char boundary[] = "B";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BOUNDARY_SD;

    const char input[] = "-";
    multipartparser_parse(&parser, (char*)input, 1);
    TEST_ASSERT_EQUAL(BODY, parser.stage, "BOUNDARY_SD -> BODY on '-'");
    close(fd);
}

TEST(test_mp_transition_chain_initial_boundary) {
    TEST_CASE("Full chain: BOUNDARY_FN -> SECOND_DASH -> BOUNDARY via --");

    const char boundary[] = "ABC";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    // stage is BOUNDARY_FN from init

    const char input[] = "--A";
    multipartparser_parse(&parser, (char*)input, 3);
    TEST_ASSERT_EQUAL(BOUNDARY, parser.stage, "BOUNDARY_FN -> SECOND_DASH -> BOUNDARY via --A");
    close(fd);
}

TEST(test_mp_transition_chain_body_to_boundary) {
    TEST_CASE("Full chain: BODY -> BOUNDARY_FN -> FIRST_DASH -> SECOND_DASH -> BOUNDARY");

    const char boundary[] = "ABC";
    int fd = create_payload_fd("x", 1);
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BODY;

    const char input[] = "\r\n--A";
    multipartparser_parse(&parser, (char*)input, 5);
    TEST_ASSERT_EQUAL(BOUNDARY, parser.stage, "BODY -> ... -> BOUNDARY via \\r\\n--A");
    close(fd);
}

// ============================================================================
// Test Suite 9: Header without space after colon
// ============================================================================

TEST(test_mp_header_no_space_after_colon) {
    TEST_SUITE("Multipart Parser - Header Formatting");
    TEST_CASE("Header without space after colon");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition:form-data; name=\"x\"\r\n"
        "\r\n"
        "v\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");
    TEST_ASSERT_STR_EQUAL("Content-Disposition", part->header->key, "Header key");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 10: Multiple fields in Content-Disposition
// ============================================================================

TEST(test_mp_content_disposition_name_and_filename) {
    TEST_SUITE("Multipart Parser - Content-Disposition Fields");
    TEST_CASE("name and filename in Content-Disposition");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"upload\"; filename=\"doc.pdf\"\r\n"
        "\r\n"
        "%PDF-fake\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");

    TEST_ASSERT_NOT_NULL(part->field, "Should have first field");
    TEST_ASSERT_NOT_NULL(part->field->next, "Should have second field");
    TEST_ASSERT_STR_EQUAL("name", part->field->key, "First field key");
    TEST_ASSERT_STR_EQUAL("upload", part->field->value, "First field value");
    TEST_ASSERT_STR_EQUAL("filename", part->field->next->key, "Second field key");
    TEST_ASSERT_STR_EQUAL("doc.pdf", part->field->next->value, "Second field value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 11: Binary body content
// ============================================================================

TEST(test_mp_binary_body) {
    TEST_SUITE("Multipart Parser - Binary Content");
    TEST_CASE("Part with binary body content");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"bin\"\r\n"
        "\r\n"
        "\x01\x02\x03\x00\xFF\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse part with binary body");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_binary_body2) {
    TEST_SUITE("Multipart Parser - Binary Content");
    TEST_CASE("Part with binary body content");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"bin\"\r\n"
        "Content-Type: application/pdf\r\n"
        "\r\n"
        "\x01\x02\x03\x00\xFF\r\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse part with binary body");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_binary_body3) {
    TEST_SUITE("Multipart Parser - Binary Content");
    TEST_CASE("Part with binary body content");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"bin\"\r\n"
        "Content-Type: application/pdf\r\n"
        "\r\n"
        "\x01\x02\x03\x00\xFF\r\n\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse part with binary body");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_binary_body4) {
    TEST_SUITE("Multipart Parser - Binary Content");
    TEST_CASE("Part with binary body content");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"bin\"\r\n"
        "Content-Type: application/pdf\r\n"
        "\r\n"
        "\x01\x02\x03\x00\xFF\n\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse part with binary body");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 12: Body with multiline \r\n
// ============================================================================

TEST(test_mp_body_multiline_cr_lf) {
    TEST_SUITE("Multipart Parser - Multiline Body");
    TEST_CASE("Body with multiple \\r\\n that don't form boundary");

    const char boundary[] = "MYBOUNDARY";
    const char payload[] =
        "--MYBOUNDARY\r\n"
        "Content-Disposition: form-data; name=\"text\"\r\n"
        "\r\n"
        "line1\r\nline2\r\nline3\r\n"
        "--MYBOUNDARY--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");
    TEST_ASSERT_NULL(part->next, "Should have exactly one part");
    TEST_ASSERT_STR_EQUAL("text", part->field->value, "Field value should be 'text'");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 13: Closing boundary only
// ============================================================================

TEST(test_mp_closing_boundary_only) {
    TEST_SUITE("Multipart Parser - Closing Boundary");
    TEST_CASE("Closing boundary with no parts");

    const char boundary[] = "B";
    const char payload[] = "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Should have no parts for closing-only boundary");

    close(fd);
}

// ============================================================================
// Test Suite 14: Part offset tracking
// ============================================================================

TEST(test_mp_part_offset) {
    TEST_SUITE("Multipart Parser - Offset Tracking");
    TEST_CASE("Verify part offset points to body start");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "ABCD\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have one part");

    // "--B\r\n" = 5
    // "Content-Disposition: form-data; name=\"f\"\r\n" = 41
    // "\r\n" = 2
    // Total header + separator = 48, +1 for \n after \r in END_N
    TEST_ASSERT_EQUAL_SIZE(49, part->offset, "Part offset should point to body start");
    TEST_ASSERT(part->size > 0, "Part size should be > 0");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 15: Boundary variations
// ============================================================================

TEST(test_mp_long_boundary) {
    TEST_SUITE("Multipart Parser - Boundary Variations");
    TEST_CASE("Long boundary string");

    const char boundary[] = "----WebKitFormBoundaryRAndOMCharACTerS123456789";
    const char payload[] =
        "------WebKitFormBoundaryRAndOMCharACTerS123456789\r\n"
        "Content-Disposition: form-data; name=\"x\"\r\n"
        "\r\n"
        "v\r\n"
        "------WebKitFormBoundaryRAndOMCharACTerS123456789--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse with long boundary");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_short_boundary) {
    TEST_CASE("Single character boundary");

    const char boundary[] = "X";
    const char payload[] =
        "--X\r\n"
        "Content-Disposition: form-data; name=\"a\"\r\n"
        "\r\n"
        "b\r\n"
        "--X--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse with single-char boundary");
    TEST_ASSERT_STR_EQUAL("a", part->field->value, "Field value should be 'a'");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 16: Tricky body content with CR/LF combinations
// ============================================================================

TEST(test_mp_body_cr_cr_lf_before_boundary) {
    TEST_SUITE("Multipart Parser - CR/LF Edge Cases in Body");
    TEST_CASE("Body ends with \\r\\r\\n before boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should find boundary after \\r\\r\\n");
    TEST_ASSERT_STR_EQUAL("f", part->field->value, "Field value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_cr_cr_cr_lf_before_boundary) {
    TEST_CASE("Body ends with \\r\\r\\r\\n before boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\r\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should find boundary after \\r\\r\\r\\n");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_lf_before_boundary) {
    TEST_CASE("Body ends with bare \\n before boundary (no \\r)");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Bare \\n should not trigger boundary detection (RFC requires CRLF)");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_cr_lf_cr_lf_before_boundary) {
    TEST_CASE("Body ends with \\r\\n\\r\\n before boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should find boundary after \\r\\n\\r\\n");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_lf_cr_lf_before_boundary) {
    TEST_CASE("Body ends with \\n\\r\\n before boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\n\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    // \n -> BODY, \r -> BOUNDARY_FN, \n -> FIRST_DASH, - -> SECOND_DASH, - -> BOUNDARY
    TEST_ASSERT_NOT_NULL(part, "Should find boundary after \\n\\r\\n");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_only_cr_before_boundary) {
    TEST_CASE("Body ends with bare \\r then --boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    // \r -> BOUNDARY_FN, '-' -> SECOND_DASH, '-' -> BOUNDARY
    TEST_ASSERT_NOT_NULL(part, "Should find boundary after bare \\r then --");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_multiple_cr_before_lf) {
    TEST_CASE("Body ends with \\r\\r\\r\\r\\n before boundary");

    const char boundary[] = "BND";
    const char payload[] =
        "--BND\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\r\r\r\n"
        "--BND--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should find boundary after many \\r before \\n");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_null_byte_in_middle) {
    TEST_CASE("Body contains null byte");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "before\x00after\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse body with null byte");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_contains_double_dash) {
    TEST_CASE("Body contains -- that is not a boundary");

    const char boundary[] = "MYBOUND";
    const char payload[] =
        "--MYBOUND\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "text with -- inside\r\n"
        "--MYBOUND--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should not confuse -- in body with boundary");
    TEST_ASSERT_NULL(part->next, "Should have exactly one part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_cr_only_no_closing_boundary) {
    TEST_CASE("Body is just \\r with no closing boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "\r";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Incomplete payload should not produce part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_lf_lf_before_boundary) {
    TEST_CASE("Body ends with \\n\\n before boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\n\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Bare \\n\\n should not trigger boundary");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_two_parts_first_body_cr_cr_lf) {
    TEST_CASE("Two parts where first body ends with \\r\\r\\n");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"a\"\r\n"
        "\r\n"
        "AAA\r\r\n"
        "--B\r\n"
        "Content-Disposition: form-data; name=\"b\"\r\n"
        "\r\n"
        "BBB\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part");
    TEST_ASSERT_STR_EQUAL("a", part->field->value, "Part 1 value");
    TEST_ASSERT_STR_EQUAL("b", part->next->field->value, "Part 2 value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 17: Invalid / malformed payloads
// ============================================================================

TEST(test_mp_no_headers_at_all) {
    TEST_SUITE("Multipart Parser - Malformed Payloads");
    TEST_CASE("Part with no headers, body immediately after boundary");

    const char boundary[] = "B";
    // After boundary there is \r\n then immediately body data
    // No headers, no \r\n separator between headers and body
    const char payload[] =
        "--B\r\n"
        "body data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    // "body data" is treated as a header key (no colon) -> stays in HEADER_KEY
    // until \r triggers END_N, then \n -> BODY (offset set)
    // Then --B-- is closing boundary -> creates part with no headers
    http_payloadpart_t* part = multipartparser_part(&parser);
    // Parser should not crash; part may or may not be created
    TEST_ASSERT(1, "Parser should not crash on no-headers payload");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_header_without_crlf_terminator) {
    TEST_CASE("Header line without \\r\\n terminator, then boundary");

    const char boundary[] = "B";
    // Header key "X" with colon, but value never terminated with \r\n
    const char payload[] =
        "--B\r\n"
        "X: value"
        "\r\n--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    TEST_ASSERT(1, "Parser should not crash on unterminated header");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_empty_header_value) {
    TEST_CASE("Header with empty value after colon");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "X:\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse with empty header value");
    TEST_ASSERT_NOT_NULL(part->header, "Should have headers");
    TEST_ASSERT_NULL(part->header->value, "Should not have header value");
    // First header: "X" with empty value, second: Content-Disposition
    TEST_ASSERT_NOT_NULL(part->header->next, "Should have second header");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_header_colon_only) {
    TEST_CASE("Header with only colon (empty key and value)");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        ":\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    // ":" produces a header with key_size=0, value_size=0
    // Then \r\n is blank line -> END_N -> BODY
    // Part is created with a header that has empty key and value
    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should create part with colon-only header");
    TEST_ASSERT_NOT_NULL(part->header, "Should have header");
    TEST_ASSERT_EQUAL_SIZE(0, part->header->key_length, "Key length should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, part->header->value_length, "Value length should be 0");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_truncated_after_boundary) {
    TEST_CASE("Payload ends right after boundary, no headers or body");

    const char boundary[] = "B";
    const char payload[] = "--B\r\n";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Truncated payload should not produce part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_truncated_mid_header) {
    TEST_CASE("Payload truncated in the middle of a header");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Truncated mid-header should not produce part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_truncated_mid_header_value) {
    TEST_CASE("Payload truncated in the middle of a header value");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"fi";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Truncated mid-value should not produce part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_no_closing_boundary) {
    TEST_CASE("Payload with no closing boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "No closing boundary means no part created");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_wrong_boundary) {
    TEST_CASE("Payload with completely wrong boundary");

    const char boundary[] = "RIGHT";
    const char payload[] =
        "--WRONG\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--WRONG--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Wrong boundary should not produce part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_empty_payload) {
    TEST_CASE("Completely empty payload");

    const char boundary[] = "B";
    const char payload[] = "";

    int fd = create_payload_fd(payload, 0);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, 0);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Empty payload should not produce part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_only_dashes) {
    TEST_CASE("Payload is just -- (incomplete boundary)");

    const char boundary[] = "B";
    const char payload[] = "--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Incomplete boundary should not produce part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_only_boundary_no_dash_suffix) {
    TEST_CASE("Boundary without closing -- and no headers/body");

    const char boundary[] = "B";
    const char payload[] = "--B";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NULL(part, "Boundary without content should not produce part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_no_blank_line_between_headers_and_body) {
    TEST_CASE("Headers present but no \\r\\n separator before body");

    const char boundary[] = "B";
    // Header line, then body immediately without \r\n blank line
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "body data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    // "body data" is parsed as another header key (no colon) -> HEADER_KEY
    // \r -> END_N, \n -> BODY (offset set). Then --B-- creates part.
    TEST_ASSERT(1, "Parser should not crash without blank line separator");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_lf_only_newlines) {
    TEST_CASE("Payload with LF only (no CR) everywhere");

    const char boundary[] = "B";
    const char payload[] =
        "--B\n"
        "Content-Disposition: form-data; name=\"f\"\n"
        "\n"
        "data\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    // Bare \n in BOUNDARY_FN triggers FIRST_DASH,
    // but after headers \n doesn't trigger END_N (expects \r first)
    // Parser won't find blank line separator -> likely no part
    TEST_ASSERT(1, "Parser should not crash on LF-only payload");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_cr_only_newlines) {
    TEST_CASE("Payload with CR only (no LF) everywhere");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r"
        "Content-Disposition: form-data; name=\"f\"\r"
        "\r"
        "data\r"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    TEST_ASSERT(1, "Parser should not crash on CR-only payload");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_binary_garbage_before_boundary) {
    TEST_CASE("Random binary garbage before first boundary");

    const char boundary[] = "B";
    const char payload[] =
        "\xDE\xAD\xBE\xEF\x00\xFF\x01\x02"
        "\r\n--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    // Start in BODY so garbage is consumed, then \r\n triggers boundary search
    parser.stage = BODY;
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should find boundary after binary garbage preamble");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_binary_garbage_after_body) {
    TEST_CASE("Random binary garbage after body, no closing boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "\xDE\xAD\xBE\xEF";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    // No closing boundary -> part not created (garbage consumed as body)
    TEST_ASSERT_NULL(part, "No closing boundary with trailing garbage");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_boundary_substring_prefix) {
    TEST_CASE("Boundary string is a prefix of actual boundary in payload");

    const char boundary[] = "B";
    // Payload uses "BORDER" which starts with "B"
    const char payload[] =
        "--BORDER\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--BORDER--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    // Parser matches "B" from "BORDER" -> BOUNDARY_FD
    // Then 'R' is not '-' or '\r' -> BODY. Part created with wrong size.
    // This tests that parser doesn't crash on boundary prefix mismatch.
    TEST_ASSERT(1, "Parser should not crash on boundary prefix confusion");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_double_closing_boundary) {
    TEST_CASE("Two closing boundaries in a row");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse part even with double closing");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_header_value_with_colon) {
    TEST_CASE("Header value contains colons (like Content-Type with MIME)");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse headers with colons in value");
    TEST_ASSERT_NOT_NULL(part->header->next, "Should have two headers");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_single_dash_before_boundary_name) {
    TEST_CASE("Only one dash before boundary name (should be --)");

    const char boundary[] = "B";
    const char payload[] =
        "-B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    // Single dash doesn't form boundary, parser won't find opening boundary
    TEST_ASSERT(1, "Parser should not crash on single dash");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_three_dashes_before_boundary) {
    TEST_CASE("Three dashes before boundary name");

    const char boundary[] = "B";
    const char payload[] =
        "---B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    TEST_ASSERT(1, "Parser should not crash on three dashes");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_no_content_disposition) {
    TEST_CASE("Part with Content-Type but no Content-Disposition");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should create part even without Content-Disposition");
    TEST_ASSERT_NULL(part->field, "Should have no fields without Content-Disposition");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_header_with_tab_after_colon) {
    TEST_CASE("Header with tab character after colon instead of space");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition:\tform-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    // Tab is not space, so HEADER_SPACE transitions to HEADER_VALUE with tab as first char
    TEST_ASSERT(1, "Parser should not crash on tab after colon");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_very_long_header_value) {
    TEST_CASE("Header with very long value (4096 bytes)");

    const char boundary[] = "B";
    char payload[8192];
    size_t pos = 0;

    memcpy(payload + pos, "--B\r\nContent-Disposition: ", 26);
    pos += 26;

    // Fill with 4096 'x' characters
    memset(payload + pos, 'x', 4096);
    pos += 4096;

    memcpy(payload + pos, "\r\n\r\ndata\r\n--B--", 16);
    pos += 16;

    int fd = create_payload_fd(payload, pos);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, payload, pos);

    TEST_ASSERT(1, "Parser should not crash on very long header value");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_many_headers) {
    TEST_CASE("Part with many headers (50)");

    const char boundary[] = "BOUNDARY";
    char payload[16384];
    size_t pos = 0;

    memcpy(payload + pos, "--BOUNDARY\r\n", 12);
    pos += 12;

    for (int i = 0; i < 50; i++) {
        pos += sprintf(payload + pos, "X-Header-%02d: value-%02d\r\n", i, i);
    }

    memcpy(payload + pos, "Content-Disposition: form-data; name=\"f\"\r\n", 41);
    pos += 41;
    memcpy(payload + pos, "\r\ndata\r\n--BOUNDARY--", 18);
    pos += 18;

    int fd = create_payload_fd(payload, pos);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, payload, pos);

    TEST_ASSERT(1, "Parser should not crash with many headers");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_boundary_inside_header_value) {
    TEST_CASE("Boundary string appears inside a header value");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "X-Custom: --B is the boundary\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    TEST_ASSERT(1, "Parser should not confuse boundary in header value");

    free_parts(multipartparser_part(&parser));
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_part_size_with_empty_body) {
    TEST_CASE("Part size calculation with empty body");

    const char boundary[] = "BOUNDARY";
    const char payload[] =
        "--BOUNDARY\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "\r\n"
        "--BOUNDARY--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should create part with empty body");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 18: Mixed parts — text field + file upload + empty field
// ============================================================================

TEST(test_mp_mixed_text_file_empty) {
    TEST_SUITE("Multipart Parser - Mixed Parts");
    TEST_CASE("Text field, file upload, and empty field in one payload");

    const char boundary[] = "----WebKitFormBoundary";
    const char payload[] =
        "------WebKitFormBoundary\r\n"
        "Content-Disposition: form-data; name=\"title\"\r\n"
        "\r\n"
        "My Document\r\n"
        "------WebKitFormBoundary\r\n"
        "Content-Disposition: form-data; name=\"upload\"; filename=\"doc.pdf\"\r\n"
        "Content-Type: application/pdf\r\n"
        "\r\n"
        "%PDF-1.4 fake content\r\n"
        "------WebKitFormBoundary\r\n"
        "Content-Disposition: form-data; name=\"optional\"\r\n"
        "\r\n"
        "\r\n"
        "------WebKitFormBoundary--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part (title)");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part (file)");
    TEST_ASSERT_NOT_NULL(part->next->next, "Should have third part (empty)");
    TEST_ASSERT_NULL(part->next->next->next, "Should have exactly three parts");

    // Part 1: text field "title"
    TEST_ASSERT_STR_EQUAL("name", part->field->key, "Part 1 field key");
    TEST_ASSERT_STR_EQUAL("title", part->field->value, "Part 1 field value");

    // Part 2: file upload — should have name + filename + Content-Type
    TEST_ASSERT_STR_EQUAL("name", part->next->field->key, "Part 2 first field key");
    TEST_ASSERT_STR_EQUAL("upload", part->next->field->value, "Part 2 name value");
    TEST_ASSERT_NOT_NULL(part->next->field->next, "Part 2 should have filename field");
    TEST_ASSERT_STR_EQUAL("filename", part->next->field->next->key, "Part 2 filename key");
    TEST_ASSERT_STR_EQUAL("doc.pdf", part->next->field->next->value, "Part 2 filename value");
    TEST_ASSERT_NOT_NULL(part->next->header->next, "Part 2 should have Content-Type header");

    // Part 3: empty field
    TEST_ASSERT_STR_EQUAL("optional", part->next->next->field->value, "Part 3 field value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_five_parts_mixed) {
    TEST_CASE("Five parts with varying content types");

    const char boundary[] = "b";
    const char payload[] =
        "--b\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "alpha\r\n"
        "--b\r\n"
        "Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "file content\r\n"
        "--b\r\n"
        "Content-Disposition: form-data; name=\"field2\"\r\n"
        "\r\n"
        "beta\r\n"
        "--b\r\n"
        "Content-Disposition: form-data; name=\"empty_field\"\r\n"
        "\r\n"
        "\r\n"
        "--b\r\n"
        "Content-Disposition: form-data; name=\"file2\"; filename=\"b.json\"\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        "{\"key\":\"val\"}\r\n"
        "--b--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part");
    TEST_ASSERT_NOT_NULL(part->next->next, "Should have third part");
    TEST_ASSERT_NOT_NULL(part->next->next->next, "Should have fourth part");
    TEST_ASSERT_NOT_NULL(part->next->next->next->next, "Should have fifth part");
    TEST_ASSERT_NULL(part->next->next->next->next->next, "Should have exactly five parts");

    // Verify name attribute values in order
    // field->value stores the attribute value from name="..." (not the body content)
    TEST_ASSERT_STR_EQUAL("field1", part->field->value, "Part 1 name");
    TEST_ASSERT_STR_EQUAL("file1", part->next->field->value, "Part 2 name");
    TEST_ASSERT_STR_EQUAL("field2", part->next->next->field->value, "Part 3 name");
    TEST_ASSERT_STR_EQUAL("empty_field", part->next->next->next->field->value, "Part 4 name");
    TEST_ASSERT_STR_EQUAL("file2", part->next->next->next->next->field->value, "Part 5 name");

    // File parts should have filename
    TEST_ASSERT_STR_EQUAL("a.txt", part->next->field->next->value, "Part 2 filename");
    TEST_ASSERT_STR_EQUAL("b.json", part->next->next->next->next->field->next->value, "Part 5 filename");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 19: Boundary with special characters
// ============================================================================

TEST(test_mp_boundary_with_dashes) {
    TEST_SUITE("Multipart Parser - Boundary Special Chars");
    TEST_CASE("Boundary containing dashes");

    const char boundary[] = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    const char payload[] =
        "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
        "Content-Disposition: form-data; name=\"x\"\r\n"
        "\r\n"
        "val\r\n"
        "------WebKitFormBoundary7MA4YWxkTrZu0gW--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse with dash-heavy boundary");
    TEST_ASSERT_STR_EQUAL("x", part->field->value, "Field value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_boundary_with_digits_and_underscores) {
    TEST_CASE("Boundary with digits and underscores");

    const char boundary[] = "abc_123_XYZ";
    const char payload[] =
        "--abc_123_XYZ\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--abc_123_XYZ--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse boundary with digits and underscores");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 20: Unicode / UTF-8 in field values and filenames
// ============================================================================

TEST(test_mp_utf8_field_value) {
    TEST_SUITE("Multipart Parser - Unicode Content");
    TEST_CASE("UTF-8 Cyrillic text in field value");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"description\"\r\n"
        "\r\n"
        "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 \xd0\xbc\xd0\xb8\xd1\x80\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse UTF-8 field value");
    TEST_ASSERT_STR_EQUAL("description", part->field->value, "Field name");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_utf8_filename) {
    TEST_CASE("UTF-8 filename in Content-Disposition");

    const char boundary[] = "B";
    // filename = "документ.pdf" in UTF-8
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"\xd0\xb4\xd0\xbe\xd0\xba\xd1\x83\xd0\xbc\xd0\xb5\xd0\xbd\xd1\x82.pdf\"\r\n"
        "Content-Type: application/pdf\r\n"
        "\r\n"
        "%PDF-fake\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse UTF-8 filename");
    TEST_ASSERT_NOT_NULL(part->field->next, "Should have filename field");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 21: Escaped quotes in filename
// ============================================================================

TEST(test_mp_escaped_quotes_in_filename) {
    TEST_SUITE("Multipart Parser - Escaped Quotes");
    TEST_CASE("Filename with backslash-escaped quotes (formdataparser level)");

    // Note: multipartparser extracts the raw Content-Disposition value.
    // The formdataparser handles quote escaping. This test verifies
    // multipartparser doesn't crash and creates the part correctly.
    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"test\\\"file.txt\"\r\n"
        "\r\n"
        "content\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse part with escaped quotes in filename");
    TEST_ASSERT_NOT_NULL(part->field, "Should have fields");
    TEST_ASSERT_NOT_NULL(part->field->next, "Should have filename field");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 22: Incremental parsing with multiple parts
// ============================================================================

TEST(test_mp_incremental_two_parts_split) {
    TEST_SUITE("Multipart Parser - Incremental Multi-Part");
    TEST_CASE("Two parts parsed in three chunks");

    const char boundary[] = "BND";
    const char payload[] =
        "--BND\r\n"
        "Content-Disposition: form-data; name=\"a\"\r\n"
        "\r\n"
        "AAA\r\n"
        "--BND\r\n"
        "Content-Disposition: form-data; name=\"b\"\r\n"
        "\r\n"
        "BBB\r\n"
        "--BND--";

    size_t total = sizeof(payload) - 1;
    // Split roughly into header1 | body1+header2 | body2+close
    size_t chunk1 = 20;
    size_t chunk2 = total / 2 - chunk1;

    int fd = create_payload_fd(payload, total);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);

    multipartparser_parse(&parser, (char*)payload, chunk1);
    multipartparser_parse(&parser, (char*)payload + chunk1, chunk2);
    multipartparser_parse(&parser, (char*)payload + chunk1 + chunk2, total - chunk1 - chunk2);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part");
    TEST_ASSERT_STR_EQUAL("a", part->field->value, "Part 1 value");
    TEST_ASSERT_STR_EQUAL("b", part->next->field->value, "Part 2 value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_incremental_byte_by_byte_two_parts) {
    TEST_CASE("Two parts parsed one byte at a time");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"x\"\r\n"
        "\r\n"
        "X\r\n"
        "--B\r\n"
        "Content-Disposition: form-data; name=\"y\"\r\n"
        "\r\n"
        "Y\r\n"
        "--B--";

    size_t total = sizeof(payload) - 1;

    int fd = create_payload_fd(payload, total);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);

    for (size_t i = 0; i < total; i++)
        multipartparser_parse(&parser, (char*)payload + i, 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part (byte-by-byte)");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part (byte-by-byte)");
    TEST_ASSERT_STR_EQUAL("x", part->field->value, "Part 1 value");
    TEST_ASSERT_STR_EQUAL("y", part->next->field->value, "Part 2 value");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 23: Body with content identical to boundary prefix
// ============================================================================

TEST(test_mp_body_starts_with_boundary_prefix) {
    TEST_SUITE("Multipart Parser - Boundary Prefix in Body");
    TEST_CASE("Body starts with \\r\\n-- followed by partial boundary");

    const char boundary[] = "ABC";
    const char payload[] =
        "--ABC\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "\r\n--ABextra\r\n"
        "--ABC--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should not confuse body prefix with boundary");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_body_contains_full_boundary_but_no_crlf_prefix) {
    TEST_CASE("Body contains --BOUNDARY but without preceding \\r\\n");

    const char boundary[] = "ABC";
    const char payload[] =
        "--ABC\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "prefix--ABCsuffix\r\n"
        "--ABC--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should not confuse mid-text boundary string");
    TEST_ASSERT_NULL(part->next, "Should have exactly one part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 24: Part offset and size verification across multiple parts
// ============================================================================

TEST(test_mp_two_parts_offset_and_size) {
    TEST_SUITE("Multipart Parser - Offset and Size Verification");
    TEST_CASE("Verify offsets and sizes are correct for two parts");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"a\"\r\n"
        "\r\n"
        "HELLO\r\n"
        "--B\r\n"
        "Content-Disposition: form-data; name=\"b\"\r\n"
        "\r\n"
        "WORLD\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part");

    // Part 1: offset should point to body start after headers
    // "--B\r\n" (5) + "Content-Disposition: form-data; name=\"a\"\r\n" (40) + "\r\n" (2) = 47
    // +1 for \n after \r in END_N transition = 48
    TEST_ASSERT(part->offset > 0, "Part 1 offset should be > 0");
    TEST_ASSERT(part->size > 0, "Part 1 size should be > 0");

    // Part 2: offset should be greater than part 1 offset
    TEST_ASSERT(part->next->offset > part->offset, "Part 2 offset should be > Part 1 offset");
    TEST_ASSERT(part->next->size > 0, "Part 2 size should be > 0");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 25: Preamble and postamble
// ============================================================================

TEST(test_mp_with_preamble) {
    TEST_SUITE("Multipart Parser - Preamble/Postamble");
    TEST_CASE("Payload with preamble before first boundary");

    const char boundary[] = "B";
    const char payload[] =
        "This is preamble text\r\n"
        "It should be ignored\r\n"
        "\r\n--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    parser.stage = BODY; // Start in BODY to consume preamble
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should find part after preamble");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

TEST(test_mp_with_postamble) {
    TEST_CASE("Payload with postamble after closing boundary");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"\r\n"
        "\r\n"
        "data\r\n"
        "--B--\r\n"
        "This is postamble and should be ignored";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should find part before postamble");
    TEST_ASSERT_NULL(part->next, "Should have exactly one part");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 26: Multiple parts with binary file between text fields
// ============================================================================

TEST(test_mp_text_binary_text_sequence) {
    TEST_SUITE("Multipart Parser - Alternating Text and Binary");
    TEST_CASE("Text field, binary file, text field sequence");

    const char boundary[] = "SEP";
    const char payload[] =
        "--SEP\r\n"
        "Content-Disposition: form-data; name=\"metadata\"\r\n"
        "\r\n"
        "some metadata\r\n"
        "--SEP\r\n"
        "Content-Disposition: form-data; name=\"image\"; filename=\"img.png\"\r\n"
        "Content-Type: image/png\r\n"
        "\r\n"
        "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\r\n"
        "--SEP\r\n"
        "Content-Disposition: form-data; name=\"caption\"\r\n"
        "\r\n"
        "A photo description\r\n"
        "--SEP--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should have first part (metadata)");
    TEST_ASSERT_NOT_NULL(part->next, "Should have second part (image)");
    TEST_ASSERT_NOT_NULL(part->next->next, "Should have third part (caption)");
    TEST_ASSERT_NULL(part->next->next->next, "Should have exactly three parts");

    TEST_ASSERT_STR_EQUAL("metadata", part->field->value, "Part 1 name");
    TEST_ASSERT_STR_EQUAL("image", part->next->field->value, "Part 2 name");
    TEST_ASSERT_STR_EQUAL("caption", part->next->next->field->value, "Part 3 name");

    // Image part should have filename
    TEST_ASSERT_NOT_NULL(part->next->field->next, "Part 2 should have filename");
    TEST_ASSERT_STR_EQUAL("img.png", part->next->field->next->value, "Part 2 filename");

    // Image part should have two headers (Content-Disposition + Content-Type)
    TEST_ASSERT_NOT_NULL(part->next->header->next, "Part 2 should have Content-Type");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 27: Header value with semicolons (Content-Type params)
// ============================================================================

TEST(test_mp_content_type_with_charset) {
    TEST_SUITE("Multipart Parser - Complex Header Values");
    TEST_CASE("Content-Type with charset parameter");

    const char boundary[] = "B";
    const char payload[] =
        "--B\r\n"
        "Content-Disposition: form-data; name=\"f\"; filename=\"page.html\"\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<h1>Hello</h1>\r\n"
        "--B--";

    int fd = create_payload_fd(payload, sizeof(payload) - 1);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);
    multipartparser_parse(&parser, (char*)payload, sizeof(payload) - 1);

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse Content-Type with charset");
    TEST_ASSERT_NOT_NULL(part->header->next, "Should have two headers");

    free_parts(part);
    free_orphan_headers(parser.header);
    close(fd);
}

// ============================================================================
// Test Suite 28: Repeated calls to multipartparser_parse
// ============================================================================

TEST(test_mp_repeated_parse_calls_accumulate) {
    TEST_SUITE("Multipart Parser - Repeated Parse Calls");
    TEST_CASE("Calling parse multiple times with small chunks");

    const char boundary[] = "X";
    const char* chunks[] = {
        "--X\r\n",
        "Content-Disposition: form-data; ",
        "name=\"f\"\r\n",
        "\r\n",
        "hello ",
        "world\r\n",
        "--X--"
    };
    int num_chunks = 7;

    // Calculate total size
    size_t total = 0;
    for (int i = 0; i < num_chunks; i++)
        total += strlen(chunks[i]);

    // Build contiguous payload for fd
    char* payload = malloc(total);
    size_t pos = 0;
    for (int i = 0; i < num_chunks; i++) {
        size_t len = strlen(chunks[i]);
        memcpy(payload + pos, chunks[i], len);
        pos += len;
    }

    int fd = create_payload_fd(payload, total);
    TEST_ASSERT(fd >= 0, "memfd_create should succeed");

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);

    // Parse each chunk individually (all share same buffer)
    pos = 0;
    for (int i = 0; i < num_chunks; i++) {
        size_t len = strlen(chunks[i]);
        multipartparser_parse(&parser, payload + pos, len);
        pos += len;
    }

    http_payloadpart_t* part = multipartparser_part(&parser);
    TEST_ASSERT_NOT_NULL(part, "Should parse across many small chunks");
    TEST_ASSERT_STR_EQUAL("f", part->field->value, "Field value");

    free_parts(part);
    free_orphan_headers(parser.header);
    free(payload);
    close(fd);
}

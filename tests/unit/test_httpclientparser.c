#include "framework.h"
#include "httpclientparser.h"
#include "query.h"

#include <string.h>
#include <stdlib.h>

// ============================================================================
// Helpers
// ============================================================================
//
// Парсер владеет host/uri/path/query и освобождает их в httpclientparser_free.
// Поэтому в большинстве тестов поля читаются напрямую (без move_*), а вся
// память освобождается одним вызовом httpclientparser_free(parser).

static httpclientparser_t* parser_new(void) {
    httpclientparser_t* parser = malloc(sizeof(*parser));
    TEST_ASSERT_NOT_NULL(parser, "parser allocation should succeed");
    httpclientparser_init(parser);
    return parser;
}

// Считает количество узлов в списке query.
static size_t query_count(query_t* query) {
    size_t count = 0;
    while (query != NULL) {
        count++;
        query = query->next;
    }
    return count;
}

// Ожидаем, что разбор url завершится с кодом CLIENTPARSER_OK.
#define EXPECT_PARSE_OK(parser, url) \
    do { \
        int _r = httpclientparser_parse(parser, url); \
        TEST_ASSERT_EQUAL(CLIENTPARSER_OK, _r, "parse should succeed for: " url); \
    } while (0)

// ============================================================================
// init / free / reset
// ============================================================================

TEST(test_init_zeroes_fields) {
    TEST_SUITE("init / free / reset");
    TEST_CASE("init zeroes all output fields");

    httpclientparser_t* parser = parser_new();

    TEST_ASSERT_EQUAL(CLIENTPARSER_PROTOCOL, parser->stage, "stage should be PROTOCOL");
    TEST_ASSERT_EQUAL(0, parser->use_ssl, "use_ssl should be 0");
    TEST_ASSERT_EQUAL(0, parser->port, "port should be 0");
    TEST_ASSERT_EQUAL(0, parser->path_length, "path_length should be 0");
    TEST_ASSERT_NULL(parser->host, "host should be NULL");
    TEST_ASSERT_NULL(parser->uri, "uri should be NULL");
    TEST_ASSERT_NULL(parser->path, "path should be NULL");
    TEST_ASSERT_NULL(parser->query, "query should be NULL");

    httpclientparser_free(parser);
}

TEST(test_reset_clears_previous_result) {
    TEST_SUITE("init / free / reset");
    TEST_CASE("reset clears a previous successful parse");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://example.com/path?key=value");

    httpclientparser_reset(parser);

    TEST_ASSERT_EQUAL(CLIENTPARSER_PROTOCOL, parser->stage, "stage should reset to PROTOCOL");
    TEST_ASSERT_EQUAL(0, parser->port, "port should reset to 0");
    TEST_ASSERT_EQUAL(0, parser->use_ssl, "use_ssl should reset to 0");
    TEST_ASSERT_NULL(parser->host, "host should be NULL after reset");
    TEST_ASSERT_NULL(parser->uri, "uri should be NULL after reset");
    TEST_ASSERT_NULL(parser->path, "path should be NULL after reset");
    TEST_ASSERT_NULL(parser->query, "query should be NULL after reset");

    httpclientparser_free(parser);
}

TEST(test_free_null_is_safe) {
    TEST_SUITE("init / free / reset");
    TEST_CASE("httpclientparser_free(NULL) does not crash");

    // Regression: при отказе malloc в __httpclient_init_parser client->parser
    // остаётся NULL, и httpclient_free звал httpclientparser_free(NULL), что
    // приводило к NULL-deref в __httpclientparser_flush. free обязан быть null-safe.
    httpclientparser_free(NULL);
}

// ============================================================================
// Schemes
// ============================================================================

TEST(test_scheme_http_defaults) {
    TEST_SUITE("schemes");
    TEST_CASE("http:// sets use_ssl=0 and default port 80");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://example.com/");

    TEST_ASSERT_EQUAL(0, parser->use_ssl, "http should not use ssl");
    TEST_ASSERT_EQUAL_UINT(80, parser->port, "http default port should be 80");
    TEST_ASSERT_STR_EQUAL("example.com", parser->host, "host should match");

    httpclientparser_free(parser);
}

TEST(test_scheme_https_defaults) {
    TEST_SUITE("schemes");
    TEST_CASE("https:// sets use_ssl=1 and default port 443");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "https://example.com/");

    TEST_ASSERT_EQUAL(1, parser->use_ssl, "https should use ssl");
    TEST_ASSERT_EQUAL_UINT(443, parser->port, "https default port should be 443");
    TEST_ASSERT_STR_EQUAL("example.com", parser->host, "host should match");

    httpclientparser_free(parser);
}

TEST(test_scheme_http_clears_stale_use_ssl) {
    TEST_SUITE("schemes");
    TEST_CASE("http scheme clears a stale use_ssl flag (reuse without reset)");

    // Имитируем состояние после разбора https://: use_ssl=1. Без сброса парсер
    // разбирает http:// — set_protocol обязан явно обнулить use_ssl.
    httpclientparser_t* parser = parser_new();
    parser->use_ssl = 1;

    EXPECT_PARSE_OK(parser, "http://example.com/");

    TEST_ASSERT_EQUAL(0, parser->use_ssl, "http scheme must clear stale use_ssl");
    TEST_ASSERT_EQUAL_UINT(80, parser->port, "http default port should be 80");

    httpclientparser_free(parser);
}

TEST(test_scheme_https_after_http_via_reset) {
    TEST_SUITE("schemes");
    TEST_CASE("https after http (with reset) sets use_ssl=1");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://a.com/");
    TEST_ASSERT_EQUAL(0, parser->use_ssl, "first http should be ssl=0");

    httpclientparser_reset(parser);
    EXPECT_PARSE_OK(parser, "https://b.com/");
    TEST_ASSERT_EQUAL(1, parser->use_ssl, "https should be ssl=1");
    TEST_ASSERT_EQUAL_UINT(443, parser->port, "https port should be 443");
    TEST_ASSERT_STR_EQUAL("b.com", parser->host, "host should be from second parse");

    httpclientparser_free(parser);
}

// ============================================================================
// Host
// ============================================================================

TEST(test_host_simple) {
    TEST_SUITE("host");
    TEST_CASE("host extracted without port/path");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://example.com");

    TEST_ASSERT_STR_EQUAL("example.com", parser->host, "host should match");
    TEST_ASSERT_STR_EQUAL("/", parser->path, "path should default to /");

    httpclientparser_free(parser);
}

TEST(test_host_with_port_and_path) {
    TEST_SUITE("host");
    TEST_CASE("host excludes port and path");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://example.com:8080/api/users");

    TEST_ASSERT_STR_EQUAL("example.com", parser->host, "host should exclude port");
    TEST_ASSERT_EQUAL_UINT(8080, parser->port, "port should be 8080");
    TEST_ASSERT_STR_EQUAL("/api/users", parser->path, "path should match");

    httpclientparser_free(parser);
}

TEST(test_host_subdomain) {
    TEST_SUITE("host");
    TEST_CASE("host with multiple subdomains");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "https://a.b.c.example.com/x");

    TEST_ASSERT_STR_EQUAL("a.b.c.example.com", parser->host, "host should keep all labels");

    httpclientparser_free(parser);
}

// ============================================================================
// Port
// ============================================================================

TEST(test_port_explicit) {
    TEST_SUITE("port");
    TEST_CASE("explicit port 8080");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host:8080/");

    TEST_ASSERT_EQUAL_UINT(8080, parser->port, "port should be 8080");

    httpclientparser_free(parser);
}

TEST(test_port_max_65535) {
    TEST_SUITE("port");
    TEST_CASE("port 65535 is accepted");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host:65535/");

    TEST_ASSERT_EQUAL_UINT(65535, parser->port, "max port should be accepted");

    httpclientparser_free(parser);
}

TEST(test_port_above_65535_rejected) {
    TEST_SUITE("port");
    TEST_CASE("port 65536 is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host:65536/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PORT, r, "65536 should be BAD_PORT");

    httpclientparser_free(parser);
}

TEST(test_port_zero_rejected) {
    TEST_SUITE("port");
    TEST_CASE("port 0 is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host:0/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PORT, r, "port 0 should be BAD_PORT");

    httpclientparser_free(parser);
}

TEST(test_port_non_numeric_rejected) {
    TEST_SUITE("port");
    TEST_CASE("non-numeric port is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host:abc/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PORT, r, "non-numeric port should be BAD_PORT");

    httpclientparser_free(parser);
}

TEST(test_port_too_long_rejected) {
    TEST_SUITE("port");
    TEST_CASE("oversized port string (>5 digits) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host:123456/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PORT, r, "6-digit port should be BAD_PORT");

    httpclientparser_free(parser);
}

TEST(test_port_partial_numeric_rejected) {
    TEST_SUITE("port");
    TEST_CASE("port with trailing letters is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host:80abc/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PORT, r, "80abc should be BAD_PORT");

    httpclientparser_free(parser);
}

TEST(test_port_at_end_of_url) {
    TEST_SUITE("port");
    TEST_CASE("port without trailing path");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host:3000");

    TEST_ASSERT_EQUAL_UINT(3000, parser->port, "port should be 3000");
    TEST_ASSERT_STR_EQUAL("/", parser->path, "path should default to /");

    httpclientparser_free(parser);
}

// ============================================================================
// Path
// ============================================================================

TEST(test_path_root_only) {
    TEST_SUITE("path");
    TEST_CASE("root path /");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/");

    TEST_ASSERT_STR_EQUAL("/", parser->path, "path should be /");
    TEST_ASSERT_EQUAL_SIZE(1, parser->path_length, "path_length should be 1");

    httpclientparser_free(parser);
}

TEST(test_path_default_when_missing) {
    TEST_SUITE("path");
    TEST_CASE("missing path normalizes to /");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host");

    TEST_ASSERT_STR_EQUAL("/", parser->path, "missing path should become /");
    TEST_ASSERT_EQUAL_SIZE(1, parser->path_length, "path_length should be 1");

    httpclientparser_free(parser);
}

TEST(test_path_nested) {
    TEST_SUITE("path");
    TEST_CASE("nested path segments");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/a/b/c");

    TEST_ASSERT_STR_EQUAL("/a/b/c", parser->path, "path should match");
    TEST_ASSERT_EQUAL_SIZE(6, parser->path_length, "path_length should be 6");

    httpclientparser_free(parser);
}

TEST(test_path_percent_encoded) {
    TEST_SUITE("path");
    TEST_CASE("percent-encoded path is decoded");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/%2Fpath");

    // "/%2Fpath" декодируется в "//path": ведущий '/' + '%2F'->'/' + "path".
    TEST_ASSERT_EQUAL_SIZE(6, parser->path_length, "decoded path length should be 6");
    TEST_ASSERT_EQUAL('/', parser->path[0], "first char is /");
    TEST_ASSERT_EQUAL('/', parser->path[1], "%2F decodes to /");
    TEST_ASSERT_STR_EQUAL("//path", parser->path, "decoded path string");

    httpclientparser_free(parser);
}

TEST(test_path_percent_encoded_space) {
    TEST_SUITE("path");
    TEST_CASE("%20 decodes to space");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/a%20b");

    TEST_ASSERT_STR_EQUAL("/a b", parser->path, "%20 should decode to space");
    TEST_ASSERT_EQUAL_SIZE(4, parser->path_length, "decoded length is 4");

    httpclientparser_free(parser);
}

TEST(test_path_traversal_rejected) {
    TEST_SUITE("path");
    TEST_CASE("path traversal /../ is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host/../etc");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_URI, r, "traversal /../ should be BAD_URI");

    httpclientparser_free(parser);
}

TEST(test_path_traversal_mid_rejected) {
    TEST_SUITE("path");
    TEST_CASE("mid-path traversal /a/../b is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host/a/../b");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_URI, r, "mid traversal should be BAD_URI");

    httpclientparser_free(parser);
}

TEST(test_path_traversal_trailing_rejected) {
    TEST_SUITE("path");
    TEST_CASE("trailing /.. is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host/a/..");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_URI, r, "trailing /.. should be BAD_URI");

    httpclientparser_free(parser);
}

TEST(test_path_encoded_traversal_rejected) {
    TEST_SUITE("path");
    TEST_CASE("encoded traversal %2e%2e/ is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host/%2e%2e/x");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_URI, r, "encoded traversal should be BAD_URI");

    httpclientparser_free(parser);
}

TEST(test_path_dotdot_inside_segment_ok) {
    TEST_SUITE("path");
    TEST_CASE("literal '..' inside a segment is not traversal");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/a..b");

    TEST_ASSERT_STR_EQUAL("/a..b", parser->path, "non-traversal dots allowed");

    httpclientparser_free(parser);
}

// ============================================================================
// Query string
// ============================================================================

TEST(test_query_single_param) {
    TEST_SUITE("query");
    TEST_CASE("single key=value");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/?key=value");

    TEST_ASSERT_EQUAL_SIZE(1, query_count(parser->query), "one query param");
    TEST_ASSERT_STR_EQUAL("key", parser->query->key, "key");
    TEST_ASSERT_STR_EQUAL("value", parser->query->value, "value");

    httpclientparser_free(parser);
}

TEST(test_query_multiple_params) {
    TEST_SUITE("query");
    TEST_CASE("multiple key=value pairs");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/?a=1&b=2&c=3");

    TEST_ASSERT_EQUAL_SIZE(3, query_count(parser->query), "three params");
    TEST_ASSERT_STR_EQUAL("a", parser->query->key, "first key");
    TEST_ASSERT_STR_EQUAL("1", parser->query->value, "first value");
    TEST_ASSERT_STR_EQUAL("c", parser->query->next->next->key, "third key");

    httpclientparser_free(parser);
}

TEST(test_query_encoded_value) {
    TEST_SUITE("query");
    TEST_CASE("percent-encoded value is decoded");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/?q=%3Cscript%3E");

    TEST_ASSERT_STR_EQUAL("q", parser->query->key, "key");
    TEST_ASSERT_STR_EQUAL("<script>", parser->query->value, "value decoded");

    httpclientparser_free(parser);
}

TEST(test_query_plus_decodes_space) {
    TEST_SUITE("query");
    TEST_CASE("+ decodes to space in query value");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/?name=hello+world");

    TEST_ASSERT_STR_EQUAL("hello world", parser->query->value, "+ -> space");

    httpclientparser_free(parser);
}

TEST(test_fragment_dropped) {
    TEST_SUITE("query");
    TEST_CASE("fragment is dropped");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/path?a=1#section");

    TEST_ASSERT_EQUAL_SIZE(1, query_count(parser->query), "fragment not parsed as query");
    TEST_ASSERT_STR_EQUAL("a", parser->query->key, "key before fragment");
    TEST_ASSERT_STR_EQUAL("1", parser->query->value, "value before fragment");
    TEST_ASSERT_STR_EQUAL("/path", parser->path, "path stops before fragment");

    httpclientparser_free(parser);
}

TEST(test_query_without_path) {
    TEST_SUITE("query");
    TEST_CASE("query without path normalizes path to /");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host?x=1");

    TEST_ASSERT_STR_EQUAL("/", parser->path, "empty path becomes /");
    TEST_ASSERT_EQUAL_SIZE(1, query_count(parser->query), "one param");
    TEST_ASSERT_STR_EQUAL("x", parser->query->key, "key");

    httpclientparser_free(parser);
}

// ============================================================================
// URI reconstruction
// ============================================================================

TEST(test_uri_with_path_and_query) {
    TEST_SUITE("uri");
    TEST_CASE("uri built from decoded path + query");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/path?q=1");

    TEST_ASSERT_STR_EQUAL("/path?q=1", parser->uri, "uri should combine path and query");

    httpclientparser_free(parser);
}

TEST(test_uri_without_query) {
    TEST_SUITE("uri");
    TEST_CASE("uri without query is just the path");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/path");

    TEST_ASSERT_STR_EQUAL("/path", parser->uri, "uri equals path when no query");

    httpclientparser_free(parser);
}

TEST(test_uri_root) {
    TEST_SUITE("uri");
    TEST_CASE("uri for root");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/");

    TEST_ASSERT_STR_EQUAL("/", parser->uri, "root uri");

    httpclientparser_free(parser);
}

// ============================================================================
// move_* (ownership transfer)
// ============================================================================

TEST(test_move_host_transfers_ownership) {
    TEST_SUITE("move_*");
    TEST_CASE("move_host returns host and NULLs the field");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://example.com/");

    char* host = httpclientparser_move_host(parser);
    TEST_ASSERT_STR_EQUAL("example.com", host, "moved host");
    TEST_ASSERT_NULL(parser->host, "host NULL after move");

    free(host);
    httpclientparser_free(parser);
}

TEST(test_move_all_fields) {
    TEST_SUITE("move_*");
    TEST_CASE("move all fields then free is safe");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "https://host:9090/path?a=1&b=2");

    TEST_ASSERT_EQUAL(1, httpclientparser_move_use_ssl(parser), "ssl flag for https");

    unsigned short port = httpclientparser_move_port(parser);
    TEST_ASSERT_EQUAL_UINT(9090, port, "moved port");

    char* host = httpclientparser_move_host(parser);
    char* uri = httpclientparser_move_uri(parser);
    char* path = httpclientparser_move_path(parser);
    query_t* query = httpclientparser_move_query(parser);
    query_t* last_query = httpclientparser_move_last_query(parser);

    TEST_ASSERT_STR_EQUAL("host", host, "moved host value");
    TEST_ASSERT_STR_EQUAL("/path?a=1&b=2", uri, "moved uri value");
    TEST_ASSERT_STR_EQUAL("/path", path, "moved path value");
    TEST_ASSERT_NOT_NULL(query, "moved query head");
    TEST_ASSERT_NOT_NULL(last_query, "moved query tail");
    // "a=1&b=2" -> 2 узла: query (a=1) -> query->next (b=2) -> NULL.
    // last_query указывает на хвост, т.е. на второй узел.
    TEST_ASSERT_EQUAL((intptr_t)query->next, (intptr_t)last_query, "tail is last node");

    // После move_* владение передано наружу; поля обнулены, поэтому
    // последующий httpclientparser_free не должен делать double-free.
    TEST_ASSERT_NULL(parser->host, "host NULL after move");
    TEST_ASSERT_NULL(parser->uri, "uri NULL after move");
    TEST_ASSERT_NULL(parser->path, "path NULL after move");
    TEST_ASSERT_NULL(parser->query, "query NULL after move");
    TEST_ASSERT_NULL(parser->last_query, "last_query NULL after move");

    free(host);
    free(uri);
    free(path);
    queries_free(query);
    httpclientparser_free(parser);
}

TEST(test_move_use_ssl_http_is_zero) {
    TEST_SUITE("move_*");
    TEST_CASE("move_use_ssl returns 0 for http");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "http://host/");

    TEST_ASSERT_EQUAL(0, httpclientparser_move_use_ssl(parser), "http ssl flag is 0");

    httpclientparser_free(parser);
}

// ============================================================================
// Error cases
// ============================================================================

TEST(test_null_url_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("NULL url is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, NULL);

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PROTOCOL, r, "NULL url should be BAD_PROTOCOL");

    httpclientparser_free(parser);
}

TEST(test_empty_url_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("empty url is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PROTOCOL, r, "empty url should be BAD_PROTOCOL");

    httpclientparser_free(parser);
}

TEST(test_incomplete_scheme_only_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("scheme without separator (http:) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http:");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PROTOCOL_SEPARATOR, r, "'http:' should be BAD_PROTOCOL_SEPARATOR");

    httpclientparser_free(parser);
}

TEST(test_incomplete_one_slash_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("scheme with one slash (http:/) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http:/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PROTOCOL_SEPARATOR, r, "'http:/' should be BAD_PROTOCOL_SEPARATOR");

    httpclientparser_free(parser);
}

TEST(test_incomplete_empty_host_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("scheme with empty host (http://) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_HOST, r, "'http://' should be BAD_HOST");

    httpclientparser_free(parser);
}

TEST(test_https_empty_host_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("https with empty host (https://) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "https://");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_HOST, r, "'https://' should be BAD_HOST");

    httpclientparser_free(parser);
}

TEST(test_host_empty_port_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("host with empty port (http://host:) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://host:");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PORT, r, "'http://host:' should be BAD_PORT");

    httpclientparser_free(parser);
}

TEST(test_empty_host_with_port_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("empty host before port (http://:80) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://:80/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_HOST, r, "'http://:80' should be BAD_HOST");

    httpclientparser_free(parser);
}

TEST(test_empty_host_with_query_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("empty host before query (http://?x=1) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "http://?x=1");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_HOST, r, "'http://?x=1' should be BAD_HOST");

    httpclientparser_free(parser);
}

TEST(test_unknown_scheme_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("unknown scheme (ftp://) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "ftp://host/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PROTOCOL, r, "ftp should be BAD_PROTOCOL");

    httpclientparser_free(parser);
}

TEST(test_scheme_no_separator_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("scheme without :// (httpXhost) is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "httpXhost");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PROTOCOL, r, "no separator should be BAD_PROTOCOL");

    httpclientparser_free(parser);
}

TEST(test_too_long_scheme_rejected) {
    TEST_SUITE("errors");
    TEST_CASE("scheme longer than 5 chars is rejected");

    httpclientparser_t* parser = parser_new();
    int r = httpclientparser_parse(parser, "httpsx://host/");

    TEST_ASSERT_EQUAL(CLIENTPARSER_BAD_PROTOCOL, r, "6-char scheme should be BAD_PROTOCOL");

    httpclientparser_free(parser);
}

// ============================================================================
// Relative URL (no scheme)
// ============================================================================

TEST(test_relative_root_path) {
    TEST_SUITE("relative URL");
    TEST_CASE("relative / parses as path only");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "/");

    TEST_ASSERT_NULL(parser->host, "relative URL has no host");
    TEST_ASSERT_STR_EQUAL("/", parser->path, "path is /");

    httpclientparser_free(parser);
}

TEST(test_relative_nested_path) {
    TEST_SUITE("relative URL");
    TEST_CASE("relative path with segments");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "/api/v1/users");

    TEST_ASSERT_NULL(parser->host, "relative URL has no host");
    TEST_ASSERT_STR_EQUAL("/api/v1/users", parser->path, "path segments");

    httpclientparser_free(parser);
}

TEST(test_relative_path_with_query) {
    TEST_SUITE("relative URL");
    TEST_CASE("relative path with query");

    httpclientparser_t* parser = parser_new();
    EXPECT_PARSE_OK(parser, "/search?q=42");

    TEST_ASSERT_STR_EQUAL("/search", parser->path, "path");
    TEST_ASSERT_EQUAL_SIZE(1, query_count(parser->query), "one param");
    TEST_ASSERT_STR_EQUAL("/search?q=42", parser->uri, "uri");

    httpclientparser_free(parser);
}

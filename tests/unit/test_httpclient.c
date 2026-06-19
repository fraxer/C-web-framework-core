#include "framework.h"
#include "httpclient.h"

#include <string.h>

#include "route.h"

// ============================================================================
// init / free
// ============================================================================

TEST(test_init_creates_client) {
    TEST_SUITE("init / free");
    TEST_CASE("init builds a client with parsed url, method and timeout");

    httpclient_t* client = httpclient_init(ROUTE_GET, "http://example.com/", 5);
    TEST_ASSERT_NOT_NULL(client, "client should be created for a valid url");

    TEST_ASSERT_EQUAL(ROUTE_GET, client->method, "method preserved");
    TEST_ASSERT_EQUAL(5, client->timeout, "timeout preserved");
    TEST_ASSERT_STR_EQUAL("example.com", client->host, "host parsed from url");
    TEST_ASSERT_EQUAL_UINT(80, client->port, "http default port 80");
    TEST_ASSERT_EQUAL(0, client->use_ssl, "http is not ssl");
    TEST_ASSERT_NOT_NULL(client->ssl_ctx, "ssl_ctx created");
    TEST_ASSERT_NOT_NULL(client->request, "request created");
    TEST_ASSERT_NOT_NULL(client->response, "response created");

    client->free(client);
}

TEST(test_init_https_sets_ssl_defaults) {
    TEST_SUITE("init / free");
    TEST_CASE("https url sets use_ssl and default port 443");

    httpclient_t* client = httpclient_init(ROUTE_GET, "https://secure.example.com/", 0);
    TEST_ASSERT_NOT_NULL(client, "client created");

    TEST_ASSERT_EQUAL(1, client->use_ssl, "https uses ssl");
    TEST_ASSERT_EQUAL_UINT(443, client->port, "https default port 443");
    TEST_ASSERT_STR_EQUAL("secure.example.com", client->host, "host parsed");

    // timeout==0 keeps the default (10), it is not overwritten.
    TEST_ASSERT_EQUAL(10, client->timeout, "timeout 0 keeps default 10");

    client->free(client);
}

// Regression: при отказе malloc в __httpclient_init_parser parser остаётся NULL,
// и старый код звал httpclientparser_free(NULL) -> NULL-deref. Также неверный URL
// должен возвращать NULL, а не падать в free-path.
TEST(test_init_invalid_url_returns_null) {
    TEST_SUITE("init / free");
    TEST_CASE("init rejects an invalid url and returns NULL without crashing");

    httpclient_t* client = httpclient_init(ROUTE_GET, "ftp://example.com/", 5);
    TEST_ASSERT_NULL(client, "unsupported scheme must yield NULL");

    // Ещё один reject-путь: пустой host.
    httpclient_t* client2 = httpclient_init(ROUTE_GET, "http://", 5);
    TEST_ASSERT_NULL(client2, "empty host must yield NULL");
}

TEST(test_free_is_safe_without_connection) {
    TEST_SUITE("init / free");
    TEST_CASE("free on a freshly created client does not crash or leak");

    httpclient_t* client = httpclient_init(ROUTE_GET, "http://example.com/", 5);
    TEST_ASSERT_NOT_NULL(client, "client created");

    // connection остаётся NULL до первого send — free не должен на это падать.
    TEST_ASSERT_NULL(client->connection, "no connection before send");
    client->free(client);
}

// ============================================================================
// TLS verify defaults + setter
// ============================================================================

TEST(test_default_verify_is_on) {
    TEST_SUITE("TLS verify");
    TEST_CASE("verify_peer defaults to ON, ca_path to NULL");

    httpclient_t* client = httpclient_init(ROUTE_GET, "http://example.com/", 5);
    TEST_ASSERT_NOT_NULL(client, "client created");

    TEST_ASSERT_EQUAL(1, client->verify_peer, "verification must be enabled by default");
    TEST_ASSERT_NULL(client->ca_path, "no explicit CA path by default");

    client->free(client);
}

TEST(test_set_verify_toggles_flag) {
    TEST_SUITE("TLS verify");
    TEST_CASE("set_verify toggles verify_peer");

    httpclient_t* client = httpclient_init(ROUTE_GET, "http://example.com/", 5);
    TEST_ASSERT_NOT_NULL(client, "client created");

    client->set_verify(client, 0, NULL);
    TEST_ASSERT_EQUAL(0, client->verify_peer, "verify disabled");

    client->set_verify(client, 1, NULL);
    TEST_ASSERT_EQUAL(1, client->verify_peer, "verify re-enabled");

    client->free(client);
}

TEST(test_set_verify_stores_ca_path) {
    TEST_SUITE("TLS verify");
    TEST_CASE("set_verify stores and owns a copy of ca_path");

    httpclient_t* client = httpclient_init(ROUTE_GET, "http://example.com/", 5);
    TEST_ASSERT_NOT_NULL(client, "client created");

    // Реальный путь CA-пучка (Ubuntu/Debian) — чтобы configure_ssl_ctx
    // не логировал ошибку при load_verify_locations.
    const char* ca = "/etc/ssl/certs/ca-certificates.crt";
    client->set_verify(client, 1, ca);
    TEST_ASSERT_NOT_NULL(client->ca_path, "ca_path stored");
    TEST_ASSERT_STR_EQUAL(ca, client->ca_path, "ca_path value matches");

    // free должен освободить ca_path без утечки (ASan проверит).
    client->free(client);
}

// ============================================================================
// set_url / set_method
// ============================================================================

TEST(test_set_url_replaces_host) {
    TEST_SUITE("set_url / set_method");
    TEST_CASE("set_url on an existing client reparses host/port");

    httpclient_t* client = httpclient_init(ROUTE_GET, "http://example.com/", 5);
    TEST_ASSERT_NOT_NULL(client, "client created");

    int ok = client->set_url(client, "http://other.example.com:8080/api");
    TEST_ASSERT_EQUAL(1, ok, "set_url should succeed");
    TEST_ASSERT_STR_EQUAL("other.example.com", client->host, "host replaced");
    TEST_ASSERT_EQUAL_UINT(8080, client->port, "port replaced");

    client->free(client);
}

TEST(test_set_method_changes_method) {
    TEST_SUITE("set_url / set_method");
    TEST_CASE("set_method updates the request method");

    httpclient_t* client = httpclient_init(ROUTE_GET, "http://example.com/", 5);
    TEST_ASSERT_NOT_NULL(client, "client created");
    TEST_ASSERT_EQUAL(ROUTE_GET, client->method, "starts as GET");

    client->set_method(client, ROUTE_POST);
    TEST_ASSERT_EQUAL(ROUTE_POST, client->method, "switched to POST");

    client->set_method(client, ROUTE_HEAD);
    TEST_ASSERT_EQUAL(ROUTE_HEAD, client->method, "switched to HEAD");

    client->free(client);
}

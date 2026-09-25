/*
 * Unit tests for protocols/websocket/websocketsswitch.c: the server side of
 * the WebSocket opening handshake (RFC 6455 §4.2).
 *
 * switch_to_websockets() is what an application's handler calls to accept an
 * upgrade, so everything it reads comes straight from the client's request.
 * It used to copy Sec-WebSocket-Key into a 128-byte stack buffer with strcpy
 * and append the GUID with strcat: a key longer than 91 bytes overflowed the
 * stack. It also accepted any Upgrade, Connection, version and key, and
 * answered a request missing them with 200. These cases pin the handshake the
 * RFC describes instead.
 */

#include "framework.h"
#include "connection_s.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "websocketsswitch.h"

#include <string.h>

typedef struct {
    connection_t connection;
    connection_server_ctx_t server_ctx;
    httpctx_t ctx;
} ws_fixture_t;

static int fixture_setup(ws_fixture_t* fx) {
    memset(fx, 0, sizeof(*fx));
    fx->connection.ctx = (connection_ctx_t*)&fx->server_ctx;
    fx->ctx.request = httprequest_create(NULL);
    fx->ctx.response = httpresponse_create(&fx->connection);
    return fx->ctx.request != NULL && fx->ctx.response != NULL;
}

static void fixture_teardown(ws_fixture_t* fx) {
    if (fx->server_ctx.switch_to_protocol.data_free != NULL)
        fx->server_ctx.switch_to_protocol.data_free(fx->server_ctx.switch_to_protocol.data);
    if (fx->ctx.request != NULL) httprequest_free(fx->ctx.request);
    if (fx->ctx.response != NULL) httpresponse_free(fx->ctx.response);
}

/* A handshake as RFC 6455 §1.3 shows it; NULL leaves a field out. */
static int add_handshake(ws_fixture_t* fx, const char* upgrade, const char* connection,
                         const char* version, const char* key) {
    httprequest_t* rq = fx->ctx.request;
    if (upgrade != NULL && rq->add_header(rq, "Upgrade", upgrade) != 0) return 0;
    if (connection != NULL && rq->add_header(rq, "Connection", connection) != 0) return 0;
    if (version != NULL && rq->add_header(rq, "Sec-WebSocket-Version", version) != 0) return 0;
    if (key != NULL && rq->add_header(rq, "Sec-WebSocket-Key", key) != 0) return 0;
    return 1;
}

static int header_is(httpresponse_t* response, const char* key, const char* want) {
    const http_header_t* h = response->get_header(response, key);
    return h != NULL && h->value_length == strlen(want) && memcmp(h->value, want, h->value_length) == 0;
}

#define SAMPLE_KEY    "dGhlIHNhbXBsZSBub25jZQ=="
#define SAMPLE_ACCEPT "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

TEST(test_ws_switch_accepts_rfc_sample) {
    TEST_SUITE("websocketsswitch: handshake");
    TEST_CASE("the RFC 6455 §1.3 sample key yields the sample accept value");

    ws_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");
    TEST_REQUIRE(add_handshake(&fx, "websocket", "Upgrade", "13", SAMPLE_KEY), "headers");

    switch_to_websockets(&fx.ctx);

    TEST_ASSERT_EQUAL(101, fx.ctx.response->status_code, "101 Switching Protocols");
    TEST_ASSERT(header_is(fx.ctx.response, "Sec-WebSocket-Accept", SAMPLE_ACCEPT), "accept value");
    TEST_ASSERT_NOT_NULL(fx.server_ctx.switch_to_protocol.fn, "the switch is armed");

    fixture_teardown(&fx);
}

TEST(test_ws_switch_accepts_token_lists_and_case) {
    TEST_SUITE("websocketsswitch: handshake");
    TEST_CASE("Connection is a token list, and both tokens are case-insensitive");

    /* Firefox sends "Connection: keep-alive, Upgrade" (RFC 6455 §4.1 item 6:
     * the field includes the token, it need not be all of it). */
    ws_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");
    TEST_REQUIRE(add_handshake(&fx, "WebSocket", "keep-alive, upgrade", "13", SAMPLE_KEY), "headers");

    switch_to_websockets(&fx.ctx);

    TEST_ASSERT_EQUAL(101, fx.ctx.response->status_code, "101 Switching Protocols");
    TEST_ASSERT(header_is(fx.ctx.response, "Sec-WebSocket-Accept", SAMPLE_ACCEPT), "accept value");

    fixture_teardown(&fx);
}

TEST(test_ws_switch_long_key_is_refused) {
    TEST_SUITE("websocketsswitch: handshake");
    TEST_CASE("an overlong Sec-WebSocket-Key is a 400, not a stack overflow");

    char key[400];
    memset(key, 'A', sizeof key - 1);
    key[sizeof key - 1] = '\0';

    ws_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");
    TEST_REQUIRE(add_handshake(&fx, "websocket", "Upgrade", "13", key), "headers");

    switch_to_websockets(&fx.ctx);

    TEST_ASSERT_EQUAL(400, fx.ctx.response->status_code, "400 Bad Request");
    TEST_ASSERT_NULL(fx.server_ctx.switch_to_protocol.fn, "no switch");

    fixture_teardown(&fx);
}

TEST(test_ws_switch_refuses_malformed_handshakes) {
    TEST_SUITE("websocketsswitch: handshake");
    TEST_CASE("RFC 6455 §4.2.1: anything else is refused with 400 and no switch");

    static const struct {
        const char *upgrade, *connection, *version, *key, *what;
    } cases[] = {
        { NULL,        "Upgrade",    "13", SAMPLE_KEY, "no Upgrade" },
        { "websocket", NULL,         "13", SAMPLE_KEY, "no Connection" },
        { "websocket", "Upgrade",    "13", NULL,       "no key" },
        { "h2c",       "Upgrade",    "13", SAMPLE_KEY, "Upgrade to something else" },
        { "websocket", "keep-alive", "13", SAMPLE_KEY, "Connection without upgrade" },
        { "websocket", "Upgrade",    "13", "c2hvcnQ=", "a key that is not 16 bytes" },
        { "websocket", "Upgrade",    "13", "dGhlIHNhbXBsZSBub25jZQ!!", "a key that is not base64" },
        { "websocket", "Upgrade",    "13", "", "an empty key" },
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ws_fixture_t fx;
        TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");
        TEST_REQUIRE(add_handshake(&fx, cases[i].upgrade, cases[i].connection,
                                   cases[i].version, cases[i].key), "headers");

        switch_to_websockets(&fx.ctx);

        TEST_ASSERT_EQUAL(400, fx.ctx.response->status_code, cases[i].what);
        TEST_ASSERT_NULL(fx.server_ctx.switch_to_protocol.fn, cases[i].what);

        fixture_teardown(&fx);
    }
}

TEST(test_ws_switch_unsupported_version_is_426) {
    TEST_SUITE("websocketsswitch: handshake");
    TEST_CASE("RFC 6455 §4.2.2: a version other than 13 gets 426 and the version the server speaks");

    static const char* const versions[] = { "8", "14", "", "13x", NULL };
    for (size_t i = 0; i < sizeof versions / sizeof versions[0]; i++) {
        ws_fixture_t fx;
        TEST_REQUIRE(fixture_setup(&fx), "fixture should be created");
        TEST_REQUIRE(add_handshake(&fx, "websocket", "Upgrade", versions[i], SAMPLE_KEY), "headers");

        switch_to_websockets(&fx.ctx);

        const char* what = versions[i] != NULL ? versions[i] : "(none)";
        TEST_ASSERT_EQUAL(426, fx.ctx.response->status_code, what);
        TEST_ASSERT(header_is(fx.ctx.response, "Sec-WebSocket-Version", "13"), what);
        TEST_ASSERT_NULL(fx.server_ctx.switch_to_protocol.fn, what);

        fixture_teardown(&fx);
    }
}

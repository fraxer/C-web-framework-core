#include "framework.h"
#include "ws_session.h"
#include "websocketsparser.h"
#include "websocketsprotocoldefault.h"
#include "connection_s.h"
#include <string.h>

static int destroyed;
static void destroy_payload(void* data) { (*(int*)data)++; }

TEST(test_ws_session_survives_parser_and_request_lifetimes) {
    TEST_SUITE("ws session");
    TEST_CASE("closing transport retains payload until final dispatched request finishes");
    destroyed = 0;
    char buffer[64];
    connection_server_ctx_t ctx = {0};
    connection_t connection = {.ctx = &ctx, .buffer = buffer, .buffer_size = sizeof buffer};
    websocketsparser_t* parser = websocketsparser_create(&connection, websockets_protocol_default_create);
    TEST_REQUIRE_NOT_NULL(parser, "parser");
    parser->session = ws_session_create(&destroyed, destroy_payload);
    TEST_REQUIRE_NOT_NULL(parser->session, "session");
    websocketsrequest_t* retained = NULL;
    const unsigned char frame[] = {0x82, 0x81, 0, 0, 0, 0, 'a'};
    for (int i = 0; i < 2; i++) {
        memcpy(buffer, frame, sizeof frame);
        websocketsparser_set_bytes_readed(parser, sizeof frame);
        parser->pos = parser->pos_start = 0;
        TEST_ASSERT_EQUAL(WSPARSER_COMPLETE, websocketsparser_run(parser), "complete message");
        TEST_REQUIRE_NOT_NULL(parser->request, "request");
        TEST_ASSERT(ws_session_data(parser->request->session) == &destroyed, "authenticated payload");
        parser->request->base.reset(parser->request);
        TEST_ASSERT(ws_session_data(parser->request->session) == &destroyed, "message reset retains session");
        if (retained) websocketsrequest_free(retained);
        retained = parser->request;
        parser->request = NULL;
        websocketsparser_reset(parser);
    }
    websocketsparser_free(parser);
    TEST_ASSERT_EQUAL(0, destroyed, "in-flight request keeps payload alive");
    websocketsrequest_free(retained);
    TEST_ASSERT_EQUAL(1, destroyed, "destroy exactly once");
}

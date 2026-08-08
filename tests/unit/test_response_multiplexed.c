#include "framework.h"

#include "connection_s.h"
#include "httpresponse.h"

#include <string.h>

/* Which response features a protocol is allowed to use.
 *
 * Trailers and early hints need a protocol that can carry a second field
 * section and an interim response: HTTP/2 and HTTP/3, not HTTP/1.1. The
 * response API refuses them otherwise -- loudly, because a silently dropped
 * gRPC status is debugged from the client side for a day.
 *
 * The responses here are all built with the plain httpresponse_create: what is
 * under test is the API's protocol check, which reads the connection, not the
 * filter chain the response happens to carry. Using the h3 chain would also
 * make these cases unbuildable without HTTP/3, where filters_create_h3 has
 * nothing to return.
 *
 * These cases exist because that refusal was written as "is this HTTP/2", and
 * an HTTP/3 connection is not. Every early hint on h3 was dropped while the h3
 * write path sat there able to send them, and nothing said so: the handler's
 * add_early_hint returned 0 and the response looked perfectly normal without
 * one. Only asking a real server for a 103 found it. */

typedef struct {
    connection_t            connection;
    connection_server_ctx_t ctx;
} response_fixture_t;

/* `transport` is CONN_TRANSPORT_TCP or CONN_TRANSPORT_QUIC; `http2` is the
 * ctx bit, which is meaningful only over TCP. */
static void fixture_init(response_fixture_t* f, int transport, int http2) {
    memset(f, 0, sizeof * f);

    f->connection.transport = (unsigned)transport;
    f->ctx.is_http2 = http2 ? 1 : 0;
    f->connection.ctx = &f->ctx;
}

TEST(test_response_trailers_by_protocol) {
    TEST_SUITE("response-multiplexed");

    response_fixture_t f;

    TEST_CASE("HTTP/2 accepts trailers");
    fixture_init(&f, CONN_TRANSPORT_TCP, 1);
    httpresponse_t* r = httpresponse_create(&f.connection);
    TEST_ASSERT(r->add_trailer(r, "grpc-status", "0") == 1, "accepted");
    TEST_ASSERT(r->trailer_ != NULL, "and staged");
    httpresponse_free(r);

    TEST_CASE("HTTP/3 accepts trailers too");
    /* A second HEADERS frame before the FIN (RFC 9114 §4.1) -- the same
     * capability by a different name. */
    fixture_init(&f, CONN_TRANSPORT_QUIC, 0);
    r = httpresponse_create(&f.connection);
    TEST_ASSERT(r->add_trailer(r, "grpc-status", "0") == 1, "accepted");
    TEST_ASSERT(r->trailer_ != NULL, "and staged");
    httpresponse_free(r);

    TEST_CASE("HTTP/1.1 refuses them");
    /* It would need chunked encoding and a Trailer header, and the one thing
     * that wants trailers does not speak HTTP/1.1 anyway. */
    fixture_init(&f, CONN_TRANSPORT_TCP, 0);
    r = httpresponse_create(&f.connection);
    TEST_ASSERT(r->add_trailer(r, "grpc-status", "0") == 0, "refused");
    TEST_ASSERT(r->trailer_ == NULL, "nothing staged");
    httpresponse_free(r);
}

TEST(test_response_early_hints_by_protocol) {
    TEST_SUITE("response-multiplexed");

    response_fixture_t f;

    TEST_CASE("HTTP/2 accepts early hints");
    fixture_init(&f, CONN_TRANSPORT_TCP, 1);
    httpresponse_t* r = httpresponse_create(&f.connection);
    TEST_ASSERT(r->add_early_hint(r, "link", "</a.css>; rel=preload") == 1, "accepted");
    TEST_ASSERT(r->early_hint_ != NULL, "and staged");
    httpresponse_free(r);

    TEST_CASE("HTTP/3 accepts early hints too");
    fixture_init(&f, CONN_TRANSPORT_QUIC, 0);
    r = httpresponse_create(&f.connection);
    TEST_ASSERT(r->add_early_hint(r, "link", "</a.css>; rel=preload") == 1, "accepted");
    TEST_ASSERT(r->early_hint_ != NULL, "and staged");
    httpresponse_free(r);

    TEST_CASE("HTTP/1.1 refuses them");
    fixture_init(&f, CONN_TRANSPORT_TCP, 0);
    r = httpresponse_create(&f.connection);
    TEST_ASSERT(r->add_early_hint(r, "link", "</a.css>; rel=preload") == 0, "refused");
    TEST_ASSERT(r->early_hint_ == NULL, "nothing staged");
    httpresponse_free(r);
}

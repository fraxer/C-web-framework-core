#include "framework.h"

#include "connection_s.h"
#include "httpfields.h"
#include "httpresponse.h"
#include "server.h"

#include <stdlib.h>
#include <string.h>

/* Advertising HTTP/3 over the protocols that are not it (RFC 7838,
 * docs/http3/07-integration.md §2).
 *
 * The connection and vhost are built by hand: httpfields_apply_alt_svc reads
 * exactly two things -- the response's status and the vhost's precomputed value
 * -- and standing up a listener to supply them would test the loader instead. */

typedef struct {
    connection_t             connection;
    connection_server_ctx_t  ctx;
    server_t                 server;
} altsvc_fixture_t;

static void fixture_init(altsvc_fixture_t* f, int enabled, int alt_svc) {
    memset(f, 0, sizeof * f);

    f->server.http3.enabled = enabled;
    f->server.http3.alt_svc = alt_svc;
    f->server.http3.port = 443;
    f->server.http3.alt_svc_max_age = 86400;
    memcpy(f->server.http3.alt_svc_value, "h3=\":443\"; ma=86400", 19);
    f->server.http3.alt_svc_length = 19;

    f->ctx.server = &f->server;
    f->connection.ctx = &f->ctx;
}

/* NULL-safe: a failed TEST_ASSERT records and carries on rather than aborting,
 * so every dereference below has to survive a missing header. */
static int alt_svc_is(const http_header_t* h, const char* want) {
    return h != NULL && h->value_length == strlen(want) &&
           memcmp(h->value, want, h->value_length) == 0;
}

static const http_header_t* alt_svc_of(const httpresponse_t* r) {
    for (const http_header_t* h = r->header_; h != NULL; h = h->next)
        if (h->key_length == 7 && strncasecmp(h->key, "Alt-Svc", 7) == 0) return h;

    return NULL;
}

TEST(test_altsvc_applies) {
    TEST_SUITE("alt-svc");

    altsvc_fixture_t f;
    fixture_init(&f, 1, 1);

    TEST_CASE("a vhost with HTTP/3 enabled advertises it");
    httpresponse_t* r = httpresponse_create(&f.connection);
    r->status_code = 200;
    httpfields_apply_alt_svc(r);

    const http_header_t* h = alt_svc_of(r);
    TEST_ASSERT(h != NULL, "header added");
    TEST_ASSERT(alt_svc_is(h, "h3=\":443\"; ma=86400"), "the precomputed value, verbatim");
    httpresponse_free(r);

    TEST_CASE("applying twice adds one header, not two");
    /* The write filter runs its header stage on every turn, so this is not a
     * hypothetical: a response resumed after CWF_EVENT_AGAIN passes here again. */
    r = httpresponse_create(&f.connection);
    r->status_code = 200;
    httpfields_apply_alt_svc(r);
    httpfields_apply_alt_svc(r);

    size_t count = 0;
    for (const http_header_t* it = r->header_; it != NULL; it = it->next)
        if (it->key_length == 7 && strncasecmp(it->key, "Alt-Svc", 7) == 0) count++;
    TEST_ASSERT(count == 1, "exactly one");
    httpresponse_free(r);

    TEST_CASE("an interim 1xx carries nothing");
    /* A 1xx is not the final response: its fields may be discarded, and the
     * final response repeats them anyway. */
    r = httpresponse_create(&f.connection);
    r->status_code = 103;
    httpfields_apply_alt_svc(r);
    TEST_ASSERT(alt_svc_of(r) == NULL, "no header on 103");
    r->status_code = 100;
    httpfields_apply_alt_svc(r);
    TEST_ASSERT(alt_svc_of(r) == NULL, "nor on 100");
    httpresponse_free(r);

    TEST_CASE("a handler's own Alt-Svc wins");
    r = httpresponse_create(&f.connection);
    r->status_code = 200;
    r->add_header(r, "Alt-Svc", "h3=\"alt.example:8443\"");
    httpfields_apply_alt_svc(r);

    TEST_ASSERT(alt_svc_is(alt_svc_of(r), "h3=\"alt.example:8443\""),
                "the handler's value is untouched");
    httpresponse_free(r);
}

TEST(test_altsvc_disabled) {
    TEST_SUITE("alt-svc");

    TEST_CASE("HTTP/3 off: nothing to advertise");
    altsvc_fixture_t f;
    fixture_init(&f, 0, 1);
    httpresponse_t* r = httpresponse_create(&f.connection);
    r->status_code = 200;
    httpfields_apply_alt_svc(r);
    TEST_ASSERT(alt_svc_of(r) == NULL, "no header");
    httpresponse_free(r);

    TEST_CASE("HTTP/3 on but advertising turned off");
    /* The case where something in front -- a load balancer, a CDN -- announces
     * the alternative instead, and two announcements would disagree. */
    fixture_init(&f, 1, 0);
    r = httpresponse_create(&f.connection);
    r->status_code = 200;
    httpfields_apply_alt_svc(r);
    TEST_ASSERT(alt_svc_of(r) == NULL, "no header");
    httpresponse_free(r);

    TEST_CASE("a response with no connection is left alone");
    r = httpresponse_create(NULL);
    r->status_code = 200;
    httpfields_apply_alt_svc(r);
    TEST_ASSERT(alt_svc_of(r) == NULL, "no header, no crash");
    httpresponse_free(r);
}

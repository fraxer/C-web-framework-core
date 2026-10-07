#include "framework.h"
#include "timeouts.h"
#include "connection_s.h"
#include "httpserverhandlers.h"
#include "httprequestparser.h"
#include "websocketsparser.h"
#include "websocketsprotocoldefault.h"
#include "websocketsresponse.h"
#include "multiplexing.h"
#include "domain.h"
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

static uint64_t test_time;
static uint64_t clock_ms(void) { return test_time; }
static int arm(connection_t* c, int flags) { (void)c; (void)flags; return 1; }
static int detach(connection_t* c) { (void)c; return 1; }
/* Records the installed mask the way the epoll layer does, so that
 * connection_control_mod sees read interest come and go. */
static int arm_record(connection_t* c, int flags) {
    atomic_store(&((connection_server_ctx_t*)c->ctx)->epoll_events, (unsigned)flags);
    return 1;
}
static int arm_fail(connection_t* c, int flags) { (void)c; (void)flags; return 0; }

TEST(test_timeout_configuration) {
    TEST_SUITE("timeouts");
    timeout_policy_t p;
    timeout_policy_defaults(&p);
    TEST_ASSERT(p.request_header_timeout_ms == 60000, "defaults to 60s headers");
    json_doc_t* d = json_parse("{\"request_header_timeout_ms\":200,\"ws_ping_interval_ms\":0}");
    TEST_REQUIRE(d != NULL, "JSON parsed");
    TEST_ASSERT(timeout_policy_load(&p, json_root(d), "main.timeouts"), "valid policy loads");
    json_free(d);
    TEST_ASSERT(p.request_header_timeout_ms == 200 && p.request_body_idle_timeout_ms == 60000, "partial policy inherits");
    const char* invalid[] = { "null", "[]", "{\"foo\":1}", "{\"request_header_timeout_ms\":-1}", "{\"request_header_timeout_ms\":1.5}", "{\"request_header_timeout_ms\":\"10\"}", "{\"request_header_timeout_ms\":86400001}", "{\"request_header_timeout_ms\":0}", "{\"ws_close_timeout_ms\":0}", "{\"request_body_idle_timeout_ms\":0}", "{\"ws_ping_interval_ms\":1000,\"ws_pong_timeout_ms\":0}", "{\"request_timeout_mode\":\"enforce\"}" };
    for (unsigned i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        timeout_policy_t before = p;
        d = json_parse(invalid[i]);
        TEST_ASSERT(!timeout_policy_load(&p, json_root(d), "main.timeouts"), "invalid policy rejected");
        TEST_ASSERT(memcmp(&p, &before, sizeof p) == 0, "rejected policy does not partially mutate state");
        json_free(d);
    }
    timeout_policy_t patch;
    timeout_policy_defaults(&patch);
    d = json_parse("{\"request_body_total_timeout_ms\":1234}");
    TEST_ASSERT(timeout_policy_load_route(&patch, json_root(d), "route.timeouts", 0), "body route override accepted");
    timeout_policy_merge(&p, &patch);
    TEST_ASSERT(p.request_body_total_timeout_ms == 1234 && p.request_header_timeout_ms == 200, "merge selects only explicit fields");
    json_free(d);
    d = json_parse("{\"request_header_timeout_ms\":1234}");
    TEST_ASSERT(!timeout_policy_load_route(&patch, json_root(d), "route.timeouts", 0), "route cannot change header deadline");
    json_free(d);
    TEST_ASSERT(!timeout_expired(109, 100, 10) && timeout_expired(110, 100, 10), "exact deadline boundary");
    TEST_ASSERT(!timeout_expired(1000, 100, 0) && !timeout_expired(99, 100, 1), "disabled budgets and backward clock are safe");
}

TEST(test_timeout_http1_receive) {
    TEST_SUITE("timeouts");
    for (int body = 0; body < 2; body++) {
        int fd[2];
        TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "socket pair");
        server_t server = {0};
        timeout_policy_defaults(&server.timeouts);
        server.timeouts.request_header_timeout_ms = server.timeouts.request_body_idle_timeout_ms = 10;
        char name[] = "localhost";
        domain_t domain = { .is_literal = 1, .template = name, .ascii_template = name, .ascii_length = 9 };
        server.domain = &domain;
        server.port = 8080;
        server.ip = ipaddr_from_v4(0x0100007f);
        cqueue_item_t item = { .data = &server };
        mpxapi_t api = { .control_mod = arm, .control_del = detach };
        connection_t listener_connection = { .port = 8080, .ip = server.ip };
        listener_t listener = { .servers = { .item = &item, .last_item = &item, .size = 1 }, .api = &api, .connection = &listener_connection };
        char buffer[4096];
        test_time = 100000;
        timeout_set_clock(clock_ms);
        connection_t* c = connection_s_alloc(&listener, fd[0], &server.ip, 8080, &server.ip, 40000, buffer, sizeof buffer);
        if (!c) { timeout_set_clock(NULL); close(fd[0]); close(fd[1]); TEST_ASSERT(0, "connection allocated"); continue; }
        connection_server_ctx_t* ctx = c->ctx;
        ctx->server = &server;
        ctx->receive_policy = server.timeouts;
        TEST_ASSERT(set_http(c), "HTTP parser installed");
        const char* input = body ? "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\na" : "GET / HTTP/1.1\r\nHo";
        send(fd[1], input, strlen(input), MSG_NOSIGNAL);
        TEST_ASSERT(http_server_guard_read(c), "partial request accepted");
        test_time += 9;
        http_server_tick(c);
        TEST_ASSERT(ctx->response == NULL, "not expired before deadline");
        test_time++;
        http_server_tick(c);
        TEST_ASSERT(ctx->response != NULL && ctx->timeout_closing, "408 staged at deadline");
        TEST_ASSERT(((httprequestparser_t*)ctx->parser)->timeout_reported & timeout_event_bit(body ? "body_idle" : "headers"), "expiry recorded");
        http_server_guard_write(c);
        char wire[4096] = {0};
        ssize_t n = recv(fd[1], wire, sizeof wire - 1, 0);
        TEST_ASSERT(n > 0 && strstr(wire, "408") && strstr(wire, "Connection: close"), "408 and close on wire");
        connection_free(c);
        close(fd[0]); close(fd[1]);
        timeout_set_clock(NULL);
    }
}

TEST(test_timeout_websocket_watchdog) {
    TEST_SUITE("timeouts");
    websocketsparser_t p;
    test_time = 100000;
    timeout_set_clock(clock_ms);
    websocketsparser_init(&p);
    p.timeout_policy.ws_pong_timeout_ms = 10;
    p.ping_sequence = 42;
    p.ping_queued = 1;
    TEST_ASSERT(websocketsparser_timeout(&p, test_time + 20, 0) == NULL, "queued Ping does not start Pong deadline");
    p.ping_sent_ms = test_time;
    uint64_t wrong = 43;
    websocketsparser_pong(&p, (const char*)&wrong, sizeof wrong);
    TEST_ASSERT(p.ping_sent_ms != 0, "wrong Pong does not confirm heartbeat");
    TEST_ASSERT(websocketsparser_timeout(&p, test_time + 10, 0) && !strcmp(websocketsparser_timeout(&p, test_time + 10, 0), "pong"), "missing Pong expires at boundary");
    websocketsparser_pong(&p, (const char*)&p.ping_sequence, sizeof p.ping_sequence);
    TEST_ASSERT(!p.ping_sent_ms && !p.ping_queued, "matching Pong clears outstanding probe");
    p.message_started_ms = p.message_progress_ms = test_time;
    p.timeout_policy.ws_message_idle_timeout_ms = 10;
    p.timeout_policy.ws_message_total_timeout_ms = 15;
    TEST_ASSERT(!strcmp(websocketsparser_timeout(&p, test_time + 10, 0), "message_idle"), "incomplete message idle expires");
    p.message_progress_ms += 14;
    TEST_ASSERT(!strcmp(websocketsparser_timeout(&p, test_time + 15, 0), "message_total"), "regular progress cannot extend total deadline");
    connection_t connection = {0};
    websocketsresponse_t* response = websocketsresponse_create(&connection);
    TEST_ASSERT(response != NULL, "response allocated");
    if (response) {
        websocketsresponse_ping(response, "probe", 5);
        TEST_ASSERT(response->frame_code == 0x89 && response->body.data && (unsigned char)response->body.data[0] == 0x89, "server Ping uses correct opcode");
        response->base.free(response);
    }
    bufferdata_clear(&p.buf); bufo_clear(&p.compressed_buf);
    timeout_set_clock(NULL);
}

TEST(test_timeout_http1_pipeline_cycle) {
    TEST_SUITE("timeouts");
    {
        server_t server = {0};
        timeout_policy_defaults(&server.timeouts);
        server.timeouts.request_header_timeout_ms = 100;
        server.timeouts.request_body_idle_timeout_ms = 3000;
        connection_server_ctx_t ctx = { .server = &server };
        ctx.receive_policy = server.timeouts;
        char buffer[] = "GET / HTTP/1.0\r\n\r\nGET /next HTTP/1.0\r\n";
        connection_t c = { .fd = -1, .ctx = &ctx, .buffer = buffer };
        httprequestparser_t p;
        test_time = 100000;
        timeout_set_clock(clock_ms);
        httpparser_init(&p, &c);
        ctx.parser = &p;
        httpparser_set_bytes_readed(&p, strlen(buffer));
        TEST_ASSERT(httpparser_run(&p) == HTTP1PARSER_HANDLE_AND_CONTINUE, "first pipelined request complete");
        httprequest_t* first = p.request;
        httpparser_prepare_continue(&p);
        TEST_ASSERT(httpparser_run(&p) == HTTP1PARSER_CONTINUE, "next request waits for headers");
        test_time += 800;
        const char* reason = timeout_request_reason(test_time, p.header_started_ms,
            p.body_started_ms, p.body_progress_ms, &p.timeout_policy);
        TEST_ASSERT(reason && !strcmp(reason, "headers"), "second request expires by its header budget");
        httprequest_free(first);
        httprequest_free(p.request);
        p.request = NULL;
        httpparser_reset(&p);
        if (ctx.request_cache) httprequest_free(ctx.request_cache);
        timeout_set_clock(NULL);
    }
}

TEST(test_timeout_http1_effective_slow_policy) {
    TEST_SUITE("timeouts");
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    connection_server_ctx_t ctx = { .server = &server };
    ctx.receive_policy = server.timeouts;
    char buffer[128];
    connection_t c = { .fd = -1, .ctx = &ctx, .buffer = buffer };
    httprequestparser_t p;
    test_time = 100000;
    timeout_set_clock(clock_ms);
    httpparser_init(&p, &c);
    ctx.parser = &p;
    c.read = http_server_guard_read;
    httprequest_t* r = httprequest_create(&c);
    TEST_ASSERT(r != NULL, "request created");
    if (r) {
        ctx.request = r;
        r->started_ms = test_time;
        r->timing_policy.slow_request_threshold_ms = 10000;
        test_time += 1000;
        http_server_tick(&c);
        TEST_ASSERT(!r->slow_reported, "route's longer slow budget survives dispatch");
        r->timing_policy.slow_request_threshold_ms = 500;
        http_server_tick(&c);
        TEST_ASSERT(r->slow_reported, "route's shorter slow budget applies after dispatch");
        httprequest_free(r);
    }
    httpparser_reset(&p);
    timeout_set_clock(NULL);
}

TEST(test_timeout_events_reason_and_episode) {
    TEST_SUITE("timeouts");
    unsigned reported = 0;
    TEST_ASSERT(timeout_report(&reported, "http1", "headers", -1, 0), "first expiry recorded");
    TEST_ASSERT(!timeout_report(&reported, "http1", "headers", -1, 0), "repeated tick suppressed");
    TEST_ASSERT(timeout_report(&reported, "http1", "body_idle", -1, 0), "different reason recorded");
    timeout_event_clear(&reported, "headers");
    TEST_ASSERT(timeout_report(&reported, "http1", "headers", -1, 0), "new header episode recorded");
    TEST_ASSERT(!timeout_report(&reported, "http1", "body_idle", -1, 0), "other active episode retains deduplication");
}

TEST(test_timeout_http1_send_reuse) {
    TEST_SUITE("timeouts");
    int fd[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "socket pair");
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    server.timeouts.response_send_idle_timeout_ms = 10;
    mpxapi_t api = { .control_mod = arm, .control_del = detach };
    listener_t listener = { .api = &api };
    char buffer[4096];
    test_time = 100000;
    timeout_set_clock(clock_ms);
    connection_t* c = connection_s_alloc(&listener, fd[0], &server.ip, 8080, &server.ip, 40000, buffer, sizeof buffer);
    TEST_ASSERT(c != NULL, "connection allocated");
    if (c) {
        connection_server_ctx_t* ctx = c->ctx;
        ctx->server = &server;
        ctx->receive_policy = server.timeouts;
        TEST_ASSERT(set_http(c), "HTTP parser installed");
        /* The send event is deduplicated per exchange: a keepalive reset opens
         * the next one. */
        for (int episode = 0; episode < 2; episode++) {
            TEST_ASSERT(timeout_report(&ctx->timeout_reported, "http1", "send_idle", c->fd, 0), "send event recorded once per exchange");
            TEST_ASSERT(!timeout_report(&ctx->timeout_reported, "http1", "send_idle", c->fd, 0), "repeated within the exchange");
            ctx->base.reset(ctx);
        }
        httprequest_t* r = httprequest_create(c);
        httpresponse_t* response = httpresponse_create(c);
        TEST_ASSERT(r && response, "exchange objects created");
        if (r && response) {
            r->timing_policy = server.timeouts;
            ctx->request = r;
            ctx->response = response;
            atomic_store(&ctx->need_write, 1);
            ctx->send_progress_ms = test_time;
            /* Held past the close, so the asserts below read live memory. */
            connection_s_inc(c);
            test_time += 9;
            http_server_tick(c);
            TEST_ASSERT(!atomic_load(&ctx->detached), "response still within its send budget");
            test_time++;
            http_server_tick(c);
            TEST_ASSERT(atomic_load(&ctx->detached), "stalled response closes the connection at the deadline");
            TEST_ASSERT(ctx->timeout_reported & timeout_event_bit("send_idle"), "send idle reported");
            connection_s_dec(c);
            c = NULL; /* closed its fd and freed with the last reference */
        } else {
            if (r) httprequest_free(r);
            if (response) response->base.free(response);
        }
        if (c) {
            connection_free(c);
            close(fd[0]);
        }
    }
    close(fd[1]);
    timeout_set_clock(NULL);
}

/* An idle connection -- no request byte yet, fresh or between keep-alive
 * requests -- closes without a 408: a pooled client may be sending its next
 * request right then and would take the 408 for the answer to it. */
TEST(test_timeout_http1_idle_closes_silently) {
    TEST_SUITE("timeouts");
    for (int keepalive = 0; keepalive < 2; keepalive++) {
        int fd[2];
        TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "socket pair");
        server_t server = {0};
        timeout_policy_defaults(&server.timeouts);
        server.timeouts.request_header_timeout_ms = 10;
        server.timeouts.keepalive_timeout_ms = 20;
        mpxapi_t api = { .control_mod = arm, .control_del = detach };
        listener_t listener = { .api = &api };
        char buffer[4096];
        test_time = 100000;
        timeout_set_clock(clock_ms);
        connection_t* c = connection_s_alloc(&listener, fd[0], &server.ip, 8080, &server.ip, 40000, buffer, sizeof buffer);
        if (!c) { timeout_set_clock(NULL); close(fd[0]); close(fd[1]); TEST_ASSERT(0, "connection allocated"); continue; }
        connection_server_ctx_t* ctx = c->ctx;
        ctx->server = &server;
        ctx->receive_policy = server.timeouts;
        TEST_ASSERT(set_http(c), "HTTP parser installed");
        /* The first request clears accepted_ms; from then on the keep-alive budget applies. */
        if (keepalive) ctx->accepted_ms = 0;
        const uint32_t budget = keepalive ? server.timeouts.keepalive_timeout_ms : server.timeouts.request_header_timeout_ms;
        connection_s_inc(c); /* held past the close, so the asserts read live memory */
        http_server_tick(c);
        test_time += budget - 1;
        http_server_tick(c);
        TEST_ASSERT(!atomic_load(&ctx->detached), "idle connection kept within its budget");
        test_time++;
        http_server_tick(c);
        TEST_ASSERT(atomic_load(&ctx->detached) && ctx->response == NULL, "closed at the deadline without staging a response");
        char wire[64];
        TEST_ASSERT(recv(fd[1], wire, sizeof wire, 0) == 0, keepalive ? "keep-alive peer sees a bare EOF, no 408" : "fresh peer sees a bare EOF, no 408");
        connection_s_dec(c); /* the last reference: frees it; its fd is already closed */
        close(fd[1]);
        timeout_set_clock(NULL);
    }
}

TEST(test_timeout_recv_clock) {
    TEST_SUITE("timeouts");
    int fd[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "socket pair");
    server_t server = {0};
    mpxapi_t api = { .control_mod = arm_record, .control_del = detach };
    listener_t listener = { .api = &api };
    char buffer[64];
    test_time = 100000;
    timeout_set_clock(clock_ms);
    connection_t* c = connection_s_alloc(&listener, fd[0], &server.ip, 8080, &server.ip, 40000, buffer, sizeof buffer);
    TEST_ASSERT(c != NULL, "connection allocated");
    if (c) {
        connection_server_ctx_t* ctx = c->ctx;
        atomic_store(&ctx->epoll_events, MPXIN | MPXRDHUP); /* as registered at accept */
        TEST_ASSERT(connection_recv_now(ctx, test_time) == test_time, "armed from the start: receive time is wall time");
        TEST_ASSERT(connection_control_mod(c, MPXOUT | MPXRDHUP), "parked for the response write");
        const uint64_t stopped = test_time;
        test_time += 5000;
        TEST_ASSERT(connection_recv_now(ctx, test_time) == stopped, "clock holds while not reading");
        TEST_ASSERT(connection_control_mod(c, MPXONESHOT), "parked for a handler");
        test_time += 1000;
        TEST_ASSERT(connection_recv_now(ctx, test_time) == stopped, "deaf to deaf neither restarts nor resumes");
        TEST_ASSERT(connection_control_mod(c, MPXIN | MPXRDHUP), "re-armed for reading");
        TEST_ASSERT(connection_recv_now(ctx, test_time) == stopped, "resumes where it stopped");
        test_time += 7;
        TEST_ASSERT(connection_recv_now(ctx, test_time) == stopped + 7, "runs with wall time once readable");
        TEST_ASSERT(connection_control_mod(c, MPXIN | MPXRDHUP | MPXONESHOT), "h2 park stays readable");
        test_time += 3;
        TEST_ASSERT(connection_recv_now(ctx, test_time) == stopped + 10, "readable park does not stop the clock");
        api.control_mod = arm_fail;
        TEST_ASSERT(!connection_control_mod(c, MPXOUT | MPXRDHUP), "failed park reported");
        test_time += 5;
        TEST_ASSERT(connection_recv_now(ctx, test_time) == stopped + 15, "failed park leaves the clock running: the old mask is installed");
        TEST_ASSERT(!atomic_load(&ctx->arm_locked), "arm lock released after a failure");
        TEST_ASSERT(connection_recv_stamp(NULL, test_time) == test_time, "no ctx: raw time");
        TEST_ASSERT(connection_recv_stamp(NULL, 0) == 1, "a stamp is never the not-started sentinel");
        connection_free(c);
    }
    close(fd[0]); close(fd[1]);
    timeout_set_clock(NULL);
}

/* A pause must count only against the deadline it interrupts. Stamping on wall
 * time and checking on the paused clock carried every earlier pause of the
 * connection forward: after one 5 s exchange the next request's 10 ms header
 * budget became 5010 ms -- and a client stretches such pauses at will by not
 * reading its responses. */
TEST(test_timeout_http1_pause_not_banked) {
    TEST_SUITE("timeouts");
    for (int pause_during = 0; pause_during < 2; pause_during++) {
        int fd[2];
        TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "socket pair");
        server_t server = {0};
        timeout_policy_defaults(&server.timeouts);
        server.timeouts.request_header_timeout_ms = 10;
        char name[] = "localhost";
        domain_t domain = { .is_literal = 1, .template = name, .ascii_template = name, .ascii_length = 9 };
        server.domain = &domain;
        server.port = 8080;
        server.ip = ipaddr_from_v4(0x0100007f);
        cqueue_item_t item = { .data = &server };
        mpxapi_t api = { .control_mod = arm_record, .control_del = detach };
        connection_t listener_connection = { .port = 8080, .ip = server.ip };
        listener_t listener = { .servers = { .item = &item, .last_item = &item, .size = 1 }, .api = &api, .connection = &listener_connection };
        char buffer[4096];
        test_time = 100000;
        timeout_set_clock(clock_ms);
        connection_t* c = connection_s_alloc(&listener, fd[0], &server.ip, 8080, &server.ip, 40000, buffer, sizeof buffer);
        if (!c) { timeout_set_clock(NULL); close(fd[0]); close(fd[1]); TEST_ASSERT(0, "connection allocated"); continue; }
        connection_server_ctx_t* ctx = c->ctx;
        ctx->server = &server;
        ctx->receive_policy = server.timeouts;
        atomic_store(&ctx->epoll_events, MPXIN | MPXRDHUP);
        TEST_ASSERT(set_http(c), "HTTP parser installed");

        if (!pause_during) {
            /* An earlier exchange on this connection kept it deaf for 5 s. */
            connection_control_mod(c, MPXOUT | MPXRDHUP);
            test_time += 5000;
            connection_control_mod(c, MPXIN | MPXRDHUP);
        }
        const char* input = "GET / HTTP/1.1\r\nHo";
        send(fd[1], input, strlen(input), MSG_NOSIGNAL);
        TEST_ASSERT(http_server_guard_read(c), "partial request accepted");
        if (pause_during) {
            /* Headers started, then the server stopped reading for 5 s: only
             * the time on either side of the pause is the client's. */
            test_time += 4;
            connection_control_mod(c, MPXONESHOT);
            test_time += 5000;
            http_server_tick(c);
            TEST_ASSERT(!ctx->response && !ctx->timeout_closing &&
                        !(((httprequestparser_t*)ctx->parser)->timeout_reported & timeout_event_bit("headers")),
                        "not expired while the server is not reading");
            connection_control_mod(c, MPXIN | MPXRDHUP);
            test_time += 5;
        } else {
            test_time += 9;
        }
        http_server_tick(c);
        TEST_ASSERT(ctx->response == NULL && !(((httprequestparser_t*)ctx->parser)->timeout_reported & timeout_event_bit("headers")),
                    "not expired before the budget of receive time");
        test_time++;
        http_server_tick(c);
        TEST_ASSERT(ctx->response != NULL && ctx->timeout_closing, "408 staged at the plain budget");
        connection_free(c);
        close(fd[0]); close(fd[1]);
        timeout_set_clock(NULL);
    }
}

TEST(test_timeout_websocket_pause_not_banked) {
    TEST_SUITE("timeouts");
    int fd[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "socket pair");
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    server.timeouts.ws_pong_timeout_ms = 10;
    mpxapi_t api = { .control_mod = arm_record, .control_del = detach };
    listener_t listener = { .api = &api };
    char buffer[64];
    test_time = 100000;
    timeout_set_clock(clock_ms);
    connection_t* c = connection_s_alloc(&listener, fd[0], &server.ip, 8080, &server.ip, 40000, buffer, sizeof buffer);
    websocketsparser_t* p = NULL;
    TEST_REQUIRE_GOTO(c != NULL, "connection allocated", done);
    connection_server_ctx_t* ctx = c->ctx;
    ctx->server = &server;
    ctx->receive_policy = server.timeouts;
    atomic_store(&ctx->epoll_events, MPXIN | MPXRDHUP);
    /* The upgrade request's exchange (or any earlier message) parked it 5 s. */
    connection_control_mod(c, MPXOUT | MPXRDHUP);
    test_time += 5000;
    connection_control_mod(c, MPXIN | MPXRDHUP);
    p = websocketsparser_create(c, NULL);
    TEST_REQUIRE_GOTO(p != NULL, "parser allocated", done);

    p->ping_queued = 1;
    websocketsparser_ping_sent(p);
    test_time += 9;
    TEST_ASSERT(websocketsparser_timeout(p, test_time, 0) == NULL, "Pong not yet due");
    test_time++;
    const char* reason = websocketsparser_timeout(p, test_time, 0);
    TEST_ASSERT(reason && !strcmp(reason, "pong"), "earlier pause does not extend the Pong deadline");

    p->ping_queued = 1;
    websocketsparser_ping_sent(p);
    test_time += 4;
    connection_control_mod(c, MPXONESHOT);
    test_time += 5000;
    TEST_ASSERT(websocketsparser_timeout(p, test_time, 0) == NULL, "Pong deadline holds while the server is not reading");
    connection_control_mod(c, MPXIN | MPXRDHUP);
    test_time += 5;
    TEST_ASSERT(websocketsparser_timeout(p, test_time, 0) == NULL, "only receive time counts");
    test_time++;
    reason = websocketsparser_timeout(p, test_time, 0);
    TEST_ASSERT(reason && !strcmp(reason, "pong"), "Pong expires after the budget of receive time");

done:
    if (p) p->base.free(p);
    if (c) connection_free(c);
    close(fd[0]); close(fd[1]);
    timeout_set_clock(NULL);
}

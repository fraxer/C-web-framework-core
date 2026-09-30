/*
 * HTTP/1.1: an answer to a parse error ends the connection (F-01,
 * docs/security/2026-09-30-audit.md; RFC 9112 §9.6).
 *
 * The parser gives up on a request it cannot frame -- an oversized header, a
 * malformed line, a body over the limit -- and the bytes that follow the
 * failure point cannot be trusted to start a request: the server no longer
 * knows where the broken one ends. Answering and carrying on reads that
 * remainder as a new request, which behind a proxy that reuses the upstream
 * connection is request smuggling.
 *
 * The tests drive the real read/write handlers over an AF_UNIX socketpair, the
 * way the event loop does: whatever the last control_mod() armed is what gets
 * called next, a connection marked destroyed is closed on its next event, and
 * the queued handlers are run by hand where a worker thread would.
 */

#include "framework.h"
#include "appconfig.h"
#include "connection_s.h"
#include "connection_queue.h"
#include "cqueue.h"
#include "domain.h"
#include "httpserverhandlers.h"
#include "multiplexing.h"
#include "server.h"

#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern connection_t* __connection_queue_pop(void);

#define PEC_BUFFER 16384

static char pec_domain_template[] = "localhost";

static domain_t pec_domain = {
    .is_literal = 1,
    .template = pec_domain_template,
    .ascii_template = pec_domain_template,
    .ascii_length = sizeof pec_domain_template - 1,
    .next = NULL
};

static server_t pec_server = {
    .ip = { .family = AF_INET, .u = { .v4 = { .s_addr = 0x0100007F } } },
    .port = 8080,
    .domain = &pec_domain,
    .next = NULL
};

static cqueue_item_t pec_queue_item = { .data = &pec_server, .next = NULL };

static int pec_armed;

static int pec_mpx_arm(connection_t* connection, int flags) {
    (void)connection;
    pec_armed = flags;
    return 1;
}

static int pec_mpx_del(connection_t* connection) {
    (void)connection;
    pec_armed = 0;
    return 1;
}

static mpxapi_t pec_mpxapi = {
    .control_add = pec_mpx_arm,
    .control_mod = pec_mpx_arm,
    .control_del = pec_mpx_del,
};

static listener_t pec_listener = {
    .servers = { .item = &pec_queue_item, .last_item = &pec_queue_item, .size = 1, .locked = 0 },
    .connection = NULL,
    .api = &pec_mpxapi,
    .next = NULL
};

typedef struct {
    size_t responses;      /* status lines seen on the wire */
    size_t status_400;
    size_t status_404;
    size_t status_413;
    size_t status_200;
    int    all_close;      /* every response carried "Connection: close" */
    int    last_close;     /* ... or at least the last one did */
    int    destroyed;      /* the server marked the connection for closing */
    size_t reads_after_error; /* MPXIN events delivered after the first response */
} pec_result_t;

static size_t pec_count(const char* haystack, size_t length, const char* needle) {
    const size_t n = strlen(needle);
    size_t count = 0;
    for (size_t i = 0; i + n <= length; i++)
        if (memcmp(haystack + i, needle, n) == 0) count++;
    return count;
}

/* The client sends `input` in full, then the loop plays epoll and the worker
 * until nothing moves. The socket buffers are sized to take the whole input at
 * once, so the server reads it in buffer-sized pieces (16384) rather than in
 * whatever the sender happened to flush -- which is what puts the boundary of a
 * read exactly where the test says. */
static int pec_run(const char* input, size_t length, pec_result_t* out) {
    memset(out, 0, sizeof *out);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0) return 0;
    const int big = 1 << 20;
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);

    char* buffer = malloc(PEC_BUFFER);
    char* wire = malloc(1 << 20);
    if (buffer == NULL || wire == NULL) { free(buffer); free(wire); close(sv[0]); close(sv[1]); return 0; }
    size_t wire_len = 0;

    const ipaddr_t loopback = ipaddr_from_v4(0x0100007F);
    connection_t* connection = connection_s_alloc(&pec_listener, sv[0], &loopback, 8080,
                                                  &loopback, 40000, buffer, PEC_BUFFER);
    if (connection == NULL) { free(buffer); free(wire); close(sv[0]); close(sv[1]); return 0; }
    connection_server_ctx_t* ctx = connection->ctx;
    ctx->server = &pec_server;

    int alive = set_http(connection);
    pec_armed = MPXIN | MPXRDHUP;

    size_t sent = 0;
    while (sent < length) {
        const ssize_t w = send(sv[1], input + sent, length - sent, MSG_NOSIGNAL);
        if (w <= 0) break;
        sent += (size_t)w;
    }

    int answered = 0;
    for (int step = 0; alive && step < 2000; step++) {
        int moved = 0;

        if (atomic_load(&ctx->destroyed)) break;      /* epoll closes it on the next event */

        if (pec_armed & MPXIN) {
            if (answered) out->reads_after_error++;
            if (pec_armed & MPXONESHOT) pec_armed = 0;
            alive = http_server_guard_read(connection);
            moved = 1;
        }
        else if (pec_armed & MPXOUT) {
            if (pec_armed & MPXONESHOT) pec_armed = 0;
            alive = http_server_guard_write(connection);
            moved = 1;
        }

        connection_t* queued;
        while (alive && (queued = __connection_queue_pop()) != NULL) {
            connection_server_ctx_t* qctx = queued->ctx;
            cqueue_lock(qctx->queue);
            connection_queue_item_t* item = cqueue_pop(qctx->queue);
            cqueue_unlock(qctx->queue);
            if (item != NULL) { item->run(item); item->free(item); }
            connection_s_dec(queued);
            moved = 1;
        }

        const ssize_t r = recv(sv[1], wire + wire_len, (1 << 20) - wire_len, 0);
        if (r > 0) { wire_len += (size_t)r; answered = 1; moved = 1; }

        if (!moved) break;
    }

    /* Whatever is still in flight when the server stops. */
    for (;;) {
        const ssize_t r = recv(sv[1], wire + wire_len, (1 << 20) - wire_len, 0);
        if (r <= 0) break;
        wire_len += (size_t)r;
    }

    out->destroyed = atomic_load(&ctx->destroyed) || !alive;
    out->responses = pec_count(wire, wire_len, "HTTP/1.1 ");
    out->status_200 = pec_count(wire, wire_len, "HTTP/1.1 200");
    out->status_400 = pec_count(wire, wire_len, "HTTP/1.1 400");
    out->status_404 = pec_count(wire, wire_len, "HTTP/1.1 404");
    out->status_413 = pec_count(wire, wire_len, "HTTP/1.1 413");
    out->all_close = out->responses > 0 &&
                     pec_count(wire, wire_len, "Connection: close") == out->responses;
    const char* last = NULL;
    for (size_t i = 0; i + 9 <= wire_len; i++)
        if (memcmp(wire + i, "HTTP/1.1 ", 9) == 0) last = wire + i;
    out->last_close = last != NULL &&
                      pec_count(last, wire_len - (size_t)(last - wire), "Connection: close") == 1;

    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "input %zu: responses=%zu 400=%zu close=%d destroyed=%d\n",
                length, out->responses, out->status_400, out->all_close, out->destroyed);

    connection_s_dec(connection);
    free(buffer);
    free(wire);
    close(sv[1]);
    return 1;
}

static char* pec_big_header(size_t value_len, const char* tail, size_t* total) {
    static const char head[] = "GET / HTTP/1.1\r\nHost: localhost\r\nX: ";
    const size_t tail_len = tail != NULL ? strlen(tail) : 0;
    const size_t len = sizeof head - 1 + value_len + 4 + tail_len;
    char* s = malloc(len + 1);
    if (s == NULL) return NULL;
    memcpy(s, head, sizeof head - 1);
    memset(s + sizeof head - 1, 'A', value_len);
    memcpy(s + sizeof head - 1 + value_len, "\r\n\r\n", 4);
    if (tail_len) memcpy(s + sizeof head - 1 + value_len + 4, tail, tail_len);
    s[len] = 0;
    *total = len;
    return s;
}

static void pec_expect_closed_after_first(const char* label, const char* input, size_t length) {
    pec_result_t r;
    char message[160];

    if (!pec_run(input, length, &r)) {
        TEST_ASSERT(0, "harness must start");
        return;
    }

    snprintf(message, sizeof message, "%s: exactly one response", label);
    TEST_ASSERT_EQUAL_SIZE(1, r.responses, message);
    snprintf(message, sizeof message, "%s: the response says Connection: close", label);
    TEST_ASSERT(r.all_close, message);
    snprintf(message, sizeof message, "%s: the connection is closed after it", label);
    TEST_ASSERT(r.destroyed, message);
    snprintf(message, sizeof message, "%s: no request was executed from the leftover bytes", label);
    TEST_ASSERT_EQUAL_SIZE(0, r.status_200 + r.status_404, message);
}

TEST(test_parse_error_header_too_large_closes) {
    TEST_SUITE("http1: parse error closes the connection");
    TEST_CASE("oversized header value: 400 with Connection: close, one response");

    static const size_t sizes[] = { 8193, 9000, 20000, 200000 };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        size_t total;
        char* input = pec_big_header(sizes[i], NULL, &total);
        TEST_REQUIRE_NOT_NULL(input, "input allocated");
        char label[64];
        snprintf(label, sizeof label, "value %zu", sizes[i]);
        pec_expect_closed_after_first(label, input, total);
        free(input);
    }
}

TEST(test_parse_error_then_valid_request_not_executed) {
    TEST_SUITE("http1: parse error closes the connection");
    TEST_CASE("a valid request right behind a read boundary is not run");

    /* The valid request has to start exactly where a read starts for the old
     * behaviour to run it: the chunks of a failed request each began a fresh
     * parse. Sweep the value length so the second request begins a few bytes
     * either side of the 16384-byte read boundaries. */
    static const char follow[] = "GET /json HTTP/1.1\r\nHost: localhost\r\n\r\n";
    static const char head[] = "GET / HTTP/1.1\r\nHost: localhost\r\nX: ";
    const size_t fixed = sizeof head - 1 + 4;

    for (size_t boundary = 2 * PEC_BUFFER; boundary <= 3 * PEC_BUFFER; boundary += PEC_BUFFER) {
        for (int delta = -8; delta <= 8; delta++) {
            const size_t value = boundary - fixed + (size_t)(ptrdiff_t)delta;
            size_t total;
            char* input = pec_big_header(value, follow, &total);
            TEST_REQUIRE_NOT_NULL(input, "input allocated");
            char label[64];
            snprintf(label, sizeof label, "boundary %zu%+d", boundary, delta);
            pec_expect_closed_after_first(label, input, total);
            free(input);
        }
    }
}

TEST(test_parse_error_header_key_too_large_closes) {
    TEST_SUITE("http1: parse error closes the connection");
    TEST_CASE("oversized header name: 400 with Connection: close");

    char input[2048];
    size_t n = (size_t)snprintf(input, sizeof input, "GET / HTTP/1.1\r\nHost: localhost\r\n");
    memset(input + n, 'K', 400);
    n += 400;
    n += (size_t)snprintf(input + n, sizeof input - n, ": v\r\n\r\nGET /json HTTP/1.1\r\nHost: localhost\r\n\r\n");
    pec_expect_closed_after_first("key 400", input, n);
}

TEST(test_parse_error_malformed_request_line_closes) {
    TEST_SUITE("http1: parse error closes the connection");
    TEST_CASE("a malformed request line is answered and closed (control: closed before F-01 too)");

    /* keepalive is set only once the request line names HTTP/1.1, so a line
     * that never gets that far already closed the connection: this is what
     * the header errors above are compared with. */
    static const char in[] = "BROKEN\r\n\r\nGET /json HTTP/1.1\r\nHost: localhost\r\n\r\n";
    pec_expect_closed_after_first("broken line", in, sizeof in - 1);
}

TEST(test_parse_error_behind_pipelined_request_closes) {
    TEST_SUITE("http1: parse error closes the connection");
    TEST_CASE("a refusal queued behind a pipelined request: that one is answered, then close");

    /* The first request is answered by a worker (ctx->queue is not empty when
     * the second one fails), so the refusal takes the queued path
     * (__post_response -> __deferred_handler) rather than being written at
     * once. The first answer keeps the connection -- its request was fine --
     * and __write restores connection->keepalive from it; the refusal must
     * still carry its own "close" and end the connection, and the third
     * request must not be read. */
    char input[2048];
    size_t n = (size_t)snprintf(input, sizeof input,
                                "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                "GET / HTTP/1.1\r\nHost: localhost\r\n");
    memset(input + n, 'K', 400);
    n += 400;
    n += (size_t)snprintf(input + n, sizeof input - n,
                          ": v\r\n\r\nGET /json HTTP/1.1\r\nHost: localhost\r\n\r\n");

    pec_result_t r;
    TEST_REQUIRE(pec_run(input, n, &r), "harness must start");
    TEST_ASSERT_EQUAL_SIZE(2, r.responses, "two responses: the first request's and the refusal");
    TEST_ASSERT_EQUAL_SIZE(1, r.status_404, "the first request is answered (no such file)");
    TEST_ASSERT_EQUAL_SIZE(1, r.status_400, "then the refusal");
    TEST_ASSERT(r.last_close, "the refusal says Connection: close");
    TEST_ASSERT(r.destroyed, "and the connection is closed after it");
}

TEST(test_parse_error_host_not_found_closes) {
    TEST_SUITE("http1: parse error closes the connection");
    TEST_CASE("404 for an unknown host closes and does not parse on");

    static const char in[] = "GET / HTTP/1.1\r\nHost: unknown.invalid\r\n\r\n"
                             "GET /json HTTP/1.1\r\nHost: localhost\r\n\r\n";
    pec_result_t r;
    TEST_REQUIRE(pec_run(in, sizeof in - 1, &r), "harness must start");
    TEST_ASSERT_EQUAL_SIZE(1, r.responses, "one response");
    TEST_ASSERT_EQUAL_SIZE(1, r.status_404, "and it is 404");
    TEST_ASSERT(r.all_close, "with Connection: close");
    TEST_ASSERT(r.destroyed, "and the connection is closed");
}

TEST(test_parse_error_content_length_over_limit_closes) {
    TEST_SUITE("http1: parse error closes the connection");
    TEST_CASE("Content-Length over client_max_body_size: refused, closed, body not parsed as a request");

    env_t* e = env();
    const size_t saved = e->main.client_max_body_size;
    e->main.client_max_body_size = 16;

    /* The limit is checked when the Content-Length header is read, so the
     * refusal is a 400 (the parser's PAYLOAD_LARGE, which would be a 413,
     * needs more body bytes than Content-Length allows and cannot be reached).
     * The body that follows is written as a request: if the leftover were
     * parsed on, it would be answered. */
    static const char in[] = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 64\r\n\r\n"
                             "GET /json HTTP/1.1\r\nHost: localhost\r\n\r\n";
    pec_result_t r;
    const int ok = pec_run(in, sizeof in - 1, &r);
    e->main.client_max_body_size = saved;

    TEST_REQUIRE(ok, "harness must start");
    TEST_ASSERT_EQUAL_SIZE(1, r.responses, "one response");
    TEST_ASSERT_EQUAL_SIZE(1, r.status_400, "and it is 400");
    TEST_ASSERT(r.all_close, "with Connection: close");
    TEST_ASSERT(r.destroyed, "and the connection is closed");
}

TEST(test_parse_error_te_and_cl_closes) {
    TEST_SUITE("http1: parse error closes the connection");
    TEST_CASE("Transfer-Encoding with Content-Length, duplicate Content-Length: refused and closed");

    /* Refused in __set_header_value, whose caller resets the parser like any
     * other parse error does; the bytes after the refusal are the body, which
     * is exactly what must not be read as the next request. */
    static const char te_cl[] = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                                "Transfer-Encoding: chunked\r\n\r\n"
                                "GET /json HTTP/1.1\r\nHost: localhost\r\n\r\n";
    static const char dup_cl[] = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                                 "Content-Length: 4\r\n\r\nabcd"
                                 "GET /json HTTP/1.1\r\nHost: localhost\r\n\r\n";
    pec_expect_closed_after_first("TE+CL", te_cl, sizeof te_cl - 1);
    pec_expect_closed_after_first("duplicate CL", dup_cl, sizeof dup_cl - 1);
}

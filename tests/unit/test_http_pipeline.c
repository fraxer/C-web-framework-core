/*
 * HTTP/1.1 pipelining: answers go out in request order, one at a time, and each
 * one closes the connection or not on its own request's terms.
 *
 * Two defects found while checking F-01 (docs/security/2026-09-30-audit.md):
 *
 *  - A worker takes its item off ctx->queue before it runs it, so "the queue is
 *    empty" did not mean "nothing is in flight". A request the read path could
 *    answer by itself (a missing file, a parse refusal) was bound straight to
 *    ctx->request/response over the one a worker was still building: one
 *    answer lost, its objects leaked, and on a live server a use-after-poison
 *    when the write path retired the response the handler was writing to.
 *
 *  - The parser kept its keep-alive decision in connection->keepalive, which
 *    __write also sets -- from the response it has just written. A request
 *    whose body was still arriving when the answer to the previous one went
 *    out lost its "Connection: close".
 *
 * The harness drives the real read/write handlers over an AF_UNIX socketpair
 * the way test_http_parse_error_close.c does: whatever the last control_mod()
 * armed is what gets called next, and the queued handlers are run by hand
 * where a worker thread would -- except in the race test, which needs a real
 * one.
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
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

extern connection_t* __connection_queue_pop(void);

#define HPL_BUFFER 16384
#define HPL_WIRE (1 << 20)

static char hpl_domain_template[] = "localhost";

static domain_t hpl_domain = {
    .is_literal = 1,
    .template = hpl_domain_template,
    .ascii_template = hpl_domain_template,
    .ascii_length = sizeof hpl_domain_template - 1,
    .next = NULL
};

static server_t hpl_server = {
    .ip = { .family = AF_INET, .u = { .v4 = { .s_addr = 0x0100007F } } },
    .port = 8080,
    .domain = &hpl_domain,
    .next = NULL
};

static cqueue_item_t hpl_queue_item = { .data = &hpl_server, .next = NULL };

static _Atomic int hpl_armed;

static int hpl_mpx_arm(connection_t* connection, int flags) {
    (void)connection;
    atomic_store(&hpl_armed, flags);
    return 1;
}

static int hpl_mpx_del(connection_t* connection) {
    (void)connection;
    atomic_store(&hpl_armed, 0);
    return 1;
}

static mpxapi_t hpl_mpxapi = {
    .control_add = hpl_mpx_arm,
    .control_mod = hpl_mpx_arm,
    .control_del = hpl_mpx_del,
};

static listener_t hpl_listener = {
    .servers = { .item = &hpl_queue_item, .last_item = &hpl_queue_item, .size = 1, .locked = 0 },
    .connection = NULL,
    .api = &hpl_mpxapi,
    .next = NULL
};

typedef struct {
    int sv[2];
    char* buffer;
    connection_t* connection;
    connection_server_ctx_t* ctx;
    int alive;
    char* wire;
    size_t wire_len;
} hpl_t;

typedef struct {
    size_t responses;
    size_t keepalive;      /* answers that said "Connection: keep-alive" */
    int    last_close;     /* the last answer said "Connection: close" */
    int    destroyed;      /* the server marked the connection for closing */
    char   order[64];      /* the status codes in wire order, "404 200 ..." */
} hpl_result_t;

static size_t hpl_count(const char* haystack, size_t length, const char* needle) {
    const size_t n = strlen(needle);
    size_t count = 0;
    for (size_t i = 0; i + n <= length; i++)
        if (memcmp(haystack + i, needle, n) == 0) count++;
    return count;
}

/* `blocking`: the server's end of the pair blocks in recv, which is how the
 * race test holds __read in place until its worker has done what it must. */
static int hpl_open(hpl_t* h, int blocking) {
    memset(h, 0, sizeof *h);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, h->sv) != 0) return 0;
    fcntl(h->sv[1], F_SETFL, fcntl(h->sv[1], F_GETFL) | O_NONBLOCK);
    if (!blocking)
        fcntl(h->sv[0], F_SETFL, fcntl(h->sv[0], F_GETFL) | O_NONBLOCK);
    /* A blocked recv gives up after a while rather than hang the runner if the
     * worker never comes; __read then sees EAGAIN and returns. */
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(h->sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    h->buffer = malloc(HPL_BUFFER);
    h->wire = malloc(HPL_WIRE);
    if (h->buffer == NULL || h->wire == NULL) return 0;

    const ipaddr_t loopback = ipaddr_from_v4(0x0100007F);
    h->connection = connection_s_alloc(&hpl_listener, h->sv[0], &loopback, 8080,
                                       &loopback, 40000, h->buffer, HPL_BUFFER);
    if (h->connection == NULL) return 0;
    h->ctx = h->connection->ctx;
    h->ctx->server = &hpl_server;
    h->alive = set_http(h->connection);
    atomic_store(&hpl_armed, MPXIN | MPXRDHUP);
    return 1;
}

static void hpl_send(hpl_t* h, const char* data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        const ssize_t w = send(h->sv[1], data + sent, length - sent, MSG_NOSIGNAL);
        if (w <= 0) break;
        sent += (size_t)w;
    }
}

static int hpl_drain_wire(hpl_t* h) {
    int got = 0;
    for (;;) {
        const ssize_t r = recv(h->sv[1], h->wire + h->wire_len, HPL_WIRE - h->wire_len, 0);
        if (r <= 0) break;
        h->wire_len += (size_t)r;
        got = 1;
    }
    return got;
}

/* Plays epoll and the workers until nothing moves. `tail` goes out once the
 * first answer is on the wire and the server is waiting to read again -- for
 * a request whose body the client sends late. */
static void hpl_loop(hpl_t* h, const char* tail) {
    int tail_sent = tail == NULL;

    for (int step = 0; h->alive && step < 2000; step++) {
        int moved = 0;
        if (atomic_load(&h->ctx->destroyed)) break;

        const int armed = atomic_load(&hpl_armed);
        if (armed & MPXIN) {
            if (armed & MPXONESHOT) atomic_store(&hpl_armed, 0);
            h->alive = http_server_guard_read(h->connection);
            moved = 1;
        }
        else if (armed & MPXOUT) {
            if (armed & MPXONESHOT) atomic_store(&hpl_armed, 0);
            h->alive = http_server_guard_write(h->connection);
            moved = 1;
        }

        connection_t* queued;
        while (h->alive && (queued = __connection_queue_pop()) != NULL) {
            connection_server_ctx_t* qctx = queued->ctx;
            cqueue_lock(qctx->queue);
            connection_queue_item_t* item = cqueue_pop(qctx->queue);
            cqueue_unlock(qctx->queue);
            if (item != NULL) { item->run(item); item->free(item); }
            connection_s_dec(queued);
            moved = 1;
        }

        if (hpl_drain_wire(h)) moved = 1;

        if (!tail_sent && h->wire_len > 0 && (atomic_load(&hpl_armed) & MPXIN)) {
            hpl_send(h, tail, strlen(tail));
            tail_sent = 1;
            moved = 1;
        }

        if (!moved) break;
    }
    hpl_drain_wire(h);
}

static void hpl_close(hpl_t* h, hpl_result_t* out) {
    memset(out, 0, sizeof *out);
    if (h->connection != NULL) {
        out->destroyed = atomic_load(&h->ctx->destroyed) || !h->alive;
        out->responses = hpl_count(h->wire, h->wire_len, "HTTP/1.1 ");
        out->keepalive = hpl_count(h->wire, h->wire_len, "Connection: keep-alive");

        const char* last = NULL;
        size_t at = 0;
        for (size_t i = 0; i + 12 <= h->wire_len; i++) {
            if (memcmp(h->wire + i, "HTTP/1.1 ", 9) != 0) continue;
            last = h->wire + i;
            if (at + 4 < sizeof out->order)
                at += (size_t)snprintf(out->order + at, sizeof out->order - at, "%s%.3s",
                                       at ? " " : "", h->wire + i + 9);
        }
        out->last_close = last != NULL &&
                          hpl_count(last, h->wire_len - (size_t)(last - h->wire), "Connection: close") == 1;

        connection_s_dec(h->connection);
    }
    else if (h->sv[0] > 0)
        close(h->sv[0]);

    free(h->buffer);
    free(h->wire);
    if (h->sv[1] > 0) close(h->sv[1]);
}

TEST(test_pipeline_close_on_request_with_late_body) {
    TEST_SUITE("http1 pipelining");
    TEST_CASE("Connection: close on a request whose body arrives after the previous answer is written");

    /* The first request goes to a worker (bytes follow it in the buffer). The
     * second one's head, "Connection: close" included, is read in the same
     * pass; its body is not there yet. The first answer is written while the
     * second request waits for its body -- and __write used to set
     * connection->keepalive from that answer, over what the parser had
     * decided for the second request. */
    static const char head[] = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                               "POST /second HTTP/1.1\r\nHost: localhost\r\n"
                               "Content-Length: 4\r\nConnection: close\r\n\r\n";
    hpl_t h;
    hpl_result_t r;
    const int opened = hpl_open(&h, 0);
    if (opened) {
        hpl_send(&h, head, sizeof head - 1);
        hpl_loop(&h, "abcd");
    }
    hpl_close(&h, &r);

    TEST_REQUIRE(opened, "harness must start");
    TEST_ASSERT_EQUAL_SIZE(2, r.responses, "both requests are answered");
    TEST_ASSERT_EQUAL_SIZE(1, r.keepalive, "the first answer keeps the connection");
    TEST_ASSERT(r.last_close, "the second answer says Connection: close");
    TEST_ASSERT(r.destroyed, "and the connection is closed after it");
}

TEST(test_pipeline_keepalive_on_request_with_late_body) {
    TEST_SUITE("http1 pipelining");
    TEST_CASE("control: the same exchange without close keeps the connection");

    static const char head[] = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                               "POST /second HTTP/1.1\r\nHost: localhost\r\n"
                               "Content-Length: 4\r\n\r\n";
    hpl_t h;
    hpl_result_t r;
    const int opened = hpl_open(&h, 0);
    if (opened) {
        hpl_send(&h, head, sizeof head - 1);
        hpl_loop(&h, "abcd");
    }
    hpl_close(&h, &r);

    TEST_REQUIRE(opened, "harness must start");
    TEST_ASSERT_EQUAL_SIZE(2, r.responses, "both requests are answered");
    TEST_ASSERT_EQUAL_SIZE(2, r.keepalive, "both keep the connection");
    TEST_ASSERT(!r.destroyed, "which stays open");
}

/* The race: a worker has taken the first request's item off ctx->queue and
 * the read path, still inside the same __read, reaches a request it answers by
 * itself. The server's socket blocks, so __read waits in recv for the end of
 * the second request -- which this worker sends only once it holds the item,
 * and it runs the item only once __read has returned. That is the
 * interleaving a real worker produces by chance. */
typedef struct {
    hpl_t* h;
    const char* rest;
    atomic_int read_done;
    int took_item;
} hpl_race_t;

static void* hpl_race_worker(void* arg) {
    hpl_race_t* race = arg;
    connection_t* queued = NULL;

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        queued = __connection_queue_pop();
        if (queued != NULL) break;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 2) break;
        sched_yield();
    }

    connection_queue_item_t* item = NULL;
    if (queued != NULL) {
        connection_server_ctx_t* qctx = queued->ctx;
        cqueue_lock(qctx->queue);
        item = cqueue_pop(qctx->queue);
        cqueue_unlock(qctx->queue);
        race->took_item = item != NULL;
    }

    hpl_send(race->h, race->rest, strlen(race->rest));

    while (!atomic_load(&race->read_done)) sched_yield();

    if (item != NULL) { item->run(item); item->free(item); }
    if (queued != NULL) connection_s_dec(queued);
    return NULL;
}

TEST(test_pipeline_inline_answer_waits_for_worker) {
    TEST_SUITE("http1 pipelining");
    TEST_CASE("an answer the read path makes itself waits behind one a worker is building");

    static const char first[] = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                "GET /second HTTP/1.1\r\nHost: loc";
    hpl_t h;
    hpl_result_t r;
    hpl_race_t race = { .h = &h, .rest = "alhost\r\n\r\n", .read_done = 0, .took_item = 0 };
    int started = 0;

    const int opened = hpl_open(&h, 1);
    if (opened) {
        hpl_send(&h, first, sizeof first - 1);

        pthread_t worker;
        started = pthread_create(&worker, NULL, hpl_race_worker, &race) == 0;
        if (started) {
            h.alive = http_server_guard_read(h.connection);
            atomic_store(&race.read_done, 1);
            pthread_join(worker, NULL);
        }

        fcntl(h.sv[0], F_SETFL, fcntl(h.sv[0], F_GETFL) | O_NONBLOCK);
        hpl_loop(&h, NULL);
    }
    hpl_close(&h, &r);

    TEST_REQUIRE(opened && started, "harness must start");
    TEST_ASSERT(race.took_item, "the worker took the first request off the queue mid-read");
    TEST_ASSERT_EQUAL_SIZE(2, r.responses, "both requests are answered");
    TEST_ASSERT(strcmp(r.order, "404 404") == 0, "in order");
    TEST_ASSERT_EQUAL_SIZE(2, r.keepalive, "both keep the connection");
    TEST_ASSERT(!r.destroyed, "which stays open");
}

TEST(test_pipeline_refusal_waits_for_worker) {
    TEST_SUITE("http1 pipelining");
    TEST_CASE("a parse refusal waits behind the answer a worker is building, then closes");

    static const char first[] = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                "GET /second HTTP/1.1\r\nHost: loc";
    hpl_t h;
    hpl_result_t r;
    hpl_race_t race = { .h = &h, .rest = "alhost\r\nBad Header: x\r\n\r\n", .read_done = 0, .took_item = 0 };
    int started = 0;

    const int opened = hpl_open(&h, 1);
    if (opened) {
        hpl_send(&h, first, sizeof first - 1);

        pthread_t worker;
        started = pthread_create(&worker, NULL, hpl_race_worker, &race) == 0;
        if (started) {
            h.alive = http_server_guard_read(h.connection);
            atomic_store(&race.read_done, 1);
            pthread_join(worker, NULL);
        }

        fcntl(h.sv[0], F_SETFL, fcntl(h.sv[0], F_GETFL) | O_NONBLOCK);
        hpl_loop(&h, NULL);
    }
    hpl_close(&h, &r);

    TEST_REQUIRE(opened && started, "harness must start");
    TEST_ASSERT(race.took_item, "the worker took the first request off the queue mid-read");
    TEST_ASSERT_EQUAL_SIZE(2, r.responses, "both requests are answered");
    TEST_ASSERT(strcmp(r.order, "404 400") == 0, "the first request's answer, then the refusal");
    TEST_ASSERT(r.last_close, "the refusal says Connection: close");
    TEST_ASSERT(r.destroyed, "and the connection is closed after it");
}

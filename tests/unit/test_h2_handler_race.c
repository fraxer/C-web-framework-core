/*
 * HTTP/2: a handler running on a worker thread, and the event loop acting on
 * the same connection meanwhile.
 *
 * HTTP/1.1 had a race here (test_http_pipeline.c): its one response slot on
 * the connection was taken by an answer the read path made itself while a
 * worker was still building the answer ahead of it. h2 has no such slot -- a
 * response belongs to its stream, handlers of one connection run in parallel
 * by design, and what keeps them apart is three rules these tests pin down
 * with a real worker thread rather than the fuzzers' single-threaded replay:
 *
 *  - an answer the read path makes itself goes to its own stream, whatever a
 *    worker is doing with another one (h2_server_publish_inline);
 *  - RST_STREAM on a stream whose handler is running only marks it cancelled
 *    (h2stream_close, handler_pending); the stream, its request and its
 *    response live until the handler publishes, and then go without a frame;
 *  - a connection closed under a running handler is freed by the last
 *    reference, which the worker holds (__ctx_free), so the late publish
 *    reaches a live session and nothing is freed twice.
 *
 * ASan (the default Debug build) reports what a broken rule would leave
 * behind; TSan (-DSANITIZE=thread) the unsynchronised access.
 */

#include "framework.h"
#include "appconfig.h"
#include "connection_s.h"
#include "connection_queue.h"
#include "cqueue.h"
#include "domain.h"
#include "h2frame.h"
#include "h2session.h"
#include "h2stream.h"
#include "hpack.h"
#include "httpcontext.h"
#include "multiplexing.h"
#include "route.h"
#include "server.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

extern connection_t* __connection_queue_pop(void);

#define H2R_BUFFER 16384
#define H2R_WIRE (1 << 18)
#define H2R_STREAMS 16
#define H2R_ERR_CANCEL 0x8

static char h2r_domain_template[] = "localhost";

static domain_t h2r_domain = {
    .is_literal = 1,
    .template = h2r_domain_template,
    .ascii_template = h2r_domain_template,
    .ascii_length = sizeof h2r_domain_template - 1,
    .next = NULL
};

static server_t h2r_server = {
    .ip = { .family = AF_INET, .u = { .v4 = { .s_addr = 0x0100007F } } },
    .port = 8080,
    .domain = &h2r_domain,
    .next = NULL
};

static cqueue_item_t h2r_queue_item = { .data = &h2r_server, .next = NULL };

static int h2r_mpx_arm(connection_t* connection, int flags) {
    (void)connection;
    (void)flags;
    return 1;
}

static int h2r_mpx_del(connection_t* connection) {
    (void)connection;
    return 1;
}

static mpxapi_t h2r_mpxapi = {
    .control_add = h2r_mpx_arm,
    .control_mod = h2r_mpx_arm,
    .control_del = h2r_mpx_del,
};

static listener_t h2r_listener = {
    .servers = { .item = &h2r_queue_item, .last_item = &h2r_queue_item, .size = 1, .locked = 0 },
    .connection = NULL,
    .api = &h2r_mpxapi,
    .next = NULL
};

/* ---- The handler behind /slow: holds the worker until the test lets go. ---- */

static atomic_int h2r_entered;
static atomic_int h2r_release;
static atomic_int h2r_finished;

static void h2r_slow_handler(void* arg) {
    httpctx_t* ctx = arg;
    atomic_fetch_add(&h2r_entered, 1);
    while (!atomic_load(&h2r_release)) sched_yield();
    ctx->response->send_datan(ctx->response, "slow", 4);
    atomic_fetch_add(&h2r_finished, 1);
}

static void h2r_server_init(void) {
    static int done;
    if (done) return;
    route_t* slow = route_create("/slow");
    if (slow == NULL || !route_set_http_handler(slow, "GET", h2r_slow_handler, NULL)) return;
    h2r_server.http.route = slow;
    connection_queue_init();
    done = 1;
}

/* ---- A real worker thread, the loop of threadhandler.c without its wait. ---- */

static atomic_int h2r_stop;
static atomic_int h2r_items_done;

static void* h2r_worker(void* arg) {
    (void)arg;
    while (!atomic_load(&h2r_stop)) {
        connection_t* connection = __connection_queue_pop();
        if (connection == NULL) { sched_yield(); continue; }

        connection_server_ctx_t* ctx = connection->ctx;
        cqueue_lock(ctx->queue);
        connection_queue_item_t* item = cqueue_pop(ctx->queue);
        cqueue_unlock(ctx->queue);
        if (item != NULL) { item->run(item); item->free(item); }
        connection_s_dec(connection);
        atomic_fetch_add(&h2r_items_done, 1);
    }
    return NULL;
}

static int h2r_wait(atomic_int* value, int want) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (atomic_load(value) < want) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 3) return 0;
        sched_yield();
    }
    return 1;
}

/* ---- The client end ---- */

typedef struct {
    int      headers;      /* HEADERS frames seen */
    int      status;       /* :status of the first */
    size_t   data;         /* DATA payload bytes */
    int      ended;        /* END_STREAM seen */
    int      reset;        /* RST_STREAM seen */
} h2r_stream_t;

typedef struct {
    int sv[2];
    char* buffer;
    connection_t* connection;
    connection_server_ctx_t* ctx;
    int alive;
    hpack_encoder_t* enc;
    hpack_decoder_t* dec;
    uint8_t* wire;
    size_t wire_len;
    size_t parsed;
    h2r_stream_t streams[H2R_STREAMS];
    pthread_t worker;
    int worker_started;
} h2r_t;

static void h2r_send(h2r_t* h, const void* data, size_t length) {
    const uint8_t* p = data;
    size_t sent = 0;
    while (sent < length) {
        const ssize_t w = send(h->sv[1], p + sent, length - sent, MSG_NOSIGNAL);
        if (w <= 0) break;
        sent += (size_t)w;
    }
}

static void h2r_send_frame(h2r_t* h, uint8_t type, uint8_t flags, uint32_t id,
                           const uint8_t* payload, size_t len) {
    uint8_t frame[1024];
    const size_t n = h2frame_encode(frame, sizeof frame, type, flags, id, payload, len);
    if (n != 0) h2r_send(h, frame, n);
}

static void h2r_request(h2r_t* h, uint32_t id, const char* path) {
    hpack_header_t fields[] = {
        { (char*)":method", 7, (char*)"GET", 3, 0 },
        { (char*)":scheme", 7, (char*)"http", 4, 0 },
        { (char*)":path", 5, (char*)path, strlen(path), 0 },
        { (char*)":authority", 10, (char*)"localhost", 9, 0 },
    };
    uint8_t* block = NULL;
    size_t block_len = 0;
    if (hpack_encoder_encode(h->enc, fields, 4, 0, &block, &block_len) != HPACK_OK) return;
    h2r_send_frame(h, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, id,
                   block, block_len);
    free(block);
}

static void h2r_reset(h2r_t* h, uint32_t id) {
    const uint8_t code[4] = { 0, 0, 0, H2R_ERR_CANCEL };
    h2r_send_frame(h, H2_FRAME_RST_STREAM, 0, id, code, sizeof code);
}

/* Everything the server has written so far, frame by frame. Every header block
 * is decoded, in order, to keep the HPACK table in step. */
static void h2r_take(h2r_t* h) {
    for (;;) {
        const ssize_t r = recv(h->sv[1], h->wire + h->wire_len, H2R_WIRE - h->wire_len, 0);
        if (r <= 0) break;
        h->wire_len += (size_t)r;
    }

    while (h->wire_len - h->parsed >= 9) {
        const uint8_t* f = h->wire + h->parsed;
        const size_t len = (size_t)f[0] << 16 | (size_t)f[1] << 8 | f[2];
        if (h->wire_len - h->parsed < 9 + len) break;
        const uint8_t type = f[3], flags = f[4];
        const uint32_t id = ((uint32_t)(f[5] & 0x7f) << 24) | (uint32_t)f[6] << 16 |
                            (uint32_t)f[7] << 8 | f[8];
        const uint8_t* payload = f + 9;
        h2r_stream_t* st = id < H2R_STREAMS ? &h->streams[id] : NULL;

        if (st != NULL && type == H2_FRAME_HEADERS) {
            hpack_header_t* fields = NULL;
            size_t count = 0;
            if (hpack_decoder_decode(h->dec, payload, len, 65536, &fields, &count) == HPACK_OK) {
                for (size_t i = 0; i < count; i++)
                    if (fields[i].name_len == 7 && memcmp(fields[i].name, ":status", 7) == 0 &&
                        st->headers == 0)
                        st->status = atoi(fields[i].value);
                hpack_headers_free(fields, count);
            }
            st->headers++;
        }
        if (st != NULL && type == H2_FRAME_DATA) st->data += len;
        if (st != NULL && type == H2_FRAME_RST_STREAM) st->reset = 1;
        if (st != NULL && (type == H2_FRAME_DATA || type == H2_FRAME_HEADERS) &&
            (flags & H2_FLAG_END_STREAM))
            st->ended = 1;

        h->parsed += 9 + len;
    }
}

static int h2r_open(h2r_t* h) {
    memset(h, 0, sizeof *h);
    h2r_server_init();
    if (h2r_server.http.route == NULL) return 0;

    atomic_store(&h2r_entered, 0);
    atomic_store(&h2r_release, 0);
    atomic_store(&h2r_finished, 0);
    atomic_store(&h2r_stop, 0);
    atomic_store(&h2r_items_done, 0);

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, h->sv) != 0) return 0;
    h->buffer = malloc(H2R_BUFFER);
    h->wire = malloc(H2R_WIRE);
    h->enc = hpack_encoder_create(4096);
    h->dec = hpack_decoder_create(4096);
    if (h->buffer == NULL || h->wire == NULL || h->enc == NULL || h->dec == NULL) return 0;

    const ipaddr_t loopback = ipaddr_from_v4(0x0100007F);
    h->connection = connection_s_alloc(&h2r_listener, h->sv[0], &loopback, 8080,
                                       &loopback, 40000, h->buffer, H2R_BUFFER);
    if (h->connection == NULL) return 0;
    h->ctx = h->connection->ctx;
    h->ctx->server = &h2r_server;
    h->alive = h2_server_set_http2(h->connection);
    if (!h->alive) return 0;

    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    h2r_send(h, preface, sizeof preface - 1);
    h2r_send_frame(h, H2_FRAME_SETTINGS, 0, 0, NULL, 0);

    h->worker_started = pthread_create(&h->worker, NULL, h2r_worker, NULL) == 0;
    return h->worker_started;
}

static void h2r_read(h2r_t* h) {
    if (h->alive) h->alive = h2_server_guard_read(h->connection);
}

static void h2r_write(h2r_t* h) {
    if (h->alive) h->alive = h2_server_guard_write(h->connection);
    h2r_take(h);
}

/* Write passes until the stream has ended or the time is up: the worker
 * publishes whenever the scheduler lets it. */
static int h2r_until_ended(h2r_t* h, uint32_t id) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!h->streams[id].ended && !h->streams[id].reset) {
        h2r_write(h);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 3) return 0;
        sched_yield();
    }
    return 1;
}

static h2stream_t* h2r_stream(h2r_t* h, uint32_t id) {
    h2session_t* s = h2_session_of(h->connection);
    if (s == NULL) return NULL;
    for (h2stream_t* st = s->streams; st != NULL; st = st->next)
        if (st->id == id) return st;
    return NULL;
}

static void h2r_stop_worker(h2r_t* h) {
    atomic_store(&h2r_release, 1);
    if (h->worker_started) {
        atomic_store(&h2r_stop, 1);
        pthread_join(h->worker, NULL);
        h->worker_started = 0;
    }
}

/* Teardown of a connection that is still open: as fuzz_h2_connection does it,
 * once no handler is left. */
static void h2r_close(h2r_t* h) {
    h2r_stop_worker(h);
    if (h->connection != NULL) {
        connection_s_free_local(h->connection);
        close(h->sv[0]);
    }
    else if (h->sv[0] > 0)
        close(h->sv[0]);
    if (h->sv[1] > 0) close(h->sv[1]);
    hpack_encoder_free(h->enc);
    hpack_decoder_free(h->dec);
    free(h->buffer);
    free(h->wire);
}

TEST(test_h2_race_inline_answer_while_handler_runs) {
    TEST_SUITE("h2: handlers on a worker");
    TEST_CASE("an answer the read path makes itself goes out while another stream's handler runs");

    h2r_t h;
    const int opened = h2r_open(&h);
    if (opened) {
        h2r_request(&h, 1, "/slow");
        h2r_request(&h, 3, "/missing");
        h2r_read(&h);
    }

    TEST_REQUIRE(opened, "harness must start");
    TEST_ASSERT(h2r_wait(&h2r_entered, 1), "stream 1's handler is running on the worker");

    h2r_write(&h);
    TEST_ASSERT_EQUAL(404, h.streams[3].status, "stream 3 is answered at once, 404");
    TEST_ASSERT(h.streams[3].ended, "and ended");
    TEST_ASSERT_EQUAL(0, h.streams[1].headers, "stream 1 has nothing yet");
    TEST_ASSERT(h2r_stream(&h, 1) != NULL, "and is still held for its handler");

    atomic_store(&h2r_release, 1);
    TEST_ASSERT(h2r_until_ended(&h, 1), "stream 1 is answered once its handler is done");
    TEST_ASSERT_EQUAL(200, h.streams[1].status, "with 200");
    TEST_ASSERT_EQUAL_SIZE(4, h.streams[1].data, "and its own body");
    TEST_ASSERT_EQUAL(1, h.streams[3].headers, "stream 3 got one answer, not two");
    TEST_ASSERT(h.alive, "the connection stays up");

    h2r_close(&h);
}

TEST(test_h2_race_reset_while_handler_runs) {
    TEST_SUITE("h2: handlers on a worker");
    TEST_CASE("RST_STREAM while the handler runs: the stream waits for it, then goes without a frame");

    h2r_t h;
    const int opened = h2r_open(&h);
    if (opened) {
        h2r_request(&h, 1, "/slow");
        h2r_read(&h);
    }

    TEST_REQUIRE(opened, "harness must start");
    TEST_ASSERT(h2r_wait(&h2r_entered, 1), "the handler is running on the worker");

    h2r_reset(&h, 1);
    h2r_read(&h);
    h2stream_t* held = h2r_stream(&h, 1);
    TEST_ASSERT(held != NULL, "the reset stream is still there while its handler runs");
    TEST_ASSERT(held != NULL && atomic_load(&held->cancelled), "marked cancelled");
    TEST_ASSERT(held != NULL && atomic_load(&held->handler_pending), "and held for the handler");

    atomic_store(&h2r_release, 1);
    TEST_ASSERT(h2r_wait(&h2r_items_done, 1), "the handler finished and published");

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (h2r_stream(&h, 1) != NULL) {
        h2r_write(&h);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 3) break;
        sched_yield();
    }
    TEST_ASSERT(h2r_stream(&h, 1) == NULL, "the stream is released once the answer is in");
    TEST_ASSERT_EQUAL(0, h.streams[1].headers, "and nothing was sent for it");
    TEST_ASSERT_EQUAL_SIZE(0, h.streams[1].data, "not a byte of the body");

    h2r_request(&h, 3, "/slow");
    h2r_read(&h);
    TEST_ASSERT(h2r_until_ended(&h, 3), "the next stream on the connection is answered");
    TEST_ASSERT_EQUAL(200, h.streams[3].status, "with 200");
    TEST_ASSERT(h.alive, "the connection stays up");

    h2r_close(&h);
}

TEST(test_h2_race_close_while_handler_runs) {
    TEST_SUITE("h2: handlers on a worker");
    TEST_CASE("the peer goes while a handler runs: the late answer is dropped, the worker frees the connection");

    h2r_t h;
    const int opened = h2r_open(&h);
    if (opened) {
        h2r_request(&h, 1, "/slow");
        h2r_read(&h);
    }

    TEST_REQUIRE(opened, "harness must start");
    TEST_ASSERT(h2r_wait(&h2r_entered, 1), "the handler is running on the worker");

    /* The peer hangs up; the event loop sees EOF and closes, as
     * multiplexingepoll.c does on a 0 from read. connection_close drops the
     * base reference -- the worker's is what keeps the context alive now. */
    close(h.sv[1]);
    h.sv[1] = -1;
    h2r_read(&h);
    TEST_ASSERT(!h.alive, "the read path reports the peer gone");
    connection_close(h.connection);
    h.connection = NULL;
    h.sv[0] = -1;                              /* closed by connection_close */

    atomic_store(&h2r_release, 1);
    TEST_ASSERT(h2r_wait(&h2r_finished, 1), "the handler ran to the end");
    TEST_ASSERT(h2r_wait(&h2r_items_done, 1), "and the worker let the connection go");

    h2r_close(&h);
}

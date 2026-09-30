#include "framework.h"

#include "connection_s.h"
#include "h3conn.h"
#include "h3error.h"
#include "h3frame.h"
#include "httpresponse.h"
#include "qpack.h"
#include "quicsendbuf.h"
#include "quicstream.h"
#include "varint.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* HTTP/3: a handler running on a worker thread while the connection's own
 * thread reads and writes the same connection.
 *
 * HTTP/1.1 had a race here (test_http_pipeline.c): its one response slot was
 * taken by an answer the read path made itself while a worker still built the
 * answer ahead of it. h3 has no such slot -- the response belongs to its
 * stream (h3_server_attach_response) -- and what keeps a running handler's
 * objects alive is that the transport reaps a stream only once the
 * application says it is done with it (quicconn.c __streams_reap, app_done),
 * which for a request is once its response has been written. These cases pin
 * both down with a real thread for the handler, on the bare-connection
 * fixture of test_h3dispatch.c: no handshake, the stream list and the
 * publication path are real. The connection's thread holds connection_s_lock
 * around its turns, as the endpoint does, and the handler publishes through
 * h3_server_response_ready, which takes it. */

#define STREAM_WINDOW (1024 * 1024)

typedef struct {
    quicconn_t*              qc;
    connection_server_ctx_t  ctx;
    h3conn_t*                c;
} h3rfixture_t;

static void h3r_fixture_init(h3rfixture_t* f) {
    f->qc = calloc(1, sizeof * f->qc);
    f->c = h3conn_create(NULL, 65536, 0);

    memset(&f->ctx, 0, sizeof f->ctx);
    f->ctx.parser = f->c;

    f->qc->conn.transport = CONN_TRANSPORT_QUIC;
    f->qc->conn.ctx = &f->ctx;
}

static void h3r_fixture_free(h3rfixture_t* f) {
    for (quicstream_t* qs = f->qc->streams; qs != NULL; ) {
        quicstream_t* next = qs->next;
        h3conn_stream_release(qs);
        quicstream_free(qs);
        qs = next;
    }

    h3conn_free(f->c);
    free(f->qc);
}

/* A client bidi stream carrying a complete GET, already read. `*length` is
 * the stream's final size, which a RESET_STREAM has to repeat. */
static quicstream_t* h3r_add_request(h3rfixture_t* f, uint64_t index, uint64_t* length) {
    quicstream_t* qs = quicstream_create(index << 2, STREAM_WINDOW, STREAM_WINDOW,
                                         STREAM_WINDOW);
    qs->next = f->qc->streams;
    f->qc->streams = qs;
    f->qc->stream_count++;

    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    const qpack_header_t fields[] = {
        { (char*)":method", 7, (char*)"GET", 3, 0 },
        { (char*)":path", 5, (char*)"/", 1, 0 },
        { (char*)":scheme", 7, (char*)"https", 5, 0 },
        { (char*)":authority", 10, (char*)"example.com", 11, 0 },
    };
    uint8_t block[192];
    const size_t blen = qpack_encode_block(enc, fields, 4, block, sizeof block);
    qpack_encoder_free(enc);

    uint8_t req[256];
    const size_t rlen = h3frame_write(req, sizeof req, H3_FRAME_HEADERS, block, blen);
    quicstream_on_data(qs, 0, req, rlen, 1);
    h3conn_stream_read(f->c, NULL, qs);

    if (length != NULL) *length = rlen;
    return qs;
}

static size_t h3r_frames(const quicstream_t* qs, uint64_t type, size_t* payload_total) {
    const uint8_t* p = qs->send.data;
    const size_t len = qs->send.len;
    size_t off = 0, count = 0, total = 0;

    while (off < len) {
        uint64_t t = 0, plen = 0;
        size_t n = varint_read(p + off, len - off, &t);
        if (n == 0) break;
        off += n;
        n = varint_read(p + off, len - off, &plen);
        if (n == 0) break;
        off += n;
        if (off + plen > len) break;

        if (t == type) { count++; total += (size_t)plen; }
        off += (size_t)plen;
    }

    if (payload_total != NULL) *payload_total = total;
    return count;
}

/* ---- The handler: a real thread holding a response until it is let go. ---- */

typedef struct {
    connection_t*   connection;
    httpresponse_t* response;
    atomic_int      entered;
    atomic_int      release;
    atomic_int      published;
} h3r_handler_t;

static void* h3r_handler(void* arg) {
    h3r_handler_t* h = arg;
    atomic_store(&h->entered, 1);
    while (!atomic_load(&h->release)) sched_yield();

    /* What a route handler does with its response, on its own thread. */
    h->response->status_code = 200;
    h->response->add_header(h->response, "Content-Type", "text/plain");
    h->response->send_datan(h->response, "slow", 4);
    h3_server_response_ready(h->connection, h->response);

    atomic_store(&h->published, 1);
    return NULL;
}

static int h3r_wait(atomic_int* flag) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!atomic_load(flag)) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 3) return 0;
        sched_yield();
    }
    return 1;
}

/* A turn of the connection's own thread: under the lock, as the endpoint
 * takes it. */
static int h3r_write(h3rfixture_t* f) {
    connection_s_lock(&f->qc->conn, LOCK_SITE_OTHER);
    const int r = h3conn_write(f->c, f->qc);
    connection_s_unlock(&f->qc->conn);
    return r;
}

static int h3r_read(h3rfixture_t* f, uint64_t* error) {
    connection_s_lock(&f->qc->conn, LOCK_SITE_OTHER);
    const int r = h3conn_read(f->c, f->qc, error);
    connection_s_unlock(&f->qc->conn);
    return r;
}

TEST(test_h3_race_inline_answer_while_handler_runs) {
    TEST_SUITE("h3: handlers on a worker");
    TEST_CASE("an answer the read path makes itself goes to its own stream while another's handler runs");

    h3rfixture_t f;
    h3r_fixture_init(&f);
    quicstream_t* slow = h3r_add_request(&f, 0, NULL);
    quicstream_t* fast = h3r_add_request(&f, 1, NULL);
    h3stream_t* slow_st = h3conn_request_of(slow);
    h3stream_t* fast_st = h3conn_request_of(fast);
    TEST_REQUIRE(slow_st != NULL && fast_st != NULL, "both requests built");

    /* Both dispatched: the first to a handler, which binds its response to the
     * stream before it runs (__handle), the second answered on the read path. */
    httpresponse_t* r_slow = httpresponse_create_h3(&f.qc->conn);
    TEST_REQUIRE(h3_server_attach_response(&f.qc->conn, slow_st->request, r_slow) == 1,
                 "handler's response bound");
    h3r_handler_t handler = { .connection = &f.qc->conn, .response = r_slow };
    pthread_t thread;
    const int started = pthread_create(&thread, NULL, h3r_handler, &handler) == 0;
    TEST_REQUIRE(started, "handler thread started");
    TEST_ASSERT(h3r_wait(&handler.entered), "the handler is running");

    httpresponse_t* r_fast = httpresponse_create_h3(&f.qc->conn);
    connection_s_lock(&f.qc->conn, LOCK_SITE_OTHER);
    TEST_ASSERT(h3_server_attach_response(&f.qc->conn, fast_st->request, r_fast) == 1,
                "inline response bound");
    httpresponse_default(r_fast, 404);
    h3_server_publish_inline(&f.qc->conn, r_fast);
    connection_s_unlock(&f.qc->conn);

    TEST_ASSERT(h3r_write(&f) == 1, "write turn ran");
    TEST_ASSERT(h3r_frames(fast, H3_FRAME_HEADERS, NULL) == 1, "the inline answer went out");
    TEST_ASSERT(fast->send.fin, "and finished its stream");
    TEST_ASSERT(slow->send.len == 0, "nothing on the handler's stream yet");
    TEST_ASSERT(slow_st->response == r_slow, "which still holds the handler's response");
    TEST_ASSERT(slow->app_done(slow->app) == 0, "and is not reapable");

    atomic_store(&handler.release, 1);
    pthread_join(thread, NULL);
    TEST_ASSERT(atomic_load(&handler.published), "the handler published");

    TEST_ASSERT(h3r_write(&f) == 1, "write turn ran");
    size_t payload = 0;
    TEST_ASSERT(h3r_frames(slow, H3_FRAME_HEADERS, NULL) == 1, "the handler's answer went out");
    TEST_ASSERT(h3r_frames(slow, H3_FRAME_DATA, &payload) >= 1 && payload == 4,
                "with its own body");
    TEST_ASSERT(slow->send.fin, "and finished its stream");
    TEST_ASSERT(h3r_frames(fast, H3_FRAME_HEADERS, NULL) == 1, "the other stream got one answer");
    TEST_ASSERT(slow->app_done(slow->app) == 1, "both are reapable now");

    h3r_fixture_free(&f);
}

TEST(test_h3_race_reset_while_handler_runs) {
    TEST_SUITE("h3: handlers on a worker");
    TEST_CASE("RESET_STREAM + STOP_SENDING while the handler runs: the stream is kept until its answer is in");

    h3rfixture_t f;
    h3r_fixture_init(&f);
    uint64_t length = 0;
    quicstream_t* qs = h3r_add_request(&f, 0, &length);
    h3stream_t* st = h3conn_request_of(qs);
    TEST_REQUIRE(st != NULL, "request built");

    httpresponse_t* r = httpresponse_create_h3(&f.qc->conn);
    TEST_REQUIRE(h3_server_attach_response(&f.qc->conn, st->request, r) == 1,
                 "handler's response bound");
    h3r_handler_t handler = { .connection = &f.qc->conn, .response = r };
    pthread_t thread;
    const int started = pthread_create(&thread, NULL, h3r_handler, &handler) == 0;
    TEST_REQUIRE(started, "handler thread started");
    TEST_ASSERT(h3r_wait(&handler.entered), "the handler is running");

    /* The client gives up on the request: both directions, as a browser
     * cancelling a fetch does. */
    TEST_ASSERT(quicstream_on_reset(qs, H3_REQUEST_CANCELLED, length) == QUICSTREAM_OK,
                "RESET_STREAM taken");
    TEST_ASSERT(quicstream_on_stop_sending(qs, H3_REQUEST_CANCELLED) == QUICSTREAM_OK,
                "STOP_SENDING taken");
    uint64_t error = 0;
    TEST_ASSERT(h3r_read(&f, &error) == 1, "the read turn handles the reset");
    TEST_ASSERT(h3r_write(&f) == 1, "and a write turn runs");

    /* Both halves of the transport are finished now; the stream stays only
     * because the application still holds it -- the handler's objects are on
     * it. __streams_reap asks exactly this. */
    TEST_ASSERT(qs->app_done(qs->app) == 0, "the stream is not reapable while the handler runs");
    TEST_ASSERT(st->response == r, "and still holds the handler's response");

    atomic_store(&handler.release, 1);
    pthread_join(thread, NULL);
    TEST_ASSERT(atomic_load(&handler.published), "the handler finished and published");

    TEST_ASSERT(h3r_write(&f) == 1, "write turn ran");
    TEST_ASSERT(qs->app_done(qs->app) == 1, "the stream is reapable once the answer is in");
    TEST_ASSERT(h3r_frames(qs, H3_FRAME_DATA, NULL) == 0, "and none of the body was queued on it");

    h3r_fixture_free(&f);
}

#include "framework.h"

#include "h3conn.h"
#include "h3frame.h"
#include "h3response.h"
#include "httpresponse.h"
#include "qpack.h"
#include "quicsendbuf.h"
#include "quicstream.h"
#include "varint.h"

#include <stdlib.h>
#include <string.h>

/* The publication trio and the write turn (docs/http3/05-http3.md §6.2, §6.3).
 *
 * A bare quicconn_t again: everything under test reads the stream list and the
 * embedded connection_t, and a handshake would add nothing. The connection's
 * ctx is filled just enough that h3_conn_of resolves -- which is the whole
 * mechanism these cases exist to pin down, because getting it wrong is how the
 * response of one stream ends up on another. */

#define STREAM_WINDOW (1024 * 1024)

typedef struct {
    quicconn_t*              qc;
    connection_server_ctx_t  ctx;
    h3conn_t*                c;
} h3fixture_t;

static void fixture_init(h3fixture_t* f) {
    f->qc = calloc(1, sizeof * f->qc);
    /* NULL, not &f->qc->conn: a bare connection has no listener and therefore
     * no vhost list, so select_server would refuse every request. What the
     * connection is needed for -- routing and virtual-host selection -- is
     * exactly what only the end-to-end client can exercise (tests/quicclient). */
    f->c = h3conn_create(NULL, 65536, 0);

    memset(&f->ctx, 0, sizeof f->ctx);
    f->ctx.parser = f->c;

    f->qc->conn.transport = CONN_TRANSPORT_QUIC;
    f->qc->conn.ctx = &f->ctx;
}

static void fixture_free(h3fixture_t* f) {
    for (quicstream_t* qs = f->qc->streams; qs != NULL; ) {
        quicstream_t* next = qs->next;
        h3conn_stream_release(qs);
        quicstream_free(qs);
        qs = next;
    }

    h3conn_free(f->c);
    free(f->qc);
}

/* Attach a client bidi stream carrying a complete GET, already read. */
static quicstream_t* add_request(h3fixture_t* f, uint64_t index) {
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

    return qs;
}

static quicstream_t* add_blocked_request(h3fixture_t* f, uint64_t index) {
    quicstream_t* qs = quicstream_create(index << 2, STREAM_WINDOW, STREAM_WINDOW,
                                         STREAM_WINDOW);
    qs->next = f->qc->streams;
    f->qc->streams = qs;
    f->qc->stream_count++;
    /* HEADERS whose encoded RIC=2 resolves to Required Insert Count 1 when the
     * decoder has capacity but has received no insertions yet. */
    static const uint8_t request[] = { H3_FRAME_HEADERS, 0x02, 0x02, 0x00 };
    quicstream_on_data(qs, 0, request, sizeof request, 0);
    return qs;
}

/* The frames queued on a stream's send buffer, by type. */
static size_t queued_frames(const quicstream_t* qs, uint64_t type, size_t* payload_total) {
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

TEST(test_h3dispatch_publish) {
    TEST_SUITE("h3dispatch");

    TEST_CASE("a response is bound to the stream that asked for it");
    h3fixture_t f;
    fixture_init(&f);
    quicstream_t* qs = add_request(&f, 0);

    h3stream_t* st = h3conn_request_of(qs);
    TEST_ASSERT(st != NULL && st->headers_done, "request built");
    /* h3conn_t is what lives in ctx->parser, so it is h3conn_t that has to carry
     * the free-through-a-void* contract __ctx_free relies on. */
    TEST_ASSERT(f.c->free == (void(*)(void*))h3conn_free, "free is the first field");

    httpresponse_t* r = httpresponse_create_h3(&f.qc->conn);
    TEST_ASSERT(h3_server_attach_response(&f.qc->conn, st->request, r) == 1, "attached");
    TEST_ASSERT(st->response == r, "bound to the stream");
    TEST_ASSERT(h3conn_stream_by_response(f.qc, r) == qs, "and findable from the response");

    TEST_CASE("publishing marks the stream ready");
    TEST_ASSERT(!atomic_load(&st->response_ready), "not ready yet");
    TEST_ASSERT(h3_server_publish_inline(&f.qc->conn, r) == 1, "published");
    TEST_ASSERT(atomic_load(&st->response_ready), "ready");
    TEST_ASSERT(atomic_load(&f.ctx.need_write), "and the connection is flagged");

    fixture_free(&f);

    TEST_CASE("a request nobody owns cannot be attached");
    fixture_init(&f);
    httpresponse_t* orphan = httpresponse_create_h3(&f.qc->conn);
    TEST_ASSERT(h3_server_attach_response(&f.qc->conn, NULL, orphan) == 0, "no stream");
    httpresponse_free(orphan);
    fixture_free(&f);

    TEST_CASE("a late handler publish after hard-reload detach is ignored safely");
    fixture_init(&f);
    qs = add_request(&f, 0);
    st = h3conn_request_of(qs);
    r = httpresponse_create_h3(&f.qc->conn);
    TEST_ASSERT(h3_server_attach_response(&f.qc->conn, st->request, r) == 1,
                "response attached before detach");

    /* quicconn_want_write would dereference qc->endpoint, deliberately NULL in
     * this fixture.  Reaching it after detach therefore makes this regression
     * fail immediately, while the correct path leaves ownership with the
     * stream: teardown frees the response together with that stream. */
    atomic_store_explicit(&f.ctx.detached, 1, memory_order_release);
    TEST_ASSERT(h3_server_response_ready(&f.qc->conn, r) == 1,
                "late completion accepted for teardown");
    TEST_ASSERT(st->response == r, "stream retains response ownership");
    TEST_ASSERT(!atomic_load(&st->response_ready), "response was not published");
    TEST_ASSERT(!atomic_load(&f.ctx.need_write), "detached endpoint was not woken");
    TEST_ASSERT(!atomic_load(&f.qc->want_write), "QUIC write turn was not queued");
    fixture_free(&f);
}

TEST(test_h3dispatch_write_turn) {
    TEST_SUITE("h3dispatch");

    TEST_CASE("the write turn emits HEADERS and DATA and finishes the stream");
    h3fixture_t f;
    fixture_init(&f);
    quicstream_t* qs = add_request(&f, 0);
    h3stream_t* st = h3conn_request_of(qs);

    httpresponse_t* r = httpresponse_create_h3(&f.qc->conn);
    h3_server_attach_response(&f.qc->conn, st->request, r);
    r->status_code = 200;
    r->add_header(r, "Content-Type", "text/plain");
    r->send_datan(r, "hello", 5);
    h3_server_publish_inline(&f.qc->conn, r);

    TEST_ASSERT(h3conn_write(f.c, f.qc) == 1, "write turn ran");
    TEST_ASSERT(st->response_done, "response finished");
    TEST_ASSERT(!atomic_load(&st->response_ready), "flag cleared");

    size_t payload = 0;
    TEST_ASSERT(queued_frames(qs, H3_FRAME_HEADERS, NULL) == 1, "one HEADERS frame");
    TEST_ASSERT(queued_frames(qs, H3_FRAME_DATA, &payload) >= 1, "at least one DATA frame");
    TEST_ASSERT(payload == 5, "five body bytes");
    TEST_ASSERT(qs->send.fin, "stream finished");

    TEST_CASE("a second turn does nothing to a finished stream");
    const size_t before = qs->send.len;
    TEST_ASSERT(h3conn_write(f.c, f.qc) == 1, "ran");
    TEST_ASSERT(qs->send.len == before, "and wrote nothing more");

    fixture_free(&f);

    TEST_CASE("a stream with no ready response is left alone");
    fixture_init(&f);
    qs = add_request(&f, 0);
    TEST_ASSERT(h3conn_write(f.c, f.qc) == 1, "ran");
    TEST_ASSERT(qs->send.len == 0, "nothing queued");
    TEST_ASSERT(!qs->send.fin, "and the stream is still open");
    fixture_free(&f);

    TEST_CASE("a bodyless response still closes the stream");
    fixture_init(&f);
    qs = add_request(&f, 0);
    st = h3conn_request_of(qs);
    r = httpresponse_create_h3(&f.qc->conn);
    h3_server_attach_response(&f.qc->conn, st->request, r);
    httpresponse_default(r, 204);
    h3_server_publish_inline(&f.qc->conn, r);

    TEST_ASSERT(h3conn_write(f.c, f.qc) == 1, "write turn ran");
    TEST_ASSERT(queued_frames(qs, H3_FRAME_HEADERS, NULL) == 1, "HEADERS");
    TEST_ASSERT(qs->send.fin, "FIN");
    fixture_free(&f);
}

TEST(test_h3dispatch_qpack_decoder_stream) {
    TEST_SUITE("h3dispatch");

    TEST_CASE("queued decoder instructions are written before response turns");
    h3fixture_t f;
    fixture_init(&f);

    quicstream_t* decoder = quicstream_create(3, STREAM_WINDOW, STREAM_WINDOW,
                                               STREAM_WINDOW);
    f.qc->streams = decoder;
    f.qc->stream_count = 1;
    f.c->session->qpack_dec_send_id = decoder->id;

    TEST_ASSERT(qpack_decoder_ack_section(f.c->session->qdec, 12) == QPACK_OK,
                "ack staged");
    TEST_ASSERT(h3conn_write(f.c, f.qc) == 1, "write turn");
    TEST_ASSERT(decoder->send.len == 1 && decoder->send.data[0] == 0x8c,
                "section acknowledgment reached decoder stream");

    const uint8_t* pending = NULL;
    TEST_ASSERT(qpack_decoder_pending(f.c->session->qdec, &pending) == 0,
                "staged bytes consumed exactly once");
    TEST_ASSERT(h3conn_write(f.c, f.qc) == 1 && decoder->send.len == 1,
                "second turn does not duplicate instruction");

    fixture_free(&f);
}

TEST(test_h3dispatch_qpack_blocked_limit_and_reset) {
    TEST_SUITE("h3dispatch qpack blocked");
    h3fixture_t f;
    fixture_init(&f);
    qpack_decoder_free(f.c->session->qdec);
    f.c->session->qdec = qpack_decoder_create(128, 1);

    TEST_CASE("one blocked request occupies exactly one connection slot");
    quicstream_t* first = add_blocked_request(&f, 0);
    h3conn_result_t r = h3conn_stream_read(f.c, f.qc, first);
    TEST_ASSERT(r.status == H3CONN_OK, "blocking is not a stream error");
    TEST_ASSERT(f.c->qpack_blocked_streams == 1, "one blocked slot");
    TEST_ASSERT(h3conn_request_of(first)->qpack_blocked, "stream carries threshold");

    TEST_CASE("a second blocked request over the advertised limit is fatal");
    quicstream_t* second = add_blocked_request(&f, 1);
    r = h3conn_stream_read(f.c, f.qc, second);
    TEST_ASSERT(r.status == H3CONN_CLOSED, "connection closed");
    TEST_ASSERT(r.h3_error == QPACK_DECOMPRESSION_FAILED, "QPACK error code");
    TEST_ASSERT(f.c->qpack_blocked_streams == 1, "rejected stream was not counted");

    TEST_CASE("reset releases the slot and queues Stream Cancellation");
    TEST_ASSERT(quicstream_on_reset(first, H3_REQUEST_CANCELLED, first->recv_flow.used)
                    == QUICSTREAM_OK, "peer reset accepted");
    r = h3conn_stream_read(f.c, f.qc, first);
    TEST_ASSERT(r.status == H3CONN_REQUEST_RESET, "reset reported");
    TEST_ASSERT(f.c->qpack_blocked_streams == 0, "blocked slot released");
    const uint8_t* pending = NULL;
    size_t n = qpack_decoder_pending(f.c->session->qdec, &pending);
    TEST_ASSERT(n == 1 && pending[0] == 0x40, "Stream Cancellation for stream 0");

    fixture_free(&f);
}

TEST(test_h3dispatch_qpack_blocked_retry) {
    TEST_SUITE("h3dispatch qpack blocked");
    h3fixture_t f;
    fixture_init(&f);
    qpack_decoder_free(f.c->session->qdec);
    f.c->session->qdec = qpack_decoder_create(128, 1);

    /* Static :method/:path/:scheme plus dynamic relative index 0 for
     * :authority=example.com. RIC=1 is encoded as 2 with MaxEntries=4. */
    static const uint8_t block[] = { 0x02, 0x00, 0xd1, 0xc1, 0xd7, 0x80 };
    uint8_t request[32];
    const size_t request_len = h3frame_write(request, sizeof request,
                                              H3_FRAME_HEADERS, block, sizeof block);
    quicstream_t* qs = quicstream_create(0, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
    qs->next = f.qc->streams; f.qc->streams = qs; f.qc->stream_count++;
    quicstream_on_data(qs, 0, request, request_len, 1);

    TEST_CASE("future dynamic authority blocks the complete request");
    h3conn_result_t r = h3conn_stream_read(f.c, f.qc, qs);
    TEST_ASSERT(r.status == H3CONN_OK && f.c->qpack_blocked_streams == 1,
                "request retained without dispatch");

    TEST_CASE("encoder insertion retries through FIN and completes the request");
    static const uint8_t insert[] = {
        0x3f, 0x61,             /* capacity 128 */
        0xc0, 0x0b, 'e','x','a','m','p','l','e','.','c','o','m'
    };
    size_t consumed = 0;
    TEST_ASSERT(qpack_decoder_read_encoder(f.c->session->qdec, insert, sizeof insert,
                                           &consumed) == QPACK_OK,
                "authority inserted");
    r = h3conn_stream_read(f.c, f.qc, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_DONE, "saved FIN completed request");
    TEST_ASSERT(f.c->qpack_blocked_streams == 0, "blocked slot released");
    h3stream_t* st = h3conn_request_of(qs);
    TEST_ASSERT(st != NULL && st->request->get_headern(st->request, "Host", 4) != NULL,
                "dynamic authority became Host");

    TEST_CASE("decoder instructions preserve increment before section ack");
    const uint8_t* pending = NULL;
    const size_t n = qpack_decoder_pending(f.c->session->qdec, &pending);
    TEST_ASSERT(n == 2 && pending[0] == 0x01 && pending[1] == 0x80,
                "Insert Count Increment then Section Acknowledgment stream 0");

    fixture_free(&f);
}

/* A response bigger than the connection's write-ahead budget cannot go out in
 * one turn, and nothing but h3conn_has_pending would ever ask for another. */
TEST(test_h3dispatch_large_response) {
    TEST_SUITE("h3dispatch");

    TEST_CASE("a big body takes several turns and reports itself pending");
    h3fixture_t f;
    fixture_init(&f);
    quicstream_t* qs = add_request(&f, 0);
    h3stream_t* st = h3conn_request_of(qs);

    httpresponse_t* r = httpresponse_create_h3(&f.qc->conn);
    h3_server_attach_response(&f.qc->conn, st->request, r);
    r->status_code = 200;

    const size_t size = QUICCONN_WRITE_AHEAD_MAX * 3;
    char* body = malloc(size);
    memset(body, 'x', size);
    r->send_datan(r, body, size);
    free(body);

    h3_server_publish_inline(&f.qc->conn, r);

    TEST_ASSERT(h3conn_write(f.c, f.qc) == 1, "first turn");
    TEST_ASSERT(!st->response_done, "not finished in one turn");
    TEST_ASSERT(h3conn_has_pending(f.c, f.qc), "and it says so");
    TEST_ASSERT(quicconn_unsent_bytes(f.qc) <= QUICCONN_WRITE_AHEAD_MAX + H3_DATA_CHUNK_MAX,
                "memory stayed inside the budget");

    /* Drain and turn again, as the endpoint does once the send path has run. */
    size_t turns = 0;
    while (!st->response_done && turns < 1000) {
        const size_t unsent = quicsendbuf_unsent_bytes(&qs->send);
        if (unsent > 0) quicsendbuf_mark_sent(&qs->send, qs->send.sent_off, unsent, 0);
        h3conn_write(f.c, f.qc);
        turns++;
    }

    TEST_ASSERT(st->response_done, "finishes once the network keeps up");
    TEST_ASSERT(turns > 1, "and it really did take several turns");
    TEST_ASSERT(!h3conn_has_pending(f.c, f.qc), "nothing pending afterwards");
    TEST_ASSERT(qs->send.fin, "stream closed");

    fixture_free(&f);
}

TEST(test_h3dispatch_refused) {
    TEST_SUITE("h3dispatch");

    TEST_CASE("an oversized field section is answered on the stream, not reset");
    h3fixture_t f;
    fixture_init(&f);
    /* A field-section budget nothing fits in, so the read reports REFUSED. */
    h3conn_free(f.c);
    f.c = h3conn_create(NULL, 32, 0);
    f.ctx.parser = f.c;

    quicstream_t* qs = quicstream_create(0, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
    f.qc->streams = qs;
    f.qc->stream_count = 1;

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

    uint64_t error = 0;
    TEST_ASSERT(h3conn_read(f.c, f.qc, &error) == 1, "connection survives");
    TEST_ASSERT(!qs->send_reset_pending, "stream not reset");

    h3stream_t* st = h3conn_request_of(qs);
    TEST_ASSERT(st != NULL && st->response != NULL, "a response was staged");
    TEST_ASSERT(st->response->status_code == 431, "431");
    TEST_ASSERT(atomic_load(&st->response_ready), "and published");

    TEST_ASSERT(h3conn_write(f.c, f.qc) == 1, "write turn ran");
    TEST_ASSERT(queued_frames(qs, H3_FRAME_HEADERS, NULL) == 1, "the 431 went out");
    TEST_ASSERT(qs->send.fin, "and closed the stream");

    fixture_free(&f);

    TEST_CASE("a connection error stops the read and reports its code");
    fixture_init(&f);
    qs = quicstream_create(0, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
    f.qc->streams = qs;
    f.qc->stream_count = 1;

    const uint8_t h2_ping[] = { 0x06, 0x00 };   /* a reserved HTTP/2 codepoint */
    quicstream_on_data(qs, 0, h2_ping, sizeof h2_ping, 0);

    error = 0;
    TEST_ASSERT(h3conn_read(f.c, f.qc, &error) == 0, "connection must close");
    TEST_ASSERT(error == H3_FRAME_UNEXPECTED, "H3_FRAME_UNEXPECTED");

    fixture_free(&f);
}

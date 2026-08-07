#include "framework.h"

#include "h3conn.h"
#include "h3frame.h"
#include "qpack.h"
#include "quicstream.h"

#include <stdlib.h>
#include <string.h>

/* The QUIC-to-HTTP/3 driver (docs/http3/05-http3.md §6.2).
 *
 * Streams are built with quicstream_create and fed with quicstream_on_data,
 * which is the same path a real datagram takes once quicconn has parsed the
 * STREAM frame out of it. That keeps these cases free of a handshake while
 * still exercising the receive buffer, the reordering and the FIN accounting
 * the driver depends on. */

#define STREAM_WINDOW (1024 * 1024)

/* A client-initiated bidirectional stream: id 0, 4, 8, ... */
static quicstream_t* request_stream(uint64_t index) {
    return quicstream_create(index << 2, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
}

/* A client-initiated unidirectional stream: id 2, 6, 10, ... */
static quicstream_t* uni_stream(uint64_t index) {
    return quicstream_create((index << 2) | 0x02, STREAM_WINDOW, STREAM_WINDOW, 0);
}

static void deliver(quicstream_t* qs, uint64_t offset, const uint8_t* data, size_t len, int fin) {
    quicstream_on_data(qs, offset, data, len, fin);
}

static void stream_free(quicstream_t* qs) {
    h3conn_stream_release(qs);
    quicstream_free(qs);
}

/* A complete GET request stream: HEADERS frame, QPACK-encoded. */
static size_t get_request(uint8_t* out, size_t cap) {
    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    const qpack_header_t fields[] = {
        { (char*)":method", 7, (char*)"GET", 3, 0 },
        { (char*)":path", 5, (char*)"/", 1, 0 },
        { (char*)":scheme", 7, (char*)"https", 5, 0 },
        { (char*)":authority", 10, (char*)"example.com", 11, 0 },
    };

    uint8_t block[256];
    const size_t blen = qpack_encode_block(enc, fields, 4, block, sizeof block);
    qpack_encoder_free(enc);

    return h3frame_write(out, cap, H3_FRAME_HEADERS, block, blen);
}

TEST(test_h3conn_request) {
    TEST_SUITE("h3conn");

    TEST_CASE("a request stream is read, built and reported done on FIN");
    h3conn_t* c = h3conn_create(NULL, 65536, 0);
    quicstream_t* qs = request_stream(0);

    uint8_t req[256];
    const size_t n = get_request(req, sizeof req);

    /* Headers first, no FIN: the request is known but not complete. */
    deliver(qs, 0, req, n, 0);
    h3conn_result_t r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_HEADERS, "headers reported");

    h3stream_t* st = h3conn_request_of(qs);
    TEST_ASSERT(st != NULL, "request state attached");
    TEST_ASSERT(st->request->method == ROUTE_GET, "GET");
    TEST_ASSERT(st->request->path_length == 1 && st->request->path[0] == '/', "path /");

    /* Then the FIN, with no bytes -- the shape a bodyless request really takes. */
    deliver(qs, n, NULL, 0, 1);
    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_DONE, "done on FIN");

    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("headers and FIN in one delivery report done, not headers");
    c = h3conn_create(NULL, 65536, 0);
    qs = request_stream(0);
    deliver(qs, 0, req, n, 1);
    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_DONE, "done wins");
    TEST_ASSERT(h3conn_request_of(qs)->headers_done, "headers were built");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("a body spools through and the request completes");
    c = h3conn_create(NULL, 65536, 0);
    qs = request_stream(0);

    uint8_t body[64];
    const size_t blen = h3frame_write(body, sizeof body, H3_FRAME_DATA,
                                      (const uint8_t*)"hello", 5);
    deliver(qs, 0, req, n, 0);
    deliver(qs, n, body, blen, 1);

    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_DONE, "done");
    TEST_ASSERT(h3conn_request_of(qs)->req_body_len == 5, "5 bytes spooled");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("a completed request is reported done exactly once");
    /* h3stream_feed answers DONE for every feed after the FIN -- it describes a
     * state, not an event -- so the driver has to be the thing that dispatches
     * once. Without this the same request went out again on every datagram that
     * followed, each dispatch opening its own response and its own file
     * descriptor: a 1 MB file came back as 7 MB. Found end to end, because every
     * module below was behaving correctly on its own. */
    c = h3conn_create(NULL, 65536, 0);
    qs = request_stream(0);
    deliver(qs, 0, req, n, 1);
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_REQUEST_DONE, "done once");
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_OK, "and not again");
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_OK, "however often it is read");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("reading a stream with nothing new is a no-op");
    c = h3conn_create(NULL, 65536, 0);
    qs = request_stream(0);
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_OK, "nothing to do");
    stream_free(qs);
    h3conn_free(c);
}

TEST(test_h3conn_request_errors) {
    TEST_SUITE("h3conn");

    TEST_CASE("a malformed request resets the stream in both directions");
    h3conn_t* c = h3conn_create(NULL, 65536, 0);
    quicstream_t* qs = request_stream(0);

    /* A field section with no :method at all. */
    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    const qpack_header_t bad[] = { { (char*)":path", 5, (char*)"/", 1, 0 } };
    uint8_t block[128];
    const size_t blen = qpack_encode_block(enc, bad, 1, block, sizeof block);
    qpack_encoder_free(enc);

    uint8_t frame[192];
    const size_t flen = h3frame_write(frame, sizeof frame, H3_FRAME_HEADERS, block, blen);
    deliver(qs, 0, frame, flen, 0);

    h3conn_result_t r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_RESET, "reset");
    TEST_ASSERT(r.h3_error == H3_MESSAGE_ERROR, "H3_MESSAGE_ERROR");
    TEST_ASSERT(qs->send_reset_pending, "RESET_STREAM queued");
    TEST_ASSERT(qs->send_stop_sending_pending, "STOP_SENDING queued too");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("an oversized field section is answered, not reset");
    c = h3conn_create(NULL, 32, 0);   /* a budget no real request fits in */
    qs = request_stream(0);
    uint8_t req[256];
    const size_t n = get_request(req, sizeof req);
    deliver(qs, 0, req, n, 0);

    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_REFUSED, "refused");
    TEST_ASSERT(r.http_status == 431, "431");
    TEST_ASSERT(!qs->send_reset_pending, "the stream is still usable");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("an HTTP/2 codepoint on a request stream closes the connection");
    c = h3conn_create(NULL, 65536, 0);
    qs = request_stream(0);
    const uint8_t h2_ping[] = { 0x06, 0x00 };
    deliver(qs, 0, h2_ping, sizeof h2_ping, 0);

    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_CLOSED, "connection error");
    TEST_ASSERT(r.h3_error == H3_FRAME_UNEXPECTED, "H3_FRAME_UNEXPECTED");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("a client RESET_STREAM cancels the request without a reply");
    c = h3conn_create(NULL, 65536, 0);
    qs = request_stream(0);
    deliver(qs, 0, req, n, 0);
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_REQUEST_HEADERS, "headers");

    quicstream_on_reset(qs, H3_REQUEST_CANCELLED, n);
    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_RESET, "cancelled");
    TEST_ASSERT(!qs->send_reset_pending, "nothing owed back -- they asked for it");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("a request arriving after GOAWAY is rejected, not served");
    c = h3conn_create(NULL, 65536, 0);
    uint8_t goaway[32];
    TEST_ASSERT(h3session_goaway_encode(c->session, goaway, sizeof goaway, 0) > 0, "goaway 0");

    qs = request_stream(0);
    deliver(qs, 0, req, n, 0);
    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_REQUEST_RESET, "reset");
    TEST_ASSERT(r.h3_error == H3_REQUEST_REJECTED, "H3_REQUEST_REJECTED -- safe to retry");
    stream_free(qs);
    h3conn_free(c);
}

TEST(test_h3conn_uni_streams) {
    TEST_SUITE("h3conn");

    TEST_CASE("a control stream's SETTINGS reach the session");
    h3conn_t* c = h3conn_create(NULL, 65536, 0);
    quicstream_t* qs = uni_stream(0);

    uint8_t ctrl[32];
    ctrl[0] = 0x00;   /* control stream type */
    const size_t n = 1 + h3frame_write(ctrl + 1, sizeof ctrl - 1, H3_FRAME_SETTINGS, NULL, 0);
    deliver(qs, 0, ctrl, n, 0);

    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_OK, "accepted");
    TEST_ASSERT(c->session->peer_settings_seen, "settings recorded");
    TEST_ASSERT(c->session->ctrl_recv_id == qs->id, "stream id recorded");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("an unknown stream type gets STOP_SENDING and is then ignored");
    c = h3conn_create(NULL, 65536, 0);
    qs = uni_stream(0);
    const uint8_t unknown[] = { 0x09, 0xde, 0xad };
    deliver(qs, 0, unknown, sizeof unknown, 0);

    h3conn_result_t r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_OK, "not fatal");
    TEST_ASSERT(qs->send_stop_sending_pending, "STOP_SENDING queued");
    TEST_ASSERT(qs->send_stop_sending_code == H3_STREAM_CREATION_ERROR, "the h3 code");
    TEST_ASSERT(!qs->send_reset_pending, "nothing to reset -- it is their stream");

    /* Later bytes are drained without being looked at. */
    const uint8_t more[] = { 0xff, 0xff };
    deliver(qs, sizeof unknown, more, sizeof more, 1);
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_OK, "drained");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("closing the control stream ends the connection");
    c = h3conn_create(NULL, 65536, 0);
    qs = uni_stream(0);
    deliver(qs, 0, ctrl, n, 1);

    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_CLOSED, "fatal");
    TEST_ASSERT(r.h3_error == H3_CLOSED_CRITICAL_STREAM, "H3_CLOSED_CRITICAL_STREAM");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("resetting the control stream is equally fatal");
    c = h3conn_create(NULL, 65536, 0);
    qs = uni_stream(0);
    deliver(qs, 0, ctrl, n, 0);
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_OK, "opened");

    quicstream_on_reset(qs, 0, n);
    r = h3conn_stream_read(c, qs);
    TEST_ASSERT(r.status == H3CONN_CLOSED, "fatal");
    TEST_ASSERT(r.h3_error == H3_CLOSED_CRITICAL_STREAM, "same code as a clean close");
    stream_free(qs);
    h3conn_free(c);

    TEST_CASE("a second control stream is a stream-creation error");
    c = h3conn_create(NULL, 65536, 0);
    quicstream_t* a = uni_stream(0);
    quicstream_t* b = uni_stream(1);
    deliver(a, 0, ctrl, n, 0);
    deliver(b, 0, ctrl, n, 0);

    TEST_ASSERT(h3conn_stream_read(c, a).status == H3CONN_OK, "first");
    r = h3conn_stream_read(c, b);
    TEST_ASSERT(r.status == H3CONN_CLOSED, "second is fatal");
    TEST_ASSERT(r.h3_error == H3_STREAM_CREATION_ERROR, "H3_STREAM_CREATION_ERROR");
    stream_free(a);
    stream_free(b);
    h3conn_free(c);

    TEST_CASE("a stream type split across two deliveries still resolves");
    c = h3conn_create(NULL, 65536, 0);
    qs = uni_stream(0);
    const uint8_t half1[] = { 0x40 };   /* two-byte varint for 0x21 (grease) */
    const uint8_t half2[] = { 0x21 };
    deliver(qs, 0, half1, 1, 0);
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_OK, "half");
    deliver(qs, 1, half2, 1, 0);
    TEST_ASSERT(h3conn_stream_read(c, qs).status == H3CONN_OK, "resolved");
    TEST_ASSERT(!qs->send_stop_sending_pending, "grease is ignored, not refused");
    stream_free(qs);
    h3conn_free(c);
}

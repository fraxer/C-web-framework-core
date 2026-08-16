#include "framework.h"

#include "h3conn.h"
#include "h3frame.h"
#include "h3session.h"
#include "qpack.h"
#include "quicstream.h"
#include "varint.h"

#include <stdlib.h>
#include <string.h>

/* Abuse budgets (docs/http3/07-integration.md §4).
 *
 * Leaky buckets in milli-tokens, the shape docs/http2/08 phase A settled on.
 * What is checked here is the thing that actually matters about a budget: that
 * it runs out, that running out is a connection error and not a silent stall,
 * and that ordinary traffic never reaches it.
 *
 * The default burst is 200, so every case below either stays well under it or
 * goes well past it -- nothing here depends on the exact figure. */

#define STREAM_WINDOW (1024 * 1024)

static quicstream_t* request_stream(uint64_t index) {
    return quicstream_create(index << 2, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
}

/* A control stream that has already sent its SETTINGS. */
static h3uni_recv_t* control_open(h3session_t* s) {
    h3uni_recv_t* uni = h3uni_recv_create(2);

    uint8_t buf[32];
    buf[0] = 0x00;
    const size_t n = 1 + h3frame_write(buf + 1, sizeof buf - 1, H3_FRAME_SETTINGS, NULL, 0);
    h3session_uni_feed(s, uni, buf, n, 0);

    return uni;
}

TEST(test_h3budget_ctrl) {
    TEST_SUITE("h3budget");

    TEST_CASE("a flood of MAX_PUSH_ID frames runs the control budget out");
    /* Every one is legal, costs the peer two bytes, and changes nothing: the
     * limit only ever repeats. Exactly the shape the bucket exists for. */
    h3session_t* s = h3session_create(65536, 0);
    h3uni_recv_t* uni = control_open(s);

    uint8_t id[8];
    const size_t idn = varint_write(id, sizeof id, 1);
    uint8_t frame[32];
    const size_t n = h3frame_write(frame, sizeof frame, H3_FRAME_MAX_PUSH_ID, id, idn);

    int closed_at = 0;
    uint64_t error = 0;
    for (int i = 1; i <= 5000 && closed_at == 0; i++) {
        const h3session_verdict_t v = h3session_uni_feed(s, uni, frame, n, 0);
        if (v.action == H3SESSION_CONN_ERROR) { closed_at = i; error = v.error; }
    }

    TEST_ASSERT(closed_at > 0, "the budget runs out");
    TEST_ASSERT(error == H3_EXCESSIVE_LOAD, "H3_EXCESSIVE_LOAD");
    TEST_ASSERT(closed_at > 100, "but not before a burst a real client might send");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("a handful of control frames costs nothing");
    s = h3session_create(65536, 0);
    uni = control_open(s);
    for (int i = 0; i < 20; i++)
        TEST_ASSERT(h3session_uni_feed(s, uni, frame, n, 0).action == H3SESSION_OK,
                    "accepted");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("unknown unidirectional streams are charged too");
    /* Each costs a STOP_SENDING frame and a stream slot, and a peer may open
     * them as fast as its stream limit allows. */
    s = h3session_create(65536, 0);

    int stopped = 0, fatal = 0;
    for (int i = 0; i < 5000 && !fatal; i++) {
        h3uni_recv_t* u = h3uni_recv_create((uint64_t)i);
        const uint8_t unknown[] = { 0x09 };
        const h3session_verdict_t v = h3session_uni_feed(s, u, unknown, 1, 0);

        if (v.action == H3SESSION_STOP_SENDING) stopped++;
        if (v.action == H3SESSION_CONN_ERROR) { fatal = 1; error = v.error; }

        h3uni_recv_free(u);
    }

    TEST_ASSERT(stopped > 0, "the first ones are refused politely");
    TEST_ASSERT(fatal, "the flood is not");
    TEST_ASSERT(error == H3_EXCESSIVE_LOAD, "H3_EXCESSIVE_LOAD");
    h3session_free(s);
}

TEST(test_h3budget_abort) {
    TEST_SUITE("h3budget");

    TEST_CASE("cancelling unanswered requests runs the abort budget out");
    /* Rapid Reset: open a stream, let the server decode and dispatch it, reset
     * it before it can answer, repeat. QUIC makes this cheaper than HTTP/2 did
     * -- no handshake stands between one stream and the next. */
    h3conn_t* c = h3conn_create(NULL, 65536, 0);

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

    int closed_at = 0;
    uint64_t error = 0;
    for (int i = 1; i <= 5000 && closed_at == 0; i++) {
        quicstream_t* qs = request_stream((uint64_t)i);
        quicstream_on_data(qs, 0, req, rlen, 0);
        h3conn_stream_read(c, NULL, qs);

        quicstream_on_reset(qs, H3_REQUEST_CANCELLED, rlen);
        const h3conn_result_t r = h3conn_stream_read(c, NULL, qs);

        if (r.status == H3CONN_CLOSED) { closed_at = i; error = r.h3_error; }

        h3conn_stream_release(qs);
        quicstream_free(qs);
    }

    TEST_ASSERT(closed_at > 0, "the budget runs out");
    TEST_ASSERT(error == H3_EXCESSIVE_LOAD, "H3_EXCESSIVE_LOAD");
    TEST_ASSERT(closed_at > 100, "but not before an honest burst");
    h3conn_free(c);

    TEST_CASE("a few cancellations cost nothing");
    /* Clients abandon requests all the time -- a navigation away, an aborted
     * fetch. Charging that at a rate an honest client can reach would make the
     * budget worse than useless. */
    c = h3conn_create(NULL, 65536, 0);
    for (int i = 1; i <= 20; i++) {
        quicstream_t* qs = request_stream((uint64_t)i);
        quicstream_on_data(qs, 0, req, rlen, 0);
        h3conn_stream_read(c, NULL, qs);

        quicstream_on_reset(qs, H3_REQUEST_CANCELLED, rlen);
        const h3conn_result_t r = h3conn_stream_read(c, NULL, qs);
        TEST_ASSERT(r.status == H3CONN_REQUEST_RESET, "cancelled, connection intact");

        h3conn_stream_release(qs);
        quicstream_free(qs);
    }
    h3conn_free(c);
}

/* One PRIORITY_UPDATE naming `stream_id`, ready for the control stream. */
static size_t priority_frame(uint8_t* out, size_t cap, uint64_t stream_id) {
    uint8_t payload[32];
    size_t n = varint_write(payload, sizeof payload, stream_id);
    memcpy(payload + n, "u=3", 3);
    n += 3;

    return h3frame_write(out, cap, H3_FRAME_PRIORITY_UPDATE_REQUEST, payload, n);
}

TEST(test_h3budget_priority) {
    TEST_SUITE("h3budget");

    /* PRIORITY_UPDATE used to be charged to the control budget, and that made
     * the limit fire on ordinary browsing: Chrome sends two frames per request,
     * so 100 frames/s capped a connection at ~50 requests/s and closed it with
     * H3_EXCESSIVE_LOAD on anything faster -- a page held on reload. The credit
     * that replaced it comes from requests, so these two cases are the whole
     * claim: requests pay for their own frames, and frames without requests
     * still run out. */

    TEST_CASE("a browser's rate -- two frames per request -- is never charged");
    h3conn_t* c = h3conn_create(NULL, 65536, 0);

    uint8_t ctrl[32];
    ctrl[0] = 0x00;   /* control stream type */
    size_t cn = 1 + h3frame_write(ctrl + 1, sizeof ctrl - 1, H3_FRAME_SETTINGS, NULL, 0);

    quicstream_t* control = quicstream_create(2, STREAM_WINDOW, STREAM_WINDOW, 0);
    quicstream_on_data(control, 0, ctrl, cn, 0);
    TEST_ASSERT(h3conn_stream_read(c, NULL, control).status == H3CONN_OK, "SETTINGS");

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

    uint64_t offset = cn;
    int broke_at = 0;

    for (uint64_t i = 1; i <= 2000 && broke_at == 0; i++) {
        const uint64_t id = i << 2;

        uint8_t frame[32];
        const size_t fn = priority_frame(frame, sizeof frame, id);

        /* Both frames, as Chrome sends them: one when the request is issued and
         * one when the renderer revises the priority. */
        for (int k = 0; k < 2; k++) {
            quicstream_on_data(control, offset, frame, fn, 0);
            offset += fn;

            if (h3conn_stream_read(c, NULL, control).status != H3CONN_OK)
                broke_at = (int)i;
        }

        quicstream_t* qs = request_stream(i);
        quicstream_on_data(qs, 0, req, rlen, 1);
        h3conn_stream_read(c, NULL, qs);
        h3conn_stream_release(qs);
        quicstream_free(qs);
    }

    TEST_ASSERT(broke_at == 0, "2000 requests with their priorities, connection intact");

    h3conn_stream_release(control);
    quicstream_free(control);
    h3conn_free(c);

    TEST_CASE("PRIORITY_UPDATE without any request runs the credit out");
    /* The credit is not refilled by time, so this ends however slowly it is
     * sent -- which is the point: a peer that never opens a stream has no way
     * to earn more. */
    h3session_t* s = h3session_create(65536, 0);
    h3uni_recv_t* uni = control_open(s);

    uint8_t frame[32];
    const size_t fn = priority_frame(frame, sizeof frame, 0);

    int closed_at = 0;
    uint64_t error = 0;
    for (int i = 1; i <= 5000 && closed_at == 0; i++) {
        const h3session_verdict_t v = h3session_uni_feed(s, uni, frame, fn, 0);
        if (v.action == H3SESSION_CONN_ERROR) { closed_at = i; error = v.error; }
    }

    TEST_ASSERT(closed_at > 0, "the credit runs out");
    TEST_ASSERT(error == H3_EXCESSIVE_LOAD, "H3_EXCESSIVE_LOAD");
    TEST_ASSERT(closed_at > 200, "but not before a burst a real client might send");

    h3uni_recv_free(uni);
    h3session_free(s);
}

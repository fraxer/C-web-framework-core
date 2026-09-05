#include "framework.h"

#include "h3frame.h"
#include "h3stream.h"
#include "httpcommon.h"
#include "httprequest.h"
#include "qpack.h"
#include "quicmemory.h"

#include <string.h>

/* The per-stream receive state machine (docs/http3/05-http3.md §6.2). Frames are
 * built here with the codec's own encoder so the bytes are known-good; feeding
 * them drives HEADERS → qpack → httpfields, DATA → body, and the frame-order and
 * frame-type rules, exactly as a real request stream would. */

#define QF(n, v) ((qpack_header_t){(char*)(n), strlen(n), (char*)(v), strlen(v), 0})

TEST(test_h3stream_qpack_deferred_lifecycle) {
    TEST_SUITE("h3stream qpack blocked");

    const size_t before = quicmemory_current();
    h3stream_t* st = h3stream_create(NULL, 0);
    static const uint8_t a[] = { 1, 2, 3 };
    static const uint8_t b[] = { 4, 5 };

    TEST_CASE("tails from several QUIC reads are retained with FIN");
    TEST_ASSERT(h3stream_qpack_defer(st, a, sizeof a, 0), "first tail");
    TEST_ASSERT(h3stream_qpack_defer(st, b, sizeof b, 1), "second tail");
    TEST_ASSERT(st->qpack_deferred_len == 5 && st->qpack_deferred_fin,
                "length and FIN retained");
    TEST_ASSERT(memcmp(st->qpack_deferred, "\1\2\3\4\5", 5) == 0,
                "original byte order retained");
    TEST_ASSERT(quicmemory_current() > before, "capacity charged globally");

    TEST_CASE("clear returns the complete reservation");
    h3stream_qpack_deferred_clear(st);
    TEST_ASSERT(st->qpack_deferred == NULL && st->qpack_deferred_len == 0,
                "state cleared");
    TEST_ASSERT(quicmemory_current() == before, "memory returned");

    TEST_CASE("stream destruction also releases an outstanding tail");
    TEST_ASSERT(h3stream_qpack_defer(st, a, sizeof a, 1), "tail reserved again");
    h3stream_free(st);
    TEST_ASSERT(quicmemory_current() == before, "destructor returned memory");

    TEST_CASE("a blocked stream resumes only at its Required Insert Count");
    st = h3stream_create(NULL, 0);
    TEST_ASSERT(h3stream_qpack_block(st, 7, a, sizeof a, 1), "blocked once");
    TEST_ASSERT(!h3stream_qpack_block(st, 8, b, sizeof b, 0),
                "second registration cannot double-count the stream");
    TEST_ASSERT(!h3stream_qpack_can_resume(st, 6), "insert six is too early");
    TEST_ASSERT(h3stream_qpack_can_resume(st, 7), "exact threshold resumes");
    h3stream_qpack_unblock(st);
    TEST_ASSERT(!st->qpack_blocked && st->qpack_required_insert_count == 0,
                "blocked state cleared");
    TEST_ASSERT(quicmemory_current() == before, "unblock returned deferred memory");
    h3stream_free(st);
}

TEST(test_h3stream_qpack_blocked_event) {
    TEST_SUITE("h3stream qpack blocked");
    h3stream_t* st = h3stream_create(NULL, 0);
    qpack_decoder_t* d = qpack_decoder_create(128, 4);
    /* HEADERS carrying RIC=1 in modulo form, followed by bytes already removed
     * from QUIC receive buffering. */
    static const uint8_t bytes[] = { H3_FRAME_HEADERS, 0x02, 0x02, 0x00, 0xaa, 0xbb };
    const uint8_t* p = bytes;
    TEST_ASSERT(h3stream_feed(st, d, &p, bytes + sizeof bytes, 1)
                    == H3STREAM_QPACK_BLOCKED, "non-fatal blocked event");
    TEST_ASSERT(st->qpack_blocked && st->qpack_required_insert_count == 1,
                "threshold stored");
    TEST_ASSERT(st->qpack_deferred_len == 2 && st->qpack_deferred_fin,
                "tail and FIN retained");
    TEST_ASSERT(p == bytes + sizeof bytes, "owned tail replaces caller bytes");
    h3stream_free(st);
    qpack_decoder_free(d);

    TEST_CASE("reads that land while the section is still blocked are kept, in order");
    /* h3conn reads a QUIC stream into a stack buffer before feeding it, so
     * returning from here without consuming `pp` does not leave the bytes
     * anywhere -- it drops them. That truncated the body by one read per
     * datagram, and when the read carrying FIN was the one dropped the request
     * was never dispatched at all and the stream hung to the idle timeout. */
    st = h3stream_create(NULL, 0);
    d = qpack_decoder_create(128, 4);
    static const uint8_t head[] = { H3_FRAME_HEADERS, 0x02, 0x02, 0x00, 0xaa };
    p = head;
    TEST_ASSERT(h3stream_feed(st, d, &p, head + sizeof head, 0)
                    == H3STREAM_QPACK_BLOCKED, "blocked on the first read");
    TEST_ASSERT(st->qpack_deferred_len == 1, "with the tail of that read");

    static const uint8_t more[] = { 0xbb, 0xcc, 0xdd };
    p = more;
    TEST_ASSERT(h3stream_feed(st, d, &p, more + sizeof more, 1)
                    == H3STREAM_QPACK_BLOCKED, "still blocked on the second");
    TEST_ASSERT(p == more + sizeof more, "and the read is taken, not dropped");
    TEST_ASSERT(st->qpack_deferred_len == 4, "queued behind the first tail");
    TEST_ASSERT(memcmp(st->qpack_deferred, "\xaa\xbb\xcc\xdd", 4) == 0, "in arrival order");
    TEST_ASSERT(st->qpack_deferred_fin, "and the FIN came with them");
    h3stream_free(st);
    qpack_decoder_free(d);

    TEST_CASE("deferred DATA and FIN replay through the normal frame parser");
    st = h3stream_create(NULL, 0);
    d = qpack_decoder_create(128, 4);
    st->headers_done = 1;
    st->stage = H3STREAM_BODY;
    st->content_length = 2;
    static const uint8_t body[] = { H3_FRAME_DATA, 0x02, 'x', 'y' };
    TEST_ASSERT(h3stream_qpack_defer(st, body, sizeof body, 1), "body retained");
    p = NULL;
    TEST_ASSERT(h3stream_feed(st, d, &p, NULL, 0) == H3STREAM_DONE,
                "replay reaches DATA and FIN");
    TEST_ASSERT(st->req_body_len == 2, "body accounted once");
    TEST_ASSERT(st->qpack_deferred == NULL && st->qpack_deferred_len == 0,
                "owned replay storage released");
    h3stream_free(st);
    qpack_decoder_free(d);
}

static size_t headers_frame(qpack_encoder_t* enc, const qpack_header_t* f, size_t n,
                            uint8_t* out, size_t cap) {
    /* Big enough for the oversized sections the field-limit cases build: a
     * block that does not fit encodes as zero bytes, and the test would then be
     * feeding an empty HEADERS frame while claiming to feed a huge one. */
    uint8_t block[8192];
    const size_t blen = qpack_encode_block(enc, f, n, block, sizeof block);
    return h3frame_write(out, cap, H3_FRAME_HEADERS, block, blen);
}

static size_t data_frame(const uint8_t* payload, size_t plen, uint8_t* out, size_t cap) {
    return h3frame_write(out, cap, H3_FRAME_DATA, payload, plen);
}

static h3stream_status_e feed(h3stream_t* st, qpack_decoder_t* qdec,
                              const uint8_t* data, size_t len, int fin) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    return h3stream_feed(st, qdec, &p, end, fin);
}

static int host_is(const httprequest_t* r, const char* want) {
    const http_header_t* h = r->get_headern((httprequest_t*)r, "Host", 4);
    return h != NULL && h->value_length == strlen(want) && memcmp(h->value, want, h->value_length) == 0;
}

TEST(test_h3stream_request) {
    TEST_SUITE("h3stream");

    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    qpack_decoder_t* qdec = qpack_decoder_create(0, 0);

    TEST_CASE("a GET request builds and is announced ready");
    const qpack_header_t get[] = {
        QF(":method", "GET"), QF(":path", "/"), QF(":scheme", "https"),
        QF(":authority", "example.com"), QF("accept", "*/*"),
    };
    uint8_t buf[512];
    const size_t n = headers_frame(enc, get, sizeof get / sizeof get[0], buf, sizeof buf);

    h3stream_t* st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, buf, n, 0) == H3STREAM_REQUEST_READY, "ready");
    TEST_ASSERT(st->headers_done, "headers_done");
    TEST_ASSERT(st->request->method == ROUTE_GET, "GET");
    TEST_ASSERT(st->request->path_length == 1 && memcmp(st->request->path, "/", 1) == 0, "path /");
    TEST_ASSERT(host_is(st->request, "example.com"), "Host");
    h3stream_free(st);

    TEST_CASE("HEADERS then FIN completes the request");
    st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, buf, n, 0) == H3STREAM_REQUEST_READY, "ready");
    TEST_ASSERT(feed(st, qdec, NULL, 0, 1) == H3STREAM_DONE, "done on FIN");
    h3stream_free(st);

    qpack_encoder_free(enc);
    qpack_decoder_free(qdec);
}

TEST(test_h3stream_body) {
    TEST_SUITE("h3stream");

    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    qpack_decoder_t* qdec = qpack_decoder_create(0, 0);

    TEST_CASE("HEADERS → body chunks spool → FIN");
    const qpack_header_t post[] = {
        QF(":method", "POST"), QF(":path", "/upload"), QF(":scheme", "https"),
        QF(":authority", "example.com"),
    };
    uint8_t hdr[256];
    const size_t hlen = headers_frame(enc, post, sizeof post / sizeof post[0], hdr, sizeof hdr);

    h3stream_t* st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, hdr, hlen, 0) == H3STREAM_REQUEST_READY, "ready");

    uint8_t data[128];
    const size_t dlen = data_frame((const uint8_t*)"hello body", 10, data, sizeof data);
    TEST_ASSERT(feed(st, qdec, data, dlen, 0) == H3STREAM_BODY_CHUNK, "body chunk");
    TEST_ASSERT(st->req_body_len == 10, "10 bytes spooled");

    TEST_ASSERT(feed(st, qdec, NULL, 0, 1) == H3STREAM_DONE, "done on FIN");
    h3stream_free(st);

    qpack_encoder_free(enc);
    qpack_decoder_free(qdec);
}

TEST(test_h3stream_trailers) {
    TEST_SUITE("h3stream");

    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    qpack_decoder_t* qdec = qpack_decoder_create(0, 0);

    TEST_CASE("a HEADERS frame after DATA is consumed as trailers");
    const qpack_header_t post[] = {
        QF(":method", "POST"), QF(":path", "/"), QF(":scheme", "https"),
        QF(":authority", "example.com"),
    };
    uint8_t hdr[256];
    size_t n = headers_frame(enc, post, sizeof post / sizeof post[0], hdr, sizeof hdr);
    h3stream_t* st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, hdr, n, 0) == H3STREAM_REQUEST_READY, "ready");

    uint8_t data[128];
    n = data_frame((const uint8_t*)"body", 4, data, sizeof data);
    TEST_ASSERT(feed(st, qdec, data, n, 0) == H3STREAM_BODY_CHUNK, "body");

    const qpack_header_t tr[] = { QF("x-checksum", "abc") };
    uint8_t trf[256];
    n = headers_frame(enc, tr, sizeof tr / sizeof tr[0], trf, sizeof trf);
    TEST_ASSERT(feed(st, qdec, trf, n, 0) == H3STREAM_NEED_MORE, "trailers consumed");
    TEST_ASSERT(st->stage == H3STREAM_TRAILERS, "trailers stage");

    const http_header_t* t = st->request->get_trailern(st->request, "x-checksum", 10);
    TEST_ASSERT(t != NULL && t->value_length == 3 && memcmp(t->value, "abc", 3) == 0,
                "trailer landed");

    TEST_ASSERT(feed(st, qdec, NULL, 0, 1) == H3STREAM_DONE, "done on FIN");
    h3stream_free(st);

    qpack_encoder_free(enc);
    qpack_decoder_free(qdec);
}

TEST(test_h3stream_errors) {
    TEST_SUITE("h3stream");

    qpack_decoder_t* qdec = qpack_decoder_create(0, 0);

    TEST_CASE("DATA before HEADERS is a frame error");
    uint8_t data[64];
    const size_t dlen = data_frame((const uint8_t*)"x", 1, data, sizeof data);
    h3stream_t* st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, data, dlen, 0) == H3STREAM_ERR_FRAME_UNEXPECTED, "DATA first");
    h3stream_free(st);

    TEST_CASE("a control frame on a request stream is a frame error");
    uint8_t settings[16];
    const size_t slen = h3frame_write(settings, sizeof settings, H3_FRAME_SETTINGS, NULL, 0);
    st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, settings, slen, 0) == H3STREAM_ERR_FRAME_UNEXPECTED,
                "SETTINGS on stream");
    h3stream_free(st);

    TEST_CASE("FIN before HEADERS is request-incomplete");
    st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, NULL, 0, 1) == H3STREAM_ERR_REQUEST_INCOMPLETE,
                "FIN before HEADERS");
    h3stream_free(st);

    TEST_CASE("an HTTP/2 codepoint is frame-unexpected, a truncated frame is frame-error");
    /* §11.2.1 and §7.1 name different codes, and the split is only visible if
     * the two are not collapsed into one status. */
    const uint8_t h2_ping[] = { 0x06, 0x00 };   /* type 0x06 = HTTP/2 PING */
    st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, h2_ping, sizeof h2_ping, 0) == H3STREAM_ERR_FRAME_UNEXPECTED,
                "reserved h2 codepoint");
    TEST_ASSERT(h3stream_status_error(H3STREAM_ERR_FRAME_UNEXPECTED) == H3_FRAME_UNEXPECTED,
                "maps to H3_FRAME_UNEXPECTED");
    TEST_ASSERT(h3stream_status_is_connection(H3STREAM_ERR_FRAME_UNEXPECTED),
                "and is fatal to the connection");
    h3stream_free(st);

    qpack_decoder_free(qdec);
}

/* The rules that can only be judged when the stream ends: §7.1 (a frame cut in
 * half by a clean FIN) and §4.1.2 (content-length versus the body delivered). */
TEST(test_h3stream_fin) {
    TEST_SUITE("h3stream");

    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    qpack_decoder_t* qdec = qpack_decoder_create(0, 0);

    const qpack_header_t post[] = {
        QF(":method", "POST"), QF(":path", "/"), QF(":scheme", "https"),
        QF(":authority", "example.com"), QF("content-length", "10"),
    };
    uint8_t hdr[256];
    const size_t hlen = headers_frame(enc, post, sizeof post / sizeof post[0], hdr, sizeof hdr);

    TEST_CASE("a frame truncated by FIN is a connection-level frame error");
    h3stream_t* st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, hdr, hlen, 0) == H3STREAM_REQUEST_READY, "ready");

    uint8_t data[128];
    const size_t dlen = data_frame((const uint8_t*)"0123456789", 10, data, sizeof data);
    /* Everything but the last body byte, then a clean FIN. */
    TEST_ASSERT(feed(st, qdec, data, dlen - 1, 0) == H3STREAM_BODY_CHUNK, "partial body");
    TEST_ASSERT(feed(st, qdec, NULL, 0, 1) == H3STREAM_ERR_FRAME, "truncated frame on FIN");
    TEST_ASSERT(h3stream_status_error(H3STREAM_ERR_FRAME) == H3_FRAME_ERROR, "H3_FRAME_ERROR");
    TEST_ASSERT(h3stream_status_is_connection(H3STREAM_ERR_FRAME), "connection error");
    h3stream_free(st);

    TEST_CASE("content-length that disagrees with the body is a message error");
    st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, hdr, hlen, 0) == H3STREAM_REQUEST_READY, "ready");
    TEST_ASSERT(st->content_length == 10, "content-length recorded");

    uint8_t shortdata[64];
    const size_t sdlen = data_frame((const uint8_t*)"012", 3, shortdata, sizeof shortdata);
    TEST_ASSERT(feed(st, qdec, shortdata, sdlen, 0) == H3STREAM_BODY_CHUNK, "3 bytes");
    TEST_ASSERT(feed(st, qdec, NULL, 0, 1) == H3STREAM_ERR_MESSAGE, "length mismatch");
    TEST_ASSERT(!h3stream_status_is_connection(H3STREAM_ERR_MESSAGE), "stream error only");
    TEST_ASSERT(h3stream_status_error(H3STREAM_ERR_MESSAGE) == H3_MESSAGE_ERROR, "H3_MESSAGE_ERROR");
    h3stream_free(st);

    TEST_CASE("a content-length that matches passes");
    st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, hdr, hlen, 0) == H3STREAM_REQUEST_READY, "ready");
    TEST_ASSERT(feed(st, qdec, data, dlen, 0) == H3STREAM_BODY_CHUNK, "10 bytes");
    TEST_ASSERT(feed(st, qdec, NULL, 0, 1) == H3STREAM_DONE, "done");
    h3stream_free(st);

    qpack_encoder_free(enc);
    qpack_decoder_free(qdec);
}

/* Our own MAX_FIELD_SECTION_SIZE: too large a field section is answered with
 * 431 on a stream that stays usable, never a reset (docs/http2/08 phase A.4). */
TEST(test_h3stream_field_limit) {
    TEST_SUITE("h3stream");

    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    qpack_decoder_t* qdec = qpack_decoder_create(0, 0);

    TEST_CASE("a field section over the limit is 431, not a connection error");
    const qpack_header_t get[] = {
        QF(":method", "GET"), QF(":path", "/"), QF(":scheme", "https"),
        QF(":authority", "example.com"),
    };
    uint8_t buf[512];
    const size_t n = headers_frame(enc, get, sizeof get / sizeof get[0], buf, sizeof buf);

    /* Four fields cost 4*32 plus their bytes, so a 32-byte budget is under it
     * however the fields are encoded. */
    h3stream_t* st = h3stream_create(NULL, 32);
    TEST_ASSERT(feed(st, qdec, buf, n, 0) == H3STREAM_ERR_FIELDS_TOO_LARGE, "over the limit");
    TEST_ASSERT(!h3stream_status_is_connection(H3STREAM_ERR_FIELDS_TOO_LARGE), "stream only");
    TEST_ASSERT(h3stream_status_error(H3STREAM_ERR_FIELDS_TOO_LARGE) == H3_NO_ERROR,
                "answered, not reset");
    h3stream_free(st);

    TEST_CASE("the same section under a generous limit passes");
    st = h3stream_create(NULL, 4096);
    TEST_ASSERT(feed(st, qdec, buf, n, 0) == H3STREAM_REQUEST_READY, "ready");
    h3stream_free(st);

    TEST_CASE("past the hard cap the connection ends instead of being answered");
    /* The point of the second limit: 431 tells a client what was wrong, which
     * is worth doing for a section slightly over the budget and pointless for
     * one that is orders of magnitude over -- there the decode itself is the
     * attack. The boundary is the advertised limit times the factor. */
    char big[2048];
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = '\0';

    const qpack_header_t huge[] = {
        QF(":method", "GET"), QF(":path", "/"), QF(":scheme", "https"),
        QF(":authority", "example.com"), QF("x-pad", big),
    };
    uint8_t hbuf[4096];
    const size_t hn = headers_frame(enc, huge, sizeof huge / sizeof huge[0], hbuf, sizeof hbuf);
    TEST_REQUIRE(hn > 0, "oversized HEADERS frame built");

    st = h3stream_create(NULL, 32);   /* hard cap = 32 * 8 = 256 */
    TEST_ASSERT(feed(st, qdec, hbuf, hn, 0) == H3STREAM_ERR_EXCESSIVE_LOAD, "over the hard cap");
    TEST_ASSERT(h3stream_status_is_connection(H3STREAM_ERR_EXCESSIVE_LOAD), "connection error");
    TEST_ASSERT(h3stream_status_error(H3STREAM_ERR_EXCESSIVE_LOAD) == H3_EXCESSIVE_LOAD,
                "H3_EXCESSIVE_LOAD");
    h3stream_free(st);

    TEST_CASE("between the two limits it is still only a 431");
    /* The same oversized section, with a limit high enough that the hard cap is
     * above it: the whole point is that the band between the two exists. */
    st = h3stream_create(NULL, 2048);   /* section ~2.2 KB, hard cap 16 KB */
    TEST_ASSERT(feed(st, qdec, hbuf, hn, 0) == H3STREAM_ERR_FIELDS_TOO_LARGE, "431, not fatal");
    h3stream_free(st);

    TEST_CASE("no advertised limit means no hard cap either");
    /* 0 is "unlimited", and multiplying it by the factor must not turn it into
     * a cap of zero -- which would reject every field section there is. */
    st = h3stream_create(NULL, 0);
    TEST_ASSERT(feed(st, qdec, hbuf, hn, 0) == H3STREAM_REQUEST_READY, "unlimited stays unlimited");
    h3stream_free(st);

    qpack_encoder_free(enc);
    qpack_decoder_free(qdec);
}

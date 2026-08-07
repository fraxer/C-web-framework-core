#include "framework.h"

#include "h3data.h"
#include "h3frame.h"
#include "h3response.h"
#include "quicconn.h"
#include "quicsendbuf.h"
#include "quicstream.h"
#include "varint.h"

#include <stdlib.h>
#include <string.h>

/* Body framing and the write-ahead budget (docs/http3/05-http3.md §6.3).
 *
 * The connection here is a bare quicconn_t with nothing but its stream list
 * filled in: quicconn_write_room reads only that, and building a real one would
 * mean a handshake for no gain. It is freed with free(), never quicconn_free,
 * which would tear down a TLS context that was never set up. */

#define STREAM_WINDOW (64 * 1024 * 1024)

static quicconn_t* bare_conn(quicstream_t* qs) {
    quicconn_t* qc = calloc(1, sizeof * qc);
    if (qc == NULL) return NULL;

    qc->streams = qs;
    for (const quicstream_t* s = qs; s != NULL; s = s->next) qc->stream_count++;

    return qc;
}

static quicstream_t* response_stream(void) {
    return quicstream_create(0, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
}

/* Pretend the send path packetised everything queued: this is what frees the
 * write-ahead budget in the server. */
static void drain(quicstream_t* qs) {
    const size_t unsent = quicsendbuf_unsent_bytes(&qs->send);
    if (unsent > 0) quicsendbuf_mark_sent(&qs->send, qs->send.sent_off, unsent, 0);
}

/* Walk the queued bytes as DATA frames, returning the number of frames and the
 * total payload. Reads the send buffer directly -- the bytes have not been
 * packetised, which is exactly the state under test. */
static size_t count_frames(const quicstream_t* qs, size_t* payload_total) {
    const uint8_t* p = qs->send.data;
    const size_t len = qs->send.len;
    size_t off = 0, frames = 0, total = 0;

    while (off < len) {
        uint64_t type = 0, plen = 0;
        size_t n = varint_read(p + off, len - off, &type);
        if (n == 0) break;
        off += n;

        n = varint_read(p + off, len - off, &plen);
        if (n == 0) break;
        off += n;

        if (type != H3_FRAME_DATA) break;
        if (off + plen > len) break;

        off += (size_t)plen;
        total += (size_t)plen;
        frames++;
    }

    if (payload_total != NULL) *payload_total = total;

    return frames;
}

static void fill(bufo_t* src, size_t size, char c) {
    bufo_alloc(src, size);
    memset(src->data, c, size);
    bufo_set_size(src, size);
    bufo_reset_pos(src);
}

TEST(test_h3data_framing) {
    TEST_SUITE("h3data");

    TEST_CASE("a small body is one DATA frame and a FIN");
    quicstream_t* qs = response_stream();
    quicconn_t* qc = bare_conn(qs);
    h3_data_writer_t w;
    h3_data_writer_reset(&w);

    bufo_t src;
    bufo_init(&src);
    fill(&src, 5, 'x');

    TEST_ASSERT(h3_data_write(&w, qc, qs, &src, 1, 1) == H3_DATA_DRAINED, "drained");
    TEST_ASSERT(src.pos == 5, "source consumed");

    size_t payload = 0;
    TEST_ASSERT(count_frames(qs, &payload) == 1, "one frame");
    TEST_ASSERT(payload == 5, "five payload bytes");
    TEST_ASSERT(qs->send.fin, "FIN set");
    TEST_ASSERT(w.fin_sent, "and recorded");

    bufo_clear(&src);
    quicstream_free(qs);
    free(qc);

    TEST_CASE("a body over the chunk size is cut into chunks");
    qs = response_stream();
    qc = bare_conn(qs);
    h3_data_writer_reset(&w);
    bufo_init(&src);
    fill(&src, H3_DATA_CHUNK_MAX * 2 + 100, 'y');

    /* Draining between passes keeps the budget out of this case: what is being
     * measured here is the chunking, not the back pressure. */
    h3_data_status_e st;
    size_t passes = 0;
    do {
        st = h3_data_write(&w, qc, qs, &src, 1, 1);
        if (st == H3_DATA_BLOCKED) drain(qs);
        passes++;
    } while (st == H3_DATA_BLOCKED && passes < 100);

    TEST_ASSERT(st == H3_DATA_DRAINED, "drained eventually");
    TEST_ASSERT(src.pos == src.size, "source consumed");

    bufo_clear(&src);
    quicstream_free(qs);
    free(qc);

    TEST_CASE("no FIN while trailers are still owed");
    qs = response_stream();
    qc = bare_conn(qs);
    h3_data_writer_reset(&w);
    bufo_init(&src);
    fill(&src, 10, 'z');

    TEST_ASSERT(h3_data_write(&w, qc, qs, &src, 1, 0) == H3_DATA_DRAINED, "drained");
    TEST_ASSERT(!qs->send.fin, "stream stays open for the trailing HEADERS");
    TEST_ASSERT(!w.fin_sent, "not recorded either");

    bufo_clear(&src);
    quicstream_free(qs);
    free(qc);

    TEST_CASE("an empty source with is_last still closes the stream");
    qs = response_stream();
    qc = bare_conn(qs);
    h3_data_writer_reset(&w);
    bufo_init(&src);

    TEST_ASSERT(h3_data_write(&w, qc, qs, &src, 1, 1) == H3_DATA_DRAINED, "drained");
    TEST_ASSERT(count_frames(qs, NULL) == 0, "no empty DATA frame");
    TEST_ASSERT(qs->send.fin, "FIN alone");

    bufo_clear(&src);
    quicstream_free(qs);
    free(qc);
}

TEST(test_h3data_write_ahead) {
    TEST_SUITE("h3data");

    TEST_CASE("a body past the write-ahead budget blocks instead of buffering it");
    quicstream_t* qs = response_stream();
    quicconn_t* qc = bare_conn(qs);
    h3_data_writer_t w;
    h3_data_writer_reset(&w);

    bufo_t src;
    bufo_init(&src);
    /* Four times the budget: no single pass can take it. */
    const size_t total = QUICCONN_WRITE_AHEAD_MAX * 4;
    fill(&src, total, 'b');

    TEST_ASSERT(h3_data_write(&w, qc, qs, &src, 1, 1) == H3_DATA_BLOCKED, "blocked");
    TEST_ASSERT(src.pos > 0, "some of it went");
    TEST_ASSERT(src.pos < total, "but not all");
    TEST_ASSERT(!qs->send.fin, "and the stream is not finished");

    /* The bound that matters: held bytes never approach the body's size. One
     * chunk of overshoot is allowed by design -- frames are not cut to fit the
     * threshold exactly. */
    TEST_ASSERT(quicconn_unsent_bytes(qc) <= QUICCONN_WRITE_AHEAD_MAX + H3_DATA_CHUNK_MAX,
                "held bytes stay inside the budget");

    TEST_CASE("draining the send path resumes it");
    size_t passes = 0;
    h3_data_status_e st = H3_DATA_BLOCKED;
    while (st == H3_DATA_BLOCKED && passes < 1000) {
        drain(qs);
        st = h3_data_write(&w, qc, qs, &src, 1, 1);
        passes++;
    }

    TEST_ASSERT(st == H3_DATA_DRAINED, "finishes once the network keeps up");
    TEST_ASSERT(src.pos == total, "whole body sent");
    TEST_ASSERT(qs->send.fin, "FIN at the end");
    TEST_ASSERT(passes > 1, "and it really did take several passes");

    bufo_clear(&src);
    quicstream_free(qs);
    free(qc);

    TEST_CASE("the budget counts the whole connection, not one stream");
    /* Two streams sharing one connection: filling the first leaves nothing for
     * the second. Per stream the bound would have to be multiplied by the
     * stream limit to bound anything at all. */
    quicstream_t* a = quicstream_create(0, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
    quicstream_t* b = quicstream_create(4, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
    a->next = b;
    qc = bare_conn(a);

    bufo_t sa, sb;
    bufo_init(&sa);
    bufo_init(&sb);
    fill(&sa, QUICCONN_WRITE_AHEAD_MAX * 2, 'a');
    fill(&sb, 1024, 'b');

    h3_data_writer_t wa, wb;
    h3_data_writer_reset(&wa);
    h3_data_writer_reset(&wb);

    TEST_ASSERT(h3_data_write(&wa, qc, a, &sa, 1, 1) == H3_DATA_BLOCKED, "first fills it");
    TEST_ASSERT(h3_data_write(&wb, qc, b, &sb, 1, 1) == H3_DATA_BLOCKED,
                "second sees no room");
    TEST_ASSERT(sb.pos == 0, "and wrote nothing");

    drain(a);
    TEST_ASSERT(h3_data_write(&wb, qc, b, &sb, 1, 1) == H3_DATA_DRAINED,
                "room freed on one stream serves the other");
    TEST_ASSERT(sb.pos == 1024, "second stream went out");

    bufo_clear(&sa);
    bufo_clear(&sb);
    quicstream_free(a);
    quicstream_free(b);
    free(qc);
}

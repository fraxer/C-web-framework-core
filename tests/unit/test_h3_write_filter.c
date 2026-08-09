#include "framework.h"

#include "h3_write_filter.h"
#include "h3conn.h"
#include "h3frame.h"
#include "http_filter.h"
#include "httpresponse.h"
#include "qpack.h"
#include "quicstream.h"
#include "varint.h"

#include <stdlib.h>
#include <string.h>

/* The terminal stage of the h3 chain (docs/http3/05-http3.md §6.3).
 *
 * Only the parts that need no live connection are exercised here: the chain is
 * assembled, and the response-to-stream lookup the stage depends on is checked
 * against a hand-built stream list. Driving handler_header itself needs a
 * connection_t whose ctx holds an h3conn_t, which arrives with the dispatch
 * wiring; what is verified now is that nothing in the lookup can silently
 * return the wrong stream. */

TEST(test_h3_write_filter_chain) {
    TEST_SUITE("h3_write_filter");

    TEST_CASE("the h3 chain is the h2 chain with a different terminal stage");
    http_filter_t* chain = filters_create_h3();
    TEST_ASSERT(chain != NULL, "chain created");

    size_t stages = 0;
    for (const http_filter_t* f = chain; f != NULL; f = f->next) stages++;
    /* not_modified -> range -> data -> gzip -> write. No chunked stage: the
     * body is framed by the protocol, so transfer-encoding has no place. */
    TEST_ASSERT(stages == 5, "five stages");

    const http_filter_t* last = chain;
    while (last->next != NULL) last = last->next;
    TEST_ASSERT(last->handler_header != NULL && last->handler_body != NULL,
                "the terminal stage handles both halves");

    filters_free(chain);

    TEST_CASE("a response created for h3 gets that chain");
    httpresponse_t* r = httpresponse_create_h3(NULL);
    TEST_ASSERT(r != NULL, "response created");
    TEST_ASSERT(r->filter != NULL && r->cur_filter == r->filter, "chain attached");

    size_t n = 0;
    for (const http_filter_t* f = r->filter; f != NULL; f = f->next) n++;
    TEST_ASSERT(n == 5, "same five stages");
    httpresponse_free(r);
}

TEST(test_h3_write_filter_lookup) {
    TEST_SUITE("h3_write_filter");

    TEST_CASE("a response is matched to the stream that carries it");
    /* A bare connection: quicconn_write_room and the lookup read only the
     * stream list. Freed with free(), never quicconn_free. */
    quicconn_t* qc = calloc(1, sizeof * qc);
    TEST_ASSERT(qc != NULL, "connection allocated");
    if (qc == NULL) return;

    quicstream_t* a = quicstream_create(0, 65536, 65536, 65536);
    quicstream_t* b = quicstream_create(4, 65536, 65536, 65536);
    a->next = b;
    qc->streams = a;
    qc->stream_count = 2;

    h3conn_t* c = h3conn_create(NULL, 65536, 0);

    /* Two request streams, each with its own response. */
    uint8_t req[256];
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
    const size_t rlen = h3frame_write(req, sizeof req, H3_FRAME_HEADERS, block, blen);

    quicstream_on_data(a, 0, req, rlen, 0);
    quicstream_on_data(b, 0, req, rlen, 0);
    TEST_ASSERT(h3conn_stream_read(c, NULL, a).status == H3CONN_REQUEST_HEADERS, "stream a");
    TEST_ASSERT(h3conn_stream_read(c, NULL, b).status == H3CONN_REQUEST_HEADERS, "stream b");

    httpresponse_t* ra = httpresponse_create_h3(NULL);
    httpresponse_t* rb = httpresponse_create_h3(NULL);
    h3conn_request_of(a)->response = ra;
    h3conn_request_of(b)->response = rb;

    TEST_ASSERT(h3conn_stream_by_response(qc, ra) == a, "ra -> a");
    TEST_ASSERT(h3conn_stream_by_response(qc, rb) == b, "rb -> b");

    TEST_CASE("a response no stream owns matches nothing");
    httpresponse_t* orphan = httpresponse_create_h3(NULL);
    TEST_ASSERT(h3conn_stream_by_response(qc, orphan) == NULL, "no match");
    TEST_ASSERT(h3conn_stream_by_response(qc, NULL) == NULL, "and NULL is not a wildcard");

    /* ra and rb belong to their streams now (h3stream_t::response), so releasing
     * the streams frees them; only the orphan is ours to free. */
    httpresponse_free(orphan);
    h3conn_stream_release(a);
    h3conn_stream_release(b);
    quicstream_free(a);
    quicstream_free(b);
    h3conn_free(c);
    free(qc);
}

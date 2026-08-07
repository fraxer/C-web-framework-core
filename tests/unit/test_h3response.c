#include "framework.h"

#include "h3frame.h"
#include "h3response.h"
#include "httpresponse.h"
#include "qpack.h"
#include "varint.h"

#include <stdlib.h>
#include <string.h>

/* The response encoder (docs/http3/05-http3.md §6.3). Every case encodes and
 * then decodes with the QPACK decoder, because the only claim worth making
 * about an encoder is that a decoder reads back what was meant. */

/* Unwrap a HEADERS frame and decode its field section. */
static qpack_header_t* decode(const uint8_t* frame, size_t len, size_t* count) {
    uint64_t type = 0, plen = 0;
    size_t off = varint_read(frame, len, &type);
    off += varint_read(frame + off, len - off, &plen);

    if (type != H3_FRAME_HEADERS) return NULL;
    if (off + plen != len) return NULL;

    qpack_decoder_t* d = qpack_decoder_create(0, 0);
    qpack_header_t* out = NULL;
    const qpack_status_e st = qpack_decode_block(d, frame + off, (size_t)plen, 0, &out, count);
    qpack_decoder_free(d);

    return st == QPACK_OK ? out : NULL;
}

static const qpack_header_t* find(const qpack_header_t* h, size_t n, const char* name) {
    if (h == NULL) return NULL;

    const size_t len = strlen(name);
    for (size_t i = 0; i < n; i++)
        if (h[i].name_len == len && memcmp(h[i].name, name, len) == 0) return &h[i];

    return NULL;
}

static int value_is(const qpack_header_t* f, const char* want) {
    return f != NULL && f->value_len == strlen(want) &&
           memcmp(f->value, want, f->value_len) == 0;
}

/* Field `i` by position -- the pseudo-header's placement is a rule of its own
 * (§4.3.1), so it is checked by index rather than by lookup. NULL-safe, because
 * a failed TEST_ASSERT records and carries on rather than aborting. */
static const qpack_header_t* nth(const qpack_header_t* h, size_t n, size_t i) {
    return (h != NULL && i < n) ? &h[i] : NULL;
}

static int name_is(const qpack_header_t* f, const char* want) {
    return f != NULL && f->name_len == strlen(want) &&
           memcmp(f->name, want, f->name_len) == 0;
}

static int never_indexed(const qpack_header_t* f) {
    return f != NULL && f->never_indexed;
}

TEST(test_h3response_headers) {
    TEST_SUITE("h3response");

    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    httpresponse_t* r = httpresponse_create(NULL);

    TEST_CASE("status and fields survive a round trip");
    r->status_code = 200;
    r->add_header(r, "Content-Type", "text/html");
    r->add_header(r, "X-Answer", "42");

    uint8_t* frame = NULL;
    size_t flen = 0;
    TEST_ASSERT(h3response_headers(enc, r, &frame, &flen) == H3RESPONSE_OK, "encoded");
    TEST_ASSERT(frame != NULL && flen > 2, "bytes produced");
    TEST_ASSERT(frame[0] == H3_FRAME_HEADERS, "HEADERS frame");

    size_t n = 0;
    qpack_header_t* fields = decode(frame, flen, &n);
    TEST_ASSERT(fields != NULL, "decodes");
    TEST_ASSERT(n == 3, "three fields");
    TEST_ASSERT(name_is(nth(fields, n, 0), ":status"), ":status comes first");
    TEST_ASSERT(value_is(nth(fields, n, 0), "200"), "200");
    TEST_ASSERT(value_is(find(fields, n, "content-type"), "text/html"), "content-type lowercased");
    TEST_ASSERT(value_is(find(fields, n, "x-answer"), "42"), "x-answer lowercased");
    qpack_headers_free(fields, n);
    free(frame);

    TEST_CASE("connection-specific fields are dropped");
    r->base.reset(r);
    r->status_code = 200;
    r->add_header(r, "Connection", "close");
    r->add_header(r, "Transfer-Encoding", "chunked");
    r->add_header(r, "TE", "trailers");
    r->add_header(r, "Server", "cwfr");

    TEST_ASSERT(h3response_headers(enc, r, &frame, &flen) == H3RESPONSE_OK, "encoded");
    fields = decode(frame, flen, &n);
    TEST_ASSERT(fields != NULL, "decodes");
    TEST_ASSERT(n == 2, ":status and server only");
    TEST_ASSERT(find(fields, n, "connection") == NULL, "no connection");
    TEST_ASSERT(find(fields, n, "transfer-encoding") == NULL, "no transfer-encoding");
    TEST_ASSERT(find(fields, n, "te") == NULL, "no te");
    TEST_ASSERT(value_is(find(fields, n, "server"), "cwfr"), "server kept");
    qpack_headers_free(fields, n);
    free(frame);

    TEST_CASE("sensitive fields go out never-indexed");
    r->base.reset(r);
    r->status_code = 200;
    r->add_header(r, "Set-Cookie", "sid=abc");
    r->add_header(r, "Server", "cwfr");

    TEST_ASSERT(h3response_headers(enc, r, &frame, &flen) == H3RESPONSE_OK, "encoded");
    fields = decode(frame, flen, &n);
    TEST_ASSERT(fields != NULL, "decodes");
    const qpack_header_t* cookie = find(fields, n, "set-cookie");
    TEST_ASSERT(value_is(cookie, "sid=abc"), "value survives");
    TEST_ASSERT(never_indexed(cookie), "N bit set");
    TEST_ASSERT(!never_indexed(find(fields, n, "server")), "an ordinary field is not");
    qpack_headers_free(fields, n);
    free(frame);

    TEST_CASE("a status with no fields is still a valid section");
    r->base.reset(r);
    r->status_code = 304;
    TEST_ASSERT(h3response_headers(enc, r, &frame, &flen) == H3RESPONSE_OK, "encoded");
    fields = decode(frame, flen, &n);
    TEST_ASSERT(fields != NULL && n == 1, "just :status");
    TEST_ASSERT(value_is(nth(fields, n, 0), "304"), "304");
    qpack_headers_free(fields, n);
    free(frame);

    httpresponse_free(r);
    qpack_encoder_free(enc);
}

TEST(test_h3response_interim_and_trailers) {
    TEST_SUITE("h3response");

    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    httpresponse_t* r = httpresponse_create(NULL);

    TEST_CASE("100 Continue is a bare :status");
    uint8_t* frame = NULL;
    size_t flen = 0;
    TEST_ASSERT(h3response_informational(enc, 100, NULL, &frame, &flen) == H3RESPONSE_OK,
                "encoded");
    size_t n = 0;
    qpack_header_t* fields = decode(frame, flen, &n);
    TEST_ASSERT(fields != NULL && n == 1, "one field");
    TEST_ASSERT(value_is(nth(fields, n, 0), "100"), "100");
    qpack_headers_free(fields, n);
    free(frame);

    TEST_CASE("103 Early Hints carries its Link fields");
    r->status_code = 103;
    r->add_header(r, "Link", "</style.css>; rel=preload");
    TEST_ASSERT(h3response_informational(enc, 103, r->header_, &frame, &flen) == H3RESPONSE_OK,
                "encoded");
    fields = decode(frame, flen, &n);
    TEST_ASSERT(fields != NULL && n == 2, ":status and link");
    TEST_ASSERT(value_is(nth(fields, n, 0), "103"), "103");
    TEST_ASSERT(value_is(find(fields, n, "link"), "</style.css>; rel=preload"), "link");
    qpack_headers_free(fields, n);
    free(frame);

    TEST_CASE("trailers carry no pseudo-header and no content-length");
    r->base.reset(r);
    r->add_trailer(r, "X-Checksum", "abc123");
    r->add_trailer(r, "Content-Length", "10");
    TEST_ASSERT(h3response_trailers(enc, r->trailer_, &frame, &flen) == H3RESPONSE_OK,
                "encoded");
    fields = decode(frame, flen, &n);
    TEST_ASSERT(fields != NULL, "decodes");
    TEST_ASSERT(n == 1, "content-length dropped");
    TEST_ASSERT(value_is(find(fields, n, "x-checksum"), "abc123"), "x-checksum");
    TEST_ASSERT(find(fields, n, ":status") == NULL, "no :status");
    qpack_headers_free(fields, n);
    free(frame);

    TEST_CASE("an empty trailer section is refused rather than framed");
    /* Nothing left after the drops means there is no frame worth sending; the
     * caller finishes the stream instead. */
    TEST_ASSERT(h3response_trailers(enc, NULL, &frame, &flen) == H3RESPONSE_ERR_ENCODE,
                "no trailers");

    httpresponse_free(r);
    qpack_encoder_free(enc);
}

TEST(test_h3response_data) {
    TEST_SUITE("h3response");

    TEST_CASE("a DATA header is type and length, nothing else");
    uint8_t hdr[16];
    size_t n = h3response_data_header(hdr, sizeof hdr, 100);
    /* Type 0x00 is one byte; 100 is above the 63 a one-byte varint holds, so the
     * length takes two. That the header's own width tracks the body is the
     * reason it is built after the payload length is known, never before. */
    TEST_ASSERT(n == 3, "one byte of type, two of length");
    TEST_ASSERT(hdr[0] == H3_FRAME_DATA, "DATA");

    uint8_t tiny[16];
    TEST_ASSERT(h3response_data_header(tiny, sizeof tiny, 10) == 2, "a tiny body needs two");

    uint64_t type = 0, len = 0;
    size_t off = varint_read(hdr, n, &type);
    off += varint_read(hdr + off, n - off, &len);
    TEST_ASSERT(off == n && type == H3_FRAME_DATA && len == 100, "round trip");

    TEST_CASE("the length varint widens with the body");
    n = h3response_data_header(hdr, sizeof hdr, H3_DATA_CHUNK_MAX);
    off = varint_read(hdr, n, &type);
    off += varint_read(hdr + off, n - off, &len);
    TEST_ASSERT(off == n && len == H3_DATA_CHUNK_MAX, "16K chunk");
    TEST_ASSERT(n == 5, "a 4-byte varint for 16384");

    TEST_CASE("a header that does not fit reports 0");
    TEST_ASSERT(h3response_data_header(hdr, 1, 100) == 0, "no room");
}

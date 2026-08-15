#include "framework.h"

#include "qpack.h"
#include "qpack_statictable.h"

#include <string.h>

/* QPACK-lite encoder (RFC 9204). Most cases are round-trip: encode, decode,
 * compare, so the test does not depend on whether the encoder chose Huffman.
 * The indexed-static cases are exact-byte because indexed lines carry no
 * Huffman and no literal, so the encoding is forced. */

/* Build a header pointing at a string literal. qpack_header_t.name is char* in
 * step with the decoder's malloc'd output; the encoder takes it const. */
#define H(n, v, nv) ((qpack_header_t){ (char*)(n), strlen(n), (char*)(v), strlen(v), (nv) })

static int roundtrip(qpack_encoder_t* e, qpack_decoder_t* d,
                     const qpack_header_t* in, size_t n) {
    uint8_t buf[512];
    const size_t en = qpack_encode_block(e, in, n, buf, sizeof buf);
    if (en == 0) return 0;

    qpack_header_t* out = NULL;
    size_t count = 0;
    if (qpack_decode_block(d, buf, en, 0, &out, &count) != QPACK_OK) return 0;
    if (count != n) { qpack_headers_free(out, count); return 0; }
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (out[i].name_len != in[i].name_len
            || memcmp(out[i].name, in[i].name, in[i].name_len) != 0
            || out[i].value_len != in[i].value_len
            || memcmp(out[i].value, in[i].value, in[i].value_len) != 0
            || out[i].never_indexed != in[i].never_indexed)
            ok = 0;
    }
    qpack_headers_free(out, count);
    return ok;
}

TEST(test_qpack_encode_indexed) {
    TEST_SUITE("qpack-encode");

    qpack_encoder_t* e = qpack_encoder_create(0, 0);
    uint8_t buf[16];

    TEST_CASE("an exact static match encodes to an indexed line");
    /* :method GET is static index 17 → 0xc0|17 = 0xd1, prefix 00 00. */
    qpack_header_t m = H(":method", "GET", 0);
    size_t n = qpack_encode_block(e, &m, 1, buf, sizeof buf);
    TEST_ASSERT(n == 3 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0xd1,
                ":method=GET → 00 00 d1");

    qpack_header_t p = H(":path", "/", 0);   /* index 1 → 0xc1 */
    n = qpack_encode_block(e, &p, 1, buf, sizeof buf);
    TEST_ASSERT(n == 3 && buf[2] == 0xc1, ":path=/ → 00 00 c1");

    qpack_header_t s = H(":scheme", "https", 0);  /* index 23 → 0xd7 */
    n = qpack_encode_block(e, &s, 1, buf, sizeof buf);
    TEST_ASSERT(n == 3 && buf[2] == 0xd7, ":scheme=https → 00 00 d7");

    qpack_encoder_free(e);
}

TEST(test_qpack_encode_roundtrip) {
    TEST_SUITE("qpack-encode");

    qpack_encoder_t* e = qpack_encoder_create(0, 0);
    qpack_decoder_t* d = qpack_decoder_create(0, 0);

    TEST_CASE("a mixed block round-trips: indexed, name-ref, literal, Huffman");
    qpack_header_t fields[] = {
        H(":method", "POST", 0),                       /* exact static → indexed */
        H(":path", "/api/users/42", 0),                /* :path name ref + literal */
        H(":scheme", "https", 0),                      /* exact static → indexed */
        H("content-type", "application/json", 0),      /* literal-literal-name */
        H("x-request-id", "abc-123-def-456-789", 0),   /* literal-literal, long value */
        H("x-words", "the quick brown fox jumps over the lazy dog", 0), /* Huffman-worthy */
    };
    TEST_ASSERT(roundtrip(e, d, fields, sizeof fields / sizeof fields[0]),
                "every field survives encode → decode");

    TEST_CASE("a never-indexed field round-trips and is not emitted indexed");
    qpack_header_t secret[] = {
        H(":method", "GET", 1),   /* would be indexed at 17, but never_indexed */
    };
    uint8_t buf[32];
    size_t n = qpack_encode_block(e, secret, 1, buf, sizeof buf);
    TEST_ASSERT(n > 0, "encoded");
    TEST_ASSERT((buf[2] & 0x80) == 0, "not an indexed line (N forced a literal)");
    TEST_ASSERT(roundtrip(e, d, secret, 1), "round-trips with never_indexed=1");

    qpack_encoder_free(e);
    qpack_decoder_free(d);
}

TEST(test_qpack_encode_prefix_and_capacity) {
    TEST_SUITE("qpack-encode");

    qpack_encoder_t* e = qpack_encoder_create(0, 0);

    TEST_CASE("an empty list is just the two-byte prefix");
    uint8_t buf[8];
    size_t n = qpack_encode_block(e, NULL, 0, buf, sizeof buf);
    TEST_ASSERT(n == 2 && buf[0] == 0x00 && buf[1] == 0x00, "00 00");

    TEST_CASE("a too-small cap returns 0 (unambiguous: even empty is 2 bytes)");
    qpack_header_t f = H(":method", "GET", 0);
    TEST_ASSERT(qpack_encode_block(e, &f, 1, buf, 2) == 0, "prefix alone fills 2 bytes");

    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_known_received_count) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 4);
    e->insert_count = 5;
    size_t consumed = 0;

    TEST_CASE("Insert Count Increment advances Known Received Count");
    static const uint8_t inc3[] = { 0x03 };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, inc3, sizeof inc3, &consumed)
                    == QPACK_OK, "increment accepted");
    TEST_ASSERT(consumed == 1 && e->known_received_count == 3, "advanced by three");

    TEST_CASE("increment may reach but not pass insertion count");
    static const uint8_t inc2[] = { 0x02 };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, inc2, sizeof inc2, &consumed)
                    == QPACK_OK && e->known_received_count == 5, "reached five");
    static const uint8_t inc1[] = { 0x01 };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, inc1, sizeof inc1, &consumed)
                    == QPACK_ERR_DECODER_STREAM, "cannot acknowledge a future insert");

    TEST_CASE("zero increment is always malformed");
    static const uint8_t zero[] = { 0x00 };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, zero, sizeof zero, &consumed)
                    == QPACK_ERR_DECODER_STREAM, "zero rejected");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_stream_output) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 128) == QPACK_OK, "capacity staged");
    const uint8_t* pending = NULL;
    size_t n = qpack_encoder_pending(e, &pending);
    static const uint8_t cap128[] = { 0x3f, 0x61 };
    TEST_ASSERT(n == sizeof cap128 && memcmp(pending, cap128, sizeof cap128) == 0,
                "Set Dynamic Table Capacity wire form");
    qpack_encoder_consume(e, 1);
    TEST_ASSERT(qpack_encoder_pending(e, &pending) == 1 && pending[0] == 0x61,
                "partial consume retains suffix");
    TEST_ASSERT(qpack_encoder_set_capacity(e, 129) == QPACK_ERR_ENCODER_STREAM,
                "peer SETTINGS maximum enforced");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_negotiated_limits) {
    TEST_SUITE("qpack encoder stream");
    qpack_encoder_t* e = qpack_encoder_create(0, 0);
    TEST_ASSERT(qpack_encoder_set_limits(e, 4096, 16) == QPACK_OK,
                "peer limits applied to pristine encoder");
    TEST_ASSERT(e->max_capacity == 4096 && e->max_blocked == 16, "limits stored");
    TEST_ASSERT(qpack_encoder_set_capacity(e, 128) == QPACK_OK, "encoder started");
    TEST_ASSERT(qpack_encoder_set_limits(e, 2048, 8) == QPACK_ERR_ENCODER_STREAM,
                "negotiated limits are immutable after first instruction");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_literal_insert) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 128) == QPACK_OK, "capacity");
    qpack_encoder_consume(e, 99);
    uint64_t absolute = 99;
    TEST_ASSERT(qpack_encoder_insert_literal(e, "foo", 3, "bar", 3, &absolute)
                    == QPACK_OK, "literal inserted");
    TEST_ASSERT(absolute == 0 && e->insert_count == 1 && e->bytes == 38,
                "absolute index and accounting");
    const uint8_t* pending = NULL;
    const size_t n = qpack_encoder_pending(e, &pending);
    static const uint8_t expected[] = { 0x43, 'f','o','o', 0x03, 'b','a','r' };
    TEST_ASSERT(n == sizeof expected && memcmp(pending, expected, n) == 0,
                "Insert With Literal Name wire form");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "large", 5,
                                              "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", 78,
                                              NULL) == QPACK_OK,
                "unreferenced oldest entry may be evicted");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_static_name_insert) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 128) == QPACK_OK, "capacity");
    qpack_encoder_consume(e, 99);
    uint64_t absolute = 99;
    TEST_ASSERT(qpack_encoder_insert_static_name(e, 1, "/custom", 7, &absolute)
                    == QPACK_OK, "static :path name inserted");
    TEST_ASSERT(absolute == 0 && e->entry_count == 1 && e->bytes == 44,
                "table owns one accounted entry");
    const uint8_t* pending = NULL;
    const size_t n = qpack_encoder_pending(e, &pending);
    static const uint8_t expected[] = { 0xc1, 0x07, '/','c','u','s','t','o','m' };
    TEST_ASSERT(n == sizeof expected && memcmp(pending, expected, n) == 0,
                "Insert With Name Reference wire form");
    TEST_ASSERT(qpack_encoder_insert_static_name(e, QPACK_STATIC_TABLE_SIZE,
                                                  "x", 1, NULL)
                    == QPACK_ERR_ENCODER_STREAM, "static index bounded");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_dynamic_name_insert) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(256, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 256) == QPACK_OK, "capacity");
    qpack_encoder_consume(e, 99);
    TEST_ASSERT(qpack_encoder_insert_literal(e, "foo", 3, "bar", 3, NULL) == QPACK_OK,
                "source entry");
    qpack_encoder_consume(e, 99);
    uint64_t absolute = 99;
    TEST_ASSERT(qpack_encoder_insert_dynamic_name(e, 0, "baz", 3, &absolute) == QPACK_OK,
                "newest name referenced");
    TEST_ASSERT(absolute == 1 && e->insert_count == 2, "second absolute entry");
    const uint8_t* pending = NULL;
    const size_t n = qpack_encoder_pending(e, &pending);
    static const uint8_t expected[] = { 0x80, 0x03, 'b','a','z' };
    TEST_ASSERT(n == sizeof expected && memcmp(pending, expected, n) == 0,
                "dynamic Insert With Name Reference wire form");
    TEST_ASSERT(qpack_encoder_insert_dynamic_name(e, 2, "x", 1, NULL)
                    == QPACK_ERR_ENCODER_STREAM, "relative index bounded");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_duplicate) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 128) == QPACK_OK, "capacity");
    qpack_encoder_consume(e, 99);
    TEST_ASSERT(qpack_encoder_insert_literal(e, "foo", 3, "bar", 3, NULL) == QPACK_OK,
                "source entry");
    qpack_encoder_consume(e, 99);
    uint64_t absolute = 99;
    TEST_ASSERT(qpack_encoder_duplicate(e, 0, &absolute) == QPACK_OK,
                "newest entry duplicated");
    TEST_ASSERT(absolute == 1 && e->entry_count == 2 && e->bytes == 76,
                "duplicate has a new absolute index and capacity charge");
    const uint8_t* pending = NULL;
    TEST_ASSERT(qpack_encoder_pending(e, &pending) == 1 && pending[0] == 0x00,
                "Duplicate relative zero wire form");
    TEST_ASSERT(qpack_encoder_duplicate(e, 2, NULL) == QPACK_ERR_ENCODER_STREAM,
                "relative source bounded");
    qpack_encoder_free(e);
}

TEST(test_qpack_encode_dynamic_indexed) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 4);
    qpack_decoder_t* d = qpack_decoder_create(128, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 128) == QPACK_OK, "capacity");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "foo", 3, "bar", 3, NULL) == QPACK_OK,
                "entry inserted");
    const uint8_t* instructions = NULL;
    size_t ilen = qpack_encoder_pending(e, &instructions), consumed = 0;
    TEST_ASSERT(qpack_decoder_read_encoder(d, instructions, ilen, &consumed) == QPACK_OK,
                "peer decoder received encoder stream");

    qpack_header_t field = { "foo", 3, "bar", 3, 0 };
    uint8_t block[32];
    const size_t n = qpack_encode_block(e, &field, 1, block, sizeof block);
    static const uint8_t expected[] = { 0x02, 0x00, 0x80 };
    TEST_ASSERT(n == sizeof expected && memcmp(block, expected, n) == 0,
                "RIC=1 Base=1 Indexed Dynamic relative zero");
    qpack_header_t* decoded = NULL; size_t count = 0;
    TEST_ASSERT(qpack_decode_block(d, block, n, 0, &decoded, &count) == QPACK_OK,
                "dynamic block decoded");
    TEST_ASSERT(count == 1 && decoded[0].name_len == 3 && decoded[0].value_len == 3 &&
                memcmp(decoded[0].name, "foo", 3) == 0 &&
                memcmp(decoded[0].value, "bar", 3) == 0, "round trip");
    qpack_headers_free(decoded, count);
    qpack_encoder_free(e); qpack_decoder_free(d);
}

TEST(test_qpack_encode_dynamic_tracks_stream) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 128) == QPACK_OK, "capacity");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "foo", 3, "bar", 3, NULL) == QPACK_OK,
                "entry");
    qpack_header_t field = { "foo", 3, "bar", 3, 0 };
    uint8_t block[32];
    TEST_ASSERT(qpack_encode_block_for_stream(e, 12, &field, 1, block, sizeof block) == 3,
                "dynamic section encoded for stream");
    TEST_ASSERT(e->section_count == 1, "stream and RIC registered atomically");
    size_t consumed = 0;
    static const uint8_t ack[] = { 0x8c };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, ack, sizeof ack, &consumed) == QPACK_OK,
                "peer acknowledgment accepted");
    TEST_ASSERT(e->section_count == 0, "outstanding protection released");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_respects_blocked_stream_limit) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 1);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 128) == QPACK_OK, "capacity");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "foo", 3, "bar", 3, NULL) == QPACK_OK,
                "entry");
    qpack_header_t field = { "foo", 3, "bar", 3, 0 };
    uint8_t first[32], second[32];
    TEST_ASSERT(qpack_encode_block_for_stream(e, 4, &field, 1, first, sizeof first) == 3,
                "first stream uses dynamic entry");
    TEST_ASSERT(e->section_count == 1, "one potentially blocked stream");
    TEST_ASSERT(qpack_encode_block_for_stream(e, 8, &field, 1, second, sizeof second) > 3,
                "second stream falls back to a literal at the limit");
    TEST_ASSERT(e->section_count == 1, "fallback creates no outstanding section");

    size_t consumed = 0;
    static const uint8_t ack[] = { 0x84 };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, ack, sizeof ack, &consumed) == QPACK_OK,
                "first stream acknowledged");
    TEST_ASSERT(qpack_encode_block_for_stream(e, 8, &field, 1, second, sizeof second) == 3,
                "released slot permits a dynamic section");
    TEST_ASSERT(e->section_count == 1, "second stream now tracked");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_outstanding_sections) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(128, 4);
    e->insert_count = 3;
    TEST_ASSERT(qpack_encoder_section_open(e, 8, 1) == QPACK_OK, "first section");
    TEST_ASSERT(qpack_encoder_section_open(e, 8, 3) == QPACK_OK, "trailers on same stream");
    TEST_ASSERT(e->section_count == 2, "both sections tracked");
    size_t consumed = 0;
    static const uint8_t ack[] = { 0x88 };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, ack, sizeof ack, &consumed) == QPACK_OK,
                "one section acknowledged");
    TEST_ASSERT(e->section_count == 1, "ack releases one section");
    static const uint8_t cancel[] = { 0x48 };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, cancel, sizeof cancel, &consumed) == QPACK_OK,
                "stream cancelled");
    TEST_ASSERT(e->section_count == 0, "cancellation releases every section on stream");
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, ack, sizeof ack, &consumed)
                    == QPACK_ERR_DECODER_STREAM, "unknown acknowledgment rejected");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_safe_eviction) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(80, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 80) == QPACK_OK, "capacity");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "a", 1, "one", 3, NULL) == QPACK_OK,
                "absolute zero");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "b", 1, "two", 3, NULL) == QPACK_OK,
                "absolute one");
    TEST_ASSERT(qpack_encoder_section_open(e, 4, 1) == QPACK_OK,
                "section protects absolute zero conservatively");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "c", 1, "tri", 3, NULL)
                    == QPACK_ERR_ENCODER_STREAM,
                "protected oldest entry cannot be evicted");
    size_t consumed = 0;
    static const uint8_t ack[] = { 0x84 };
    TEST_ASSERT(qpack_encoder_read_decoder_state(e, ack, sizeof ack, &consumed) == QPACK_OK,
                "section released");
    uint64_t absolute = 99;
    TEST_ASSERT(qpack_encoder_insert_literal(e, "c", 1, "tri", 3, &absolute) == QPACK_OK,
                "insertion succeeds after acknowledgment");
    TEST_ASSERT(absolute == 2 && e->entry_count == 2 && e->bytes == 72,
                "oldest evicted, absolute count remains monotonic");
    qpack_encoder_free(e);
}

TEST(test_qpack_encoder_source_survives_eviction_operation) {
    TEST_SUITE("qpack dynamic encoder");
    qpack_encoder_t* e = qpack_encoder_create(76, 4);
    TEST_ASSERT(qpack_encoder_set_capacity(e, 76) == QPACK_OK, "capacity");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "a", 1, "one", 3, NULL) == QPACK_OK,
                "oldest source");
    TEST_ASSERT(qpack_encoder_insert_literal(e, "b", 1, "two", 3, NULL) == QPACK_OK,
                "newest source");
    qpack_encoder_consume(e, 99);
    uint64_t absolute = 99;
    TEST_ASSERT(qpack_encoder_duplicate(e, 1, &absolute) == QPACK_OK,
                "oldest copied before insertion evicts it");
    TEST_ASSERT(absolute == 2 && e->entry_count == 2 && e->bytes == 72,
                "duplicate replaced its evicted source safely");
    const uint8_t* pending = NULL;
    TEST_ASSERT(qpack_encoder_pending(e, &pending) == 1 && pending[0] == 0x01,
                "wire index still names pre-insertion relative source one");
    qpack_encoder_free(e);
}

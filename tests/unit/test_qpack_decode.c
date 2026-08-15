#include "framework.h"

#include "huffman.h"
#include "qpack.h"
#include "qpack_statictable.h"

#include <string.h>

/* The QPACK decoder (RFC 9204 §4.5), in both of the shapes it takes.
 *
 * The first half works against a decoder created with capacity 0 -- what a peer
 * sees when we advertise no table: Required Insert Count is always 0, blocks
 * reference only the 0-based static table or literals, and anything naming a
 * dynamic entry is a decompression failure *because we said there was none*.
 * The second half gives the decoder a real capacity and drives the dynamic
 * table proper: insertions, Duplicate, eviction, post-base indices and a
 * section that blocks on an insert count still in the future.
 *
 * The RFC 9204 §B.1 vector is the canonical example for the static case; the
 * rest are built here using the codec's own encoder primitives, so the Huffman
 * path is exercised against known-good bytes rather than hand-computed ones. */

static int field_eq(const qpack_header_t* h,
                    const char* name, const char* value, int never) {
    return h->name_len == strlen(name) && memcmp(h->name, name, h->name_len) == 0
        && h->value_len == strlen(value) && memcmp(h->value, value, h->value_len) == 0
        && h->never_indexed == never;
}

TEST(test_qpack_static_table) {
    TEST_SUITE("qpack");

    TEST_CASE("99 entries, 0-based, known edges");
    TEST_ASSERT(QPACK_STATIC_TABLE_SIZE == 99, "size");
    TEST_ASSERT(strcmp(qpack_static_table[0].name, ":authority") == 0
                && qpack_static_table[0].value[0] == '\0', "index 0");
    TEST_ASSERT(strcmp(qpack_static_table[1].name, ":path") == 0
                && strcmp(qpack_static_table[1].value, "/") == 0, "index 1");
    TEST_ASSERT(strcmp(qpack_static_table[17].name, ":method") == 0
                && strcmp(qpack_static_table[17].value, "GET") == 0, "index 17");
    TEST_ASSERT(strcmp(qpack_static_table[23].name, ":scheme") == 0
                && strcmp(qpack_static_table[23].value, "https") == 0, "index 23");
    TEST_ASSERT(strcmp(qpack_static_table[98].name, "x-frame-options") == 0
                && strcmp(qpack_static_table[98].value, "sameorigin") == 0, "index 98");
}

TEST(test_qpack_decode_b1) {
    TEST_SUITE("qpack");

    TEST_CASE("RFC 9204 §B.1 — literal with static name reference");
    /* :path=/index.html, RIC=0, Base=0. */
    static const uint8_t block[] = {
        0x00, 0x00,
        0x51, 0x0b, '/',  'i',  'n',  'd',  'e',  'x',
        '.',  'h',  't',  'm',  'l'
    };

    qpack_decoder_t* d = qpack_decoder_create(0, 0);
    qpack_header_t* h = NULL;
    size_t count = 0;
    TEST_ASSERT(qpack_decode_block(d, block, sizeof block, 0, &h, &count) == QPACK_OK,
                "decoded");
    TEST_ASSERT(count == 1, "one field");
    TEST_ASSERT(field_eq(&h[0], ":path", "/index.html", 0), ":path=/index.html");
    qpack_headers_free(h, count);
    qpack_decoder_free(d);
}

TEST(test_qpack_decode_representations) {
    TEST_SUITE("qpack");

    qpack_decoder_t* d = qpack_decoder_create(0, 0);
    qpack_header_t* h = NULL;
    size_t count = 0;

    TEST_CASE("indexed static — :method GET (index 17)");
    static const uint8_t indexed[] = { 0x00, 0x00, 0xd1 };
    TEST_ASSERT(qpack_decode_block(d, indexed, sizeof indexed, 0, &h, &count) == QPACK_OK,
                "ok");
    TEST_ASSERT(count == 1 && field_eq(&h[0], ":method", "GET", 0), ":method=GET");
    qpack_headers_free(h, count);

    TEST_CASE("literal with literal name, no Huffman — foo=bar");
    static const uint8_t litlit[] = {
        0x00, 0x00, 0x23, 'f', 'o', 'o', 0x03, 'b', 'a', 'r'
    };
    TEST_ASSERT(qpack_decode_block(d, litlit, sizeof litlit, 0, &h, &count) == QPACK_OK,
                "ok");
    TEST_ASSERT(count == 1 && field_eq(&h[0], "foo", "bar", 0), "foo=bar");
    qpack_headers_free(h, count);

    TEST_CASE("never-indexed bit is carried through (N=1)");
    /* B.1 again but with N set: 0x71 = 01 N=1 T=1 idx=1. */
    static const uint8_t nvr[] = {
        0x00, 0x00, 0x71, 0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l'
    };
    TEST_ASSERT(qpack_decode_block(d, nvr, sizeof nvr, 0, &h, &count) == QPACK_OK, "ok");
    TEST_ASSERT(count == 1 && field_eq(&h[0], ":path", "/index.html", 1), "never_indexed=1");
    qpack_headers_free(h, count);

    TEST_CASE("two fields in one block");
    /* :method=GET (indexed 17) then foo=bar (literal-literal). */
    static const uint8_t two[] = {
        0x00, 0x00,
        0xd1,
        0x23, 'f', 'o', 'o', 0x03, 'b', 'a', 'r'
    };
    TEST_ASSERT(qpack_decode_block(d, two, sizeof two, 0, &h, &count) == QPACK_OK, "ok");
    TEST_ASSERT(count == 2, "two fields");
    TEST_ASSERT(field_eq(&h[0], ":method", "GET", 0), "first");
    TEST_ASSERT(field_eq(&h[1], "foo", "bar", 0), "second");
    qpack_headers_free(h, count);

    qpack_decoder_free(d);
}

TEST(test_qpack_decode_huffman) {
    TEST_SUITE("qpack");

    qpack_decoder_t* d = qpack_decoder_create(0, 0);
    qpack_header_t* h = NULL;
    size_t count = 0;

    TEST_CASE("a Huffman-encoded value, static name reference");
    /* :path = "/custompath", value Huffman-encoded by the codec itself. */
    const char* val = "/custompath";
    size_t vlen = strlen(val);
    uint8_t huff[64];
    ssize_t hlen = huffman_encode(huff, sizeof huff, (const uint8_t*)val, vlen);
    TEST_ASSERT(hlen > 0, "encoded");

    uint8_t block[96];
    size_t pos = 0;
    block[pos++] = 0x00; block[pos++] = 0x00;       /* prefix */
    block[pos++] = 0x51;                            /* 01 N=0 T=1 idx=1 (:path) */
    block[pos++] = (uint8_t)(0x80 | hlen);          /* H=1 | length */
    memcpy(block + pos, huff, hlen); pos += hlen;

    TEST_ASSERT(qpack_decode_block(d, block, pos, 0, &h, &count) == QPACK_OK, "ok");
    TEST_ASSERT(count == 1 && field_eq(&h[0], ":path", "/custompath", 0), "decoded");
    qpack_headers_free(h, count);

    TEST_CASE("a Huffman-encoded literal name");
    /* x-custom = v; the name is literal with H=1, built with prefix_int_encode so
     * the 3-bit length and its opcode land in the right octet. */
    const char* name = "x-custom";
    const char* v2 = "v";
    uint8_t nh[32];
    ssize_t nhlen = huffman_encode(nh, sizeof nh, (const uint8_t*)name, strlen(name));
    TEST_ASSERT(nhlen > 0, "name encoded");

    pos = 0;
    block[pos++] = 0x00; block[pos++] = 0x00;       /* prefix */
    /* opcode high bits 00101 = literal-literal-name, N=0, H=1; 3-bit length */
    pos += prefix_int_encode(block + pos, sizeof block - pos, (uint64_t)nhlen, 3, 0x28);
    memcpy(block + pos, nh, nhlen); pos += nhlen;
    /* value: H=0 | 7-bit length */
    pos += prefix_int_encode(block + pos, sizeof block - pos, strlen(v2), 7, 0x00);
    memcpy(block + pos, v2, strlen(v2)); pos += strlen(v2);

    TEST_ASSERT(qpack_decode_block(d, block, pos, 0, &h, &count) == QPACK_OK, "ok");
    TEST_ASSERT(count == 1 && field_eq(&h[0], "x-custom", "v", 0), "decoded");
    qpack_headers_free(h, count);

    qpack_decoder_free(d);
}

TEST(test_qpack_decode_empty) {
    TEST_SUITE("qpack");

    TEST_CASE("a prefix-only block decodes to zero fields");
    static const uint8_t empty[] = { 0x00, 0x00 };
    qpack_decoder_t* d = qpack_decoder_create(0, 0);
    qpack_header_t* h = (qpack_header_t*)1;  /* sentinel: must be cleared */
    size_t count = 99;
    TEST_ASSERT(qpack_decode_block(d, empty, sizeof empty, 0, &h, &count) == QPACK_OK, "ok");
    TEST_ASSERT(count == 0 && h == NULL, "no fields, out cleared");
    qpack_decoder_free(d);
}

TEST(test_qpack_decode_errors) {
    TEST_SUITE("qpack");

    qpack_decoder_t* d = qpack_decoder_create(0, 0);
    qpack_header_t* h = NULL;
    size_t count = 0;

    TEST_CASE("a dynamic-table reference is refused when we advertised no table");
    /* 0x80 = 1 T=0 idx=0 (dynamic). */
    static const uint8_t dyn[] = { 0x00, 0x00, 0x80 };
    TEST_ASSERT(qpack_decode_block(d, dyn, sizeof dyn, 0, &h, &count)
                == QPACK_ERR_DECOMPRESSION, "dynamic ref");
    TEST_ASSERT(h == NULL && count == 0, "out cleared on error");

    TEST_CASE("a post-base indexed reference is refused");
    static const uint8_t pb[] = { 0x00, 0x00, 0x10 };
    TEST_ASSERT(qpack_decode_block(d, pb, sizeof pb, 0, &h, &count)
                == QPACK_ERR_DECOMPRESSION, "post-base ref");

    TEST_CASE("Required Insert Count > 0 is refused when we advertised no table");
    static const uint8_t ric[] = { 0x01, 0x00 };
    TEST_ASSERT(qpack_decode_block(d, ric, sizeof ric, 0, &h, &count)
                == QPACK_ERR_DECOMPRESSION, "RIC=1");

    TEST_CASE("a truncated block is refused");
    static const uint8_t trunc[] = { 0x00 };  /* RIC only, Delta Base missing */
    TEST_ASSERT(qpack_decode_block(d, trunc, sizeof trunc, 0, &h, &count)
                == QPACK_ERR_DECOMPRESSION, "truncated");

    TEST_CASE("a static index out of range is refused");
    /* Indexed static (T=1, opcode bits 0xc0) with idx 99: the 6-bit prefix
     * saturates at 63 (first byte 0xc0|0x3f = 0xff), then 99-63 = 36 follows. */
    static const uint8_t oob[] = { 0x00, 0x00, 0xff, 0x24 }; /* idx = 63 + 36 = 99 */
    TEST_ASSERT(qpack_decode_block(d, oob, sizeof oob, 0, &h, &count)
                == QPACK_ERR_DECOMPRESSION, "index 99 out of range");

    TEST_CASE("oversize field section → TOO_LARGE");
    static const uint8_t small[] = {
        0x00, 0x00, 0x23, 'f', 'o', 'o', 0x03, 'b', 'a', 'r'
    };
    /* foo=bar counts 3+3+32 = 38 > 1. */
    TEST_ASSERT(qpack_decode_block(d, small, sizeof small, 1, &h, &count)
                == QPACK_ERR_TOO_LARGE, "oversize");

    qpack_decoder_free(d);
}

TEST(test_qpack_dynamic_table_instructions) {
    TEST_SUITE("qpack dynamic table");

    qpack_decoder_t* d = qpack_decoder_create(128, 4);
    size_t consumed = 99;

    TEST_CASE("capacity and literal-name insertion are applied");
    static const uint8_t first[] = {
        0x3f, 0x61,                         /* capacity 128 */
        0x43, 'f', 'o', 'o',               /* literal name foo */
        0x03, 'b', 'a', 'r'                /* value bar */
    };
    TEST_ASSERT(qpack_decoder_read_encoder(d, first, sizeof first, &consumed) == QPACK_OK,
                "encoder instructions accepted");
    TEST_ASSERT(consumed == sizeof first, "all bytes consumed");
    TEST_ASSERT(qpack_decoder_capacity(d) == 128, "capacity applied");
    TEST_ASSERT(qpack_decoder_insert_count(d) == 1, "one insertion");
    TEST_ASSERT(qpack_decoder_bytes(d) == 38, "entry uses name + value + 32 bytes");

    TEST_CASE("static and dynamic name references insert entries");
    static const uint8_t refs[] = {
        0xc1, 0x02, '/', 'x',               /* static :path name, value /x */
        0x80, 0x03, 'b', 'a', 'z'           /* newest dynamic name, value baz */
    };
    TEST_ASSERT(qpack_decoder_read_encoder(d, refs, sizeof refs, &consumed) == QPACK_OK,
                "name references accepted");
    TEST_ASSERT(consumed == sizeof refs, "both instructions consumed");
    TEST_ASSERT(qpack_decoder_insert_count(d) == 3, "absolute insert count advances");

    TEST_CASE("duplicate uses a relative dynamic index");
    static const uint8_t duplicate[] = { 0x00 }; /* duplicate newest */
    TEST_ASSERT(qpack_decoder_read_encoder(d, duplicate, sizeof duplicate, &consumed)
                    == QPACK_OK, "duplicate accepted");
    TEST_ASSERT(qpack_decoder_insert_count(d) == 4, "duplicate is a new insertion");

    TEST_CASE("an instruction split before its value remains unconsumed");
    static const uint8_t partial[] = { 0x41, 'x', 0x03, 'a' };
    consumed = 99;
    TEST_ASSERT(qpack_decoder_read_encoder(d, partial, sizeof partial, &consumed) == QPACK_OK,
                "partial feed is not malformed");
    TEST_ASSERT(consumed == 0, "caller retains the whole partial instruction");

    TEST_CASE("capacity reduction evicts oldest entries but not insert count");
    static const uint8_t shrink[] = { 0x3f, 0x01 }; /* capacity 32 */
    TEST_ASSERT(qpack_decoder_read_encoder(d, shrink, sizeof shrink, &consumed) == QPACK_OK,
                "capacity reduced");
    TEST_ASSERT(qpack_decoder_capacity(d) == 32 && qpack_decoder_bytes(d) == 0,
                "entries evicted");
    TEST_ASSERT(qpack_decoder_insert_count(d) == 4, "absolute count is monotonic");

    TEST_CASE("capacity above SETTINGS is an encoder-stream error");
    static const uint8_t too_large[] = { 0x3f, 0x62 }; /* capacity 129 */
    TEST_ASSERT(qpack_decoder_read_encoder(d, too_large, sizeof too_large, &consumed)
                    == QPACK_ERR_ENCODER_STREAM, "peer cannot exceed advertised maximum");

    qpack_decoder_free(d);
}

TEST(test_qpack_dynamic_field_references) {
    TEST_SUITE("qpack dynamic fields");

    qpack_decoder_t* d = qpack_decoder_create(128, 4);
    size_t consumed = 0;
    static const uint8_t setup[] = {
        0x3f, 0x61,                         /* capacity 128 */
        0x43, 'f', 'o', 'o', 0x03, 'b', 'a', 'r',
        0xc1, 0x02, '/', 'x'                /* :path=/x */
    };
    TEST_ASSERT(qpack_decoder_read_encoder(d, setup, sizeof setup, &consumed) == QPACK_OK,
                "dynamic table prepared");

    qpack_header_t* h = NULL;
    size_t count = 0;

    TEST_CASE("relative indexed field resolves from Base");
    static const uint8_t indexed[] = { 0x03, 0x00, 0x80 };
    TEST_ASSERT(qpack_decode_block(d, indexed, sizeof indexed, 0, &h, &count) == QPACK_OK,
                "dynamic indexed decoded");
    TEST_ASSERT(count == 1 && field_eq(&h[0], ":path", "/x", 0), "newest entry");
    qpack_headers_free(h, count);

    TEST_CASE("relative dynamic name reference supplies a new literal value");
    static const uint8_t named[] = { 0x03, 0x00, 0x41, 0x03, 'q', 'u', 'x' };
    TEST_ASSERT(qpack_decode_block(d, named, sizeof named, 0, &h, &count) == QPACK_OK,
                "dynamic name decoded");
    TEST_ASSERT(count == 1 && field_eq(&h[0], "foo", "qux", 0), "older name");
    qpack_headers_free(h, count);

    TEST_CASE("post-base indexed field resolves an entry below Required Insert Count");
    static const uint8_t postbase[] = { 0x03, 0x81, 0x10 };
    TEST_ASSERT(qpack_decode_block(d, postbase, sizeof postbase, 0, &h, &count) == QPACK_OK,
                "post-base decoded");
    TEST_ASSERT(count == 1 && field_eq(&h[0], "foo", "bar", 0), "absolute entry zero");
    qpack_headers_free(h, count);

    TEST_CASE("a future Required Insert Count blocks instead of corrupting the connection");
    qpack_decoder_t* waiting = qpack_decoder_create(128, 4);
    static const uint8_t future[] = { 0x02, 0x00 };
    uint64_t required = 99;
    TEST_ASSERT(qpack_required_insert_count(waiting, future, sizeof future, &required)
                    == QPACK_BLOCKED && required == 1,
                "scheduler learns the exact insertion threshold");
    TEST_ASSERT(qpack_decode_block(waiting, future, sizeof future, 0, &h, &count)
                    == QPACK_BLOCKED, "waits for encoder stream insertion");
    TEST_ASSERT(h == NULL && count == 0, "no partial fields escape");

    static const uint8_t one_insert[] = {
        0x3f, 0x61, 0x41, 'x', 0x01, 'y'
    };
    TEST_ASSERT(qpack_decoder_read_encoder(waiting, one_insert, sizeof one_insert,
                                           &consumed) == QPACK_OK,
                "required insertion arrived");
    TEST_ASSERT(qpack_required_insert_count(waiting, future, sizeof future, &required)
                    == QPACK_OK && required == 1,
                "same section is now ready for retry");
    qpack_decoder_free(waiting);

    qpack_decoder_free(d);
}

TEST(test_qpack_decoder_stream_output) {
    TEST_SUITE("qpack decoder stream");

    qpack_decoder_t* d = qpack_decoder_create(128, 4);
    size_t consumed = 0;
    static const uint8_t insert[] = {
        0x3f, 0x61,
        0x41, 'x', 0x01, 'y'
    };
    TEST_ASSERT(qpack_decoder_read_encoder(d, insert, sizeof insert, &consumed) == QPACK_OK,
                "one insertion accepted");

    TEST_CASE("an insertion queues Insert Count Increment");
    const uint8_t* pending = NULL;
    size_t n = qpack_decoder_pending(d, &pending);
    TEST_ASSERT(n == 1 && pending[0] == 0x01, "increment one encoded as 00iiiiii");

    TEST_CASE("section acknowledgment and stream cancellation append in order");
    TEST_ASSERT(qpack_decoder_ack_section(d, 300) == QPACK_OK, "section ack queued");
    TEST_ASSERT(qpack_decoder_cancel_stream(d, 5) == QPACK_OK, "cancellation queued");
    n = qpack_decoder_pending(d, &pending);
    static const uint8_t expected[] = { 0x01, 0xff, 0xad, 0x01, 0x45 };
    TEST_ASSERT(n == sizeof expected && memcmp(pending, expected, sizeof expected) == 0,
                "decoder instructions have RFC 9204 wire forms");

    TEST_CASE("partial consume preserves the unsent suffix");
    qpack_decoder_consume(d, 2);
    n = qpack_decoder_pending(d, &pending);
    TEST_ASSERT(n == 3 && pending[0] == 0xad && pending[2] == 0x45,
                "suffix retained");
    qpack_decoder_consume(d, 99);
    TEST_ASSERT(qpack_decoder_pending(d, &pending) == 0, "oversized consume drains queue");

    qpack_decoder_free(d);
}

#include "framework.h"

#include "h3frame.h"
#include "quicmemory.h"
#include "varint.h"

#include <string.h>

/* HTTP/3 framing (RFC 9114 §7).
 *
 * Three of these cases exist because HTTP/2 conditions the opposite reflex, and
 * getting them backwards produces a server that mostly works: unknown frames
 * are ignored rather than fatal, the HTTP/2 codepoints are rejected rather than
 * ignored, and DATA is streamed rather than buffered. */

/* Collect every frame a buffer produces, so a test can assert on the sequence
 * rather than on one call at a time. */
typedef struct {
    h3frame_status_e status[16];
    uint64_t type[16];
    uint8_t  payload[16][64];
    size_t   payload_len[16];
    int      count;
} collected_t;

static void collect(collected_t* out, h3frame_parser_t* p,
                    const uint8_t* data, size_t len) {
    const uint8_t* cursor = data;
    const uint8_t* end = data + len;

    while (out->count < 16) {
        const h3frame_status_e st = h3frame_parser_feed(p, &cursor, end);
        if (st == H3FRAME_CONTINUE) break;

        out->status[out->count] = st;
        out->type[out->count] = p->type;

        size_t n = p->payload_len;
        if (n > 64) n = 64;
        if (n > 0 && p->payload != NULL) memcpy(out->payload[out->count], p->payload, n);
        out->payload_len[out->count] = p->payload_len;

        out->count++;

        if (st == H3FRAME_ERR_ENCODING || st == H3FRAME_ERR_RESERVED ||
            st == H3FRAME_ERR_TOO_LARGE || st == H3FRAME_ERR_OOM)
            break;
    }
}

TEST(test_h3frame_basic) {
    TEST_SUITE("h3frame");

    h3frame_parser_t p;
    collected_t got;

    TEST_CASE("HEADERS is accumulated whole");
    h3frame_parser_init(&p);
    memset(&got, 0, sizeof got);
    const uint8_t headers[] = { 0x01, 0x04, 'a', 'b', 'c', 'd' };
    collect(&got, &p, headers, sizeof headers);

    TEST_ASSERT(got.count == 1, "one frame");
    TEST_ASSERT(got.status[0] == H3FRAME_READY, "ready");
    TEST_ASSERT(got.type[0] == H3_FRAME_HEADERS, "type");
    TEST_ASSERT(got.payload_len[0] == 4 && memcmp(got.payload[0], "abcd", 4) == 0,
                "payload");
    h3frame_parser_free(&p);

    TEST_CASE("two frames in one feed");
    h3frame_parser_init(&p);
    memset(&got, 0, sizeof got);
    const uint8_t two[] = { 0x01, 0x02, 'h', 'i', 0x00, 0x03, 'x', 'y', 'z' };
    collect(&got, &p, two, sizeof two);

    TEST_ASSERT(got.count == 2, "two frames");
    TEST_ASSERT(got.type[0] == H3_FRAME_HEADERS, "HEADERS first");
    TEST_ASSERT(got.status[1] == H3FRAME_DATA_CHUNK && got.type[1] == H3_FRAME_DATA,
                "DATA second");
    TEST_ASSERT(got.payload_len[1] == 3 && memcmp(got.payload[1], "xyz", 3) == 0,
                "body");
    h3frame_parser_free(&p);

    TEST_CASE("an empty frame");
    h3frame_parser_init(&p);
    memset(&got, 0, sizeof got);
    const uint8_t empty[] = { 0x04, 0x00 };   /* SETTINGS with nothing in it */
    collect(&got, &p, empty, sizeof empty);
    TEST_ASSERT(got.count == 1 && got.status[0] == H3FRAME_READY, "ready");
    TEST_ASSERT(got.payload_len[0] == 0, "empty payload");
    h3frame_parser_free(&p);
}

TEST(test_h3frame_resumption) {
    TEST_SUITE("h3frame");

    TEST_CASE("a frame split at every possible point");
    /* A QUIC stream delivers whatever sizes the network produced, so a frame
     * header can straddle two feeds -- including in the middle of a varint. */
    const uint8_t frame[] = { 0x01, 0x05, 'h', 'e', 'l', 'l', 'o' };

    int all_ok = 1;
    for (size_t cut = 1; cut < sizeof frame; cut++) {
        h3frame_parser_t p;
        h3frame_parser_init(&p);
        collected_t got;
        memset(&got, 0, sizeof got);

        collect(&got, &p, frame, cut);
        collect(&got, &p, frame + cut, sizeof frame - cut);

        if (got.count != 1) all_ok = 0;
        else if (got.status[0] != H3FRAME_READY) all_ok = 0;
        else if (got.payload_len[0] != 5 || memcmp(got.payload[0], "hello", 5) != 0)
            all_ok = 0;

        h3frame_parser_free(&p);
    }
    TEST_ASSERT(all_ok, "every split point reassembles");

    TEST_CASE("a multi-byte varint type split across feeds");
    /* Type 0x5f is a two-byte varint; splitting it exercises the path where
     * the parser has one byte of a varint and must wait. */
    const uint8_t grease[] = { 0x40, 0x5f, 0x01, 'x' };
    h3frame_parser_t p;
    h3frame_parser_init(&p);
    collected_t got;
    memset(&got, 0, sizeof got);

    collect(&got, &p, grease, 1);
    collect(&got, &p, grease + 1, sizeof grease - 1);

    TEST_ASSERT(got.count == 1, "one frame");
    TEST_ASSERT(got.status[0] == H3FRAME_SKIPPED, "an unknown type is skipped");
    TEST_ASSERT(got.type[0] == 0x5f, "type reassembled across the split");
    h3frame_parser_free(&p);
}

TEST(test_h3frame_unknown_and_reserved) {
    TEST_SUITE("h3frame");

    h3frame_parser_t p;
    collected_t got;

    TEST_CASE("an unknown frame type is skipped, not fatal");
    /* The opposite of QUIC's transport frames, where an unknown type ends the
     * connection because there is no length to skip past. Confusing the two
     * breaks one layer or the other. */
    h3frame_parser_init(&p);
    memset(&got, 0, sizeof got);
    const uint8_t unknown[] = { 0x21, 0x03, 'j', 'u', 'n', 0x01, 0x02, 'o', 'k' };
    collect(&got, &p, unknown, sizeof unknown);

    TEST_ASSERT(got.count == 2, "two results");
    TEST_ASSERT(got.status[0] == H3FRAME_SKIPPED, "the unknown one was skipped");
    TEST_ASSERT(got.status[1] == H3FRAME_READY && got.type[1] == H3_FRAME_HEADERS,
                "and parsing carried on");
    TEST_ASSERT(got.payload_len[1] == 2 && memcmp(got.payload[1], "ok", 2) == 0,
                "with the right payload");
    h3frame_parser_free(&p);

    TEST_CASE("the HTTP/2 codepoints are rejected (§11.2.1)");
    /* 0x02, 0x06, 0x08 and 0x09 were PRIORITY, PING, WINDOW_UPDATE and
     * CONTINUATION. Ignoring them would let a proxy translating between the
     * versions pass one through unnoticed, which is exactly what the rule
     * exists to prevent. */
    const uint8_t reserved[] = { 0x02, 0x06, 0x08, 0x09 };
    int all_rejected = 1;

    for (size_t i = 0; i < sizeof reserved; i++) {
        h3frame_parser_init(&p);
        memset(&got, 0, sizeof got);
        const uint8_t frame[] = { reserved[i], 0x00 };
        collect(&got, &p, frame, sizeof frame);

        if (got.count != 1 || got.status[0] != H3FRAME_ERR_RESERVED) all_rejected = 0;
        h3frame_parser_free(&p);
    }
    TEST_ASSERT(all_rejected, "all four refused");

    TEST_CASE("the reserved and grease predicates");
    TEST_ASSERT(h3_frame_type_is_reserved_h2(0x02), "0x02");
    TEST_ASSERT(h3_frame_type_is_reserved_h2(0x09), "0x09");
    TEST_ASSERT(!h3_frame_type_is_reserved_h2(0x01), "HEADERS is not reserved");
    TEST_ASSERT(h3_frame_type_is_grease(0x21), "0x21");
    TEST_ASSERT(h3_frame_type_is_grease(0x40), "0x21 + 0x1f");
    TEST_ASSERT(!h3_frame_type_is_grease(0x04), "SETTINGS is not grease");
}

TEST(test_h3frame_data_streaming) {
    TEST_SUITE("h3frame");

    TEST_CASE("DATA is handed over in pieces, never accumulated");
    /* A response body is one frame of unbounded size, so buffering it to
     * deliver in one go is not an option -- the peer chooses the size. */
    h3frame_parser_t p;
    h3frame_parser_init(&p);

    /* A 10-byte DATA frame delivered four bytes at a time. */
    const uint8_t frame[] = { 0x00, 0x0a, '0','1','2','3','4','5','6','7','8','9' };

    uint8_t assembled[16];
    size_t assembled_len = 0;
    int chunks = 0;

    const uint8_t* cursor = frame;
    const uint8_t* end = frame + sizeof frame;

    while (cursor < end) {
        const uint8_t* piece_end = cursor + 4;
        if (piece_end > end) piece_end = end;

        const uint8_t* c = cursor;
        h3frame_status_e st;
        while ((st = h3frame_parser_feed(&p, &c, piece_end)) != H3FRAME_CONTINUE) {
            if (st == H3FRAME_DATA_CHUNK) {
                memcpy(assembled + assembled_len, p.payload, p.payload_len);
                assembled_len += p.payload_len;
                chunks++;
            }
        }

        cursor = piece_end;
    }

    TEST_ASSERT(chunks > 1, "delivered in more than one piece");
    TEST_ASSERT(assembled_len == 10, "all ten bytes");
    TEST_ASSERT(memcmp(assembled, "0123456789", 10) == 0, "in order");
    h3frame_parser_free(&p);

    TEST_CASE("an oversized control frame is refused");
    /* DATA is exempt from the accumulation limit; SETTINGS announcing a
     * gigabyte is an attack rather than a use case. */
    h3frame_parser_init(&p);
    collected_t got;
    memset(&got, 0, sizeof got);
    /* SETTINGS with a length of 2^30. */
    const uint8_t huge[] = { 0x04, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 };
    collect(&got, &p, huge, sizeof huge);
    TEST_ASSERT(got.count == 1 && got.status[0] == H3FRAME_ERR_TOO_LARGE, "refused");
    h3frame_parser_free(&p);
}

TEST(test_h3frame_write) {
    TEST_SUITE("h3frame");

    TEST_CASE("round trip");
    uint8_t buf[64];
    const size_t n = h3frame_write(buf, sizeof buf, H3_FRAME_HEADERS,
                                   (const uint8_t*)"field", 5);
    TEST_ASSERT(n == 7, "type + length + payload");

    h3frame_parser_t p;
    h3frame_parser_init(&p);
    collected_t got;
    memset(&got, 0, sizeof got);
    collect(&got, &p, buf, n);

    TEST_ASSERT(got.count == 1 && got.status[0] == H3FRAME_READY, "parses back");
    TEST_ASSERT(got.type[0] == H3_FRAME_HEADERS, "type");
    TEST_ASSERT(got.payload_len[0] == 5 && memcmp(got.payload[0], "field", 5) == 0,
                "payload");
    h3frame_parser_free(&p);

    TEST_CASE("a header on its own, for streaming a body");
    const size_t h = h3frame_write_header(buf, sizeof buf, H3_FRAME_DATA, 1000000);
    TEST_ASSERT(h > 0, "written");
    TEST_ASSERT(buf[0] == 0x00, "DATA");

    TEST_CASE("refuses a buffer that is too small");
    TEST_ASSERT(h3frame_write(buf, 3, H3_FRAME_HEADERS, (const uint8_t*)"toolong", 7) == 0,
                "refused");
}

TEST(test_h3_settings) {
    TEST_SUITE("h3frame");

    TEST_CASE("defaults are not all zero");
    /* An absent MAX_FIELD_SECTION_SIZE means unlimited, not zero -- reading it
     * as zero would reject every request. */
    h3settings_t s;
    h3settings_defaults(&s);
    TEST_ASSERT(s.max_field_section_size == UINT64_MAX, "unlimited");
    TEST_ASSERT(s.qpack_max_table_capacity == 0, "no dynamic table");
    TEST_ASSERT(s.qpack_blocked_streams == 0, "no blocked streams");

    TEST_CASE("round trip");
    h3settings_t out;
    h3settings_defaults(&out);
    out.qpack_max_table_capacity = 4096;
    out.qpack_blocked_streams = 16;
    out.max_field_section_size = 262144;
    out.enable_connect_protocol = 1;

    uint8_t buf[64];
    const size_t n = h3settings_encode(buf, sizeof buf, &out);
    TEST_ASSERT(n > 0, "encoded");

    h3settings_t back;
    h3settings_defaults(&back);
    TEST_ASSERT(h3settings_decode(buf, n, &back) == H3SETTINGS_OK, "decoded");
    TEST_ASSERT(back.qpack_max_table_capacity == 4096, "table capacity");
    TEST_ASSERT(back.qpack_blocked_streams == 16, "blocked streams");
    TEST_ASSERT(back.max_field_section_size == 262144, "field section size");
    TEST_ASSERT(back.enable_connect_protocol == 1, "connect protocol");

    TEST_CASE("the HTTP/2 setting identifiers are rejected (§7.2.4.1)");
    /* Same reasoning as the frame codepoints: a translating proxy must not be
     * able to carry one across. */
    const uint8_t h2_settings[][2] = {
        { 0x02, 0x00 }, { 0x03, 0x00 }, { 0x04, 0x00 }, { 0x05, 0x00 }
    };
    int all_rejected = 1;
    for (size_t i = 0; i < 4; i++) {
        h3settings_defaults(&back);
        if (h3settings_decode(h2_settings[i], 2, &back) != H3SETTINGS_ERR_SETTINGS)
            all_rejected = 0;
    }
    TEST_ASSERT(all_rejected, "all four refused");

    TEST_CASE("a duplicate identifier is an error");
    const uint8_t dup[] = { 0x06, 0x40, 0x64, 0x06, 0x40, 0xc8 };
    h3settings_defaults(&back);
    TEST_ASSERT(h3settings_decode(dup, sizeof dup, &back) == H3SETTINGS_ERR_SETTINGS,
                "refused");

    TEST_CASE("unknown and reserved identifiers are ignored");
    /* Identifier 95 (a reserved one: 0x1f * 2 + 0x21) then a real setting.
     * 95 does not fit a one-byte varint -- 0x5f has the two-byte prefix -- so
     * it is written 0x40 0x5f. Getting that wrong garbles everything after it,
     * which is what makes varint framing unforgiving. */
    const uint8_t unknown[] = { 0x40, 0x5f, 0x00, 0x06, 0x40, 0x64 };
    h3settings_defaults(&back);
    TEST_ASSERT(h3settings_decode(unknown, sizeof unknown, &back) == H3SETTINGS_OK,
                "accepted");
    TEST_ASSERT(back.max_field_section_size == 100, "the real setting still landed");

    TEST_CASE("we emit a reserved identifier of our own");
    int found = 0;
    size_t p = 0;
    while (p < n) {
        uint64_t id = 0, value = 0;
        p += varint_read(buf + p, n - p, &id);
        p += varint_read(buf + p, n - p, &value);
        if (id >= 0x21 && (id - 0x21) % 0x1f == 0) found = 1;
    }
    TEST_ASSERT(found, "present");
    TEST_ASSERT(p == n, "the block walks exactly to its end");

    TEST_CASE("a truncated block is an error");
    const uint8_t truncated[] = { 0x06 };
    h3settings_defaults(&back);
    TEST_ASSERT(h3settings_decode(truncated, sizeof truncated, &back)
                == H3SETTINGS_ERR_ENCODING, "refused");
}

TEST(test_h3frame_accumulator_growth) {
    TEST_SUITE("h3frame");

    /* The accumulator is the one buffer in the h3 receive path a peer can grow
     * fastest, and it used to be sized from the frame's *declared* length --
     * five bytes on the wire bought a megabyte of heap, before a single payload
     * byte arrived. A peer may open a request stream per such header, and the
     * QUIC stream limit is a hundred, so one datagram of them bought a hundred
     * megabytes. It also bypassed the shared budget, so
     * http3_buffer_memory_limit could not see any of it. */

    quicmemory_configure(0, NULL);
    const size_t before = quicmemory_current();

    /* HEADERS, length 1 MiB written as an 8-byte varint -- at the accumulation
     * cap, so the frame itself is perfectly legal. Nine bytes in total. */
    static const uint8_t claim[] = {
        0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00
    };

    h3frame_parser_t p;
    h3frame_parser_init(&p);

    TEST_CASE("a declared length buys no memory on its own");
    const uint8_t* cursor = claim;
    TEST_ASSERT(h3frame_parser_feed(&p, &cursor, claim + sizeof claim) == H3FRAME_CONTINUE,
                "the header completes no frame");
    TEST_ASSERT(p.length == 1024 * 1024, "the claim was read");
    TEST_ASSERT(p.accum_cap == 0 && p.accum == NULL, "and nothing was reserved for it");
    TEST_ASSERT(quicmemory_current() == before, "nor charged to the budget");

    TEST_CASE("it grows with the payload that actually arrives");
    uint8_t chunk[64];
    memset(chunk, 'x', sizeof chunk);
    cursor = chunk;
    TEST_ASSERT(h3frame_parser_feed(&p, &cursor, chunk + sizeof chunk) == H3FRAME_CONTINUE,
                "still incomplete");
    TEST_ASSERT(p.accum_len == sizeof chunk, "the bytes are held");
    TEST_ASSERT(p.accum_cap == 256, "one step of the ladder, not the megabyte claimed");
    TEST_ASSERT(quicmemory_current() == before + p.accum_cap, "charged for exactly that");

    TEST_CASE("and hands it all back");
    h3frame_parser_free(&p);
    TEST_ASSERT(quicmemory_current() == before, "released");

    TEST_CASE("a frame smaller than the ladder step is not rounded up to it");
    /* The cap at the declared length is what keeps an ordinary header section
     * from taking 256 bytes to hold 40. */
    h3frame_parser_init(&p);
    static const uint8_t small[] = { 0x01, 0x04, 'a', 'b', 'c', 'd' };
    cursor = small;
    TEST_ASSERT(h3frame_parser_feed(&p, &cursor, small + sizeof small) == H3FRAME_READY,
                "complete");
    TEST_ASSERT(p.accum_cap == 4, "sized to the frame");
    h3frame_parser_free(&p);
    TEST_ASSERT(quicmemory_current() == before, "released");

    TEST_CASE("the budget can refuse the accumulator");
    /* The point of routing it through quicmemory: the limit an operator sets
     * now covers this buffer too. */
    quicmemory_configure(before + 64, NULL);
    h3frame_parser_init(&p);
    cursor = claim;
    h3frame_parser_feed(&p, &cursor, claim + sizeof claim);
    cursor = chunk;
    TEST_ASSERT(h3frame_parser_feed(&p, &cursor, chunk + sizeof chunk) == H3FRAME_ERR_OOM,
                "refused rather than allocated behind the limit's back");
    h3frame_parser_free(&p);

    quicmemory_configure(0, NULL);   /* do not constrain later suites */
}

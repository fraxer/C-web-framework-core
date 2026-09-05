#include "framework.h"

#include "quicframe.h"

#include <string.h>

/* QUIC frames (RFC 9000 §19).
 *
 * The ACK range encoding gets the most attention here: every field is stored
 * one less than it means and the blocks are relative to each other, so it is
 * the one structure in the protocol where an off-by-one silently acknowledges
 * the wrong packets instead of failing. */

TEST(test_quic_frame_simple) {
    TEST_SUITE("quic_frame");

    quicframe_t f;
    size_t off;

    TEST_CASE("PADDING folds a whole run into one frame");
    /* A padded Initial is ~1200 zero bytes. Reporting them individually would
     * turn one packet into a thousand iterations of the caller's loop. */
    const uint8_t padding[] = { 0, 0, 0, 0, 0, 0x01 };
    off = 0;
    TEST_ASSERT(quicframe_next(padding, sizeof padding, &off, &f) == QUICFRAME_OK, "parses");
    TEST_ASSERT(f.type == QUIC_FRAME_PADDING, "type");
    TEST_ASSERT(f.u.padding.count == 5, "five bytes folded");
    TEST_ASSERT(off == 5, "offset");
    TEST_ASSERT(quicframe_next(padding, sizeof padding, &off, &f) == QUICFRAME_OK, "next");
    TEST_ASSERT(f.type == QUIC_FRAME_PING, "PING follows");

    TEST_CASE("a frame type must use the shortest encoding (§12.4)");
    /* The one exception to "any varint encoding is legal on input". The padded
     * forms are how a frame type is smuggled past a middlebox that inspects
     * only the short one, and accepting them means two parsers can disagree
     * about which frame they just read. */
    const uint8_t padded_ping[] = { 0x40, 0x01 };   /* PING in two bytes */
    off = 0;
    TEST_ASSERT(quicframe_next(padded_ping, sizeof padded_ping, &off, &f)
                == QUICFRAME_ERR_ENCODING, "refused");

    const uint8_t padded_stream[] = { 0x40, 0x08, 0x00 };  /* STREAM in two bytes */
    off = 0;
    TEST_ASSERT(quicframe_next(padded_stream, sizeof padded_stream, &off, &f)
                == QUICFRAME_ERR_ENCODING, "including the STREAM range");

    const uint8_t padded_padding[] = { 0x40, 0x00 };  /* PADDING in two bytes */
    off = 0;
    TEST_ASSERT(quicframe_next(padded_padding, sizeof padded_padding, &off, &f)
                == QUICFRAME_ERR_ENCODING, "and PADDING, whose run count assumes it");

    const uint8_t minimal_ping[] = { 0x01 };
    off = 0;
    TEST_ASSERT(quicframe_next(minimal_ping, sizeof minimal_ping, &off, &f)
                == QUICFRAME_OK && f.type == QUIC_FRAME_PING,
                "the short form still parses");

    TEST_CASE("an unknown frame type ends the connection");
    /* The opposite of HTTP/3: there is no length prefix to skip past, so an
     * unrecognised type cannot be ignored. */
    const uint8_t unknown[] = { 0x3f };
    off = 0;
    TEST_ASSERT(quicframe_next(unknown, sizeof unknown, &off, &f) == QUICFRAME_ERR_UNKNOWN,
                "refused");

    TEST_CASE("ack-eliciting classification");
    TEST_ASSERT(!quicframe_is_ack_eliciting(QUIC_FRAME_PADDING), "PADDING");
    TEST_ASSERT(!quicframe_is_ack_eliciting(QUIC_FRAME_ACK), "ACK");
    TEST_ASSERT(!quicframe_is_ack_eliciting(QUIC_FRAME_CONNECTION_CLOSE), "CONNECTION_CLOSE");
    TEST_ASSERT(quicframe_is_ack_eliciting(QUIC_FRAME_PING), "PING");
    TEST_ASSERT(quicframe_is_ack_eliciting(QUIC_FRAME_STREAM), "STREAM");
    TEST_ASSERT(quicframe_is_ack_eliciting(QUIC_FRAME_CRYPTO), "CRYPTO");

    TEST_CASE("which frames each packet number space admits (§12.4)");
    TEST_ASSERT(quicframe_allowed_in(QUIC_FRAME_CRYPTO, QUIC_ENC_INITIAL), "CRYPTO in Initial");
    TEST_ASSERT(quicframe_allowed_in(QUIC_FRAME_ACK, QUIC_ENC_HANDSHAKE), "ACK in Handshake");
    TEST_ASSERT(!quicframe_allowed_in(QUIC_FRAME_STREAM, QUIC_ENC_INITIAL),
                "STREAM is not allowed in Initial");
    TEST_ASSERT(!quicframe_allowed_in(QUIC_FRAME_ACK, QUIC_ENC_EARLY),
                "ACK is not allowed in 0-RTT");
    TEST_ASSERT(!quicframe_allowed_in(QUIC_FRAME_HANDSHAKE_DONE, QUIC_ENC_HANDSHAKE),
                "HANDSHAKE_DONE is 1-RTT only");
    TEST_ASSERT(!quicframe_allowed_in(QUIC_FRAME_NEW_TOKEN, QUIC_ENC_INITIAL),
                "NEW_TOKEN is 1-RTT only");
    TEST_ASSERT(quicframe_allowed_in(QUIC_FRAME_CONNECTION_CLOSE, QUIC_ENC_INITIAL),
                "the transport close form works everywhere");
    TEST_ASSERT(!quicframe_allowed_in(QUIC_FRAME_CONNECTION_CLOSE_APP, QUIC_ENC_INITIAL),
                "the application close form does not");
}

TEST(test_quic_frame_stream) {
    TEST_SUITE("quic_frame");

    quicframe_t f;
    size_t off;

    TEST_CASE("all three flag bits");
    /* 0x0f = OFF | LEN | FIN */
    const uint8_t full[] = { 0x0f, 0x04, 0x40, 0x64, 0x03, 'a', 'b', 'c' };
    off = 0;
    TEST_ASSERT(quicframe_next(full, sizeof full, &off, &f) == QUICFRAME_OK, "parses");
    TEST_ASSERT(f.u.stream.id == 4, "id");
    TEST_ASSERT(f.u.stream.offset == 100, "offset");
    TEST_ASSERT(f.u.stream.len == 3 && memcmp(f.u.stream.data, "abc", 3) == 0, "data");
    TEST_ASSERT(f.u.stream.fin, "fin");
    TEST_ASSERT(off == sizeof full, "consumed");

    TEST_CASE("without LEN the frame runs to the end of the packet");
    /* This is how the last frame in a packet saves its length varint. Reading
     * it as zero-length loses the whole payload. */
    const uint8_t no_len[] = { 0x08, 0x00, 'h', 'e', 'l', 'l', 'o' };
    off = 0;
    TEST_ASSERT(quicframe_next(no_len, sizeof no_len, &off, &f) == QUICFRAME_OK, "parses");
    TEST_ASSERT(f.u.stream.len == 5 && memcmp(f.u.stream.data, "hello", 5) == 0, "data");
    TEST_ASSERT(!f.u.stream.fin, "no fin");
    TEST_ASSERT(off == sizeof no_len, "consumed");

    TEST_CASE("without OFF the offset is zero");
    const uint8_t no_off[] = { 0x0a, 0x00, 0x02, 'h', 'i' };
    off = 0;
    TEST_ASSERT(quicframe_next(no_off, sizeof no_off, &off, &f) == QUICFRAME_OK, "parses");
    TEST_ASSERT(f.u.stream.offset == 0, "offset zero");

    TEST_CASE("a length running past the payload");
    const uint8_t overlong[] = { 0x0a, 0x00, 0x20, 'x' };
    off = 0;
    TEST_ASSERT(quicframe_next(overlong, sizeof overlong, &off, &f) == QUICFRAME_ERR_ENCODING,
                "refused");

    TEST_CASE("offset + length past the varint range (§19.8)");
    /* Offset 2^62-1 (an 8-byte varint of all ones) with any data behind it puts
     * the final byte outside the space stream offsets are defined in. */
    const uint8_t huge[] = { 0x0e, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0x02, 'a', 'b' };
    off = 0;
    TEST_ASSERT(quicframe_next(huge, sizeof huge, &off, &f) == QUICFRAME_ERR_ENCODING,
                "refused");

    /* One below the edge is fine, so the check is a boundary and not a blanket
     * refusal of large offsets. */
    const uint8_t just_fits[] = { 0x0e, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xfd, 0x02, 'a', 'b' };
    off = 0;
    TEST_ASSERT(quicframe_next(just_fits, sizeof just_fits, &off, &f) == QUICFRAME_OK,
                "offset 2^62-3 with two bytes is accepted");

    TEST_CASE("round trip through the writer");
    uint8_t buf[64];
    quicframe_t out = {
        .type = QUIC_FRAME_STREAM | QUIC_STREAM_FLAG_OFF | QUIC_STREAM_FLAG_LEN |
                QUIC_STREAM_FLAG_FIN
    };
    out.u.stream.id = 12;
    out.u.stream.offset = 1000;
    out.u.stream.len = 3;
    out.u.stream.data = (const uint8_t*)"xyz";

    const size_t n = quicframe_write(buf, sizeof buf, &out);
    TEST_ASSERT(n > 0, "written");
    off = 0;
    TEST_ASSERT(quicframe_next(buf, n, &off, &f) == QUICFRAME_OK, "parses back");
    TEST_ASSERT(f.u.stream.id == 12 && f.u.stream.offset == 1000, "fields");
    TEST_ASSERT(f.u.stream.len == 3 && memcmp(f.u.stream.data, "xyz", 3) == 0, "data");
    TEST_ASSERT(f.u.stream.fin, "fin");
}

TEST(test_quic_frame_ack) {
    TEST_SUITE("quic_frame");

    quicframe_t f;
    size_t off;

    TEST_CASE("a single contiguous run");
    /* largest 10, first range 2 -> packets 8..10 */
    const uint8_t one[] = { 0x02, 0x0a, 0x00, 0x00, 0x02 };
    off = 0;
    TEST_ASSERT(quicframe_next(one, sizeof one, &off, &f) == QUICFRAME_OK, "parses");
    TEST_ASSERT(f.u.ack.largest == 10 && f.u.ack.first_range == 2, "fields");

    quicack_iter_t it;
    quicack_block_t b;
    quicack_iter_init(&f, &it);
    TEST_ASSERT(quicack_iter_next(&it, &b) == 1, "one block");
    TEST_ASSERT(b.largest == 10 && b.smallest == 8, "8..10");
    TEST_ASSERT(quicack_iter_next(&it, &b) == 0, "no more");

    TEST_CASE("two runs with a gap");
    /* largest 20, first range 0 -> {20}; then gap 1, length 1 -> {17,18}.
     * next largest = 20 - 1 - 2 = 17... careful: prev smallest is 20, so
     * largest = 20 - gap - 2 = 17, smallest = 17 - 1 = 16 -> {16,17} */
    const uint8_t two[] = { 0x02, 0x14, 0x00, 0x01, 0x00, 0x01, 0x01 };
    off = 0;
    TEST_ASSERT(quicframe_next(two, sizeof two, &off, &f) == QUICFRAME_OK, "parses");
    TEST_ASSERT(f.u.ack.range_count == 1, "one extra range");

    quicack_iter_init(&f, &it);
    TEST_ASSERT(quicack_iter_next(&it, &b) == 1 && b.largest == 20 && b.smallest == 20,
                "first block is {20}");
    TEST_ASSERT(quicack_iter_next(&it, &b) == 1 && b.largest == 17 && b.smallest == 16,
                "second block is 16..17");
    TEST_ASSERT(quicack_iter_next(&it, &b) == 0, "no more");

    TEST_CASE("a gap that would run below zero is refused at parse time");
    /* largest 3, first range 0 -> {3}; gap 10 would put the next block at -9. */
    const uint8_t underflow[] = { 0x02, 0x03, 0x00, 0x01, 0x00, 0x0a, 0x00 };
    off = 0;
    TEST_ASSERT(quicframe_next(underflow, sizeof underflow, &off, &f) == QUICFRAME_ERR_ENCODING,
                "refused");

    TEST_CASE("a first range larger than the largest acknowledged");
    const uint8_t bad_first[] = { 0x02, 0x05, 0x00, 0x00, 0x0a };
    off = 0;
    TEST_ASSERT(quicframe_next(bad_first, sizeof bad_first, &off, &f) == QUICFRAME_ERR_ENCODING,
                "refused");

    TEST_CASE("ECN counts");
    const uint8_t ecn[] = { 0x03, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03 };
    off = 0;
    TEST_ASSERT(quicframe_next(ecn, sizeof ecn, &off, &f) == QUICFRAME_OK, "parses");
    TEST_ASSERT(f.u.ack.has_ecn, "flagged");
    TEST_ASSERT(f.u.ack.ect0 == 1 && f.u.ack.ect1 == 2 && f.u.ack.ce == 3, "counts");
    TEST_ASSERT(off == sizeof ecn, "consumed");

    TEST_CASE("hostile ACK encodings are rejected without partial consumption");
    /* These are bytes a connected peer can send to the server after AEAD:
     * false range counts, truncated ECN counters and ranges whose relative
     * arithmetic would cross packet number zero. */
    static const struct {
        const uint8_t bytes[16];
        size_t len;
    } hostile[] = {
        { { 0x02, 0x00, 0x00, 0x01, 0x00 }, 5 },       /* missing range */
        { { 0x02, 0x00, 0x00, 0x00, 0x01 }, 5 },       /* first > largest */
        { { 0x02, 0x03, 0x00, 0x01, 0x00, 0x03, 0x00 }, 7 }, /* gap below 0 */
        { { 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02 }, 7 }, /* missing CE */
        { { 0x02, 0x00, 0x00, 0x40 }, 4 },             /* cut range count varint */
        { { 0x02, 0x00, 0x00, 0x01, 0x00, 0x40 }, 6 }  /* cut gap varint */
    };
    int hostile_rejected = 1;
    for (size_t i = 0; i < sizeof hostile / sizeof hostile[0]; i++) {
        off = 0;
        if (quicframe_next(hostile[i].bytes, hostile[i].len, &off, &f) !=
                QUICFRAME_ERR_ENCODING || off != 0) {
            hostile_rejected = 0;
            break;
        }
    }
    TEST_ASSERT(hostile_rejected, "all malformed peer ACKs are rejected atomically");

    TEST_CASE("every truncated prefix of ACK_ECN is rejected");
    int prefixes_rejected = 1;
    for (size_t len = 1; len < sizeof ecn; len++) {
        off = 0;
        if (quicframe_next(ecn, len, &off, &f) != QUICFRAME_ERR_ENCODING || off != 0) {
            prefixes_rejected = 0;
            break;
        }
    }
    TEST_ASSERT(prefixes_rejected, "no truncated ACK_ECN reaches server state");

    TEST_CASE("writer round trip over several blocks");
    const quicack_block_t blocks[] = {
        { .largest = 100, .smallest = 98 },
        { .largest = 90,  .smallest = 90 },
        { .largest = 50,  .smallest = 40 }
    };
    uint8_t buf[64];
    const size_t n = quicframe_write_ack(buf, sizeof buf, blocks, 3, 1234, NULL);
    TEST_ASSERT(n > 0, "written");

    off = 0;
    TEST_ASSERT(quicframe_next(buf, n, &off, &f) == QUICFRAME_OK, "parses back");
    TEST_ASSERT(f.u.ack.largest == 100 && f.u.ack.delay == 1234, "header fields");
    TEST_ASSERT(f.u.ack.range_count == 2, "range count");

    quicack_iter_init(&f, &it);
    int ok = 1;
    for (size_t i = 0; i < 3; i++) {
        if (quicack_iter_next(&it, &b) != 1) { ok = 0; break; }
        if (b.largest != blocks[i].largest || b.smallest != blocks[i].smallest) ok = 0;
    }
    TEST_ASSERT(ok, "every block survives the round trip");
    TEST_ASSERT(quicack_iter_next(&it, &b) == 0, "and no extra block appears");

    TEST_CASE("the writer refuses blocks that touch or run the wrong way");
    /* Adjacent runs are one run; the encoding cannot express a gap of zero. */
    const quicack_block_t adjacent[] = {
        { .largest = 10, .smallest = 10 },
        { .largest = 9,  .smallest = 9 }
    };
    TEST_ASSERT(quicframe_write_ack(buf, sizeof buf, adjacent, 2, 0, NULL) == 0, "adjacent");

    const quicack_block_t ascending[] = {
        { .largest = 10, .smallest = 10 },
        { .largest = 20, .smallest = 20 }
    };
    TEST_ASSERT(quicframe_write_ack(buf, sizeof buf, ascending, 2, 0, NULL) == 0, "ascending");

    const quicack_block_t inverted[] = { { .largest = 5, .smallest = 9 } };
    TEST_ASSERT(quicframe_write_ack(buf, sizeof buf, inverted, 1, 0, NULL) == 0, "inverted");
}

TEST(test_quic_frame_roundtrip) {
    TEST_SUITE("quic_frame");

    TEST_CASE("every simple frame type survives encode -> decode");
    uint8_t buf[128];
    quicframe_t in;
    quicframe_t back;
    size_t off;
    int all_ok = 1;

    struct { uint64_t type; void (*fill)(quicframe_t*); } cases[] = { { 0, NULL } };
    (void)cases;

    /* PING */
    memset(&in, 0, sizeof in); in.type = QUIC_FRAME_PING;
    size_t n = quicframe_write(buf, sizeof buf, &in);
    off = 0;
    if (n != 1 || quicframe_next(buf, n, &off, &back) != QUICFRAME_OK ||
        back.type != QUIC_FRAME_PING) all_ok = 0;
    TEST_ASSERT(all_ok, "PING");

    /* RESET_STREAM */
    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_RESET_STREAM;
    in.u.reset_stream.id = 7; in.u.reset_stream.error = 0x0102; in.u.reset_stream.final_size = 4096;
    n = quicframe_write(buf, sizeof buf, &in);
    off = 0;
    TEST_ASSERT(n > 0 && quicframe_next(buf, n, &off, &back) == QUICFRAME_OK &&
                back.u.reset_stream.id == 7 && back.u.reset_stream.error == 0x0102 &&
                back.u.reset_stream.final_size == 4096, "RESET_STREAM");

    /* CRYPTO */
    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_CRYPTO;
    in.u.crypto.offset = 300; in.u.crypto.len = 4; in.u.crypto.data = (const uint8_t*)"data";
    n = quicframe_write(buf, sizeof buf, &in);
    off = 0;
    TEST_ASSERT(n > 0 && quicframe_next(buf, n, &off, &back) == QUICFRAME_OK &&
                back.u.crypto.offset == 300 && back.u.crypto.len == 4 &&
                memcmp(back.u.crypto.data, "data", 4) == 0, "CRYPTO");

    /* NEW_CONNECTION_ID */
    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_NEW_CONNECTION_ID;
    in.u.new_cid.seq = 5; in.u.new_cid.retire_prior_to = 2;
    in.u.new_cid.cid.len = 8;
    memcpy(in.u.new_cid.cid.data, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    memset(in.u.new_cid.token, 0xab, 16);
    n = quicframe_write(buf, sizeof buf, &in);
    off = 0;
    TEST_ASSERT(n > 0 && quicframe_next(buf, n, &off, &back) == QUICFRAME_OK &&
                back.u.new_cid.seq == 5 && back.u.new_cid.retire_prior_to == 2 &&
                back.u.new_cid.cid.len == 8 && back.u.new_cid.token[0] == 0xab,
                "NEW_CONNECTION_ID");

    /* PATH_CHALLENGE */
    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_PATH_CHALLENGE;
    memcpy(in.u.path.data, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    n = quicframe_write(buf, sizeof buf, &in);
    off = 0;
    TEST_ASSERT(n == 9 && quicframe_next(buf, n, &off, &back) == QUICFRAME_OK &&
                memcmp(back.u.path.data, in.u.path.data, 8) == 0, "PATH_CHALLENGE");

    /* CONNECTION_CLOSE with a reason */
    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_CONNECTION_CLOSE;
    in.u.close.error = 0x0a; in.u.close.frame_type = QUIC_FRAME_STREAM;
    in.u.close.reason = "bad stream"; in.u.close.reason_len = 10;
    n = quicframe_write(buf, sizeof buf, &in);
    off = 0;
    TEST_ASSERT(n > 0 && quicframe_next(buf, n, &off, &back) == QUICFRAME_OK &&
                back.u.close.error == 0x0a && back.u.close.frame_type == QUIC_FRAME_STREAM &&
                back.u.close.reason_len == 10 &&
                memcmp(back.u.close.reason, "bad stream", 10) == 0, "CONNECTION_CLOSE");

    /* The application form has no frame type field -- reading one would shift
     * the reason and produce garbage. */
    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_CONNECTION_CLOSE_APP;
    in.u.close.error = 0x0100; in.u.close.reason = "h3"; in.u.close.reason_len = 2;
    n = quicframe_write(buf, sizeof buf, &in);
    off = 0;
    TEST_ASSERT(n > 0 && quicframe_next(buf, n, &off, &back) == QUICFRAME_OK &&
                back.u.close.error == 0x0100 && back.u.close.reason_len == 2 &&
                memcmp(back.u.close.reason, "h3", 2) == 0, "CONNECTION_CLOSE (application)");

    TEST_CASE("frames the writer must refuse");
    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_ACK;
    TEST_ASSERT(quicframe_write(buf, sizeof buf, &in) == 0, "ACK has its own writer");

    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_NEW_TOKEN;
    TEST_ASSERT(quicframe_write(buf, sizeof buf, &in) == 0, "an empty NEW_TOKEN");

    memset(&in, 0, sizeof in);
    in.type = QUIC_FRAME_NEW_CONNECTION_ID;
    in.u.new_cid.seq = 1; in.u.new_cid.retire_prior_to = 5; in.u.new_cid.cid.len = 8;
    TEST_ASSERT(quicframe_write(buf, sizeof buf, &in) == 0, "retire_prior_to above seq");
}

TEST(test_quic_frame_truncation) {
    TEST_SUITE("quic_frame");

    TEST_CASE("every proper prefix of a frame sequence is refused or ends cleanly");
    /* The payload is authenticated by the time it reaches here, so this is
     * about a buggy peer rather than an attacker -- but reading past the buffer
     * would be just as fatal. */
    const uint8_t frames[] = {
        0x01,                                     /* PING */
        0x0f, 0x04, 0x40, 0x64, 0x03, 'a', 'b', 'c',  /* STREAM */
        0x02, 0x0a, 0x00, 0x00, 0x02,             /* ACK */
        0x1e                                      /* HANDSHAKE_DONE */
    };

    int no_crash = 1;
    for (size_t n = 0; n <= sizeof frames; n++) {
        size_t off = 0;
        quicframe_t f;
        quicframe_status_e st;
        while ((st = quicframe_next(frames, n, &off, &f)) == QUICFRAME_OK) {
            if (off > n) { no_crash = 0; break; }
        }
        if (st == QUICFRAME_ERR_UNKNOWN) no_crash = 0;
    }
    TEST_ASSERT(no_crash, "no prefix walks past its buffer or misreads a type");

    size_t off = 0;
    quicframe_t f;
    int count = 0;
    while (quicframe_next(frames, sizeof frames, &off, &f) == QUICFRAME_OK) count++;
    TEST_ASSERT(count == 4, "the whole sequence yields four frames");
}

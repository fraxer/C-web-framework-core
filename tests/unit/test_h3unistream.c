#include "framework.h"

#include "h3unistream.h"
#include "h3error.h"
#include "varint.h"

#include <string.h>

/* Unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2).
 *
 * The cases here are the ones the design doc warns are easy to invert by analogy
 * with HTTP/2 or with the QUIC transport layer: unknown is not fatal (it is at
 * the transport layer), the service streams are critical and unique, a client
 * may not open a push stream, and a split varint must reassemble. */

/* ---- Predicates ---- */

TEST(test_h3uni_predicates) {
    TEST_SUITE("h3unistream");

    TEST_CASE("the four HTTP/3 stream types");
    TEST_ASSERT(h3uni_type_is_known(H3_UNI_STREAM_CONTROL), "control");
    TEST_ASSERT(h3uni_type_is_known(H3_UNI_STREAM_PUSH), "push");
    TEST_ASSERT(h3uni_type_is_known(H3_UNI_STREAM_QPACK_ENCODER), "qpack enc");
    TEST_ASSERT(h3uni_type_is_known(H3_UNI_STREAM_QPACK_DECODER), "qpack dec");
    TEST_ASSERT(!h3uni_type_is_known(0x04), "0x04 is not known");
    TEST_ASSERT(!h3uni_type_is_known(0x21), "grease is not 'known'");

    TEST_CASE("control and both QPACK streams are critical; push is not");
    /* Closing any of these is a connection error; a closed push stops one push. */
    TEST_ASSERT(h3uni_type_is_critical(H3_UNI_STREAM_CONTROL), "control critical");
    TEST_ASSERT(h3uni_type_is_critical(H3_UNI_STREAM_QPACK_ENCODER), "enc critical");
    TEST_ASSERT(h3uni_type_is_critical(H3_UNI_STREAM_QPACK_DECODER), "dec critical");
    TEST_ASSERT(!h3uni_type_is_critical(H3_UNI_STREAM_PUSH), "push not critical");
    TEST_ASSERT(!h3uni_type_is_critical(0x05), "unknown not critical");
    TEST_ASSERT(!h3uni_type_is_critical(0x21), "grease not critical");

    TEST_CASE("grease values 0x1f*N + 0x21");
    TEST_ASSERT(h3uni_type_is_grease(0x21), "0x21");
    TEST_ASSERT(h3uni_type_is_grease(0x40), "0x21 + 0x1f");
    TEST_ASSERT(h3uni_type_is_grease(0x5f), "0x21 + 2*0x1f");
    TEST_ASSERT(!h3uni_type_is_grease(0x00), "control not grease");
    TEST_ASSERT(!h3uni_type_is_grease(0x05), "unknown not grease");
    TEST_ASSERT(!h3uni_type_is_grease(0x20), "just below the grease range");
}

/* ---- Parsing the type prefix ---- */

TEST(test_h3uni_parse_known) {
    TEST_SUITE("h3unistream");

    TEST_CASE("each known type, in one feed");
    const uint64_t types[] = {
        H3_UNI_STREAM_CONTROL, H3_UNI_STREAM_PUSH,
        H3_UNI_STREAM_QPACK_ENCODER, H3_UNI_STREAM_QPACK_DECODER
    };
    int all_ok = 1;
    for (size_t i = 0; i < sizeof types / sizeof types[0]; i++) {
        uint8_t buf[8];
        const size_t n = h3uni_write_type(buf, sizeof buf, types[i]);
        TEST_ASSERT(n > 0, "encoded");

        h3uni_parser_t p;
        h3uni_parser_init(&p);
        const uint8_t* cur = buf;
        const h3uni_status_e st = h3uni_parser_feed(&p, &cur, buf + n);

        if (st != H3UNI_READY || p.type != types[i] || cur != buf + n) all_ok = 0;
    }
    TEST_ASSERT(all_ok, "all four parsed, cursor advanced past the varint");

    TEST_CASE("a READY parser does not re-parse stream content");
    /* The type prefix is one varint; the bytes after it belong to a different
     * parser. Feeding them here again must be a no-op. */
    uint8_t buf[16];
    const size_t n = h3uni_write_type(buf, sizeof buf, H3_UNI_STREAM_CONTROL);
    /* Append bytes that look like another type prefix. */
    buf[n] = H3_UNI_STREAM_PUSH;

    h3uni_parser_t p;
    h3uni_parser_init(&p);
    const uint8_t* cur = buf;
    TEST_ASSERT(h3uni_parser_feed(&p, &cur, buf + n + 1) == H3UNI_READY, "ready");
    TEST_ASSERT(cur == buf + n, "cursor at the end of the varint");
    TEST_ASSERT(p.type == H3_UNI_STREAM_CONTROL, "control");
    TEST_ASSERT(p.done, "marked done");

    const uint8_t* cur2 = cur;
    TEST_ASSERT(h3uni_parser_feed(&p, &cur2, buf + n + 1) == H3UNI_CONTINUE,
                "a second feed is a no-op");
    TEST_ASSERT(cur2 == cur, "no bytes consumed");
    TEST_ASSERT(p.type == H3_UNI_STREAM_CONTROL, "type unchanged");
}

TEST(test_h3uni_parse_resumption) {
    TEST_SUITE("h3unistream");

    TEST_CASE("a two-byte varint type, split at every point");
    /* 0x40 is a grease value (64). Its minimal encoding is two bytes because the
     * 1-byte form only reaches 63: 0x40 | (64>>8), 64 & 0xff == 0x40 0x40. */
    uint8_t grease[2];
    TEST_ASSERT(h3uni_write_type(grease, sizeof grease, 0x40) == 2, "two bytes");
    TEST_ASSERT(grease[0] == 0x40 && grease[1] == 0x40, "the expected encoding");

    int all_ok = 1;
    for (size_t cut = 1; cut < sizeof grease; cut++) {
        h3uni_parser_t p;
        h3uni_parser_init(&p);

        const uint8_t* cur = grease;
        h3uni_status_e st = h3uni_parser_feed(&p, &cur, grease + cut);
        if (st != H3UNI_CONTINUE) all_ok = 0;
        if (cur != grease + cut) all_ok = 0;

        const uint8_t* rest = grease + cut;
        st = h3uni_parser_feed(&p, &rest, grease + sizeof grease);
        if (st != H3UNI_READY) all_ok = 0;
        if (p.type != 0x40) all_ok = 0;
        if (rest != grease + sizeof grease) all_ok = 0;
    }
    TEST_ASSERT(all_ok, "reassembles regardless of where it was split");

    TEST_CASE("a one-byte type delivered empty, then in full");
    uint8_t ctrl[1] = { H3_UNI_STREAM_CONTROL };
    h3uni_parser_t p;
    h3uni_parser_init(&p);
    const uint8_t* cur = ctrl;
    TEST_ASSERT(h3uni_parser_feed(&p, &cur, cur) == H3UNI_CONTINUE, "need bytes");
    TEST_ASSERT(cur == ctrl, "nothing consumed");
    TEST_ASSERT(h3uni_parser_feed(&p, &cur, ctrl + 1) == H3UNI_READY, "ready");
    TEST_ASSERT(p.type == H3_UNI_STREAM_CONTROL, "control");
}

/* ---- Per-direction duplicate tracking ---- */

TEST(test_h3uni_seen) {
    TEST_SUITE("h3unistream");

    TEST_CASE("a unique type is first-accepted, then duplicate");
    h3uni_seen_t seen;
    h3uni_seen_init(&seen);
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_CONTROL) == 1, "first control");
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_CONTROL) == 0, "second control");
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_QPACK_ENCODER) == 1, "first enc");
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_QPACK_ENCODER) == 0, "second enc");
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_QPACK_DECODER) == 1, "first dec");
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_QPACK_DECODER) == 0, "second dec");

    /* The three are independent: the control bit being set did not block enc/dec
     * above, and a fresh tracker accepts each once. */
    h3uni_seen_init(&seen);
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_QPACK_DECODER) == 1, "dec alone");

    TEST_CASE("push is not tracked -- many per server");
    /* A client opening one is illegal, but that is a policy decision for
     * classify(), not the tracker. The tracker simply does not record it. */
    h3uni_seen_init(&seen);
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_PUSH) == 1, "push ignored");
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_PUSH) == 1, "still ignored");
    /* And a push did not consume the control bit. */
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_CONTROL) == 1, "control still free");

    TEST_CASE("unknown and grease are not tracked");
    h3uni_seen_init(&seen);
    TEST_ASSERT(h3uni_seen_mark(&seen, 0x05) == 1, "unknown ignored");
    TEST_ASSERT(h3uni_seen_mark(&seen, 0x21) == 1, "grease ignored");
    TEST_ASSERT(h3uni_seen_mark(&seen, H3_UNI_STREAM_CONTROL) == 1, "control still free");
}

/* ---- Policy: the server's verdict on a client-opened stream ---- */

TEST(test_h3uni_classify) {
    TEST_SUITE("h3unistream");

    TEST_CASE("unique service streams route on first sight");
    h3uni_seen_t seen;
    h3uni_seen_init(&seen);

    h3uni_verdict_t v = h3uni_server_classify(&seen, H3_UNI_STREAM_CONTROL);
    TEST_ASSERT(v.action == H3UNI_ROUTE && v.type == H3_UNI_STREAM_CONTROL,
                "control routed");
    TEST_ASSERT(v.error == 0, "no error");

    v = h3uni_server_classify(&seen, H3_UNI_STREAM_QPACK_ENCODER);
    TEST_ASSERT(v.action == H3UNI_ROUTE && v.type == H3_UNI_STREAM_QPACK_ENCODER,
                "encoder routed");

    v = h3uni_server_classify(&seen, H3_UNI_STREAM_QPACK_DECODER);
    TEST_ASSERT(v.action == H3UNI_ROUTE && v.type == H3_UNI_STREAM_QPACK_DECODER,
                "decoder routed");

    TEST_CASE("a duplicate service stream is a connection error");
    v = h3uni_server_classify(&seen, H3_UNI_STREAM_CONTROL);
    TEST_ASSERT(v.action == H3UNI_CONN_ERROR, "fatal");
    TEST_ASSERT(v.error == H3_STREAM_CREATION_ERROR, "H3_STREAM_CREATION_ERROR");

    v = h3uni_server_classify(&seen, H3_UNI_STREAM_QPACK_ENCODER);
    TEST_ASSERT(v.action == H3UNI_CONN_ERROR && v.error == H3_STREAM_CREATION_ERROR,
                "duplicate encoder fatal");
    v = h3uni_server_classify(&seen, H3_UNI_STREAM_QPACK_DECODER);
    TEST_ASSERT(v.action == H3UNI_CONN_ERROR && v.error == H3_STREAM_CREATION_ERROR,
                "duplicate decoder fatal");

    TEST_CASE("a push stream from a client is illegal, even once");
    /* Only a server pushes (RFC 9114 §6.2.2). This is a connection error on
     * first sight, not an unknown type. */
    h3uni_seen_init(&seen);
    v = h3uni_server_classify(&seen, H3_UNI_STREAM_PUSH);
    TEST_ASSERT(v.action == H3UNI_CONN_ERROR, "fatal");
    TEST_ASSERT(v.error == H3_STREAM_CREATION_ERROR, "stream creation error");
    /* And classifying push did not consume any unique-type bit. */
    v = h3uni_server_classify(&seen, H3_UNI_STREAM_CONTROL);
    TEST_ASSERT(v.action == H3UNI_ROUTE, "control still routes after a push");

    TEST_CASE("grease is ignored, and leaves nothing tracked");
    h3uni_seen_init(&seen);
    v = h3uni_server_classify(&seen, 0x21);
    TEST_ASSERT(v.action == H3UNI_IGNORE, "grease ignored");
    v = h3uni_server_classify(&seen, 0x40);
    TEST_ASSERT(v.action == H3UNI_IGNORE, "grease again still ignored");
    v = h3uni_server_classify(&seen, H3_UNI_STREAM_CONTROL);
    TEST_ASSERT(v.action == H3UNI_ROUTE, "control unaffected by grease");

    TEST_CASE("an unknown type is STOP_SENDING + discard, not fatal");
    h3uni_seen_init(&seen);
    v = h3uni_server_classify(&seen, 0x05);
    TEST_ASSERT(v.action == H3UNI_STOP_DROP, "stop and drop");
    TEST_ASSERT(v.error == H3_STREAM_CREATION_ERROR, "the STOP_SENDING code");
    /* The connection survives. */
    v = h3uni_server_classify(&seen, H3_UNI_STREAM_CONTROL);
    TEST_ASSERT(v.action == H3UNI_ROUTE, "control still routes after unknown");
}

/* ---- Writing ---- */

TEST(test_h3uni_write) {
    TEST_SUITE("h3unistream");

    TEST_CASE("round trip the server's own stream types");
    const uint64_t types[] = {
        H3_UNI_STREAM_CONTROL, H3_UNI_STREAM_PUSH,
        H3_UNI_STREAM_QPACK_ENCODER, H3_UNI_STREAM_QPACK_DECODER, 0x21 /* grease */
    };
    int all_ok = 1;
    for (size_t i = 0; i < sizeof types / sizeof types[0]; i++) {
        uint8_t buf[8];
        const size_t n = h3uni_write_type(buf, sizeof buf, types[i]);
        if (n == 0) { all_ok = 0; continue; }

        h3uni_parser_t p;
        h3uni_parser_init(&p);
        const uint8_t* cur = buf;
        if (h3uni_parser_feed(&p, &cur, buf + n) != H3UNI_READY) all_ok = 0;
        if (p.type != types[i]) all_ok = 0;
        if (cur != buf + n) all_ok = 0;
    }
    TEST_ASSERT(all_ok, "all five types round-trip");

    TEST_CASE("refuses a buffer that is too small");
    uint8_t tiny[1];
    /* 0x40 needs two bytes; handing it a one-byte buffer fails. */
    TEST_ASSERT(h3uni_write_type(tiny, sizeof tiny, 0x40) == 0, "refused");
    /* varint_write rejects out-of-range values too. */
    uint8_t buf[8];
    TEST_ASSERT(h3uni_write_type(buf, sizeof buf, UINT64_MAX) == 0,
                "out-of-range refused");
}

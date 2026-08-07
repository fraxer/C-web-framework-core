#include "framework.h"

#include "h3frame.h"
#include "h3session.h"
#include "qpack.h"
#include "varint.h"

#include <string.h>

/* The connection-level rules (docs/http3/05-http3.md §3, §4, §7). Every case
 * here feeds bytes of a peer-initiated unidirectional stream and reads back a
 * verdict, which is the whole interface the transport glue will use. */

static h3session_verdict_t feed(h3session_t* s, h3uni_recv_t* uni,
                                const uint8_t* data, size_t len, int fin) {
    return h3session_uni_feed(s, uni, data, len, fin);
}

/* A control stream's bytes: the type varint 0x00 followed by whatever frames. */
static size_t control_bytes(uint8_t* dst, size_t cap,
                            uint64_t type, const uint8_t* payload, size_t plen) {
    dst[0] = 0x00;
    return 1 + h3frame_write(dst + 1, cap - 1, type, payload, plen);
}

TEST(test_h3session_settings) {
    TEST_SUITE("h3session");

    TEST_CASE("our control preamble is the stream type then SETTINGS");
    h3session_t* s = h3session_create(65536, 1);
    TEST_ASSERT(s != NULL, "session created");

    uint8_t pre[128];
    const size_t plen = h3session_control_preamble(s, pre, sizeof pre);
    TEST_ASSERT(plen > 2, "preamble written");
    TEST_ASSERT(pre[0] == 0x00, "control stream type first");
    TEST_ASSERT(pre[1] == H3_FRAME_SETTINGS, "SETTINGS is the first frame");

    /* It must read back as our own settings -- the codec is symmetric, and this
     * is the cheapest guard against advertising something we do not mean. */
    uint64_t ftype = 0, flen = 0;
    size_t off = 1;
    off += varint_read(pre + off, plen - off, &ftype);
    off += varint_read(pre + off, plen - off, &flen);

    h3settings_t back;
    h3settings_defaults(&back);
    TEST_ASSERT(h3settings_decode(pre + off, (size_t)flen, &back) == H3SETTINGS_OK, "decodes");
    TEST_ASSERT(back.max_field_section_size == 65536, "field section size");
    TEST_ASSERT(back.qpack_max_table_capacity == 0, "no dynamic table in lite");
    TEST_ASSERT(back.qpack_blocked_streams == 0, "no blocked streams in lite");
    TEST_ASSERT(back.enable_connect_protocol == 1, "extended CONNECT advertised");
    h3session_free(s);

    TEST_CASE("the peer's SETTINGS are recorded");
    s = h3session_create(65536, 0);
    h3uni_recv_t* uni = h3uni_recv_create(2);

    uint8_t settings[32];
    size_t sp = 0;
    sp += varint_write(settings + sp, sizeof settings - sp, H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
    sp += varint_write(settings + sp, sizeof settings - sp, 4096);

    uint8_t buf[64];
    const size_t n = control_bytes(buf, sizeof buf, H3_FRAME_SETTINGS, settings, sp);
    TEST_ASSERT(feed(s, uni, buf, n, 0).action == H3SESSION_OK, "accepted");
    TEST_ASSERT(s->peer_settings_seen, "seen");
    TEST_ASSERT(s->peer_settings.max_field_section_size == 4096, "value");
    TEST_ASSERT(s->ctrl_recv_id == 2, "control stream id recorded");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("a control stream that opens with any other frame is MISSING_SETTINGS");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(2);
    uint8_t goaway_payload[1] = { 0x00 };
    const size_t gn = control_bytes(buf, sizeof buf, H3_FRAME_GOAWAY, goaway_payload, 1);
    h3session_verdict_t v = feed(s, uni, buf, gn, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR, "connection error");
    TEST_ASSERT(v.error == H3_MISSING_SETTINGS, "H3_MISSING_SETTINGS");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("a second SETTINGS is FRAME_UNEXPECTED");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(2);
    const size_t n1 = control_bytes(buf, sizeof buf, H3_FRAME_SETTINGS, NULL, 0);
    TEST_ASSERT(feed(s, uni, buf, n1, 0).action == H3SESSION_OK, "first");
    uint8_t again[16];
    const size_t n2 = h3frame_write(again, sizeof again, H3_FRAME_SETTINGS, NULL, 0);
    v = feed(s, uni, again, n2, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_FRAME_UNEXPECTED, "second");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("a duplicated setting identifier is SETTINGS_ERROR");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(2);
    sp = 0;
    sp += varint_write(settings + sp, sizeof settings - sp, H3_SETTINGS_QPACK_BLOCKED_STREAMS);
    sp += varint_write(settings + sp, sizeof settings - sp, 0);
    sp += varint_write(settings + sp, sizeof settings - sp, H3_SETTINGS_QPACK_BLOCKED_STREAMS);
    sp += varint_write(settings + sp, sizeof settings - sp, 0);
    const size_t dn = control_bytes(buf, sizeof buf, H3_FRAME_SETTINGS, settings, sp);
    v = feed(s, uni, buf, dn, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_SETTINGS_ERROR, "duplicate");
    h3uni_recv_free(uni);
    h3session_free(s);
}

TEST(test_h3session_uni_routing) {
    TEST_SUITE("h3session");

    TEST_CASE("the stream type may be split across feeds");
    /* Type 0x21 is a grease value encoded as two bytes (0x40 0x21), so cutting
     * it in half is the case a one-byte type could never exercise. */
    h3session_t* s = h3session_create(65536, 0);
    h3uni_recv_t* uni = h3uni_recv_create(6);
    const uint8_t half1[] = { 0x40 };
    const uint8_t half2[] = { 0x21 };
    TEST_ASSERT(feed(s, uni, half1, 1, 0).action == H3SESSION_OK, "half a varint");
    TEST_ASSERT(!uni->typed, "not typed yet");
    TEST_ASSERT(feed(s, uni, half2, 1, 0).action == H3SESSION_OK, "grease ignored");
    TEST_ASSERT(uni->typed && uni->type == 0x21, "type assembled");
    TEST_ASSERT(uni->action == H3UNI_IGNORE, "grease is ignored, not stopped");
    /* Content on a grease stream is swallowed, never parsed. */
    const uint8_t junk[] = { 0xff, 0xff, 0xff };
    TEST_ASSERT(feed(s, uni, junk, sizeof junk, 0).action == H3SESSION_OK, "content dropped");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("an unknown stream type is STOP_SENDING, not a connection error");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(6);
    const uint8_t unknown[] = { 0x09 };
    h3session_verdict_t v = feed(s, uni, unknown, 1, 0);
    TEST_ASSERT(v.action == H3SESSION_STOP_SENDING, "stop sending");
    TEST_ASSERT(v.error == H3_STREAM_CREATION_ERROR, "H3_STREAM_CREATION_ERROR");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("a second control stream is a stream-creation error");
    s = h3session_create(65536, 0);
    h3uni_recv_t* a = h3uni_recv_create(2);
    h3uni_recv_t* b = h3uni_recv_create(6);
    const uint8_t ctrl[] = { 0x00 };
    TEST_ASSERT(feed(s, a, ctrl, 1, 0).action == H3SESSION_OK, "first control stream");
    v = feed(s, b, ctrl, 1, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR, "second is fatal");
    TEST_ASSERT(v.error == H3_STREAM_CREATION_ERROR, "H3_STREAM_CREATION_ERROR");
    h3uni_recv_free(a);
    h3uni_recv_free(b);
    h3session_free(s);

    TEST_CASE("a push stream from a client is illegal on sight");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(6);
    const uint8_t push[] = { 0x01 };
    v = feed(s, uni, push, 1, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_STREAM_CREATION_ERROR, "push");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("closing a critical stream ends the connection");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(2);
    TEST_ASSERT(feed(s, uni, ctrl, 1, 0).action == H3SESSION_OK, "control opened");
    v = h3session_uni_closed(s, uni);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR, "fatal");
    TEST_ASSERT(v.error == H3_CLOSED_CRITICAL_STREAM, "H3_CLOSED_CRITICAL_STREAM");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("a stream that ended before its type arrived is harmless");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(6);
    TEST_ASSERT(feed(s, uni, NULL, 0, 1).action == H3SESSION_OK, "empty FIN");
    h3uni_recv_free(uni);
    h3session_free(s);
}

TEST(test_h3session_control_frames) {
    TEST_SUITE("h3session");

    uint8_t buf[64];
    uint8_t frame[32];

    /* Every case starts from a control stream that has already sent SETTINGS. */
#define OPEN(sess, stream)                                                       \
    do {                                                                         \
        (sess) = h3session_create(65536, 0);                                      \
        (stream) = h3uni_recv_create(2);                                          \
        const size_t __n = control_bytes(buf, sizeof buf, H3_FRAME_SETTINGS, NULL, 0); \
        TEST_ASSERT(feed((sess), (stream), buf, __n, 0).action == H3SESSION_OK,   \
                    "settings first");                                            \
    } while (0)

    h3session_t* s = NULL;
    h3uni_recv_t* uni = NULL;
    h3session_verdict_t v;

    TEST_CASE("a request frame on the control stream is FRAME_UNEXPECTED");
    OPEN(s, uni);
    size_t n = h3frame_write(frame, sizeof frame, H3_FRAME_HEADERS, (const uint8_t*)"\x00\x00", 2);
    v = feed(s, uni, frame, n, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_FRAME_UNEXPECTED, "HEADERS");
    h3uni_recv_free(uni); h3session_free(s);

    OPEN(s, uni);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_DATA, (const uint8_t*)"x", 1);
    v = feed(s, uni, frame, n, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_FRAME_UNEXPECTED, "DATA");
    h3uni_recv_free(uni); h3session_free(s);

    TEST_CASE("an HTTP/2 codepoint on the control stream is FRAME_UNEXPECTED");
    OPEN(s, uni);
    const uint8_t h2_window_update[] = { 0x08, 0x04, 0, 0, 0, 0 };
    v = feed(s, uni, h2_window_update, sizeof h2_window_update, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_FRAME_UNEXPECTED, "0x08");
    h3uni_recv_free(uni); h3session_free(s);

    TEST_CASE("an unknown frame type on the control stream is skipped");
    OPEN(s, uni);
    n = h3frame_write(frame, sizeof frame, 0x21 /* grease */, (const uint8_t*)"junk", 4);
    TEST_ASSERT(feed(s, uni, frame, n, 0).action == H3SESSION_OK, "grease skipped");
    h3uni_recv_free(uni); h3session_free(s);

    TEST_CASE("MAX_PUSH_ID may rise but never fall");
    OPEN(s, uni);
    uint8_t id[8];
    size_t idn = varint_write(id, sizeof id, 10);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_MAX_PUSH_ID, id, idn);
    TEST_ASSERT(feed(s, uni, frame, n, 0).action == H3SESSION_OK, "10");
    TEST_ASSERT(s->max_push_id == 10, "recorded");

    idn = varint_write(id, sizeof id, 20);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_MAX_PUSH_ID, id, idn);
    TEST_ASSERT(feed(s, uni, frame, n, 0).action == H3SESSION_OK, "20 is a rise");

    idn = varint_write(id, sizeof id, 5);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_MAX_PUSH_ID, id, idn);
    v = feed(s, uni, frame, n, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_ID_ERROR, "5 is a fall");
    h3uni_recv_free(uni); h3session_free(s);

    TEST_CASE("CANCEL_PUSH is an ID error -- this server never promises a push");
    OPEN(s, uni);
    idn = varint_write(id, sizeof id, 0);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_CANCEL_PUSH, id, idn);
    v = feed(s, uni, frame, n, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_ID_ERROR, "H3_ID_ERROR");
    h3uni_recv_free(uni); h3session_free(s);

    TEST_CASE("a client GOAWAY is recorded and may only shrink");
    OPEN(s, uni);
    idn = varint_write(id, sizeof id, 8);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_GOAWAY, id, idn);
    TEST_ASSERT(feed(s, uni, frame, n, 0).action == H3SESSION_OK, "8");
    TEST_ASSERT(s->peer_goaway_seen && s->peer_goaway_id == 8, "recorded");

    idn = varint_write(id, sizeof id, 4);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_GOAWAY, id, idn);
    TEST_ASSERT(feed(s, uni, frame, n, 0).action == H3SESSION_OK, "4 shrinks");

    idn = varint_write(id, sizeof id, 12);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_GOAWAY, id, idn);
    v = feed(s, uni, frame, n, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_ID_ERROR, "12 grows");
    h3uni_recv_free(uni); h3session_free(s);

    TEST_CASE("a GOAWAY payload that is not exactly one varint is a frame error");
    OPEN(s, uni);
    const uint8_t two_varints[] = { 0x01, 0x02 };
    n = h3frame_write(frame, sizeof frame, H3_FRAME_GOAWAY, two_varints, 2);
    v = feed(s, uni, frame, n, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == H3_FRAME_ERROR, "trailing bytes");
    h3uni_recv_free(uni); h3session_free(s);

    TEST_CASE("a control frame arriving one byte at a time is still one frame");
    OPEN(s, uni);
    idn = varint_write(id, sizeof id, 7);
    n = h3frame_write(frame, sizeof frame, H3_FRAME_MAX_PUSH_ID, id, idn);
    for (size_t i = 0; i < n; i++)
        TEST_ASSERT(feed(s, uni, frame + i, 1, 0).action == H3SESSION_OK, "byte at a time");
    TEST_ASSERT(s->max_push_id == 7, "assembled");
    h3uni_recv_free(uni); h3session_free(s);

#undef OPEN
}

TEST(test_h3session_qpack_streams) {
    TEST_SUITE("h3session");

    TEST_CASE("Set Dynamic Table Capacity 0 is the one legal encoder instruction");
    h3session_t* s = h3session_create(65536, 0);
    h3uni_recv_t* uni = h3uni_recv_create(6);
    const uint8_t enc_stream[] = { 0x02, 0x20 };   /* type 0x02, then capacity 0 */
    TEST_ASSERT(feed(s, uni, enc_stream, sizeof enc_stream, 0).action == H3SESSION_OK,
                "capacity 0 accepted");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("an insert into a table we said we do not have is an encoder-stream error");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(6);
    /* 0xc0 = Insert With Name Reference, static index 0. */
    const uint8_t insert[] = { 0x02, 0xc0 };
    h3session_verdict_t v = feed(s, uni, insert, sizeof insert, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR, "fatal");
    TEST_ASSERT(v.error == QPACK_ENCODER_STREAM_ERROR, "QPACK_ENCODER_STREAM_ERROR");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("a non-zero capacity is refused too");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(6);
    const uint8_t cap1[] = { 0x02, 0x21 };   /* Set Dynamic Table Capacity 1 */
    v = feed(s, uni, cap1, sizeof cap1, 0);
    TEST_ASSERT(v.action == H3SESSION_CONN_ERROR && v.error == QPACK_ENCODER_STREAM_ERROR,
                "capacity 1 > 0");
    h3uni_recv_free(uni);
    h3session_free(s);

    TEST_CASE("the peer's decoder stream is drained, not parsed");
    s = h3session_create(65536, 0);
    uni = h3uni_recv_create(10);
    const uint8_t dec_stream[] = { 0x03, 0x80, 0x40, 0x00 };
    TEST_ASSERT(feed(s, uni, dec_stream, sizeof dec_stream, 0).action == H3SESSION_OK,
                "acks ignored in lite");
    h3uni_recv_free(uni);
    h3session_free(s);
}

TEST(test_h3session_goaway) {
    TEST_SUITE("h3session");

    TEST_CASE("GOAWAY names the first stream we will not serve");
    h3session_t* s = h3session_create(65536, 0);
    TEST_ASSERT(h3session_accepts_request(s, 400), "everything accepted before GOAWAY");

    uint8_t buf[32];
    const size_t n = h3session_goaway_encode(s, buf, sizeof buf, 12);
    TEST_ASSERT(n > 0, "encoded");
    TEST_ASSERT(buf[0] == H3_FRAME_GOAWAY, "GOAWAY");
    TEST_ASSERT(s->goaway_sent && s->goaway_id == 12, "recorded");

    TEST_ASSERT(h3session_accepts_request(s, 8), "8 is below the id");
    TEST_ASSERT(!h3session_accepts_request(s, 12), "12 itself is not served");
    TEST_ASSERT(!h3session_accepts_request(s, 16), "nor anything above");

    TEST_CASE("a second GOAWAY may only shrink");
    TEST_ASSERT(h3session_goaway_encode(s, buf, sizeof buf, 8) > 0, "8 shrinks");
    TEST_ASSERT(s->goaway_id == 8, "updated");
    TEST_ASSERT(h3session_goaway_encode(s, buf, sizeof buf, 20) == 0, "20 refused");
    TEST_ASSERT(s->goaway_id == 8, "unchanged");

    h3session_free(s);
}

#include "framework.h"
#include "h2session.h"
#include "httprequest.h"
#include "appconfig.h"
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

/* Drive real DATA frames through a session without dispatching a handler. */
static h2session_t* body_session(connection_t* connection) {
    h2session_t* s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->connection = connection;
    s->decoder = hpack_decoder_create(4096);
    s->encoder = hpack_encoder_create(4096);
    s->publish_queue = cqueue_create();
    s->read_cap = 16384;
    s->read_buf = malloc(s->read_cap);
    s->peer_settings_seen = 1;
    s->peer_initial_window = H2_DEFAULT_WINDOW;
    s->peer_max_frame_size = H2_MAX_FRAME_SIZE_DEFAULT;
    /* Enough initial receive credit for the storage test without a send loop. */
    s->stream_recv_learned = 2 * BODY_STORE_FILE_THRESHOLD;
    s->recv.size = s->recv.avail = s->stream_recv_learned;
    s->abort_tokens = s->ctrl_tokens = 200000;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    s->abort_epoch_ms = s->ctrl_epoch_ms = s->last_activity_ms =
        (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    h2frame_parser_init(&s->frame, 0, H2_MAX_FRAME_SIZE_DEFAULT);
    if (!s->decoder || !s->encoder || !s->publish_queue || !s->read_buf) {
        h2_session_free(s);
        return NULL;
    }
    return s;
}

TEST(test_httpbody_h2_fragmented_storage) {
    TEST_SUITE("HTTP/2 body storage");
    for (int known = 0; known < 2; ++known) {
        connection_t connection = {.fd = -1};
        h2session_t* session = body_session(&connection);
        TEST_REQUIRE_NOT_NULL(session, "session");
        h2stream_t* stream = h2stream_create(session, 1);
        h2stream_t* other = h2stream_create(session, 3);
        TEST_REQUIRE(stream && other, "parallel streams");
        session->last_stream_id = 3;
        stream->recv.avail = other->recv.avail = session->stream_recv_learned;
        stream->headers_done = other->headers_done = 1;
        stream->request->method = other->request->method = ROUTE_POST;
        if (known) stream->content_length = BODY_STORE_FILE_THRESHOLD + 1;
        uint8_t payload[4096], wire[4105];
        memset(payload, 'x', sizeof(payload));
        size_t sent = 0;
        while (sent < BODY_STORE_FILE_THRESHOLD + 1) {
            size_t count = BODY_STORE_FILE_THRESHOLD + 1 - sent;
            if (count > sizeof(payload)) count = sizeof(payload);
            /* End a DATA frame one byte below the message threshold. */
            if (sent < BODY_STORE_FILE_THRESHOLD - 1 && sent + count >= BODY_STORE_FILE_THRESHOLD - 1)
                count = BODY_STORE_FILE_THRESHOLD - 1 - sent;
            size_t n = h2frame_encode(wire, sizeof(wire), H2_FRAME_DATA, 0, 1, payload, count);
            TEST_ASSERT(h2_session_feed(session, wire, n), "DATA accepted");
            sent += count;
            TEST_REQUIRE(h2stream_find(session, 1) == stream, "stream remains open");
            TEST_ASSERT_EQUAL(sent, stream->req_body_len, "DATA counted");
            if (!known && sent == BODY_STORE_FILE_THRESHOLD - 1)
                TEST_ASSERT_EQUAL(BODY_STORE_MEMORY, stream->request->payload_.incoming.state, "unknown length stays memory below threshold");
        }
        TEST_ASSERT_EQUAL(BODY_STORE_FILE, stream->request->payload_.incoming.state, "sum of DATA selects file");
        char* copy = stream->request->get_payload(stream->request);
        TEST_ASSERT_NOT_NULL(copy, "large body readable");
        if (copy) {
            TEST_ASSERT_EQUAL('x', copy[0], "first byte");
            TEST_ASSERT_EQUAL('x', copy[BODY_STORE_FILE_THRESHOLD], "last byte");
        }
        free(copy);
        size_t n = h2frame_encode(wire, sizeof(wire), H2_FRAME_DATA, 0, 3, (const uint8_t*)"small", 5);
        TEST_ASSERT(h2_session_feed(session, wire, n), "parallel small body");
        TEST_ASSERT_EQUAL(BODY_STORE_MEMORY, other->request->payload_.incoming.state, "parallel stream owns separate memory");
        int fd = stream->request->payload_.incoming.fd;
        char* path = strdup(stream->request->payload_.incoming.path);
        const uint8_t cancel[] = {0, 0, 0, 8};
        n = h2frame_encode(wire, sizeof(wire), H2_FRAME_RST_STREAM, 0, 1, cancel, sizeof(cancel));
        TEST_ASSERT(h2_session_feed(session, wire, n), "stream cancellation");
        TEST_ASSERT_NULL(h2stream_find(session, 1), "cancelled stream removed");
        TEST_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD), "cancellation closes file");
        if (path) TEST_ASSERT_EQUAL(-1, access(path, F_OK), "cancellation removes file");
        free(path);
        copy = other->request->get_payload(other->request);
        TEST_ASSERT_NOT_NULL(copy, "other stream survives cancellation");
        if (copy) TEST_ASSERT_STR_EQUAL("small", copy, "other stream bytes");
        free(copy);
        h2_session_free(session);
    }
}

#include "framework.h"
#include "h2session.h"
#include "connection_s.h"

#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* The wire parser and stream table are real; only the event loop is absent. */
static h2session_t* h2_test_session_create(connection_t* connection) {
    h2session_t* s = calloc(1, sizeof(*s));
    if (s == NULL) return NULL;
    s->connection = connection;
    s->decoder = hpack_decoder_create(4096);
    s->encoder = hpack_encoder_create(4096);
    s->publish_queue = cqueue_create();
    s->read_cap = 16384;
    s->read_buf = malloc(s->read_cap);
    s->peer_settings_seen = 1;
    s->peer_initial_window = H2_DEFAULT_WINDOW;
    s->peer_max_frame_size = H2_MAX_FRAME_SIZE_DEFAULT;
    s->stream_recv_learned = H2_DEFAULT_WINDOW;
    s->recv.size = s->recv.avail = H2_DEFAULT_WINDOW;
    s->abort_tokens = s->ctrl_tokens = 200000;
    s->abort_epoch_ms = s->ctrl_epoch_ms = s->last_activity_ms = now_ms();
    h2frame_parser_init(&s->frame, 0, H2_MAX_FRAME_SIZE_DEFAULT);
    if (!s->decoder || !s->encoder || !s->publish_queue || !s->read_buf) {
        h2_session_free(s);
        return NULL;
    }
    return s;
}

static int feed_frame(h2session_t* s, uint8_t type, uint8_t flags, uint32_t id,
                       const uint8_t* payload, size_t len) {
    uint8_t wire[128];
    const size_t n = h2frame_encode(wire, sizeof wire, type, flags, id, payload, len);
    return n != 0 && h2_session_feed(s, wire, n);
}

TEST(test_h2session_rejected_continuation) {
    TEST_SUITE("h2session");
    TEST_CASE("fragmented rejected headers preserve the connection's HPACK table");
    for (int reason = 0; reason < 3; reason++) {
        connection_t connection = {.fd = -1};
        h2session_t* s = h2_test_session_create(&connection);
        TEST_REQUIRE(s != NULL, "session created");
        uint32_t id = 1, error = 1;
        if (reason == 0) {
            h2stream_t* stream = h2stream_create(s, id);
            TEST_REQUIRE(stream != NULL, "existing stream created");
            stream->state = H2_STREAM_HALF_CLOSED_REMOTE;
            s->last_stream_id = id;
            error = 5; /* STREAM_CLOSED */
        } else if (reason == 1) {
            for (id = 1; id < 201; id += 2)
                TEST_REQUIRE(h2stream_create(s, id) != NULL, "concurrent stream created");
            s->last_stream_id = 199;
            error = 7; /* REFUSED_STREAM */
        }
        /* An incremental-indexing literal, split in the middle of its name. */
        const uint8_t block[] = {0x40, 6, 'x', '-', 't', 'e', 's', 't', 5,
                                  'v', 'a', 'l', 'u', 'e'};
        uint8_t first[8] = {0};
        size_t prefix = 0;
        uint8_t flags = 0;
        if (reason == 2) {
            first[3] = (uint8_t)id; /* PRIORITY dependency on self */
            prefix = 5;
            flags = H2_FLAG_PRIORITY;
        }
        memcpy(first + prefix, block, 3);
        TEST_ASSERT(feed_frame(s, H2_FRAME_HEADERS, flags, id, first, prefix + 3),
                    "first fragment accepted");
        TEST_ASSERT(s->cont_active && s->out_len == 0, "reset waits for END_HEADERS");
        TEST_ASSERT(feed_frame(s, H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, id,
                               block + 3, sizeof block - 3), "continuation accepted");
        TEST_ASSERT(!s->cont_active && s->decoder->table.count == 1,
                    "entire rejected block decoded");
        TEST_ASSERT(s->out_len == 13 && s->out[3] == H2_FRAME_RST_STREAM &&
                    s->out[12] == error, "only the rejected stream is reset");
        /* The following block uses the inserted dynamic entry (index 62). */
        const uint32_t next = id + 2;
        const uint8_t indexed[] = {0, 0, (uint8_t)(next >> 8), (uint8_t)next, 0, 0xbe};
        TEST_ASSERT(feed_frame(s, H2_FRAME_HEADERS, H2_FLAG_PRIORITY | H2_FLAG_END_HEADERS,
                               next, indexed, sizeof indexed), "later dynamic reference decodes");
        h2_session_free(s);
    }
}

TEST(test_h2session_upload_timeout) {
    TEST_SUITE("h2session");
    TEST_CASE("connection activity cannot keep an abandoned upload alive");
    int fd[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0,
                 "local transport created");
    connection_server_ctx_t ctx = {0};
    atomic_init(&ctx.locked, 0);
    connection_t connection = {.fd = fd[0], .ctx = &ctx};
    h2session_t* s = h2_test_session_create(&connection);
    TEST_REQUIRE(s != NULL, "session created");
    ctx.parser = s;
    ctx.is_http2 = 1;
    h2stream_t* stalled = h2stream_create(s, 1);
    h2stream_t* active = h2stream_create(s, 3);
    h2stream_t* handler = h2stream_create(s, 5);
    TEST_REQUIRE(stalled && active && handler, "streams created");
    stalled->request_progress_ms = now_ms() - 121000;
    active->request_progress_ms = now_ms();
    handler->request_progress_ms = stalled->request_progress_ms;
    handler->state = H2_STREAM_HALF_CLOSED_REMOTE;
    s->last_stream_id = 5;
    s->last_activity_ms = now_ms(); /* e.g. PING / traffic on stream 3 */
    h2_server_tick(&connection, 0);
    TEST_ASSERT(h2stream_find(s, 1) == NULL, "stalled upload released");
    TEST_ASSERT(h2stream_find(s, 3) == active && h2stream_find(s, 5) == handler,
                "active upload and completed request survive");
    uint8_t wire[64];
    const ssize_t n = recv(fd[1], wire, sizeof wire, 0);
    TEST_ASSERT(n == 13 && wire[3] == H2_FRAME_RST_STREAM && wire[8] == 1 && wire[12] == 8,
                "RST_STREAM(CANCEL) sent for the abandoned upload");
    h2_session_free(s);
    close(fd[0]);
    close(fd[1]);
}

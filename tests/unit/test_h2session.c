#include "framework.h"
#include "h2session.h"
#include "connection_s.h"
#include "domain.h"
#include "h2ws.h"
#include "multiplexing.h"

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
    /* As h2_stream_recv_init leaves them without a vhost: the default policy. */
    timeout_policy_defaults(&stalled->timeout_policy);
    active->timeout_policy = handler->timeout_policy = stalled->timeout_policy;
    stalled->request_progress_ms = now_ms() - stalled->timeout_policy.request_body_idle_timeout_ms - 1000;
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

static uint64_t timeout_test_ms;
static uint64_t timeout_test_clock(void) { return timeout_test_ms; }

TEST(test_h2session_late_partial_frame) {
    TEST_SUITE("h2session");
    connection_server_ctx_t ctx = {0};
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    server.timeouts.request_header_timeout_ms = 10;
    ctx.server = &server;
    connection_t connection = { .fd = -1, .ctx = &ctx };
    h2session_t* s = h2_test_session_create(&connection);
    TEST_REQUIRE(s != NULL, "session allocated");
    timeout_test_ms = 100000;
    timeout_set_clock(timeout_test_clock);
    uint8_t wire[32];
    uint8_t payload[8] = {0};
    size_t n = h2frame_encode(wire, sizeof wire, H2_FRAME_PING, 0, 0, payload, sizeof payload);
    TEST_ASSERT(n == 17 && h2_session_feed(s, wire, 4), "partial frame starts deadline");
    timeout_test_ms += 10;
    TEST_ASSERT(!h2_session_feed(s, wire + 4, n - 4), "late completion rejected before timer tick");
    TEST_ASSERT(s->header_timeout_reported, "expiry recorded");
    timeout_set_clock(NULL);
    h2_session_free(s);
}

TEST(test_h2session_configured_timeout_isolation) {
    TEST_SUITE("h2session");
    int fd[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "local socket pair");
    connection_server_ctx_t ctx = {0};
    connection_t connection = { .fd = fd[0], .ctx = &ctx };
    h2session_t* s = h2_test_session_create(&connection);
    TEST_REQUIRE(s != NULL, "session allocated");
    ctx.parser = s; ctx.is_http2 = 1;
    h2stream_t* stalled = h2stream_create(s, 1);
    h2stream_t* active = h2stream_create(s, 3);
    TEST_REQUIRE(stalled && active, "streams allocated");
    timeout_test_ms = 100000;
    timeout_set_clock(timeout_test_clock);
    timeout_policy_defaults(&stalled->timeout_policy);
    stalled->timeout_policy.request_body_idle_timeout_ms = 10;
    active->timeout_policy = stalled->timeout_policy;
    stalled->body_started_ms = stalled->request_progress_ms = timeout_test_ms;
    active->body_started_ms = active->request_progress_ms = timeout_test_ms + 5;
    s->last_activity_ms = timeout_test_ms;
    timeout_test_ms += 10;
    h2_server_tick(&connection, 0);
    TEST_ASSERT(h2stream_find(s, 1) == NULL && h2stream_find(s, 3) == active, "only the expired stream is cancelled");
    uint8_t wire[64];
    ssize_t n = recv(fd[1], wire, sizeof wire, 0);
    TEST_ASSERT(n == 13 && wire[3] == H2_FRAME_RST_STREAM && wire[8] == 1 && wire[12] == 8, "RST_STREAM(CANCEL) is emitted");
    timeout_set_clock(NULL);
    h2_session_free(s);
    close(fd[0]); close(fd[1]);
}

TEST(test_h2session_data_header_budget) {
    TEST_SUITE("h2session");
    {
        server_t server = {0};
        timeout_policy_defaults(&server.timeouts);
        server.timeouts.request_header_timeout_ms = 10;
        server.timeouts.request_body_idle_timeout_ms = 1000;
        connection_server_ctx_t ctx = { .server = &server };
        connection_t c = { .fd = -1, .ctx = &ctx };
        h2session_t* s = h2_test_session_create(&c);
        TEST_REQUIRE(s != NULL, "session created");
        timeout_test_ms = 100000;
        timeout_set_clock(timeout_test_clock);
        h2stream_t* stream = h2stream_create(s, 1);
        if (stream) {
            s->last_stream_id = 1;
            stream->timeout_policy = server.timeouts;
            stream->recv.avail = H2_DEFAULT_WINDOW;
            stream->body_started_ms = stream->request_progress_ms = timeout_test_ms;
            const uint8_t body[] = {'a','b','c','d'};
            uint8_t wire[32];
            size_t n = h2frame_encode(wire, sizeof wire, H2_FRAME_DATA, 0, 1, body, sizeof body);
            TEST_ASSERT(h2_session_feed(s, wire, 10), "partial DATA accepted");
            timeout_test_ms += 20;
            TEST_ASSERT(h2_session_feed(s, wire + 10, n - 10), "DATA uses body budget despite header expiry");
            TEST_ASSERT(h2stream_find(s, 1) == stream && !s->header_timeout_reported, "stream alive without header event");
        } else TEST_ASSERT(0, "stream allocated");
        timeout_set_clock(NULL);
        h2_session_free(s);
    }
}

TEST(test_h2session_absolute_header_block) {
    TEST_SUITE("h2session");
    const unsigned elapsed[] = {9, 10, 18};
    for (unsigned boundary = 0; boundary < 3; boundary++) {
        server_t server = {0};
        timeout_policy_defaults(&server.timeouts);
        server.timeouts.request_header_timeout_ms = 10;
        connection_server_ctx_t ctx = { .server = &server };
        connection_t c = { .fd = -1, .ctx = &ctx };
        h2session_t* s = h2_test_session_create(&c);
        TEST_REQUIRE(s != NULL, "session created");
        timeout_test_ms = 100000;
        timeout_set_clock(timeout_test_clock);
        s->abort_epoch_ms = s->ctrl_epoch_ms = timeout_test_ms;
        /* Self-dependent priority rejects this stream after decoding; no dispatch. */
        uint8_t payload[] = {0,0,0,1,0,0x82};
        uint8_t wire[32];
        size_t n = h2frame_encode(wire, sizeof wire, H2_FRAME_HEADERS, H2_FLAG_PRIORITY, 1, payload, sizeof payload);
        TEST_ASSERT(h2_session_feed(s, wire, 10), "HEADERS starts block");
        timeout_test_ms += 9;
        TEST_ASSERT(h2_session_feed(s, wire + 10, n - 10), "HEADERS completes before deadline");
        timeout_test_ms = 100000 + elapsed[boundary];
        const uint8_t rest[] = {0x86,0x84};
        int accepted = feed_frame(s, H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, rest, sizeof rest);
        TEST_ASSERT(accepted == (elapsed[boundary] < 10), "continuation cannot restart absolute budget");
        TEST_ASSERT((s->header_timeout_reported != 0) == (elapsed[boundary] >= 10), "expiry reported exactly at the boundary");
        timeout_set_clock(NULL);
        h2_session_free(s);
    }
}

TEST(test_h2session_partial_data_progress_and_cancel) {
    TEST_SUITE("h2session");
    for (int padded = 0; padded < 2; padded++) {
        connection_server_ctx_t ctx = {0};
        connection_t c = { .fd = -1, .ctx = &ctx };
        h2session_t* s = h2_test_session_create(&c);
        TEST_REQUIRE(s != NULL, "session allocated");
        timeout_test_ms = 100000;
        timeout_set_clock(timeout_test_clock);
        s->abort_epoch_ms = s->ctrl_epoch_ms = timeout_test_ms;
        h2stream_t* stalled = h2stream_create(s, 1);
        h2stream_t* neighbor = h2stream_create(s, 3);
        if (stalled && neighbor) {
            s->last_stream_id = 3;
            timeout_policy_defaults(&stalled->timeout_policy);
            stalled->timeout_policy.request_body_idle_timeout_ms = 10;
            stalled->timeout_policy.request_body_total_timeout_ms = 0;
            stalled->body_started_ms = stalled->request_progress_ms = timeout_test_ms;
            stalled->recv.avail = neighbor->recv.avail = H2_DEFAULT_WINDOW;
            uint8_t payload[] = {2,'a','b','c',0,0};
            uint8_t wire[32];
            size_t n = h2frame_encode(wire, sizeof wire, H2_FRAME_DATA, padded ? H2_FLAG_PADDED : 0,
                                     1, payload, sizeof payload);
            TEST_ASSERT(h2_session_feed(s, wire, 10), "first DATA fragment accepted");
            timeout_test_ms += 9;
            TEST_ASSERT(h2_session_feed(s, wire + 10, 1), "useful progress before idle deadline");
            timeout_test_ms += 9;
            TEST_ASSERT(h2_session_feed(s, wire + 11, 2), "long frame remains live with useful progress");
            if (padded) {
                timeout_test_ms += 9;
                TEST_ASSERT(h2_session_feed(s, wire + 13, 1), "padding read before expiry");
                timeout_test_ms += 1;
                TEST_ASSERT(h2_session_feed(s, wire + 14, n - 14), "expired DATA drained to frame boundary");
                TEST_ASSERT(h2stream_find(s, 1) == NULL, "padding cannot extend body idle");
            } else {
                timeout_test_ms += 10;
                TEST_ASSERT(h2_session_feed(s, wire + 13, n - 13), "late body fragment drained");
                TEST_ASSERT(h2stream_find(s, 1) == NULL, "late payload cannot revive expired body");
            }
            const uint8_t data[] = {'z'};
            TEST_ASSERT(feed_frame(s, H2_FRAME_DATA, 0, 3, data, sizeof data), "neighbor frame accepted after draining");
            TEST_ASSERT(h2stream_find(s, 3) == neighbor && neighbor->req_body_len == 1, "neighbor continues without framing loss");
        } else TEST_ASSERT(0, "streams allocated");
        timeout_set_clock(NULL);
        h2_session_free(s);
    }
}

TEST(test_h2session_header_receive_timing) {
    TEST_SUITE("h2session");
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    server.timeouts.request_header_timeout_ms = 1000;
    server.timeouts.slow_request_threshold_ms = 10;
    char host[] = "localhost";
    domain_t domain = { .is_literal = 1, .template = host, .ascii_template = host, .ascii_length = 9 };
    server.domain = &domain;
    server.port = 8080;
    server.ip = ipaddr_from_v4(0x0100007f);
    cqueue_item_t item = { .data = &server };
    connection_t listening = { .port = 8080, .ip = server.ip };
    listener_t listener = { .servers = { .item = &item, .last_item = &item, .size = 1 }, .connection = &listening };
    connection_server_ctx_t ctx = { .server = &server, .listener = &listener };
    connection_t c = { .fd = -1, .ctx = &ctx, .port = 8080, .ip = server.ip };
    h2session_t* s = h2_test_session_create(&c);
    TEST_REQUIRE(s != NULL, "session allocated");
    timeout_test_ms = 100000;
    timeout_set_clock(timeout_test_clock);
    s->abort_epoch_ms = s->ctrl_epoch_ms = timeout_test_ms;
    /* POST, scheme http, path /, literal authority localhost. */
    const uint8_t block[] = {0x83,0x86,0x84,0x01,9,'l','o','c','a','l','h','o','s','t'};
    uint8_t wire[64];
    size_t n = h2frame_encode(wire, sizeof wire, H2_FRAME_HEADERS, 0, 1, block, sizeof block);
    TEST_ASSERT(h2_session_feed(s, wire, 10), "initial HEADERS fragment");
    timeout_test_ms += 9;
    TEST_ASSERT(h2_session_feed(s, wire + 10, n - 10), "HEADERS ends while block continues");
    timeout_test_ms += 9;
    /* Trigger observation before END_HEADERS, retaining a partial transport header. */
    n = h2frame_encode(wire, sizeof wire, H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, NULL, 0);
    TEST_ASSERT(h2_session_feed(s, wire, 1), "partial CONTINUATION accepted");
    TEST_ASSERT(s->header_slow_reported, "live slow event during headers");
    TEST_ASSERT(h2_session_feed(s, wire + 1, n - 1), "block completes");
    h2stream_t* stream = h2stream_find(s, 1);
    TEST_ASSERT(stream && stream->headers_done, "real request built without dispatch");
    if (stream) {
        TEST_ASSERT(stream->request->headers_done_ms - stream->request->started_ms == 18, "timing includes HEADERS and CONTINUATION");
        TEST_ASSERT(stream->request->slow_reported, "header slow event transferred, so the request does not report it again");
        httprequest_slow_tick(stream->request, &stream->timeout_policy, "h2", timeout_test_ms);
        httprequest_timing_finish(stream->request);
    }
    timeout_test_ms++;
    TEST_ASSERT(feed_frame(s, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 3, block, sizeof block),
                "next request with a single HEADERS block");
    h2stream_t* next = h2stream_find(s, 3);
    TEST_ASSERT(next && next->request->started_ms == timeout_test_ms &&
                next->request->headers_done_ms == timeout_test_ms, "next request has independent header timing");
    if (next) {
        const uint64_t original_start = next->request->started_ms;
        const uint64_t original_headers = next->request->headers_done_ms;
        /* An already answered request still consumes trailers to keep HPACK
         * synchronized, without going through application dispatch. */
        next->rejected = 1;
        timeout_test_ms += 5;
        TEST_ASSERT(feed_frame(s, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 3, NULL, 0),
                    "trailers accepted for an answered request");
        TEST_ASSERT(next->request->started_ms == original_start && next->request->headers_done_ms == original_headers,
                    "trailers do not overwrite initial timing");
    }
    timeout_set_clock(NULL);
    h2_session_free(s);
}

static int trailers_control_mod(connection_t* c, int flags) { (void)c; (void)flags; return 1; }

TEST(test_h2session_trailers_after_body_deadline) {
    TEST_SUITE("h2session");
    TEST_CASE("trailers completing after the body deadline do not dispatch the request");
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    server.timeouts.request_body_idle_timeout_ms = 10;
    char host[] = "localhost";
    domain_t domain = { .is_literal = 1, .template = host, .ascii_template = host, .ascii_length = 9 };
    server.domain = &domain;
    server.port = 8080;
    server.ip = ipaddr_from_v4(0x0100007f);
    cqueue_item_t item = { .data = &server };
    connection_t listening = { .port = 8080, .ip = server.ip };
    /* Lets a wrongly dispatched request be answered instead of crashing. */
    mpxapi_t api = { .control_mod = trailers_control_mod };
    listener_t listener = { .servers = { .item = &item, .last_item = &item, .size = 1 },
                            .connection = &listening, .api = &api };
    connection_server_ctx_t ctx = { .server = &server, .listener = &listener };
    connection_t c = { .fd = -1, .ctx = &ctx, .port = 8080, .ip = server.ip };
    h2session_t* s = h2_test_session_create(&c);
    TEST_REQUIRE(s != NULL, "session allocated");
    timeout_test_ms = 100000;
    timeout_set_clock(timeout_test_clock);
    s->abort_epoch_ms = s->ctrl_epoch_ms = timeout_test_ms;
    /* POST, scheme http, path /, literal authority localhost; body follows. */
    const uint8_t block[] = {0x83,0x86,0x84,0x01,9,'l','o','c','a','l','h','o','s','t'};
    TEST_ASSERT(feed_frame(s, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, block, sizeof block),
                "request headers accepted");
    h2stream_t* stream = h2stream_find(s, 1);
    TEST_REQUIRE(stream && stream->headers_done && stream->state == H2_STREAM_OPEN, "body pending");
    stream->timeout_policy.request_body_idle_timeout_ms = 10;
    /* No timer tick runs between expiry and the trailers' arrival. */
    timeout_test_ms += 11;
    const size_t out_before = s->out_len;
    TEST_ASSERT(feed_frame(s, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, NULL, 0),
                "late trailers handled as a stream error");
    TEST_ASSERT(h2stream_find(s, 1) == NULL, "expired request is not dispatched");
    TEST_ASSERT(s->out_len - out_before == 13 && s->out[out_before + 3] == H2_FRAME_RST_STREAM &&
                s->out[out_before + 12] == 8, "RST_STREAM(CANCEL) is queued");
    timeout_set_clock(NULL);
    h2_session_free(s);
}

TEST(test_h2session_websocket_partial_data_deadlines) {
    TEST_SUITE("h2 websocket partial data");
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    server.timeouts.ws_ping_interval_ms = 0; /* no heartbeat to catch the stall instead */
    server.timeouts.ws_message_idle_timeout_ms = 10;
    server.timeouts.ws_message_total_timeout_ms = 20;
    connection_server_ctx_t ctx = { .server = &server };
    connection_t c = { .fd = -1, .ctx = &ctx };
    h2session_t* s = h2_test_session_create(&c);
    TEST_REQUIRE(s != NULL, "session allocated");
    timeout_test_ms = 100000;
    timeout_set_clock(timeout_test_clock);
    s->abort_epoch_ms = s->ctrl_epoch_ms = timeout_test_ms;
    h2stream_t* stream = h2stream_create(s, 1);
    if (stream) {
        s->last_stream_id = 1;
        stream->recv.avail = H2_DEFAULT_WINDOW;
        stream->ws = h2_ws_tunnel_create(&c, stream, 0, NULL);
    }
    TEST_ASSERT(stream && stream->ws, "tunnel created");
    if (stream && stream->ws) {
        websocketsparser_t* p = stream->ws->parser;
        /* One masked text frame, "hello", carried by one DATA frame that the
         * client trickles in: the tunnel parser sees none of it until the end. */
        uint8_t payload[] = {0x81,0x85,0,0,0,0,'h','e','l','l','o'};
        uint8_t wire[32];
        const size_t n = h2frame_encode(wire, sizeof wire, H2_FRAME_DATA, 0, 1, payload, sizeof payload);
        const uint64_t start = timeout_test_ms;
        TEST_ASSERT(h2_session_feed(s, wire, 10), "DATA header and the first WebSocket byte");
        TEST_ASSERT(p->message_started_ms == start && p->message_progress_ms == start,
                    "message timers start before the DATA frame completes");
        timeout_test_ms += 9;
        TEST_ASSERT(h2_session_feed(s, wire + 10, 1), "progress before the idle deadline");
        TEST_ASSERT(p->message_progress_ms == timeout_test_ms && p->message_started_ms == start,
                    "progress refreshes the idle timer, not the total one");
        const char* idle = websocketsparser_timeout(p, timeout_test_ms + 10, 0);
        TEST_ASSERT(idle && !strcmp(idle, "message_idle"), "a stalled DATA frame hits message idle");
        timeout_test_ms += 9;
        TEST_ASSERT(h2_session_feed(s, wire + 11, 1), "still within both budgets");
        TEST_ASSERT(h2stream_find(s, 1) == stream, "stream alive");
        timeout_test_ms += 2;
        TEST_ASSERT(h2_session_feed(s, wire + 12, 1), "late byte drained, connection kept");
        TEST_ASSERT(h2stream_find(s, 1) == NULL, "steady trickle cannot outrun message total");
        TEST_ASSERT(h2_session_feed(s, wire + 13, n - 13), "rest of the frame discarded at the boundary");
    }
    timeout_set_clock(NULL);
    h2_session_free(s);
}

TEST(test_h2session_websocket_send_idle_ignores_handler_blocked_output) {
    TEST_SUITE("h2 websocket send timeout");
    TEST_CASE("a Ping queued behind an unfinished handler does not run the send clock");
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    server.timeouts.ws_ping_interval_ms = 10;
    server.timeouts.ws_send_idle_timeout_ms = 100;
    server.timeouts.ws_pong_timeout_ms = 3000;
    server.timeouts.ws_application_idle_timeout_ms = 0;
    connection_server_ctx_t ctx = { .server = &server };
    connection_t c = { .fd = -1, .ctx = &ctx };
    h2session_t* s = h2_test_session_create(&c);
    TEST_REQUIRE(s != NULL, "session allocated");
    timeout_test_ms = 100000;
    timeout_set_clock(timeout_test_clock);
    h2stream_t* stream = h2stream_create(s, 1);
    if (stream) stream->ws = h2_ws_tunnel_create(&c, stream, 0, NULL);
    connection_out_slot_t* blocked = calloc(1, sizeof *blocked);
    if (stream && stream->ws && blocked) {
        h2_ws_tunnel_t* tunnel = stream->ws;
        websocketsparser_t* p = tunnel->parser;
        p->timeout_policy = server.timeouts;
        p->heartbeat_ms = timeout_test_ms;
        /* The reserved, still empty slot of a handler that has not returned. */
        cqueue_lock(tunnel->out);
        cqueue_append(tunnel->out, blocked);
        cqueue_unlock(tunnel->out);
        timeout_test_ms += 10;
        TEST_ASSERT(h2_ws_tunnel_tick(tunnel, timeout_test_ms) && p->ping_queued, "Ping queued");
        TEST_ASSERT(!h2_ws_tunnel_has_output(tunnel), "Ping waits behind the handler's slot");
        timeout_test_ms += 1000;
        TEST_ASSERT(h2_ws_tunnel_tick(tunnel, timeout_test_ms), "tunnel survives a long handler");
        TEST_ASSERT(!(p->timeout_reported & timeout_event_bit("send_idle")), "no send_idle while output is blocked");

        /* The handler finishes without a reply: the Ping is now writable. */
        cqueue_lock(tunnel->out);
        cqueue_pop(tunnel->out);
        cqueue_unlock(tunnel->out);
        free(blocked);
        blocked = NULL;
        TEST_ASSERT(h2_ws_tunnel_tick(tunnel, timeout_test_ms), "send clock starts once the head is ready");
        timeout_test_ms += 100;
        TEST_ASSERT(!h2_ws_tunnel_tick(tunnel, timeout_test_ms), "stalled writable output still hits send_idle");
    } else TEST_ASSERT(0, "tunnel and slot allocated");
    free(blocked);
    timeout_set_clock(NULL);
    h2_session_free(s);
}

TEST(test_h2session_websocket_heartbeat_lifecycle) {
    TEST_SUITE("h2 websocket heartbeat");
    int fd[2];
    TEST_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "socket pair");
    server_t server = {0};
    timeout_policy_defaults(&server.timeouts);
    server.timeouts.ws_ping_interval_ms = 10;
    server.timeouts.ws_send_idle_timeout_ms = 100;
    server.timeouts.ws_pong_timeout_ms = 3000;
    connection_server_ctx_t ctx = { .server = &server };
    connection_t c = { .fd = fd[0], .ctx = &ctx };
    h2session_t* s = h2_test_session_create(&c);
    TEST_ASSERT(s != NULL, "session created");
    if (s) {
        timeout_test_ms = 100000;
        timeout_set_clock(timeout_test_clock);
        s->send_window = H2_DEFAULT_WINDOW;
        h2stream_t* stream = h2stream_create(s, 1);
        TEST_ASSERT(stream != NULL, "stream created");
        if (stream) {
            stream->write_credit = H2_DEFAULT_WINDOW;
            stream->ws = h2_ws_tunnel_create(&c, stream, 0, NULL);
            TEST_ASSERT(stream->ws != NULL, "tunnel created");
            if (stream->ws) {
                h2_ws_tunnel_t* t = stream->ws;
                websocketsparser_t* p = t->parser;
                timeout_test_ms += 10;
                TEST_ASSERT(h2_ws_tunnel_tick(t, timeout_test_ms), "heartbeat queued");
                s->send_window = 0;
                TEST_ASSERT(h2_ws_tunnel_write(s, stream) == H2_DATA_WINDOW, "queued Ping waits for flow control");
                TEST_ASSERT(p->ping_queued && !p->ping_sent_ms, "queued Ping has no Pong clock");
                const char* queued_reason = websocketsparser_timeout(p, timeout_test_ms + 100, 1);
                TEST_ASSERT(queued_reason && !strcmp(queued_reason, "send_idle"), "queued Ping bounded by send idle");
                s->send_window = H2_DEFAULT_WINDOW;
                TEST_ASSERT(h2_ws_tunnel_write(s, stream) == H2_DATA_DRAINED, "Ping sent over DATA");
                uint8_t wire[64];
                ssize_t n = recv(fd[1], wire, sizeof wire, 0);
                TEST_ASSERT(n == 19 && wire[3] == H2_FRAME_DATA && wire[9] == 0x89, "one server Ping on wire");
                timeout_test_ms += 100;
                TEST_ASSERT(!websocketsparser_timeout(p, timeout_test_ms, h2_ws_tunnel_has_output(t) || p->ping_queued),
                            "sent Ping waits for Pong budget");
                TEST_ASSERT(h2_ws_tunnel_tick(t, timeout_test_ms) && !h2_ws_tunnel_has_output(t), "no duplicate Ping");
                timeout_test_ms += 2900;
                websocketsparser_pong(p, (char*)&p->ping_sequence, sizeof p->ping_sequence);
                TEST_ASSERT(p->ping_sent_ms != 0, "Pong at deadline cannot revive the probe");
                TEST_ASSERT(h2_ws_tunnel_tick(t, timeout_test_ms), "timeout queues Close");
                stream->write_credit = H2_DEFAULT_WINDOW;
                TEST_ASSERT(h2_ws_tunnel_write(s, stream) == H2_DATA_DRAINED, "Close written");
                n = recv(fd[1], wire, sizeof wire, 0);
                TEST_ASSERT(n >= 13 && wire[9] == 0x88 && wire[11] == 3 && wire[12] == 0xf0, "H2 policy timeout sends Close 1008");
            }
        }
        timeout_set_clock(NULL);
        h2_session_free(s);
    }
    close(fd[0]); close(fd[1]);
}

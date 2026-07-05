/*
 * Unit tests for protocols/websocket/server/websocketsserverhandlers.c
 *
 * Covers the epoll-facing guard handlers (websockets_guard_read/write), the
 * control/data frame dispatch (__handle), the direct and queued response
 * posting paths, websockets_deferred_handler and the worker-side
 * websockets_queue_request_handler. The handlers run end-to-end over a real
 * AF_UNIX socketpair (recv/send paths included); the epoll api is replaced by
 * a stub control_mod so connection_after_read/write can run.
 *
 * The epoll-loop contract (multiplexingepoll.c): a handler returning 0 closes
 * the connection, non-zero keeps it alive.
 *
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - __write dereferenced ctx->response without a NULL check, so a write
 *     event with no staged response (spurious EPOLLOUT) crashed the worker.
 *   - __write treated every send() -1 as fatal: EAGAIN on a peer with a full
 *     socket buffer (a slow reader) closed the connection mid-response.
 *   - __write finished the response after a short write: it only kept going
 *     when writed == buffer_size exactly, so a partial send fell through to
 *     connection_after_write and truncated the frame on the wire.
 *   - __write stored read()'s result in a size_t: a read error became a
 *     SIZE_MAX-sized send() from the connection buffer, and a file truncated
 *     behind the response (read() == 0) spun the event loop forever because
 *     file_.pos never advanced.
 *   - __handle leaked the request when get_resource failed (unknown route):
 *     ownership never left the parser, and the parser drops its pointer on
 *     reset without freeing - one leaked request per message to a bad route.
 *   - websockets_deferred_handler freed the queue item on a
 *     connection_queue_append failure while the item was still linked in
 *     ctx->queue: the worker thread or __ctx_free then freed it again.
 *   - __queue_data_response_free did not free the staged response, so
 *     responses queued behind an in-flight one leaked whenever the item was
 *     discarded without running (connection closed with a non-empty queue).
 *   - protocol errors (bad frame, oversized payload) were answered with a
 *     TEXT frame and the connection kept reading the desynced stream; per
 *     RFC 6455 §7.1.7 they now fail the connection with CLOSE 1002/1009.
 *   - a handler that never called send_* had its connection closed by
 *     __write (body.data == NULL was treated as an error); silent handlers
 *     now complete the write phase as a no-op.
 */

#include "framework.h"
#include "connection_s.h"
#include "connection_queue.h"
#include "cqueue.h"
#include "middleware.h"
#include "multiplexing.h"
#include "ratelimiter.h"
#include "websocketsparser.h"
#include "websocketsprotocoldefault.h"
#include "websocketsprotocolresource.h"
#include "websocketsserverhandlers.h"
#include "websocket/wscontext.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define WSH_BUFFER_SIZE 16384

/* -------------------------------------------------------------------------- */
/* Epoll api stub                                                             */
/* -------------------------------------------------------------------------- */

static int stub_control_mod_result = 1;
static int stub_control_mod_calls = 0;
static int stub_control_mod_last_events = 0;

static int stub_control_mod(connection_t* connection, int events) {
    (void)connection;
    stub_control_mod_calls++;
    stub_control_mod_last_events = events;
    return stub_control_mod_result;
}

/* -------------------------------------------------------------------------- */
/* Harness                                                                    */
/* -------------------------------------------------------------------------- */

typedef struct {
    connection_t* conn;
    connection_server_ctx_t ctx;
    server_t server;
    listener_t listener;
    mpxapi_t api;

    char* buffer;
    int conn_fd;  /* conn->fd side of the socketpair */
    int peer_fd;  /* the other end, driven by the test */
} wsh_harness_t;

static void safe_close(int* fd) {
    if (fd != NULL && *fd != -1) {
        close(*fd);
        *fd = -1;
    }
}

/* Mimics the private __ctx_reset in connection_s.c: connection_after_write
 * resets the connection through this callback on the keepalive path. */
static void wsh_ctx_reset(void* arg) {
    connection_server_ctx_t* ctx = arg;

    ctx->need_write = 0;

    request_t* request = ctx->request;
    if (request != NULL) {
        request->free(request);
        ctx->request = NULL;
    }

    response_t* response = ctx->response;
    if (response != NULL) {
        response->free(response);
        ctx->response = NULL;
    }
}

static void wsh_harness_free(wsh_harness_t* h);

static int wsh_harness_init_sized(wsh_harness_t* h, size_t buffer_size) {
    memset(h, 0, sizeof *h);
    h->conn_fd = -1;
    h->peer_fd = -1;

    /* The deferred path appends the connection to the global worker queue;
     * the runner has no worker threads, entries just accumulate unpopped. */
    if (!connection_queue_init())
        return 0;

    stub_control_mod_result = 1;
    stub_control_mod_calls = 0;
    stub_control_mod_last_events = 0;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return 0;

    /* Non-blocking on both ends: __read must see EAGAIN instead of blocking
     * the runner, and __write must be able to fill the socket buffer. */
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    fcntl(fds[1], F_SETFL, O_NONBLOCK);

    h->buffer = malloc(buffer_size);
    if (h->buffer == NULL) { safe_close(&fds[0]); safe_close(&fds[1]); return 0; }

    h->conn = calloc(1, sizeof(connection_t));
    if (h->conn == NULL) { free(h->buffer); h->buffer = NULL; safe_close(&fds[0]); safe_close(&fds[1]); return 0; }

    h->conn_fd = fds[0];
    h->peer_fd = fds[1];

    h->api.control_mod = stub_control_mod;
    h->listener.api = &h->api;

    h->ctx.base.reset = wsh_ctx_reset;
    h->ctx.listener = &h->listener;
    h->ctx.server = &h->server;
    h->ctx.queue = cqueue_create();
    h->ctx.broadcast_queue = cqueue_create();
    atomic_store(&h->ctx.ref_count, 1);
    atomic_store(&h->ctx.broadcast_ref_count, 1);
    atomic_store(&h->ctx.destroyed, 0);
    atomic_store(&h->ctx.locked, 0);

    /* ssl == NULL routes connection_data_{read,write} to recv()/send(). */
    h->conn->fd = h->conn_fd;
    h->conn->buffer = h->buffer;
    h->conn->buffer_size = buffer_size;
    h->conn->ctx = &h->ctx;
    h->conn->keepalive = 1;

    if (h->ctx.queue == NULL || h->ctx.broadcast_queue == NULL) {
        wsh_harness_free(h);
        return 0;
    }

    return 1;
}

static int wsh_harness_init(wsh_harness_t* h) {
    return wsh_harness_init_sized(h, WSH_BUFFER_SIZE);
}

/* Attach a parser so websockets_guard_read can run. */
static int wsh_attach_parser(wsh_harness_t* h, websockets_protocol_t*(*protocol_create)(void)) {
    websocketsparser_t* parser = websocketsparser_create(h->conn, protocol_create);
    if (parser == NULL) return 0;

    h->ctx.parser = parser;
    return 1;
}

static void wsh_queue_item_free_cb(void* data) {
    if (data == NULL) return;
    connection_queue_item_t* item = data;
    item->free(item);
}

static void wsh_harness_free(wsh_harness_t* h) {
    if (h->ctx.parser != NULL) {
        requestparser_t* parser = h->ctx.parser;
        parser->free(parser);
        h->ctx.parser = NULL;
    }

    wsh_ctx_reset(&h->ctx); /* releases staged request/response */

    if (h->ctx.queue != NULL) cqueue_freecb(h->ctx.queue, wsh_queue_item_free_cb);
    if (h->ctx.broadcast_queue != NULL) cqueue_freecb(h->ctx.broadcast_queue, wsh_queue_item_free_cb);
    h->ctx.queue = NULL;
    h->ctx.broadcast_queue = NULL;

    safe_close(&h->conn_fd);
    safe_close(&h->peer_fd);

    free(h->buffer);
    h->buffer = NULL;
    free(h->conn);
    h->conn = NULL;
}

/* -------------------------------------------------------------------------- */
/* Frame helpers                                                              */
/* -------------------------------------------------------------------------- */

static const unsigned char WSH_MASK[4] = {0x12, 0x34, 0x56, 0x78};

/* Build a masked client-to-server frame. Returns the wire size. */
static size_t wsh_build_frame(unsigned char* out, int opcode, int fin,
                              const unsigned char* payload, size_t payload_len) {
    size_t pos = 0;
    out[pos++] = (unsigned char)((fin ? 0x80 : 0x00) | (opcode & 0x0F));

    if (payload_len < 126) {
        out[pos++] = (unsigned char)(0x80 | (payload_len & 0x7F));
    } else {
        out[pos++] = 0x80 | 126;
        out[pos++] = (unsigned char)((payload_len >> 8) & 0xFF);
        out[pos++] = (unsigned char)(payload_len & 0xFF);
    }

    memcpy(&out[pos], WSH_MASK, 4);
    pos += 4;

    for (size_t i = 0; i < payload_len; i++)
        out[pos + i] = payload[i] ^ WSH_MASK[i % 4];

    return pos + payload_len;
}

/* Parse the header of a staged (server-to-client, unmasked) frame in
 * body.data; returns the payload offset or -1 on a malformed header. */
static ssize_t wsh_staged_payload(const websocketsresponse_t* response, size_t* out_len) {
    const unsigned char* data = (const unsigned char*)response->body.data;
    if (data == NULL) return -1;
    if (data[1] & 0x80) return -1; /* server frames must not be masked */

    size_t length = data[1] & 0x7F;
    size_t offset = 2;

    if (length == 126) {
        length = ((size_t)data[2] << 8) | data[3];
        offset = 4;
    }
    else if (length == 127) {
        length = 0;
        for (int i = 0; i < 8; i++)
            length = (length << 8) | data[2 + i];
        offset = 10;
    }

    if (out_len != NULL) *out_len = length;
    return (ssize_t)offset;
}

/* Non-blocking drain of everything currently readable from fd. */
static size_t wsh_drain(int fd, unsigned char* out, size_t cap, size_t pos) {
    while (pos < cap) {
        const ssize_t r = recv(fd, out + pos, cap - pos, MSG_DONTWAIT);
        if (r <= 0) break;
        pos += (size_t)r;
    }

    return pos;
}

/* Assert helper: staged response is a text frame with the given payload. */
static int wsh_staged_text_is(const wsh_harness_t* h, const char* expected) {
    const websocketsresponse_t* response = h->ctx.response;
    if (response == NULL) return 0;

    size_t length = 0;
    const ssize_t offset = wsh_staged_payload(response, &length);
    if (offset < 0) return 0;

    if (((unsigned char)response->body.data[0]) != 0x81) return 0;
    if (length != strlen(expected)) return 0;

    return memcmp(response->body.data + offset, expected, length) == 0;
}

/* Assert helper: staged response is a CLOSE frame with the given status code
 * (RFC 6455 §5.5.1: first two payload bytes, network byte order). */
static int wsh_staged_close_is(const wsh_harness_t* h, unsigned short status_code) {
    const websocketsresponse_t* response = h->ctx.response;
    if (response == NULL) return 0;

    size_t length = 0;
    const ssize_t offset = wsh_staged_payload(response, &length);
    if (offset < 0) return 0;

    if (((unsigned char)response->body.data[0]) != 0x88) return 0;
    if (length < 2) return 0;

    const unsigned char* payload = (const unsigned char*)response->body.data + offset;
    return (((unsigned short)payload[0] << 8) | payload[1]) == status_code;
}

/* ==========================================================================
 * websockets_guard_write
 * ========================================================================== */

TEST(test_wsh_write_null_response_closes) {
    TEST_SUITE("websocketsserverhandlers: guard_write");
    /* REGRESSION: ctx->response was dereferenced without a NULL check, so a
     * write event with no staged response crashed instead of closing. */
    TEST_CASE("NULL staged response returns 0 instead of crashing");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    TEST_ASSERT_EQUAL(0, websockets_guard_write(h.conn), "no response closes the connection");

    wsh_harness_free(&h);
}

TEST(test_wsh_write_empty_response_is_noop) {
    TEST_SUITE("websocketsserverhandlers: guard_write");
    /* A handler is allowed not to reply: the write phase completes as a
     * no-op and the connection goes back to reading (it used to be closed). */
    TEST_CASE("a response the handler never filled completes without writing");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    websocketsresponse_t* response = websocketsresponse_create(h.conn);
    TEST_REQUIRE_NOT_NULL_GOTO(response, "response allocation", teardown);
    h.ctx.response = response;

    TEST_ASSERT_EQUAL(1, websockets_guard_write(h.conn), "silent handler keeps the connection");
    TEST_ASSERT_NULL(h.ctx.response, "connection was reset for the next message");
    TEST_ASSERT(stub_control_mod_last_events == (MPXIN | MPXRDHUP), "re-armed for reading");

    unsigned char wire[8];
    TEST_ASSERT_EQUAL_SIZE(0, wsh_drain(h.peer_fd, wire, sizeof(wire), 0), "nothing on the wire");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_write_small_text_frame) {
    TEST_SUITE("websocketsserverhandlers: guard_write");
    TEST_CASE("a small text frame is written whole and the connection resets");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    websocketsresponse_t* response = websocketsresponse_create(h.conn);
    TEST_REQUIRE_NOT_NULL_GOTO(response, "response allocation", teardown);
    response->send_text(response, "hello");
    h.ctx.response = response;

    TEST_ASSERT_EQUAL(1, websockets_guard_write(h.conn), "write succeeds");
    TEST_ASSERT_NULL(h.ctx.response, "keepalive path reset the connection");
    TEST_ASSERT(stub_control_mod_last_events == (MPXIN | MPXRDHUP), "re-armed for reading");

    unsigned char wire[64];
    const size_t received = wsh_drain(h.peer_fd, wire, sizeof(wire), 0);
    TEST_ASSERT_EQUAL_SIZE(7, received, "frame size on the wire");
    TEST_ASSERT_EQUAL(0x81, wire[0], "FIN text opcode");
    TEST_ASSERT_EQUAL(5, wire[1], "payload length");
    TEST_ASSERT(memcmp(wire + 2, "hello", 5) == 0, "payload content");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_write_partial_send_regression) {
    TEST_SUITE("websocketsserverhandlers: guard_write");
    /* REGRESSION: after a short send() the handler only continued when
     * writed == buffer_size exactly; any other partial write fell through to
     * connection_after_write and truncated the frame on the wire. */
    TEST_CASE("a short write keeps the response staged until every byte is sent");

    enum { PAYLOAD = 1 << 20 }; /* well past the AF_UNIX socket buffer */

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init_sized(&h, 2 * PAYLOAD), "harness init");

    char* payload = malloc(PAYLOAD);
    TEST_REQUIRE_NOT_NULL_GOTO(payload, "payload allocation", teardown);
    for (size_t i = 0; i < PAYLOAD; i++)
        payload[i] = (char)('a' + i % 26);

    websocketsresponse_t* response = websocketsresponse_create(h.conn);
    TEST_REQUIRE_NOT_NULL_GOTO(response, "response allocation", teardown_payload);
    response->send_binaryn(response, payload, PAYLOAD);
    h.ctx.response = response;

    const size_t frame_size = response->body.size; /* 10-byte header + payload */

    TEST_ASSERT_EQUAL(1, websockets_guard_write(h.conn), "first write keeps the connection");
    TEST_ASSERT_NOT_NULL(h.ctx.response, "partially sent response is still staged");
    TEST_ASSERT(response->body.pos > 0 && response->body.pos < response->body.size,
                "first send was partial");

    unsigned char* wire = malloc(frame_size);
    TEST_REQUIRE_NOT_NULL_GOTO(wire, "wire buffer allocation", teardown_payload);

    size_t received = wsh_drain(h.peer_fd, wire, frame_size, 0);
    int rounds = 0;
    while (h.ctx.response != NULL && rounds++ < 10000) {
        TEST_REQUIRE_GOTO(websockets_guard_write(h.conn) == 1, "resumed write keeps the connection", teardown_wire);
        received = wsh_drain(h.peer_fd, wire, frame_size, received);
    }
    received = wsh_drain(h.peer_fd, wire, frame_size, received);

    TEST_ASSERT_NULL(h.ctx.response, "response completed and was reset");
    TEST_ASSERT_EQUAL_SIZE(frame_size, received, "whole frame arrived");
    TEST_ASSERT_EQUAL(0x82, wire[0], "FIN binary opcode");
    TEST_ASSERT(memcmp(wire + (frame_size - PAYLOAD), payload, PAYLOAD) == 0, "payload intact");

    teardown_wire:
    free(wire);
    teardown_payload:
    free(payload);
    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_write_eagain_keeps_connection_regression) {
    TEST_SUITE("websocketsserverhandlers: guard_write");
    /* REGRESSION: send() failing with EAGAIN (peer not draining, socket
     * buffer full) was treated as fatal and closed the connection. */
    TEST_CASE("EAGAIN on a full socket buffer does not close the connection");

    enum { PAYLOAD = 1 << 20 };

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init_sized(&h, 2 * PAYLOAD), "harness init");

    char* payload = malloc(PAYLOAD);
    TEST_REQUIRE_NOT_NULL_GOTO(payload, "payload allocation", teardown);
    memset(payload, 'x', PAYLOAD);

    websocketsresponse_t* response = websocketsresponse_create(h.conn);
    TEST_REQUIRE_NOT_NULL_GOTO(response, "response allocation", teardown_payload);
    response->send_binaryn(response, payload, PAYLOAD);
    h.ctx.response = response;

    /* Never drain the peer: the socket buffer fills, later sends hit EAGAIN. */
    for (int i = 0; i < 16; i++)
        TEST_REQUIRE_GOTO(websockets_guard_write(h.conn) == 1, "write with a stalled peer keeps the connection", teardown_payload);

    TEST_ASSERT_NOT_NULL(h.ctx.response, "response still staged");
    TEST_ASSERT(response->body.pos < response->body.size, "frame is not complete yet");

    teardown_payload:
    free(payload);
    teardown:
    wsh_harness_free(&h);
}

/* Shared setup for the file-response tests: a server root with one file. */
static int wsh_file_setup(wsh_harness_t* h, char* root, size_t root_size,
                          char* file_path, size_t file_path_size,
                          const void* content, size_t content_size) {
    (void)root_size; (void)file_path_size;

    strcpy(root, "/tmp/wshtestXXXXXX");
    if (mkdtemp(root) == NULL) return 0;

    sprintf(file_path, "%s/data.bin", root);

    const int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) return 0;

    const ssize_t written = write(fd, content, content_size);
    close(fd);
    if (written != (ssize_t)content_size) return 0;

    h->server.root = root;
    h->server.root_length = strlen(root);

    return 1;
}

static void wsh_file_teardown(const char* root, const char* file_path) {
    if (file_path[0] != '\0') unlink(file_path);
    if (root[0] != '\0') rmdir(root);
}

TEST(test_wsh_write_file_response_streams) {
    TEST_SUITE("websocketsserverhandlers: guard_write");
    TEST_CASE("a file response streams in buffer_size chunks until complete");

    enum { CONTENT = 100000, SMALL_BUFFER = 4096 };

    char root[64] = "";
    char file_path[96] = "";

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init_sized(&h, SMALL_BUFFER), "harness init");

    unsigned char* content = malloc(CONTENT);
    TEST_REQUIRE_NOT_NULL_GOTO(content, "content allocation", teardown);
    for (size_t i = 0; i < CONTENT; i++)
        content[i] = (unsigned char)(i * 7);

    TEST_REQUIRE_GOTO(wsh_file_setup(&h, root, sizeof root, file_path, sizeof file_path, content, CONTENT),
                      "file setup", teardown_content);

    websocketsresponse_t* response = websocketsresponse_create(h.conn);
    TEST_REQUIRE_NOT_NULL_GOTO(response, "response allocation", teardown_content);
    h.ctx.response = response;

    TEST_REQUIRE_GOTO(response->send_file(response, "/data.bin") == 0, "file staged", teardown_content);

    const size_t total = response->body.size + CONTENT; /* header + file body */
    unsigned char* wire = malloc(total);
    TEST_REQUIRE_NOT_NULL_GOTO(wire, "wire buffer allocation", teardown_content);

    size_t received = 0;
    int rounds = 0;
    while (h.ctx.response != NULL && rounds++ < 10000) {
        TEST_REQUIRE_GOTO(websockets_guard_write(h.conn) == 1, "chunked write keeps the connection", teardown_wire);
        received = wsh_drain(h.peer_fd, wire, total, received);
    }
    received = wsh_drain(h.peer_fd, wire, total, received);

    TEST_ASSERT_NULL(h.ctx.response, "file response completed");
    TEST_ASSERT_EQUAL_SIZE(total, received, "header and file content arrived");
    TEST_ASSERT_EQUAL(0x82, wire[0], "file is sent as a binary frame");
    TEST_ASSERT(memcmp(wire + (total - CONTENT), content, CONTENT) == 0, "file content intact");

    teardown_wire:
    free(wire);
    teardown_content:
    free(content);
    teardown:
    wsh_file_teardown(root, file_path);
    wsh_harness_free(&h);
}

TEST(test_wsh_write_file_truncated_behind_response_regression) {
    TEST_SUITE("websocketsserverhandlers: guard_write");
    /* REGRESSION: read() == 0 (the file shrank after being staged) advanced
     * file_.pos by zero and returned 1, spinning the event loop forever. */
    TEST_CASE("a file truncated after staging closes the connection");

    enum { CONTENT = 5000 };

    char root[64] = "";
    char file_path[96] = "";

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    char content[CONTENT];
    memset(content, 'f', sizeof content);

    TEST_REQUIRE_GOTO(wsh_file_setup(&h, root, sizeof root, file_path, sizeof file_path, content, CONTENT),
                      "file setup", teardown);

    websocketsresponse_t* response = websocketsresponse_create(h.conn);
    TEST_REQUIRE_NOT_NULL_GOTO(response, "response allocation", teardown);
    h.ctx.response = response;

    TEST_REQUIRE_GOTO(response->send_file(response, "/data.bin") == 0, "file staged", teardown);
    TEST_REQUIRE_GOTO(truncate(file_path, 0) == 0, "file truncated behind the response", teardown);

    TEST_ASSERT_EQUAL(0, websockets_guard_write(h.conn), "truncated file closes instead of spinning");

    teardown:
    wsh_file_teardown(root, file_path);
    wsh_harness_free(&h);
}

TEST(test_wsh_write_file_read_error_closes_regression) {
    TEST_SUITE("websocketsserverhandlers: guard_write");
    /* REGRESSION: read()'s result was stored in a size_t, so -1 became a
     * SIZE_MAX byte count handed to send() over the connection buffer. */
    TEST_CASE("a file read error closes the connection");

    enum { CONTENT = 5000 };

    char root[64] = "";
    char file_path[96] = "";

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    char content[CONTENT];
    memset(content, 'e', sizeof content);

    TEST_REQUIRE_GOTO(wsh_file_setup(&h, root, sizeof root, file_path, sizeof file_path, content, CONTENT),
                      "file setup", teardown);

    websocketsresponse_t* response = websocketsresponse_create(h.conn);
    TEST_REQUIRE_NOT_NULL_GOTO(response, "response allocation", teardown);
    h.ctx.response = response;

    TEST_REQUIRE_GOTO(response->send_file(response, "/data.bin") == 0, "file staged", teardown);

    /* Make the read fail deterministically (EBADF). */
    close(response->file_.fd);

    TEST_ASSERT_EQUAL(0, websockets_guard_write(h.conn), "read failure closes the connection");

    response->file_.fd = -1; /* keep the response reset from double-closing */

    teardown:
    wsh_file_teardown(root, file_path);
    wsh_harness_free(&h);
}

/* ==========================================================================
 * websockets_guard_read
 * ========================================================================== */

TEST(test_wsh_read_ping_stages_pong) {
    TEST_SUITE("websocketsserverhandlers: guard_read");
    TEST_CASE("PING is answered with a PONG echoing the payload");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    unsigned char frame[64];
    const size_t frame_size = wsh_build_frame(frame, 0x09, 1, (const unsigned char*)"hi", 2);
    TEST_REQUIRE_GOTO(send(h.peer_fd, frame, frame_size, 0) == (ssize_t)frame_size, "ping sent", teardown);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "read keeps the connection");
    TEST_ASSERT_NOT_NULL(h.ctx.response, "pong staged for writing");
    TEST_ASSERT_EQUAL(1, h.ctx.need_write, "need_write raised for the same epoll iteration");
    TEST_ASSERT(stub_control_mod_last_events == (MPXOUT | MPXRDHUP), "armed for writing");

    TEST_ASSERT_EQUAL(1, websockets_guard_write(h.conn), "pong written");

    unsigned char wire[64];
    const size_t received = wsh_drain(h.peer_fd, wire, sizeof(wire), 0);
    TEST_ASSERT_EQUAL_SIZE(4, received, "pong frame size");
    TEST_ASSERT_EQUAL(0x8A, wire[0], "PONG opcode");
    TEST_ASSERT_EQUAL(2, wire[1], "pong payload length");
    TEST_ASSERT(memcmp(wire + 2, "hi", 2) == 0, "ping payload echoed");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_read_close_frame_echoes_and_destroys) {
    TEST_SUITE("websocketsserverhandlers: guard_read");
    TEST_CASE("CLOSE is echoed, keepalive drops and the write destroys the connection");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    const unsigned char status[2] = {0x03, 0xE8}; /* 1000: normal closure */
    unsigned char frame[64];
    const size_t frame_size = wsh_build_frame(frame, 0x08, 1, status, sizeof status);
    TEST_REQUIRE_GOTO(send(h.peer_fd, frame, frame_size, 0) == (ssize_t)frame_size, "close sent", teardown);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "read keeps the connection for the reply");
    TEST_ASSERT_EQUAL(0, h.conn->keepalive, "keepalive dropped");
    TEST_ASSERT_NOT_NULL(h.ctx.response, "close reply staged");

    TEST_ASSERT_EQUAL(1, websockets_guard_write(h.conn), "close reply written");
    TEST_ASSERT_EQUAL(1, atomic_load(&h.ctx.destroyed), "connection marked destroyed after the write");

    unsigned char wire[64];
    const size_t received = wsh_drain(h.peer_fd, wire, sizeof(wire), 0);
    TEST_ASSERT_EQUAL_SIZE(4, received, "close frame size");
    TEST_ASSERT_EQUAL(0x88, wire[0], "CLOSE opcode");
    TEST_ASSERT(memcmp(wire + 2, status, 2) == 0, "status code echoed");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_read_pong_is_ignored) {
    TEST_SUITE("websocketsserverhandlers: guard_read");
    TEST_CASE("an unsolicited PONG is consumed without staging a response");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    unsigned char frame[64];
    const size_t frame_size = wsh_build_frame(frame, 0x0A, 1, (const unsigned char*)"x", 1);
    TEST_REQUIRE_GOTO(send(h.peer_fd, frame, frame_size, 0) == (ssize_t)frame_size, "pong sent", teardown);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "read keeps the connection");
    TEST_ASSERT_NULL(h.ctx.response, "nothing staged");

    unsigned char wire[8];
    TEST_ASSERT_EQUAL_SIZE(0, wsh_drain(h.peer_fd, wire, sizeof(wire), 0), "nothing on the wire");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_read_eof_closes) {
    TEST_SUITE("websocketsserverhandlers: guard_read");
    TEST_CASE("peer EOF returns 0");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    safe_close(&h.peer_fd);

    TEST_ASSERT_EQUAL(0, websockets_guard_read(h.conn), "EOF closes the connection");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_read_eagain_keeps_connection) {
    TEST_SUITE("websocketsserverhandlers: guard_read");
    TEST_CASE("an empty non-blocking socket returns 1 (EAGAIN)");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "EAGAIN keeps the connection");
    TEST_ASSERT_NULL(h.ctx.response, "nothing staged");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_read_bad_frame_fails_connection_with_1002) {
    TEST_SUITE("websocketsserverhandlers: guard_read");
    /* RFC 6455 §7.1.7: a protocol error fails the connection. Replying with
     * a text frame used to keep the server parsing a desynced stream. */
    TEST_CASE("a reserved opcode stages CLOSE 1002 and drops keepalive");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    unsigned char frame[64];
    const size_t frame_size = wsh_build_frame(frame, 0x03 /* reserved */, 1, NULL, 0);
    TEST_REQUIRE_GOTO(send(h.peer_fd, frame, frame_size, 0) == (ssize_t)frame_size, "frame sent", teardown);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "the close frame still has to be written");
    TEST_ASSERT(wsh_staged_close_is(&h, 1002), "CLOSE 1002 (protocol error) staged");
    TEST_ASSERT_EQUAL(0, h.conn->keepalive, "keepalive dropped");

    TEST_ASSERT_EQUAL(1, websockets_guard_write(h.conn), "close frame written");
    TEST_ASSERT_EQUAL(1, atomic_load(&h.ctx.destroyed), "connection destroyed after the close");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_read_oversized_payload_fails_connection_with_1009) {
    TEST_SUITE("websocketsserverhandlers: guard_read");
    /* RFC 6455 §7.4.1: 1009 "message too big". The old reply was a text
     * frame that left the connection reading the rest of the huge message
     * as if it were new frames. */
    TEST_CASE("a payload over client_max_body_size stages CLOSE 1009 and drops keepalive");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    const unsigned int saved_limit = env()->main.client_max_body_size;
    env()->main.client_max_body_size = 8;

    const unsigned char payload[] = "0123456789abcdef"; /* 16 > 8 */
    unsigned char frame[64];
    const size_t frame_size = wsh_build_frame(frame, 0x01, 1, payload, 16);
    TEST_REQUIRE_GOTO(send(h.peer_fd, frame, frame_size, 0) == (ssize_t)frame_size, "frame sent", teardown_limit);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "the close frame still has to be written");
    TEST_ASSERT(wsh_staged_close_is(&h, 1009), "CLOSE 1009 (message too big) staged");
    TEST_ASSERT_EQUAL(0, h.conn->keepalive, "keepalive dropped");

    teardown_limit:
    env()->main.client_max_body_size = saved_limit;
    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_read_unknown_route_frees_request_regression) {
    TEST_SUITE("websocketsserverhandlers: guard_read");
    /* REGRESSION: when get_resource found no route the request was never
     * freed - the parser drops its pointer on reset - so every message to an
     * unknown route leaked a request (visible to LeakSanitizer here). */
    TEST_CASE("a message to an unknown route answers 'resource not found' without leaking");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_resource_create), "parser attach", teardown);

    /* server.websockets.route == NULL: no route can match. */
    const char* message = "GET /nope";
    unsigned char frame[64];
    const size_t frame_size = wsh_build_frame(frame, 0x01, 1, (const unsigned char*)message, strlen(message));
    TEST_REQUIRE_GOTO(send(h.peer_fd, frame, frame_size, 0) == (ssize_t)frame_size, "frame sent", teardown);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "read keeps the connection");
    TEST_ASSERT(wsh_staged_text_is(&h, "resource not found"), "'resource not found' staged");

    websocketsparser_t* parser = h.ctx.parser;
    TEST_ASSERT_NULL(parser->request, "parser no longer references the freed request");

    teardown:
    wsh_harness_free(&h);
}

/* ==========================================================================
 * Pipelined control frames: the queued (deferred) response path
 * ========================================================================== */

/* Run one queue item the way threadhandler.c does. */
static void wsh_run_queue_item(wsh_harness_t* h) {
    connection_queue_item_t* item = cqueue_pop(h->ctx.queue);
    if (item == NULL) return;

    item->run(item);
    item->free(item);
}

TEST(test_wsh_read_pipelined_pings_queue_in_order) {
    TEST_SUITE("websocketsserverhandlers: deferred responses");
    TEST_CASE("two pipelined PINGs queue both pongs and deliver them in order");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    unsigned char frames[64];
    size_t pos = wsh_build_frame(frames, 0x09, 1, (const unsigned char*)"a", 1);
    pos += wsh_build_frame(frames + pos, 0x09, 1, (const unsigned char*)"b", 1);
    TEST_REQUIRE_GOTO(send(h.peer_fd, frames, pos, 0) == (ssize_t)pos, "pings sent", teardown);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "read keeps the connection");
    TEST_ASSERT_NULL(h.ctx.response, "responses went through the queue, not the direct path");
    TEST_ASSERT_EQUAL(0, cqueue_empty(h.ctx.queue), "queue holds the deferred responses");
    TEST_ASSERT_EQUAL(2, atomic_load(&h.ctx.broadcast_ref_count), "connection scheduled on the worker queue");

    unsigned char wire[64];

    /* Worker runs item 1: pong "a" is staged, then written. */
    wsh_run_queue_item(&h);
    TEST_ASSERT_NOT_NULL(h.ctx.response, "first pong staged");
    TEST_ASSERT_EQUAL(1, websockets_guard_write(h.conn), "first pong written");

    size_t received = wsh_drain(h.peer_fd, wire, sizeof(wire), 0);
    TEST_ASSERT_EQUAL_SIZE(3, received, "first pong frame size");
    TEST_ASSERT_EQUAL(0x8A, wire[0], "first reply is a PONG");
    TEST_ASSERT_EQUAL('a', wire[2], "first ping answered first");

    /* Worker runs item 2. */
    wsh_run_queue_item(&h);
    TEST_ASSERT_NOT_NULL(h.ctx.response, "second pong staged");
    TEST_ASSERT_EQUAL(1, websockets_guard_write(h.conn), "second pong written");

    received = wsh_drain(h.peer_fd, wire, sizeof(wire), 0);
    TEST_ASSERT_EQUAL_SIZE(3, received, "second pong frame size");
    TEST_ASSERT_EQUAL('b', wire[2], "second ping answered second");

    TEST_ASSERT_EQUAL(1, cqueue_empty(h.ctx.queue), "queue drained");

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_discarded_queued_response_freed_regression) {
    TEST_SUITE("websocketsserverhandlers: deferred responses");
    /* REGRESSION: __queue_data_response_free did not free the staged
     * response, so a connection closed with queued responses leaked them
     * (visible to LeakSanitizer here: the items are freed without running). */
    TEST_CASE("queued responses discarded without running do not leak");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    unsigned char frames[64];
    size_t pos = wsh_build_frame(frames, 0x09, 1, (const unsigned char*)"a", 1);
    pos += wsh_build_frame(frames + pos, 0x09, 1, (const unsigned char*)"b", 1);
    TEST_REQUIRE_GOTO(send(h.peer_fd, frames, pos, 0) == (ssize_t)pos, "pings sent", teardown);

    TEST_ASSERT_EQUAL(1, websockets_guard_read(h.conn), "read keeps the connection");
    TEST_ASSERT_EQUAL(0, cqueue_empty(h.ctx.queue), "responses queued");

    /* Teardown frees the queue items without running them - as __ctx_free
     * does when the connection dies with work pending. */
    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_read_queue_schedule_failure_closes_cleanly_regression) {
    TEST_SUITE("websocketsserverhandlers: deferred responses");
    /* REGRESSION: when connection_queue_append failed, the item was freed
     * while still linked in ctx->queue; the next queue consumer (or ctx
     * teardown, as here) freed it a second time. */
    TEST_CASE("a failed worker-queue schedule closes without double-freeing the item");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");
    TEST_REQUIRE_GOTO(wsh_attach_parser(&h, websockets_protocol_default_create), "parser attach", teardown);

    unsigned char frames[64];
    size_t pos = wsh_build_frame(frames, 0x09, 1, (const unsigned char*)"a", 1);
    pos += wsh_build_frame(frames + pos, 0x09, 1, (const unsigned char*)"b", 1);
    TEST_REQUIRE_GOTO(send(h.peer_fd, frames, pos, 0) == (ssize_t)pos, "pings sent", teardown);

    stub_control_mod_result = 0; /* connection_queue_append fails */

    TEST_ASSERT_EQUAL(0, websockets_guard_read(h.conn), "scheduling failure closes the connection");
    TEST_ASSERT_EQUAL(1, cqueue_empty(h.ctx.queue), "failed item was unlinked from the queue");
    TEST_ASSERT_EQUAL(1, atomic_load(&h.ctx.broadcast_ref_count), "scheduling flag rolled back");

    teardown:
    wsh_harness_free(&h);
}

/* ==========================================================================
 * websockets_deferred_handler
 * ========================================================================== */

static void wsh_noop_handle(void* arg) { (void)arg; }

TEST(test_wsh_deferred_handler_queues_and_schedules) {
    TEST_SUITE("websocketsserverhandlers: deferred_handler");
    TEST_CASE("first item lands in ctx->queue and schedules the connection");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    websockets_protocol_t* protocol = websockets_protocol_default_create();
    TEST_REQUIRE_NOT_NULL_GOTO(protocol, "protocol allocation", teardown);

    websocketsrequest_t* request = websocketsrequest_create(h.conn, protocol);
    if (request == NULL) protocol->free(protocol);
    TEST_REQUIRE_NOT_NULL_GOTO(request, "request allocation", teardown);

    const int r = websockets_deferred_handler(h.conn, request, websockets_queue_request_handler,
                                              wsh_noop_handle, websockets_queue_data_request_create, NULL);

    TEST_ASSERT_EQUAL(1, r, "request queued");
    TEST_ASSERT_EQUAL(0, cqueue_empty(h.ctx.queue), "item is in the connection queue");
    TEST_ASSERT_EQUAL(2, atomic_load(&h.ctx.broadcast_ref_count), "connection scheduled");
    TEST_ASSERT_EQUAL(2, atomic_load(&h.ctx.ref_count), "worker holds a reference");
    TEST_ASSERT(stub_control_mod_last_events == MPXONESHOT, "moved to oneshot while a worker owns it");

    connection_queue_item_t* item = cqueue_pop(h.ctx.queue);
    TEST_REQUIRE_NOT_NULL_GOTO(item, "item retrievable", teardown);
    TEST_ASSERT(item->run == websockets_queue_request_handler, "runner attached");
    TEST_ASSERT(item->handle == wsh_noop_handle, "handler attached");
    TEST_ASSERT(item->connection == h.conn, "connection attached");

    item->free(item); /* releases the request too */

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_deferred_handler_second_item_not_rescheduled) {
    TEST_SUITE("websocketsserverhandlers: deferred_handler");
    TEST_CASE("an item behind a non-empty queue does not reschedule the connection");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    /* A sentinel keeps the queue non-empty, as if a worker were busy. */
    int sentinel = 0;
    TEST_REQUIRE_GOTO(cqueue_append(h.ctx.queue, &sentinel), "sentinel appended", teardown);

    websockets_protocol_t* protocol = websockets_protocol_default_create();
    TEST_REQUIRE_NOT_NULL_GOTO(protocol, "protocol allocation", teardown_sentinel);

    websocketsrequest_t* request = websocketsrequest_create(h.conn, protocol);
    if (request == NULL) protocol->free(protocol);
    TEST_REQUIRE_NOT_NULL_GOTO(request, "request allocation", teardown_sentinel);

    const int r = websockets_deferred_handler(h.conn, request, websockets_queue_request_handler,
                                              wsh_noop_handle, websockets_queue_data_request_create, NULL);

    TEST_ASSERT_EQUAL(1, r, "request queued");
    TEST_ASSERT_EQUAL(1, atomic_load(&h.ctx.broadcast_ref_count), "no second schedule");
    TEST_ASSERT_EQUAL(1, atomic_load(&h.ctx.ref_count), "no extra reference taken");
    TEST_ASSERT_EQUAL(0, stub_control_mod_calls, "epoll api untouched");

    teardown_sentinel:
    TEST_ASSERT(cqueue_pop(h.ctx.queue) == &sentinel, "sentinel still first in the queue");

    connection_queue_item_t* item = cqueue_pop(h.ctx.queue);
    if (item != NULL) item->free(item);

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_deferred_handler_schedule_failure_keeps_component_regression) {
    TEST_SUITE("websocketsserverhandlers: deferred_handler");
    /* REGRESSION: on a connection_queue_append failure the item was freed in
     * place - still linked in ctx->queue AND with the component inside, so
     * the caller's request was freed behind its back and the queue kept a
     * dangling pointer. */
    TEST_CASE("a schedule failure returns 0, unlinks the item and leaves the request to the caller");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    websockets_protocol_t* protocol = websockets_protocol_default_create();
    TEST_REQUIRE_NOT_NULL_GOTO(protocol, "protocol allocation", teardown);

    websocketsrequest_t* request = websocketsrequest_create(h.conn, protocol);
    if (request == NULL) protocol->free(protocol);
    TEST_REQUIRE_NOT_NULL_GOTO(request, "request allocation", teardown);

    stub_control_mod_result = 0; /* connection_queue_append fails */

    const int r = websockets_deferred_handler(h.conn, request, websockets_queue_request_handler,
                                              wsh_noop_handle, websockets_queue_data_request_create, NULL);

    TEST_ASSERT_EQUAL(0, r, "failure reported");
    TEST_ASSERT_EQUAL(1, cqueue_empty(h.ctx.queue), "item unlinked from the queue");
    TEST_ASSERT_EQUAL(1, atomic_load(&h.ctx.broadcast_ref_count), "scheduling flag rolled back");

    /* The request is still the caller's: freeing it must be safe (a double
     * free here aborts the runner under AddressSanitizer). */
    websocketsrequest_free(request);

    teardown:
    wsh_harness_free(&h);
}

/* ==========================================================================
 * websockets_queue_request_handler
 * ========================================================================== */

static int wsh_handler_calls = 0;

static void wsh_text_handle(void* arg) {
    wsctx_t* ctx = arg;
    wsh_handler_calls++;
    ctx->response->send_text(ctx->response, "handled");
}

static int wsh_deny_middleware(void* arg) {
    (void)arg;
    return 0;
}

/* Build the queue item websockets_deferred_handler would have produced. */
static connection_queue_item_t* wsh_make_request_item(wsh_harness_t* h, ratelimiter_t* ratelimiter) {
    websockets_protocol_t* protocol = websockets_protocol_default_create();
    if (protocol == NULL) return NULL;

    websocketsrequest_t* request = websocketsrequest_create(h->conn, protocol);
    if (request == NULL) { protocol->free(protocol); return NULL; }

    connection_queue_item_t* item = connection_queue_item_create();
    if (item == NULL) { websocketsrequest_free(request); return NULL; }

    item->run = websockets_queue_request_handler;
    item->handle = wsh_text_handle;
    item->connection = h->conn;
    item->data = websockets_queue_data_request_create(h->conn, request, ratelimiter);

    if (item->data == NULL) {
        websocketsrequest_free(request);
        item->free(item);
        return NULL;
    }

    return item;
}

TEST(test_wsh_queue_request_handler_runs_route_handler) {
    TEST_SUITE("websocketsserverhandlers: queue_request_handler");
    TEST_CASE("the route handler runs and its response is staged for writing");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    connection_queue_item_t* item = wsh_make_request_item(&h, NULL);
    TEST_REQUIRE_NOT_NULL_GOTO(item, "item built", teardown);

    wsh_handler_calls = 0;
    websockets_queue_request_handler(item);

    TEST_ASSERT_EQUAL(1, wsh_handler_calls, "route handler ran once");
    TEST_ASSERT(wsh_staged_text_is(&h, "handled"), "handler's frame staged");
    TEST_ASSERT(stub_control_mod_last_events == (MPXOUT | MPXRDHUP), "armed for writing");

    item->free(item);

    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_queue_request_handler_rate_limited) {
    TEST_SUITE("websocketsserverhandlers: queue_request_handler");
    TEST_CASE("an exhausted rate limit answers 'Too Many Requests' without running the handler");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    ratelimiter_config_t config = {
        .max_tokens = 1,
        .refill_rate = 1,
        .time_window_ns = 1000000000ULL,
        .cleanup_interval_s = 3600,
    };
    ratelimiter_t* limiter = ratelimiter_init(&config);
    TEST_REQUIRE_NOT_NULL_GOTO(limiter, "ratelimiter init", teardown);

    /* First message takes the only token. */
    connection_queue_item_t* item = wsh_make_request_item(&h, limiter);
    TEST_REQUIRE_NOT_NULL_GOTO(item, "first item built", teardown_limiter);

    wsh_handler_calls = 0;
    websockets_queue_request_handler(item);
    item->free(item);

    TEST_ASSERT_EQUAL(1, wsh_handler_calls, "first message is served");

    /* Stage cleared the way connection_reset does between messages. */
    wsh_ctx_reset(&h.ctx);

    /* Second message inside the same second is over the limit. */
    item = wsh_make_request_item(&h, limiter);
    TEST_REQUIRE_NOT_NULL_GOTO(item, "second item built", teardown_limiter);

    websockets_queue_request_handler(item);
    item->free(item);

    TEST_ASSERT_EQUAL(1, wsh_handler_calls, "route handler did not run again");
    TEST_ASSERT(wsh_staged_text_is(&h, "Too Many Requests"), "'Too Many Requests' staged");

    teardown_limiter:
    ratelimiter_free(limiter);
    teardown:
    wsh_harness_free(&h);
}

TEST(test_wsh_queue_request_handler_middleware_denies) {
    TEST_SUITE("websocketsserverhandlers: queue_request_handler");
    TEST_CASE("a denying middleware stops the chain before the route handler");

    wsh_harness_t h;
    TEST_REQUIRE(wsh_harness_init(&h), "harness init");

    middleware_item_t deny = { .fn = wsh_deny_middleware, .next = NULL };
    h.server.websockets.middleware = &deny;

    connection_queue_item_t* item = wsh_make_request_item(&h, NULL);
    TEST_REQUIRE_NOT_NULL_GOTO(item, "item built", teardown);

    wsh_handler_calls = 0;
    websockets_queue_request_handler(item);

    TEST_ASSERT_EQUAL(0, wsh_handler_calls, "route handler was not reached");
    TEST_ASSERT_NOT_NULL(h.ctx.response, "response object still staged for the middleware to fill");
    TEST_ASSERT(stub_control_mod_last_events == (MPXOUT | MPXRDHUP), "connection handed back to epoll");

    item->free(item);

    teardown:
    wsh_harness_free(&h);
}

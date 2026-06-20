#include "framework.h"
#include "smtpclienthandlers.h"
#include "smtprequest.h"
#include "smtpresponse.h"
#include "smtpresponseparser.h"
#include "connection.h"
#include "connection_c.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

/* The SMTP client read/write handlers are the outbound counterparts of
 * httpclienthandlers.c. Each is wired as connection->{read,write} and driven by
 * the epoll loop (multiplexingepoll.c), which treats a handler return of 0 as
 * "close the connection" and non-zero as "keep it alive". So the contract is:
 *
 *   read/write return 0  -> fatal error, close the connection
 *   read/write return !0 -> progress / keep alive
 *
 * smtp_client_read feeds recv() chunks to the response parser until a reply is
 * complete. The write handlers flush a command (smtprequest_t) or a body
 * (smtprequest_data_t) onto the socket.
 *
 * These tests exercise the handlers end-to-end over a real AF_UNIX socketpair
 * — no mocks — so the actual recv()/send() paths run. Error paths are forced
 * deterministically: closing the peer makes the next send() fail with EPIPE,
 * closing the peer makes recv() return 0 (EOF), and a non-blocking empty socket
 * makes recv() fail with EAGAIN. */

#define CLIENT_BUFFER_SIZE 4096

/* -------------------------------------------------------------------------- */
/* Harness                                                                    */
/* -------------------------------------------------------------------------- */

typedef struct {
    connection_t* conn;
    connection_client_ctx_t ctx;
    smtpresponse_t* response;   /* owns the parser; used by read tests */

    char* buffer;               /* conn->buffer backing store */
    int client_fd;              /* conn->fd side of the socketpair */
    int peer_fd;                /* the other end, driven by the test */
} client_harness_t;

/* Close *fd if open and invalidate it so harness teardown never double-closes
 * (a test that closes the peer to force an error sets peer_fd = -1 here). */
static void safe_close(int* fd) {
    if (fd != NULL && *fd != -1) {
        close(*fd);
        *fd = -1;
    }
}

/* Freed on both the happy path and init's allocation-failure path. */
static void client_harness_free(client_harness_t* h);

static int client_harness_init(client_harness_t* h) {
    memset(h, 0, sizeof *h);
    h->client_fd = -1;
    h->peer_fd = -1;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return 0;

    h->buffer = malloc(CLIENT_BUFFER_SIZE);
    if (h->buffer == NULL) { safe_close(&fds[0]); safe_close(&fds[1]); return 0; }

    h->conn = calloc(1, sizeof(connection_t));
    if (h->conn == NULL) { free(h->buffer); safe_close(&fds[0]); safe_close(&fds[1]); return 0; }

    h->client_fd = fds[0];
    h->peer_fd = fds[1];

    /* ssl == NULL makes connection_data_{read,write} use recv()/send() rather
     * than openssl, so the handlers run against the raw socketpair. */
    h->conn->fd = h->client_fd;
    h->conn->buffer = h->buffer;
    h->conn->buffer_size = CLIENT_BUFFER_SIZE;
    h->conn->ctx = (connection_ctx_t*)&h->ctx;

    h->response = smtpresponse_create(h->conn);
    if (h->response == NULL) {
        client_harness_free(h); /* tear down partial state */
        return 0;
    }
    h->ctx.response = h->response;

    return 1;
}

static void client_harness_free(client_harness_t* h) {
    if (h == NULL) return;
    if (h->response) h->response->base.free(h->response);
    free(h->conn);
    free(h->buffer);
    safe_close(&h->client_fd);
    safe_close(&h->peer_fd);
    memset(h, 0, sizeof *h);
}

/* -------------------------------------------------------------------------- */
/* Handler wiring (set_*)                                                     */
/* -------------------------------------------------------------------------- */

TEST(test_smtpclient_set_command_wires_handlers) {
    TEST_SUITE("SMTP Client Handlers - wiring");
    TEST_CASE("set_smtp_client_command wires read + write_command");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    set_smtp_client_command(h.conn);

    TEST_ASSERT(h.conn->read == smtp_client_read, "read -> smtp_client_read");
    TEST_ASSERT(h.conn->write == smtp_client_write_command, "write -> smtp_client_write_command");

    client_harness_free(&h);
}

TEST(test_smtpclient_set_content_wires_handlers) {
    TEST_CASE("set_smtp_client_content wires read + write_content");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    set_smtp_client_content(h.conn);

    TEST_ASSERT(h.conn->read == smtp_client_read, "read -> smtp_client_read");
    TEST_ASSERT(h.conn->write == smtp_client_write_content, "write -> smtp_client_write_content");

    client_harness_free(&h);
}

TEST(test_smtpclient_set_tls_wires_handlers) {
    TEST_CASE("set_smtp_client_tls wires the TLS handshake pair");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    set_smtp_client_tls(h.conn);

    TEST_ASSERT(h.conn->read == tls_smtp_client_read, "read -> tls_smtp_client_read");
    TEST_ASSERT(h.conn->write == tls_smtp_client_write, "write -> tls_smtp_client_write");

    client_harness_free(&h);
}

TEST(test_smtpclient_tls_read_is_noop_keepalive) {
    TEST_CASE("tls_smtp_client_read is a keep-alive no-op (mirrors http __tls_read)");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    /* During the TLS handshake the write side drives SSL_do_handshake; the read
     * side is intentionally inert and must report "alive" (non-zero). */
    TEST_ASSERT_EQUAL(1, tls_smtp_client_read(h.conn), "no-op read keeps the connection alive");

    client_harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* smtp_client_read                                                           */
/* -------------------------------------------------------------------------- */

TEST(test_smtpclient_read_single_line) {
    TEST_SUITE("SMTP Client Handlers - read");
    TEST_CASE("a complete single-line reply parses and returns keep-alive");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    const char reply[] = "250 OK\r\n";
    ssize_t seed = write(h.peer_fd, reply, sizeof(reply) - 1);
    TEST_REQUIRE(seed == (ssize_t)(sizeof(reply) - 1), "seed the reply onto the socket");

    int r = smtp_client_read(h.conn);

    TEST_ASSERT_EQUAL(1, r, "complete reply -> keep-alive (1)");
    TEST_ASSERT_EQUAL(250, h.response->status, "status parsed");
    TEST_ASSERT_STR_EQUAL("250 OK\r\n", h.response->message, "message is the full final line");

    client_harness_free(&h);
}

TEST(test_smtpclient_read_greeting_220) {
    TEST_CASE("a 220 ESMTP greeting parses");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    const char reply[] = "220 mail.example.com ESMTP\r\n";
    write(h.peer_fd, reply, sizeof(reply) - 1);

    int r = smtp_client_read(h.conn);

    TEST_ASSERT_EQUAL(1, r, "greeting -> keep-alive");
    TEST_ASSERT_EQUAL(220, h.response->status, "status 220");

    client_harness_free(&h);
}

TEST(test_smtpclient_read_multiline_keeps_final_line) {
    TEST_CASE("a multiline reply keeps only the final line's status/message");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    const char reply[] = "250-PIPELINING\r\n250-SIZE 10240000\r\n250 OK\r\n";
    write(h.peer_fd, reply, sizeof(reply) - 1);

    int r = smtp_client_read(h.conn);

    TEST_ASSERT_EQUAL(1, r, "multiline reply -> keep-alive");
    TEST_ASSERT_EQUAL(250, h.response->status, "status from the final line");
    TEST_ASSERT_STR_EQUAL("250 OK\r\n", h.response->message, "message is the final line only");
    TEST_ASSERT(strstr(h.response->message, "PIPELINING") == NULL,
                "continuation text must not leak into the message");

    client_harness_free(&h);
}

TEST(test_smtpclient_read_eof_sets_keepalive_and_returns_alive) {
    TEST_CASE("peer EOF (recv == 0) clears keepalive but reports non-fatal (1)");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    /* Closing the peer makes the next recv() on our end return 0 (EOF). */
    safe_close(&h.peer_fd);

    int r = smtp_client_read(h.conn);

    TEST_ASSERT_EQUAL(1, r, "EOF is non-fatal: returns 1");
    TEST_ASSERT_EQUAL(0, h.conn->keepalive, "keepalive cleared so the loop reaps the connection");

    client_harness_free(&h);
}

TEST(test_smtpclient_read_error_returns_zero) {
    TEST_CASE("a recv() failure (EAGAIN on a dry non-blocking socket) returns 0 (close)");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    /* Non-blocking + no pending data -> recv() returns -1/EAGAIN, which the
     * handler must treat as a read error (0 = close). */
    int flags = fcntl(h.client_fd, F_GETFL, 0);
    TEST_REQUIRE(flags != -1, "read fd flags");
    TEST_REQUIRE(fcntl(h.client_fd, F_SETFL, flags | O_NONBLOCK) != -1, "set non-blocking");

    int r = smtp_client_read(h.conn);

    TEST_ASSERT_EQUAL(0, r, "read error -> close (0)");

    client_harness_free(&h);
}

TEST(test_smtpclient_read_malformed_returns_zero) {
    TEST_CASE("a malformed reply (parse ERROR) returns 0 (close)");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    /* Non-numeric status code -> parser ERROR -> handler returns 0. */
    const char reply[] = "xyz bad\r\n";
    write(h.peer_fd, reply, sizeof(reply) - 1);

    int r = smtp_client_read(h.conn);

    TEST_ASSERT_EQUAL(0, r, "malformed reply -> close (0)");

    client_harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* smtp_client_write_command                                                  */
/* -------------------------------------------------------------------------- */

TEST(test_smtpclient_write_command_success) {
    TEST_SUITE("SMTP Client Handlers - write_command");
    TEST_CASE("a command is flushed in full and the handler reports success (1)");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    smtprequest_t* request = smtprequest_create(h.conn);
    TEST_REQUIRE_NOT_NULL(request, "create request");
    h.ctx.request = request;

    const char cmd[] = "EHLO mail.example.com\r\n";
    strcpy(request->command, cmd);

    int r = smtp_client_write_command(h.conn);

    TEST_ASSERT_EQUAL(1, r, "successful write -> keep-alive (1)");

    /* The whole command must arrive on the peer intact (no truncation). */
    char got[64];
    ssize_t n = read(h.peer_fd, got, sizeof(got) - 1);
    TEST_ASSERT_EQUAL((ssize_t)(sizeof(cmd) - 1), n, "peer received the full command");
    got[n >= 0 ? n : 0] = 0;
    TEST_ASSERT_STR_EQUAL(cmd, got, "command bytes match exactly");

    request->base.free(request);
    h.ctx.request = NULL;
    client_harness_free(&h);
}

TEST(test_smtpclient_write_command_empty_is_noop_success) {
    TEST_CASE("an empty command writes nothing and still reports success (1)");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    smtprequest_t* request = smtprequest_create(h.conn);
    TEST_REQUIRE_NOT_NULL(request, "create request");
    h.ctx.request = request;
    /* command[0] == 0 from create -> strlen 0 -> write nothing. */

    int r = smtp_client_write_command(h.conn);

    TEST_ASSERT_EQUAL(1, r, "zero-length write -> success (1), not an error");

    /* Nothing should have been sent. Make the peer non-blocking and confirm. */
    int flags = fcntl(h.peer_fd, F_GETFL, 0);
    fcntl(h.peer_fd, F_SETFL, flags | O_NONBLOCK);
    char got[16];
    TEST_ASSERT_EQUAL(-1, read(h.peer_fd, got, sizeof got), "peer received no bytes (EAGAIN)");

    request->base.free(request);
    h.ctx.request = NULL;
    client_harness_free(&h);
}

TEST(test_smtpclient_write_command_error_returns_zero) {
    TEST_CASE("a write failure (peer closed) returns 0 (close), not a truthy byte count");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    smtprequest_t* request = smtprequest_create(h.conn);
    TEST_REQUIRE_NOT_NULL(request, "create request");
    h.ctx.request = request;
    strcpy(request->command, "MAIL FROM:<a@b.c>\r\n");

    /* Closing the peer makes send() fail with EPIPE. Before the fix the handler
     * returned connection_data_write()'s -1 directly — which is truthy, so the
     * loop kept the broken connection open. The fix must map it to 0. */
    safe_close(&h.peer_fd);

    int r = smtp_client_write_command(h.conn);

    TEST_ASSERT_EQUAL(0, r, "write error -> close (0)");

    request->base.free(request);
    h.ctx.request = NULL;
    client_harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* smtp_client_write_content                                                  */
/* -------------------------------------------------------------------------- */

TEST(test_smtpclient_write_content_success) {
    TEST_SUITE("SMTP Client Handlers - write_content");
    TEST_CASE("a content payload is flushed in full and the handler reports success (1)");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    smtprequest_data_t* request = smtprequest_data_create(h.conn);
    TEST_REQUIRE_NOT_NULL(request, "create data request");
    h.ctx.request = request;

    const char body[] = "Subject: hi\r\n\r\nHello, world.\r\n";
    request->content_size = sizeof(body) - 1;
    request->content = malloc(request->content_size);
    TEST_REQUIRE_NOT_NULL(request->content, "allocate content");
    memcpy(request->content, body, request->content_size);

    int r = smtp_client_write_content(h.conn);

    TEST_ASSERT_EQUAL(1, r, "successful write -> keep-alive (1)");

    char got[128];
    ssize_t n = read(h.peer_fd, got, sizeof got);
    TEST_ASSERT_EQUAL((ssize_t)(sizeof(body) - 1), n, "peer received the full body");
    TEST_ASSERT(memcmp(got, body, (size_t)n) == 0, "body bytes match exactly");

    request->base.free(request); /* frees content */
    h.ctx.request = NULL;
    client_harness_free(&h);
}

TEST(test_smtpclient_write_content_binary_size_honored) {
    TEST_CASE("content_size (not strlen) drives the write — embedded NULs are sent");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    smtprequest_data_t* request = smtprequest_data_create(h.conn);
    TEST_REQUIRE_NOT_NULL(request, "create data request");
    h.ctx.request = request;

    /* A body with an embedded NUL: strlen() would stop at byte 2, but the wire
     * payload must include all 5 bytes. */
    const char body[5] = { 'A', 'B', '\0', 'C', 'D' };
    request->content_size = sizeof(body);
    request->content = malloc(sizeof(body));
    TEST_REQUIRE_NOT_NULL(request->content, "allocate content");
    memcpy(request->content, body, sizeof(body));

    int r = smtp_client_write_content(h.conn);

    TEST_ASSERT_EQUAL(1, r, "binary write -> keep-alive (1)");

    char got[16];
    ssize_t n = read(h.peer_fd, got, sizeof got);
    TEST_ASSERT_EQUAL((ssize_t)sizeof(body), n, "all 5 bytes delivered past the NUL");
    TEST_ASSERT(memcmp(got, body, (size_t)n) == 0, "binary bytes match, including the NUL");

    request->base.free(request);
    h.ctx.request = NULL;
    client_harness_free(&h);
}

TEST(test_smtpclient_write_content_error_returns_zero) {
    TEST_CASE("a write failure (peer closed) returns 0 (close)");

    client_harness_t h;
    TEST_REQUIRE(client_harness_init(&h), "harness should initialize");

    smtprequest_data_t* request = smtprequest_data_create(h.conn);
    TEST_REQUIRE_NOT_NULL(request, "create data request");
    h.ctx.request = request;

    request->content_size = 32;
    request->content = malloc(32);
    TEST_REQUIRE_NOT_NULL(request->content, "allocate content");
    memset(request->content, 'x', 32);

    safe_close(&h.peer_fd);

    int r = smtp_client_write_content(h.conn);

    TEST_ASSERT_EQUAL(0, r, "write error -> close (0)");

    request->base.free(request);
    h.ctx.request = NULL;
    client_harness_free(&h);
}

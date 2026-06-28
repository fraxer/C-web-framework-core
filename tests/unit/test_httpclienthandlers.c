#include "framework.h"
#include "httpclienthandlers.h"
#include "connection.h"
#include "connection_c.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "route.h"
#include "httpcommon.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>

// ============================================================================
// Harness
// ============================================================================
//
// handlers.c в целом изолирован от appconfig/server: http_client_read и
// http_client_write работают только с connection_t (fd, buffer, ctx) и
// request/response. Чтобы прогнать их с реальным I/O, соединение строится на
// AF_UNIX socketpair: conn владеет fds[0], тест читает/пишет «серверную»
// сторону через peer_fd (fds[1]).

#define HANDLER_BUFFER_SIZE 16384

static connection_client_ctx_t mock_ctx;

typedef struct {
    connection_t* conn;
    httprequest_t* request;
    httpresponse_t* response;
    int peer_fd;
} handler_harness_t;

static connection_t* make_handler_conn(unsigned short port, int* peer_fd) {
    *peer_fd = -1;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return NULL;

    connection_t* conn = malloc(sizeof(connection_t));
    if (conn == NULL) {
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }
    memset(conn, 0, sizeof(*conn));
    conn->fd = fds[0];
    conn->port = port;
    conn->buffer = malloc(HANDLER_BUFFER_SIZE);
    conn->buffer_size = HANDLER_BUFFER_SIZE;
    if (conn->buffer == NULL) {
        free(conn);
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }
    conn->ctx = (connection_ctx_t*)&mock_ctx;

    *peer_fd = fds[1];
    return conn;
}

static int handler_harness_init(handler_harness_t* h, unsigned short port) {
    memset(h, 0, sizeof(*h));
    memset(&mock_ctx, 0, sizeof(mock_ctx));

    h->conn = make_handler_conn(port, &h->peer_fd);
    if (h->conn == NULL) return 0;

    h->response = httpresponse_create(h->conn);
    h->request = httprequest_create(h->conn);
    if (h->response == NULL || h->request == NULL) {
        if (h->response) httpresponse_free(h->response);
        if (h->request) httprequest_free(h->request);
        free(h->conn->buffer);
        close(h->conn->fd);
        free(h->conn);
        if (h->peer_fd >= 0) close(h->peer_fd);
        memset(h, 0, sizeof(*h));
        return 0;
    }

    mock_ctx.request = h->request;
    mock_ctx.response = h->response;
    h->conn->ctx = (connection_ctx_t*)&mock_ctx;

    return 1;
}

static void handler_harness_free(handler_harness_t* h) {
    // httprequest_free -> httprequest_reset -> httprequest_payload_free, которая
    // закрывает payload_.file.fd. Тест владеет своим временным файлом и закрывает
    // его сам, поэтому отсоединяем fd, чтобы избежать двойного закрытия.
    if (h->request) {
        h->request->payload_.file.fd = -1;
        httprequest_free(h->request);
    }
    if (h->response) httpresponse_free(h->response);
    if (h->conn) {
        if (h->conn->buffer) free(h->conn->buffer);
        if (h->conn->fd > 0) close(h->conn->fd);
        free(h->conn);
    }
    if (h->peer_fd >= 0) close(h->peer_fd);
    memset(h, 0, sizeof(*h));
}

// Вычитать всё, что лежит в буфере socketpair на стороне пира. После исчерпания
// данных poll уходит в таймаут и чтение завершается.
static size_t read_all_peer(int fd, char* buf, size_t cap, int timeout_ms) {
    size_t total = 0;
    while (total < cap) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) break;
        ssize_t n = read(fd, buf + total, cap - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    return total;
}

// Декодировать chunked body из wire в out. Возвращает кол-во декодированных
// байт или -1 при битом фрейминге.
static ssize_t decode_chunked(const char* wire, size_t len, char* out, size_t outcap) {
    size_t i = 0;
    size_t outn = 0;

    while (i < len) {
        size_t sz = 0;
        while (i < len && wire[i] != '\r') {
            char c = wire[i++];
            int v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else return -1;
            sz = sz * 16 + (size_t)v;
        }
        if (i + 1 >= len || wire[i] != '\r' || wire[i + 1] != '\n') return -1;
        i += 2;
        if (sz == 0) break;  // последний chunk
        if (i + sz > len) return -1;
        if (outn + sz > outcap) return -1;
        memcpy(out + outn, wire + i, sz);
        outn += sz;
        i += sz;
        if (i + 1 >= len || wire[i] != '\r' || wire[i + 1] != '\n') return -1;
        i += 2;
    }
    return (ssize_t)outn;
}

// ============================================================================
// Handler wiring
// ============================================================================

TEST(test_set_client_http_assigns_handlers) {
    TEST_SUITE("handler setup");
    TEST_CASE("set_client_http wires read/write to http_client_*");

    handler_harness_t h;
    TEST_REQUIRE(handler_harness_init(&h, 80), "harness init");

    set_client_http(h.conn);
    TEST_ASSERT(h.conn->read == http_client_read, "read == http_client_read");
    TEST_ASSERT(h.conn->write == http_client_write, "write == http_client_write");

    handler_harness_free(&h);
}

TEST(test_set_client_tls_replaces_handlers) {
    TEST_SUITE("handler setup");
    TEST_CASE("set_client_tls swaps in TLS handlers (not invoked here)");

    handler_harness_t h;
    TEST_REQUIRE(handler_harness_init(&h, 443), "harness init");

    set_client_http(h.conn);
    int (*http_read)(connection_t*) = h.conn->read;
    int (*http_write)(connection_t*) = h.conn->write;

    // Не вызываем обработчики: __handshake сделал бы SSL_do_handshake на NULL ssl.
    set_client_tls(h.conn);
    TEST_ASSERT_NOT_NULL(h.conn->read, "tls read handler set");
    TEST_ASSERT_NOT_NULL(h.conn->write, "tls write handler set");
    TEST_ASSERT(h.conn->read != http_read, "tls read differs from http read");
    TEST_ASSERT(h.conn->write != http_write, "tls write differs from http write");

    handler_harness_free(&h);
}

// ============================================================================
// http_client_write
// ============================================================================

TEST(test_write_get_no_body) {
    TEST_SUITE("http_client_write");
    TEST_CASE("GET without body serializes the head only");

    handler_harness_t h;
    TEST_REQUIRE(handler_harness_init(&h, 80), "harness init");

    h.request->method = ROUTE_GET;
    h.request->uri = strdup("/");
    h.request->uri_length = 1;
    h.request->add_header(h.request, "Host", "example.com");
    h.response->transfer_encoding = TE_NONE;

    set_client_http(h.conn);
    int rc = http_client_write(h.conn);
    TEST_ASSERT_EQUAL(1, rc, "write succeeds");

    char wire[1024];
    size_t wn = read_all_peer(h.peer_fd, wire, sizeof(wire) - 1, 100);
    wire[wn] = 0;
    TEST_ASSERT(wn > 0, "peer received bytes");
    TEST_ASSERT(strstr(wire, "GET / HTTP/1.1\r\n") != NULL, "request line");
    TEST_ASSERT(strstr(wire, "Host: example.com") != NULL, "Host header");
    TEST_ASSERT(strstr(wire, "\r\n\r\n") != NULL, "head terminator");

    handler_harness_free(&h);
}

TEST(test_write_post_plain_preserves_body) {
    TEST_SUITE("http_client_write");
    TEST_CASE("plain POST sends the full file body unchanged");

    handler_harness_t h;
    TEST_REQUIRE(handler_harness_init(&h, 80), "harness init");

    const size_t PAYLOAD = 40960;

    char tmppath[] = "/tmp/handler_plain_XXXXXX";
    int tmpfd = mkstemp(tmppath);
    TEST_REQUIRE(tmpfd >= 0, "mkstemp");

    char* pattern = malloc(PAYLOAD);
    TEST_REQUIRE_NOT_NULL(pattern, "pattern buffer");
    for (size_t i = 0; i < PAYLOAD; i++) pattern[i] = (char)(i % 256);

    ssize_t wr = write(tmpfd, pattern, PAYLOAD);
    TEST_ASSERT_EQUAL_SIZE(PAYLOAD, (size_t)wr, "wrote payload file");

    h.request->method = ROUTE_POST;
    h.request->uri = strdup("/upload");
    h.request->uri_length = strlen(h.request->uri);
    h.request->add_header(h.request, "Host", "example.com");
    h.request->payload_.file.fd = tmpfd;
    h.request->payload_.file.size = PAYLOAD;
    h.request->payload_.pos = 0;
    h.response->transfer_encoding = TE_NONE;

    set_client_http(h.conn);
    int rc = http_client_write(h.conn);
    TEST_ASSERT_EQUAL(1, rc, "write succeeds");

    char wire[65536];
    size_t wn = read_all_peer(h.peer_fd, wire, sizeof(wire), 100);
    TEST_ASSERT(wn > PAYLOAD, "peer received head + body");

    const char* body = strstr(wire, "\r\n\r\n");
    TEST_ASSERT_NOT_NULL(body, "head terminator present");
    body += 4;
    size_t body_len = wn - (size_t)(body - wire);
    TEST_ASSERT_EQUAL_SIZE(PAYLOAD, body_len, "plain body length equals payload");
    TEST_ASSERT(memcmp(body, pattern, PAYLOAD) == 0, "plain body matches payload");

    close(tmpfd);
    unlink(tmppath);
    free(pattern);
    handler_harness_free(&h);
}

TEST(test_write_post_chunked_preserves_body) {
    TEST_SUITE("http_client_write");
    TEST_CASE("chunked POST preserves full body (regression: file-position overshoot)");

    handler_harness_t h;
    TEST_REQUIRE(handler_harness_init(&h, 80), "harness init");

    const size_t PAYLOAD = 40960;  // > 16384 → более одного chunk'а

    char tmppath[] = "/tmp/handler_chunk_XXXXXX";
    int tmpfd = mkstemp(tmppath);
    TEST_REQUIRE(tmpfd >= 0, "mkstemp");

    char* pattern = malloc(PAYLOAD);
    TEST_REQUIRE_NOT_NULL(pattern, "pattern buffer");
    for (size_t i = 0; i < PAYLOAD; i++) pattern[i] = (char)(i % 256);

    ssize_t wr = write(tmpfd, pattern, PAYLOAD);
    TEST_ASSERT_EQUAL_SIZE(PAYLOAD, (size_t)wr, "wrote payload file");

    h.request->method = ROUTE_POST;
    h.request->uri = strdup("/upload");
    h.request->uri_length = strlen(h.request->uri);
    h.request->add_header(h.request, "Host", "example.com");
    h.request->payload_.file.fd = tmpfd;
    h.request->payload_.file.size = PAYLOAD;
    h.request->payload_.pos = 0;
    h.response->transfer_encoding = TE_CHUNKED;

    set_client_http(h.conn);
    int rc = http_client_write(h.conn);
    TEST_ASSERT_EQUAL(1, rc, "write succeeds");

    char wire[65536];
    size_t wn = read_all_peer(h.peer_fd, wire, sizeof(wire), 100);
    TEST_ASSERT(wn > 0, "peer received bytes");

    const char* body = strstr(wire, "\r\n\r\n");
    TEST_ASSERT_NOT_NULL(body, "head terminator present");
    body += 4;
    size_t body_len = wn - (size_t)(body - wire);

    char decoded[65536];
    ssize_t dn = decode_chunked(body, body_len, decoded, sizeof(decoded));
    TEST_ASSERT(dn >= 0, "chunk framing is valid");
    TEST_ASSERT_EQUAL_SIZE(PAYLOAD, (size_t)dn, "decoded body length equals payload");
    TEST_ASSERT(memcmp(decoded, pattern, PAYLOAD) == 0, "decoded chunked body matches payload");

    close(tmpfd);
    unlink(tmppath);
    free(pattern);
    handler_harness_free(&h);
}

// ============================================================================
// http_client_read
// ============================================================================

TEST(test_read_parses_valid_response) {
    TEST_SUITE("http_client_read");
    TEST_CASE("a complete server response is parsed and reports its status");

    handler_harness_t h;
    TEST_REQUIRE(handler_harness_init(&h, 80), "harness init");

    const char* response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    ssize_t wr = write(h.peer_fd, response, strlen(response));
    TEST_ASSERT(wr > 0, "feed response to peer");

    // Неблокирующий fd: если парщику понадобится ещё данных, recv вернёт
    // EAGAIN и http_client_read корректно завершится, а не зависнет.
    int flags = fcntl(h.conn->fd, F_GETFL, 0);
    fcntl(h.conn->fd, F_SETFL, flags | O_NONBLOCK);

    set_client_http(h.conn);
    int rc = http_client_read(h.conn);
    TEST_ASSERT_EQUAL(1, rc, "read succeeds for a complete response");
    TEST_ASSERT_EQUAL(200, h.response->status_code, "status code parsed");

    handler_harness_free(&h);
}

TEST(test_read_malformed_does_not_write_back) {
    TEST_SUITE("http_client_read");
    TEST_CASE("a malformed response fails the read WITHOUT writing back to the server");

    handler_harness_t h;
    TEST_REQUIRE(handler_harness_init(&h, 80), "harness init");

    // 10 байт без пробела в токене протокола -> парсер сразу вернёт BAD_REQUEST
    // (httpresponseparser.c: токен > 8 байт до пробела). Старый код звал тут
    // send_default(400) и писал HTML обратно серверу; новый — просто read error.
    const char* malformed = "AAAAAAAAAA\r\n\r\n";
    ssize_t wr = write(h.peer_fd, malformed, strlen(malformed));
    TEST_ASSERT(wr > 0, "feed malformed bytes to peer");

    int flags = fcntl(h.conn->fd, F_GETFL, 0);
    fcntl(h.conn->fd, F_SETFL, flags | O_NONBLOCK);

    set_client_http(h.conn);
    int rc = http_client_read(h.conn);
    TEST_ASSERT_EQUAL(0, rc, "malformed response must fail the read");

    // Ничего не должно быть отправлено обратно серверу: на peer_fd нет данных.
    struct pollfd pfd = { .fd = h.peer_fd, .events = POLLIN };
    int prc = poll(&pfd, 1, 0);
    TEST_ASSERT_EQUAL(0, prc, "client must not write anything back to the server");

    handler_harness_free(&h);
}

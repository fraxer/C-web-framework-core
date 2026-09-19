#include "framework.h"
#include "mail.h"
#include "mailattachment.h"
#include "mailheader.h"
#include "smtprequest.h"
#include "base64.h"
#include "appconfig.h"

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* The internal helpers are not declared in mail.h; redeclare them here so the
 * session-level internals can be unit-tested in isolation. The message-assembly
 * internals moved to mailmessage.c and are covered by test_mailmessage.c.
 * (The network/TLS/MX paths — mail_is_real, __mail_connect, __mail_init_tls,
 *  send_mail_async — are not covered here; they need a live server.) */
void __mail_free(mail_t* instance);
const char* __mail_domain_from_email(const char* email);

/* Внутренние функции асинхронного пути: становятся нестатическими (тот же
 * паттерн переобъявления внутренних хелперов). */
mail_payload_t* __mail_payload_copy(mail_payload_t* payload);
void __mail_payload_free(void* data);

/* -------------------------------------------------------------------------- */
/* Test helpers                                                               */
/* -------------------------------------------------------------------------- */

/* Populate the mail config fields that the date/message-id/build paths read.
 * The runner's env() returns a calloc'd appconfig, so these are NULL until set. */
static void mail_test_env_setup(const char* host, const char* selector, const char* pem) {
    env()->mail.host = (char*)host;
    env()->mail.dkim_selector = (char*)selector;
    env()->mail.dkim_private = (char*)pem;
}

/* -------------------------------------------------------------------------- */
/* __mail_domain_from_email                                                   */
/* -------------------------------------------------------------------------- */

TEST(test_mail_domain_from_email_basic) {
    TEST_CASE("extracts the domain after '@'");

    TEST_ASSERT_STR_EQUAL("example.com", __mail_domain_from_email("user@example.com"), "simple domain");
    TEST_ASSERT_STR_EQUAL("sub.example.com", __mail_domain_from_email("user@sub.example.com"), "multi-label domain");
}

TEST(test_mail_domain_from_email_guards) {
    TEST_CASE("returns NULL for NULL input or missing '@'");

    TEST_ASSERT_NULL(__mail_domain_from_email(NULL), "NULL email does not crash");
    TEST_ASSERT_NULL(__mail_domain_from_email("noatsign"), "no '@' returns NULL");
    TEST_ASSERT_NULL(__mail_domain_from_email(""), "empty string returns NULL");
}

TEST(test_mail_domain_from_email_edge_local_part) {
    TEST_CASE("empty local part still yields the domain");

    TEST_ASSERT_STR_EQUAL("example.com", __mail_domain_from_email("@example.com"), "leading '@'");
}

/* -------------------------------------------------------------------------- */
/* send_mail_result: why a send failed (S.7)                                   */
/* -------------------------------------------------------------------------- */

TEST(test_mail_result_reports_failure_reason) {
    TEST_CASE("a failed send fills the caller's mail_result_t");

    /* Relay mode against a port nothing listens on: no MX lookup, no DNS, and
     * connect() is refused immediately — which is also what proves the relay
     * path skips mail_is_real() entirely (the recipient domain here has no MX
     * and would have been rejected before a socket was ever opened). */
    mail_test_env_setup("example.com", "", "");

    env_mail_relay_t saved = env()->mail.relay;

    env()->mail.relay.enabled = true;
    env()->mail.relay.host = (char*)"127.0.0.1";
    env()->mail.relay.port = 1;   /* a privileged port nothing binds */
    env()->mail.relay.security = ENV_MAIL_SECURITY_NONE;
    env()->mail.relay.user = NULL;
    env()->mail.relay.password = NULL;
    env()->mail.relay.auth = ENV_MAIL_AUTH_AUTO;
    env()->mail.relay.timeout = 1;
    env()->mail.relay.verify = false;

    mail_payload_t payload = {
        .from = "alice@example.com",
        .from_name = "Alice",
        .to = "bob@invalid.invalid",
        .subject = "Hello",
        .body = "body"
    };

    mail_result_t result;
    memset(&result, 0xAA, sizeof(result));   /* the callee must fill every field */

    TEST_ASSERT_EQUAL(0, send_mail_result(&payload, &result), "send fails against a closed port");

    /* No reply ever arrived, so the code is 0 (as opposed to a 4xx/5xx the
     * caller could act on) and the text says which step gave up. */
    TEST_ASSERT_EQUAL(0, result.status, "no SMTP reply code when the connect fails");
    TEST_ASSERT_STR_EQUAL("Failed to connect", result.error, "the failing step is named");

    /* Plain send_mail() is the same call with no reporting, and must not fall
     * over on the NULL result. */
    TEST_ASSERT_EQUAL(0, send_mail(&payload), "send_mail() behaves identically");

    env()->mail.relay = saved;
}

TEST(test_mail_result_survives_a_second_send) {
    TEST_CASE("the answer belongs to the caller: a later send does not overwrite it");

    /* This is what the thread-local version could not do — its values were
     * valid only until the next send in the same thread. */
    mail_test_env_setup("example.com", "", "");

    env_mail_relay_t saved = env()->mail.relay;

    env()->mail.relay.enabled = true;
    env()->mail.relay.host = (char*)"127.0.0.1";
    env()->mail.relay.port = 1;
    env()->mail.relay.security = ENV_MAIL_SECURITY_NONE;
    env()->mail.relay.user = NULL;
    env()->mail.relay.password = NULL;
    env()->mail.relay.auth = ENV_MAIL_AUTH_AUTO;
    env()->mail.relay.timeout = 1;
    env()->mail.relay.verify = false;

    mail_payload_t payload = {
        .from = "alice@example.com",
        .from_name = "Alice",
        .to = "bob@invalid.invalid",
        .subject = "Hello",
        .body = "body"
    };

    mail_result_t first;
    TEST_ASSERT_EQUAL(0, send_mail_result(&payload, &first), "first send fails");

    mail_result_t second;
    TEST_ASSERT_EQUAL(0, send_mail_result(&payload, &second), "second send fails");

    TEST_ASSERT_STR_EQUAL("Failed to connect", first.error, "the first answer is still intact");
    TEST_ASSERT_EQUAL(0, first.status, "the first status is still intact");

    env()->mail.relay = saved;
}

TEST(test_mail_result_guards) {
    TEST_CASE("a rejected argument still leaves a usable result, and NULL is accepted");

    mail_result_t result;
    memset(&result, 0xAA, sizeof(result));

    TEST_ASSERT_EQUAL(0, send_mail_result(NULL, &result), "NULL payload returns 0");
    TEST_ASSERT_EQUAL(0, result.status, "status cleared");
    TEST_ASSERT_EQUAL(0, result.error[0], "error cleared, not left uninitialised");

    TEST_ASSERT_EQUAL(0, send_mail_result(NULL, NULL), "a NULL result is not dereferenced");
    TEST_ASSERT_EQUAL(0, send_mail(NULL), "send_mail(NULL) returns 0");
}

TEST(test_mail_set_error_trims_and_clears) {
    TEST_CASE("mail_set_error stores the reason on the session, trimming the reply CRLF");

    mail_t* m = mail_create();
    TEST_REQUIRE_NOT_NULL(m, "mail_create should succeed");

    TEST_ASSERT_EQUAL(0, m->last_status, "a new session has no recorded status");
    TEST_ASSERT_EQUAL(0, m->last_error[0], "a new session has no recorded error");

    mail_set_error(m, 535, "535 5.7.8 Error: authentication failed\r\n");
    TEST_ASSERT_EQUAL(535, m->last_status, "status stored");
    TEST_ASSERT_STR_EQUAL("535 5.7.8 Error: authentication failed", m->last_error, "CRLF trimmed");

    mail_set_error(m, 0, NULL);
    TEST_ASSERT_EQUAL(0, m->last_status, "status cleared");
    TEST_ASSERT_EQUAL(0, m->last_error[0], "a NULL message clears the text");

    mail_set_error(NULL, 500, "ignored");   /* must not dereference */

    __mail_free(m);
}

/* -------------------------------------------------------------------------- */
/* Relay: EHLO capabilities, the STARTTLS gate and AUTH (S.3, S.4)            */
/* -------------------------------------------------------------------------- */

/* These drive the real client over an AF_UNIX socketpair, the way
 * test_smtpclienthandlers.c does: the server side of the exchange is staged
 * into the peer end up front, so the client's blocking read always finds its
 * reply waiting. No TLS is involved — "security": "none" is a configured mode,
 * and it is the one that leaves the SMTP dialogue readable.
 *
 * SOCK_SEQPACKET rather than SOCK_STREAM, because the client reads one reply
 * per recv(): over a stream, several staged replies coalesce into a single
 * recv, the parser completes on the first and the rest of the buffer is
 * dropped. A real server never gets ahead of the client like that; the packet
 * boundaries reproduce the one-reply-per-read the client actually sees. */

int __mail_connection_setup(mail_t* instance, const int fd, const unsigned short port);
int __mail_send_hello(mail_t* instance);
int __mail_start_tls(mail_t* instance);
int __mail_auth(mail_t* instance);

typedef struct {
    mail_t* mail;
    int peer_fd;
    env_mail_relay_t saved_relay;
} mail_relay_harness_t;

static void mail_relay_harness_free(mail_relay_harness_t* h) {
    if (h->mail != NULL) {
        h->mail->free(h->mail);   /* closes the client end of the pair */
        h->mail = NULL;
    }
    if (h->peer_fd != -1) {
        close(h->peer_fd);
        h->peer_fd = -1;
    }

    env()->mail.relay = h->saved_relay;
}

/* A connected mail_t whose socket is one end of a socketpair, plus a relay
 * configuration with credentials. The caller stages the server's replies with
 * mail_relay_stage() before each client step. */
static int mail_relay_harness_init(mail_relay_harness_t* h, env_mail_security_e security, env_mail_auth_e auth) {
    memset(h, 0, sizeof *h);
    h->peer_fd = -1;
    h->saved_relay = env()->mail.relay;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0) return 0;

    /* A read that finds nothing staged must fail rather than hang the suite. */
    struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    h->mail = mail_create();
    if (h->mail == NULL) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }

    if (!__mail_connection_setup(h->mail, fds[0], 587)) {
        h->mail->free(h->mail);
        h->mail = NULL;
        close(fds[1]);
        return 0;
    }

    h->peer_fd = fds[1];

    env()->mail.relay.enabled = true;
    env()->mail.relay.host = (char*)"relay.example.org";
    env()->mail.relay.port = 587;
    env()->mail.relay.security = security;
    env()->mail.relay.auth = auth;
    env()->mail.relay.user = (char*)"info@example.com";
    env()->mail.relay.password = (char*)"s3cret";
    env()->mail.relay.timeout = 2;
    env()->mail.relay.verify = false;

    return 1;
}

/* One staged reply — one datagram, hence one recv() on the client side. */
static void mail_relay_stage(mail_relay_harness_t* h, const char* reply) {
    const ssize_t n = write(h->peer_fd, reply, strlen(reply));
    (void)n;
}

/* Everything the client has written so far, concatenated and NUL-terminated.
 * Non-blocking, so an empty socket yields "" instead of hanging. */
static size_t mail_relay_sent(mail_relay_harness_t* h, char* out, size_t size) {
    const int flags = fcntl(h->peer_fd, F_GETFL, 0);
    fcntl(h->peer_fd, F_SETFL, flags | O_NONBLOCK);

    size_t total = 0;
    while (total + 1 < size) {
        const ssize_t n = read(h->peer_fd, out + total, size - total - 1);
        if (n <= 0) break;
        total += (size_t)n;
    }
    out[total] = '\0';

    fcntl(h->peer_fd, F_SETFL, flags);
    return total;
}

/* The base64 argument of the client's "AUTH PLAIN <arg>" line, decoded. Returns
 * the decoded length, or -1 when the line is not there. */
static int mail_relay_decode_auth_plain(const char* sent, char* out, size_t size) {
    const char* start = strstr(sent, "AUTH PLAIN ");
    if (start == NULL) return -1;
    start += strlen("AUTH PLAIN ");

    const char* end = strstr(start, "\r\n");
    if (end == NULL) return -1;

    char b64[512];
    const size_t length = (size_t)(end - start);
    if (length >= sizeof(b64)) return -1;
    memcpy(b64, start, length);
    b64[length] = '\0';

    const int decoded = base64_decode(out, b64);
    if (decoded < 0 || (size_t)decoded >= size) return -1;

    return decoded;
}

TEST(test_mail_relay_auth_plain) {
    TEST_SUITE("Mail relay - AUTH");
    TEST_CASE("AUTH PLAIN sends base64(\\0user\\0password) and accepts 235");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250-SIZE 10240000\r\n"
        "250-AUTH PLAIN LOGIN\r\n"
        "250 HELP\r\n");
    mail_relay_stage(&h, "235 2.7.0 Authentication successful\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(1, __mail_auth(h.mail), "AUTH succeeds");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));

    TEST_ASSERT(strstr(sent, "EHLO ") != NULL, "EHLO was sent");
    TEST_ASSERT(strstr(sent, "AUTH PLAIN ") != NULL, "PLAIN was chosen over LOGIN");
    TEST_ASSERT_NULL(strstr(sent, "s3cret"), "the password never appears in the clear");

    /* RFC 4616: an empty authorization identity, the login and the password,
     * NUL-separated. */
    char decoded[256];
    const int decoded_length = mail_relay_decode_auth_plain(sent, decoded, sizeof(decoded));
    const char expected[] = "\0info@example.com\0s3cret";

    TEST_ASSERT_EQUAL((int)sizeof(expected) - 1, decoded_length, "decoded credential has the expected length");
    if (decoded_length == (int)sizeof(expected) - 1)
        TEST_ASSERT_EQUAL(0, memcmp(decoded, expected, sizeof(expected) - 1), "decodes to \\0user\\0password");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_login) {
    TEST_CASE("AUTH LOGIN answers both 334 challenges with base64 of user and password");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    /* Only LOGIN is offered, so "auto" has to fall back to it. */
    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH LOGIN\r\n");
    mail_relay_stage(&h, "334 VXNlcm5hbWU6\r\n");
    mail_relay_stage(&h, "334 UGFzc3dvcmQ6\r\n");
    mail_relay_stage(&h, "235 2.7.0 Authentication successful\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(1, __mail_auth(h.mail), "AUTH succeeds");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));

    TEST_ASSERT(strstr(sent, "AUTH LOGIN\r\n") != NULL, "LOGIN was chosen when PLAIN is not offered");
    TEST_ASSERT_NULL(strstr(sent, "AUTH PLAIN"), "PLAIN was not attempted");
    TEST_ASSERT_NULL(strstr(sent, "s3cret"), "the password never appears in the clear");

    /* base64("info@example.com") and base64("s3cret"), each on its own line. */
    TEST_ASSERT(strstr(sent, "aW5mb0BleGFtcGxlLmNvbQ==\r\n") != NULL, "login sent as base64");
    TEST_ASSERT(strstr(sent, "czNjcmV0\r\n") != NULL, "password sent as base64");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_bad_credentials) {
    TEST_CASE("a 535 reply fails the send instead of continuing unauthenticated");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_PLAIN), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH PLAIN LOGIN\r\n");
    mail_relay_stage(&h, "535 5.7.8 Error: authentication failed\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_auth(h.mail), "AUTH fails on 535");
    TEST_ASSERT_EQUAL(1, h.mail->reseted, "the session is marked unusable");

    /* A manually driven sequence gets the reason too, without going through
     * send_mail() -- which is what putting the state on mail_t is for. */
    TEST_ASSERT_EQUAL(535, h.mail->last_status, "the reply code is on the session");
    TEST_ASSERT_STR_EQUAL("535 5.7.8 Error: authentication failed", h.mail->last_error,
        "the server's own words, CRLF trimmed");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_mechanism_not_offered) {
    TEST_CASE("an explicitly configured mechanism the server does not offer is an error, not a fallback");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_PLAIN), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH LOGIN\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_auth(h.mail), "auth: plain against a LOGIN-only server fails");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "AUTH"), "no AUTH command was attempted");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_not_offered_at_all) {
    TEST_CASE("a server announcing no AUTH is an error rather than a silent skip");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 SIZE 10240000\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_auth(h.mail), "AUTH refused when unannounced");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_refuses_plaintext) {
    TEST_CASE("credentials are not sent in the clear unless security is \"none\"");

    /* security: "starttls" with no TLS on the socket is the dangerous case: it
     * means the upgrade did not happen and the password would go out readable. */
    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_STARTTLS, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH PLAIN LOGIN\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_auth(h.mail), "AUTH refused over an unencrypted socket");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "AUTH"), "no credentials left the process");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_skipped_without_credentials) {
    TEST_CASE("no user configured means no AUTH — an open internal relay is a valid setup");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    env()->mail.relay.user = NULL;
    env()->mail.relay.password = NULL;

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 AUTH PLAIN LOGIN\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(1, __mail_auth(h.mail), "auth is a no-op without credentials");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "AUTH"), "no AUTH command sent");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_auth_skipped_in_direct_mode) {
    TEST_CASE("direct delivery never authenticates, whatever else is configured");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    env()->mail.relay.enabled = false;

    TEST_ASSERT_EQUAL(1, __mail_auth(h.mail), "auth is a no-op in direct mode");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "AUTH"), "no AUTH command sent");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_starttls_requires_announcement) {
    TEST_CASE("STARTTLS is not sent to a server that did not announce it");

    /* Before the EHLO reply was parsed this was decided by the reply code to a
     * STARTTLS sent blind. */
    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_STARTTLS, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h,
        "250-relay.example.org Hello\r\n"
        "250 SIZE 10240000\r\n");

    TEST_ASSERT_EQUAL(1, __mail_send_hello(h.mail), "EHLO accepted");
    TEST_ASSERT_EQUAL(0, __mail_start_tls(h.mail), "start_tls refuses without the announcement");

    char sent[1024];
    mail_relay_sent(&h, sent, sizeof(sent));
    TEST_ASSERT_NULL(strstr(sent, "STARTTLS"), "no STARTTLS command was written");

    /* Not described by the latest reply, which is the EHLO's own 250: the step
     * has to name its own reason. */
    TEST_ASSERT_EQUAL(0, h.mail->last_status, "no reply code -- nothing was rejected");
    TEST_ASSERT_STR_EQUAL("Server does not offer STARTTLS", h.mail->last_error, "the step names itself");

    mail_relay_harness_free(&h);
}

TEST(test_mail_relay_ehlo_rejection_is_an_error) {
    TEST_CASE("a non-250 EHLO reply fails instead of leaving stale capabilities");

    mail_relay_harness_t h;
    TEST_REQUIRE(mail_relay_harness_init(&h, ENV_MAIL_SECURITY_NONE, ENV_MAIL_AUTH_AUTO), "harness init");

    mail_relay_stage(&h, "502 5.5.1 Command not implemented\r\n");

    TEST_ASSERT_EQUAL(0, __mail_send_hello(h.mail), "EHLO rejection is reported");
    TEST_ASSERT_EQUAL(1, h.mail->reseted, "the session is marked unusable");
    TEST_ASSERT_EQUAL(502, h.mail->last_status, "the rejection code is on the session");

    mail_relay_harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* __mail_payload_copy — вложения                                             */
/* -------------------------------------------------------------------------- */

TEST(test_mail_payload_copy_attachments) {
    TEST_SUITE("mail payload");
    TEST_CASE("вложения копируются глубоко: бинарные данные и строки");

    static const uint8_t bytes[] = { 0x00, 0x01, 0xFF, 'a', 'b', 'c' };
    const mail_attachment_t attachments[] = {
        { .filename = "отчёт.pdf", .content_type = NULL, .data = bytes, .size = sizeof(bytes) },
        { .filename = "n.txt", .content_type = "text/plain", .data = "hi", .size = 2 },
    };

    mail_payload_t payload = {
        .from = "a@b.c", .from_name = "A", .to = "d@e.f",
        .subject = "S", .body = "B",
        .attachments = attachments, .attachments_count = 2,
    };

    mail_payload_t* copy = __mail_payload_copy(&payload);
    TEST_REQUIRE_NOT_NULL(copy, "копия создаётся");
    TEST_REQUIRE_NOT_NULL(copy->attachments, "массив вложений скопирован");
    TEST_ASSERT_EQUAL(2, copy->attachments_count, "количество");

    const mail_attachment_t* a0 = &copy->attachments[0];
    TEST_ASSERT_STR_EQUAL("отчёт.pdf", a0->filename, "имя скопировано");
    TEST_ASSERT_NULL(a0->content_type, "NULL content_type остаётся NULL");
    TEST_ASSERT(a0->data != bytes, "данные — другая память");
    TEST_ASSERT_EQUAL(sizeof(bytes), a0->size, "размер");
    TEST_ASSERT_EQUAL(0, memcmp(a0->data, bytes, sizeof(bytes)), "байты совпадают");

    const mail_attachment_t* a1 = &copy->attachments[1];
    TEST_ASSERT_STR_EQUAL("text/plain", a1->content_type, "content_type скопирован");
    TEST_ASSERT_EQUAL(0, memcmp(a1->data, "hi", 2), "второе вложение");

    /* копия не ссылается на оригинал */
    TEST_ASSERT(copy->attachments != attachments, "массив — другая память");

    __mail_payload_free(copy);
}

#include "framework.h"
#include "smtpresponse.h"
#include "smtpresponseparser.h"
#include "connection_c.h"
#include "bufferdata.h"

#include <stdlib.h>
#include <string.h>

/* The SMTP response parser is a small push automaton: bytes are handed to it
 * one read() chunk at a time via set_buffer()/set_bytes_readed()/run(). Each
 * reply line is "<3-digit code><sep><text>\r\n" where sep is '-' for a
 * continuation line and ' ' for the final line. run() returns COMPLETE once the
 * final line lands, CONTINUE while more bytes are needed, ERROR on malformed
 * input.
 *
 * These tests drive it through the same surface the client uses (see
 * smtp_client_read), with a mock connection whose ctx->response points at a
 * real smtpresponse_t owning the parser. */

/* Mock client context: the parser reads ctx->response. Zero-initialized
 * (static) so the unused gzip/base members are harmless. */
static connection_client_ctx_t mock_client_ctx;

/* -------------------------------------------------------------------------- */
/* Harness                                                                    */
/* -------------------------------------------------------------------------- */

typedef struct {
    connection_t* conn;
    smtpresponse_t* response;
    smtpresponseparser_t* parser;
} smtp_harness_t;

static int harness_init(smtp_harness_t* h) {
    memset(h, 0, sizeof *h);

    h->conn = calloc(1, sizeof(connection_t));
    if (h->conn == NULL) return 0;

    h->response = smtpresponse_create(h->conn);
    if (h->response == NULL) {
        free(h->conn);
        h->conn = NULL;
        return 0;
    }

    mock_client_ctx.response = h->response;
    h->conn->ctx = (connection_ctx_t*)&mock_client_ctx;

    h->parser = (smtpresponseparser_t*)h->response->parser;
    smtpresponseparser_set_connection(h->parser, h->conn);

    return 1;
}

static void harness_free(smtp_harness_t* h) {
    if (h->response) h->response->base.free(h->response);
    if (h->conn) free(h->conn);
    memset(h, 0, sizeof *h);
}

/* Feed exactly `len` bytes to the parser in one run() pass. The scratch buffer
 * is allocated to exactly `len` bytes (no trailing NUL) so ASan catches any
 * out-of-bounds read the parser might do. */
static int harness_feed(smtp_harness_t* h, const char* data, size_t len) {
    char* buffer = malloc(len ? len : 1);
    if (buffer == NULL) return -1;
    if (len) memcpy(buffer, data, len);

    smtpresponseparser_set_buffer(h->parser, buffer);
    smtpresponseparser_set_bytes_readed(h->parser, (int)len);

    int result = smtpresponseparser_run(h->parser);

    free(buffer);
    return result;
}

#define FEED(h, literal) harness_feed((h), (literal), sizeof(literal) - 1)

/* -------------------------------------------------------------------------- */
/* Single-line replies                                                        */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponseparser_single_line) {
    TEST_SUITE("SMTP Response Parser - single line");
    TEST_CASE("a complete final line yields COMPLETE with status + message");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "250 OK\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "single line is complete");
    TEST_ASSERT_EQUAL(250, h.response->status, "status parsed");
    TEST_ASSERT_STR_EQUAL("250 OK\r\n", h.response->message, "message is the full final line");

    harness_free(&h);
}

TEST(test_smtpresponseparser_greeting_220) {
    TEST_CASE("a 220 greeting parses");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "220 mail.example.com ESMTP Postfix\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "greeting complete");
    TEST_ASSERT_EQUAL(220, h.response->status, "status 220");

    harness_free(&h);
}

TEST(test_smtpresponseparser_error_code_535) {
    TEST_CASE("a 5xx auth-failure line parses");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "535 5.7.8 Authentication credentials invalid\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "error line complete");
    TEST_ASSERT_EQUAL(535, h.response->status, "status 535");

    harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* Multi-line (continuation) replies — the buffer-accumulation regression     */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponseparser_continuation_two_lines) {
    TEST_SUITE("SMTP Response Parser - multiline");
    TEST_CASE("a two-line reply keeps only the final line in message");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "250-PIPELINING\r\n250 OK\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "multiline reply complete");
    TEST_ASSERT_EQUAL(250, h.response->status, "status from final line");
    TEST_ASSERT_STR_EQUAL("250 OK\r\n", h.response->message, "message is the final line only");
    /* Regression: continuation text must NOT leak into the message. */
    TEST_ASSERT(strstr(h.response->message, "PIPELINING") == NULL,
                "continuation text must not appear in message");

    harness_free(&h);
}

TEST(test_smtpresponseparser_continuation_three_lines) {
    TEST_CASE("a three-line reply keeps only the final line in message");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "250-PIPELINING\r\n250-SIZE 10240000\r\n250 OK\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "three-line reply complete");
    TEST_ASSERT_EQUAL(250, h.response->status, "status 250");
    TEST_ASSERT_STR_EQUAL("250 OK\r\n", h.response->message, "message is the final line");
    TEST_ASSERT(strstr(h.response->message, "SIZE") == NULL, "no SIZE in message");
    TEST_ASSERT(strstr(h.response->message, "PIPELINING") == NULL, "no PIPELINING in message");

    harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* Incremental input (a reply split across read() chunks)                     */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponseparser_incremental_split_before_newline) {
    TEST_SUITE("SMTP Response Parser - incremental");
    TEST_CASE("a reply split just before the final LF spans two passes");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_CONTINUE, FEED(&h, "250 OK\r"),
                      "partial line -> CONTINUE");

    int r = FEED(&h, "\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "completion -> COMPLETE");
    TEST_ASSERT_EQUAL(250, h.response->status, "status parsed");
    TEST_ASSERT_STR_EQUAL("250 OK\r\n", h.response->message, "message assembled across chunks");

    harness_free(&h);
}

TEST(test_smtpresponseparser_incremental_split_mid_status) {
    TEST_CASE("a reply split inside the status code spans two passes");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_CONTINUE, FEED(&h, "25"),
                      "half a status code -> CONTINUE");

    int r = FEED(&h, "0 OK\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "rest of line -> COMPLETE");
    TEST_ASSERT_EQUAL(250, h.response->status, "status reassembled to 250");

    harness_free(&h);
}

TEST(test_smtpresponseparser_continuation_split_across_reads) {
    TEST_CASE("a multiline reply split between continuation lines");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_CONTINUE, FEED(&h, "250-PIPELINING\r\n"),
                      "continuation line alone -> CONTINUE");

    int r = FEED(&h, "250 OK\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "final line -> COMPLETE");
    TEST_ASSERT_EQUAL(250, h.response->status, "status 250");
    TEST_ASSERT_STR_EQUAL("250 OK\r\n", h.response->message, "final line message");
    TEST_ASSERT(strstr(h.response->message, "PIPELINING") == NULL,
                "continuation text dropped across the split");

    harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* Incomplete / empty input                                                    */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponseparser_incomplete_no_newline) {
    TEST_SUITE("SMTP Response Parser - incomplete");
    TEST_CASE("a line with no terminator needs more bytes");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "250 OK");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_CONTINUE, r, "no CRLF -> CONTINUE");
    /* The status is known once the separator is seen; the message is not. */
    TEST_ASSERT_EQUAL(250, h.response->status, "status captured before terminator");

    harness_free(&h);
}

TEST(test_smtpresponseparser_empty_input) {
    TEST_CASE("zero bytes is a harmless CONTINUE");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = harness_feed(&h, "", 0);
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_CONTINUE, r, "empty -> CONTINUE");
    TEST_ASSERT_EQUAL(0, h.response->status, "status untouched");

    harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* Malformed input -> ERROR                                                   */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponseparser_error_bare_lf) {
    TEST_SUITE("SMTP Response Parser - errors");
    TEST_CASE("a line terminated with bare LF (no CR) is rejected");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "250 OK\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_ERROR, r, "bare LF -> ERROR");

    harness_free(&h);
}

TEST(test_smtpresponseparser_error_nonnumeric_status) {
    TEST_CASE("a non-numeric status code is rejected");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "abc OK\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_ERROR, r, "alpha status -> ERROR");

    harness_free(&h);
}

TEST(test_smtpresponseparser_error_two_digit_status) {
    TEST_CASE("a two-digit status code is rejected (must be exactly three)");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "25 OK\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_ERROR, r, "two-digit status -> ERROR");

    harness_free(&h);
}

TEST(test_smtpresponseparser_error_four_digit_status) {
    TEST_CASE("a four-digit status code is rejected");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    int r = FEED(&h, "2500 OK\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_ERROR, r, "four-digit status -> ERROR");

    harness_free(&h);
}

TEST(test_smtpresponseparser_error_nul_in_status) {
    TEST_CASE("a NUL byte inside the status code is rejected");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    const char data[] = { '2', '5', '\0', 'x', ' ', 'O', 'K', '\r', '\n' };
    int r = harness_feed(&h, data, sizeof data);
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_ERROR, r, "NUL in status -> ERROR");

    harness_free(&h);
}

TEST(test_smtpresponseparser_error_nul_in_message) {
    TEST_CASE("a NUL byte inside the message is rejected");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    const char data[] = { '2', '5', '0', ' ', 'O', '\0', 'K', '\r', '\n' };
    int r = harness_feed(&h, data, sizeof data);
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_ERROR, r, "NUL in message -> ERROR");

    harness_free(&h);
}

TEST(test_smtpresponseparser_error_oversized_line) {
    TEST_CASE("a line longer than the message buffer is rejected, not overflowed");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    /* "250 " + 2000 bytes of text + CRLF: well past SMTPRESPONSE_MESSAGE_SIZE. */
    char huge[4 + 2000 + 2];
    memcpy(huge, "250 ", 4);
    memset(huge + 4, 'x', 2000);
    memcpy(huge + 4 + 2000, "\r\n", 2);

    int r = harness_feed(&h, huge, sizeof huge);
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_ERROR, r, "oversized line -> ERROR");

    harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* Boundary: a long line that fits exercises set_message truncation safely    */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponseparser_long_line_truncation_safe) {
    TEST_SUITE("SMTP Response Parser - boundaries");
    TEST_CASE("a line at the buffer limit completes and stays null-terminated");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    /* "250 " (4) + 1019 'x' + "\r\n": writed reaches 1025 at the LF, so
     * set_message clamps to SMTPRESPONSE_MESSAGE_SIZE-1 and writes a NUL at the
     * last index — no out-of-bounds write. */
    char line[4 + 1019 + 2];
    memcpy(line, "250 ", 4);
    memset(line + 4, 'x', 1019);
    memcpy(line + 4 + 1019, "\r\n", 2);

    int r = harness_feed(&h, line, sizeof line);
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "boundary-length line completes");
    TEST_ASSERT_EQUAL(250, h.response->status, "status parsed");
    TEST_ASSERT_EQUAL(0, h.response->message[SMTPRESPONSE_MESSAGE_SIZE - 1],
                      "message is NUL-terminated at the last index");
    TEST_ASSERT_EQUAL(SMTPRESPONSE_MESSAGE_SIZE - 1, (int)strlen(h.response->message),
                      "message occupies the whole buffer without overflow");

    harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* Reset / reuse                                                               */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponseparser_reset_then_reuse) {
    TEST_SUITE("SMTP Response Parser - reset");
    TEST_CASE("after reset a second response parses from a clean slate");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness should initialize");

    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, FEED(&h, "250 OK\r\n"),
                      "first response complete");
    TEST_ASSERT_EQUAL(250, h.response->status, "first status 250");

    /* reset() (smtpresponseparser_init inside) clears the connection pointer,
     * exactly as production re-wires it on the next smtp_client_read. */
    h.response->base.reset(h.response);
    TEST_ASSERT_EQUAL(0, h.response->status, "reset clears status");
    TEST_ASSERT_EQUAL(0, h.response->message[0], "reset clears message");
    smtpresponseparser_set_connection(h.parser, h.conn);

    int r = FEED(&h, "220 Hi\r\n");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, r, "second response complete");
    TEST_ASSERT_EQUAL(220, h.response->status, "second status 220");
    TEST_ASSERT_STR_EQUAL("220 Hi\r\n", h.response->message, "second message");

    harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* NULL-connection guard                                                       */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponseparser_null_connection_returns_error) {
    TEST_SUITE("SMTP Response Parser - guards");
    TEST_CASE("run() without a connection returns ERROR instead of crashing");

    smtpresponseparser_t parser;
    smtpresponseparser_init(&parser);
    /* parser.connection is NULL after init. */

    char buffer[] = "250 OK\r\n";
    smtpresponseparser_set_buffer(&parser, buffer);
    smtpresponseparser_set_bytes_readed(&parser, (int)(sizeof(buffer) - 1));

    int r = smtpresponseparser_run(&parser);
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_ERROR, r, "no connection -> ERROR");

    /* Stack-allocated parser: init owns no heap, so do not smtpresponseparser_free
     * (it would free() the stack address). */
}

/* -------------------------------------------------------------------------- */
/* EHLO extension list                                                        */
/* -------------------------------------------------------------------------- */

/* The extension list lives only in the continuation lines, which the parser
 * drops as soon as each one ends — so if it is not taken there it is gone. */

TEST(test_smtpresponseparser_ehlo_capabilities) {
    TEST_SUITE("SMTP Response Parser - EHLO capabilities");
    TEST_CASE("a multi-line EHLO reply is mined for STARTTLS, SIZE and AUTH");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness init");

    const int result = FEED(&h,
        "250-smtp.example.org Hello\r\n"
        "250-SIZE 73400320\r\n"
        "250-8BITMIME\r\n"
        "250-STARTTLS\r\n"
        "250-AUTH PLAIN LOGIN\r\n"
        "250 HELP\r\n");

    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, result, "reply completes");
    TEST_ASSERT_EQUAL(250, h.response->status, "status is 250");

    TEST_ASSERT((h.response->extensions & SMTPRESPONSE_EXT_STARTTLS) != 0, "STARTTLS taken from a continuation line");
    TEST_ASSERT((h.response->extensions & SMTPRESPONSE_EXT_SIZE) != 0, "SIZE taken from a continuation line");
    TEST_ASSERT((h.response->extensions & SMTPRESPONSE_EXT_AUTH) != 0, "AUTH taken from a continuation line");
    TEST_ASSERT_EQUAL(73400320, (int)h.response->size_limit, "SIZE value parsed");
    TEST_ASSERT((h.response->auth_mechanisms & SMTPRESPONSE_AUTH_PLAIN) != 0, "PLAIN offered");
    TEST_ASSERT((h.response->auth_mechanisms & SMTPRESPONSE_AUTH_LOGIN) != 0, "LOGIN offered");

    /* The message is still just the final line: the continuation lines must not
     * leak into it. */
    TEST_ASSERT_STR_EQUAL("250 HELP\r\n", h.response->message, "message is the final line only");

    harness_free(&h);
}

TEST(test_smtpresponseparser_ehlo_capabilities_split_reads) {
    TEST_CASE("capabilities survive a reply arriving in several read() chunks");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness init");

    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_CONTINUE, FEED(&h, "250-smtp.example.org Hel"), "first chunk continues");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_CONTINUE, FEED(&h, "lo\r\n250-STARTT"), "second chunk continues");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_CONTINUE, FEED(&h, "LS\r\n250-AUTH PLA"), "third chunk continues");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, FEED(&h, "IN\r\n250 HELP\r\n"), "final chunk completes");

    TEST_ASSERT((h.response->extensions & SMTPRESPONSE_EXT_STARTTLS) != 0, "STARTTLS split across reads");
    TEST_ASSERT((h.response->auth_mechanisms & SMTPRESPONSE_AUTH_PLAIN) != 0, "PLAIN split across reads");
    TEST_ASSERT_EQUAL(0, (int)(h.response->auth_mechanisms & SMTPRESPONSE_AUTH_LOGIN), "LOGIN not offered");

    harness_free(&h);
}

TEST(test_smtpresponseparser_ehlo_without_starttls) {
    TEST_CASE("a server that offers no STARTTLS leaves the flag clear");

    smtp_harness_t h;
    TEST_REQUIRE(harness_init(&h), "harness init");

    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_COMPLETE, FEED(&h,
        "250-smtp.example.org Hello\r\n"
        "250-PIPELINING\r\n"
        "250 SIZE 10240000\r\n"), "reply completes");

    TEST_ASSERT_EQUAL(0, (int)(h.response->extensions & SMTPRESPONSE_EXT_STARTTLS), "STARTTLS not announced");
    TEST_ASSERT((h.response->extensions & SMTPRESPONSE_EXT_PIPELINING) != 0, "PIPELINING announced");
    TEST_ASSERT_EQUAL(10240000, (int)h.response->size_limit, "SIZE from the final line");

    harness_free(&h);
}

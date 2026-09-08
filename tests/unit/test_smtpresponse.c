#include "framework.h"
#include "smtpresponse.h"
#include "smtpresponseparser.h"
#include "bufferdata.h"

#include <stdlib.h>
#include <string.h>

/* smtpresponse wraps the generic response_t vtable ({reset,free}) around a
 * status code, a fixed message buffer, and an owned smtpresponseparser_t. The
 * create functions take a connection that is stored but never dereferenced
 * here, so NULL is a safe stand-in for unit tests. */

/* Internal impls are not in smtpresponse.h; redeclare so the NULL-argument
 * contract can be tested directly as well as through the vtable. */
void __smtpresponse_reset(void* arg);
void __smtpresponse_free(void* arg);
int __smtpresponse_init_parser(smtpresponse_t* response);

/* -------------------------------------------------------------------------- */
/* create / initial state                                                     */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponse_create_initial_state) {
    TEST_CASE("create zeroes status/message, allocates the parser, wires the vtable");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    TEST_ASSERT_EQUAL(0, r->status, "status initially 0");
    TEST_ASSERT_EQUAL(0, r->message[0], "message[0] cleared");
    TEST_ASSERT_EQUAL(0, r->message[SMTPRESPONSE_MESSAGE_SIZE - 1], "message end cleared");
    TEST_ASSERT(r->connection == NULL, "connection stored as given (NULL)");

    TEST_ASSERT_NOT_NULL(r->parser, "parser allocated");

    TEST_ASSERT(r->base.reset != NULL, "reset wired");
    TEST_ASSERT(r->base.free != NULL, "free wired");
    TEST_ASSERT(r->base.reset == __smtpresponse_reset, "reset points at __smtpresponse_reset");
    TEST_ASSERT(r->base.free == __smtpresponse_free, "free points at __smtpresponse_free");

    r->base.free(r);
}

TEST(test_smtpresponse_parser_starts_in_status_stage) {
    TEST_CASE("the owned parser begins in the STATUS stage");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    smtpresponseparser_t* p = r->parser;
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_STATUS, p->stage, "parser stage is STATUS");

    r->base.free(r);
}

/* -------------------------------------------------------------------------- */
/* reset                                                                      */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponse_reset_clears_fields) {
    TEST_CASE("reset zeroes status/message and restores the parser stage");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    smtpresponseparser_t* p = r->parser;

    /* Populate response fields and move the parser off its initial stage. */
    r->status = 250;
    strcpy(r->message, "2.0.0 OK\r\n");
    p->stage = SMTPRESPONSEPARSER_MESSAGE;

    r->base.reset(r);

    TEST_ASSERT_EQUAL(0, r->status, "status cleared");
    TEST_ASSERT_EQUAL(0, r->message[0], "message cleared");
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_STATUS, p->stage, "parser stage restored to STATUS");

    r->base.free(r);
}

TEST(test_smtpresponse_reset_frees_parser_dynamic_buffer) {
    TEST_CASE("reset flushes the parser's dynamic buffer (no leak on reuse)");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    smtpresponseparser_t* p = r->parser;

    /* Push past the static threshold so the parser's bufferdata spills into a
     * heap allocation; reset must free it (smtpresponseparser_reset flushes). */
    for (int i = 0; i < BUFFERDATA_SIZE + 16; i++)
        bufferdata_push(&p->buf, 'x');
    TEST_ASSERT(p->buf.dynamic_buffer != NULL, "parser dynamic buffer allocated");

    r->base.reset(r);

    TEST_ASSERT_NULL(p->buf.dynamic_buffer, "reset freed the parser dynamic buffer");
    /* The parser struct itself is still alive after reset (only its state was
     * flushed), so inspecting it here is valid. */
    TEST_ASSERT_EQUAL(SMTPRESPONSEPARSER_STATUS, p->stage, "parser re-initialized");

    r->base.free(r);
}

TEST(test_smtpresponse_reset_is_idempotent) {
    TEST_CASE("resetting twice is harmless");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    r->status = 451;
    r->base.reset(r);
    r->base.reset(r);
    TEST_ASSERT_EQUAL(0, r->status, "status cleared after double reset");

    r->base.free(r);
}

/* -------------------------------------------------------------------------- */
/* free / lifecycle                                                           */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponse_free_no_leak) {
    TEST_CASE("free releases the parser and the response (ASan leak-clean)");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    /* Give the parser something to own so a missed free would be detected. */
    smtpresponseparser_t* p = r->parser;
    for (int i = 0; i < BUFFERDATA_SIZE + 16; i++)
        bufferdata_push(&p->buf, 'y');

    r->base.free(r);
}

TEST(test_smtpresponse_reset_then_free) {
    TEST_CASE("the full reset+free path is safe and leak-free");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    r->status = 220;
    strcpy(r->message, "greeted\r\n");
    r->base.reset(r);
    r->base.free(r);
}

/* -------------------------------------------------------------------------- */
/* NULL-argument safety (the fix)                                             */
/* -------------------------------------------------------------------------- */

TEST(test_smtpresponse_null_arg_does_not_crash) {
    TEST_CASE("reset/free/init_parser accept a NULL handle without dereferencing");

    /* Direct calls. Before the guard these were NULL dereferences. */
    __smtpresponse_reset(NULL);
    __smtpresponse_free(NULL);
    TEST_ASSERT_EQUAL(0, __smtpresponse_init_parser(NULL), "init_parser(NULL) returns 0");

    /* Through the vtable pointer as well (how generic code would invoke it). */
    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");
    void (*reset_fn)(void*) = r->base.reset;
    void (*free_fn)(void*) = r->base.free;
    reset_fn(NULL);
    free_fn(NULL);
    r->base.free(r);

    TEST_ASSERT(1, "reached here without crashing on NULL handles");
}

/* -------------------------------------------------------------------------- */
/* EHLO capabilities (smtpresponse_parse_capability)                          */
/* -------------------------------------------------------------------------- */

/* Feed one EHLO reply line, written the way a server sends it. */
#define PARSE_LINE(r, literal) smtpresponse_parse_capability((r), (literal), sizeof(literal) - 1)

TEST(test_smtpresponse_capabilities_initially_empty) {
    TEST_SUITE("SMTP Response - EHLO capabilities");
    TEST_CASE("a fresh response announces nothing");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    TEST_ASSERT_EQUAL(0, (int)r->extensions, "no extensions");
    TEST_ASSERT_EQUAL(0, (int)r->auth_mechanisms, "no auth mechanisms");
    TEST_ASSERT_EQUAL(0, (int)r->size_limit, "no size limit");

    r->base.free(r);
}

TEST(test_smtpresponse_capabilities_full_ehlo) {
    TEST_CASE("a complete EHLO reply yields STARTTLS, SIZE with its value, and both AUTH mechanisms");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    PARSE_LINE(r, "250-smtp.mail.ru Hello\r\n");
    PARSE_LINE(r, "250-SIZE 73400320\r\n");
    PARSE_LINE(r, "250-STARTTLS\r\n");
    PARSE_LINE(r, "250-AUTH PLAIN LOGIN\r\n");
    PARSE_LINE(r, "250 HELP\r\n");

    TEST_ASSERT((r->extensions & SMTPRESPONSE_EXT_STARTTLS) != 0, "STARTTLS announced");
    TEST_ASSERT((r->extensions & SMTPRESPONSE_EXT_SIZE) != 0, "SIZE announced");
    TEST_ASSERT((r->extensions & SMTPRESPONSE_EXT_AUTH) != 0, "AUTH announced");
    TEST_ASSERT_EQUAL(73400320, (int)r->size_limit, "SIZE value parsed");
    TEST_ASSERT((r->auth_mechanisms & SMTPRESPONSE_AUTH_PLAIN) != 0, "PLAIN offered");
    TEST_ASSERT((r->auth_mechanisms & SMTPRESPONSE_AUTH_LOGIN) != 0, "LOGIN offered");

    r->base.free(r);
}

TEST(test_smtpresponse_capabilities_on_final_line) {
    TEST_CASE("the final line of a reply carries a keyword too");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    PARSE_LINE(r, "250-example.org Hello\r\n");
    PARSE_LINE(r, "250 AUTH LOGIN\r\n");

    TEST_ASSERT((r->extensions & SMTPRESPONSE_EXT_AUTH) != 0, "AUTH announced on the final line");
    TEST_ASSERT((r->auth_mechanisms & SMTPRESPONSE_AUTH_LOGIN) != 0, "LOGIN offered");
    TEST_ASSERT_EQUAL(0, (int)(r->auth_mechanisms & SMTPRESPONSE_AUTH_PLAIN), "PLAIN not offered");

    r->base.free(r);
}

TEST(test_smtpresponse_capabilities_case_and_equals_form) {
    TEST_CASE("keywords are case-insensitive and the legacy AUTH=... form is understood");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    PARSE_LINE(r, "250-starttls\r\n");
    PARSE_LINE(r, "250 AUTH=plain login\r\n");

    TEST_ASSERT((r->extensions & SMTPRESPONSE_EXT_STARTTLS) != 0, "lowercase STARTTLS recognised");
    TEST_ASSERT((r->auth_mechanisms & SMTPRESPONSE_AUTH_PLAIN) != 0, "PLAIN from the '=' form");
    TEST_ASSERT((r->auth_mechanisms & SMTPRESPONSE_AUTH_LOGIN) != 0, "LOGIN from the '=' form");

    r->base.free(r);
}

TEST(test_smtpresponse_capabilities_ignore_non_250) {
    TEST_CASE("a non-250 reply is free text and is not mined for keywords");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    PARSE_LINE(r, "500-STARTTLS is not available here\r\n");
    PARSE_LINE(r, "500 AUTH PLAIN is not available either\r\n");

    TEST_ASSERT_EQUAL(0, (int)r->extensions, "nothing taken from a 5xx reply");
    TEST_ASSERT_EQUAL(0, (int)r->auth_mechanisms, "no mechanisms taken from a 5xx reply");

    r->base.free(r);
}

TEST(test_smtpresponse_capabilities_word_boundary) {
    TEST_CASE("a keyword must end at a word boundary");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    PARSE_LINE(r, "250-STARTTLSX\r\n");
    PARSE_LINE(r, "250-SIZEX 100\r\n");
    PARSE_LINE(r, "250 AUTHENTICATE PLAIN\r\n");

    TEST_ASSERT_EQUAL(0, (int)r->extensions, "no prefix match on a longer keyword");
    TEST_ASSERT_EQUAL(0, (int)r->size_limit, "no SIZE value from SIZEX");
    TEST_ASSERT_EQUAL(0, (int)r->auth_mechanisms, "no mechanisms from AUTHENTICATE");

    r->base.free(r);
}

TEST(test_smtpresponse_capabilities_size_without_value) {
    TEST_CASE("SIZE with no argument sets the flag and leaves the limit at 0");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    PARSE_LINE(r, "250 SIZE\r\n");

    TEST_ASSERT((r->extensions & SMTPRESPONSE_EXT_SIZE) != 0, "SIZE announced");
    TEST_ASSERT_EQUAL(0, (int)r->size_limit, "limit stays 0 when unstated");

    r->base.free(r);
}

TEST(test_smtpresponse_capabilities_reset) {
    TEST_CASE("reset_capabilities forgets the previous EHLO (the pre-STARTTLS one)");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    PARSE_LINE(r, "250-STARTTLS\r\n");
    PARSE_LINE(r, "250 SIZE 100\r\n");
    TEST_ASSERT(r->extensions != 0, "capabilities recorded");

    smtpresponse_reset_capabilities(r);

    TEST_ASSERT_EQUAL(0, (int)r->extensions, "extensions cleared");
    TEST_ASSERT_EQUAL(0, (int)r->auth_mechanisms, "mechanisms cleared");
    TEST_ASSERT_EQUAL(0, (int)r->size_limit, "size limit cleared");

    /* The generic reset() must clear them as well, since it is what the
     * connection layer calls between uses. */
    PARSE_LINE(r, "250 STARTTLS\r\n");
    r->base.reset(r);
    TEST_ASSERT_EQUAL(0, (int)r->extensions, "base.reset clears capabilities too");

    r->base.free(r);
}

TEST(test_smtpresponse_capabilities_malformed_lines) {
    TEST_CASE("truncated or NULL input is ignored without reading past the buffer");

    smtpresponse_t* r = smtpresponse_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    smtpresponse_parse_capability(NULL, "250 STARTTLS\r\n", 14);
    smtpresponse_parse_capability(r, NULL, 10);
    PARSE_LINE(r, "250");
    PARSE_LINE(r, "");
    PARSE_LINE(r, "250 ");
    PARSE_LINE(r, "250X STARTTLS\r\n");

    TEST_ASSERT_EQUAL(0, (int)r->extensions, "nothing recorded from malformed input");

    r->base.free(r);
}

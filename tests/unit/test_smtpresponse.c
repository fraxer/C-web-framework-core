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

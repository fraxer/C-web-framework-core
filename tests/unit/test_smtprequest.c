#include "framework.h"
#include "smtprequest.h"

#include <stdlib.h>
#include <string.h>

/* smtprequest wraps the generic request_t vtable ({reset,free}) for two SMTP
 * request shapes: a fixed-size command buffer (smtprequest_t) and a dynamically
 * allocated content payload (smtprequest_data_t). The create functions take a
 * connection that is stored but never dereferenced here, so NULL is a safe stand
 * -in for unit tests. */

/* The internal reset/free impls are not in smtprequest.h; redeclare them so the
 * NULL-argument contract can be tested directly as well as through the vtable. */
void __smtprequest_reset(void* arg);
void __smtprequest_free(void* arg);
void __smtprequest_data_reset(void* arg);
void __smtprequest_data_free(void* arg);

/* -------------------------------------------------------------------------- */
/* smtprequest_t (command)                                                    */
/* -------------------------------------------------------------------------- */

TEST(test_smtprequest_create_initial_state) {
    TEST_CASE("create zeroes the command buffer and wires the vtable");

    smtprequest_t* r = smtprequest_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    /* The whole command buffer is zeroed, not just the first byte. */
    TEST_ASSERT_EQUAL(0, r->command[0], "command[0] cleared");
    TEST_ASSERT_EQUAL(0, r->command[SMTPREQUEST_COMMAND_SIZE / 2], "command middle cleared");
    TEST_ASSERT_EQUAL(0, r->command[SMTPREQUEST_COMMAND_SIZE - 1], "command end cleared");

    TEST_ASSERT(r->connection == NULL, "connection stored as given (NULL)");

    /* Vtable wired to the correct impls. */
    TEST_ASSERT(r->base.reset != NULL, "reset wired");
    TEST_ASSERT(r->base.free != NULL, "free wired");
    TEST_ASSERT(r->base.reset == __smtprequest_reset, "reset points at __smtprequest_reset");
    TEST_ASSERT(r->base.free == __smtprequest_free, "free points at __smtprequest_free");

    r->base.free(r);
}

TEST(test_smtprequest_reset_clears_command) {
    TEST_CASE("reset zeroes a populated command buffer");

    smtprequest_t* r = smtprequest_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    strcpy(r->command, "EHLO example.com");
    TEST_ASSERT_EQUAL('E', r->command[0], "command populated before reset");

    r->base.reset(r);

    TEST_ASSERT_EQUAL(0, r->command[0], "command cleared after reset");
    TEST_ASSERT_EQUAL(0, r->command[strlen("EHLO example.com")], "old tail cleared");

    r->base.free(r);
}

TEST(test_smtprequest_reset_is_idempotent) {
    TEST_CASE("resetting twice is harmless");

    smtprequest_t* r = smtprequest_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");

    r->base.reset(r);
    r->base.reset(r);
    TEST_ASSERT_EQUAL(0, r->command[0], "still cleared after double reset");

    r->base.free(r);
}

/* -------------------------------------------------------------------------- */
/* smtprequest_data_t (content payload)                                       */
/* -------------------------------------------------------------------------- */

TEST(test_smtprequest_data_create_initial_state) {
    TEST_CASE("data_create clears content/size and wires the vtable");

    smtprequest_data_t* r = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "data_create should succeed");

    TEST_ASSERT_NULL(r->content, "content initially NULL");
    TEST_ASSERT_EQUAL(0, (int)r->content_size, "content_size initially 0");
    TEST_ASSERT(r->connection == NULL, "connection stored as given (NULL)");

    TEST_ASSERT(r->base.reset != NULL, "reset wired");
    TEST_ASSERT(r->base.free != NULL, "free wired");
    TEST_ASSERT(r->base.reset == __smtprequest_data_reset, "reset points at __smtprequest_data_reset");
    TEST_ASSERT(r->base.free == __smtprequest_data_free, "free points at __smtprequest_data_free");

    r->base.free(r);
}

TEST(test_smtprequest_data_reset_frees_content) {
    TEST_CASE("data reset frees the content buffer and zeroes the size");

    smtprequest_data_t* r = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "data_create should succeed");

    /* Stand in for __mail_build_content assigning an owned buffer. */
    r->content = malloc(16);
    TEST_REQUIRE_NOT_NULL(r->content, "allocate content");
    memcpy(r->content, "payload", 8);
    r->content_size = 8;

    r->base.reset(r);

    TEST_ASSERT_NULL(r->content, "content freed and NULLed");
    TEST_ASSERT_EQUAL(0, (int)r->content_size, "content_size zeroed");

    /* Reset again must not double-free (content is already NULL). */
    r->base.reset(r);
    TEST_ASSERT_NULL(r->content, "still NULL after second reset");

    r->base.free(r);
}

TEST(test_smtprequest_data_free_no_leak) {
    TEST_CASE("data free releases both content and the struct (ASan leak-clean)");

    smtprequest_data_t* r = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "data_create should succeed");

    r->content = malloc(64);
    TEST_REQUIRE_NOT_NULL(r->content, "allocate content");
    r->content_size = 64;

    /* If content were not freed, ASan's leak detector would flag it. */
    r->base.free(r);
}

TEST(test_smtprequest_data_reset_null_content_safe) {
    TEST_CASE("data reset with content already NULL is a no-op");

    smtprequest_data_t* r = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "data_create should succeed");

    /* content starts NULL; reset must not deref/free it. */
    r->base.reset(r);
    TEST_ASSERT_NULL(r->content, "content stays NULL");
    TEST_ASSERT_EQUAL(0, (int)r->content_size, "size stays 0");

    r->base.free(r);
}

/* -------------------------------------------------------------------------- */
/* NULL-argument safety (the fix)                                             */
/* -------------------------------------------------------------------------- */

TEST(test_smtprequest_null_arg_does_not_crash) {
    TEST_CASE("reset/free accept a NULL handle without dereferencing");

    /* Direct calls. Before the guard these were NULL dereferences. */
    __smtprequest_reset(NULL);
    __smtprequest_free(NULL);
    __smtprequest_data_reset(NULL);
    __smtprequest_data_free(NULL);

    /* Through the vtable pointer as well (how generic code would invoke it). */
    smtprequest_t* r = smtprequest_create(NULL);
    TEST_REQUIRE_NOT_NULL(r, "create should succeed");
    void (*reset_fn)(void*) = r->base.reset;
    void (*free_fn)(void*) = r->base.free;
    reset_fn(NULL);
    free_fn(NULL);

    smtprequest_data_t* d = smtprequest_data_create(NULL);
    TEST_REQUIRE_NOT_NULL(d, "data_create should succeed");
    void (*data_reset_fn)(void*) = d->base.reset;
    void (*data_free_fn)(void*) = d->base.free;
    data_reset_fn(NULL);
    data_free_fn(NULL);

    d->base.free(d);
    r->base.free(r);

    TEST_ASSERT(1, "reached here without crashing on NULL handles");
}

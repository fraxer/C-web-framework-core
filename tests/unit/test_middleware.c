#include "framework.h"
#include "middleware.h"
#include "middleware_registry.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// Middleware chain (middleware.c) and registry (middleware_registry.c) tests.
//
// Several cases are regressions for former bugs:
//  - registry stored the caller's name pointer instead of copying it
//    (use-after-free when the name came from a temporary buffer)
//  - middleware() macro was a bare `if`, so an `else` after a call site
//    attached to the macro's internal if and inverted the logic
//  - run_middlewares crashed on a chain item with fn == NULL
//  - empty name was accepted by the registry
// ============================================================================

// --- helpers ----------------------------------------------------------------

#define MW_CALL_LOG_MAX 8

typedef struct {
    int calls[MW_CALL_LOG_MAX];
    int count;
} mw_call_log_t;

static int __mw_log_call(void* ctx, int id, int result) {
    mw_call_log_t* log = ctx;
    if (log != NULL && log->count < MW_CALL_LOG_MAX)
        log->calls[log->count++] = id;
    return result;
}

static int mw_pass_1(void* ctx) { return __mw_log_call(ctx, 1, 1); }
static int mw_pass_2(void* ctx) { return __mw_log_call(ctx, 2, 1); }
static int mw_pass_3(void* ctx) { return __mw_log_call(ctx, 3, 1); }
static int mw_block_2(void* ctx) { return __mw_log_call(ctx, 2, 0); }

static int mw_noop(void* ctx) { (void)ctx; return 1; }
static int mw_noop_other(void* ctx) { (void)ctx; return 1; }

// Builds a chain from fns[0..count-1]; returns the head or NULL.
static middleware_item_t* mw_chain_create(middleware_fn_p* fns, int count) {
    middleware_item_t* first = NULL;
    middleware_item_t* last = NULL;

    for (int i = 0; i < count; i++) {
        middleware_item_t* item = middleware_create(fns[i]);
        if (item == NULL) {
            middlewares_free(first);
            return NULL;
        }

        if (first == NULL) first = item;
        if (last != NULL) last->next = item;
        last = item;
    }

    return first;
}

// --- middleware_create / middlewares_free -----------------------------------

TEST(test_middleware_create_null_fn) {
    TEST_CASE("middleware_create rejects NULL fn");

    TEST_ASSERT_NULL(middleware_create(NULL), "NULL fn must not create an item");
}

TEST(test_middleware_create_valid) {
    TEST_CASE("middleware_create initializes fn and next");

    middleware_item_t* item = middleware_create(mw_noop);
    TEST_REQUIRE_NOT_NULL(item, "middleware_create should succeed");
    TEST_ASSERT(item->fn == mw_noop, "fn should be stored");
    TEST_ASSERT_NULL(item->next, "next should be NULL");

    middlewares_free(item);
}

TEST(test_middlewares_free_null) {
    TEST_CASE("middlewares_free(NULL) is a no-op");

    middlewares_free(NULL);
    TEST_ASSERT(1, "should not crash");
}

// --- run_middlewares ---------------------------------------------------------

TEST(test_run_middlewares_empty_chain) {
    TEST_CASE("Empty chain passes");

    TEST_ASSERT_EQUAL(1, run_middlewares(NULL, NULL), "NULL chain means no checks, pass");
}

TEST(test_run_middlewares_all_pass_in_order) {
    TEST_CASE("All middlewares called in registration order");

    middleware_fn_p fns[] = { mw_pass_1, mw_pass_2, mw_pass_3 };
    middleware_item_t* chain = mw_chain_create(fns, 3);
    TEST_REQUIRE_NOT_NULL(chain, "chain should be created");

    mw_call_log_t log = {0};
    TEST_ASSERT_EQUAL(1, run_middlewares(chain, &log), "All pass, chain passes");
    TEST_ASSERT_EQUAL(3, log.count, "All 3 middlewares called");
    TEST_ASSERT(log.calls[0] == 1 && log.calls[1] == 2 && log.calls[2] == 3,
                "Called in chain order");

    middlewares_free(chain);
}

TEST(test_run_middlewares_stops_on_block) {
    TEST_CASE("Chain stops at the first middleware returning 0");

    middleware_fn_p fns[] = { mw_pass_1, mw_block_2, mw_pass_3 };
    middleware_item_t* chain = mw_chain_create(fns, 3);
    TEST_REQUIRE_NOT_NULL(chain, "chain should be created");

    mw_call_log_t log = {0};
    TEST_ASSERT_EQUAL(0, run_middlewares(chain, &log), "Blocked chain fails");
    TEST_ASSERT_EQUAL(2, log.count, "Third middleware not called after block");
    TEST_ASSERT(log.calls[0] == 1 && log.calls[1] == 2, "First two called");

    middlewares_free(chain);
}

TEST(test_run_middlewares_null_fn_fails_closed) {
    TEST_CASE("Item with fn == NULL fails closed (crash regression)");

    middleware_item_t item = { .fn = NULL, .next = NULL };
    TEST_ASSERT_EQUAL(0, run_middlewares(&item, NULL), "NULL fn must stop the chain");
}

// --- middleware() macro ------------------------------------------------------

static void __mw_macro_handler(mw_call_log_t* log, int* reached_end) {
    middleware(mw_pass_1(log), mw_block_2(log), mw_pass_3(log))

    *reached_end = 1;
}

TEST(test_middleware_macro_short_circuit) {
    TEST_CASE("middleware() macro returns on first failing check");

    mw_call_log_t log = {0};
    int reached_end = 0;
    __mw_macro_handler(&log, &reached_end);

    TEST_ASSERT_EQUAL(0, reached_end, "Handler body after macro must not run");
    TEST_ASSERT_EQUAL(2, log.count, "Third check short-circuited");
}

static void __mw_macro_else_handler(int cond, int* else_taken, int* reached_end) {
    if (cond)
        middleware(mw_noop(NULL))
    else
        *else_taken = 1;

    *reached_end = 1;
}

TEST(test_middleware_macro_dangling_else) {
    TEST_CASE("middleware() under if/else binds else to the outer if (regression)");

    int else_taken = 0, reached_end = 0;

    __mw_macro_else_handler(1, &else_taken, &reached_end);
    TEST_ASSERT_EQUAL(0, else_taken, "cond=1: else branch must not run");
    TEST_ASSERT_EQUAL(1, reached_end, "cond=1: passing middleware continues the handler");

    else_taken = 0;
    reached_end = 0;
    __mw_macro_else_handler(0, &else_taken, &reached_end);
    TEST_ASSERT_EQUAL(1, else_taken, "cond=0: else branch must run");
    TEST_ASSERT_EQUAL(1, reached_end, "cond=0: handler continues after else");
}

// --- middleware_registry -----------------------------------------------------

TEST(test_registry_register_null_args) {
    TEST_CASE("Register rejects NULL name and NULL handler");

    middleware_registry_clear();

    TEST_ASSERT_EQUAL(0, middleware_registry_register(NULL, mw_noop), "NULL name rejected");
    TEST_ASSERT_EQUAL(0, middleware_registry_register("mw", NULL), "NULL handler rejected");

    int count = -1;
    middleware_registry_get_all(&count);
    TEST_ASSERT_EQUAL(0, count, "Nothing registered");

    middleware_registry_clear();
}

TEST(test_registry_register_empty_name) {
    TEST_CASE("Register rejects empty name");

    middleware_registry_clear();

    TEST_ASSERT_EQUAL(0, middleware_registry_register("", mw_noop), "Empty name rejected");
    TEST_ASSERT(middleware_by_name("") == NULL, "Empty name not findable");

    middleware_registry_clear();
}

TEST(test_registry_register_and_lookup) {
    TEST_CASE("Registered middleware found by name");

    middleware_registry_clear();

    TEST_ASSERT_EQUAL(1, middleware_registry_register("auth", mw_noop), "Register should succeed");
    TEST_ASSERT_EQUAL(1, middleware_registry_register("cors", mw_noop_other), "Second register should succeed");

    TEST_ASSERT(middleware_by_name("auth") == mw_noop, "auth resolves to its handler");
    TEST_ASSERT(middleware_by_name("cors") == mw_noop_other, "cors resolves to its handler");
    TEST_ASSERT_NULL(middleware_by_name("unknown"), "Unknown name returns NULL");
    TEST_ASSERT_NULL(middleware_by_name(NULL), "NULL name returns NULL");

    middleware_registry_clear();
}

TEST(test_registry_register_duplicate) {
    TEST_CASE("Duplicate name rejected, original handler kept");

    middleware_registry_clear();

    TEST_ASSERT_EQUAL(1, middleware_registry_register("auth", mw_noop), "First register should succeed");
    TEST_ASSERT_EQUAL(0, middleware_registry_register("auth", mw_noop_other), "Duplicate rejected");
    TEST_ASSERT(middleware_by_name("auth") == mw_noop, "Original handler kept");

    int count = -1;
    middleware_registry_get_all(&count);
    TEST_ASSERT_EQUAL(1, count, "Only one entry stored");

    middleware_registry_clear();
}

TEST(test_registry_name_is_copied) {
    TEST_CASE("Name is copied, caller's buffer may be reused (dangling pointer regression)");

    middleware_registry_clear();

    char buffer[64];
    snprintf(buffer, sizeof(buffer), "transient_name");
    TEST_ASSERT_EQUAL(1, middleware_registry_register(buffer, mw_noop), "Register from stack buffer");

    // Overwrite the caller's buffer: the registry must not see the change.
    snprintf(buffer, sizeof(buffer), "clobbered_value");

    TEST_ASSERT(middleware_by_name("transient_name") == mw_noop, "Lookup by original name still works");
    TEST_ASSERT_NULL(middleware_by_name("clobbered_value"), "Clobbered value is not a registered name");

    middleware_registry_clear();
}

TEST(test_registry_name_too_long) {
    TEST_CASE("Name of MIDDLEWARE_NAME_MAX chars and longer rejected");

    middleware_registry_clear();

    char long_name[MIDDLEWARE_NAME_MAX + 1];
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    TEST_ASSERT_EQUAL(0, middleware_registry_register(long_name, mw_noop), "Too long name rejected");

    // Longest allowed name: MIDDLEWARE_NAME_MAX - 1 chars.
    long_name[MIDDLEWARE_NAME_MAX - 1] = '\0';
    TEST_ASSERT_EQUAL(1, middleware_registry_register(long_name, mw_noop), "Max length name accepted");
    TEST_ASSERT(middleware_by_name(long_name) == mw_noop, "Max length name findable");

    middleware_registry_clear();
}

TEST(test_registry_full) {
    TEST_CASE("Registry rejects registration beyond MIDDLEWARE_REGISTRY_MAX");

    middleware_registry_clear();

    char name[32];
    for (int i = 0; i < MIDDLEWARE_REGISTRY_MAX; i++) {
        snprintf(name, sizeof(name), "mw_%d", i);
        TEST_REQUIRE(middleware_registry_register(name, mw_noop), "Register up to capacity should succeed");
    }

    snprintf(name, sizeof(name), "mw_overflow");
    TEST_ASSERT_EQUAL(0, middleware_registry_register(name, mw_noop), "Register beyond capacity rejected");

    int count = -1;
    middleware_registry_get_all(&count);
    TEST_ASSERT_EQUAL(MIDDLEWARE_REGISTRY_MAX, count, "Count capped at capacity");

    TEST_ASSERT(middleware_by_name("mw_0") != NULL, "First entry still findable");
    snprintf(name, sizeof(name), "mw_%d", MIDDLEWARE_REGISTRY_MAX - 1);
    TEST_ASSERT(middleware_by_name(name) != NULL, "Last entry still findable");

    middleware_registry_clear();
}

TEST(test_registry_get_all) {
    TEST_CASE("get_all returns entries in registration order");

    middleware_registry_clear();

    TEST_REQUIRE(middleware_registry_register("first", mw_noop), "Register first");
    TEST_REQUIRE(middleware_registry_register("second", mw_noop_other), "Register second");

    int count = -1;
    middleware_registry_entry_t* entries = middleware_registry_get_all(&count);
    TEST_REQUIRE_NOT_NULL(entries, "get_all returns the array");
    TEST_ASSERT_EQUAL(2, count, "Two entries");
    TEST_ASSERT_STR_EQUAL("first", entries[0].name, "First entry name");
    TEST_ASSERT_STR_EQUAL("second", entries[1].name, "Second entry name");
    TEST_ASSERT(entries[0].handler == mw_noop, "First entry handler");
    TEST_ASSERT(entries[1].handler == mw_noop_other, "Second entry handler");

    entries = middleware_registry_get_all(NULL);
    TEST_ASSERT_NOT_NULL(entries, "get_all(NULL) does not crash");

    middleware_registry_clear();
}

TEST(test_registry_clear_and_reregister) {
    TEST_CASE("Clear empties the registry and allows re-registration (config reload)");

    middleware_registry_clear();

    TEST_REQUIRE(middleware_registry_register("auth", mw_noop), "Register before clear");
    middleware_registry_clear();

    TEST_ASSERT_NULL(middleware_by_name("auth"), "Cleared entry not findable");

    int count = -1;
    middleware_registry_get_all(&count);
    TEST_ASSERT_EQUAL(0, count, "Count reset to 0");

    TEST_ASSERT_EQUAL(1, middleware_registry_register("auth", mw_noop_other), "Same name registers again after clear");
    TEST_ASSERT(middleware_by_name("auth") == mw_noop_other, "New handler resolved after reload");

    middleware_registry_clear();
}

// --- integration: registry -> chain -> run -----------------------------------

TEST(test_registry_to_chain_integration) {
    TEST_CASE("Chain built from registry lookups runs in order");

    middleware_registry_clear();

    TEST_REQUIRE(middleware_registry_register("log_1", mw_pass_1), "Register log_1");
    TEST_REQUIRE(middleware_registry_register("log_2", mw_pass_2), "Register log_2");

    // Mirrors __module_loader_middlewares_load: resolve names, build the chain.
    const char* names[] = { "log_1", "log_2" };
    middleware_fn_p fns[2];
    for (int i = 0; i < 2; i++) {
        fns[i] = middleware_by_name(names[i]);
        TEST_REQUIRE_NOT_NULL(fns[i], "Configured middleware must resolve");
    }

    middleware_item_t* chain = mw_chain_create(fns, 2);
    TEST_REQUIRE_NOT_NULL(chain, "chain should be created");

    mw_call_log_t log = {0};
    TEST_ASSERT_EQUAL(1, run_middlewares(chain, &log), "Chain passes");
    TEST_ASSERT_EQUAL(2, log.count, "Both middlewares called");
    TEST_ASSERT(log.calls[0] == 1 && log.calls[1] == 2, "Called in config order");

    middlewares_free(chain);
    middleware_registry_clear();
}

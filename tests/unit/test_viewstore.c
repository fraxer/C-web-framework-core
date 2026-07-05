#include "framework.h"
#include "viewstore.h"
#include <pthread.h>
#include <stdatomic.h>

// ============================================================================
// Helper functions and structures
// ============================================================================

static int tag_free_count = 0;

static void test_tag_free(view_tag_t* tag) {
    tag_free_count++;
    free(tag);
}

static view_tag_t* create_test_tag(void) {
    view_tag_t* tag = calloc(1, sizeof(view_tag_t));
    if (tag == NULL) return NULL;

    bufferdata_init(&tag->result_content);
    tag->free = test_tag_free;

    return tag;
}

static void reset_tag_free_count(void) {
    tag_free_count = 0;
}

// ============================================================================
// Тесты создания стора
// ============================================================================

TEST(test_viewstore_create) {
    TEST_CASE("Create view store");

    viewstore_t* store = viewstore_create();

    TEST_REQUIRE_NOT_NULL(store, "Store should be created");
    TEST_ASSERT_NULL(store->view, "First view should be NULL");
    TEST_ASSERT_NULL(store->last_view, "Last view should be NULL");
    TEST_ASSERT_EQUAL(0, atomic_load(&store->locked), "Store should not be locked");

    viewstore_destroy(store);
}

// ============================================================================
// Тесты добавления view
// ============================================================================

TEST(test_viewstore_add_single_view) {
    TEST_CASE("Add a single view");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    view_tag_t* tag = create_test_tag();
    TEST_REQUIRE_NOT_NULL_GOTO(tag, "Tag should be created", cleanup);

    const char* path = "/views/index.html";
    view_t* view = viewstore_add_view(store, tag, path);

    TEST_REQUIRE_NOT_NULL_GOTO(view, "View should be added", cleanup);
    TEST_ASSERT(store->view == view, "Head should point to the added view");
    TEST_ASSERT(store->last_view == view, "Tail should point to the added view");
    TEST_ASSERT_NULL(view->next, "Next of a single view should be NULL");
    TEST_ASSERT(view->root_tag == tag, "Root tag should be stored as passed");
    TEST_ASSERT(view->path != path, "Path should be copied, not aliased");
    TEST_ASSERT_STR_EQUAL(path, view->path, "Path content should match");

cleanup:
    viewstore_destroy(store);
}

TEST(test_viewstore_add_multiple_views) {
    TEST_CASE("Add multiple views keeps insertion order");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    view_t* first = viewstore_add_view(store, create_test_tag(), "/a.html");
    view_t* second = viewstore_add_view(store, create_test_tag(), "/b.html");
    view_t* third = viewstore_add_view(store, create_test_tag(), "/c.html");

    TEST_REQUIRE_GOTO(first != NULL && second != NULL && third != NULL,
                      "All views should be added", cleanup);

    TEST_ASSERT(store->view == first, "Head should stay at the first view");
    TEST_ASSERT(store->last_view == third, "Tail should move to the last view");
    TEST_ASSERT(first->next == second, "First should link to second");
    TEST_ASSERT(second->next == third, "Second should link to third");
    TEST_ASSERT_NULL(third->next, "Last view next should be NULL");

cleanup:
    viewstore_destroy(store);
}

TEST(test_viewstore_add_view_invalid_args) {
    TEST_CASE("Add view rejects NULL arguments");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    view_tag_t* tag = create_test_tag();
    TEST_REQUIRE_NOT_NULL_GOTO(tag, "Tag should be created", cleanup);

    TEST_ASSERT_NULL(viewstore_add_view(NULL, tag, "/x.html"), "NULL store should be rejected");
    TEST_ASSERT_NULL(viewstore_add_view(store, NULL, "/x.html"), "NULL tag should be rejected");
    TEST_ASSERT_NULL(viewstore_add_view(store, tag, NULL), "NULL path should be rejected");
    TEST_ASSERT_NULL(store->view, "Rejected adds should not modify the store");
    TEST_ASSERT_NULL(store->last_view, "Rejected adds should not modify the tail");

    // тег не перешёл во владение стора — освобождаем вручную
    tag->free(tag);

cleanup:
    viewstore_destroy(store);
}

TEST(test_viewstore_add_view_empty_path) {
    TEST_CASE("Add view with empty path");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    view_t* view = viewstore_add_view(store, create_test_tag(), "");
    TEST_REQUIRE_NOT_NULL_GOTO(view, "View with empty path should be added", cleanup);
    TEST_ASSERT_STR_EQUAL("", view->path, "Empty path should be stored as empty string");
    TEST_ASSERT(viewstore_get_view(store, "") == view, "View should be found by empty path");

cleanup:
    viewstore_destroy(store);
}

// ============================================================================
// Тесты поиска view
// ============================================================================

TEST(test_viewstore_get_view) {
    TEST_CASE("Get view by path");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    view_t* first = viewstore_add_view(store, create_test_tag(), "/a.html");
    view_t* second = viewstore_add_view(store, create_test_tag(), "/b.html");
    view_t* third = viewstore_add_view(store, create_test_tag(), "/c.html");

    TEST_REQUIRE_GOTO(first != NULL && second != NULL && third != NULL,
                      "All views should be added", cleanup);

    TEST_ASSERT(viewstore_get_view(store, "/a.html") == first, "First view should be found");
    TEST_ASSERT(viewstore_get_view(store, "/b.html") == second, "Middle view should be found");
    TEST_ASSERT(viewstore_get_view(store, "/c.html") == third, "Last view should be found");
    TEST_ASSERT_NULL(viewstore_get_view(store, "/missing.html"), "Unknown path should return NULL");
    TEST_ASSERT_NULL(viewstore_get_view(store, "/a.htm"), "Path prefix should not match");

cleanup:
    viewstore_destroy(store);
}

TEST(test_viewstore_get_view_empty_store) {
    TEST_CASE("Get view from empty store");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    TEST_ASSERT_NULL(viewstore_get_view(store, "/a.html"), "Empty store should return NULL");

    viewstore_destroy(store);
}

TEST(test_viewstore_get_view_null_args) {
    TEST_CASE("Get view with NULL arguments");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    TEST_ASSERT_NULL(viewstore_get_view(NULL, "/a.html"), "NULL store should return NULL");
    TEST_ASSERT_NULL(viewstore_get_view(store, NULL), "NULL path should return NULL");

    viewstore_destroy(store);
}

TEST(test_viewstore_get_view_duplicate_path) {
    TEST_CASE("Get view with duplicate path returns first added");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    view_t* first = viewstore_add_view(store, create_test_tag(), "/dup.html");
    view_t* second = viewstore_add_view(store, create_test_tag(), "/dup.html");

    TEST_REQUIRE_GOTO(first != NULL && second != NULL, "Both views should be added", cleanup);
    TEST_ASSERT(viewstore_get_view(store, "/dup.html") == first,
                "Lookup should return the first added view");

cleanup:
    viewstore_destroy(store);
}

// ============================================================================
// Тесты освобождения
// ============================================================================

TEST(test_viewstore_destroy_null) {
    TEST_CASE("Destroy NULL store is a no-op");

    viewstore_destroy(NULL);
    TEST_ASSERT(1, "Destroying NULL store should not crash");
}

TEST(test_viewstore_destroy_frees_all_tags) {
    TEST_CASE("Destroy frees every view root tag");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    reset_tag_free_count();

    view_t* first = viewstore_add_view(store, create_test_tag(), "/a.html");
    view_t* second = viewstore_add_view(store, create_test_tag(), "/b.html");
    view_t* third = viewstore_add_view(store, create_test_tag(), "/c.html");
    TEST_REQUIRE(first != NULL && second != NULL && third != NULL,
                 "All views should be added");

    viewstore_destroy(store);

    TEST_ASSERT_EQUAL(3, tag_free_count, "Each root tag free callback should run once");
}

TEST(test_viewstore_destroy_view_without_free_fn) {
    TEST_CASE("Destroy tolerates a root tag without free callback");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    view_tag_t* tag = create_test_tag();
    TEST_REQUIRE_NOT_NULL_GOTO(tag, "Tag should be created", cleanup);
    tag->free = NULL;

    view_t* view = viewstore_add_view(store, tag, "/nofree.html");
    TEST_REQUIRE_NOT_NULL_GOTO(view, "View should be added", cleanup);

    viewstore_destroy(store);
    store = NULL;
    TEST_ASSERT(1, "Destroy with NULL free callback should not crash");

    // стор не владеет тегом без free-колбэка — освобождаем вручную
    free(tag);
    return;

cleanup:
    viewstore_destroy(store);
}

// ============================================================================
// Тесты блокировки
// ============================================================================

TEST(test_viewstore_lock_unlock) {
    TEST_CASE("Lock and unlock toggle the flag");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    viewstore_lock(store);
    TEST_ASSERT_EQUAL(1, atomic_load(&store->locked), "Store should be locked after lock");

    viewstore_unlock(store);
    TEST_ASSERT_EQUAL(0, atomic_load(&store->locked), "Store should be unlocked after unlock");

    viewstore_destroy(store);
}

TEST(test_viewstore_lock_unlock_null) {
    TEST_CASE("Lock and unlock on NULL store are no-ops");

    viewstore_lock(NULL);
    viewstore_unlock(NULL);
    TEST_ASSERT(1, "Lock/unlock on NULL store should not crash");
}

#define LOCK_TEST_THREADS 4
#define LOCK_TEST_ITERATIONS 10000

typedef struct {
    viewstore_t* store;
    long* counter;
} lock_test_arg_t;

static void* lock_test_worker(void* raw) {
    lock_test_arg_t* arg = raw;
    for (int i = 0; i < LOCK_TEST_ITERATIONS; i++) {
        viewstore_lock(arg->store);
        (*arg->counter)++;
        viewstore_unlock(arg->store);
    }
    return NULL;
}

TEST(test_viewstore_lock_mutual_exclusion) {
    TEST_CASE("Lock provides mutual exclusion between threads");

    viewstore_t* store = viewstore_create();
    TEST_REQUIRE_NOT_NULL(store, "Store should be created");

    long counter = 0;
    lock_test_arg_t arg = { store, &counter };
    pthread_t threads[LOCK_TEST_THREADS];

    int started = 0;
    for (; started < LOCK_TEST_THREADS; started++)
        if (pthread_create(&threads[started], NULL, lock_test_worker, &arg) != 0)
            break;

    for (int i = 0; i < started; i++)
        pthread_join(threads[i], NULL);

    TEST_REQUIRE_GOTO(started == LOCK_TEST_THREADS, "All threads should start", cleanup);
    TEST_ASSERT_EQUAL((long)LOCK_TEST_THREADS * LOCK_TEST_ITERATIONS, counter,
                      "Increments under lock should not be lost");
    TEST_ASSERT_EQUAL(0, atomic_load(&store->locked), "Store should end unlocked");

cleanup:
    viewstore_destroy(store);
}

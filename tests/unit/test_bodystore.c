#include "framework.h"
#include "bodystore.h"
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

TEST(test_bodystore_boundaries) {
    TEST_SUITE("body store: boundaries and byte ownership");
    const size_t sizes[] = {0, 1, 200, 20480, BODY_STORE_DEFAULT_FILE_THRESHOLD - 1,
        BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_DEFAULT_FILE_THRESHOLD + 1, 3 * BODY_STORE_DEFAULT_FILE_THRESHOLD};
    char* bytes = malloc(sizes[7]);
    TEST_REQUIRE_NOT_NULL(bytes, "source allocated");
    for (size_t i = 0; i < sizes[7]; ++i) bytes[i] = (char)(i % 251);
    for (size_t i = 0; i < 8; ++i) {
        for (int known = 0; known < 2; ++known) {
            body_store_t store;
            body_store_init(&store, sizes[7], BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_MODE_AUTO);
            if (known) {
                TEST_ASSERT(body_store_prepare(&store, sizes[i], "/tmp"), "known size prepared");
                if (sizes[i] < BODY_STORE_DEFAULT_FILE_THRESHOLD)
                    TEST_ASSERT_EQUAL(sizes[i] + 1, store.capacity, "exact reservation");
            }
            TEST_ASSERT(body_store_append(&store, bytes, sizes[i], "/tmp"), "append");
            TEST_ASSERT_EQUAL(sizes[i], store.size, "actual size");
            if (sizes[i] >= BODY_STORE_DEFAULT_FILE_THRESHOLD) {
                TEST_ASSERT_EQUAL(BODY_STORE_FILE, store.state, "threshold selects file");
                TEST_ASSERT(store.fd >= 0, "live file");
                TEST_ASSERT_NULL(store.data, "memory released");
            } else {
                TEST_ASSERT_EQUAL(sizes[i] || known ? BODY_STORE_MEMORY : BODY_STORE_EMPTY,
                    store.state, "small or empty state");
                TEST_ASSERT_EQUAL(-1, store.fd, "no file");
                TEST_ASSERT_NULL(store.path, "no path");
                TEST_ASSERT(store.capacity <= BODY_STORE_DEFAULT_FILE_THRESHOLD, "bounded capacity");
            }
            char* copy = body_store_copy(&store, 0, store.size);
            TEST_ASSERT_NOT_NULL(copy, "owned copy");
            if (copy) {
                TEST_ASSERT(memcmp(bytes, copy, store.size) == 0, "binary bytes including NUL");
                TEST_ASSERT_EQUAL(0, copy[store.size], "extra terminator");
            }
            body_store_reset(&store);
            if (copy) TEST_ASSERT(memcmp(bytes, copy, sizes[i]) == 0, "copy survives reset");
            free(copy);
            body_store_reset(&store);
            TEST_ASSERT_EQUAL(BODY_STORE_EMPTY, store.state, "idempotent cleanup");
        }
    }
    free(bytes);
}

TEST(test_bodystore_fragment_migration) {
    TEST_SUITE("body store: fragmented threshold crossing");
    body_store_t store;
    body_store_init(&store, BODY_STORE_DEFAULT_FILE_THRESHOLD + 500, BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_MODE_AUTO);
    char block[4096]; memset(block, 'x', sizeof(block));
    while (store.size < BODY_STORE_DEFAULT_FILE_THRESHOLD - 1) {
        size_t n = BODY_STORE_DEFAULT_FILE_THRESHOLD - 1 - store.size;
        if (n > sizeof(block)) n = sizeof(block);
        TEST_REQUIRE(body_store_append(&store, block, n, "/tmp"), "fragment appended");
    }
    TEST_ASSERT_EQUAL(BODY_STORE_MEMORY, store.state, "one byte below threshold");
    TEST_ASSERT(body_store_append(&store, "z", 1, "/tmp"), "cross threshold");
    TEST_ASSERT_EQUAL(BODY_STORE_FILE, store.state, "migrated");
    int fd = store.fd;
    TEST_ASSERT(body_store_append(&store, "end", 3, "/tmp"), "append after migration");
    TEST_ASSERT_EQUAL(fd, store.fd, "same file");
    char* end = body_store_copy(&store, BODY_STORE_DEFAULT_FILE_THRESHOLD - 2, 5);
    TEST_ASSERT_NOT_NULL(end, "cross-boundary read");
    if (end) TEST_ASSERT_STR_EQUAL("xzend", end, "old and new bytes preserved");
    free(end);
    char* path = strdup(store.path);
    body_store_reset(&store);
    TEST_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD), "fd closed");
    if (path) TEST_ASSERT_EQUAL(-1, access(path, F_OK), "file removed");
    free(path);
}

TEST(test_bodystore_materialization) {
    TEST_SUITE("body store: lazy file and range reads");
    body_store_t store;
    body_store_init(&store, 200, BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_MODE_AUTO);
    const char bytes[] = {'a', 0, 'b', 'c', 'd', 'e'};
    TEST_ASSERT(body_store_append(&store, bytes, sizeof(bytes), NULL), "memory needs no temp directory");
    TEST_ASSERT(body_store_materialize(&store, "/tmp"), "materialize memory");
    int fd = store.fd;
    TEST_ASSERT(body_store_materialize(&store, NULL), "reuse file without directory");
    TEST_ASSERT_EQUAL(fd, store.fd, "same descriptor");
    TEST_ASSERT(body_store_append(&store, "f", 1, NULL), "stays file below threshold");
    char* copy = body_store_copy(&store, 0, store.size);
    TEST_ASSERT_NOT_NULL(copy, "read materialized bytes");
    if (copy) {
        TEST_ASSERT(memcmp(copy, bytes, sizeof(bytes)) == 0, "binary prefix intact");
        TEST_ASSERT_EQUAL('f', copy[6], "append intact");
    }
    free(copy);
    TEST_ASSERT(!body_store_read(&store, SIZE_MAX, NULL, 0), "invalid offset");
    TEST_ASSERT(!body_store_read(&store, 6, NULL, 2), "range beyond end");
    TEST_ASSERT(body_store_read(&store, 7, NULL, 0), "empty range at end");
    copy = body_store_copy(&store, 0, SIZE_MAX);
    TEST_ASSERT_NULL(copy, "copy overflow");
    free(copy);
    TEST_ASSERT_EQUAL(0, ftruncate(fd, 2), "simulate truncated file");
    copy = body_store_copy(&store, 0, store.size);
    TEST_ASSERT_NULL(copy, "truncation rejected");
    free(copy);
    body_store_reset(&store);
}

TEST(test_bodystore_failures) {
    TEST_SUITE("body store: failures poison partial bodies and release resources");
    /* A regular file used as a directory produces a real ENOTDIR error. */
    char not_dir[] = "/tmp/cwfr-bodystore-test-XXXXXX";
    int not_dir_fd = mkstemp(not_dir);
    TEST_REQUIRE(not_dir_fd >= 0, "create non-directory fixture");
    for (int fault = 0; fault < 2; ++fault) {
        body_store_t store;
        body_store_init(&store, BODY_STORE_DEFAULT_FILE_THRESHOLD + 10, BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_MODE_AUTO);
        TEST_ASSERT(body_store_append(&store, "abcdef", 6, NULL), "prefix accepted");
        int ok;
        if (fault == 0) {
            ok = body_store_materialize(&store, not_dir);
            TEST_ASSERT_EQUAL(-1, store.fd, "creation failure leaves no fd");
            TEST_ASSERT_NULL(store.path, "creation failure leaves no path");
        } else {
            TEST_REQUIRE(body_store_materialize(&store, "/tmp"), "file before write failure");
            /* Reopen the store's real file read-only: pwrite must fail. */
            int readonly_fd = open(store.path, O_RDONLY);
            TEST_REQUIRE(readonly_fd >= 0, "open read-only fixture");
            TEST_ASSERT_EQUAL(0, close(store.fd), "close writable descriptor");
            store.fd = readonly_fd;
            ok = body_store_append(&store, "g", 1, NULL);
        }
        TEST_ASSERT(!ok, "real filesystem failure");
        TEST_ASSERT_EQUAL(6, store.size, "failed operation preserves actual size");
        char* partial = body_store_copy(&store, 0, 6);
        TEST_ASSERT_NULL(partial, "partial body unreadable");
        free(partial);
        TEST_ASSERT(!body_store_append(&store, "g", 1, NULL), "failure sticky");
        int fd = store.fd;
        char* path = store.path ? strdup(store.path) : NULL;
        body_store_reset(&store);
        if (fd >= 0) TEST_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD), "failed store closes fd");
        if (path) TEST_ASSERT_EQUAL(-1, access(path, F_OK), "failed store removes file");
        free(path);
        TEST_ASSERT_NULL(store.data, "memory freed");
        TEST_ASSERT_NULL(store.path, "path freed");
        TEST_ASSERT_EQUAL(-1, store.fd, "fd released");
        TEST_ASSERT(body_store_append(&store, "new", 3, NULL), "reset permits reuse");
        body_store_reset(&store);
    }
    close(not_dir_fd);
    unlink(not_dir);
    body_store_t store;
    body_store_init(&store, 6, BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_MODE_AUTO);
    TEST_ASSERT(!body_store_prepare(&store, 7, "/tmp"), "known length rejected before allocation");
    TEST_ASSERT_NULL(store.data, "no allocation");
    body_store_reset(&store);
    TEST_ASSERT(body_store_append(&store, "abcdef", 6, NULL), "exact maximum accepted");
    TEST_ASSERT(!body_store_append(&store, "x", SIZE_MAX, NULL), "overflow/maximum rejected");
    TEST_ASSERT_EQUAL(6, store.size, "actual size unchanged");
    body_store_reset(&store);
    char long_dir[PATH_MAX + 1];
    memset(long_dir, 'x', sizeof(long_dir));
    long_dir[PATH_MAX] = '\0';
    TEST_ASSERT(!body_store_materialize(&store, long_dir), "temp path exceeds PATH_MAX");
    TEST_ASSERT_EQUAL(-1, store.fd, "overlong path creates no file");
    TEST_ASSERT_NULL(store.path, "overlong path allocates no path");
    body_store_reset(&store);
}

TEST(test_bodystore_crossing_inside_chunk) {
    TEST_SUITE("body store: threshold inside chunk and buffer growth");
    body_store_t store;
    body_store_init(&store, 2 * BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_MODE_AUTO);
    TEST_ASSERT(body_store_prepare(&store, 1, NULL), "tiny known reservation");
    TEST_ASSERT(body_store_append(&store, "a", 1, NULL), "prefix");
    TEST_ASSERT(body_store_append(&store, "bc", 2, NULL), "grow tiny reservation");
    TEST_ASSERT_EQUAL(3, store.size, "growth updates length");
    TEST_ASSERT_STR_EQUAL("abc", store.data, "growth preserves prefix");
    body_store_reset(&store);
    TEST_ASSERT(body_store_append(&store, "prefix", 6, NULL), "prefix before migration");
    char* block = malloc(BODY_STORE_DEFAULT_FILE_THRESHOLD);
    TEST_REQUIRE_NOT_NULL(block, "large block");
    memset(block, 'x', BODY_STORE_DEFAULT_FILE_THRESHOLD);
    TEST_ASSERT(body_store_append(&store, block, BODY_STORE_DEFAULT_FILE_THRESHOLD, "/tmp"), "threshold inside block");
    TEST_ASSERT_EQUAL(BODY_STORE_FILE, store.state, "file selected");
    TEST_ASSERT_EQUAL(BODY_STORE_DEFAULT_FILE_THRESHOLD + 6, store.size, "combined size");
    char* copy = body_store_copy(&store, 0, store.size);
    TEST_ASSERT_NOT_NULL(copy, "full migrated copy");
    if (copy) {
        TEST_ASSERT(memcmp(copy, "prefix", 6) == 0, "prior bytes");
        TEST_ASSERT(memcmp(copy + 6, block, BODY_STORE_DEFAULT_FILE_THRESHOLD) == 0, "new block");
    }
    free(copy);
    free(block);
    body_store_reset(&store);
    TEST_ASSERT(body_store_materialize(&store, "/tmp"), "empty explicit file");
    TEST_ASSERT_EQUAL(0, store.size, "empty size");
    copy = body_store_copy(&store, 0, 0);
    TEST_ASSERT_NOT_NULL(copy, "empty file copy");
    if (copy) TEST_ASSERT_STR_EQUAL("", copy, "empty text");
    free(copy);
    body_store_reset(&store);
}

TEST(test_bodystore_configured_policy) {
    TEST_SUITE("body store: configurable policy and bounded growth");
    const size_t thresholds[] = {0, 1, 7, 257, BODY_STORE_DEFAULT_FILE_THRESHOLD + 1};
    const char bytes[] = {'a', 0, 'b', 'c', 'd', 'e', 'f'};
    for (int mode = BODY_STORE_MODE_AUTO; mode <= BODY_STORE_MODE_FILE; ++mode) {
        for (size_t t = 0; t < sizeof(thresholds)/sizeof(thresholds[0]); ++t) {
            for (int known = 0; known < 2; ++known) {
                body_store_t store;
                body_store_init(&store, sizeof(bytes), thresholds[t], mode);
                if (known) TEST_ASSERT(body_store_prepare(&store, sizeof(bytes), "/tmp"), "prepare configured policy");
                for (size_t i = 0; i < sizeof(bytes); ++i) {
                    TEST_ASSERT(body_store_append(&store, bytes+i, 1, "/tmp"), "incremental append");
                    int file = mode == BODY_STORE_MODE_FILE ||
                        (mode == BODY_STORE_MODE_AUTO && (known ? sizeof(bytes) : i+1) >= thresholds[t]);
                    TEST_ASSERT_EQUAL(file ? BODY_STORE_FILE : BODY_STORE_MEMORY, store.state, "policy selects storage");
                    if (!file) TEST_ASSERT(store.capacity <= (mode == BODY_STORE_MODE_AUTO ? thresholds[t] : sizeof(bytes)+1), "growth bounded including NUL");
                }
                char* copy = body_store_copy(&store, 0, sizeof(bytes));
                TEST_ASSERT_NOT_NULL(copy, "owned binary copy");
                if (copy) TEST_ASSERT(memcmp(copy, bytes, sizeof(bytes)) == 0, "binary bytes preserved");
                free(copy);
                TEST_ASSERT(body_store_materialize(&store, "/tmp"), "explicit file accessor works in every mode");
                body_store_reset(&store);
                TEST_ASSERT_EQUAL(mode, store.mode, "reset preserves mode");
                TEST_ASSERT_EQUAL(thresholds[t], store.file_threshold, "reset preserves threshold");
                TEST_ASSERT(!body_store_append(&store, bytes, sizeof(bytes)+1, "/tmp"), "body limit applies in every mode");
                TEST_ASSERT_NULL(body_store_copy(&store, 0, 0), "failure poisons reads");
                body_store_reset(&store);
            }
        }
    }
    body_store_t store;
    body_store_init(&store, 32, 1, BODY_STORE_MODE_MEMORY);
    TEST_ASSERT(body_store_append(&store, bytes, sizeof(bytes), "/missing-cwfr-directory"), "memory mode ignores automatic file threshold");
    TEST_ASSERT_EQUAL(BODY_STORE_MEMORY, store.state, "forced memory");
    body_store_reset(&store);
    body_store_init(&store, 32, 100, BODY_STORE_MODE_FILE);
    TEST_ASSERT(!body_store_append(&store, bytes, 1, "/missing-cwfr-directory"), "forced file requires usable temp directory");
    body_store_reset(&store);
}

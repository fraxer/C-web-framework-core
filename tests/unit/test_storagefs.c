/*
 * Unit tests for storage_entry_type() over a filesystem storage: what lies at a
 * path (file, directory, something else, nothing) and which paths the storage
 * refuses to resolve.
 */

#include "framework.h"
#include "storagefs.h"
#include "appconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STORAGEFS_TEST_ROOT_TEMPLATE "/tmp/cwfr-storagefs-XXXXXX"
#define STORAGEFS_TEST_NAME "storagefs_test"

/* env()/appconfig() are weak test doubles from test_httprequestparser.c;
 * appconfig()->storages starts NULL and the fixture restores it. */
extern appconfig_t* appconfig(void);

/* root/
 *   file.txt
 *   100%.txt       name that looks like a format directive
 *   dir/
 *     inner.txt
 *   link.txt -> file.txt
 */
typedef struct {
    char root[sizeof STORAGEFS_TEST_ROOT_TEMPLATE];
    char paths[5][sizeof STORAGEFS_TEST_ROOT_TEMPLATE + 16];
    storagefs_t* storage;
} storagefs_fixture_t;

enum { PATH_FILE, PATH_PERCENT, PATH_DIR, PATH_INNER, PATH_LINK };

static int write_file(const char* path) {
    FILE* file = fopen(path, "wb");
    if (file == NULL) return 0;
    const int ok = fputs("x", file) >= 0;
    return fclose(file) == 0 && ok;
}

static void storagefs_fixture_teardown(storagefs_fixture_t* fx) {
    appconfig()->storages = NULL;
    storages_free((storage_t*)fx->storage);

    unlink(fx->paths[PATH_LINK]);
    unlink(fx->paths[PATH_INNER]);
    rmdir(fx->paths[PATH_DIR]);
    unlink(fx->paths[PATH_PERCENT]);
    unlink(fx->paths[PATH_FILE]);
    TEST_ASSERT_EQUAL(0, rmdir(fx->root), "the storage root should be removed");
}

static int storagefs_fixture_setup(storagefs_fixture_t* fx) {
    memset(fx, 0, sizeof *fx);
    memcpy(fx->root, STORAGEFS_TEST_ROOT_TEMPLATE, sizeof STORAGEFS_TEST_ROOT_TEMPLATE);
    if (mkdtemp(fx->root) == NULL) return 0;

    static const char* const names[] = { "file.txt", "100%.txt", "dir", "dir/inner.txt", "link.txt" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        snprintf(fx->paths[i], sizeof fx->paths[i], "%s/%s", fx->root, names[i]);

    fx->storage = storage_create_fs(STORAGEFS_TEST_NAME, fx->root);
    const int ok = fx->storage != NULL &&
                   write_file(fx->paths[PATH_FILE]) &&
                   write_file(fx->paths[PATH_PERCENT]) &&
                   mkdir(fx->paths[PATH_DIR], 0700) == 0 &&
                   write_file(fx->paths[PATH_INNER]) &&
                   symlink("file.txt", fx->paths[PATH_LINK]) == 0;
    if (!ok) {
        storagefs_fixture_teardown(fx);
        return 0;
    }

    appconfig()->storages = (storage_t*)fx->storage;
    return 1;
}

TEST(test_storagefs_entry_type) {
    TEST_SUITE("storage: entry type");
    TEST_CASE("files, directories, symlinks and missing paths are told apart");

    storagefs_fixture_t fx;
    TEST_REQUIRE(storagefs_fixture_setup(&fx), "the storage fixture should be created");

    TEST_ASSERT_EQUAL(STORAGE_ENTRY_FILE, storage_entry_type(STORAGEFS_TEST_NAME, "file.txt"),
                      "a regular file is a file");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_FILE, storage_entry_type(STORAGEFS_TEST_NAME, "%s/%s", "dir", "inner.txt"),
                      "a file in a subdirectory is a file");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_FILE, storage_entry_type(STORAGEFS_TEST_NAME, "%s", "100%.txt"),
                      "a name with '%' passed as an argument is a file");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_DIRECTORY, storage_entry_type(STORAGEFS_TEST_NAME, "dir"),
                      "a directory is a directory");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_DIRECTORY, storage_entry_type(STORAGEFS_TEST_NAME, "dir/"),
                      "a trailing slash still names the directory");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_OTHER, storage_entry_type(STORAGEFS_TEST_NAME, "link.txt"),
                      "a symlink is not followed");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_NONE, storage_entry_type(STORAGEFS_TEST_NAME, "missing.txt"),
                      "a missing path is nothing");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_NONE, storage_entry_type("no_such_storage", "file.txt"),
                      "an unknown storage is nothing");

    storagefs_fixture_teardown(&fx);
}

TEST(test_storagefs_entry_type_rejects_escape) {
    TEST_CASE("paths leaving the storage root are refused");

    storagefs_fixture_t fx;
    TEST_REQUIRE(storagefs_fixture_setup(&fx), "the storage fixture should be created");

    /* The parent of the root is /tmp, which exists: NONE means refused. */
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_NONE, storage_entry_type(STORAGEFS_TEST_NAME, ".."),
                      "'..' alone is refused");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_NONE, storage_entry_type(STORAGEFS_TEST_NAME, "../"),
                      "'../' is refused");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_NONE, storage_entry_type(STORAGEFS_TEST_NAME, "dir/.."),
                      "a trailing '/..' is refused");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_NONE, storage_entry_type(STORAGEFS_TEST_NAME, "dir/../file.txt"),
                      "'/../' in the middle is refused");
    TEST_ASSERT_EQUAL(STORAGE_ENTRY_NONE, storage_entry_type(STORAGEFS_TEST_NAME, ""),
                      "an empty path is refused");

    storagefs_fixture_teardown(&fx);
}

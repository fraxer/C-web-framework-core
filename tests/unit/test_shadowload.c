#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "framework.h"
#include "shadowload.h"

// ============================================================================
// shadow_dlopen -- picking up a shared object that was rebuilt in place.
//
// TEST_SHADOW_V1 and TEST_SHADOW_V2 are two .so files that differ only in what
// shadow_test_version() returns, built with the same output name so they carry
// the same SONAME -- a rebuilt handler does. Every test works in its own
// directory and finishes with shadow_cleanup(), which is process-wide state.
// ============================================================================

#define SHADOW_PREFIX ".cwfr-shadow-"

static int version_of(void* handle) {
    int (*version)(void);
    *(void**)(&version) = dlsym(handle, "shadow_test_version");

    return version == NULL ? -1 : version();
}

/* Publish `source` at `destination` the way a linker does: a new file, then a
 * rename over the old name. The inode changes, which is the case dlopen() gets
 * wrong on its own. */
static int publish(const char* source, const char* destination) {
    char staging[PATH_MAX];
    snprintf(staging, sizeof staging, "%s.staging", destination);

    const int in = open(source, O_RDONLY);
    if (in == -1) return 0;

    const int out = open(staging, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (out == -1) {
        close(in);
        return 0;
    }

    char buffer[65536];
    ssize_t got;
    int ok = 1;
    while ((got = read(in, buffer, sizeof buffer)) > 0)
        if (write(out, buffer, (size_t)got) != got) {
            ok = 0;
            break;
        }

    close(out);
    close(in);

    if (!ok || rename(staging, destination) != 0) {
        unlink(staging);
        return 0;
    }

    return 1;
}

static int count_shadow_files(const char* dir) {
    DIR* handle = opendir(dir);
    if (handle == NULL) return -1;

    int count = 0;
    struct dirent* item;
    while ((item = readdir(handle)) != NULL)
        if (strncmp(item->d_name, SHADOW_PREFIX, strlen(SHADOW_PREFIX)) == 0)
            count++;

    closedir(handle);

    return count;
}

static void remove_tree(const char* dir) {
    DIR* handle = opendir(dir);
    if (handle == NULL) return;

    struct dirent* item;
    while ((item = readdir(handle)) != NULL) {
        if (strcmp(item->d_name, ".") == 0 || strcmp(item->d_name, "..") == 0) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", dir, item->d_name);
        unlink(path);
    }

    closedir(handle);
    rmdir(dir);
}

static int make_dir(char* buffer, size_t size, const char* name) {
    snprintf(buffer, size, "/tmp/cwfr_shadow_%d_%s", (int)getpid(), name);
    remove_tree(buffer);

    return mkdir(buffer, 0700) == 0;
}

TEST(test_shadow_dlopen_first_load_is_a_plain_dlopen) {
    TEST_SUITE("shadowload");

    TEST_CASE("A path that is not loaded yet is opened directly, leaving no copy");

    char dir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "first"), "Working directory created");

    char module[PATH_MAX];
    snprintf(module, sizeof module, "%s/mod.so", dir);
    TEST_REQUIRE(publish(TEST_SHADOW_V1, module), "v1 published");

    void* first = shadow_dlopen(module, RTLD_LAZY, dir);
    TEST_REQUIRE_NOT_NULL(first, "First load succeeded");
    TEST_ASSERT_EQUAL(1, version_of(first), "First load runs v1");
    TEST_ASSERT_EQUAL(0, count_shadow_files(dir), "A first load copies nothing");

    void* again = shadow_dlopen(module, RTLD_LAZY, dir);
    TEST_ASSERT(again == first, "An unchanged file is the same object, not a new one");
    TEST_ASSERT_EQUAL(0, count_shadow_files(dir), "An unchanged file copies nothing either");

    dlclose(again);
    dlclose(first);

    shadow_cleanup();
    remove_tree(dir);
}

TEST(test_shadow_dlopen_picks_up_a_rebuild) {
    TEST_SUITE("shadowload");

    TEST_CASE("A rebuilt file is loaded through a copy, and the copy outlives the unload");

    char dir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "rebuild"), "Working directory created");

    char module[PATH_MAX];
    snprintf(module, sizeof module, "%s/mod.so", dir);
    TEST_REQUIRE(publish(TEST_SHADOW_V1, module), "v1 published");

    void* old = shadow_dlopen(module, RTLD_LAZY, dir);
    TEST_REQUIRE_NOT_NULL(old, "v1 loaded");
    TEST_ASSERT_EQUAL(1, version_of(old), "v1 is what runs");

    TEST_REQUIRE(publish(TEST_SHADOW_V2, module), "v2 published over the same path");

    /* The point of the whole exercise: plain dlopen() answers with the object it
     * already has, whatever is on disk now. */
    void* plain = dlopen(module, RTLD_LAZY);
    TEST_ASSERT_EQUAL(1, version_of(plain), "dlopen on its own still returns v1");
    dlclose(plain);

    void* fresh = shadow_dlopen(module, RTLD_LAZY, dir);
    TEST_REQUIRE_NOT_NULL(fresh, "Rebuilt file loaded");
    TEST_ASSERT(fresh != old, "The rebuild is a different object");
    TEST_ASSERT_EQUAL(2, version_of(fresh), "The rebuilt code is what runs");
    TEST_ASSERT_EQUAL(1, count_shadow_files(dir), "Exactly one copy, next to the original");

    dlclose(fresh);
    TEST_ASSERT_EQUAL(1, count_shadow_files(dir),
                      "The copy survives the unload -- a core dump still symbolises it");

    dlclose(old);

    shadow_cleanup();
    TEST_ASSERT_EQUAL(0, count_shadow_files(dir), "shadow_cleanup removes what it made");

    remove_tree(dir);
}

TEST(test_shadow_dlopen_matching_rules) {
    TEST_SUITE("shadowload");

    TEST_CASE("Only a new name AND a new inode give dlopen a new object");

    char dir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "rules"), "Working directory created");

    char module[PATH_MAX], softpath[PATH_MAX], hardpath[PATH_MAX], copypath[PATH_MAX];
    snprintf(module, sizeof module, "%s/mod.so", dir);
    snprintf(softpath, sizeof softpath, "%s/link.so", dir);
    snprintf(hardpath, sizeof hardpath, "%s/hard.so", dir);
    snprintf(copypath, sizeof copypath, "%s/copy.so", dir);

    TEST_REQUIRE(publish(TEST_SHADOW_V1, module), "v1 published");
    TEST_REQUIRE(symlink(module, softpath) == 0, "Symlink created");
    TEST_REQUIRE(link(module, hardpath) == 0, "Hard link created");
    TEST_REQUIRE(publish(TEST_SHADOW_V1, copypath), "Copy created");

    void* original = dlopen(module, RTLD_LAZY);
    TEST_REQUIRE_NOT_NULL(original, "Original loaded");

    void* through_link = dlopen(softpath, RTLD_LAZY);
    TEST_ASSERT(through_link == original, "A symlink resolves to the same object");

    void* through_hard = dlopen(hardpath, RTLD_LAZY);
    TEST_ASSERT(through_hard == original, "A hard link resolves to the same object");

    void* through_copy = dlopen(copypath, RTLD_LAZY);
    TEST_ASSERT(through_copy != original, "A copy is a new object");

    dlclose(through_copy);
    dlclose(through_hard);
    dlclose(through_link);
    dlclose(original);

    shadow_cleanup();
    remove_tree(dir);
}

TEST(test_shadow_sweep_removes_only_dead_owners) {
    TEST_SUITE("shadowload");

    TEST_CASE("Startup drops copies of processes that are gone and keeps live ones");

    char dir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "sweep"), "Working directory created");

    /* A pid that is certainly not running: forked, exited, reaped. */
    const pid_t child = fork();
    TEST_REQUIRE(child != -1, "Child forked");
    if (child == 0) _exit(0);
    waitpid(child, NULL, 0);

    char dead[PATH_MAX], alive[PATH_MAX], unrelated[PATH_MAX];
    snprintf(dead, sizeof dead, "%s/%s%d-1-mod.so", dir, SHADOW_PREFIX, (int)child);
    snprintf(alive, sizeof alive, "%s/%s%d-1-mod.so", dir, SHADOW_PREFIX, (int)getpid());
    snprintf(unrelated, sizeof unrelated, "%s/keep.so", dir);

    TEST_REQUIRE(publish(TEST_SHADOW_V1, dead), "A dead process's copy left behind");
    TEST_REQUIRE(publish(TEST_SHADOW_V1, alive), "This process's own copy left behind");
    TEST_REQUIRE(publish(TEST_SHADOW_V1, unrelated), "An unrelated file left behind");

    char module[PATH_MAX];
    snprintf(module, sizeof module, "%s/mod.so", dir);
    TEST_REQUIRE(publish(TEST_SHADOW_V1, module), "v1 published");

    /* The sweep runs once per directory, on the first load out of it. */
    void* handle = shadow_dlopen(module, RTLD_LAZY, dir);
    TEST_REQUIRE_NOT_NULL(handle, "Module loaded");

    TEST_ASSERT_EQUAL(-1, access(dead, F_OK), "The dead process's copy is gone");
    TEST_ASSERT_EQUAL(0, access(alive, F_OK), "A live owner's copy is left alone");
    TEST_ASSERT_EQUAL(0, access(unrelated, F_OK), "Files without the prefix are untouched");

    dlclose(handle);

    shadow_cleanup();
    remove_tree(dir);
}

TEST(test_shadow_dlopen_falls_back_to_tmpdir) {
    TEST_SUITE("shadowload");

    TEST_CASE("A read-only directory sends the copy to tmp instead of failing the load");

    if (geteuid() == 0) {
        TEST_ASSERT(1, "Skipped: root ignores the directory's write permission");
        return;
    }

    char dir[64], tmpdir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "readonly"), "Working directory created");
    TEST_REQUIRE(make_dir(tmpdir, sizeof tmpdir, "readonly_tmp"), "tmp directory created");

    char module[PATH_MAX];
    snprintf(module, sizeof module, "%s/mod.so", dir);
    TEST_REQUIRE(publish(TEST_SHADOW_V1, module), "v1 published");

    void* old = shadow_dlopen(module, RTLD_LAZY, tmpdir);
    TEST_REQUIRE_NOT_NULL(old, "v1 loaded");

    TEST_REQUIRE(publish(TEST_SHADOW_V2, module), "v2 published over the same path");
    TEST_REQUIRE(chmod(dir, 0500) == 0, "Directory made read-only");

    void* fresh = shadow_dlopen(module, RTLD_LAZY, tmpdir);
    TEST_ASSERT_NOT_NULL(fresh, "The rebuild still loads");
    TEST_ASSERT_EQUAL(2, version_of(fresh), "And it is the rebuilt code");
    TEST_ASSERT_EQUAL(0, count_shadow_files(dir), "Nothing was written next to the original");
    TEST_ASSERT_EQUAL(1, count_shadow_files(tmpdir), "The copy went to tmp");

    if (fresh != NULL) dlclose(fresh);
    dlclose(old);

    chmod(dir, 0700);
    shadow_cleanup();
    remove_tree(tmpdir);
    remove_tree(dir);
}

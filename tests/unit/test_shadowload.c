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
#include "elfsoname.h"
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

// ============================================================================
// elfsoname -- renaming the library names inside a copy.
//
// What makes a rebuilt application module reachable at all: the copy is loaded
// under a SONAME of its own, and everything of that generation which needs it
// gets the same name in DT_NEEDED (docs/hotreload/01-soname-per-generation.md).
// ============================================================================

typedef struct {
    const char* wanted;
    const char* replacement;
} rename_one_t;

static const char* rename_one(const char* name, void* arg) {
    const rename_one_t* state = arg;

    return strcmp(name, state->wanted) == 0 ? state->replacement : NULL;
}

typedef struct {
    char soname[128];
    int needed;
} names_t;

static int collect_names(const char* name, int is_soname, void* arg) {
    names_t* state = arg;

    if (is_soname)
        snprintf(state->soname, sizeof state->soname, "%s", name);
    else
        state->needed++;

    return 1;
}

typedef struct {
    const char* wanted;
    int found;
} find_name_t;

static int find_name(const char* name, int is_soname, void* arg) {
    (void)is_soname;

    find_name_t* state = arg;
    if (strcmp(name, state->wanted) != 0) return 1;

    state->found = 1;

    return 0;
}

static int has_name(const char* path, const char* name) {
    find_name_t state = { .wanted = name, .found = 0 };

    elf_dynamic_names(path, find_name, &state);

    return state.found;
}

/* Is `name` stored as the tail of a longer string? The linker is free to merge
 * suffixes, and whether it did decides what the test can expect. */
static int name_is_merged(const char* path, const char* name) {
    FILE* file = fopen(path, "rb");
    if (file == NULL) return -1;

    static char data[4 * 1024 * 1024];
    const size_t size = fread(data, 1, sizeof data, file);
    fclose(file);

    char needle[160];
    const int length = snprintf(needle, sizeof needle, "%s", name);

    for (size_t i = 0; i + (size_t)length + 1 <= size; i++) {
        if (memcmp(data + i, needle, (size_t)length + 1) != 0) continue;
        if (i == 0) return 0;

        return data[i - 1] != 0;
    }

    return -1;
}

TEST(test_elf_rename_soname_in_place) {
    TEST_SUITE("shadowload");

    TEST_CASE("A SONAME of the same length is rewritten where it lies");

    char dir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "rename"), "Working directory created");

    char module[PATH_MAX];
    snprintf(module, sizeof module, "%s/mod.so", dir);
    TEST_REQUIRE(publish(TEST_SHADOW_V1, module), "Module published");

    names_t before = {0};
    TEST_REQUIRE(elf_dynamic_names(module, collect_names, &before), "Names read");
    TEST_REQUIRE(before.soname[0] != 0, "The module declares a SONAME");

    char tagged[128];
    snprintf(tagged, sizeof tagged, "%s", before.soname);
    const size_t length = strlen(tagged);
    tagged[length - 2] = 'z';
    tagged[length - 1] = 'z';

    rename_one_t rename = { .wanted = before.soname, .replacement = tagged };
    char reason[512] = {0};
    TEST_ASSERT(elf_rename_sonames(module, rename_one, &rename, reason, sizeof reason),
                "The rename is accepted");

    names_t after = {0};
    elf_dynamic_names(module, collect_names, &after);
    TEST_ASSERT_STR_EQUAL(tagged, after.soname, "The file now declares the new name");
    TEST_ASSERT_EQUAL(before.needed, after.needed, "Its dependencies are untouched");

    /* And the loader agrees: the object is findable under the new name and not
     * under the old one -- which is the whole point of doing this. */
    void* handle = dlopen(module, RTLD_LAZY);
    TEST_REQUIRE_NOT_NULL(handle, "The renamed copy still loads");

    void* by_new = dlopen(tagged, RTLD_LAZY | RTLD_NOLOAD);
    TEST_ASSERT_NOT_NULL(by_new, "It answers to the new SONAME");
    if (by_new != NULL) dlclose(by_new);

    void* by_old = dlopen(before.soname, RTLD_LAZY | RTLD_NOLOAD);
    TEST_ASSERT_NULL(by_old, "And no longer to the old one");
    if (by_old != NULL) dlclose(by_old);

    dlclose(handle);

    shadow_cleanup();
    remove_tree(dir);
}

TEST(test_elf_rename_refuses_a_different_length) {
    TEST_SUITE("shadowload");

    TEST_CASE("A replacement of another length is refused, not truncated");

    char dir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "length"), "Working directory created");

    char module[PATH_MAX];
    snprintf(module, sizeof module, "%s/mod.so", dir);
    TEST_REQUIRE(publish(TEST_SHADOW_V1, module), "Module published");

    names_t before = {0};
    elf_dynamic_names(module, collect_names, &before);

    rename_one_t rename = { .wanted = before.soname, .replacement = "short.so" };
    char reason[512] = {0};

    TEST_ASSERT(!elf_rename_sonames(module, rename_one, &rename, reason, sizeof reason),
                "Refused");
    TEST_ASSERT(reason[0] != 0, "And said why");

    names_t after = {0};
    elf_dynamic_names(module, collect_names, &after);
    TEST_ASSERT_STR_EQUAL(before.soname, after.soname, "The file was left alone");

    shadow_cleanup();
    remove_tree(dir);
}

TEST(test_elf_rename_refuses_merged_strings) {
    TEST_SUITE("shadowload");

    TEST_CASE("A name the linker merged into a longer one is refused");

    char dir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "merged"), "Working directory created");

    char module[PATH_MAX];
    snprintf(module, sizeof module, "%s/merged.so", dir);
    TEST_REQUIRE(publish(TEST_SHADOW_MERGED, module), "Library published");

    const int merged = name_is_merged(module, "libshadowdep.so");
    if (merged != 1) {
        /* Suffix merging is a linker's choice, not a guarantee. Where it did not
         * happen there is nothing here to refuse, and the check below would be
         * asserting the linker's behaviour rather than ours. */
        TEST_ASSERT(1, "Skipped: this linker did not merge the two names");
        remove_tree(dir);
        return;
    }

    rename_one_t rename = { .wanted = "libshadowdep.so", .replacement = "libshadowdep.zz" };
    char reason[512] = {0};

    TEST_ASSERT(!elf_rename_sonames(module, rename_one, &rename, reason, sizeof reason),
                "Refused rather than overwriting the longer name");
    TEST_ASSERT(reason[0] != 0, "And said why");

    /* Nothing was written: the file still names both libraries. Counted by name
     * and not by how many there are -- a sanitized build links more. */
    TEST_ASSERT(has_name(module, "libshadowdep.so"), "The shorter name survived");
    TEST_ASSERT(has_name(module, "libxxlibshadowdep.so"), "And so did the one holding it");

    shadow_cleanup();
    remove_tree(dir);
}

TEST(test_shadow_soname_tags_are_released_by_the_loader) {
    TEST_SUITE("shadowload");

    TEST_CASE("A tag is taken while a generation holds it and free once it is unloaded");

    char dir[64];
    TEST_REQUIRE(make_dir(dir, sizeof dir, "tags"), "Working directory created");

    char module[PATH_MAX];
    snprintf(module, sizeof module, "%s/mod.so", dir);
    TEST_REQUIRE(publish(TEST_SHADOW_V1, module), "Module published");

    names_t names = {0};
    elf_dynamic_names(module, collect_names, &names);

    shadow_sonames_t* first = shadow_sonames_create();
    TEST_REQUIRE_NOT_NULL(first, "Map created");

    char reason[512] = {0};
    TEST_REQUIRE(shadow_sonames_add(first, names.soname, reason, sizeof reason), "Tag reserved");

    const char* tag = shadow_sonames_tagged(first, names.soname);
    TEST_REQUIRE_NOT_NULL(tag, "The map knows the tag");
    TEST_ASSERT_EQUAL_SIZE(strlen(names.soname), strlen(tag), "It is the same length");

    char tagged[128];
    snprintf(tagged, sizeof tagged, "%s", tag);

    rename_one_t rename = { .wanted = names.soname, .replacement = tagged };
    TEST_REQUIRE(elf_rename_sonames(module, rename_one, &rename, reason, sizeof reason),
                 "The copy is renamed to it");

    void* handle = dlopen(module, RTLD_LAZY);
    TEST_REQUIRE_NOT_NULL(handle, "And loads");

    /* A second generation asking for a tag must not be given the live one. */
    shadow_sonames_t* second = shadow_sonames_create();
    TEST_REQUIRE_NOT_NULL(second, "Second map created");
    TEST_REQUIRE(shadow_sonames_add(second, names.soname, reason, sizeof reason),
                 "Second tag reserved");
    TEST_ASSERT(strcmp(tagged, shadow_sonames_tagged(second, names.soname)) != 0,
                "A live tag is not handed out twice");
    shadow_sonames_free(second);

    dlclose(handle);

    /* Unloaded, so the name is free again -- with no bookkeeping of ours. */
    shadow_sonames_t* third = shadow_sonames_create();
    TEST_REQUIRE_NOT_NULL(third, "Third map created");
    TEST_REQUIRE(shadow_sonames_add(third, names.soname, reason, sizeof reason),
                 "Third tag reserved");
    TEST_ASSERT_STR_EQUAL(tagged, shadow_sonames_tagged(third, names.soname),
                          "The released tag is offered again");
    shadow_sonames_free(third);

    shadow_sonames_free(first);
    shadow_cleanup();
    remove_tree(dir);
}

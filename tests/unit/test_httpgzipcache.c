/*
 * Unit tests for protocols/http/httpgzipcache.c
 *
 * The cache stores one gzip representation per static file and is bounded in
 * two directions (a total byte budget with LRU eviction, and a per-file
 * ceiling). What the cases below pin down is what makes it safe rather than
 * merely fast:
 *
 *   - the key is path + mtime + size, so a file rewritten in place is a miss,
 *     not a stale hit;
 *   - the bytes it hands out decompress to the file's bytes;
 *   - eviction never frees memory a response is still reading (refcounts);
 *   - a budget that cannot hold the entry still produces a usable answer.
 */

#include "framework.h"
#include "httpgzipcache.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <zlib.h>
#include <stdint.h>

// ============================================================================
// Helpers
// ============================================================================

typedef struct {
    char root[64];
    char path[PATH_MAX];
    int fd;
    size_t size;
    time_t mtime;
} gc_file_t;

/* Compressible content: a cache of random bytes would prove nothing about
 * compression and everything about deflate's worst case. */
static char* gc_body(size_t length) {
    char* data = malloc(length + 1);
    if (data == NULL) return NULL;

    for (size_t i = 0; i < length; i++)
        data[i] = (char)('a' + (i % 16));
    data[length] = 0;

    return data;
}

/* Deliberately incompressible, and deliberately deterministic: the size-bound
 * cases below need to know how big an entry will be, and "a body that gzip
 * shrinks by an unknown factor" is not something a budget can be written
 * against. A linear congruential sequence gives both. */
static char* gc_body_incompressible(size_t length) {
    char* data = malloc(length + 1);
    if (data == NULL) return NULL;

    uint32_t state = 0x12345678u;
    for (size_t i = 0; i < length; i++) {
        state = state * 1103515245u + 12345u;
        data[i] = (char)(state >> 16);
    }
    data[length] = 0;

    return data;
}

static int gc_write(const char* path, const char* data, size_t length) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return 0;

    const ssize_t written = write(fd, data, length);
    close(fd);

    return written == (ssize_t)length;
}

static int gc_open_with(gc_file_t* f, const char* name, size_t length, int compressible) {
    snprintf(f->path, sizeof(f->path), "%s/%s", f->root, name);

    char* data = compressible ? gc_body(length) : gc_body_incompressible(length);
    if (data == NULL) return 0;

    const int ok = gc_write(f->path, data, length);
    free(data);
    if (!ok) return 0;

    f->fd = open(f->path, O_RDONLY);
    if (f->fd < 0) return 0;

    struct stat st;
    if (fstat(f->fd, &st) != 0) return 0;

    f->size = (size_t)st.st_size;
    f->mtime = st.st_mtime;

    return 1;
}

static int gc_open(gc_file_t* f, const char* name, size_t length) {
    return gc_open_with(f, name, length, 1);
}

static void gc_close(gc_file_t* f) {
    if (f->fd >= 0) close(f->fd);
    unlink(f->path);
    f->fd = -1;
}

static int gc_root(gc_file_t* f) {
    memset(f, 0, sizeof(*f));
    f->fd = -1;
    snprintf(f->root, sizeof(f->root), "/tmp/cwfr_gzipcache_XXXXXX");

    return mkdtemp(f->root) != NULL;
}

/* Inflate what the cache handed out and compare with the file on disk: the only
 * assertion that says the entry is a representation of THIS file. */
static int gc_matches_file(const http_gzip_cache_entry_t* entry, const char* path) {
    const char* compressed = http_gzip_cache_data(entry);
    const size_t compressed_size = http_gzip_cache_data_size(entry);
    if (compressed == NULL || compressed_size == 0) return 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return 0; }

    char* expected = malloc((size_t)st.st_size);
    char* actual = malloc((size_t)st.st_size + 64);
    if (expected == NULL || actual == NULL) {
        free(expected); free(actual); close(fd);
        return 0;
    }

    const ssize_t got = read(fd, expected, (size_t)st.st_size);
    close(fd);

    int ok = 0;
    if (got == st.st_size) {
        z_stream stream;
        memset(&stream, 0, sizeof(stream));
        if (inflateInit2(&stream, MAX_WBITS + 16) == Z_OK) {
            stream.next_in = (Bytef*)compressed;
            stream.avail_in = (uInt)compressed_size;
            stream.next_out = (Bytef*)actual;
            stream.avail_out = (uInt)st.st_size + 64;

            const int r = inflate(&stream, Z_FINISH);
            ok = r == Z_STREAM_END &&
                 stream.total_out == (uLong)st.st_size &&
                 memcmp(expected, actual, (size_t)st.st_size) == 0;

            inflateEnd(&stream);
        }
    }

    free(expected);
    free(actual);

    return ok;
}

/* Leave the cache off and empty for whatever test runs next: these globals are
 * process-wide. */
static void gc_disable(void) {
    http_gzip_cache_configure(0, 0);
}

// ============================================================================
// Hit, miss and what the key means
// ============================================================================

TEST(test_gzip_cache_disabled_by_default) {
    TEST_SUITE("http_gzip_cache: configuration");
    TEST_CASE("a zero budget means no cache at all");

    gc_disable();

    gc_file_t f;
    TEST_REQUIRE(gc_root(&f), "temp root created");
    TEST_REQUIRE_GOTO(gc_open(&f, "asset.js", 4096), "file created", cleanup);

    TEST_ASSERT_EQUAL(0, http_gzip_cache_enabled(), "the cache reports itself off");
    TEST_ASSERT_NULL(http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size),
                     "and hands out nothing");

    cleanup:
    gc_close(&f);
    rmdir(f.root);
}

TEST(test_gzip_cache_stores_and_reuses) {
    TEST_SUITE("http_gzip_cache: hit and miss");
    TEST_CASE("the first request compresses, the second gets the same bytes");

    http_gzip_cache_configure(1024 * 1024, 512 * 1024);

    gc_file_t f;
    TEST_REQUIRE(gc_root(&f), "temp root created");
    TEST_REQUIRE_GOTO(gc_open(&f, "asset.js", 8192), "file created", cleanup);

    http_gzip_cache_entry_t* first = http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size);
    TEST_REQUIRE_NOT_NULL_GOTO(first, "a miss produces an entry", cleanup);
    TEST_ASSERT(gc_matches_file(first, f.path), "the entry decompresses to the file");
    TEST_ASSERT(http_gzip_cache_data_size(first) < f.size, "and it is smaller than the source");
    TEST_ASSERT_EQUAL_SIZE(1, http_gzip_cache_count(), "one entry is published");

    http_gzip_cache_entry_t* second = http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size);
    TEST_ASSERT(first == second, "the second request gets the very same entry");
    TEST_ASSERT_EQUAL_SIZE(1, http_gzip_cache_count(), "and nothing new is published");

    http_gzip_cache_release(second);
    http_gzip_cache_release(first);

    cleanup:
    gc_close(&f);
    rmdir(f.root);
    gc_disable();
}

TEST(test_gzip_cache_rejects_stale_key) {
    TEST_SUITE("http_gzip_cache: hit and miss");
    TEST_CASE("a file rewritten in place is a different resource");

    http_gzip_cache_configure(1024 * 1024, 512 * 1024);

    gc_file_t f;
    TEST_REQUIRE(gc_root(&f), "temp root created");
    TEST_REQUIRE_GOTO(gc_open(&f, "asset.js", 8192), "file created", cleanup);

    http_gzip_cache_entry_t* first = http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size);
    TEST_REQUIRE_NOT_NULL_GOTO(first, "first entry", cleanup);
    const size_t first_size = http_gzip_cache_data_size(first);
    http_gzip_cache_release(first);

    /* Same path, new content: a different size is enough to change the key, and
     * so is a different mtime — real rewrites usually change both. */
    close(f.fd);
    char* bigger = gc_body(20000);
    TEST_REQUIRE_GOTO(bigger != NULL, "replacement body", cleanup);
    const int written = gc_write(f.path, bigger, 20000);
    free(bigger);
    TEST_REQUIRE_GOTO(written, "file rewritten", cleanup);

    f.fd = open(f.path, O_RDONLY);
    TEST_REQUIRE_GOTO(f.fd >= 0, "reopened", cleanup);
    struct stat st;
    TEST_REQUIRE_GOTO(fstat(f.fd, &st) == 0, "stat", cleanup);

    http_gzip_cache_entry_t* second =
        http_gzip_cache_acquire(f.path, f.fd, st.st_mtime, (size_t)st.st_size);
    TEST_REQUIRE_NOT_NULL_GOTO(second, "second entry", cleanup);
    /* Compared by content, never by pointer: the stale entry was released and
     * freed, and an allocator is free to hand its address straight back — which
     * is exactly what TSan's allocator did to an earlier version of this case,
     * turning "not the same entry" into a coin flip. */
    TEST_ASSERT(http_gzip_cache_data_size(second) != first_size, "the bytes are the new ones");
    TEST_ASSERT(gc_matches_file(second, f.path), "which decompress to the new file");
    TEST_ASSERT_EQUAL_SIZE(1, http_gzip_cache_count(), "the old entry did not linger");

    http_gzip_cache_release(second);

    cleanup:
    gc_close(&f);
    rmdir(f.root);
    gc_disable();
}

TEST(test_gzip_cache_honours_per_file_ceiling) {
    TEST_SUITE("http_gzip_cache: limits");
    TEST_CASE("a file above the per-file ceiling is never compressed");

    http_gzip_cache_configure(1024 * 1024, 4096);

    gc_file_t f;
    TEST_REQUIRE(gc_root(&f), "temp root created");
    TEST_REQUIRE_GOTO(gc_open(&f, "big.js", 40000), "file created", cleanup);

    TEST_ASSERT_NULL(http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size),
                     "the oversized file is refused outright");
    TEST_ASSERT_EQUAL_SIZE(0, http_gzip_cache_count(), "and nothing is published");

    cleanup:
    gc_close(&f);
    rmdir(f.root);
    gc_disable();
}

TEST(test_gzip_cache_evicts_least_recently_used) {
    TEST_SUITE("http_gzip_cache: limits");
    TEST_CASE("the budget is enforced by dropping the coldest entry");

    /* Sized against bodies gzip cannot shrink: each entry is ~20 KB, so two fit
     * in 45 KB and a third cannot. Written against a known entry size on
     * purpose — with compressible bodies the budget would depend on how well
     * zlib happened to do. */
    http_gzip_cache_configure(45000, 512 * 1024);

    gc_file_t a, b, c;
    TEST_REQUIRE(gc_root(&a), "temp root created");
    memcpy(b.root, a.root, sizeof(a.root));
    memcpy(c.root, a.root, sizeof(a.root));
    b.fd = c.fd = -1;

    TEST_REQUIRE_GOTO(gc_open_with(&a, "a.js", 20000, 0), "a created", cleanup);
    TEST_REQUIRE_GOTO(gc_open_with(&b, "b.js", 20000, 0), "b created", cleanup);
    TEST_REQUIRE_GOTO(gc_open_with(&c, "c.js", 20000, 0), "c created", cleanup);

    http_gzip_cache_entry_t* ea = http_gzip_cache_acquire(a.path, a.fd, a.mtime, a.size);
    TEST_REQUIRE_NOT_NULL_GOTO(ea, "a cached", cleanup);
    http_gzip_cache_release(ea);

    http_gzip_cache_entry_t* eb = http_gzip_cache_acquire(b.path, b.fd, b.mtime, b.size);
    TEST_REQUIRE_NOT_NULL_GOTO(eb, "b cached", cleanup);
    http_gzip_cache_release(eb);

    const size_t before = http_gzip_cache_bytes();
    TEST_ASSERT(before <= 45000, "the budget holds after two entries");
    TEST_ASSERT_EQUAL_SIZE(2, http_gzip_cache_count(), "and both entries are published");

    /* Touch a, so b becomes the coldest. */
    http_gzip_cache_entry_t* again = http_gzip_cache_acquire(a.path, a.fd, a.mtime, a.size);
    TEST_REQUIRE_NOT_NULL_GOTO(again, "a is still cached", cleanup);
    TEST_ASSERT(again == ea, "and it is the same entry, not a recompression");
    http_gzip_cache_release(again);

    http_gzip_cache_entry_t* ec = http_gzip_cache_acquire(c.path, c.fd, c.mtime, c.size);
    TEST_REQUIRE_NOT_NULL_GOTO(ec, "c cached", cleanup);
    http_gzip_cache_release(ec);

    TEST_ASSERT(http_gzip_cache_bytes() <= 45000, "the budget still holds");
    /* Two of the three, never all three: the count is the check that eviction
     * actually happened, and it does not depend on a freed pointer's address
     * (which an allocator is free to hand back). */
    TEST_ASSERT_EQUAL_SIZE(2, http_gzip_cache_count(), "the third entry cost the coldest one");

    /* b was the least recently used, so it is the one that went. Asking for it
     * again must produce a fresh entry rather than the old pointer. */
    http_gzip_cache_entry_t* eb2 = http_gzip_cache_acquire(b.path, b.fd, b.mtime, b.size);
    TEST_REQUIRE_NOT_NULL_GOTO(eb2, "b re-cached", cleanup);
    TEST_ASSERT(gc_matches_file(eb2, b.path), "and it is still b's bytes");
    http_gzip_cache_release(eb2);

    cleanup:
    gc_close(&a);
    gc_close(&b);
    gc_close(&c);
    rmdir(a.root);
    gc_disable();
}

TEST(test_gzip_cache_entry_survives_eviction_while_in_use) {
    TEST_SUITE("http_gzip_cache: lifetime");
    TEST_CASE("an entry evicted under a live reader stays readable");

    http_gzip_cache_configure(35000, 512 * 1024);

    gc_file_t a, b;
    TEST_REQUIRE(gc_root(&a), "temp root created");
    memcpy(b.root, a.root, sizeof(a.root));
    b.fd = -1;

    TEST_REQUIRE_GOTO(gc_open_with(&a, "a.js", 20000, 0), "a created", cleanup);
    TEST_REQUIRE_GOTO(gc_open_with(&b, "b.js", 30000, 0), "b created", cleanup);

    /* Held, as a response being written would hold it. */
    http_gzip_cache_entry_t* held = http_gzip_cache_acquire(a.path, a.fd, a.mtime, a.size);
    TEST_REQUIRE_NOT_NULL_GOTO(held, "a cached and held", cleanup);

    /* Force the budget to give: b cannot fit next to a. */
    http_gzip_cache_entry_t* eb = http_gzip_cache_acquire(b.path, b.fd, b.mtime, b.size);
    TEST_REQUIRE_NOT_NULL_GOTO(eb, "b cached", cleanup);

    /* Whatever the cache decided about publishing, the bytes the holder is
     * reading are still its own and still correct — this is the case that would
     * be a use-after-free without refcounts. */
    TEST_ASSERT(gc_matches_file(held, a.path), "the held entry still decompresses to a");

    http_gzip_cache_release(eb);
    http_gzip_cache_release(held);

    cleanup:
    gc_close(&a);
    gc_close(&b);
    rmdir(a.root);
    gc_disable();
}

TEST(test_gzip_cache_unpublish_under_reader_keeps_bytes_alive) {
    TEST_SUITE("http_gzip_cache: lifetime");
    TEST_CASE("clearing the cache under a live reader does not pull its bytes away");

    http_gzip_cache_configure(1024 * 1024, 512 * 1024);

    gc_file_t f;
    TEST_REQUIRE(gc_root(&f), "temp root created");
    TEST_REQUIRE_GOTO(gc_open(&f, "asset.js", 16384), "file created", cleanup);

    /* Held the way a response being written holds it. */
    http_gzip_cache_entry_t* held = http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size);
    TEST_REQUIRE_NOT_NULL_GOTO(held, "entry cached and held", cleanup);

    /* This is the case refcounts exist for: the entry leaves the table while
     * someone is still reading it. Without them the read below is a
     * use-after-free — which is why the assertion decompresses the bytes rather
     * than merely looking at the pointer. */
    http_gzip_cache_clear();
    TEST_ASSERT_EQUAL_SIZE(0, http_gzip_cache_count(), "the table let go of it");
    TEST_ASSERT(gc_matches_file(held, f.path), "the reader's bytes are still its own");

    http_gzip_cache_release(held);

    /* And the next request re-publishes rather than resurrecting. */
    http_gzip_cache_entry_t* again = http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size);
    TEST_REQUIRE_NOT_NULL_GOTO(again, "re-cached", cleanup);
    TEST_ASSERT_EQUAL_SIZE(1, http_gzip_cache_count(), "one entry again");
    http_gzip_cache_release(again);

    cleanup:
    gc_close(&f);
    rmdir(f.root);
    gc_disable();
}

TEST(test_gzip_cache_serves_when_budget_cannot_hold_it) {
    TEST_SUITE("http_gzip_cache: limits");
    TEST_CASE("a body larger than the whole budget is still served, just not kept");

    /* Budget smaller than one compressed entry, ceiling large enough to admit
     * the file: the entry is produced for this caller and never published. */
    http_gzip_cache_configure(64, 512 * 1024);

    gc_file_t f;
    TEST_REQUIRE(gc_root(&f), "temp root created");
    TEST_REQUIRE_GOTO(gc_open_with(&f, "asset.js", 40000, 0), "file created", cleanup);

    http_gzip_cache_entry_t* entry = http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size);
    TEST_REQUIRE_NOT_NULL_GOTO(entry, "the caller still gets bytes", cleanup);
    TEST_ASSERT(gc_matches_file(entry, f.path), "and they are the right ones");
    TEST_ASSERT_EQUAL_SIZE(0, http_gzip_cache_count(), "but nothing was published");
    TEST_ASSERT_EQUAL_SIZE(0, http_gzip_cache_bytes(), "and the budget is untouched");

    http_gzip_cache_release(entry);

    cleanup:
    gc_close(&f);
    rmdir(f.root);
    gc_disable();
}

TEST(test_gzip_cache_clear_empties_it) {
    TEST_SUITE("http_gzip_cache: lifetime");
    TEST_CASE("clear drops everything idle");

    http_gzip_cache_configure(1024 * 1024, 512 * 1024);

    gc_file_t f;
    TEST_REQUIRE(gc_root(&f), "temp root created");
    TEST_REQUIRE_GOTO(gc_open(&f, "asset.js", 8192), "file created", cleanup);

    http_gzip_cache_entry_t* entry = http_gzip_cache_acquire(f.path, f.fd, f.mtime, f.size);
    TEST_REQUIRE_NOT_NULL_GOTO(entry, "entry cached", cleanup);
    http_gzip_cache_release(entry);

    TEST_ASSERT_EQUAL_SIZE(1, http_gzip_cache_count(), "one entry before the clear");
    http_gzip_cache_clear();
    TEST_ASSERT_EQUAL_SIZE(0, http_gzip_cache_count(), "none after it");
    TEST_ASSERT_EQUAL_SIZE(0, http_gzip_cache_bytes(), "and no bytes accounted");

    cleanup:
    gc_close(&f);
    rmdir(f.root);
    gc_disable();
}

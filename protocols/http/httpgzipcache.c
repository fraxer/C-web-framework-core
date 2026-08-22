#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include "httpgzipcache.h"
#include "gzip.h"
#include "log.h"

/* Fixed bucket count. The cache is bounded in bytes, and the number of distinct
 * static paths a server has is small next to that; a rehashing table would add
 * a moving part for no measurable gain. Collisions chain. */
#define BUCKETS 1024

struct http_gzip_cache_entry {
    char* path;
    /* What the entry is a representation OF: an entry whose source changed is
     * not stale data to be refreshed, it is a different resource. */
    time_t mtime;
    size_t source_size;

    char* data;
    size_t size;

    /* Users right now. The table itself does not count as one; `published` is
     * what says the table still points here. */
    unsigned refs;
    unsigned published : 1;

    struct http_gzip_cache_entry* hash_next;
    struct http_gzip_cache_entry* lru_prev;
    struct http_gzip_cache_entry* lru_next;
};

static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* Written by http_gzip_cache_configure before any worker exists, read
 * afterwards -- the same contract h2_policy_init works under. */
static size_t cache_total_limit = 0;
static size_t cache_max_file = 0;

static http_gzip_cache_entry_t* buckets[BUCKETS];
/* Most recently used at the head; eviction takes from the tail. */
static http_gzip_cache_entry_t* lru_head;
static http_gzip_cache_entry_t* lru_tail;
static size_t cache_bytes;
static size_t cache_entries;

static uint64_t __hash(const char* path) {
    /* FNV-1a: paths are short and this is called once per compressible
     * response, so the cheapest reasonable hash is the right one. */
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char* p = (const unsigned char*)path; *p != 0; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }

    return h;
}

static void __lru_unlink(http_gzip_cache_entry_t* entry) {
    if (entry->lru_prev != NULL) entry->lru_prev->lru_next = entry->lru_next;
    else if (lru_head == entry) lru_head = entry->lru_next;

    if (entry->lru_next != NULL) entry->lru_next->lru_prev = entry->lru_prev;
    else if (lru_tail == entry) lru_tail = entry->lru_prev;

    entry->lru_prev = NULL;
    entry->lru_next = NULL;
}

static void __lru_push_front(http_gzip_cache_entry_t* entry) {
    entry->lru_prev = NULL;
    entry->lru_next = lru_head;

    if (lru_head != NULL) lru_head->lru_prev = entry;
    lru_head = entry;
    if (lru_tail == NULL) lru_tail = entry;
}

static void __entry_free(http_gzip_cache_entry_t* entry) {
    free(entry->path);
    free(entry->data);
    free(entry);
}

/* Take the entry out of the table and the LRU order. It keeps its data as long
 * as someone is reading it; the last release frees it. */
static void __unpublish(http_gzip_cache_entry_t* entry) {
    if (!entry->published) return;

    const uint64_t hash = __hash(entry->path);
    http_gzip_cache_entry_t** slot = &buckets[hash % BUCKETS];
    while (*slot != NULL) {
        if (*slot == entry) {
            *slot = entry->hash_next;
            break;
        }
        slot = &(*slot)->hash_next;
    }

    __lru_unlink(entry);
    entry->published = 0;
    entry->hash_next = NULL;
    cache_bytes -= entry->size;
    cache_entries--;

    if (entry->refs == 0)
        __entry_free(entry);
}

/* Make room for `size` more bytes by dropping the least recently used entries
 * nobody is holding. Returns 0 when even that is not enough -- the caller then
 * serves the compressed bytes without publishing them. */
static int __make_room(size_t size) {
    if (size > cache_total_limit) return 0;

    http_gzip_cache_entry_t* candidate = lru_tail;
    while (cache_bytes + size > cache_total_limit && candidate != NULL) {
        http_gzip_cache_entry_t* prev = candidate->lru_prev;

        /* An entry in use is skipped, not waited for: the response holding it
         * is being written right now, and this path must not block on it. */
        if (candidate->refs == 0)
            __unpublish(candidate);

        candidate = prev;
    }

    return cache_bytes + size <= cache_total_limit;
}

static http_gzip_cache_entry_t* __find(const char* path, uint64_t hash) {
    for (http_gzip_cache_entry_t* e = buckets[hash % BUCKETS]; e != NULL; e = e->hash_next)
        if (strcmp(e->path, path) == 0)
            return e;

    return NULL;
}

/* Read the whole file through pread: the caller's descriptor is the one the
 * response would have served from, and moving its offset would corrupt the
 * fallback path. */
static char* __read_all(int fd, size_t size) {
    char* data = malloc(size);
    if (data == NULL) return NULL;

    size_t done = 0;
    while (done < size) {
        const ssize_t n = pread(fd, data + done, size - done, (off_t)done);
        if (n > 0) {
            done += (size_t)n;
            continue;
        }

        if (n < 0 && errno == EINTR) continue;

        /* A short read means the file changed under us (or is not what its size
         * said). Either way there is nothing to cache. */
        free(data);
        return NULL;
    }

    return data;
}

/* One-shot gzip of the whole body. Deliberately not the streaming shape the
 * filter uses: those bytes differ (Z_SYNC_FLUSH inserts empty blocks between
 * chunks), and a cache entry is compressed exactly once, so it may as well be
 * compressed in one call. The two representations stay interchangeable because
 * the ETag is weak and describes the resource, not the octets. */
static char* __compress(const char* source, size_t size, size_t* out_size) {
    gzip_t gzip;
    gzip_init(&gzip);

    /* Maximum compression, unlike the response filter's Z_BEST_SPEED: an entry
     * is compressed exactly once and then served until the file changes, so the
     * trade the filter makes (CPU now, bytes forever) is the wrong way round
     * here. The ETag is unaffected — it describes the resource, not the octets
     * (validator_mtime/validator_size), so a cache entry and a runtime-
     * compressed answer stay interchangeable. */
    if (!gzip_deflate_init_level(&gzip, Z_BEST_COMPRESSION)) return NULL;

    const size_t capacity = (size_t)deflateBound(&gzip.stream, (uLong)size) + 32;
    char* out = malloc(capacity);
    if (out == NULL) {
        gzip_free(&gzip);
        return NULL;
    }

    gzip_set_in(&gzip, source, size);
    const size_t written = gzip_deflate(&gzip, out, capacity, 1);

    const int failed = gzip_deflate_has_error(&gzip) || !gzip_is_end(&gzip) || written == 0;
    gzip_free(&gzip);

    if (failed) {
        log_error("http_gzip_cache: deflate failed for a %zu byte body\n", size);
        free(out);
        return NULL;
    }

    *out_size = written;

    return out;
}

void http_gzip_cache_configure(size_t total_bytes, size_t max_file_bytes) {
    http_gzip_cache_clear();

    pthread_mutex_lock(&cache_lock);
    cache_total_limit = total_bytes;
    cache_max_file = max_file_bytes;
    pthread_mutex_unlock(&cache_lock);
}

int http_gzip_cache_enabled(void) {
    return cache_total_limit > 0;
}

size_t http_gzip_cache_max_file(void) {
    return cache_max_file;
}

const char* http_gzip_cache_data(const http_gzip_cache_entry_t* entry) {
    return entry == NULL ? NULL : entry->data;
}

size_t http_gzip_cache_data_size(const http_gzip_cache_entry_t* entry) {
    return entry == NULL ? 0 : entry->size;
}

size_t http_gzip_cache_bytes(void) {
    pthread_mutex_lock(&cache_lock);
    const size_t bytes = cache_bytes;
    pthread_mutex_unlock(&cache_lock);

    return bytes;
}

size_t http_gzip_cache_count(void) {
    pthread_mutex_lock(&cache_lock);
    const size_t count = cache_entries;
    pthread_mutex_unlock(&cache_lock);

    return count;
}

void http_gzip_cache_release(http_gzip_cache_entry_t* entry) {
    if (entry == NULL) return;

    pthread_mutex_lock(&cache_lock);

    entry->refs--;
    /* The last reader of an entry the table has already let go frees it. An
     * entry still published stays, however cold: eviction is the LRU's job. */
    const int dead = entry->refs == 0 && !entry->published;

    pthread_mutex_unlock(&cache_lock);

    if (dead)
        __entry_free(entry);
}

void http_gzip_cache_clear(void) {
    pthread_mutex_lock(&cache_lock);

    for (size_t i = 0; i < BUCKETS; i++) {
        http_gzip_cache_entry_t* entry = buckets[i];
        while (entry != NULL) {
            http_gzip_cache_entry_t* next = entry->hash_next;
            __unpublish(entry);
            entry = next;
        }
    }

    pthread_mutex_unlock(&cache_lock);
}

http_gzip_cache_entry_t* http_gzip_cache_acquire(const char* path, int fd, time_t mtime, size_t size) {
    if (cache_total_limit == 0 || path == NULL || fd < 0) return NULL;
    if (size == 0 || size > cache_max_file) return NULL;

    const uint64_t hash = __hash(path);

    pthread_mutex_lock(&cache_lock);

    http_gzip_cache_entry_t* entry = __find(path, hash);
    if (entry != NULL) {
        if (entry->mtime == mtime && entry->source_size == size) {
            entry->refs++;
            __lru_unlink(entry);
            __lru_push_front(entry);
            pthread_mutex_unlock(&cache_lock);

            return entry;
        }

        /* Same path, different file. */
        __unpublish(entry);
    }

    pthread_mutex_unlock(&cache_lock);

    /* Compressing outside the lock is the point: it is the expensive part, and
     * holding the cache during it would serialize every miss in the process.
     * Two threads racing on the same cold path both compress; the loser's copy
     * is dropped below. */
    char* source = __read_all(fd, size);
    if (source == NULL) return NULL;

    size_t compressed_size = 0;
    char* compressed = __compress(source, size, &compressed_size);
    free(source);

    if (compressed == NULL) return NULL;

    http_gzip_cache_entry_t* fresh = calloc(1, sizeof(*fresh));
    char* path_copy = strdup(path);
    if (fresh == NULL || path_copy == NULL) {
        free(fresh);
        free(path_copy);
        free(compressed);
        return NULL;
    }

    fresh->path = path_copy;
    fresh->mtime = mtime;
    fresh->source_size = size;
    fresh->data = compressed;
    fresh->size = compressed_size;
    fresh->refs = 1;

    pthread_mutex_lock(&cache_lock);

    /* Someone may have published the same representation while we compressed.
     * Theirs wins -- it is already in the LRU order — and ours becomes an
     * unpublished entry that dies with its single reference. */
    http_gzip_cache_entry_t* published = __find(path, hash);
    if (published != NULL && published->mtime == mtime && published->source_size == size) {
        published->refs++;
        __lru_unlink(published);
        __lru_push_front(published);
        pthread_mutex_unlock(&cache_lock);

        __entry_free(fresh);

        return published;
    }

    if (published != NULL)
        __unpublish(published);

    /* No room even after evicting everything idle: serve these bytes anyway and
     * let them go when the response is done. The alternative -- refusing -- would
     * mean compressing again on the very next request. */
    if (__make_room(fresh->size)) {
        fresh->published = 1;
        fresh->hash_next = buckets[hash % BUCKETS];
        buckets[hash % BUCKETS] = fresh;
        __lru_push_front(fresh);
        cache_bytes += fresh->size;
        cache_entries++;
    }

    pthread_mutex_unlock(&cache_lock);

    return fresh;
}

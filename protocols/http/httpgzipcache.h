#ifndef __HTTP_GZIP_CACHE__
#define __HTTP_GZIP_CACHE__

#include <stddef.h>
#include <time.h>

/* In-memory cache of gzip representations of static files (docs/http2/10 §10.5,
 * step 2).
 *
 * The problem it answers is measured, not assumed: the same 92 KB asset costs
 * ~410 us of zlib per request, four times everything else the response does,
 * and it is paid again on every request for a file that never changes. Step 1
 * (a ".gz" next to the file) removes that where the build writes one; this
 * covers everything else.
 *
 * What the cache is keyed by is the whole correctness argument: path, mtime AND
 * size of the source. A file rewritten in place gets a new mtime or a new size
 * — usually both — so a stale entry cannot be served; and because the key names
 * the source rather than the wire bytes, the coding is not part of it: only one
 * representation, gzip, is ever stored.
 *
 * Bounded on purpose, in two directions: a total byte budget with LRU eviction
 * (without it this is a leak that grows with the number of distinct paths) and
 * a per-file ceiling, so one large file cannot evict everything else. Both come
 * from main.env; a zero budget disables the cache entirely, which is the
 * default.
 *
 * Entries are reference-counted because eviction and use overlap: a response
 * that is still being written holds a reference, and an entry evicted under it
 * stays alive until that reference goes away.
 *
 * Thread-safe: workers are threads of one process and share this. */

typedef struct http_gzip_cache_entry http_gzip_cache_entry_t;

/* Sizing, from main.env, applied once per config load. `total_bytes` == 0
 * disables the cache and drops whatever it held. */
void http_gzip_cache_configure(size_t total_bytes, size_t max_file_bytes);
int http_gzip_cache_enabled(void);
/* The largest source file that may be compressed into the cache. Callers check
 * it before opening anything, so an oversized file costs nothing. */
size_t http_gzip_cache_max_file(void);

/* The compressed representation of the file open on `fd`, compressing it on a
 * miss. Returns a reference the caller must release, or NULL when the cache is
 * off, the file does not qualify, or compression failed — in which case the
 * caller compresses on the fly as before.
 *
 * `fd` is read with pread(), so the caller's file position is untouched. */
http_gzip_cache_entry_t* http_gzip_cache_acquire(const char* path, int fd, time_t mtime, size_t size);
const char* http_gzip_cache_data(const http_gzip_cache_entry_t* entry);
size_t http_gzip_cache_data_size(const http_gzip_cache_entry_t* entry);
void http_gzip_cache_release(http_gzip_cache_entry_t* entry);

/* Drop every entry nobody is using and unpublish the rest. Called on a config
 * reload and at shutdown. */
void http_gzip_cache_clear(void);

/* How many bytes of compressed representation are held right now, and how many
 * entries — for tests and for whoever adds a /metrics line later. */
size_t http_gzip_cache_bytes(void);
size_t http_gzip_cache_count(void);

#endif

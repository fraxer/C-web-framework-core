#ifndef __ARENA__
#define __ARENA__

#include <stddef.h>

/* A bump allocator whose lifetime is one response.
 *
 * Why it exists: `perf` on a static-file profile put malloc/free at ~17% of the
 * server's CPU — more than HPACK, TLS bookkeeping or anything else this code
 * does (docs/http2/10 §8). Most of it is small, short-lived and freed together:
 * a response header costs three allocations (the node and both strings) and is
 * released at the end of the same response.
 *
 * The arena answers that shape directly. Allocation is a pointer bump; freeing
 * is not a per-object operation at all — arena_reset() takes the whole thing
 * back at once and KEEPS the memory, so a keep-alive connection stops calling
 * the allocator entirely after its first request.
 *
 * The cost is the usual one: a pointer into the arena must not outlive the
 * reset. Debug builds catch that — reset poisons the reclaimed blocks for
 * AddressSanitizer, so a stale read is reported at the read rather than
 * silently returning recycled bytes.
 */

typedef struct arena_block {
    struct arena_block* next;
    size_t capacity;
    size_t used;
    /* The block's bytes follow the header in the same allocation. */
    unsigned char data[];
} arena_block_t;

typedef struct arena {
    arena_block_t* head;    /* current block, where the bump happens */
    arena_block_t* spare;   /* blocks kept across reset, newest first */
    size_t block_size;      /* size of the next block to allocate */
    size_t total_bytes;     /* capacity held, for diagnostics */
} arena_t;

/* Ready to use with no allocation: the first block is taken on first use. */
void arena_init(arena_t* arena);

/* Aligned to max_align_t. Returns NULL only on allocation failure — callers
 * treat that exactly as a failed malloc. */
void* arena_alloc(arena_t* arena, size_t size);

/* Copy `length` bytes plus a terminating NUL. Returns NULL on failure. */
char* arena_strndup(arena_t* arena, const char* src, size_t length);

/* Reclaim everything handed out, keep the memory for the next round. Every
 * pointer from this arena is invalid afterwards. */
void arena_reset(arena_t* arena);

/* Give the memory back to the allocator. */
void arena_free(arena_t* arena);

#endif

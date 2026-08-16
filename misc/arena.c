#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "arena.h"

#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/asan_interface.h>
#define ARENA_POISON(p, n)   ASAN_POISON_MEMORY_REGION((p), (n))
#define ARENA_UNPOISON(p, n) ASAN_UNPOISON_MEMORY_REGION((p), (n))
#else
#define ARENA_POISON(p, n)   ((void)(p), (void)(n))
#define ARENA_UNPOISON(p, n) ((void)(p), (void)(n))
#endif

/* Enough for the header block of an ordinary response without a second block,
 * and small enough that an idle keep-alive connection does not hold much. */
#define ARENA_DEFAULT_BLOCK 2048
/* Growth is capped: a response that asks for a lot should not make every
 * following connection hold the high-water mark. */
#define ARENA_MAX_BLOCK     65536

#define ARENA_ALIGN sizeof(void*) * 2 /* max_align_t on every target here */

void arena_init(arena_t* arena) {
    if (arena == NULL) return;

    arena->head = NULL;
    arena->spare = NULL;
    arena->block_size = ARENA_DEFAULT_BLOCK;
    arena->total_bytes = 0;
}

static size_t __align_up(size_t n) {
    const size_t a = ARENA_ALIGN;
    return (n + (a - 1)) & ~(a - 1);
}

/* Take a block off the spare list if one is big enough, otherwise allocate.
 * The spare list is what makes a reset free: a keep-alive connection reuses
 * the same block for every request it ever serves. */
static arena_block_t* __block_get(arena_t* arena, size_t need) {
    arena_block_t* prev = NULL;
    for (arena_block_t* b = arena->spare; b != NULL; prev = b, b = b->next) {
        if (b->capacity < need) continue;

        if (prev == NULL) arena->spare = b->next;
        else prev->next = b->next;

        b->next = NULL;
        b->used = 0;
        ARENA_UNPOISON(b->data, b->capacity);
        return b;
    }

    size_t capacity = arena->block_size;
    if (capacity < need) capacity = need;

    arena_block_t* b = malloc(sizeof(*b) + capacity);
    if (b == NULL) return NULL;

    b->next = NULL;
    b->capacity = capacity;
    b->used = 0;

    arena->total_bytes += capacity;
    if (arena->block_size < ARENA_MAX_BLOCK)
        arena->block_size *= 2;

    return b;
}

void* arena_alloc(arena_t* arena, size_t size) {
    if (arena == NULL) return NULL;
    if (size == 0) size = 1;

    const size_t aligned = __align_up(size);
    if (aligned < size) return NULL; /* overflow */

    arena_block_t* block = arena->head;
    if (block == NULL || block->capacity - block->used < aligned) {
        arena_block_t* fresh = __block_get(arena, aligned);
        if (fresh == NULL) return NULL;

        /* The old block keeps whatever it still holds — its pointers are live
         * until the reset — so it goes on the chain, not on the spare list. */
        fresh->next = arena->head;
        arena->head = fresh;
        block = fresh;
    }

    unsigned char* p = block->data + block->used;
    block->used += aligned;

    ARENA_UNPOISON(p, size);

    return p;
}

char* arena_strndup(arena_t* arena, const char* src, size_t length) {
    char* dst = arena_alloc(arena, length + 1);
    if (dst == NULL) return NULL;

    if (length > 0 && src != NULL) memcpy(dst, src, length);
    dst[length] = '\0';

    return dst;
}

void arena_reset(arena_t* arena) {
    if (arena == NULL) return;

    arena_block_t* block = arena->head;
    while (block != NULL) {
        arena_block_t* next = block->next;

        /* Poisoned, not freed: the point of the arena is that the next request
         * costs no allocation, and the point of the poison is that a pointer
         * that outlived this reset is reported at the read instead of quietly
         * returning bytes that now belong to someone else. */
        ARENA_POISON(block->data, block->capacity);
        block->used = 0;
        block->next = arena->spare;
        arena->spare = block;

        block = next;
    }

    arena->head = NULL;
}

void arena_free(arena_t* arena) {
    if (arena == NULL) return;

    arena_reset(arena);

    arena_block_t* block = arena->spare;
    while (block != NULL) {
        arena_block_t* next = block->next;
        ARENA_UNPOISON(block->data, block->capacity);
        free(block);
        block = next;
    }

    arena_init(arena);
}

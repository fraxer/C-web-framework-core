#include "framework.h"
#include "arena.h"
#include <stddef.h>
#include <stdint.h>

TEST(test_arena_alignment_is_max_align_t) {
    TEST_CASE("every allocation is aligned to max_align_t, as arena.h promises");

    /* The block data followed a 24-byte header, so every pointer was 8 bytes
     * off a 16-byte boundary. Found by the misc_containers fuzz target. */
    arena_t arena;
    arena_init(&arena);
    for (size_t size = 1; size < 5000; size += 97) {
        void* p = arena_alloc(&arena, size);
        TEST_REQUIRE_NOT_NULL(p, "allocated");
        TEST_ASSERT_EQUAL_SIZE((size_t)0, (uintptr_t)p % _Alignof(max_align_t), "aligned");
    }
    arena_reset(&arena);
    void* p = arena_alloc(&arena, 3);
    TEST_ASSERT_EQUAL_SIZE((size_t)0, (uintptr_t)p % _Alignof(max_align_t), "aligned after a reset");
    arena_free(&arena);
}

TEST(test_arena_refuses_sizes_no_block_can_hold) {
    TEST_CASE("a size the block header would wrap around is refused");

    /* sizeof(header) + capacity wrapped to a few bytes, malloc succeeded, and
     * the caller was handed a pointer "to" SIZE_MAX bytes. */
    arena_t arena;
    arena_init(&arena);
    for (size_t k = 0; k < 256; k++)
        TEST_ASSERT_NULL(arena_alloc(&arena, SIZE_MAX - k), "refused");
    TEST_ASSERT_NULL(arena_alloc(&arena, (size_t)PTRDIFF_MAX + 1), "past PTRDIFF_MAX: refused");
    TEST_ASSERT_EQUAL_SIZE((size_t)0, arena.total_bytes, "nothing was allocated");
    TEST_ASSERT_NOT_NULL(arena_alloc(&arena, 16), "an ordinary size still works");
    arena_free(&arena);
}

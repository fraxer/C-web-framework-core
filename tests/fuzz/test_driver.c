/* Exercise the actual GCC mutator, including bytes beyond the logical input.
 * ASan cannot detect reading stale bytes inside an allocated input buffer. */
#define main fuzz_driver_main
#include "fuzz_main.c"
#undef main

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void)data;
    (void)size;
    return 0;
}

int main(void) {
    for (size_t cap = 9; cap <= 32; cap++) {
        uint8_t a[33], b[33];
        memset(a, 0xaa, sizeof a);
        memset(b, 0xbb, sizeof b);
        memcpy(a, "ABCDEFGH", 8);
        memcpy(b, "ABCDEFGH", 8);
        /* This seed chooses duplication as its first mutation. */
        __rng_state = 17;
        const size_t na = __mutate(a, 8, cap);
        __rng_state = 17;
        const size_t nb = __mutate(b, 8, cap);
        if (na <= 8 || na > cap || na != nb || memcmp(a, b, na) != 0 ||
            a[cap] != 0xaa || b[cap] != 0xbb) {
            fprintf(stderr, "duplicate mutation depends on tail or exceeds cap=%zu\n", cap);
            return 1;
        }
        if (cap >= 10 && (na != 10 || memcmp(a, "ABCDEDEFGH", 10) != 0)) {
            fprintf(stderr, "duplicate mutation lost the input suffix\n");
            return 1;
        }
    }
    puts("GCC mutator regression passed");
    return 0;
}

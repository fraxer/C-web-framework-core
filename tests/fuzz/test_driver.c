/* Exercise the actual GCC mutator, including bytes beyond the logical input.
 * ASan cannot detect reading stale bytes inside an allocated input buffer. */
#define main fuzz_driver_main
#include "fuzz_main.c"
#undef main

/* Edges by hand: this file is built without coverage, so each input reaches
 * exactly the edges these calls report -- one per function, since the driver
 * hashes the caller's return address. */
__attribute__((noinline)) static void __edge_a(void) { __sanitizer_cov_trace_pc(); }
__attribute__((noinline)) static void __edge_b(void) { __sanitizer_cov_trace_pc(); }
__attribute__((noinline)) static void __edge_c(void) { __sanitizer_cov_trace_pc(); }
__attribute__((noinline)) static void __edge_second_b(void) { __sanitizer_cov_trace_pc(); }

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (data[i] == 'a') __edge_a();
        if (data[i] == 'b') __edge_b();
        if (data[i] == 'c') __edge_c();
    }
    if (size >= 2 && data[1] == 'b') __edge_second_b();
    return 0;
}

static void __put(const char* dir, const char* name, const char* text) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE* f = fopen(path, "wb");
    if (f == NULL) return;
    fwrite(text, 1, strlen(text), f);
    fclose(f);
}

static size_t __files(const char* dir) {
    size_t n = 0;
    DIR* d = opendir(dir);
    if (d == NULL) return 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) n += e->d_name[0] != '.';
    closedir(d);
    return n;
}

/* -minimize keeps the smallest inputs that together reach what the corpus
 * reaches, beyond what the base already does, and writes nothing else. */
static int __minimize_test(void) {
    char base[] = "/tmp/fuzz-min-base-XXXXXX", corpus[] = "/tmp/fuzz-min-corpus-XXXXXX",
         out[] = "/tmp/fuzz-min-out-XXXXXX";
    if (mkdtemp(base) == NULL || mkdtemp(corpus) == NULL || mkdtemp(out) == NULL) return 1;

    __put(base, "seed", "a");
    __put(corpus, "1", "a");      /* the base has it */
    __put(corpus, "2", "bb");     /* nothing "b" and "ab" do not */
    __put(corpus, "3", "ab");     /* the second 'b' */
    __put(corpus, "4", "b");
    __put(corpus, "5", "c");

    size_t kept = 0, total = 0;
    const int rc = __minimize(base, corpus, out, &kept, &total);
    const size_t written = __files(out);

    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s %s %s", base, corpus, out);
    if (system(cmd) != 0) return 1;

    if (rc != 0 || total != 5 || kept != 3 || written != 3) {
        fprintf(stderr, "minimize: rc %d, kept %zu of %zu, %zu files written\n", rc, kept, total, written);
        return 1;
    }
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

    if (__minimize_test() != 0) return 1;
    puts("corpus minimisation passed");
    return 0;
}

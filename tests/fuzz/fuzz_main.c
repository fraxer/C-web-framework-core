/* A coverage-guided fuzzing driver, because this machine has no clang.
 *
 * libFuzzer is a clang runtime and gcc has no equivalent, but gcc *does* have
 * `-fsanitize-coverage=trace-pc`: a call to __sanitizer_cov_trace_pc() on every
 * edge. That is the same signal libFuzzer feeds on, so the missing part is only
 * the loop -- a few hundred lines of bitmap, corpus and mutation, which is what
 * this file is. Targets keep libFuzzer's entry point (fuzz_targets.c), so
 * installing clang later replaces this driver and nothing else.
 *
 * Deliberately simple where simplicity is free: the corpus lives in memory, the
 * mutations are the classic six, and the schedule is uniform. What it must not
 * skimp on is the crash report -- a fuzzer that finds a crash and cannot say
 * which bytes caused it has found nothing.
 *
 * Usage: fuzz_<target> [-seconds=N] [-runs=N] [-seed=N] [corpus_dir]
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

/* ---- Coverage ---- *
 *
 * Edges are hashed by return address into a bitmap. Collisions cost coverage
 * resolution, never correctness: two edges landing in one bucket make the
 * fuzzer blind to the second, not wrong about the first. */

#define COV_BITS 16
#define COV_SIZE (1u << COV_BITS)

static uint8_t  __cov_map[COV_SIZE];
static uint64_t __cov_hits;

void __sanitizer_cov_trace_pc(void);

/* The hook must not be instrumented, or it calls itself: the flag is global, so
 * this file is compiled with coverage too, and the first edge inside the
 * callback lands back in the callback. It shows up as a stack overflow in the
 * hook itself -- an honest report of a fuzzer eating its own tail. */
__attribute__((no_sanitize_coverage))
void __sanitizer_cov_trace_pc(void) {
    const uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    const uint32_t h = (uint32_t)((pc >> 4) ^ (pc >> 12) ^ (pc << 3));

    __cov_map[h & (COV_SIZE - 1)] = 1;
    __cov_hits++;
}

static size_t __cov_count(void) {
    size_t n = 0;
    for (size_t i = 0; i < COV_SIZE; i++) n += __cov_map[i];

    return n;
}

/* ---- Corpus ---- */

#define CORPUS_MAX      4096
#define INPUT_MAX       8192

typedef struct {
    uint8_t* data;
    size_t   len;
} input_t;

static input_t __corpus[CORPUS_MAX];
static size_t  __corpus_count;

static void __corpus_add(const uint8_t* data, size_t len) {
    if (__corpus_count >= CORPUS_MAX || len > INPUT_MAX) return;

    uint8_t* copy = malloc(len > 0 ? len : 1);
    if (copy == NULL) return;

    memcpy(copy, data, len);
    __corpus[__corpus_count].data = copy;
    __corpus[__corpus_count].len = len;
    __corpus_count++;
}

static void __corpus_load(const char* dir) {
    DIR* d = opendir(dir);
    if (d == NULL) return;

    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;

        char path[4096];
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);

        FILE* f = fopen(path, "rb");
        if (f == NULL) continue;

        uint8_t buf[INPUT_MAX];
        const size_t n = fread(buf, 1, sizeof buf, f);
        fclose(f);

        __corpus_add(buf, n);
    }

    closedir(d);
}

/* ---- Random ---- */

static uint64_t __rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t __rnd(void) {
    uint64_t x = __rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    __rng_state = x;

    return x;
}

static size_t __rnd_below(size_t n) {
    return n == 0 ? 0 : (size_t)(__rnd() % n);
}

/* ---- Mutation ---- */

static size_t __mutate(uint8_t* buf, size_t len, size_t cap) {
    switch (__rnd() % 6) {
    case 0:   /* flip a bit */
        if (len > 0) buf[__rnd_below(len)] ^= (uint8_t)(1u << (__rnd() % 8));
        break;

    case 1:   /* set a byte, favouring the values protocols care about */
        if (len > 0) {
            static const uint8_t interesting[] = {
                0x00, 0x01, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff
            };
            buf[__rnd_below(len)] = (__rnd() % 2)
                ? interesting[__rnd() % (sizeof interesting)]
                : (uint8_t)__rnd();
        }
        break;

    case 2:   /* grow */
        if (len < cap) {
            const size_t add = 1 + __rnd_below(cap - len < 16 ? cap - len : 16);
            for (size_t i = 0; i < add; i++) buf[len + i] = (uint8_t)__rnd();
            len += add;
        }
        break;

    case 3:   /* shrink */
        if (len > 1) len -= 1 + __rnd_below(len / 2);
        break;

    case 4:   /* splice a piece of another corpus entry over this one */
        if (len > 0 && __corpus_count > 0) {
            const input_t* other = &__corpus[__rnd_below(__corpus_count)];
            if (other->len > 0) {
                const size_t n = 1 + __rnd_below(other->len < len ? other->len : len);
                const size_t at = __rnd_below(len - n + 1);
                memcpy(buf + at, other->data, n);
            }
        }
        break;

    default:  /* duplicate a run in place -- what makes a length field lie */
        if (len > 1 && len < cap) {
            const size_t n = 1 + __rnd_below(len / 2);
            const size_t at = __rnd_below(len - n);
            const size_t room = cap - len < n ? cap - len : n;
            memmove(buf + at + room, buf + at, len - at - room);
            len += room;
        }
        break;
    }

    return len;
}

/* ---- Crash reporting ---- *
 *
 * The sanitizer aborts the process, so the input has to be recoverable from
 * outside the run. ASan calls this on the way out, and by then the bytes that
 * caused it are still in memory. */

static const uint8_t* __current;
static size_t __current_len;
static const char* __artifact_dir = ".";
static const char* __corpus_dir;

/* Keep what found new coverage, so the next run starts where this one stopped.
 * Without it every run re-derives the same inputs from the seeds, and §5's
 * "24 hours per target" would mean 24 hours in one sitting. Named by content
 * hash, so re-running never duplicates an entry. */
static void __corpus_save(const uint8_t* data, size_t len) {
    if (__corpus_dir == NULL) return;

    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }

    char path[4096];
    snprintf(path, sizeof path, "%s/id-%016llx", __corpus_dir,
             (unsigned long long)h);

    FILE* f = fopen(path, "wb");
    if (f == NULL) return;

    fwrite(data, 1, len, f);
    fclose(f);
}

void __sanitizer_set_death_callback(void (*callback)(void));

static void __on_death(void) {
    if (__current == NULL) return;

    char path[4096];
    snprintf(path, sizeof path, "%s/crash-%u.bin", __artifact_dir, (unsigned)getpid());

    FILE* f = fopen(path, "wb");
    if (f != NULL) {
        fwrite(__current, 1, __current_len, f);
        fclose(f);
    }

    fprintf(stderr, "\n[fuzz] crashing input (%zu bytes) written to %s\n",
            __current_len, path);
}

/* A target may also fail an invariant of its own, by trapping or aborting.
 * The sanitizer's death callback does not fire for those -- it is for errors
 * the sanitizer itself detects -- so the process died silently and the input
 * that caused it was lost. Which is the one thing this driver's whole crash
 * path exists to prevent (see the header): a fuzzer that finds a crash and
 * cannot say which bytes found it has reported nothing.
 *
 * SIGILL and SIGABRT only. SIGSEGV and friends belong to the sanitizer, and
 * taking them from it would replace its report with this one. */
static void __on_signal(int sig) {
    __on_death();

    signal(sig, SIG_DFL);
    raise(sig);
}

static void __run(const uint8_t* data, size_t len) {
    __current = data;
    __current_len = len;

    LLVMFuzzerTestOneInput(data, len);

    __current = NULL;
}

int main(int argc, char* argv[]) {
    unsigned seconds = 60;
    uint64_t runs = 0;   /* 0 = unlimited, bounded by time */
    const char* corpus_dir = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-seconds=", 9) == 0) seconds = (unsigned)atoi(argv[i] + 9);
        else if (strncmp(argv[i], "-runs=", 6) == 0) runs = strtoull(argv[i] + 6, NULL, 10);
        else if (strncmp(argv[i], "-seed=", 6) == 0) __rng_state = strtoull(argv[i] + 6, NULL, 10) | 1;
        else if (strncmp(argv[i], "-artifacts=", 11) == 0) __artifact_dir = argv[i] + 11;
        else corpus_dir = argv[i];
    }

    __sanitizer_set_death_callback(__on_death);
    signal(SIGILL, __on_signal);
    signal(SIGABRT, __on_signal);

    __corpus_dir = corpus_dir;
    if (corpus_dir != NULL) __corpus_load(corpus_dir);

    /* An empty corpus is not fatal, it is just a slower start: the mutator
     * grows inputs out of nothing soon enough. */
    if (__corpus_count == 0) {
        static const uint8_t empty = 0;
        __corpus_add(&empty, 1);
    }

    const size_t seeded = __corpus_count;

    /* The seeds themselves first: they are the coverage the corpus was chosen
     * for, and a crash on one of them should not wait for a mutation. */
    for (size_t i = 0; i < __corpus_count; i++)
        __run(__corpus[i].data, __corpus[i].len);

    size_t base_cov = __cov_count();

    uint8_t buf[INPUT_MAX];
    uint64_t executed = 0;
    size_t found = 0;

    const time_t deadline = time(NULL) + (time_t)seconds;

    while ((runs == 0 || executed < runs) && time(NULL) < deadline) {
        const input_t* pick = &__corpus[__rnd_below(__corpus_count)];

        size_t len = pick->len < sizeof buf ? pick->len : sizeof buf;
        memcpy(buf, pick->data, len);

        const size_t rounds = 1 + __rnd_below(4);
        for (size_t i = 0; i < rounds; i++) len = __mutate(buf, len, sizeof buf);

        __run(buf, len);
        executed++;

        const size_t cov = __cov_count();
        if (cov > base_cov) {
            base_cov = cov;
            __corpus_add(buf, len);
            __corpus_save(buf, len);
            found++;
        }
    }

    printf("%-22s %8llu runs, corpus %zu (+%zu from %zu seeds), "
           "%zu edges, %llu hits\n",
           argv[0], (unsigned long long)executed, __corpus_count, found, seeded,
           base_cov, (unsigned long long)__cov_hits);

    for (size_t i = 0; i < __corpus_count; i++) free(__corpus[i].data);

    return 0;
}

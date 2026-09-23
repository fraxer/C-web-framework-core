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
#include <fcntl.h>
#include <limits.h>
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
#define INPUT_LIMIT     (1024u * 1024u)
static size_t __input_max = 8192;

typedef struct {
    uint8_t* data;
    size_t   len;
} input_t;

static input_t __corpus[CORPUS_MAX];
static size_t  __corpus_count;

static void __corpus_add(const uint8_t* data, size_t len) {
    if (__corpus_count >= CORPUS_MAX || len > __input_max) return;

    uint8_t* copy = malloc(len > 0 ? len : 1);
    if (copy == NULL) return;

    memcpy(copy, data, len);
    __corpus[__corpus_count].data = copy;
    __corpus[__corpus_count].len = len;
    __corpus_count++;
}

static void __corpus_load(const char* dir) {
    struct stat st;
    if (stat(dir, &st) == 0 && S_ISREG(st.st_mode)) {
        /* A single file is an input to replay, and it is replayed whole: one
         * saved by a run with a larger -max_len must not be cut to this one's. */
        if ((size_t)st.st_size > __input_max && (size_t)st.st_size <= INPUT_LIMIT)
            __input_max = (size_t)st.st_size;
        FILE* f = fopen(dir, "rb");
        if (f == NULL) return;
        uint8_t* buf = malloc(__input_max);
        if (buf != NULL) {
            const size_t n = fread(buf, 1, __input_max, f);
            __corpus_add(buf, n);
            free(buf);
        }
        fclose(f);
        return;
    }
    DIR* d = opendir(dir);
    if (d == NULL) return;

    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;

        char path[4096];
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);

        FILE* f = fopen(path, "rb");
        if (f == NULL) continue;

        uint8_t* buf = malloc(__input_max);
        if (buf == NULL) { fclose(f); break; }
        const size_t n = fread(buf, 1, __input_max, f);
        fclose(f);

        __corpus_add(buf, n);
        free(buf);
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

/* ---- Dictionary ----
 *
 * Mutating bytes at random gets to a malformed header quickly and to a
 * well-spelled one slowly: "Transfer-Encoding" is seventeen bytes that have to
 * land in order before the branch behind it is worth anything. A dictionary is
 * the standard answer, and the format is libFuzzer's so that the same file
 * works when the targets are built with clang. Note that libFuzzer's own
 * parser is the stricter of the two -- it knows \\xNN, \\\\ and \\" and nothing
 * else, and rejects the whole file on the first line it cannot read -- so a
 * dictionary meant for both stays inside that subset, however much \\r\\n
 * would read better:
 *
 *     # comment
 *     name="token"
 *     "\r\n"
 *     "\x82"
 *
 * The name before '=' is documentation; only the quoted token is used. */

#define DICT_MAX 256

static input_t __dict[DICT_MAX];
static size_t  __dict_count;

static int __dict_hex(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* One line to one token. Returns the token length, or 0 for a line that holds
 * none -- a comment, a blank, or something malformed, all of which are skipped
 * rather than treated as an error: a dictionary is an optimisation, and a
 * typo in it must not stop a run. */
static size_t __dict_parse_line(const char* line, uint8_t* out, size_t cap) {
    const char* p = strchr(line, '"');
    if (p == NULL) return 0;
    p++;

    size_t n = 0;
    while (*p != '\0' && *p != '"' && n < cap) {
        if (*p != '\\') {
            out[n++] = (uint8_t)*p++;
            continue;
        }

        p++;
        switch (*p) {
        case 'n':  out[n++] = '\n'; p++; break;
        case 'r':  out[n++] = '\r'; p++; break;
        case 't':  out[n++] = '\t'; p++; break;
        case '\\': out[n++] = '\\'; p++; break;
        case '"':  out[n++] = '"';  p++; break;
        case 'x': {
            const int hi = __dict_hex(p[1]);
            const int lo = hi < 0 ? -1 : __dict_hex(p[2]);
            if (lo < 0) return 0;
            out[n++] = (uint8_t)((hi << 4) | lo);
            p += 3;
            break;
        }
        default: return 0;
        }
    }

    return n;
}

static void __dict_load(const char* path) {
    FILE* f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "[fuzz] dictionary %s not readable, continuing without it\n", path);
        return;
    }

    char line[1024];
    uint8_t token[256];

    while (fgets(line, sizeof line, f) != NULL && __dict_count < DICT_MAX) {
        const char* trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (*trimmed == '#' || *trimmed == '\n' || *trimmed == '\0') continue;

        const size_t n = __dict_parse_line(trimmed, token, sizeof token);
        if (n == 0) continue;

        uint8_t* copy = malloc(n);
        if (copy == NULL) break;

        memcpy(copy, token, n);
        __dict[__dict_count].data = copy;
        __dict[__dict_count].len = n;
        __dict_count++;
    }

    fclose(f);
}

/* ---- Mutation ---- */

static size_t __mutate(uint8_t* buf, size_t len, size_t cap) {
    /* The dictionary strategy only exists when there is a dictionary, so that
     * a run without one keeps exactly the distribution it had before. */
    const uint64_t strategies = __dict_count > 0 ? 7 : 6;

    switch (__rnd() % strategies) {
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

    case 6: {  /* write a dictionary token in, or splice one over what is there */
        const input_t* tok = &__dict[__rnd_below(__dict_count)];
        if (tok->len == 0 || tok->len > cap) break;

        const size_t at = __rnd_below(len + 1 > cap - tok->len + 1 ? cap - tok->len + 1 : len + 1);

        if ((__rnd() % 2) && len + tok->len <= cap) {
            /* Insert: the bytes after the point move along, which is what
               grows a request one header at a time. */
            memmove(buf + at + tok->len, buf + at, len - at);
            memcpy(buf + at, tok->data, tok->len);
            len += tok->len;
        }
        else if (at + tok->len <= cap) {
            memcpy(buf + at, tok->data, tok->len);
            if (at + tok->len > len) len = at + tok->len;
        }
        break;
    }

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
static unsigned __input_timeout = 5;
static char __crash_path[4096];

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

/* UBSan does not run the death callback above: with -fno-sanitize-recover it
 * reports and exits, and the input that caused it was lost -- a failed run
 * with nothing to replay. Asking it to abort instead routes it through
 * __on_signal, which saves the input. UBSAN_OPTIONS still overrides this. */
const char* __ubsan_default_options(void);
const char* __ubsan_default_options(void) {
    return "halt_on_error=1:abort_on_error=1:print_stacktrace=1";
}

static void __on_death(void) {
    if (__current == NULL || __crash_path[0] == '\0') return;

    const int fd = open(__crash_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        size_t off = 0;
        while (off < __current_len) {
            const ssize_t n = write(fd, __current + off, __current_len - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
        close(fd);
    }
    static const char msg[] = "\n[fuzz] failing input saved to artifact directory\n";
    (void)write(STDERR_FILENO, msg, sizeof msg - 1);
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
    if (sig == SIGALRM) {
        static const char msg[] = "\n[fuzz] input exceeded -timeout\n";
        (void)write(STDERR_FILENO, msg, sizeof msg - 1);
    }
    __on_death();
    _exit(128 + sig);
}

static void __run(const uint8_t* data, size_t len) {
    __current = data;
    __current_len = len;
    alarm(__input_timeout);
    LLVMFuzzerTestOneInput(data, len);
    alarm(0);
    __current = NULL;
}

int main(int argc, char* argv[]) {
    unsigned seconds = 60;
    uint64_t runs = 0;   /* 0 = unlimited, bounded by time */
    const char* corpus_dir = NULL;
    int replay_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-seconds=", 9) == 0) seconds = (unsigned)atoi(argv[i] + 9);
        else if (strncmp(argv[i], "-runs=", 6) == 0) runs = strtoull(argv[i] + 6, NULL, 10);
        else if (strncmp(argv[i], "-seed=", 6) == 0) __rng_state = strtoull(argv[i] + 6, NULL, 10) | 1;
        else if (strncmp(argv[i], "-artifacts=", 11) == 0) __artifact_dir = argv[i] + 11;
        else if (strncmp(argv[i], "-dict=", 6) == 0) __dict_load(argv[i] + 6);
        else if (strncmp(argv[i], "-timeout=", 9) == 0) __input_timeout = (unsigned)strtoul(argv[i] + 9, NULL, 10);
        else if (strncmp(argv[i], "-max_len=", 9) == 0) __input_max = (size_t)strtoull(argv[i] + 9, NULL, 10);
        else corpus_dir = argv[i];
    }

    if (__input_timeout == 0 || __input_max == 0 || __input_max > INPUT_LIMIT) {
        fprintf(stderr, "[fuzz] timeout and max_len must be positive; max_len <= %u\n", INPUT_LIMIT);
        return 2;
    }
    if (corpus_dir != NULL) {
        struct stat st;
        replay_only = stat(corpus_dir, &st) == 0 && S_ISREG(st.st_mode);
    }

    /* Replaying a saved input must not save it again: the verdict is the exit
     * status, and a copy in the working directory is litter. */
    if (!replay_only)
        snprintf(__crash_path, sizeof __crash_path, "%s/crash-%u.bin",
                 __artifact_dir, (unsigned)getpid());

    __sanitizer_set_death_callback(__on_death);
    signal(SIGILL, __on_signal);
    signal(SIGABRT, __on_signal);
    signal(SIGALRM, __on_signal);

    __corpus_dir = replay_only ? NULL : corpus_dir;
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

    if (replay_only) {
        printf("replayed %s (%zu bytes)\n", corpus_dir, __corpus[0].len);
        for (size_t i = 0; i < __corpus_count; i++) free(__corpus[i].data);
        for (size_t i = 0; i < __dict_count; i++) free(__dict[i].data);
        return 0;
    }

    size_t base_cov = __cov_count();

    uint8_t* buf = malloc(__input_max);
    if (buf == NULL) return 2;
    uint64_t executed = 0;
    size_t found = 0;

    const time_t deadline = time(NULL) + (time_t)seconds;

    while ((runs == 0 || executed < runs) && time(NULL) < deadline) {
        const input_t* pick = &__corpus[__rnd_below(__corpus_count)];

        size_t len = pick->len < __input_max ? pick->len : __input_max;
        memcpy(buf, pick->data, len);

        const size_t rounds = 1 + __rnd_below(4);
        for (size_t i = 0; i < rounds; i++) len = __mutate(buf, len, __input_max);

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

    /* The dictionary is reported whether one was asked for or not: a run that
     * silently loaded nothing and a run that was never given a file look the
     * same from the outside otherwise, and the difference is the whole point
     * of passing one. */
    char dict_note[32] = "";
    if (__dict_count > 0)
        snprintf(dict_note, sizeof dict_note, ", dict %zu", __dict_count);

    printf("%-22s %8llu runs, corpus %zu (+%zu from %zu seeds), "
           "%zu edges, %llu hits%s\n",
           argv[0], (unsigned long long)executed, __corpus_count, found, seeded,
           base_cov, (unsigned long long)__cov_hits, dict_note);

    for (size_t i = 0; i < __dict_count; i++) free(__dict[i].data);
    for (size_t i = 0; i < __corpus_count; i++) free(__corpus[i].data);
    free(buf);

    return 0;
}

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "log.h"
#include "quicqlog.h"
#include "quictime.h"

/* One event line. Longer than any event this server emits (the widest is a
 * connection_started with two addresses), and a bound rather than a heap
 * allocation because this runs on the packet path: an event that would not fit
 * is truncated, which costs one unreadable line, where an allocation failure
 * here would cost a branch on every event forever. */
#define QUICQLOG_LINE_MAX 1024
#define QUICQLOG_DIR_MAX  256
/* Two hex digits per byte of a connection id (RFC 9000 §5.1 caps it at 20),
 * plus the extension and the terminator. */
#define QUICQLOG_NAME_MAX 64

struct quicqlog {
    FILE*    file;
    /* Event times are relative to this, in milliseconds -- what the qlog schema
     * calls a relative time format. Absolute wall-clock times would make every
     * line 13 characters longer and still need this subtraction to be read. */
    uint64_t start_us;
};

/* ---- Process-wide configuration ----
 *
 * The budget is atomic because connections are accepted on several workers at
 * once and the limit is the only thing standing between "logging is on" and
 * "every connection on a busy server writes a file". The directory is a string,
 * so it takes a lock instead: a reload may rewrite it while a worker is
 * building a path out of it, and that is a use-after-free waiting to happen if
 * it were a pointer, or a torn path if it were an unguarded buffer.
 *
 * The lock is taken once per logged connection and never on the packet path. */
static pthread_mutex_t __config_lock = PTHREAD_MUTEX_INITIALIZER;
static char __dir[QUICQLOG_DIR_MAX];
static atomic_int __budget;

int quicqlog_configure(const char* dir, unsigned connections) {
    if (dir == NULL) dir = "";

    const size_t len = strlen(dir);
    if (len >= sizeof __dir) {
        log_error("quic: http3_qlog_dir is longer than %zu characters\n",
                  sizeof __dir - 1);
        return 0;
    }

    /* Created here rather than at the first connection: a directory that cannot
     * be created is a configuration error, and an operator who turned qlog on
     * has to learn that at load time and not from an empty directory an hour
     * later. mkdir is one level -- a path whose parent does not exist is the
     * operator's mistake, and reported as such. */
    if (len > 0 && mkdir(dir, 0755) == -1 && errno != EEXIST) {
        log_error("quic: cannot create http3_qlog_dir '%s' (errno %d)\n",
                  dir, errno);
        return 0;
    }

    pthread_mutex_lock(&__config_lock);
    memcpy(__dir, dir, len + 1);
    pthread_mutex_unlock(&__config_lock);

    /* Re-armed on every load, including a reload. Deliberate: an operator who
     * enables qlog by reloading wants the next N connections logged, and a
     * budget that survived the reload would give them nothing. */
    atomic_store_explicit(&__budget, len == 0 ? 0 : (int)connections,
                          memory_order_relaxed);

    if (len > 0)
        log_info("quic: qlog enabled, %u connections into %s\n", connections, dir);

    return 1;
}

/* One connection's share of the budget, or 0. A compare-exchange rather than a
 * fetch_sub: a decrement past zero would let a burst of accepts each see a
 * negative count as "one more available" once the counter wrapped. */
static int __budget_take(void) {
    int left = atomic_load_explicit(&__budget, memory_order_relaxed);

    while (left > 0)
        if (atomic_compare_exchange_weak_explicit(&__budget, &left, left - 1,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
            return 1;

    return 0;
}

static void __hex(const uint8_t* data, size_t len, char* out) {
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }

    out[len * 2] = 0;
}

quicqlog_t* quicqlog_open(const uint8_t* odcid, size_t odcid_len) {
    if (odcid == NULL || odcid_len == 0 || odcid_len > 20) return NULL;
    if (!__budget_take()) return NULL;

    char path[QUICQLOG_DIR_MAX + QUICQLOG_NAME_MAX];
    char id[41];
    __hex(odcid, odcid_len, id);

    pthread_mutex_lock(&__config_lock);
    const int written = __dir[0] == 0
        ? -1 : snprintf(path, sizeof path, "%s/%s.sqlog", __dir, id);
    pthread_mutex_unlock(&__config_lock);

    if (written < 0 || (size_t)written >= sizeof path) return NULL;

    quicqlog_t* q = malloc(sizeof * q);
    if (q == NULL) return NULL;

    q->file = fopen(path, "w");
    if (q->file == NULL) {
        /* Reported once per connection that could not be logged, which is
         * bounded by the budget: a full disk or a directory that turned
         * read-only must be visible, and cannot flood the log. */
        log_error("quic: cannot open qlog file '%s' (errno %d)\n", path, errno);
        free(q);
        return NULL;
    }

    /* Line-buffered, for the reason in the header: the events before a silence
     * are what a hang is diagnosed from, and a buffer holding them when the
     * process is killed holds exactly the part that mattered. */
    setvbuf(q->file, NULL, _IOLBF, QUICQLOG_LINE_MAX);

    q->start_us = quic_now_us();

    /* The wall-clock moment the trace starts, so a qlog can be lined up against
     * the server log and a packet capture. Everything after it is relative to
     * it, in milliseconds. */
    struct timespec wall;
    const double epoch_ms = clock_gettime(CLOCK_REALTIME, &wall) == 0
        ? (double)wall.tv_sec * 1000.0 + (double)wall.tv_nsec / 1000000.0 : 0.0;

    fprintf(q->file,
            "\x1e{\"qlog_format\":\"JSON-SEQ\",\"qlog_version\":\"0.3\","
            "\"title\":\"cwfr\",\"trace\":{"
            "\"vantage_point\":{\"name\":\"cwfr\",\"type\":\"server\"},"
            "\"common_fields\":{\"ODCID\":\"%s\",\"time_format\":\"relative\","
            "\"reference_time\":%.3f}}}\n",
            id, epoch_ms);

    return q;
}

void quicqlog_close(quicqlog_t* q) {
    if (q == NULL) return;

    if (q->file != NULL) fclose(q->file);

    free(q);
}

void quicqlog_escape(const char* in, size_t len, char* out, size_t out_len) {
    if (out == NULL || out_len == 0) return;

    static const char digits[] = "0123456789abcdef";
    size_t w = 0;

    for (size_t i = 0; i < len && in != NULL; i++) {
        const unsigned char c = (unsigned char)in[i];
        char piece[7];
        size_t plen;

        if (c == '"' || c == '\\') {
            piece[0] = '\\';
            piece[1] = (char)c;
            plen = 2;
        }
        else if (c >= 0x20 && c < 0x7f) {
            piece[0] = (char)c;
            plen = 1;
        }
        else {
            /* Escaped one byte at a time, so a truncated UTF-8 sequence -- which
             * a peer may well send -- still produces valid JSON rather than an
             * unparseable trace. */
            memcpy(piece, "\\u00", 4);
            piece[4] = digits[c >> 4];
            piece[5] = digits[c & 0x0f];
            plen = 6;
        }

        if (w + plen >= out_len) break;

        memcpy(out + w, piece, plen);
        w += plen;
    }

    out[w] = 0;
}

void quicqlog_event(quicqlog_t* q, const char* category, const char* event,
                    const char* fmt, ...) {
    if (q == NULL || q->file == NULL) return;

    char data[QUICQLOG_LINE_MAX];
    va_list args;
    va_start(args, fmt);
    const int n = vsnprintf(data, sizeof data, fmt, args);
    va_end(args);

    if (n < 0) return;

    const uint64_t now = quic_now_us();
    const double at_ms = now > q->start_us
        ? (double)(now - q->start_us) / 1000.0 : 0.0;

    /* One fprintf, not several: the line is what the reader parses, and a line
     * interleaved with another one is a corrupt trace. Nothing here shares a
     * file between connections, but a build that ever did would break silently
     * otherwise. */
    fprintf(q->file, "\x1e{\"time\":%.3f,\"name\":\"%s:%s\",\"data\":{%s}}\n",
            at_ms, category, event, data);
}

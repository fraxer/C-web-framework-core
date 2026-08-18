#ifndef __QUICQLOG__
#define __QUICQLOG__

#include <stddef.h>
#include <stdint.h>

/* qlog (draft-ietf-quic-qlog-*): structured event log of a QUIC connection.
 *
 * QUIC is an encrypted binary protocol over a lossy transport: what a
 * connection did is not in a packet capture without keys, not in the response,
 * and only partly in the counters -- /metrics says how often something happened
 * across the process, never in what order it happened to one peer. That order
 * is the whole question whenever a connection stalls, and it is why this exists
 * (docs/http3/04-quic-transport.md §10).
 *
 * It lives in quic/common rather than quic/transport because every layer emits
 * into it, and a diagnostics facility must not be something the lower layers
 * depend upwards on.
 *
 * ## What it costs when it is off
 *
 * A NULL check per call site, and nothing else -- the log is a pointer a
 * connection either has or does not. It is deliberately NOT behind a build flag
 * any more: the incidents this is for are the ones where the server is already
 * running (docs/http3/08 §7j), and a facility that needs a rebuild before it
 * can answer is a facility that answers after the incident. `http3_qlog_dir`
 * turns it on, and `http3_qlog_connections` bounds how many connections get
 * one, because logging every connection on a busy server is itself a denial of
 * service.
 *
 * ## Threading
 *
 * A log belongs to one connection and is written only by the worker serving it,
 * under connection_s_lock -- the same rule every other field of quicconn_t
 * follows. Nothing here is thread-safe on its own, and it does not need to be.
 * The process-wide configuration is the exception (a reload can change it while
 * workers run) and takes a lock of its own.
 *
 * ## Output
 *
 * JSON-SEQ (RFC 7464): one record per line, each prefixed with 0x1E, written to
 * `<dir>/<odcid>.sqlog`. That is the format qvis (qvis.quictools.info) reads,
 * and being able to drop the file into an existing visualiser is most of the
 * value -- the alternative is writing a viewer for our own log format.
 *
 * Lines are flushed as they are written. A log that loses its tail is worth
 * very little for the failure it is most often opened for -- a connection that
 * hung, where the last events before the silence are the answer -- and the cost
 * is a write() per event on a path that at most `http3_qlog_connections`
 * connections are on. */

struct quicqlog;
typedef struct quicqlog quicqlog_t;

/* Process-wide configuration, from `http3_qlog_dir` / `http3_qlog_connections`.
 * An empty or NULL directory disables logging. Called on every config load,
 * including a reload -- which re-arms the connection budget, so turning qlog on
 * by reload logs the next N connections rather than nothing.
 *
 * The directory is created if it does not exist. Returns 0 when it could not
 * be, having logged why; the caller may treat that as a configuration error. */
int quicqlog_configure(const char* dir, unsigned connections);

/* Open the log for one connection, or return NULL -- because logging is off,
 * because the budget is spent, or because the file could not be created. NULL
 * is the ordinary case and not an error: every call site is a QLOG(), which
 * does nothing with it. */
quicqlog_t* quicqlog_open(const uint8_t* odcid, size_t odcid_len);

/* Ends the trace and releases the file. Safe on NULL. */
void quicqlog_close(quicqlog_t* q);

/* Emit one event.
 *
 *   QLOG(q, "recovery", "packet_lost", "\"pn\":%llu", (unsigned long long)pn);
 *
 * `category` and `event` are the qlog event identity; the remaining arguments
 * are a printf format and its arguments producing the body of the event's
 * "data" object (no surrounding braces -- the writer adds them). */
void quicqlog_event(quicqlog_t* q, const char* category, const char* event,
                    const char* fmt, ...) __attribute__((format(printf, 4, 5)));

/* JSON-escape peer-supplied bytes into `out`, always NUL-terminated, truncated
 * to fit. Anything a peer chose -- a CONNECTION_CLOSE reason, an ALPN, a header
 * name -- has to go through this: a quote or a newline in the middle of an
 * event does not corrupt one field, it corrupts the whole trace, and the peer
 * picks those bytes. Non-printable and non-ASCII bytes become \uXXXX, so the
 * output is valid JSON whatever arrived. */
void quicqlog_escape(const char* in, size_t len, char* out, size_t out_len);

/* The argument is evaluated once, and the format arguments only when a log is
 * actually open -- so a call site may compute its values inline without paying
 * for them on a connection that is not being logged. */
#define QLOG(q, category, event, ...)                                          \
    do {                                                                       \
        quicqlog_t* __qlog_target = (q);                                       \
        if (__qlog_target != NULL)                                             \
            quicqlog_event(__qlog_target, (category), (event), __VA_ARGS__);   \
    } while (0)

#endif

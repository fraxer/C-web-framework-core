#ifndef __QUICQLOG__
#define __QUICQLOG__

#include <stdio.h>

/* qlog (draft-ietf-quic-qlog-*): structured event log of a QUIC connection.
 *
 * Introduced as a stub in phase 0 and implemented in phase 4
 * (docs/http3/04-quic-transport.md §10). It is here from the start on purpose:
 * QUIC is an encrypted binary protocol over a lossy transport, and the events
 * worth logging have to be emitted from inside the packet, crypto, recovery and
 * HTTP/3 paths as those are written. Retrofitting them afterwards means
 * re-reading every one of those paths, which is exactly the work qlog is meant
 * to save. Existing visualisers (qvis) read the format directly.
 *
 * It lives in quic/common rather than quic/transport because every layer emits
 * into it, and a diagnostics facility must not be something the lower layers
 * depend upwards on.
 *
 * Off unless CWFR_QUIC_QLOG is defined AND a log has been opened for the
 * connection: on a busy server, logging every connection is itself a denial of
 * service, so phase 7 gates it to the first N connections
 * (docs/http3/07-integration.md §1.2, http3_qlog_connections). */

struct quicqlog;
typedef struct quicqlog quicqlog_t;

/* Emit one event.
 *
 *   QLOG(q, "recovery", "packet_lost", "\"pn\":%llu", (unsigned long long)pn);
 *
 * `category` and `event` are the qlog event identity; the remaining arguments
 * are a printf format and its arguments producing the body of the event's
 * "data" object (no surrounding braces -- the writer adds them).
 *
 * The stub discards everything. It deliberately still type-checks the format
 * and its arguments, in an unevaluated sizeof: a call site written in phase 1
 * against a stub that ignored its arguments would silently rot until phase 4
 * turned the macro on, and the compiler would then report the accumulated
 * mistakes all at once, in code nobody has looked at for weeks. sizeof() emits
 * no code at any optimisation level, so this costs nothing at runtime. */
#ifdef CWFR_QUIC_QLOG

void quicqlog_event(quicqlog_t* q, const char* category, const char* event,
                    const char* fmt, ...) __attribute__((format(printf, 4, 5)));

#define QLOG(q, category, event, ...) \
    quicqlog_event((q), (category), (event), __VA_ARGS__)

#else

#define QLOG(q, category, event, ...) \
    ((void)(q), (void)(category), (void)(event), \
     (void)sizeof(printf(__VA_ARGS__)))

#endif

#endif

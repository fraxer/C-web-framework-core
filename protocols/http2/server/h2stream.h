#ifndef __H2STREAM__
#define __H2STREAM__

#include <stdint.h>

#include "httprequest.h"
#include "httpresponse.h"

/* One HTTP/2 stream (RFC 9113 §5). Phase 4 keeps several of these alive at once
 * on a connection; the session owns the table.
 *
 * Concurrency: every field is touched only while connection_s_lock() is held.
 * That covers all three visitors — the worker's read path, its write path, and
 * a handler thread (connection_queue_guard_pop hands the connection over with
 * the lock already taken and holds it for the whole handler run). So the fields
 * below need no atomics, and a stream cannot be destroyed underneath a handler.
 * The one thing that ordering does NOT rule out is a RST_STREAM arriving while
 * a handler is still queued, which is what `cancelled` is for. */

/* Receive-side flow-control state of one flow — a stream, or the connection
 * itself (RFC 9113 §6.9). Shared shape so one tuner serves both; see
 * h2_recv_credit() in h2session.c. */
typedef struct {
    int64_t  size;      /* window currently advertised to the peer */
    int64_t  pending;   /* consumed by the peer, not yet given back */
    int64_t  bytes;     /* received since epoch_ms — the rate sample */
    uint64_t epoch_ms;  /* start of the current rate sample (CLOCK_MONOTONIC) */
} h2_recv_window_t;

typedef enum {
    H2_STREAM_IDLE = 0,
    H2_STREAM_OPEN,               /* HEADERS received, END_STREAM not yet */
    H2_STREAM_HALF_CLOSED_REMOTE, /* request complete, response still owed */
    H2_STREAM_CLOSED,
} h2stream_state_e;

typedef struct h2stream {
    uint32_t id;
    h2stream_state_e state;

    /* Reused unchanged from HTTP/1.1, one pair per stream instead of one pair
     * per connection. The stream owns both. */
    httprequest_t*  request;
    httpresponse_t* response;

    /* Send-side flow-control window for this stream (RFC 9113 §6.9). Signed: a
     * SETTINGS_INITIAL_WINDOW_SIZE decrease may drive it negative, which is
     * legal and must not wrap. */
    int64_t send_window;
    /* Receive side: advertised window plus the counters that auto-scale it. */
    h2_recv_window_t recv;

    size_t  req_body_len;   /* DATA bytes spooled into request->payload_.file */
    int64_t content_length; /* declared, or -1 when the request carried none */

    /* Scheduling: bytes this stream may still put on the wire during the current
     * write turn. Refilled per turn by the write path, spent by the write filter,
     * which yields at the next DATA frame boundary once it runs out. Signed —
     * the frame that empties it overshoots, and the deficit is not carried. */
    int64_t write_credit;

    unsigned handler_pending : 1; /* queued for, or running in, a handler thread */
    unsigned response_ready  : 1; /* handler returned; the response may be sent */
    unsigned cancelled       : 1; /* reset by the peer — discard the response */
    unsigned headers_done    : 1; /* the request header block is complete */
    unsigned end_stream_sent : 1; /* the response already carried END_STREAM */
    unsigned window_blocked  : 1; /* body stalled waiting on a WINDOW_UPDATE */
    unsigned yielded         : 1; /* quantum spent; more body still to send */
    unsigned served          : 1; /* already had its turn in this write pass */

    struct h2stream* next;        /* session stream list */
} h2stream_t;

struct h2session;

/* Create a stream and append it to the session table. Returns NULL on allocation
 * failure. The request is created here too, since every stream has one.
 * Appending (rather than prepending) makes the table's order the order requests
 * arrived in, which is what the round-robin write scheduler walks. */
h2stream_t* h2stream_create(struct h2session* session, uint32_t id);

h2stream_t* h2stream_find(struct h2session* session, uint32_t id);
/* Locate the stream owning a response — the seam the write filter and the
 * post-handler hook come back through, since both only hold the response. */
h2stream_t* h2stream_find_by_response(struct h2session* session, const httpresponse_t* response);

/* Detach from the session table and free, along with its request/response. A
 * stream with a handler still pending is kept alive and marked cancelled
 * instead; it is freed once the handler comes back. */
void h2stream_close(struct h2session* session, h2stream_t* stream);

/* Move a stream to the end of the table. The write scheduler calls this on a
 * stream that stopped before finishing its response, so the next write turn
 * starts with somebody else — this is what makes the walk round-robin rather
 * than "whoever is nearest the head wins". */
void h2stream_rotate(struct h2session* session, h2stream_t* stream);

/* Free every stream in the table (session teardown). */
void h2stream_free_all(struct h2session* session);

/* Number of streams still occupying a concurrency slot. */
size_t h2stream_active_count(struct h2session* session);

#endif

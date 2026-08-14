#ifndef __H2DATA__
#define __H2DATA__

#include <stddef.h>
#include <stdint.h>

#include "bufo.h"
#include "h2frame.h"
#include "h2stream.h"

/* Cutting a byte stream into DATA frames on one stream — docs/http2/09 §4.3.
 *
 * Extracted from h2_write_filter.c rather than reimplemented, because two
 * callers now need it: ordinary responses coming down the filter chain, and
 * WebSocket frames going into an RFC 8441 tunnel. The arithmetic it does —
 * chunking by the peer's max frame size, debiting both flow-control windows,
 * spending the write quantum, and yielding only ever on a frame boundary — is
 * the h2 write scheduler's contract. A second copy of it would be a second
 * place to fix, and the copies would drift.
 *
 * The state below is what makes it resumable: a frame half-written to a
 * saturated socket must continue byte for byte on the next EPOLLOUT, and a
 * frame header half-written must not be rebuilt. */

struct h2session;

typedef enum {
    H2_DATA_DRAINED = 0, /* the source has no bytes left */
    H2_DATA_SOCKET,      /* the socket would block — possibly mid-frame */
    H2_DATA_WINDOW,      /* out of flow-control window, stopped on a boundary */
    H2_DATA_YIELD,       /* write quantum spent, stopped on a boundary */
    H2_DATA_ERROR,
} h2_data_status_e;

/* Payload up to this size travels in the same write as its frame header.
 *
 * The header is nine bytes, and sending it on its own costs a syscall and --
 * over TLS, which is the only way h2 is served here -- a whole record: 22 bytes
 * of overhead and an AEAD seal to carry nine bytes of length. Measured on
 * `robots.txt`: three writes of 39, 31 and 131 bytes per response, where nginx
 * does one (docs/http2/10 §1).
 *
 * The bound is what keeps the cure from being worse: a copy is cheap next to a
 * syscall only while it is small. Above it the payload goes straight from the
 * caller's buffer as before, and one extra header write per 16 KB frame is
 * noise. */
#define H2_DATA_JOIN_MAX 2048

typedef struct h2_data_writer {
    uint8_t  fh[H2_FRAME_HEADER_LEN];
    size_t   fh_len;              /* 0 = no frame header pending or being built */
    size_t   fh_pos;
    size_t   frame_remaining;     /* payload bytes still owed for this frame */
    unsigned frame_end_stream : 1;

    /* Header and a small payload, joined. `join_payload` is how many of the
     * bytes past the header came from `src`: the source is only advanced, and
     * the windows only debited, once the whole buffer has left -- a partial
     * write must not be counted twice when the socket comes back. */
    uint8_t  join[H2_DATA_JOIN_MAX + H2_FRAME_HEADER_LEN + H2_DATA_JOIN_MAX];
    size_t   join_len;            /* 0 = nothing joined and pending */
    size_t   join_pos;
    size_t   join_payload;
    size_t   join_prefix;         /* prefix bytes that went into `join` */

    /* Bytes that must precede the first DATA frame -- the response's HEADERS
     * block, handed over by the write filter instead of being sent on its own.
     *
     * Sending it separately doubled the *client's* work, not ours: over TLS
     * each record costs the peer two reads (five bytes of length, then the
     * body), so two records per response meant 4.3 reads per response against
     * 2.2 for nginx, and a benchmark client that spent 8.8 us of CPU per
     * request against 3.3 (docs/http2/10 §6).
     *
     * Not owned here: the buffer belongs to the filter and outlives the write. */
    const uint8_t* prefix;
    size_t   prefix_len;
    size_t   prefix_pos;
} h2_data_writer_t;

/* Hand the writer bytes to put in front of the first DATA frame. Must be called
 * before the first h2_data_write of the response, and the memory must stay put
 * until the write completes. */
void h2_data_writer_prefix(h2_data_writer_t* w, const uint8_t* data, size_t len);

/* Push out a prefix that never found a DATA frame to ride with -- a response
 * that turned out to have no body at all. Returns the same statuses as
 * h2_data_write. */
h2_data_status_e h2_data_flush_prefix(h2_data_writer_t* w, struct h2session* s);

void h2_data_writer_reset(h2_data_writer_t* w);

/* Push as much of `src` as the windows, the quantum and the socket allow.
 *
 * END_STREAM rides the frame carrying the final byte when `src->is_last` and
 * `end_stream_allowed` agree. Two gates rather than one because the reasons are
 * different and both real: `is_last` is "this is the end of the data", while
 * end_stream_allowed is "the stream may end here at all" — false for a tunnel,
 * and false for a response whose trailing HEADERS block still has to follow
 * (RFC 9113 §8.1, docs/http2/08 phase E.1).
 *
 * Advances src->pos by what was written, sets stream->yielded / window_blocked
 * on the matching outcomes, and leaves `w` positioned to resume. */
h2_data_status_e h2_data_write(h2_data_writer_t* w, struct h2session* s,
                               h2stream_t* stream, bufo_t* src, int end_stream_allowed);

#endif

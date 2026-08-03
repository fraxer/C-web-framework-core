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

typedef struct h2_data_writer {
    uint8_t  fh[H2_FRAME_HEADER_LEN];
    size_t   fh_len;              /* 0 = no frame header pending or being built */
    size_t   fh_pos;
    size_t   frame_remaining;     /* payload bytes still owed for this frame */
    unsigned frame_end_stream : 1;
} h2_data_writer_t;

void h2_data_writer_reset(h2_data_writer_t* w);

/* Push as much of `src` as the windows, the quantum and the socket allow.
 *
 * `src->is_last` asks for END_STREAM on the frame that carries the final byte;
 * a tunnel passes 0 there, since ending the stream is exactly what it must not
 * do. Advances src->pos by what was written, sets stream->yielded /
 * window_blocked on the matching outcomes, and leaves `w` positioned to resume.
 */
h2_data_status_e h2_data_write(h2_data_writer_t* w, struct h2session* s,
                               h2stream_t* stream, bufo_t* src);

#endif

#ifndef __H2_WRITE_FILTER__
#define __H2_WRITE_FILTER__

#include "http_filter.h"
#include "h2stream.h"
#include "httpresponse.h"

/* Terminal stage of the HTTP/2 filter chain (see filters_create_h2).
 *
 * Where http_write_filter emits a status line + headers + raw body bytes, this
 * one emits a HEADERS frame (HPACK-compressed, split into CONTINUATION frames
 * when it exceeds the peer's max frame size) followed by DATA frames carrying
 * whatever the upstream stages (range, data, gzip) produced. Send-side flow
 * control is honoured here: the body is chopped to the smaller of the peer's
 * max frame size and the connection/stream send windows. So is the scheduler's
 * write quantum — once a stream has spent it, this stage stops at the next DATA
 * frame boundary and reports CWF_EVENT_AGAIN, which is how a large response is
 * kept from monopolising the connection.
 *
 * Every earlier stage is shared with HTTP/1.1 verbatim — this is the only
 * protocol-specific stage. */
http_filter_t* h2_write_filter_create(void);

struct h2session;

/* Encode the response's trailing fields into a HEADERS block with END_STREAM and
 * queue it (RFC 9113 §8.1) — docs/http2/08, phase E.1. Queued rather than
 * written directly: the block is small, and going through the session's
 * outbound buffer keeps it behind every DATA byte already on the socket without
 * a second resumable-write path. Returns 1 on success. */
int h2_write_filter_trailers(struct h2session* s, h2stream_t* stream, httpresponse_t* response);

/* Encode one informational response (103 Early Hints) into a HEADERS block and
 * queue it — docs/http2/08, phase E.2. No END_STREAM: a 1xx is not the final
 * response, and the stream carries on. `fields` is borrowed, not consumed. */
int h2_write_filter_early_hints(struct h2session* s, h2stream_t* stream,
                                const http_header_t* fields);

/* Encode an interim 100 (Continue) — a :status and nothing else — and queue it
 * (RFC 9110 §10.1.1) — docs/http2/10, T.2. Sent from the read path as soon as a
 * request that expects it has its headers in, since its whole purpose is to
 * arrive before the body the client is holding back. Returns 1 on success. */
int h2_write_filter_continue(struct h2session* s, h2stream_t* stream);

#endif

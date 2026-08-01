#ifndef __H2_WRITE_FILTER__
#define __H2_WRITE_FILTER__

#include "http_filter.h"

/* Terminal stage of the HTTP/2 filter chain (see filters_create_h2).
 *
 * Where http_write_filter emits a status line + headers + raw body bytes, this
 * one emits a HEADERS frame (HPACK-compressed, split into CONTINUATION frames
 * when it exceeds the peer's max frame size) followed by DATA frames carrying
 * whatever the upstream stages (range, data, gzip) produced. Send-side flow
 * control is honoured here: the body is chopped to the smaller of the peer's
 * max frame size and the connection/stream send windows.
 *
 * Every earlier stage is shared with HTTP/1.1 verbatim — this is the only
 * protocol-specific stage. */
http_filter_t* h2_write_filter_create(void);

#endif

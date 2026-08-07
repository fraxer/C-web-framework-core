#ifndef __H3_WRITE_FILTER__
#define __H3_WRITE_FILTER__

#include "http_filter.h"

/* Terminal stage of the HTTP/3 filter chain (see filters_create_h3).
 *
 * Every stage before it -- not_modified, range, data, gzip -- is shared with
 * HTTP/1.1 and HTTP/2 unchanged. This one emits a QPACK-compressed HEADERS
 * frame and then DATA frames, onto a QUIC stream rather than a socket.
 *
 * It is markedly smaller than h2_write_filter, and the reasons are worth
 * naming because they are what HTTP/3 bought: QUIC owns both flow-control
 * windows, so nothing is debited here; a HEADERS frame has no size limit, so
 * there are no CONTINUATION frames; the transport schedules streams, so there
 * is no write quantum; and the stream's FIN replaces END_STREAM, so the flag
 * does not have to be placed on the right frame.
 *
 * What replaces all of it is one thing h2 never needed: a stopping point. A TCP
 * write stops when the socket says so, but quicsendbuf_write always accepts,
 * so how far to run ahead of the network is a decision -- taken against the
 * connection's write-ahead budget in h3data.c. */
http_filter_t* h3_write_filter_create(void);

#endif

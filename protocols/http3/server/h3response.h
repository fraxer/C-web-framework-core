#ifndef __H3RESPONSE__
#define __H3RESPONSE__

#include <stddef.h>
#include <stdint.h>

#include "httpcommon.h"
#include "httpresponse.h"

struct qpack_encoder;

/* Turning an httpresponse_t into HTTP/3 bytes (RFC 9114 §4.1, §7.2).
 *
 * Extracted from the write filter before the write filter exists, for the
 * reason h2data.{c,h} was extracted after it: two callers need the same
 * encoding -- ordinary responses coming down the filter chain, and the
 * Extended CONNECT tunnel of §8 -- and two copies would drift. Keeping it
 * free of the session and the socket also makes it the part of the response
 * path that can be tested byte for byte today.
 *
 * What is *not* here is everything h2 needed and h3 does not: no window
 * accounting (the transport owns it), no CONTINUATION frames (a HEADERS frame
 * is one frame however long), no END_STREAM flag (the stream's FIN says it).
 * That is most of why §6.3 of the plan calls the h3 filter the simpler one. */

typedef enum {
    H3RESPONSE_OK = 0,
    H3RESPONSE_ERR_MEMORY,
    H3RESPONSE_ERR_ENCODE    /* QPACK refused the field list */
} h3response_status_e;

/* Encode a final response's `:status` plus its fields as one HEADERS frame.
 * `*out` is a malloc'd buffer the caller frees. Connection-specific fields are
 * dropped (§4.2), names are lowercased, and the sensitive ones go out as
 * never-indexed literals. */
h3response_status_e h3response_headers(struct qpack_encoder* enc,
                                       const httpresponse_t* response,
                                       uint8_t** out, size_t* out_len);

/* An informational response: `:status` and the given fields, nothing else.
 * Covers both 100 (Continue), which carries no fields at all, and 103 (Early
 * Hints), which carries Link fields. `fields` is borrowed. */
h3response_status_e h3response_informational(struct qpack_encoder* enc, int status_code,
                                             const http_header_t* fields,
                                             uint8_t** out, size_t* out_len);

/* Trailing fields as a second HEADERS frame (§4.1). No `:status` -- a trailer
 * section carries no pseudo-header -- and no content-length, which by then
 * describes a body already delivered. */
h3response_status_e h3response_trailers(struct qpack_encoder* enc,
                                        const http_header_t* trailers,
                                        uint8_t** out, size_t* out_len);

/* ---- DATA framing ---- */

/* A response body is one DATA frame of unbounded length as far as the RFC is
 * concerned. It is cut at this size anyway, so no single frame header commits
 * the writer to a length it may not be able to finish, and so a stalled stream
 * holds one chunk rather than a whole file (docs/http3/05-http3.md §6.3). */
#define H3_DATA_CHUNK_MAX (16 * 1024)

/* Write a DATA frame header for `payload_len` bytes. The payload follows
 * verbatim -- there is nothing to escape and no flags to set. Returns bytes
 * written, or 0 if they do not fit. At most 9 bytes are ever needed. */
size_t h3response_data_header(uint8_t* dst, size_t cap, uint64_t payload_len);

#endif

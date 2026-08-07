#ifndef __H2FIELD__
#define __H2FIELD__

#include <stddef.h>

/* Field name/value octet validity, shared by HTTP/2 (RFC 9113 §8.2.1) and
 * HTTP/3 (RFC 9114 §4.3, whose rules are identical) — docs/http2/08 phase B.
 *
 * Kept self-contained on purpose: no dependency beyond stddef, so the rules can
 * be unit-tested octet by octet without a connection, a session or a decoder.
 * It lives in the shared http layer (not under protocols/http2) because both
 * h2 and h3 build requests through protocols/http/httpfields.c against it.
 *
 * A field that fails any of these makes the request malformed (§8.1.1 / §4.1.1),
 * which costs the stream and nothing else.
 *
 * What HPACK/QPACK hands back is bytes. Nothing before this point looks at them:
 * the decoder copies whatever the peer encoded, so without this a value
 * containing CR LF travels intact into the request, the application, the log
 * file, and — the case that actually bites — into any HTTP/1.1 request the
 * application builds from it downstream, where those two bytes end a header and
 * start another one.
 *
 * The names keep the "h2_" prefix for history; the rules are not h2-specific. */

typedef enum {
    H2_FIELD_OK = 0,
    H2_FIELD_BAD_NAME,
    H2_FIELD_BAD_VALUE,
} h2_field_status_e;

/* Validate one decoded field. `name` may be a pseudo-header (leading ':'); the
 * caller decides whether a pseudo-header is allowed where it appeared. */
h2_field_status_e h2_field_validate(const char* name, size_t name_len,
                                    const char* value, size_t value_len);

/* The two halves, exposed for tests and for callers that only hold one side. */
int h2_field_name_valid(const char* name, size_t len);
int h2_field_value_valid(const char* value, size_t len);

#endif

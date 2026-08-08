#ifndef __HTTPFIELDS__
#define __HTTPFIELDS__

#include <stddef.h>
#include <stdint.h>

#include "httprequest.h"

struct httpresponse;

/* The protocol-agnostic half of request construction: turn a decoded field
 * list into an httprequest_t, applying the request validity rules of RFC 9113
 * §8.3/§8.2 (h2) and RFC 9114 §4.1-§4.3 (h3). The two are word-for-word on every
 * rule this function enforces, which is the whole reason it exists: a rule
 * fixed in one protocol and forgotten in the other has bitten this project
 * before (the h1.1/h2 divergence noted in docs/http2/08 phase B).
 *
 * The protocol-dependent half (HPACK/QPACK decode, decoded-list size
 * accounting) stays in the caller; this function takes the field list as bytes.
 * Virtual-host selection is left to the caller too -- it needs the connection,
 * and keeping it out keeps this function unit-testable. On HTTP_FIELDS_OK the
 * request carries the Host field (from :authority), which the caller feeds to
 * select_server. (docs/http3/05-http3.md §6.1.) */

typedef enum { HTTP_FIELDS_H2, HTTP_FIELDS_H3 } http_fields_proto_e;

typedef enum {
    HTTP_FIELDS_OK = 0,
    HTTP_FIELDS_MALFORMED,         /* stream error: H3_MESSAGE_ERROR / h2 PROTOCOL_ERROR */
    HTTP_FIELDS_INTERNAL,          /* allocation failure */
    HTTP_FIELDS_EXTENDED_CONNECT,  /* RFC 8441/9220 :protocol we do not serve → 501 */
    HTTP_FIELDS_WEBSOCKET          /* :protocol websocket → open a tunnel */
} http_fields_status_e;

/* Layout-compatible with hpack_header_t (protocols/http2/hpack) and
 * qpack_header_t (protocols/http3/qpack): {name, name_len, value, value_len,
 * never_indexed}. Callers pass their decoded array cast to this type; a
 * _Static_assert on sizeof at each call site guards the layout against drift. */
typedef struct {
    char*  name;
    size_t name_len;
    char*  value;
    size_t value_len;
    int    never_indexed;
} httpfields_field_t;

/* Populate `request` from `count` fields. On HTTP_FIELDS_OK the request is
 * complete except vhost selection; *content_length receives the declared
 * Content-Length (-1 if none). On any error the request may be partially filled
 * and the caller rejects the stream. `proto` threads the protocol for rules
 * that may yet diverge; today the h2 and h3 rules are identical. */
http_fields_status_e httpfields_to_request(httprequest_t* request,
                                           const httpfields_field_t* fields, size_t count,
                                           http_fields_proto_e proto,
                                           int64_t* content_length);

/* Connection-specific fields banned in requests (RFC 9113 §8.2.2 / RFC 9114
 * §4.3): connection, keep-alive, proxy-connection, transfer-encoding, upgrade.
 * Exposed for the trailers path, which rejects the same set. */
int httpfields_is_forbidden_header(const char* name, size_t len);

/* ---- The response side ---- *
 *
 * Shared by h2_write_filter and h3response for the reason httpfields exists at
 * all: these are the same rules in RFC 9113 §8.2.2 and RFC 9114 §4.2, and a
 * second copy is a second place to fix. */

/* The request-side set plus `te`, which a response may not carry at all
 * (§8.2.2 allows TE only in a request, and only as "trailers"). Compared
 * case-insensitively: h1.1 response headers are canonical-cased. */
int httpfields_is_forbidden_response_header(const char* name, size_t len);

/* Fields whose value must never enter a compressor's dynamic table (RFC 7541
 * §7.1.3, RFC 9204 §7.1). A table entry is a compression oracle: an attacker
 * who can make the server emit a response of their choosing on the same
 * connection learns a secret by watching the encoded size shrink when a guess
 * matches -- CRIME applied to HPACK/QPACK. Expects an already-lowercased name. */
int httpfields_is_sensitive_header(const char* name, size_t len);

/* Advertise HTTP/3 on a response that is not itself HTTP/3 (RFC 7838,
 * docs/http3/07-integration.md §2).
 *
 * A browser does not probe UDP on speculation: without this header, or a DNS
 * HTTPS record, an HTTP/3 listener is never reached at all. The value is
 * precomputed per vhost at config load (server_http3_t::alt_svc_value); this
 * only decides whether to attach it.
 *
 * Skipped for an interim 1xx -- it is not the final response and a client may
 * discard its fields -- and skipped when the handler set one itself, because a
 * handler that names an alternative knows something the config does not.
 * Never called from the h3 write filter: telling a client over HTTP/3 that
 * HTTP/3 is available says nothing. */
void httpfields_apply_alt_svc(struct httpresponse* response);

/* §8.2.1 / §4.2: field names are lowercase on the wire, and nghttp2-based
 * clients (curl, browsers) treat an uppercase byte as a protocol error.
 * `dst` must have room for `len` bytes; no terminator is written. */
void httpfields_lowercase(char* dst, const char* src, size_t len);

#endif

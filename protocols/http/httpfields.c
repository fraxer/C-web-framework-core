#include "httpfields.h"

#include <stdlib.h>
#include <string.h>

#include "cookieparser.h"
#include "h2field.h"
#include "httpcommon.h"        /* http_header_t, HTTP1_VER_1_1 */
#include "connection_s.h"      /* connection_server_ctx_t::server */
#include "httprequestparser.h" /* httpparser_parse_range */
#include "httpresponse.h"
#include "server.h"           /* server_http3_t */
#include "httpparsercommon.h"  /* HTTP1PARSER_CONTINUE */
#include "log.h"

/* The rules below were lifted verbatim from h2session.c's h2_build_request()
 * (docs/http3/05-http3.md §6.1): the field loop, the pseudo-header routing, the
 * forbidden/TE/content-length checks, the mandatory-pseudo and asterisk-form
 * post-checks, and the cookie/range derivation. They are byte-for-byte what h2
 * already enforced via h2spec, which is what makes sharing them safe. Server
 * selection is the one piece that stayed in the caller (it needs a connection). */

static route_methods_e method_from(const char* method, size_t len) {
    if (len == 3 && memcmp(method, "GET", 3) == 0) return ROUTE_GET;
    if (len == 4 && memcmp(method, "POST", 4) == 0) return ROUTE_POST;
    if (len == 3 && memcmp(method, "PUT", 3) == 0) return ROUTE_PUT;
    if (len == 6 && memcmp(method, "DELETE", 6) == 0) return ROUTE_DELETE;
    if (len == 7 && memcmp(method, "OPTIONS", 7) == 0) return ROUTE_OPTIONS;
    if (len == 5 && memcmp(method, "PATCH", 5) == 0) return ROUTE_PATCH;
    if (len == 4 && memcmp(method, "HEAD", 4) == 0) return ROUTE_HEAD;

    return ROUTE_NONE;
}

/* Connection-specific fields banned in requests too (RFC 9113 §8.2.2 /
 * RFC 9114 §4.3). */
int httpfields_is_forbidden_header(const char* key, size_t len) {
    static const struct { const char* name; size_t len; } banned[] = {
        {"connection", 10}, {"keep-alive", 10}, {"proxy-connection", 16},
        {"transfer-encoding", 17}, {"upgrade", 7},
    };

    for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++)
        if (len == banned[i].len && memcmp(key, banned[i].name, len) == 0) return 1;

    return 0;
}

void httpfields_apply_alt_svc(httpresponse_t* response) {
    if (response == NULL || response->connection == NULL) return;

    /* 1xx is interim: the fields of a final response follow, and a client is
     * free to drop these. Advertising here would be a header a peer may never
     * read, on the one response shape where repeating it is guaranteed. */
    if (response->status_code < 200) return;

    /* httpresponse_t carries the connection as void* -- the response layer is
     * built to not know about it. */
    const connection_t* connection = response->connection;
    const connection_server_ctx_t* ctx = connection->ctx;
    if (ctx == NULL || ctx->server == NULL) return;

    const server_http3_t* h3 = &ctx->server->http3;
    if (!h3->enabled || !h3->alt_svc || h3->alt_svc_length == 0) return;

    /* A handler that set its own knows something the config does not -- another
     * host, another protocol -- so it wins. httpresponse_t has no reader for its
     * own fields (nothing needed one before), so the list is walked here rather
     * than growing the vtable for a single caller. */
    for (const http_header_t* h = response->header_; h != NULL; h = h->next) {
        if (h->key_length != 7) continue;
        if (strncasecmp(h->key, "Alt-Svc", 7) == 0) return;
    }

    response->add_headern(response, "Alt-Svc", 7, h3->alt_svc_value, h3->alt_svc_length);
}

int httpfields_is_forbidden_response_header(const char* key, size_t len) {
    static const struct { const char* name; size_t len; } banned[] = {
        {"connection", 10}, {"keep-alive", 10}, {"proxy-connection", 16},
        {"transfer-encoding", 17}, {"upgrade", 7}, {"te", 2},
    };

    for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++) {
        if (len != banned[i].len) continue;

        size_t j = 0;
        for (; j < len; j++) {
            char c = key[j];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            if (c != banned[i].name[j]) break;
        }
        if (j == len) return 1;
    }

    return 0;
}

int httpfields_is_sensitive_header(const char* key, size_t len) {
    static const struct { const char* name; size_t len; } sensitive[] = {
        {"set-cookie", 10}, {"authorization", 13}, {"proxy-authorization", 19},
    };

    for (size_t i = 0; i < sizeof(sensitive) / sizeof(sensitive[0]); i++)
        if (len == sensitive[i].len && memcmp(key, sensitive[i].name, len) == 0) return 1;

    return 0;
}

void httpfields_lowercase(char* dst, const char* src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        const char c = src[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
}

/* RFC 9113 §8.2.2 / RFC 9114 §4.3 allow exactly one TE value: "trailers". */
static int te_is_valid(const char* value, size_t len) {
    return len == 8 && memcmp(value, "trailers", 8) == 0;
}

/* Parse a content-length value into *out. Returns 0 if it is not a plain
 * non-negative integer, which makes the request malformed. */
static int parse_content_length(const char* value, size_t len, int64_t* out) {
    if (len == 0 || len > 19) return 0;

    int64_t n = 0;
    for (size_t i = 0; i < len; i++) {
        if (value[i] < '0' || value[i] > '9') return 0;
        const int digit = value[i] - '0';
        if (n > (INT64_MAX - digit) / 10) return 0;
        n = n * 10 + digit;
    }

    *out = n;

    return 1;
}

/* The h1.1 parser derives cookies and ranges from headers as it parses them
 * (httprequestparser.c __try_set_cookie / __try_set_range). h2/h3 get their
 * headers from HPACK/QPACK, so the same derivations run here, over the
 * request's own null-terminated copies. */
static void apply_cookies(httprequest_t* request) {
    size_t total = 0;
    size_t count = 0;
    for (http_header_t* h = request->header_; h != NULL; h = h->next) {
        if (h->key_length != 6 || memcmp(h->key, "cookie", 6) != 0) continue;
        total += h->value_length;
        count++;
    }

    if (count == 0) return;

    /* RFC 9113 §8.2.3 / RFC 9114 §4.2 let a client split Cookie into several
     * fields for better compression (browsers do); rejoin them with "; ". */
    total += (count - 1) * 2;

    char* joined = malloc(total + 1);
    if (joined == NULL) return;

    size_t off = 0;
    for (http_header_t* h = request->header_; h != NULL; h = h->next) {
        if (h->key_length != 6 || memcmp(h->key, "cookie", 6) != 0) continue;

        if (off > 0) {
            memcpy(joined + off, "; ", 2);
            off += 2;
        }
        memcpy(joined + off, h->value, h->value_length);
        off += h->value_length;
    }
    joined[off] = '\0';

    cookieparser_t parser;
    cookieparser_init(&parser);
    if (!cookieparser_parse(&parser, joined, off)) {
        log_error("Cookie parser error: %s\n", parser.error);
        free(joined);
        return;
    }

    http_cookie_free(request->cookie_);
    request->cookie_ = cookieparser_cookie(&parser);

    free(joined);
}

static void apply_range(httprequest_t* request) {
    for (http_header_t* h = request->header_; h != NULL; h = h->next) {
        if (h->key_length != 5 || memcmp(h->key, "range", 5) != 0) continue;

        http_ranges_free(request->ranges);
        request->ranges = httpparser_parse_range(h->value, h->value_length);
        return;
    }
}

/* Copy the :path slice and hand it to the request. The decoded slice belongs to
 * the caller's field array, while request->uri must be a heap buffer the
 * request owns -- httprequest_reset() frees it exactly once. httpparser_set_uri
 * stores the buffer before it validates, so the request owns it on either
 * outcome and it must never be freed here. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
static int set_path(httprequest_t* request, const char* value, size_t len) {
    char* uri = malloc(len + 1);
    if (uri == NULL) return 0;

    memcpy(uri, value, len);
    uri[len] = '\0';

    request->uri = uri;
    request->uri_length = len;

    /* asterisk-form (§8.3.1): ":path" of "*" for an OPTIONS request. Handled
     * here rather than left to httpparser_set_uri, which decides it by looking
     * at request->method: pseudo-headers may arrive in any order, so :method is
     * not necessarily known yet. Whether OPTIONS was the method is checked once
     * the whole block has been read. */
    if (len == 1 && uri[0] == '*') {
        char* path = malloc(2);
        if (path == NULL) return 0;

        path[0] = '*';
        path[1] = '\0';
        request->path = path;
        request->path_length = 1;
        request->asterisk_form = 1;

        return 1;
    }

    return httpparser_set_uri(request, uri, len) == HTTP1PARSER_CONTINUE;
}
#pragma GCC diagnostic pop

/* ---- The shared request builder ---- */

http_fields_status_e httpfields_to_request(httprequest_t* request,
                                           const httpfields_field_t* fields, size_t count,
                                           http_fields_proto_e proto,
                                           int64_t* content_length) {
    if (content_length != NULL) *content_length = -1;
    if (request == NULL || fields == NULL) return HTTP_FIELDS_MALFORMED;
    (void)proto; /* the h2 and h3 field rules are identical today */

    http_fields_status_e status = HTTP_FIELDS_OK;
    int method_seen = 0, path_seen = 0, scheme_seen = 0, authority_seen = 0, regular_seen = 0;
    /* Extended CONNECT (RFC 8441 / RFC 9220). The verdict on :protocol is taken
     * inside the loop, and only a copy of the name survives it (the field array
     * is not ours to keep). */
    int connect_method = 0, protocol_seen = 0, protocol_websocket = 0;
    char protocol_name[32] = {0};

    int64_t clength = -1;

    for (size_t i = 0; i < count && status == HTTP_FIELDS_OK; i++) {
        const char* name = fields[i].name;
        const size_t name_len = fields[i].name_len;
        const char* value = fields[i].value;
        const size_t value_len = fields[i].value_len;

        /* §8.2.1/§4.3, before anything reads the bytes: an invalid octet in a
         * name or a value makes the request malformed whatever the field means. */
        if (h2_field_validate(name, name_len, value, value_len) != H2_FIELD_OK) {
            status = HTTP_FIELDS_MALFORMED;
            break;
        }

        if (name[0] == ':') {
            if (regular_seen) { status = HTTP_FIELDS_MALFORMED; break; }

            if (name_len == 7 && memcmp(name, ":method", 7) == 0) {
                if (method_seen) { status = HTTP_FIELDS_MALFORMED; break; }
                request->method = method_from(value, value_len);
                connect_method = (value_len == 7 && memcmp(value, "CONNECT", 7) == 0);
                method_seen = 1;
            }
            else if (name_len == 5 && memcmp(name, ":path", 5) == 0) {
                if (value_len == 0 || path_seen) { status = HTTP_FIELDS_MALFORMED; break; }
                if (!set_path(request, value, value_len)) status = HTTP_FIELDS_MALFORMED;
                path_seen = 1;
            }
            else if (name_len == 7 && memcmp(name, ":scheme", 7) == 0) {
                if (value_len == 0 || scheme_seen) { status = HTTP_FIELDS_MALFORMED; break; }
                scheme_seen = 1;
            }
            else if (name_len == 10 && memcmp(name, ":authority", 10) == 0) {
                if (authority_seen) { status = HTTP_FIELDS_MALFORMED; break; }
                /* httprequest's add_headern returns 0 on success. */
                if (request->add_headern(request, "Host", 4, value, value_len) != 0)
                    status = HTTP_FIELDS_INTERNAL;
                authority_seen = 1;
            }
            else if (name_len == 9 && memcmp(name, ":protocol", 9) == 0) {
                if (value_len == 0 || protocol_seen) { status = HTTP_FIELDS_MALFORMED; break; }
                protocol_websocket = (value_len == 9 && memcmp(value, "websocket", 9) == 0);

                const size_t copy = value_len < sizeof(protocol_name) ?
                    value_len : sizeof(protocol_name) - 1;
                memcpy(protocol_name, value, copy);
                protocol_name[copy] = '\0';

                protocol_seen = 1;
            }
            else {
                status = HTTP_FIELDS_MALFORMED;
                break;
            }

            continue;
        }

        regular_seen = 1;

        if (httpfields_is_forbidden_header(name, name_len)) {
            status = HTTP_FIELDS_MALFORMED;
            break;
        }

        if (name_len == 2 && memcmp(name, "te", 2) == 0 && !te_is_valid(value, value_len)) {
            status = HTTP_FIELDS_MALFORMED;
            break;
        }

        if (name_len == 14 && memcmp(name, "content-length", 14) == 0) {
            int64_t declared = 0;
            /* A second content-length is only tolerable if it agrees. */
            if (!parse_content_length(value, value_len, &declared) ||
                (clength >= 0 && clength != declared)) {
                status = HTTP_FIELDS_MALFORMED;
                break;
            }
            clength = declared;
        }

        if (request->add_headern(request, name, name_len, value, value_len) != 0)
            status = HTTP_FIELDS_INTERNAL;
    }

    if (status != HTTP_FIELDS_OK) goto done;

    /* Extended CONNECT (RFC 8441 §4 / RFC 9220): :protocol is legal only in a
     * CONNECT that also carries :scheme, :path and :authority, which is not
     * knowable until every pseudo-header has been seen. "websocket" opens a
     * tunnel; anything else is well-formed but unserved → 501, not a reset. */
    if (protocol_seen) {
        if (!connect_method || !scheme_seen || !path_seen || !authority_seen) {
            status = HTTP_FIELDS_MALFORMED;
            goto done;
        }
        if (!protocol_websocket) {
            log_info("httpfields: extended CONNECT for unsupported protocol \"%s\"\n",
                     protocol_name);
            status = HTTP_FIELDS_EXTENDED_CONNECT;
            goto done;
        }
        status = HTTP_FIELDS_WEBSOCKET;
        goto done;
    }

    if (!method_seen || !path_seen || !scheme_seen || request->method == ROUTE_NONE) {
        status = HTTP_FIELDS_MALFORMED;
        goto done;
    }

    /* §8.3.1: ":path" may be "*" only for an OPTIONS request (set_path recorded
     * asterisk_form; :method may have arrived after :path). */
    if (request->asterisk_form && request->method != ROUTE_OPTIONS) {
        status = HTTP_FIELDS_MALFORMED;
        goto done;
    }

    /* :authority (mapped to Host above) is mandatory. Selecting the virtual
     * server from it needs the connection, so the caller does that next. */
    if (request->get_headern(request, "Host", 4) == NULL) {
        status = HTTP_FIELDS_MALFORMED;
        goto done;
    }

    apply_cookies(request);
    apply_range(request);

    request->version = HTTP1_VER_1_1;

done:
    if (content_length != NULL) *content_length = clength;
    return status;
}

#include "h2session.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "appconfig.h"
#include "connection_s.h"
#include "cookieparser.h"
#include "httpcommon.h"
#include "httpparsercommon.h"
#include "httprequest.h"
#include "httprequestparser.h"
#include "httpresponse.h"
#include "httpserverhandlers.h"
#include "log.h"
#include "multiplexing.h"
#include "openssl.h"
#include "route.h"

/* HTTP/2 error codes (RFC 9113 §7). */
#define H2_ERR_NO_ERROR           0
#define H2_ERR_PROTOCOL_ERROR     1
#define H2_ERR_INTERNAL_ERROR     2
#define H2_ERR_FLOW_CONTROL_ERROR 3
#define H2_ERR_STREAM_CLOSED      5
#define H2_ERR_REFUSED_STREAM     7
#define H2_ERR_COMPRESSION_ERROR  9

/* SETTINGS identifiers (RFC 9113 §6.5.2). */
#define H2_SETTINGS_HEADER_TABLE_SIZE      0x1
#define H2_SETTINGS_ENABLE_PUSH            0x2
#define H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define H2_SETTINGS_INITIAL_WINDOW_SIZE    0x4
#define H2_SETTINGS_MAX_FRAME_SIZE         0x5

#define H2_MAX_WINDOW 2147483647LL /* 2^31 - 1 */

/* Give receive-window credit back once this much has been consumed, rather than
 * emitting a WINDOW_UPDATE per DATA frame. */
#define H2_WINDOW_UPDATE_THRESHOLD 16384

/* Cap on a single header block (HEADERS + CONTINUATION*). Bounds the
 * CONTINUATION-flood attack noted in docs/http2/07. */
#define H2_MAX_HEADER_BLOCK (1u << 20)

typedef enum {
    H2_FRAME_ERROR = 0,      /* connection error — GOAWAY(s->error_code) and close */
    H2_FRAME_OK,             /* keep processing frames */
    H2_FRAME_DISPATCHED,     /* a request was handed to a handler — stop reading */
    H2_FRAME_CLOSE,          /* orderly close (peer GOAWAY) */
} h2_frame_result_e;

static int h2_flush_out(h2session_t* s);
static void h2_stream_close(h2session_t* s);

/* ======================================================================= *
 *  Outbound frame buffer
 * ======================================================================= */

int h2_session_queue_frame(h2session_t* s, uint8_t type, uint8_t flags,
                           uint32_t stream_id, const uint8_t* payload, size_t len) {
    const size_t need = (size_t)H2_FRAME_HEADER_LEN + len;

    /* Drop the already-sent prefix before growing. */
    if (s->out_pos > 0) {
        memmove(s->out, s->out + s->out_pos, s->out_len - s->out_pos);
        s->out_len -= s->out_pos;
        s->out_pos = 0;
    }

    if (s->out_len + need > s->out_cap) {
        size_t cap = s->out_cap ? s->out_cap : 256;
        while (cap < s->out_len + need) cap *= 2;

        uint8_t* buf = realloc(s->out, cap);
        if (buf == NULL) return 0;

        s->out = buf;
        s->out_cap = cap;
    }

    const size_t written = h2frame_encode(s->out + s->out_len, s->out_cap - s->out_len,
                                          type, flags, stream_id, payload, len);
    if (written == 0) return 0;

    s->out_len += written;

    return 1;
}

/* Returns 1 when the buffer is empty, 0 on a fatal error, -1 when the socket
 * would block and bytes remain. */
static int h2_flush_out(h2session_t* s) {
    connection_t* conn = s->connection;

    while (s->out_pos < s->out_len) {
        const ssize_t written = connection_data_write(conn, (const char*)(s->out + s->out_pos),
                                                      s->out_len - s->out_pos);
        if (written < 0) {
            if (conn->ssl != NULL) {
                const openssl_io_status_e st = openssl_io_status(conn->ssl, (int)written);
                if (st == OPENSSL_IO_WANT_READ || st == OPENSSL_IO_WANT_WRITE) return -1;
                return 0;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            return 0;
        }
        if (written == 0) return 0;

        s->out_pos += (size_t)written;
    }

    s->out_len = 0;
    s->out_pos = 0;

    return 1;
}

static void h2_queue_goaway(h2session_t* s, uint32_t error_code) {
    if (s->goaway_sent) return;

    uint8_t payload[8];
    payload[0] = (uint8_t)((s->last_stream_id >> 24) & 0x7f);
    payload[1] = (uint8_t)((s->last_stream_id >> 16) & 0xff);
    payload[2] = (uint8_t)((s->last_stream_id >> 8) & 0xff);
    payload[3] = (uint8_t)(s->last_stream_id & 0xff);
    payload[4] = (uint8_t)((error_code >> 24) & 0xff);
    payload[5] = (uint8_t)((error_code >> 16) & 0xff);
    payload[6] = (uint8_t)((error_code >> 8) & 0xff);
    payload[7] = (uint8_t)(error_code & 0xff);

    (void)h2_session_queue_frame(s, H2_FRAME_GOAWAY, 0, 0, payload, sizeof(payload));

    s->goaway_sent = 1;
}

/* Terminal path: report the error to the peer on a best-effort basis and tell
 * the dispatcher to close. */
static int h2_fail(h2session_t* s, uint32_t error_code) {
    h2_queue_goaway(s, error_code);
    (void)h2_flush_out(s);

    return 0;
}

static void h2_queue_window_update(h2session_t* s, uint32_t stream_id, uint32_t increment) {
    if (increment == 0) return;

    const uint8_t payload[4] = {
        (uint8_t)((increment >> 24) & 0x7f),
        (uint8_t)((increment >> 16) & 0xff),
        (uint8_t)((increment >> 8) & 0xff),
        (uint8_t)(increment & 0xff),
    };

    (void)h2_session_queue_frame(s, H2_FRAME_WINDOW_UPDATE, 0, stream_id, payload, sizeof(payload));
}

static int rearm(connection_t* conn, int events) {
    connection_server_ctx_t* ctx = conn->ctx;

    return ctx->listener->api->control_mod(conn, events);
}

/* ======================================================================= *
 *  Error signalling (RFC 9113 §5.4)
 * ======================================================================= */

/* Connection error: the caller unwinds to h2_read, which sends GOAWAY with this
 * code and closes. */
static h2_frame_result_e h2_conn_error(h2session_t* s, uint32_t error_code) {
    s->error_code = error_code;

    return H2_FRAME_ERROR;
}

/* Stream error: only the stream dies, the connection carries on. Any half-built
 * request for that stream is dropped. */
static h2_frame_result_e h2_stream_error(h2session_t* s, uint32_t stream_id, uint32_t error_code) {
    const uint8_t payload[4] = {
        (uint8_t)((error_code >> 24) & 0xff),
        (uint8_t)((error_code >> 16) & 0xff),
        (uint8_t)((error_code >> 8) & 0xff),
        (uint8_t)(error_code & 0xff),
    };

    if (!h2_session_queue_frame(s, H2_FRAME_RST_STREAM, 0, stream_id, payload, sizeof(payload)))
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

    if (stream_id == s->stream_id) {
        connection_reset(s->connection); /* frees any in-flight request/response */
        h2_stream_close(s);
    }

    return H2_FRAME_OK;
}

/* State of an arbitrary stream id. Only one stream is tracked in detail; ids
 * above the highest one we ever opened are idle, the rest are closed. */
static h2_stream_state_e h2_stream_state(const h2session_t* s, uint32_t stream_id) {
    if (stream_id > s->last_stream_id) return H2_STREAM_IDLE;
    if (stream_id != 0 && stream_id == s->stream_id) return s->stream_state;

    return H2_STREAM_CLOSED;
}

h2session_t* h2_session_of(connection_t* connection) {
    if (connection == NULL) return NULL;

    connection_server_ctx_t* ctx = connection->ctx;
    if (ctx == NULL || !ctx->is_http2) return NULL;

    return ctx->parser;
}

/* ======================================================================= *
 *  Request construction from frames
 * ======================================================================= */

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

/* Connection-specific fields banned in requests too (RFC 9113 §8.2.2). */
static int is_forbidden_h2_header(const char* key, size_t len) {
    static const struct { const char* name; size_t len; } banned[] = {
        {"connection", 10}, {"keep-alive", 10}, {"proxy-connection", 16},
        {"transfer-encoding", 17}, {"upgrade", 7},
    };

    for (size_t i = 0; i < sizeof(banned) / sizeof(banned[0]); i++)
        if (len == banned[i].len && memcmp(key, banned[i].name, len) == 0) return 1;

    return 0;
}

/* The h1.1 parser derives cookies and ranges from headers as it parses them
 * (httprequestparser.c __try_set_cookie / __try_set_range). h2 gets its headers
 * from HPACK, so the same derivations run here, over the request's own
 * null-terminated copies. */
static void h2_apply_cookies(httprequest_t* request) {
    size_t total = 0;
    size_t count = 0;
    for (http_header_t* h = request->header_; h != NULL; h = h->next) {
        if (h->key_length != 6 || memcmp(h->key, "cookie", 6) != 0) continue;
        total += h->value_length;
        count++;
    }

    if (count == 0) return;

    /* RFC 9113 §8.2.3 lets a client split Cookie into several fields for better
     * compression (browsers do); rejoin them with "; " before parsing. */
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

static void h2_apply_range(httprequest_t* request) {
    for (http_header_t* h = request->header_; h != NULL; h = h->next) {
        if (h->key_length != 5 || memcmp(h->key, "range", 5) != 0) continue;

        http_ranges_free(request->ranges);
        request->ranges = httpparser_parse_range(h->value, h->value_length);
        return;
    }
}

/* Copy the :path slice and hand it to the request. The HPACK slice belongs to
 * the decoded header array, while request->uri must be a heap buffer the
 * request owns — httprequest_reset() frees it. httpparser_set_uri stores the
 * buffer before it validates, so the request owns it on either outcome and it
 * must never be freed here. */
static int h2_set_path(httprequest_t* request, const char* value, size_t len) {
    char* uri = malloc(len + 1);
    if (uri == NULL) return 0;

    memcpy(uri, value, len);
    uri[len] = '\0';

    /* httpparser_set_uri makes this same assignment, but declares the buffer
     * const char* even though the request takes ownership of it. Stating the
     * hand-off here keeps it visible to readers and to static analysis, which
     * otherwise reads the buffer as leaked. */
    request->uri = uri;
    request->uri_length = len;

    return httpparser_set_uri(request, uri, len) == HTTP1PARSER_CONTINUE;
}

/* RFC 9113 §8.2.2 allows exactly one TE value: "trailers". */
static int h2_te_is_valid(const char* value, size_t len) {
    return len == 8 && memcmp(value, "trailers", 8) == 0;
}

/* Parse a content-length value into *out. Returns 0 if it is not a plain
 * non-negative integer, which makes the request malformed. */
static int h2_parse_content_length(const char* value, size_t len, int64_t* out) {
    if (len == 0 || len > 19) return 0;

    int64_t n = 0;
    for (size_t i = 0; i < len; i++) {
        if (value[i] < '0' || value[i] > '9') return 0;
        n = n * 10 + (value[i] - '0');
    }

    *out = n;

    return 1;
}

typedef enum {
    H2_REQUEST_OK = 0,
    H2_REQUEST_MALFORMED,   /* stream error: RST_STREAM(PROTOCOL_ERROR) */
    H2_REQUEST_COMPRESSION, /* connection error: the HPACK context is unusable */
    H2_REQUEST_INTERNAL,
} h2_request_status_e;

/* Fill an httprequest_t from a decoded HPACK block, applying the request
 * validity rules of RFC 9113 §8.3 / §8.2 on the way. Everything the h1.1 parser
 * derives from headers is derived here too. */
static h2_request_status_e h2_build_request(h2session_t* s, httprequest_t* request,
                                            const uint8_t* block, size_t len) {
    hpack_header_t* headers = NULL;
    size_t count = 0;
    if (hpack_decoder_decode(s->decoder, block, len, &headers, &count) != HPACK_OK)
        return H2_REQUEST_COMPRESSION;

    h2_request_status_e status = H2_REQUEST_OK;
    int method_seen = 0;
    int path_seen = 0;
    int scheme_seen = 0;
    int authority_seen = 0;
    int regular_seen = 0;

    s->content_length = -1;

    for (size_t i = 0; i < count && status == H2_REQUEST_OK; i++) {
        const char* name = headers[i].name;
        const size_t name_len = headers[i].name_len;
        const char* value = headers[i].value;
        const size_t value_len = headers[i].value_len;

        if (name_len == 0) {
            status = H2_REQUEST_MALFORMED;
            break;
        }

        if (name[0] == ':') {
            /* §8.3: pseudo-headers must all precede the regular fields. */
            if (regular_seen) {
                status = H2_REQUEST_MALFORMED;
                break;
            }

            if (name_len == 7 && memcmp(name, ":method", 7) == 0) {
                /* A repeated pseudo-header makes the request malformed (§8.3.1). */
                if (method_seen) {
                    status = H2_REQUEST_MALFORMED;
                    break;
                }
                request->method = method_from(value, value_len);
                method_seen = 1;
            }
            else if (name_len == 5 && memcmp(name, ":path", 5) == 0) {
                if (value_len == 0 || path_seen) {
                    status = H2_REQUEST_MALFORMED;
                    break;
                }
                if (!h2_set_path(request, value, value_len))
                    status = H2_REQUEST_MALFORMED;
                path_seen = 1;
            }
            else if (name_len == 7 && memcmp(name, ":scheme", 7) == 0) {
                /* The value carries no routing information — the transport
                 * already says http vs https — but §8.3.1 requires it to be
                 * present exactly once. */
                if (value_len == 0 || scheme_seen) {
                    status = H2_REQUEST_MALFORMED;
                    break;
                }
                scheme_seen = 1;
            }
            else if (name_len == 10 && memcmp(name, ":authority", 10) == 0) {
                if (authority_seen) {
                    status = H2_REQUEST_MALFORMED;
                    break;
                }
                /* httprequest's add_headern returns 0 on success (the mirror
                 * method on httpresponse returns 1 — they disagree). */
                if (request->add_headern(request, "Host", 4, value, value_len) != 0)
                    status = H2_REQUEST_INTERNAL;
                authority_seen = 1;
            }
            else {
                /* Unknown pseudo-headers, and the response-only ones such as
                 * :status, are malformed in a request (§8.3). */
                status = H2_REQUEST_MALFORMED;
                break;
            }

            continue;
        }

        regular_seen = 1;

        /* §8.2.1: an uppercase name is malformed. */
        for (size_t j = 0; j < name_len; j++) {
            if (name[j] >= 'A' && name[j] <= 'Z') {
                status = H2_REQUEST_MALFORMED;
                break;
            }
        }
        if (status != H2_REQUEST_OK) break;

        if (is_forbidden_h2_header(name, name_len)) {
            status = H2_REQUEST_MALFORMED;
            break;
        }

        if (name_len == 2 && memcmp(name, "te", 2) == 0 && !h2_te_is_valid(value, value_len)) {
            status = H2_REQUEST_MALFORMED;
            break;
        }

        if (name_len == 14 && memcmp(name, "content-length", 14) == 0) {
            int64_t declared = 0;
            /* A second content-length is only tolerable if it agrees. */
            if (!h2_parse_content_length(value, value_len, &declared) ||
                (s->content_length >= 0 && s->content_length != declared)) {
                status = H2_REQUEST_MALFORMED;
                break;
            }
            s->content_length = declared;
        }

        if (request->add_headern(request, name, name_len, value, value_len) != 0)
            status = H2_REQUEST_INTERNAL;
    }

    hpack_headers_free(headers, count);

    if (status != H2_REQUEST_OK) return status;

    if (!method_seen || !path_seen || !scheme_seen || request->method == ROUTE_NONE)
        return H2_REQUEST_MALFORMED;

    /* :authority (mapped to Host above) selects the virtual server, and on a
     * TLS connection it must agree with the SNI-selected one (RFC 9110 §7.4).
     * Without this, routing would silently use the listener's first server. */
    http_header_t* host = request->get_headern(request, "Host", 4);
    if (host == NULL) return H2_REQUEST_MALFORMED; /* §8.3.1: :authority or Host */
    if (httpparser_select_server(s->connection, host->value, host->value_length) != HTTP1PARSER_CONTINUE)
        return H2_REQUEST_MALFORMED;

    h2_apply_cookies(request);
    h2_apply_range(request);

    request->version = HTTP1_VER_1_1;

    return H2_REQUEST_OK;
}

/* Feed a header block to the decoder and throw the fields away. Whenever a
 * stream is rejected without being served, its block still has to go through
 * the decoder: the HPACK dynamic table is shared by every stream on the
 * connection, so skipping one block desynchronises the peer for good. */
static h2_request_status_e h2_discard_header_block(h2session_t* s, const uint8_t* block, size_t len) {
    hpack_header_t* headers = NULL;
    size_t count = 0;
    if (hpack_decoder_decode(s->decoder, block, len, &headers, &count) != HPACK_OK)
        return H2_REQUEST_COMPRESSION;

    hpack_headers_free(headers, count);

    return H2_REQUEST_OK;
}

/* Trailers (a HEADERS frame after DATA). The block still has to be fed to the
 * decoder so the shared HPACK context stays in sync, but the fields are dropped:
 * nothing downstream consumes trailers. Pseudo-headers are forbidden there
 * (§8.1), which makes the request malformed. */
static h2_request_status_e h2_consume_trailers(h2session_t* s, const uint8_t* block, size_t len) {
    hpack_header_t* headers = NULL;
    size_t count = 0;
    if (hpack_decoder_decode(s->decoder, block, len, &headers, &count) != HPACK_OK)
        return H2_REQUEST_COMPRESSION;

    h2_request_status_e status = H2_REQUEST_OK;
    for (size_t i = 0; i < count; i++) {
        if (headers[i].name_len > 0 && headers[i].name[0] == ':') {
            status = H2_REQUEST_MALFORMED;
            break;
        }
    }

    hpack_headers_free(headers, count);

    return status;
}

/* Spool a DATA payload into the request's temp file, mirroring the h1.1 parser
 * (httprequestparser.c __parse_payload): the payload type is then derived from
 * Content-Type on demand, so get_payload/get_payload_json/multipart accessors
 * behave identically under h2. */
static int h2_body_append(h2session_t* s, httprequest_t* request,
                          const uint8_t* data, size_t len) {
    if (len == 0) return 1;

    if (len > SIZE_MAX - s->req_body_len) return 0;
    if (s->req_body_len + len > env()->main.client_max_body_size) return 0;

    http_payload_t* payload = &request->payload_;
    if (payload->file.fd < 0)
        if (!httprequest_create_payload_file(payload))
            return 0;

    if (!payload->file.append_content(&payload->file, (const char*)data, len))
        return 0;

    s->req_body_len += len;

    return 1;
}

static void h2_stream_close(h2session_t* s) {
    s->stream_id = 0;
    s->stream_state = H2_STREAM_CLOSED;
    s->req_body_len = 0;
    s->content_length = -1;
    s->end_stream_sent = 0;
    s->window_blocked = 0;
    s->stream_recv_pending = 0;
    s->stream_send_window = s->peer_initial_window;
}

static void h2_stream_open(h2session_t* s, uint32_t stream_id) {
    s->stream_id = stream_id;
    s->last_stream_id = stream_id;
    s->stream_state = H2_STREAM_OPEN;
    s->req_body_len = 0;
    s->content_length = -1;
    s->end_stream_sent = 0;
    s->window_blocked = 0;
    s->stream_recv_pending = 0;
    s->stream_send_window = s->peer_initial_window;
}

/* The request is complete: validate what could only be checked once the body
 * was fully received, then hand it to the shared handler pipeline. */
static h2_frame_result_e h2_dispatch(h2session_t* s) {
    connection_t* conn = s->connection;
    connection_server_ctx_t* ctx = conn->ctx;

    /* RFC 9113 §8.1.1: a content-length that disagrees with the DATA total
     * makes the request malformed. */
    if (s->content_length >= 0 && (uint64_t)s->content_length != (uint64_t)s->req_body_len)
        return h2_stream_error(s, s->stream_id, H2_ERR_PROTOCOL_ERROR);

    s->stream_state = H2_STREAM_HALF_CLOSED_REMOTE;

    /* Ownership of ctx->request passes to the connection context / queue item,
     * exactly as in h1.1 after httpparser_reset(). */
    if (!http_server_dispatch(conn, ctx->request))
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

    return H2_FRAME_DISPATCHED;
}

/* ======================================================================= *
 *  Frame handling
 * ======================================================================= */

static h2_frame_result_e h2_on_settings(h2session_t* s, const h2_frame_t* frame) {
    if (frame->flags & H2_FLAG_ACK) return H2_FRAME_OK;

    for (size_t off = 0; off + 6 <= frame->payload_len; off += 6) {
        const uint8_t* p = frame->payload + off;
        const uint16_t id = (uint16_t)((p[0] << 8) | p[1]);
        const uint32_t value = ((uint32_t)p[2] << 24) | ((uint32_t)p[3] << 16) |
                               ((uint32_t)p[4] << 8) | p[5];

        switch (id) {
        case H2_SETTINGS_HEADER_TABLE_SIZE:
            /* This bounds the table the peer's *decoder* keeps, so it limits
             * our encoder, not our decoder. */
            s->peer_header_table_size = value;
            hpack_encoder_set_max_table_size(s->encoder, value);
            break;
        case H2_SETTINGS_ENABLE_PUSH:
            /* §6.5.2: the only legal values are 0 and 1, even though we never
             * push. A client may not enable push on us either, but 1 is only
             * meaningless here, not illegal. */
            if (value > 1) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
            break;
        case H2_SETTINGS_INITIAL_WINDOW_SIZE: {
            if (value > (uint32_t)H2_MAX_WINDOW)
                return h2_conn_error(s, H2_ERR_FLOW_CONTROL_ERROR);

            /* §6.9.2: the change applies as a delta to every open stream's send
             * window, not as an assignment. */
            const int64_t delta = (int64_t)value - (int64_t)s->peer_initial_window;
            s->peer_initial_window = value;
            if (s->stream_id != 0) s->stream_send_window += delta;
            if (s->stream_send_window > 0) s->window_blocked = 0;
            break;
        }
        case H2_SETTINGS_MAX_FRAME_SIZE:
            if (value < H2_MAX_FRAME_SIZE_DEFAULT || value > H2_MAX_FRAME_SIZE_LIMIT)
                return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
            s->peer_max_frame_size = value;
            break;
        default:
            break; /* unknown settings must be ignored (§6.5.2) */
        }
    }

    if (!h2_session_queue_frame(s, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, NULL, 0))
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

    return H2_FRAME_OK;
}

static h2_frame_result_e h2_on_window_update(h2session_t* s, const h2_frame_t* frame) {
    const uint32_t increment = ((uint32_t)(frame->payload[0] & 0x7f) << 24) |
                               ((uint32_t)frame->payload[1] << 16) |
                               ((uint32_t)frame->payload[2] << 8) | frame->payload[3];

    if (frame->stream_id == 0) {
        if (increment == 0) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

        s->send_window += increment;
        if (s->send_window > H2_MAX_WINDOW)
            return h2_conn_error(s, H2_ERR_FLOW_CONTROL_ERROR);
    }
    else {
        /* §5.1: a frame for a stream that was never opened is a connection
         * error, while one for a stream we already finished is harmless. */
        if (h2_stream_state(s, frame->stream_id) == H2_STREAM_IDLE)
            return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

        if (increment == 0)
            return h2_stream_error(s, frame->stream_id, H2_ERR_PROTOCOL_ERROR);

        if (frame->stream_id != s->stream_id) return H2_FRAME_OK;

        s->stream_send_window += increment;
        if (s->stream_send_window > H2_MAX_WINDOW)
            return h2_stream_error(s, frame->stream_id, H2_ERR_FLOW_CONTROL_ERROR);
    }

    if (s->send_window > 0 && s->stream_send_window > 0)
        s->window_blocked = 0;

    return H2_FRAME_OK;
}

/* PRIORITY is deprecated (§6.3) and its scheduling hints are ignored, but a
 * stream that depends on itself is still a stream error (§5.3.1). */
static int h2_priority_self_dependent(uint32_t stream_id, const uint8_t* priority) {
    const uint32_t dependency = ((uint32_t)(priority[0] & 0x7f) << 24) |
                                ((uint32_t)priority[1] << 16) |
                                ((uint32_t)priority[2] << 8) | priority[3];

    return dependency == stream_id;
}

static h2_frame_result_e h2_on_priority(h2session_t* s, const h2_frame_t* frame) {
    if (h2_priority_self_dependent(frame->stream_id, frame->payload))
        return h2_stream_error(s, frame->stream_id, H2_ERR_PROTOCOL_ERROR);

    return H2_FRAME_OK;
}

static h2_frame_result_e h2_on_rst_stream(h2session_t* s, const h2_frame_t* frame) {
    /* §6.4: RST_STREAM on an idle stream is a connection error. */
    if (h2_stream_state(s, frame->stream_id) == H2_STREAM_IDLE)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    if (frame->stream_id == s->stream_id) {
        connection_reset(s->connection); /* drops the in-flight request/response */
        h2_stream_close(s);
    }

    return H2_FRAME_OK;
}

/* Map a request-construction outcome onto the wire. */
static h2_frame_result_e h2_request_failed(h2session_t* s, uint32_t stream_id,
                                           h2_request_status_e status) {
    connection_server_ctx_t* ctx = s->connection->ctx;

    /* Release the half-built request here rather than leaving it for
     * __ctx_free, so nothing downstream can observe it. */
    if (ctx->request != NULL) {
        httprequest_free(ctx->request);
        ctx->request = NULL;
    }

    /* A bad HPACK block leaves the shared decoder unusable, so the connection
     * has to go; a merely malformed request only costs the stream. */
    if (status == H2_REQUEST_COMPRESSION) {
        h2_stream_close(s);
        return h2_conn_error(s, H2_ERR_COMPRESSION_ERROR);
    }
    if (status == H2_REQUEST_INTERNAL) {
        h2_stream_close(s);
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);
    }

    return h2_stream_error(s, stream_id, H2_ERR_PROTOCOL_ERROR);
}

static h2_frame_result_e h2_on_header_block(h2session_t* s, uint32_t stream_id,
                                            const uint8_t* block, size_t len,
                                            int end_stream) {
    connection_t* conn = s->connection;
    connection_server_ctx_t* ctx = conn->ctx;

    /* A HEADERS block on a stream that is already open is trailers, not a new
     * request (§8.1). */
    if (stream_id == s->stream_id && s->stream_state == H2_STREAM_OPEN) {
        /* The block must still be decoded to keep the HPACK context in sync,
         * even when the stream is about to be reset. */
        const h2_request_status_e status = h2_consume_trailers(s, block, len);
        if (status != H2_REQUEST_OK)
            return h2_request_failed(s, stream_id, status);

        /* §8.1: trailers terminate the request; without END_STREAM this is a
         * second header block in mid-stream. */
        if (!end_stream)
            return h2_stream_error(s, stream_id, H2_ERR_PROTOCOL_ERROR);

        return h2_dispatch(s);
    }

    h2_stream_open(s, stream_id);

    ctx->request = httprequest_create(conn);
    if (ctx->request == NULL) return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

    const h2_request_status_e status = h2_build_request(s, ctx->request, block, len);
    if (status != H2_REQUEST_OK)
        return h2_request_failed(s, stream_id, status);

    if (!end_stream) return H2_FRAME_OK;

    return h2_dispatch(s);
}

static h2_frame_result_e h2_on_headers(h2session_t* s, const h2_frame_t* frame) {
    connection_server_ctx_t* ctx = s->connection->ctx;

    /* §5.1.1: client-initiated streams are odd-numbered, and ids only ever
     * increase — reusing a closed one is a connection error. */
    if ((frame->stream_id & 1) == 0) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    const h2_stream_state_e state = h2_stream_state(s, frame->stream_id);
    if (state == H2_STREAM_CLOSED || state == H2_STREAM_HALF_CLOSED_REMOTE)
        return h2_conn_error(s, H2_ERR_STREAM_CLOSED);

    const int trailers = (state == H2_STREAM_OPEN);

    const uint8_t* block = frame->payload;
    size_t block_len = frame->payload_len;
    size_t pad_len = 0;
    int self_dependent = 0;

    if (frame->flags & H2_FLAG_PADDED) {
        if (block_len < 1) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
        pad_len = block[0];
        block++;
        block_len--;
    }
    if (frame->flags & H2_FLAG_PRIORITY) {
        if (block_len < 5) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
        self_dependent = h2_priority_self_dependent(frame->stream_id, block);
        block += 5;
        block_len -= 5;
    }
    if (pad_len > block_len) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
    block_len -= pad_len;

    const int end_stream = (frame->flags & H2_FLAG_END_STREAM) != 0;

    /* Reasons to reject the stream outright. The block is still decoded first,
     * to keep the connection-wide HPACK context usable for later streams. */
    const int refused = !trailers && (ctx->request != NULL || s->stream_id != 0);
    if (self_dependent || refused) {
        if (frame->flags & H2_FLAG_END_HEADERS) {
            const h2_request_status_e status = h2_discard_header_block(s, block, block_len);
            if (status != H2_REQUEST_OK)
                return h2_conn_error(s, H2_ERR_COMPRESSION_ERROR);
        }

        if (refused) {
            /* Phase 3 serves one stream at a time; SETTINGS_MAX_CONCURRENT_STREAMS
             * tells conforming peers not to do this, so refuse the extra stream
             * instead of failing the connection. */
            s->last_stream_id = frame->stream_id;
            return h2_stream_error(s, frame->stream_id, H2_ERR_REFUSED_STREAM);
        }

        return h2_stream_error(s, frame->stream_id, H2_ERR_PROTOCOL_ERROR);
    }

    if (!(frame->flags & H2_FLAG_END_HEADERS)) {
        if (block_len > H2_MAX_HEADER_BLOCK) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

        uint8_t* buf = realloc(s->cont, block_len ? block_len : 1);
        if (buf == NULL) return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

        memcpy(buf, block, block_len);
        s->cont = buf;
        s->cont_len = block_len;
        s->cont_stream_id = frame->stream_id;
        s->cont_end_stream = end_stream;
        s->cont_active = 1;

        return H2_FRAME_OK;
    }

    return h2_on_header_block(s, frame->stream_id, block, block_len, end_stream);
}

static h2_frame_result_e h2_on_continuation(h2session_t* s, const h2_frame_t* frame) {
    if (!s->cont_active || frame->stream_id != s->cont_stream_id)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    if (s->cont_len + frame->payload_len > H2_MAX_HEADER_BLOCK)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    uint8_t* buf = realloc(s->cont, s->cont_len + frame->payload_len + 1);
    if (buf == NULL) return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

    memcpy(buf + s->cont_len, frame->payload, frame->payload_len);
    s->cont = buf;
    s->cont_len += frame->payload_len;

    if (!(frame->flags & H2_FLAG_END_HEADERS)) return H2_FRAME_OK;

    s->cont_active = 0;

    return h2_on_header_block(s, s->cont_stream_id, s->cont, s->cont_len, s->cont_end_stream);
}

static h2_frame_result_e h2_on_data(h2session_t* s, const h2_frame_t* frame) {
    connection_server_ctx_t* ctx = s->connection->ctx;

    /* Credit the connection window back regardless of what happens to the
     * payload: the peer counted it against our window either way. */
    s->recv_pending += frame->payload_len;
    if (s->recv_pending >= H2_WINDOW_UPDATE_THRESHOLD) {
        h2_queue_window_update(s, 0, (uint32_t)s->recv_pending);
        s->recv_pending = 0;
    }

    /* §5.1: DATA on a stream that was never opened is a connection error; on
     * one that no longer accepts data it is a stream error. */
    const h2_stream_state_e state = h2_stream_state(s, frame->stream_id);
    if (state == H2_STREAM_IDLE)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
    if (state != H2_STREAM_OPEN || ctx->request == NULL)
        return h2_stream_error(s, frame->stream_id, H2_ERR_STREAM_CLOSED);

    const uint8_t* data = frame->payload;
    size_t data_len = frame->payload_len;

    if (frame->flags & H2_FLAG_PADDED) {
        if (data_len < 1) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
        const size_t pad_len = data[0];
        data++;
        data_len--;
        if (pad_len > data_len) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
        data_len -= pad_len;
    }

    s->stream_recv_pending += frame->payload_len;
    if (s->stream_recv_pending >= H2_WINDOW_UPDATE_THRESHOLD) {
        h2_queue_window_update(s, s->stream_id, (uint32_t)s->stream_recv_pending);
        s->stream_recv_pending = 0;
    }

    if (!h2_body_append(s, ctx->request, data, data_len))
        return h2_stream_error(s, s->stream_id, H2_ERR_INTERNAL_ERROR);

    if (!(frame->flags & H2_FLAG_END_STREAM)) return H2_FRAME_OK;

    return h2_dispatch(s);
}

static h2_frame_result_e h2_handle_frame(h2session_t* s, const h2_frame_t* frame) {
    /* A header block must not be interleaved with any other frame (§6.10). */
    if (s->cont_active && frame->type != H2_FRAME_CONTINUATION)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    switch (frame->type) {
    case H2_FRAME_SETTINGS:
        return h2_on_settings(s, frame);

    case H2_FRAME_PING:
        if (frame->flags & H2_FLAG_ACK) return H2_FRAME_OK;
        if (!h2_session_queue_frame(s, H2_FRAME_PING, H2_FLAG_ACK, 0,
                                    frame->payload, frame->payload_len))
            return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);
        return H2_FRAME_OK;

    case H2_FRAME_WINDOW_UPDATE:
        return h2_on_window_update(s, frame);

    case H2_FRAME_HEADERS:
        return h2_on_headers(s, frame);

    case H2_FRAME_CONTINUATION:
        return h2_on_continuation(s, frame);

    case H2_FRAME_DATA:
        return h2_on_data(s, frame);

    case H2_FRAME_PRIORITY:
        return h2_on_priority(s, frame);

    case H2_FRAME_RST_STREAM:
        return h2_on_rst_stream(s, frame);

    case H2_FRAME_GOAWAY:
        return H2_FRAME_CLOSE;

    case H2_FRAME_PUSH_PROMISE:
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR); /* a client never sends one (§6.6) */

    default:
        return H2_FRAME_OK; /* unknown frame types must be ignored (§5.5) */
    }
}

/* ======================================================================= *
 *  Read path
 * ======================================================================= */

/* Parse and handle whole frames sitting in the session buffer. Returns 1 to
 * keep going, 0 to close, and sets *dispatched when a request was handed off
 * (further frames stay buffered until the response has been written). */
static int h2_process_buffer(h2session_t* s, int* dispatched) {
    const uint8_t* p = s->read_buf;
    const uint8_t* end = s->read_buf + s->read_len;
    int result = 1;

    *dispatched = 0;

    while (p < end) {
        const h2parse_status_e st = h2frame_parser_feed(&s->frame, &p, end);

        if (st == H2PARSE_CONTINUE) break;

        if (st != H2PARSE_FRAME_READY) {
            const uint32_t err = (st == H2PARSE_OOM) ? H2_ERR_INTERNAL_ERROR : H2_ERR_PROTOCOL_ERROR;
            result = h2_fail(s, err);
            break;
        }

        h2_frame_t frame;
        h2frame_parser_get(&s->frame, &frame);

        const h2_frame_result_e r = h2_handle_frame(s, &frame);
        if (r == H2_FRAME_ERROR) {
            result = h2_fail(s, s->error_code);
            break;
        }
        if (r == H2_FRAME_CLOSE) {
            result = 0;
            break;
        }
        if (r == H2_FRAME_DISPATCHED) {
            *dispatched = 1;
            break;
        }
    }

    const size_t consumed = (size_t)(p - s->read_buf);
    if (consumed > 0) {
        memmove(s->read_buf, s->read_buf + consumed, s->read_len - consumed);
        s->read_len -= consumed;
    }

    return result;
}

static int h2_read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = ctx->parser;

    for (;;) {
        /* Frames left over from the previous wakeup (a pipelined request that
         * arrived in the same segment) come first — no new readable event will
         * announce bytes that are already in our buffer. */
        if (s->read_len > 0 && ctx->request == NULL) {
            int dispatched = 0;
            if (!h2_process_buffer(s, &dispatched)) return 0;
            if (dispatched) break;
        }

        const ssize_t n = connection_data_read(connection);
        if (n < 0) {
            if (connection->ssl != NULL) {
                const openssl_io_status_e st = openssl_io_status(connection->ssl, (int)n);
                if (st == OPENSSL_IO_WANT_READ || st == OPENSSL_IO_WANT_WRITE) break;
                return 0;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return 0;
        }
        if (n == 0) return 0; /* peer closed */

        if (s->read_len + (size_t)n > s->read_cap) {
            size_t cap = s->read_cap ? s->read_cap : 16384;
            while (cap < s->read_len + (size_t)n) cap *= 2;

            uint8_t* buf = realloc(s->read_buf, cap);
            if (buf == NULL) return 0;

            s->read_buf = buf;
            s->read_cap = cap;
        }

        memcpy(s->read_buf + s->read_len, connection->buffer, (size_t)n);
        s->read_len += (size_t)n;

        /* Unlike the leftover branch above, freshly read bytes are always
         * parsed, even while a request is in flight: they usually carry the
         * WINDOW_UPDATE or RST_STREAM that the response in progress is waiting
         * on. A HEADERS frame for a second stream is refused there
         * (REFUSED_STREAM) rather than deferred — conforming peers do not send
         * one, since we advertise SETTINGS_MAX_CONCURRENT_STREAMS=1. */
        int dispatched = 0;
        if (!h2_process_buffer(s, &dispatched)) return 0;
        if (dispatched) break;
    }

    /* Acks and window updates produced while parsing. */
    if (h2_flush_out(s) == 0) return 0;

    if (s->out_len > s->out_pos) {
        ctx->need_write = 1;
        return rearm(connection, MPXOUT | MPXRDHUP);
    }

    /* A window-blocked response resumes on the WINDOW_UPDATE we just consumed. */
    if (s->window_blocked && ctx->response != NULL)
        ctx->need_write = 1;

    return 1;
}

/* ======================================================================= *
 *  Write path
 * ======================================================================= */

static int h2_write(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = ctx->parser;

    const int flushed = h2_flush_out(s);
    if (flushed == 0) return 0;
    if (flushed < 0) return rearm(connection, MPXOUT | MPXRDHUP);

    httpresponse_t* response = ctx->response;
    if (response == NULL) {
        /* EPOLLOUT with nothing to send (control frames just drained). */
        return rearm(connection, MPXIN | MPXRDHUP);
    }

    s->window_blocked = 0;

    int r = __run_header_filters(ctx->request, response);
    if (r == CWF_ERROR) return h2_fail(s, H2_ERR_INTERNAL_ERROR);
    if (r == CWF_EVENT_AGAIN)
        return s->window_blocked ? rearm(connection, MPXIN | MPXRDHUP) : 1;

    r = __run_body_filters(ctx->request, response);
    if (r == CWF_ERROR) return h2_fail(s, H2_ERR_INTERNAL_ERROR);
    if (r == CWF_EVENT_AGAIN)
        return s->window_blocked ? rearm(connection, MPXIN | MPXRDHUP) : 1;

    /* The filter chain emits no buffer at all for an empty body (and the
     * HEADERS frame only carries END_STREAM when we could prove up front that
     * no body follows), so close the stream explicitly when it is still open. */
    if (!s->end_stream_sent) {
        if (!h2_session_queue_frame(s, H2_FRAME_DATA, H2_FLAG_END_STREAM, s->stream_id, NULL, 0))
            return h2_fail(s, H2_ERR_INTERNAL_ERROR);

        s->end_stream_sent = 1;

        const int tail = h2_flush_out(s);
        if (tail == 0) return 0;
        if (tail < 0) return rearm(connection, MPXOUT | MPXRDHUP);
    }

    h2_stream_close(s);

    /* Same teardown as h1.1 __write: resets the context (freeing request and
     * response), drains any queued handler and re-arms reading. */
    if (!connection_after_write(connection)) return 0;

    /* Frames that arrived while the response was being written. */
    if (s->read_len > 0 && ctx->request == NULL) {
        int dispatched = 0;
        if (!h2_process_buffer(s, &dispatched)) return 0;
        if (h2_flush_out(s) == 0) return 0;
        if (dispatched || s->out_len > s->out_pos) {
            ctx->need_write = 1;
            return rearm(connection, MPXOUT | MPXRDHUP);
        }
    }

    return 1;
}

/* ======================================================================= *
 *  Guards + lifecycle
 * ======================================================================= */

int h2_server_guard_read(connection_t* connection) {
    connection_s_lock(connection);
    const int r = h2_read(connection);
    connection_s_unlock(connection);

    return r;
}

int h2_server_guard_write(connection_t* connection) {
    if (connection == NULL) return 0;

    connection_s_lock(connection);
    const int r = h2_write(connection);
    connection_s_unlock(connection);

    return r;
}

/* Server connection preface (§3.4): SETTINGS must be the first frame we send.
 * MAX_CONCURRENT_STREAMS = 1 makes the Phase 3 single-stream limit explicit, so
 * conforming clients queue requests instead of getting REFUSED_STREAM. */
static int h2_send_preface(h2session_t* s) {
    const uint8_t settings[] = {
        0x00, H2_SETTINGS_ENABLE_PUSH,            0x00, 0x00, 0x00, 0x00,
        0x00, H2_SETTINGS_MAX_CONCURRENT_STREAMS, 0x00, 0x00, 0x00, 0x01,
    };

    return h2_session_queue_frame(s, H2_FRAME_SETTINGS, 0, 0, settings, sizeof(settings));
}

int h2_server_set_http2(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    h2session_t* s = calloc(1, sizeof(*s));
    if (s == NULL) return 0;

    s->free = h2_session_free;
    s->connection = connection;
    s->read_cap = 16384;
    s->read_buf = malloc(s->read_cap);
    s->decoder = hpack_decoder_create(4096);
    s->encoder = hpack_encoder_create(4096);
    if (s->read_buf == NULL || s->decoder == NULL || s->encoder == NULL) {
        h2_session_free(s);
        return 0;
    }

    h2frame_parser_init(&s->frame, 1, H2_MAX_FRAME_SIZE_DEFAULT); /* expect the client preface */
    s->peer_max_frame_size = H2_MAX_FRAME_SIZE_DEFAULT;
    s->peer_initial_window = H2_DEFAULT_WINDOW;
    s->peer_header_table_size = 4096;
    s->send_window = H2_DEFAULT_WINDOW;
    s->stream_send_window = H2_DEFAULT_WINDOW;
    s->stream_state = H2_STREAM_IDLE;
    s->content_length = -1;
    s->error_code = H2_ERR_PROTOCOL_ERROR;

    if (!h2_send_preface(s)) {
        h2_session_free(s);
        return 0;
    }

    if (ctx->parser != NULL)
        ((requestparser_t*)ctx->parser)->free(ctx->parser);

    ctx->parser = s;
    ctx->is_http2 = 1;
    /* h2 connections are always persistent; connection_after_write() tears down
     * a connection whose keepalive flag is clear. */
    connection->keepalive = 1;
    connection->read = h2_server_guard_read;
    connection->write = h2_server_guard_write;

    if (h2_flush_out(s) == 0) return 0;

    log_info("HTTP/2 session established (fd %d)\n", connection->fd);

    return 1;
}

void h2_session_free(void* arg) {
    if (arg == NULL) return;

    h2session_t* s = arg;

    free(s->read_buf);
    free(s->cont);
    free(s->out);
    if (s->decoder != NULL) hpack_decoder_free(s->decoder);
    if (s->encoder != NULL) hpack_encoder_free(s->encoder);
    h2frame_parser_free(&s->frame);

    free(s);
}

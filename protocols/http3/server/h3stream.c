#include "h3stream.h"

#include <stdlib.h>
#include <string.h>

#include "appconfig.h"          /* env()->main.client_max_body_size */
#include "h2field.h"            /* h2_field_validate (trailers octet rules) */
#include "httpcommon.h"         /* http_payload_t */
#include "httpfields.h"         /* httpfields_to_request, httpfields_is_forbidden_header */
#include "httprequest.h"        /* httprequest_create_payload_file, ..._trailern_add */
#include "httpresponse.h"       /* httpresponse_free -- the stream owns its response */
#include "httprequestparser.h"  /* httpparser_select_server */
#include "httpparsercommon.h"   /* HTTP1PARSER_CONTINUE */
#include "log.h"
#include "metrics.h"
#include "qpack.h"
#include "quicmemory.h"

_Static_assert(sizeof(qpack_header_t) == sizeof(httpfields_field_t),
               "qpack_header_t must stay layout-compatible with httpfields_field_t");

uint64_t h3stream_status_error(h3stream_status_e st) {
    switch (st) {
    case H3STREAM_ERR_MESSAGE:             return H3_MESSAGE_ERROR;
    case H3STREAM_ERR_REQUEST_INCOMPLETE:  return H3_REQUEST_INCOMPLETE;
    case H3STREAM_ERR_FRAME_UNEXPECTED:    return H3_FRAME_UNEXPECTED;
    case H3STREAM_ERR_FRAME:               return H3_FRAME_ERROR;
    case H3STREAM_ERR_EXCESSIVE_LOAD:      return H3_EXCESSIVE_LOAD;
    case H3STREAM_ERR_QPACK_DECOMPRESSION: return QPACK_DECOMPRESSION_FAILED;
    /* BODY_TOO_LARGE / FIELDS_TOO_LARGE / MISDIRECTED / INTERNAL are answered
     * with a status code on a stream that stays well-formed, so they carry no
     * h3 error. */
    default:                               return H3_NO_ERROR;
    }
}

h3stream_t* h3stream_create(connection_t* connection, size_t max_field_section_size) {
    h3stream_t* st = malloc(sizeof * st);
    if (st == NULL) return NULL;

    h3frame_parser_init(&st->parser);
    st->request = httprequest_create(connection);
    if (st->request == NULL) {
        free(st);
        return NULL;
    }

    st->response = NULL;
    atomic_init(&st->response_ready, 0);
    st->response_done = 0;
    st->response_headers_sent = 0;
    st->early_hints = NULL;
    st->last_early_hint = NULL;
    st->stage = H3STREAM_EXPECT_HEADERS;
    st->headers_done = 0;
    st->content_length = -1;
    st->req_body_len = 0;
    st->qpack_deferred = NULL;
    st->qpack_deferred_len = 0;
    st->qpack_deferred_cap = 0;
    st->qpack_deferred_fin = 0;
    st->qpack_blocked = 0;
    st->qpack_required_insert_count = 0;
    st->max_field_section_size = max_field_section_size;

    /* The factor HTTP/2 uses, not the ×2 the plan first guessed at: an operator
     * tunes one idea of "too many headers" across both protocols, and two
     * different multipliers behind the same idea is a trap. "No limit" stays no
     * limit -- 0 times anything must not become a cap of 0, which would reject
     * every field section there is. */
    st->max_field_section_hard =
        max_field_section_size == 0 ? 0
                                    : max_field_section_size * H3STREAM_FIELD_SECTION_HARD_FACTOR;

    return st;
}

void h3stream_free(h3stream_t* st) {
    if (st == NULL) return;
    h3frame_parser_free(&st->parser);
    if (st->request != NULL) httprequest_free(st->request);
    if (st->response != NULL) httpresponse_free(st->response);
    http_headers_free(st->early_hints);
    h3stream_qpack_deferred_clear(st);
    free(st);
}

int h3stream_qpack_defer(h3stream_t* st, const uint8_t* data, size_t len, int fin) {
    if (st == NULL || (data == NULL && len != 0)) return 0;
    if (len > SIZE_MAX - st->qpack_deferred_len) return 0;
    const size_t need = st->qpack_deferred_len + len;
    if (need > H3FRAME_MAX_ACCUMULATED) return 0;

    if (need > st->qpack_deferred_cap) {
        size_t cap = st->qpack_deferred_cap ? st->qpack_deferred_cap : 256;
        while (cap < need) cap *= 2;
        if (cap > H3FRAME_MAX_ACCUMULATED) cap = H3FRAME_MAX_ACCUMULATED;
        const size_t growth = cap - st->qpack_deferred_cap;
        if (!quicmemory_reserve(growth)) return 0;
        uint8_t* grown = realloc(st->qpack_deferred, cap);
        if (grown == NULL) { quicmemory_release(growth); return 0; }
        st->qpack_deferred = grown;
        st->qpack_deferred_cap = cap;
    }
    if (len != 0) memcpy(st->qpack_deferred + st->qpack_deferred_len, data, len);
    st->qpack_deferred_len = need;
    if (fin) st->qpack_deferred_fin = 1;
    return 1;
}

void h3stream_qpack_deferred_clear(h3stream_t* st) {
    if (st == NULL) return;
    quicmemory_release(st->qpack_deferred_cap);
    free(st->qpack_deferred);
    st->qpack_deferred = NULL;
    st->qpack_deferred_len = 0;
    st->qpack_deferred_cap = 0;
    st->qpack_deferred_fin = 0;
}

int h3stream_qpack_block(h3stream_t* st, uint64_t required,
                         const uint8_t* tail, size_t tail_len, int fin) {
    if (st == NULL || required == 0 || st->qpack_blocked) return 0;
    if (!h3stream_qpack_defer(st, tail, tail_len, fin)) return 0;
    st->qpack_required_insert_count = required;
    st->qpack_blocked = 1;
    return 1;
}

int h3stream_qpack_can_resume(const h3stream_t* st, uint64_t insert_count) {
    return st != NULL && st->qpack_blocked &&
           insert_count >= st->qpack_required_insert_count;
}

void h3stream_qpack_unblock(h3stream_t* st) {
    if (st == NULL) return;
    st->qpack_blocked = 0;
    st->qpack_required_insert_count = 0;
    h3stream_qpack_deferred_clear(st);
}

/* Spool a DATA chunk into the request's tmp-file payload, mirroring h2's
 * h2_body_append: the payload type is derived from Content-Type on demand, so
 * get_payload/get_payload_json/multipart behave identically under h3.
 *
 * Returns H3STREAM_OK, or the status the caller must report. Over-limit and
 * "the tmp file would not take it" are told apart deliberately: one is the
 * client's fault (413) and the other ours (500). */
static h3stream_status_e body_append(h3stream_t* st, const uint8_t* data, size_t len) {
    if (len == 0) return H3STREAM_OK;
    if (len > SIZE_MAX - st->req_body_len) return H3STREAM_ERR_BODY_TOO_LARGE;
    /* env() is NULL only in the unit harness (no config loaded); the server has
     * it set at startup. Treat its absence as no limit so the body path stays
     * testable without affecting production. */
    const env_t* cfg = env();
    if (cfg != NULL && st->req_body_len + len > cfg->main.client_max_body_size)
        return H3STREAM_ERR_BODY_TOO_LARGE;

    http_payload_t* payload = &st->request->payload_;
    if (payload->file.fd < 0)
        if (!httprequest_create_payload_file(payload))
            return H3STREAM_ERR_INTERNAL;

    if (!payload->file.append_content(&payload->file, (const char*)data, len))
        return H3STREAM_ERR_INTERNAL;

    st->req_body_len += len;
    return H3STREAM_OK;
}

/* A field section's size as RFC 9114 §4.2.2 counts it -- the same formula HPACK
 * and HTTP/2 use, which is why the two protocols can share one operator-facing
 * idea of "too many headers" even with different limits behind it. */
static size_t field_section_size(const qpack_header_t* fields, size_t count) {
    size_t total = 0;

    for (size_t i = 0; i < count; i++)
        total += fields[i].name_len + fields[i].value_len + 32;

    return total;
}

/* Decode a field section. QPACK_DECOMPRESSION_FAILED is connection-fatal: the
 * dynamic-table context is shared and unrecoverable, so it cannot be a stream
 * error. Returns H3STREAM_OK when *fields is usable.
 *
 * Two limits, not one, exactly as HTTP/2 settled on (docs/http2/08 phase A):
 *
 *   - the **hard** cap goes to the decoder, which stops the moment it is
 *     passed. A block that big is decoded only as far as proving it is that
 *     big, and the connection ends -- a peer that sends one is not going to
 *     send a smaller one next;
 *   - the **advertised** limit is checked afterwards, over a section that
 *     decoded in full. That one is a 431: the message is well-formed and the
 *     client can be told what was wrong with it, which it cannot be if the
 *     connection is gone.
 *
 * Without the first, the advertised limit was doing both jobs, and the only
 * outcome available for a field section of any size at all was to answer it. */
static h3stream_status_e decode_fields(h3stream_t* st, qpack_decoder_t* qdec,
                                       const uint8_t* block, size_t len,
                                       qpack_header_t** fields, size_t* count) {
    const qpack_status_e qst = qpack_decode_block(qdec, block, len,
                                                  st->max_field_section_hard, fields, count);
    switch (qst) {
    case QPACK_OK:               break;
    case QPACK_BLOCKED:          return H3STREAM_QPACK_BLOCKED;
    case QPACK_ERR_TOO_LARGE:
        metrics_h3(METRICS_H3_FIELD_SECTION_HARD);
        log_error("h3: field section over the hard cap (%zu) -- closing connection\n",
                  st->max_field_section_hard);
        return H3STREAM_ERR_EXCESSIVE_LOAD;
    case QPACK_ERR_DECOMPRESSION:
    case QPACK_ERR_ENCODER_STREAM: return H3STREAM_ERR_QPACK_DECOMPRESSION;
    default:                     return H3STREAM_ERR_INTERNAL;
    }

    if (st->max_field_section_size != 0 &&
        field_section_size(*fields, *count) > st->max_field_section_size) {
        qpack_headers_free(*fields, *count);
        *fields = NULL;
        *count = 0;
        return H3STREAM_ERR_FIELDS_TOO_LARGE;
    }

    return H3STREAM_OK;
}

/* First HEADERS → request. */
static h3stream_status_e build_request(h3stream_t* st, qpack_decoder_t* qdec,
                                       const uint8_t* block, size_t len) {
    qpack_header_t* fields = NULL;
    size_t count = 0;
    const h3stream_status_e dst = decode_fields(st, qdec, block, len, &fields, &count);
    if (dst != H3STREAM_OK) { qpack_headers_free(fields, count); return dst; }

    int64_t cl = -1;
    const http_fields_status_e hf = httpfields_to_request(
        st->request, (const httpfields_field_t*)fields, count, HTTP_FIELDS_H3, &cl);
    qpack_headers_free(fields, count);
    st->content_length = cl;

    /* EXTENDED_CONNECT/WEBSOCKET are dispatch verdicts, not assembly errors: the
     * request is well-formed, so it is announced ready and h3session decides
     * (501 for an unsupported :protocol, a tunnel for websocket — docs/http3/05
     * §8). The common path is OK. */
    switch (hf) {
    case HTTP_FIELDS_OK:
    case HTTP_FIELDS_EXTENDED_CONNECT:
    case HTTP_FIELDS_WEBSOCKET:
        break;
    case HTTP_FIELDS_INTERNAL:
        return H3STREAM_ERR_INTERNAL;
    default:
        return H3STREAM_ERR_MESSAGE;
    }

    /* :authority (now Host) picks the virtual server, and on a TLS connection it
     * must agree with the one SNI chose (RFC 9110 §7.4). Left to the caller in
     * httpfields_to_request because it needs the connection, which that function
     * deliberately does not take -- so it happens here, exactly as h2 does it in
     * h2_build_request. Without it every request would be routed to the
     * listener's first vhost. */
    if (st->request->connection != NULL) {
        const http_header_t* host = st->request->get_headern(st->request, "Host", 4);
        if (host == NULL) return H3STREAM_ERR_MESSAGE;

        /* The two failures are not the same thing. A syntactically broken
         * authority (BAD_REQUEST -- an empty one, an unterminated IPv6 literal)
         * is malformed under §4.1.2 and gets the stream error. One that is
         * merely addressed to a host we do not serve is a routing outcome, and
         * §4.1.2 does not cover it; it is answered 404, as HTTP/1.1 does. */
        const int sel = httpparser_select_server(st->request->connection,
                                                 host->value, host->value_length);
        if (sel == HTTP1PARSER_HOST_NOT_FOUND) return H3STREAM_ERR_MISDIRECTED;
        if (sel != HTTP1PARSER_CONTINUE) return H3STREAM_ERR_MESSAGE;
    }

    return H3STREAM_REQUEST_READY;
}



/* Trailers (a HEADERS frame after DATA). The same octet and forbidden-field rules
 * as a header block apply, plus §4.1.2: no pseudo-headers, and content-length is
 * refused (§8.1) — by the time trailers arrive, the message has been read. */
static h3stream_status_e consume_trailers(h3stream_t* st, qpack_decoder_t* qdec,
                                          const uint8_t* block, size_t len) {
    qpack_header_t* fields = NULL;
    size_t count = 0;
    const h3stream_status_e dst = decode_fields(st, qdec, block, len, &fields, &count);
    if (dst != H3STREAM_OK) { qpack_headers_free(fields, count); return dst; }

    h3stream_status_e r = H3STREAM_OK;
    for (size_t i = 0; i < count; i++) {
        if (fields[i].name_len > 0 && fields[i].name[0] == ':') { r = H3STREAM_ERR_MESSAGE; break; }
        if (h2_field_validate(fields[i].name, fields[i].name_len,
                              fields[i].value, fields[i].value_len) != H2_FIELD_OK) {
            r = H3STREAM_ERR_MESSAGE; break;
        }
        if (httpfields_is_forbidden_header(fields[i].name, fields[i].name_len) ||
            (fields[i].name_len == 14 && memcmp(fields[i].name, "content-length", 14) == 0)) {
            r = H3STREAM_ERR_MESSAGE; break;
        }
        if (httprequest_trailern_add(st->request,
                                     fields[i].name, fields[i].name_len,
                                     fields[i].value, fields[i].value_len) != 0) {
            r = H3STREAM_ERR_INTERNAL; break;
        }
    }

    qpack_headers_free(fields, count);
    return r;
}

/* Everything that can only be judged once the stream has ended cleanly. */
static h3stream_status_e on_fin(h3stream_t* st) {
    /* §4.1: a request stream that ends before the request is complete is
     * H3_REQUEST_INCOMPLETE -- a stream error, the connection is fine. */
    if (!st->headers_done) return H3STREAM_ERR_REQUEST_INCOMPLETE;

    /* §7.1: a frame still half-read when the stream ends cleanly is a
     * *connection* error. Checked before content-length because a truncated
     * DATA frame would otherwise be reported as a length mismatch, which is the
     * wrong error at the wrong scope. */
    if (!h3frame_parser_at_boundary(&st->parser)) return H3STREAM_ERR_FRAME;

    /* §4.1.2: a content-length that disagrees with the body actually delivered
     * makes the request malformed (the same check h2 makes in h2_dispatch). */
    if (st->content_length >= 0 &&
        (uint64_t)st->content_length != (uint64_t)st->req_body_len)
        return H3STREAM_ERR_MESSAGE;

    return H3STREAM_DONE;
}

h3stream_status_e h3stream_feed(h3stream_t* st, qpack_decoder_t* qdec,
                                const uint8_t** pp, const uint8_t* end, int fin) {
    /* An empty feed is legal: FIN can arrive on a STREAM frame with no bytes,
     * and that is exactly when on_fin below has to run. Only a cursor past its
     * own end is a bad argument. */
    if (st == NULL || pp == NULL || qdec == NULL || *pp > end) return H3STREAM_ERR_INTERNAL;

    /* Retry a complete HEADERS payload retained by h3frame_parser. No request
     * bytes are consumed while the required insertion is still in the future. */
    if (st->qpack_blocked) {
        if (!h3stream_qpack_can_resume(st, qpack_decoder_insert_count(qdec)))
            return H3STREAM_QPACK_BLOCKED;

        h3stream_status_e r = build_request(st, qdec, st->parser.payload,
                                             st->parser.payload_len);
        if (r != H3STREAM_REQUEST_READY) return r;
        st->qpack_blocked = 0;
        st->qpack_required_insert_count = 0;
        st->headers_done = 1;
        st->stage = H3STREAM_BODY;
        return H3STREAM_REQUEST_READY;
    }

    /* A successful retry returns REQUEST_READY first so dispatch ordering stays
     * identical to an unblocked request. On the following pass replay bytes
     * that QUIC had already handed us after that HEADERS frame. Detach the old
     * allocation before recursion: replay may itself encounter blocked
     * trailers and must then be able to install a fresh deferred buffer. */
    if (st->qpack_deferred_len != 0 || st->qpack_deferred_fin) {
        uint8_t* saved = st->qpack_deferred;
        const size_t saved_len = st->qpack_deferred_len;
        const size_t saved_cap = st->qpack_deferred_cap;
        const int saved_fin = st->qpack_deferred_fin;
        st->qpack_deferred = NULL;
        st->qpack_deferred_len = 0;
        st->qpack_deferred_cap = 0;
        st->qpack_deferred_fin = 0;

        const uint8_t* replay = saved;
        const uint8_t* replay_end = saved_len != 0 ? saved + saved_len : saved;
        h3stream_status_e r = h3stream_feed(st, qdec, &replay,
                                             replay_end, saved_fin);
        quicmemory_release(saved_cap);
        free(saved);
        return r;
    }

    int saw_body = 0;

    for (;;) {
        const h3frame_status_e fst = h3frame_parser_feed(&st->parser, pp, end);

        switch (fst) {
        case H3FRAME_CONTINUE:
            /* No complete frame left in this feed. */
            if (fin) return on_fin(st);
            return saw_body ? H3STREAM_BODY_CHUNK : H3STREAM_NEED_MORE;

        case H3FRAME_DATA_CHUNK: {
            /* DATA is legal only between HEADERS and trailers. */
            if (st->stage != H3STREAM_BODY) return H3STREAM_ERR_FRAME_UNEXPECTED;
            const h3stream_status_e bst =
                body_append(st, st->parser.payload, st->parser.payload_len);
            if (bst != H3STREAM_OK) return bst;
            saw_body = 1;
            continue;
        }

        case H3FRAME_READY:
            if (st->parser.type == H3_FRAME_HEADERS) {
                if (st->stage == H3STREAM_EXPECT_HEADERS) {
                    const h3stream_status_e r = build_request(st, qdec, st->parser.payload, st->parser.payload_len);
                    if (r == H3STREAM_QPACK_BLOCKED) {
                        uint64_t required = 0;
                        if (qpack_required_insert_count(qdec, st->parser.payload,
                                                       st->parser.payload_len,
                                                       &required) != QPACK_BLOCKED ||
                            !h3stream_qpack_block(st, required, *pp,
                                                 (size_t)(end - *pp), fin))
                            return H3STREAM_ERR_INTERNAL;
                        *pp = end;
                        return H3STREAM_QPACK_BLOCKED;
                    }
                    if (r != H3STREAM_REQUEST_READY) return r;
                    st->headers_done = 1;
                    st->stage = H3STREAM_BODY;
                    return H3STREAM_REQUEST_READY; /* stop → caller dispatches */
                }
                if (st->stage == H3STREAM_BODY) {
                    const h3stream_status_e r = consume_trailers(st, qdec, st->parser.payload, st->parser.payload_len);
                    if (r != H3STREAM_OK) return r;
                    st->stage = H3STREAM_TRAILERS;
                    continue;
                }
                return H3STREAM_ERR_FRAME_UNEXPECTED; /* HEADERS after trailers */
            }
            /* SETTINGS/GOAWAY/MAX_PUSH_ID/CANCEL_PUSH/PUSH_PROMISE belong on the
             * control stream; on a request stream any of them is a frame error. */
            return H3STREAM_ERR_FRAME_UNEXPECTED;

        case H3FRAME_SKIPPED:
            continue; /* unknown / grease frame type ignored */

        case H3FRAME_HEAD:
            continue; /* not reported by this parser (READY/DATA_CHUNK are) */

        /* The three frame-level failures carry three different codes, and
         * h3frame.h names the mapping. Keeping them apart is the whole point of
         * §10 in the plan doc. */
        case H3FRAME_ERR_RESERVED:    /* an HTTP/2 codepoint smuggled in (§11.2.1) */
            return H3STREAM_ERR_FRAME_UNEXPECTED;
        case H3FRAME_ERR_ENCODING:    /* truncated / malformed frame (§7.1) */
            return H3STREAM_ERR_FRAME;
        case H3FRAME_ERR_TOO_LARGE:   /* over the control-frame accumulation cap */
            return H3STREAM_ERR_EXCESSIVE_LOAD;

        case H3FRAME_ERR_OOM:
            return H3STREAM_ERR_INTERNAL;
        }
    }
}

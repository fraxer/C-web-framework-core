#include "h3conn.h"

#include <stdlib.h>
#include <string.h>

#include "connection_s.h"
#include "httpresponse.h"
#include "log.h"
#include "qpack.h"

/* One read from a QUIC stream. Big enough that an ordinary request's headers
 * arrive in one pass, small enough to stay on the stack: a body of any size is
 * spooled straight into the request's payload file as it goes past. */
#define H3CONN_READ_CHUNK 4096

static h3conn_result_t __ok(void) {
    h3conn_result_t r = { H3CONN_OK, 0, 0 };
    return r;
}

static h3conn_result_t __closed(uint64_t error) {
    h3conn_result_t r = { H3CONN_CLOSED, error, 0 };
    return r;
}

static h3conn_result_t __reset(uint64_t error) {
    h3conn_result_t r = { H3CONN_REQUEST_RESET, error, 0 };
    return r;
}

static h3conn_result_t __refused(int http_status) {
    h3conn_result_t r = { H3CONN_REQUEST_REFUSED, 0, http_status };
    return r;
}

/* ---- Lifecycle ---- */

h3conn_t* h3conn_create(uint64_t max_field_section_size, int enable_connect_protocol) {
    h3conn_t* c = calloc(1, sizeof * c);
    if (c == NULL) return NULL;

    c->session = h3session_create(max_field_section_size, enable_connect_protocol);
    if (c->session == NULL) {
        free(c);
        return NULL;
    }

    c->max_field_section_size = max_field_section_size;

    return c;
}

void h3conn_free(h3conn_t* c) {
    if (c == NULL) return;

    h3session_free(c->session);
    free(c);
}

static void __app_free(h3app_t* app) {
    if (app == NULL) return;

    h3uni_recv_free(app->uni);
    h3stream_free(app->req);
    free(app);
}

void h3conn_stream_release(quicstream_t* qs) {
    if (qs == NULL) return;

    __app_free(qs->app);
    qs->app = NULL;
}

h3stream_t* h3conn_request_of(quicstream_t* qs) {
    if (qs == NULL || qs->app == NULL) return NULL;

    const h3app_t* app = qs->app;

    return app->is_request ? app->req : NULL;
}

h3conn_t* h3_conn_of(connection_t* connection) {
    if (connection == NULL || connection->transport != CONN_TRANSPORT_QUIC) return NULL;

    connection_server_ctx_t* ctx = connection->ctx;
    if (ctx == NULL) return NULL;

    return ctx->parser;
}

quicstream_t* h3conn_stream_by_response(quicconn_t* qc, const httpresponse_t* response) {
    if (qc == NULL || response == NULL) return NULL;

    for (quicstream_t* qs = qc->streams; qs != NULL; qs = qs->next) {
        const h3stream_t* st = h3conn_request_of(qs);
        if (st != NULL && st->response == response) return qs;
    }

    return NULL;
}

/* Attach state on first sight of a stream. Which kind it is follows from the
 * id alone (§6.1): bidirectional means a request, unidirectional means a
 * service stream whose own first varint says which. */
static h3app_t* __app_of(h3conn_t* c, quicstream_t* qs) {
    if (qs->app != NULL) return qs->app;

    h3app_t* app = calloc(1, sizeof * app);
    if (app == NULL) return NULL;

    if (quic_stream_is_uni(qs->id)) {
        app->uni = h3uni_recv_create(qs->id);
        if (app->uni == NULL) { free(app); return NULL; }
    } else {
        app->is_request = 1;
        app->req = h3stream_create((size_t)c->max_field_section_size);
        if (app->req == NULL) { free(app); return NULL; }
    }

    qs->app = app;

    return app;
}

/* ---- Our own service streams ---- */

/* Open one server-initiated unidirectional stream and write `len` opening
 * bytes onto it. */
static int __open_uni(quicconn_t* qc, const uint8_t* preamble, size_t len,
                      uint64_t* id_out) {
    quicstream_t* qs = quicconn_open_uni(qc);
    if (qs == NULL) return 0;

    if (!quicstream_write(qs, preamble, len)) return 0;

    if (id_out != NULL) *id_out = qs->id;

    return 1;
}

int h3conn_open_service_streams(h3conn_t* c, quicconn_t* qc) {
    if (c == NULL || qc == NULL) return 0;
    if (c->service_streams_open) return 1;

    uint8_t buf[128];

    /* Control first, and SETTINGS with it: §6.2.1 requires SETTINGS to be the
     * first frame on the control stream, and nothing else we send has any
     * meaning until the peer has read it. */
    size_t n = h3session_control_preamble(c->session, buf, sizeof buf);
    if (n == 0 || !__open_uni(qc, buf, n, &c->session->ctrl_send_id)) return 0;

    /* Both QPACK streams stay empty in lite -- we insert nothing and, with a
     * Required Insert Count of 0 everywhere, have nothing to acknowledge -- but
     * they are opened anyway: RFC 9204 §4.2 has each side open both, and a peer
     * that waits for ours would wait forever. */
    n = h3session_uni_preamble(buf, sizeof buf, H3_UNI_STREAM_QPACK_ENCODER);
    if (n == 0 || !__open_uni(qc, buf, n, &c->session->qpack_enc_send_id)) return 0;

    n = h3session_uni_preamble(buf, sizeof buf, H3_UNI_STREAM_QPACK_DECODER);
    if (n == 0 || !__open_uni(qc, buf, n, &c->session->qpack_dec_send_id)) return 0;

    /* And one grease stream (RFC 9287), which exists only to be ignored. Sent
     * because a peer's handling of the unknown is otherwise exercised by
     * nobody, and the cost is one stream that never carries a byte. */
    n = h3session_uni_preamble(buf, sizeof buf, 0x21);
    if (n == 0 || !__open_uni(qc, buf, n, &c->session->grease_send_id)) return 0;

    c->service_streams_open = 1;

    return 1;
}

/* ---- Reading ---- */

/* Map an h3session verdict onto transport actions. */
static h3conn_result_t __apply_uni_verdict(quicstream_t* qs, h3app_t* app,
                                           h3session_verdict_t v) {
    switch (v.action) {
    case H3SESSION_OK:
        return __ok();

    case H3SESSION_STOP_SENDING:
        /* §6.2.3: an unknown stream type is refused, not fatal. The stream has
         * no send side of ours to reset -- it is unidirectional and theirs --
         * so STOP_SENDING alone is the whole of the answer. */
        quicstream_stop_sending(qs, v.error);
        app->drained = 1;
        return __ok();

    case H3SESSION_CONN_ERROR:
        return __closed(v.error);
    }

    return __ok();
}

/* Map an h3stream status onto transport actions. */
static h3conn_result_t __apply_stream_status(quicstream_t* qs, h3app_t* app,
                                             h3stream_status_e st) {
    if (h3stream_status_is_connection(st))
        return __closed(h3stream_status_error(st));

    switch (st) {
    case H3STREAM_ERR_MESSAGE:
    case H3STREAM_ERR_REQUEST_INCOMPLETE: {
        /* A stream error kills the stream in both directions: RESET_STREAM
         * abandons what we would have sent, STOP_SENDING what they would still
         * send. Sending only the first leaves a client uploading a body nobody
         * will ever read. */
        const uint64_t code = h3stream_status_error(st);
        quicstream_reset(qs, code);
        quicstream_stop_sending(qs, code);
        app->drained = 1;
        return __reset(code);
    }

    /* The three that are answered rather than reset. The stream stays
     * well-formed, so the response goes out on it normally. */
    case H3STREAM_ERR_BODY_TOO_LARGE:   app->drained = 1; return __refused(413);
    case H3STREAM_ERR_FIELDS_TOO_LARGE: app->drained = 1; return __refused(431);
    case H3STREAM_ERR_INTERNAL:         app->drained = 1; return __refused(500);

    default:
        return __ok();
    }
}

/* A peer RESET_STREAM. */
static h3conn_result_t __on_reset(h3conn_t* c, quicstream_t* qs, h3app_t* app) {
    if (!app->is_request) {
        /* §6.2.6: resetting a critical stream is as fatal as closing it. */
        return __apply_uni_verdict(qs, app, h3session_uni_closed(c->session, app->uni));
    }

    /* The request is abandoned. Nothing is owed to the peer -- it asked for
     * this -- so the stream is simply dropped. */
    app->drained = 1;

    return __reset(H3_REQUEST_CANCELLED);
}

static h3conn_result_t __read_uni(h3conn_t* c, quicstream_t* qs, h3app_t* app) {
    uint8_t buf[H3CONN_READ_CHUNK];

    for (;;) {
        const size_t n = quicstream_read(qs, buf, sizeof buf);
        const int fin = (qs->recv_state == QUIC_RECV_DATA_READ);

        if (n == 0 && !fin) return __ok();

        if (app->drained) {
            /* Bytes read and thrown away; only the ending still matters. */
            if (fin) return __apply_uni_verdict(qs, app,
                                                h3session_uni_closed(c->session, app->uni));
            if (n < sizeof buf) return __ok();
            continue;
        }

        const h3conn_result_t r =
            __apply_uni_verdict(qs, app, h3session_uni_feed(c->session, app->uni, buf, n, fin));
        if (r.status != H3CONN_OK) return r;

        if (fin || n < sizeof buf) return __ok();
    }
}

static h3conn_result_t __read_request(h3conn_t* c, quicstream_t* qs, h3app_t* app) {
    uint8_t buf[H3CONN_READ_CHUNK];
    int headers_became_ready = 0;

    for (;;) {
        const size_t n = quicstream_read(qs, buf, sizeof buf);
        const int fin = (qs->recv_state == QUIC_RECV_DATA_READ);

        if (n == 0 && !fin) break;

        if (app->drained) {
            if (fin || n < sizeof buf) break;
            continue;
        }

        /* h3stream_feed stops at each event, so one buffer may need several
         * passes: HEADERS ends one, and the body behind it is still unread. */
        const uint8_t* p = buf;
        const uint8_t* end = buf + n;

        for (;;) {
            const h3stream_status_e st = h3stream_feed(app->req, c->session->qdec, &p, end, fin);

            if (st == H3STREAM_REQUEST_READY) {
                headers_became_ready = 1;

                /* §5.2: once we have said we will not serve this stream, the
                 * honest answer is to say so at once. H3_REQUEST_REJECTED is
                 * the code that tells a client the request was untouched and is
                 * safe to retry on another connection. */
                if (!h3session_accepts_request(c->session, qs->id)) {
                    quicstream_reset(qs, H3_REQUEST_REJECTED);
                    quicstream_stop_sending(qs, H3_REQUEST_REJECTED);
                    app->drained = 1;
                    return __reset(H3_REQUEST_REJECTED);
                }

                /* The rest of the buffer is body or trailers; keep going. */
                if (p < end || fin) continue;
                break;
            }

            if (st == H3STREAM_DONE) {
                h3conn_result_t r = { H3CONN_REQUEST_DONE, 0, 0 };
                return r;
            }

            if (st == H3STREAM_NEED_MORE || st == H3STREAM_BODY_CHUNK) break;

            return __apply_stream_status(qs, app, st);
        }

        if (fin || n < sizeof buf) break;
    }

    if (headers_became_ready) {
        h3conn_result_t r = { H3CONN_REQUEST_HEADERS, 0, 0 };
        return r;
    }

    return __ok();
}

h3conn_result_t h3conn_stream_read(h3conn_t* c, quicstream_t* qs) {
    if (c == NULL || qs == NULL) return __closed(H3_INTERNAL_ERROR);

    h3app_t* app = __app_of(c, qs);
    if (app == NULL) return __closed(H3_INTERNAL_ERROR);

    if (qs->recv_state == QUIC_RECV_RESET_RECVD || qs->recv_state == QUIC_RECV_RESET_READ) {
        if (app->drained) return __ok();
        return __on_reset(c, qs, app);
    }

    return app->is_request ? __read_request(c, qs, app) : __read_uni(c, qs, app);
}

#include "h3conn.h"

#include <stdlib.h>
#include <string.h>

#include "connection_s.h"
#include "h3response.h"
#include "http_filter.h"
#include "httpresponse.h"
#include "httpserverhandlers.h"
#include "log.h"
#include "metrics.h"
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

h3conn_t* h3conn_create(connection_t* connection, uint64_t max_field_section_size,
                        int enable_connect_protocol) {
    h3conn_t* c = calloc(1, sizeof * c);
    if (c == NULL) return NULL;

    c->free = (void(*)(void*))h3conn_free;
    c->connection = connection;

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

/* Whether the transport may release the stream: for a request, once the
 * response has been written in full. Service streams say no by never finishing,
 * which is what keeps the control stream alive for the connection. */
static int __app_done(h3app_t* app) {
    if (app == NULL) return 1;
    if (!app->is_request) return 0;

    return app->req == NULL || app->req->response_done;
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
    qs->app_free = NULL;
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
        app->req = h3stream_create(c->connection, (size_t)c->max_field_section_size);
        if (app->req == NULL) { free(app); return NULL; }
    }

    qs->app = app;
    /* The transport owns when a stream dies and frees it without knowing what
     * `app` is, so it is told here how to let go of it. */
    qs->app_free = (void(*)(void*))__app_free;
    qs->app_done = (int(*)(void*))__app_done;

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
     * nobody, and the cost is one stream that never carries a byte.
     *
     * Best effort, and that is the whole point: §6.2 obliges a peer to allow
     * only the three streams above, so a fourth is a courtesy it may refuse.
     * Treating the refusal as failure killed every connection from a peer that
     * granted exactly three -- immediately after the handshake, with
     * H3_INTERNAL_ERROR, which names nothing. h3spec grants exactly three, and
     * this one bug accounted for all 31 of its transport failures: the
     * connection was dead before any of them could be tested. */
    c->session->grease_send_id = H3_STREAM_ID_NONE;
    n = h3session_uni_preamble(buf, sizeof buf, 0x21);
    if (n > 0) __open_uni(qc, buf, n, &c->session->grease_send_id);

    c->service_streams_open = 1;

    if (c->session->grease_send_id == H3_STREAM_ID_NONE)
        log_info("h3: service streams opened: control %llu, qpack %llu/%llu, no grease "
                 "(the peer granted exactly three)\n",
                 (unsigned long long)c->session->ctrl_send_id,
                 (unsigned long long)c->session->qpack_enc_send_id,
                 (unsigned long long)c->session->qpack_dec_send_id);
    else
        log_info("h3: service streams opened: control %llu, qpack %llu/%llu, grease %llu\n",
                 (unsigned long long)c->session->ctrl_send_id,
                 (unsigned long long)c->session->qpack_enc_send_id,
                 (unsigned long long)c->session->qpack_dec_send_id,
                 (unsigned long long)c->session->grease_send_id);

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
        metrics_h3(METRICS_H3_CONN_ERROR);
        return __closed(v.error);
    }

    return __ok();
}

/* Map an h3stream status onto transport actions. */
static h3conn_result_t __apply_stream_status(quicstream_t* qs, h3app_t* app,
                                             h3stream_status_e st) {
    if (h3stream_status_is_connection(st)) {
        metrics_h3(METRICS_H3_CONN_ERROR);
        return __closed(h3stream_status_error(st));
    }

    switch (st) {
    case H3STREAM_ERR_MESSAGE:
    case H3STREAM_ERR_REQUEST_INCOMPLETE: {
        metrics_h3(METRICS_H3_STREAM_ERROR);

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
    case H3STREAM_ERR_BODY_TOO_LARGE:
        metrics_h3(METRICS_H3_BODY_TOO_LARGE);
        app->drained = 1;
        return __refused(413);

    case H3STREAM_ERR_FIELDS_TOO_LARGE:
        metrics_h3(METRICS_H3_FIELD_SECTION_TOO_LARGE);
        app->drained = 1;
        return __refused(431);

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
     * this -- so the stream is simply dropped.
     *
     * Charged first, and only when we had not answered yet: a cancellation
     * after the response went out is an ordinary client changing its mind,
     * while one before it is the Rapid Reset shape (docs/http3/07 §4). QUIC
     * makes that attack cheaper than HTTP/2 did -- there is no handshake
     * between the attacker and the next stream -- so the budget is not
     * optional here. */
    const int answered = app->req != NULL && app->req->response_done;
    app->drained = 1;

    metrics_h3(METRICS_H3_STREAMS_CANCELLED);

    if (!answered && !h3session_abort_spend(c->session))
        return __closed(H3_EXCESSIVE_LOAD);

    return __reset(H3_REQUEST_CANCELLED);
}

static h3conn_result_t __read_uni(h3conn_t* c, quicconn_t* qc, quicstream_t* qs, h3app_t* app) {
    uint8_t buf[H3CONN_READ_CHUNK];

    for (;;) {
        const size_t n = quicstream_read(qs, buf, sizeof buf);
        quicconn_consumed(qc, n);
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

static h3conn_result_t __read_request(h3conn_t* c, quicconn_t* qc, quicstream_t* qs, h3app_t* app) {
    uint8_t buf[H3CONN_READ_CHUNK];
    int headers_became_ready = 0;

    for (;;) {
        const size_t n = quicstream_read(qs, buf, sizeof buf);
        quicconn_consumed(qc, n);
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

                /* A request exists from here: the field section decoded into
                 * one. The outcomes that replace this event rather than follow
                 * it -- a field section over the limit, a malformed message --
                 * are counted by their own limits instead, so in a 431 storm
                 * the response classes can outnumber the requests. That is the
                 * honest reading: those responses answered no request. */
                metrics_h3(METRICS_H3_REQUESTS);

                /* §5.2: once we have said we will not serve this stream, the
                 * honest answer is to say so at once. H3_REQUEST_REJECTED is
                 * the code that tells a client the request was untouched and is
                 * safe to retry on another connection. */
                if (!h3session_accepts_request(c->session, qs->id)) {
                    metrics_h3(METRICS_H3_REQUESTS_REJECTED);
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
                /* Reported once and once only. h3stream_feed answers DONE for
                 * every feed after the FIN -- it is a state machine describing a
                 * state, not an event -- so without this the same request is
                 * dispatched again on every datagram that arrives afterwards,
                 * each dispatch opening its own response and its own file
                 * descriptor. A megabyte file came back as seven megabytes, and
                 * nothing below this line could have shown it: each module was
                 * behaving correctly, one request at a time. */
                app->drained = 1;

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

/* ---- Dispatch ---- */

/* Answer a refused request (413/431/500) without running a handler: the stream
 * is well-formed, so it gets a real response rather than a reset. Builds the
 * response the same way the dispatch path does, so it goes out through the same
 * filter chain. */
static void __answer_status(connection_t* connection, quicstream_t* qs, int status_code) {
    h3stream_t* st = h3conn_request_of(qs);
    if (st == NULL) return;

    httpresponse_t* response = httpresponse_create_h3(connection);
    if (response == NULL) return;

    httpresponse_default(response, status_code);
    st->response = response;

    /* The worker is on the read path with the connection lock held, so this is
     * the inline publication -- taking it again would deadlock. */
    h3_server_publish_inline(connection, response);
}

int h3conn_read(h3conn_t* c, quicconn_t* qc, uint64_t* error) {
    if (c == NULL || qc == NULL) return 0;

    connection_t* connection = &qc->conn;

    for (quicstream_t* qs = qc->streams; qs != NULL; qs = qs->next) {
        /* Nothing new and no state change to report: skip without allocating
         * per-stream state for a stream that has said nothing yet. */
        if (qs->app == NULL && quicstream_readable(qs) == 0 &&
            qs->recv_state != QUIC_RECV_RESET_RECVD)
            continue;

        const h3conn_result_t r = h3conn_stream_read(c, qc, qs);

        switch (r.status) {
        case H3CONN_OK:
        case H3CONN_REQUEST_RESET:
            break;

        case H3CONN_REQUEST_HEADERS: {
            /* The body is still to come and the client said it would wait for
             * permission (RFC 9110 §10.1.1). Sent at once, not staged: its whole
             * purpose is to arrive before the client's timer, and the packets
             * for this datagram are built moments from now. */
            h3stream_t* st = h3conn_request_of(qs);
            if (st == NULL) break;

            const http_header_t* expect =
                st->request->get_headern(st->request, "Expect", 6);

            if (expect != NULL && expect->value != NULL &&
                strcasecmp(expect->value, "100-continue") == 0)
                (void)h3_server_continue(c, qs);

            break;
        }

        case H3CONN_REQUEST_DONE: {
            h3stream_t* st = h3conn_request_of(qs);
            if (st == NULL) break;

            log_debug("h3: request cid=%02x%02x%02x%02x stream=%llu\n",
                      qc->odcid.data[0], qc->odcid.data[1],
                      qc->odcid.data[2], qc->odcid.data[3],
                      (unsigned long long)qs->id);

            /* http_server_dispatch queues the handler and, for anything it can
             * answer itself (a static file, a 404, a redirect), publishes
             * inline -- which is why this has to run with the lock already
             * held and never take it again. */
            if (!http_server_dispatch(connection, st->request)) {
                if (error != NULL) *error = H3_INTERNAL_ERROR;
                return 0;
            }
            break;
        }

        case H3CONN_REQUEST_REFUSED:
            __answer_status(connection, qs, r.http_status);
            break;

        case H3CONN_CLOSED:
            if (error != NULL) *error = r.h3_error;
            return 0;
        }
    }

    return 1;
}

/* ---- Publication ---- */

/* The stream carrying `request`, or NULL. */
static quicstream_t* __stream_by_request(quicconn_t* qc, const httprequest_t* request) {
    for (quicstream_t* qs = qc->streams; qs != NULL; qs = qs->next) {
        const h3stream_t* st = h3conn_request_of(qs);
        if (st != NULL && st->request == request) return qs;
    }

    return NULL;
}

int h3_server_attach_response(connection_t* connection, httprequest_t* request,
                              httpresponse_t* response) {
    if (h3_conn_of(connection) == NULL) return 0;

    quicconn_t* qc = (quicconn_t*)connection;
    quicstream_t* qs = __stream_by_request(qc, request);
    if (qs == NULL) return 0;

    h3stream_t* st = h3conn_request_of(qs);
    st->response = response;

    return 1;
}

/* Mark the stream that owns `response` ready for its write turn. Returns 0 when
 * no stream owns it any more -- the client reset it while the handler ran -- in
 * which case the response is nobody's and is freed here. */
static int __publish_one(quicconn_t* qc, httpresponse_t* response) {
    quicstream_t* qs = h3conn_stream_by_response(qc, response);
    if (qs == NULL) {
        httpresponse_free(response);
        return 0;
    }

    h3stream_t* st = h3conn_request_of(qs);
    atomic_store_explicit(&st->response_ready, 1, memory_order_release);

    return 1;
}

int h3_server_response_ready(connection_t* connection, httpresponse_t* response) {
    if (h3_conn_of(connection) == NULL) {
        httpresponse_free(response);
        return 0;
    }

    /* Unlike h2 there is no publish queue here, and none is needed. h2's exists
     * because its publish walks a stream table the worker owns; ours sets one
     * atomic flag on a stream the response already points at, so there is
     * nothing to hand over. The lock is still taken, because finding the stream
     * walks the connection's stream list, which the worker mutates.
     * (docs/concurrency/01 §2.3 measured h2's queue as a net contention cost --
     * worth not repeating.) */
    connection_s_lock(connection, LOCK_SITE_H3_PUBLISH);
    __publish_one((quicconn_t*)connection, response);
    connection_s_unlock(connection);

    connection_server_ctx_t* ctx = connection->ctx;
    atomic_store_explicit(&ctx->need_write, 1, memory_order_release);

    /* Wake the endpoint so it gives this connection a send turn. Takes only the
     * endpoint's leaf lock, never connection_s_lock, which is why it is outside
     * the block above. */
    quicconn_want_write(connection);

    return 1;
}

int h3_server_publish_inline(connection_t* connection, httpresponse_t* response) {
    if (h3_conn_of(connection) == NULL) {
        httpresponse_free(response);
        return 1;
    }

    /* The worker is on the read path and already holds connection_s_lock, so it
     * is the sole owner of the stream list: publish straight to the stream.
     * Taking the lock again would deadlock -- it is not recursive. This is the
     * trap h2 hit and solved the same way (docs/concurrency/01 phase B.1). */
    __publish_one((quicconn_t*)connection, response);

    connection_server_ctx_t* ctx = connection->ctx;
    atomic_store_explicit(&ctx->need_write, 1, memory_order_release);

    return 1;
}

/* ---- Informational responses ---- */

int h3_server_early_hints(connection_t* connection, httpresponse_t* response,
                          http_header_t* fields) {
    if (connection == NULL || fields == NULL) return 0;
    if (h3_conn_of(connection) == NULL) return 0;

    connection_s_lock(connection, LOCK_SITE_H3_PUBLISH);

    int ok = 0;
    quicstream_t* qs = h3conn_stream_by_response((quicconn_t*)connection, response);
    h3stream_t* st = h3conn_request_of(qs);

    if (st != NULL && !st->response_headers_sent) {
        http_header_t* last = fields;
        while (last->next != NULL) last = last->next;

        if (st->early_hints == NULL) st->early_hints = fields;
        else                         st->last_early_hint->next = fields;

        st->last_early_hint = last;
        ok = 1;
    }

    connection_s_unlock(connection);

    if (!ok) return 0;

    connection_server_ctx_t* ctx = connection->ctx;
    atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
    quicconn_want_write(connection);

    return 1;
}

/* Encode one informational response and put it on the stream. */
static int __write_informational(h3conn_t* c, quicstream_t* qs, int status,
                                 const http_header_t* fields) {
    uint8_t* frame = NULL;
    size_t flen = 0;

    if (h3response_informational(c->session->qenc, status, fields, &frame, &flen)
        != H3RESPONSE_OK)
        return 0;

    const int ok = quicstream_write(qs, frame, flen);
    free(frame);

    /* The only place a 1xx is counted: informational responses bypass the write
     * filter entirely, which is where every final status is counted. */
    if (ok) metrics_h3(METRICS_H3_RESPONSE_1XX);

    return ok;
}

int h3_server_continue(h3conn_t* c, quicstream_t* qs) {
    if (c == NULL || qs == NULL) return 0;

    h3stream_t* st = h3conn_request_of(qs);
    if (st == NULL || st->response_headers_sent) return 0;

    /* A 100 carries no fields at all -- just the status (RFC 9110 §10.1.1). */
    return __write_informational(c, qs, 100, NULL);
}

/* ---- The write turn ---- */

/* One stream's turn at the filter chain. */
static int __write_stream(quicstream_t* qs, h3stream_t* st) {
    httpresponse_t* response = st->response;
    if (response == NULL) return 1;

    int r = __run_header_filters(st->request, response);
    if (r == CWF_ERROR) return 0;
    if (r == CWF_EVENT_AGAIN) return 1;   /* budget spent; resumed next turn */

    r = __run_body_filters(st->request, response);
    if (r == CWF_ERROR) return 0;
    if (r == CWF_EVENT_AGAIN) return 1;

    /* Trailing fields close the stream instead of a bare FIN (§4.1). Encoded
     * here, at the point of sending, for the reason h2 encodes them here too:
     * field sections must reach the peer in the order they were encoded, and in
     * full QPACK an early encode would put the dynamic table out of step. */
    if (!qs->send.fin && response->trailer_ != NULL) {
        h3conn_t* c = h3_conn_of(response->connection);
        uint8_t* frame = NULL;
        size_t flen = 0;

        if (c != NULL &&
            h3response_trailers(c->session->qenc, response->trailer_, &frame, &flen)
                == H3RESPONSE_OK) {
            const int ok = quicstream_write(qs, frame, flen);
            free(frame);
            if (!ok) return 0;
        }
    }

    /* The chain emits no buffer at all for an empty body, and the header stage
     * only finishes the stream when it could prove up front that none follows,
     * so close it explicitly when it is still open. */
    if (!qs->send.fin) quicstream_finish(qs);

    st->response_done = 1;
    atomic_store_explicit(&st->response_ready, 0, memory_order_release);

    return 1;
}

int h3conn_write(h3conn_t* c, quicconn_t* qc) {
    if (c == NULL || qc == NULL) return 0;

    /* Informational responses first, and outside the per-stream turn below: a
     * 103 is a staged block, not a scheduled body, and it has to precede the
     * final HEADERS of its own stream. */
    for (quicstream_t* qs = qc->streams; qs != NULL; qs = qs->next) {
        h3stream_t* st = h3conn_request_of(qs);
        if (st == NULL || st->early_hints == NULL) continue;

        http_header_t* fields = st->early_hints;
        st->early_hints = NULL;
        st->last_early_hint = NULL;

        if (!st->response_headers_sent)
            (void)__write_informational(c, qs, 103, fields);

        http_headers_free(fields);
    }

    for (quicstream_t* qs = qc->streams; qs != NULL; qs = qs->next) {
        h3stream_t* st = h3conn_request_of(qs);
        if (st == NULL || st->response_done) continue;
        if (!atomic_load_explicit(&st->response_ready, memory_order_acquire)) continue;

        log_debug("h3: response cid=%02x%02x%02x%02x stream=%llu\n",
                  qc->odcid.data[0], qc->odcid.data[1],
                  qc->odcid.data[2], qc->odcid.data[3],
                  (unsigned long long)qs->id);

        if (!__write_stream(qs, st)) {
            log_error("h3: write failed on stream %llu\n", (unsigned long long)qs->id);
            /* One stream's response failing is not the connection's problem:
             * reset it and carry on with the rest. */
            quicstream_reset(qs, H3_INTERNAL_ERROR);
            st->response_done = 1;
            atomic_store_explicit(&st->response_ready, 0, memory_order_release);
        }
    }

    return 1;
}

int h3conn_has_pending(const h3conn_t* c, const quicconn_t* qc) {
    if (c == NULL || qc == NULL) return 0;

    for (quicstream_t* qs = qc->streams; qs != NULL; qs = qs->next) {
        const h3stream_t* st = h3conn_request_of(qs);
        if (st == NULL || st->response_done) continue;
        if (atomic_load_explicit(&st->response_ready, memory_order_acquire)) return 1;
    }

    return 0;
}

/* ---- Graceful shutdown ---- */

int h3conn_goaway(h3conn_t* c, quicconn_t* qc) {
    if (c == NULL || qc == NULL) return 0;
    if (c->session->goaway_sent) return 1;

    quicstream_t* ctrl = quicconn_stream_find(qc, c->session->ctrl_send_id);
    if (ctrl == NULL) return 0;

    /* The first client bidi stream id we will not serve. next_peer_bidi counts
     * the ones opened so far, so this names the next one -- everything already
     * in flight is below it and still gets answered, which is the whole
     * difference between GOAWAY and hanging up. */
    const uint64_t stream_id = qc->next_peer_bidi << 2;

    uint8_t frame[32];
    const size_t n = h3session_goaway_encode(c->session, frame, sizeof frame, stream_id);
    if (n == 0) return 0;

    if (!quicstream_write(ctrl, frame, n)) return 0;

    log_info("h3: GOAWAY sent, no requests past stream %llu\n",
             (unsigned long long)stream_id);

    return 1;
}

size_t h3conn_requests_in_flight(const h3conn_t* c, const quicconn_t* qc) {
    if (c == NULL || qc == NULL) return 0;

    size_t n = 0;

    for (const quicstream_t* qs = qc->streams; qs != NULL; qs = qs->next) {
        const h3stream_t* st = h3conn_request_of((quicstream_t*)qs);
        if (st != NULL && !st->response_done) n++;
    }

    return n;
}

h3conn_result_t h3conn_stream_read(h3conn_t* c, quicconn_t* qc, quicstream_t* qs) {
    if (c == NULL || qs == NULL) return __closed(H3_INTERNAL_ERROR);

    h3app_t* app = __app_of(c, qs);
    if (app == NULL) return __closed(H3_INTERNAL_ERROR);

    if (qs->recv_state == QUIC_RECV_RESET_RECVD || qs->recv_state == QUIC_RECV_RESET_READ) {
        if (app->drained) return __ok();
        return __on_reset(c, qs, app);
    }

    return app->is_request ? __read_request(c, qc, qs, app) : __read_uni(c, qc, qs, app);
}

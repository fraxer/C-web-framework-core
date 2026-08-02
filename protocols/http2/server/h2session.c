#define _GNU_SOURCE
#include "h2session.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <time.h>

#include "appconfig.h"
#include "base64.h"
#include "connection_queue.h"
#include "connection_s.h"
#include "cookieparser.h"
#include "httpcommon.h"
#include "httpparsercommon.h"
#include "httprequest.h"
#include "httprequestparser.h"
#include "httpresponse.h"
#include "h2stream.h"
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
 * emitting a WINDOW_UPDATE per DATA frame. Scales with the window (an 8 MB
 * window returning credit every 16 KB would cost 512 frames per window), with
 * this as the floor. */
#define H2_WINDOW_UPDATE_MIN 16384
#define H2_WINDOW_UPDATE_DIVISOR 8

/* Cap on a single header block (HEADERS + CONTINUATION*). Bounds the
 * CONTINUATION-flood attack noted in docs/http2/07. */
#define H2_MAX_HEADER_BLOCK (1u << 20)

/* ======================================================================= *
 *  Lifecycle policy (Phase 5): idle timeout, PING watchdog
 * ======================================================================= *
 * Process-global, read once from config.json main.env (env_get_int). Seconds;
 * 0 disables that check. Defaults: idle 120 s; PING watchdog off (a healthy
 * connection needs no keep-alive traffic, and idle timeout already reaps silent
 * peers). Operators enable PING to detect half-dead clients faster than the
 * idle timeout on links where the server otherwise has nothing to send. */
#define H2_DEFAULT_IDLE_TIMEOUT_SEC 120
#define H2_DEFAULT_PING_ACK_TIMEOUT_SEC 15

/* Receive-window policy (Phase 4 tail, RFC §6.9.1). The RFC default of 65535
 * caps inbound throughput at window/RTT whatever the bandwidth — 0.6 MB/s over
 * a 100 ms link, per connection, however many streams are uploading. So the
 * window starts at the default and grows towards the measured bandwidth-delay
 * product, up to `max`. Only peers that actually sustain the rate get the big
 * window, and only on the receive side: what we advertise is our own risk to
 * take, and the body is spooled to a tmp file rather than held in memory. */
#define H2_DEFAULT_RECV_WINDOW_MAX (4 * 1024 * 1024)

/* Write scheduling (Phase 4 tail). How many body bytes one stream may put on the
 * wire before the write path moves on to the next ready stream. Without a bound
 * a large response runs to completion — it holds the socket through every
 * EPOLLOUT until its last byte — and the small requests sharing the connection
 * wait for the whole file, which is the head-of-line blocking multiplexing is
 * supposed to remove.
 *
 * 64 KB is four DATA frames at the default max frame size: large enough that the
 * extra epoll turn per quantum is noise against the copy, small enough that a
 * request queued behind a big download waits milliseconds rather than the length
 * of the download. RFC 9113 has nothing to say here — stream priorities are
 * deprecated (§5.3), so scheduling between ready streams is entirely ours. */
#define H2_DEFAULT_WRITE_QUANTUM (64 * 1024)
#define H2_MIN_WRITE_QUANTUM 1024

static uint32_t h2_idle_timeout_sec;
static uint32_t h2_ping_interval_sec;
static uint32_t h2_ping_ack_timeout_sec;
static int64_t  h2_recv_window_initial;
static int64_t  h2_recv_window_max;
static int64_t  h2_write_quantum;
static int      h2_policy_loaded;

static void h2_load_policy(void) {
    if (h2_policy_loaded) return;
    h2_policy_loaded = 1;

    h2_idle_timeout_sec = (uint32_t)env_get_int("http2_idle_timeout_sec", H2_DEFAULT_IDLE_TIMEOUT_SEC);
    h2_ping_interval_sec = (uint32_t)env_get_int("http2_ping_interval_sec", 0);
    /* Default ack grace: the interval itself, capped so a stuck peer is caught
     * in bounded time even with long intervals. */
    uint32_t ack_default = h2_ping_interval_sec ? h2_ping_interval_sec : H2_DEFAULT_PING_ACK_TIMEOUT_SEC;
    if (ack_default > H2_DEFAULT_PING_ACK_TIMEOUT_SEC) ack_default = H2_DEFAULT_PING_ACK_TIMEOUT_SEC;
    h2_ping_ack_timeout_sec = (uint32_t)env_get_int("http2_ping_ack_timeout_sec", (int)ack_default);

    /* Window we open with, advertised in the preface; the auto-scaler takes it
     * from there. Set max == initial to pin the window and disable scaling. */
    h2_recv_window_initial = env_get_int("http2_recv_window_initial", H2_DEFAULT_WINDOW);
    if (h2_recv_window_initial < H2_DEFAULT_WINDOW) h2_recv_window_initial = H2_DEFAULT_WINDOW;
    if (h2_recv_window_initial > H2_MAX_WINDOW) h2_recv_window_initial = H2_MAX_WINDOW;

    h2_recv_window_max = env_get_int("http2_recv_window_max", H2_DEFAULT_RECV_WINDOW_MAX);
    if (h2_recv_window_max > H2_MAX_WINDOW) h2_recv_window_max = H2_MAX_WINDOW;
    if (h2_recv_window_max < h2_recv_window_initial) h2_recv_window_max = h2_recv_window_initial;

    /* Raise for throughput on connections that carry one big transfer at a time,
     * lower for latency when many small responses share a connection. */
    h2_write_quantum = env_get_int("http2_write_quantum", H2_DEFAULT_WRITE_QUANTUM);
    if (h2_write_quantum < H2_MIN_WRITE_QUANTUM) h2_write_quantum = H2_MIN_WRITE_QUANTUM;
}

/* CLOCK_MONOTONIC milliseconds — immune to wall-clock jumps, so deadlines never
 * shift under NTP. */
static uint64_t h2_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

typedef enum {
    H2_FRAME_ERROR = 0,      /* connection error — GOAWAY(s->error_code) and close */
    H2_FRAME_OK,             /* keep processing frames */
    H2_FRAME_DISPATCHED,     /* a request was handed to a handler — stop reading */
    H2_FRAME_CLOSE,          /* orderly close (peer GOAWAY) */
} h2_frame_result_e;

static int h2_flush_out(h2session_t* s);
static void h2_session_drop_stream(h2session_t* s, h2stream_t* stream);

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

/* Process-wide, monotonically increasing. Makes every PING's opaque 8-byte
 * payload unique so only its own ACK retires it. */
static _Atomic uint64_t h2_ping_seq = 1;

static void h2_fill_ping_payload(uint8_t payload[8]) {
    uint64_t seq = atomic_fetch_add(&h2_ping_seq, 1);

    for (int i = 7; i >= 0; i--) {
        payload[i] = (uint8_t)(seq & 0xff);
        seq >>= 8;
    }
}

/* Smoothed RTT of the underlying TCP connection in microseconds, 0 when the
 * kernel has no estimate yet. Free next to a probe of our own: it is the same
 * number congestion control keeps, refreshed on every ACK, and it works
 * identically under TLS. What it cannot see past is a proxy — it reports the
 * RTT to whatever terminates the TCP connection, so behind a TCP load balancer
 * it measures the hop to the balancer, not to the client. */
static uint32_t h2_conn_rtt_us(const h2session_t* s) {
    struct tcp_info info;
    socklen_t len = sizeof(info);

    if (getsockopt(s->connection->fd, IPPROTO_TCP, TCP_INFO, &info, &len) == -1)
        return 0;

    return info.tcpi_rtt;
}

/* RTT to the peer for window tuning: the larger of the kernel's estimate and
 * the last PING round trip. Taking the larger one is what makes a proxied
 * deployment work — the PING crosses the whole path, so it is the honest number
 * whenever the two disagree. 0 when neither is known yet. */
static uint32_t h2_peer_rtt_us(const h2session_t* s) {
    const uint32_t tcp_us = h2_conn_rtt_us(s);

    return s->rtt_us > tcp_us ? s->rtt_us : tcp_us;
}

/* Re-probe a stalled tuning PING after this long, so a peer that drops one does
 * not wedge the tuner. Liveness is not this PING's job — the idle timeout and
 * the optional watchdog own that. */
#define H2_TUNE_PING_TIMEOUT_MS 5000

/* Floor on the gap between tuning PINGs. One per round trip is all the tuner
 * can use (it grows a window at most once per RTT), and on a fast link the ACK
 * comes back instantly — without a floor that would mean a PING per credit
 * cycle for a transfer that never needed tuning at all. */
#define H2_TUNE_PING_MIN_INTERVAL_MS 50

/* Measure the path RTT with a PING (§6.7). Sent only while a receive window is
 * still growing, one at a time, so the ramp costs at most one PING per round
 * trip and stops as soon as the window settles. */
static void h2_send_tune_ping(h2session_t* s) {
    const uint64_t now = h2_now_ms();

    if (s->tune_ping_sent_ms != 0 && now - s->tune_ping_sent_ms < H2_TUNE_PING_TIMEOUT_MS)
        return;

    uint64_t interval_ms = s->rtt_us / 1000;
    if (interval_ms < H2_TUNE_PING_MIN_INTERVAL_MS) interval_ms = H2_TUNE_PING_MIN_INTERVAL_MS;
    if (s->tune_ping_done_ms != 0 && now - s->tune_ping_done_ms < interval_ms)
        return;

    uint8_t payload[8];
    h2_fill_ping_payload(payload);

    memcpy(s->tune_ping_payload, payload, sizeof payload);
    s->tune_ping_sent_ms = now;

    (void)h2_session_queue_frame(s, H2_FRAME_PING, 0, 0, payload, sizeof payload);
}

/* Count `len` bytes received on one flow (a stream, or the connection when
 * stream_id is 0) and give the credit back once enough has piled up — growing
 * the window first if the peer looks limited by it (§6.9.1).
 *
 * Target is two bandwidth-delay products: one keeps the peer sending while our
 * WINDOW_UPDATE is still in flight, the second absorbs a stale sample. The rate
 * sample is only trusted once it spans a round trip (below that a single burst
 * reads as infinite bandwidth), and one step may at most double the window, so
 * a noisy sample cannot jump straight to the cap. On a fast link the measured
 * BDP stays under 65535 and the window never moves — loopback and LAN keep the
 * exact frame pattern they had before. */
static void h2_recv_credit(h2session_t* s, uint32_t stream_id, h2_recv_window_t* w, uint32_t len) {
    w->pending += len;
    w->bytes += len;

    int64_t threshold = w->size / H2_WINDOW_UPDATE_DIVISOR;
    if (threshold < H2_WINDOW_UPDATE_MIN) threshold = H2_WINDOW_UPDATE_MIN;
    if (w->pending < threshold) return;

    int64_t increment = w->pending;
    w->pending = 0;

    if (w->size < h2_recv_window_max) {
        const uint64_t now = h2_now_ms();
        const uint64_t elapsed_us = (now - w->epoch_ms) * 1000;
        const uint32_t rtt_us = h2_peer_rtt_us(s);

        /* Keep a fresh RTT sample coming while there is still room to grow. */
        h2_send_tune_ping(s);

        /* elapsed_us >= rtt_us > 0 also keeps the division below safe. */
        if (rtt_us > 0 && elapsed_us >= rtt_us) {
            int64_t target = 2 * w->bytes * (int64_t)rtt_us / (int64_t)elapsed_us;

            if (target > w->size * 2) target = w->size * 2;
            if (target > h2_recv_window_max) target = h2_recv_window_max;

            if (target > w->size) {
                increment += target - w->size;
                w->size = target;

                /* Streams opened later start from what this connection already
                 * learned, instead of re-paying the ramp per request. */
                if (stream_id != 0 && w->size > s->stream_recv_learned)
                    s->stream_recv_learned = w->size;
            }

            w->epoch_ms = now;
            w->bytes = 0;
        }
    }

    h2_queue_window_update(s, stream_id, (uint32_t)increment);
}

/* A fresh stream is credited up to the learned window (§6.9.2 lets SETTINGS set
 * only the initial value, so the difference has to go out as a WINDOW_UPDATE). */
static void h2_stream_recv_init(h2session_t* s, h2stream_t* stream) {
    stream->recv.epoch_ms = h2_now_ms();

    if (stream->recv.size > h2_recv_window_initial)
        h2_queue_window_update(s, stream->id, (uint32_t)(stream->recv.size - h2_recv_window_initial));
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

/* Retire a stream, keeping the session's write cursor consistent. h2stream_close
 * keeps the stream alive when a handler still holds its request/response. */
static void h2_session_drop_stream(h2session_t* s, h2stream_t* stream) {
    if (stream == NULL) return;

    if (s->writing == stream) s->writing = NULL;

    h2stream_close(s, stream);
}

/* Stream error: only the stream dies, the connection carries on. */
static h2_frame_result_e h2_stream_error(h2session_t* s, uint32_t stream_id, uint32_t error_code) {
    const uint8_t payload[4] = {
        (uint8_t)((error_code >> 24) & 0xff),
        (uint8_t)((error_code >> 16) & 0xff),
        (uint8_t)((error_code >> 8) & 0xff),
        (uint8_t)(error_code & 0xff),
    };

    if (!h2_session_queue_frame(s, H2_FRAME_RST_STREAM, 0, stream_id, payload, sizeof(payload)))
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

    h2stream_t* stream = h2stream_find(s, stream_id);
    if (stream != NULL) {
        stream->state = H2_STREAM_CLOSED;
        h2_session_drop_stream(s, stream);
    }

    return H2_FRAME_OK;
}

/* State of an arbitrary stream id. Ids above the highest one we ever accepted
 * are idle; ones no longer in the table have been closed. */
static h2stream_state_e h2_stream_state_of(h2session_t* s, uint32_t stream_id) {
    if (stream_id > s->last_stream_id) return H2_STREAM_IDLE;

    const h2stream_t* stream = h2stream_find(s, stream_id);

    return stream != NULL ? stream->state : H2_STREAM_CLOSED;
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
 * request owns — httprequest_reset() frees it exactly once. httpparser_set_uri
 * stores the buffer before it validates, so the request owns it on either
 * outcome and it must never be freed here.
 *
 * -fanalyzer reports the hand-off as a leak: httpparser_set_uri takes the
 * buffer as const char* yet retains it, and the owning httprequest_t is freed
 * from another translation unit, so the analyzer cannot follow it. Assigning
 * request->uri here as well makes the escape explicit to a reader but does not
 * convince the analyzer, hence the scoped suppression. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
static int h2_set_path(httprequest_t* request, const char* value, size_t len) {
    char* uri = malloc(len + 1);
    if (uri == NULL) return 0;

    memcpy(uri, value, len);
    uri[len] = '\0';

    request->uri = uri;
    request->uri_length = len;

    return httpparser_set_uri(request, uri, len) == HTTP1PARSER_CONTINUE;
}
#pragma GCC diagnostic pop

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
static h2_request_status_e h2_build_request(h2session_t* s, h2stream_t* stream,
                                            const uint8_t* block, size_t len) {
    httprequest_t* request = stream->request;
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

    stream->content_length = -1;

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
                (stream->content_length >= 0 && stream->content_length != declared)) {
                status = H2_REQUEST_MALFORMED;
                break;
            }
            stream->content_length = declared;
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
static int h2_body_append(h2stream_t* stream, const uint8_t* data, size_t len) {
    if (len == 0) return 1;

    if (len > SIZE_MAX - stream->req_body_len) return 0;
    if (stream->req_body_len + len > env()->main.client_max_body_size) return 0;

    http_payload_t* payload = &stream->request->payload_;
    if (payload->file.fd < 0)
        if (!httprequest_create_payload_file(payload))
            return 0;

    if (!payload->file.append_content(&payload->file, (const char*)data, len))
        return 0;

    stream->req_body_len += len;

    return 1;
}

/* The request is complete: validate what could only be checked once the body
 * was fully received, then hand it to the shared handler pipeline. */
static h2_frame_result_e h2_dispatch(h2session_t* s, h2stream_t* stream) {
    /* RFC 9113 §8.1.1: a content-length that disagrees with the DATA total
     * makes the request malformed. */
    if (stream->content_length >= 0 &&
        (uint64_t)stream->content_length != (uint64_t)stream->req_body_len)
        return h2_stream_error(s, stream->id, H2_ERR_PROTOCOL_ERROR);

    stream->state = H2_STREAM_HALF_CLOSED_REMOTE;

    /* The handler may run on another thread, or inline on this one for a static
     * file. Either way the stream must survive until it reports back, so a
     * RST_STREAM arriving meanwhile only marks it cancelled. */
    stream->handler_pending = 1;

    if (!http_server_dispatch(s->connection, stream->request)) {
        stream->handler_pending = 0;
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);
    }

    return H2_FRAME_OK;
}

/* ======================================================================= *
 *  Frame handling
 * ======================================================================= */

/* Apply a SETTINGS frame payload (6-byte id/value tuples) to the peer settings.
 * Shared by h2_on_settings (a real SETTINGS frame, which then acks) and the h2c
 * Upgrade path (the HTTP2-Settings header, which is not acked — RFC 7540 §3.2.1).
 * Returns H2_FRAME_OK or a connection-error result. */
static h2_frame_result_e h2_apply_settings_payload(h2session_t* s,
                                                   const uint8_t* payload, size_t len) {
    for (size_t off = 0; off + 6 <= len; off += 6) {
        const uint8_t* p = payload + off;
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
             * push. */
            if (value > 1) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
            break;
        case H2_SETTINGS_INITIAL_WINDOW_SIZE: {
            if (value > (uint32_t)H2_MAX_WINDOW)
                return h2_conn_error(s, H2_ERR_FLOW_CONTROL_ERROR);

            /* §6.9.2: the change applies as a delta to *every* open stream's
             * send window, not as an assignment. */
            const int64_t delta = (int64_t)value - (int64_t)s->peer_initial_window;
            s->peer_initial_window = value;

            for (h2stream_t* stream = s->streams; stream != NULL; stream = stream->next) {
                stream->send_window += delta;
                if (stream->send_window > 0) stream->window_blocked = 0;
            }
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

    return H2_FRAME_OK;
}

static h2_frame_result_e h2_on_settings(h2session_t* s, const h2_frame_t* frame) {
    if (frame->flags & H2_FLAG_ACK) return H2_FRAME_OK;

    const h2_frame_result_e r = h2_apply_settings_payload(s, frame->payload, frame->payload_len);
    if (r != H2_FRAME_OK) return r;

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

        if (s->send_window > 0) s->window_blocked = 0;

        return H2_FRAME_OK;
    }

    /* §5.1: a frame for a stream that was never opened is a connection error,
     * while one for a stream we already finished is harmless. */
    if (h2_stream_state_of(s, frame->stream_id) == H2_STREAM_IDLE)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    if (increment == 0)
        return h2_stream_error(s, frame->stream_id, H2_ERR_PROTOCOL_ERROR);

    h2stream_t* stream = h2stream_find(s, frame->stream_id);
    if (stream == NULL) return H2_FRAME_OK;

    stream->send_window += increment;
    if (stream->send_window > H2_MAX_WINDOW)
        return h2_stream_error(s, frame->stream_id, H2_ERR_FLOW_CONTROL_ERROR);

    if (stream->send_window > 0) stream->window_blocked = 0;

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
    if (h2_stream_state_of(s, frame->stream_id) == H2_STREAM_IDLE)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    h2stream_t* stream = h2stream_find(s, frame->stream_id);
    if (stream != NULL) {
        stream->state = H2_STREAM_CLOSED;
        h2_session_drop_stream(s, stream);
    }

    return H2_FRAME_OK;
}

/* Map a request-construction outcome onto the wire. */
static h2_frame_result_e h2_request_failed(h2session_t* s, h2stream_t* stream,
                                           h2_request_status_e status) {
    const uint32_t stream_id = stream->id;

    /* A bad HPACK block leaves the shared decoder unusable, so the connection
     * has to go; a merely malformed request only costs the stream. */
    if (status == H2_REQUEST_COMPRESSION || status == H2_REQUEST_INTERNAL) {
        h2_session_drop_stream(s, stream);
        return h2_conn_error(s, status == H2_REQUEST_COMPRESSION ?
                             H2_ERR_COMPRESSION_ERROR : H2_ERR_INTERNAL_ERROR);
    }

    h2_session_drop_stream(s, stream);

    return h2_stream_error(s, stream_id, H2_ERR_PROTOCOL_ERROR);
}

static h2_frame_result_e h2_on_header_block(h2session_t* s, uint32_t stream_id,
                                            const uint8_t* block, size_t len,
                                            int end_stream) {
    h2stream_t* stream = h2stream_find(s, stream_id);

    /* A header block on a stream that is already open is trailers, not a new
     * request (§8.1). */
    if (stream != NULL && stream->state == H2_STREAM_OPEN && stream->headers_done) {
        /* The block must still be decoded to keep the HPACK context in sync,
         * even when the stream is about to be reset. */
        const h2_request_status_e status = h2_consume_trailers(s, block, len);
        if (status != H2_REQUEST_OK)
            return h2_request_failed(s, stream, status);

        /* §8.1: trailers terminate the request; without END_STREAM this is a
         * second header block in mid-stream. */
        if (!end_stream)
            return h2_stream_error(s, stream_id, H2_ERR_PROTOCOL_ERROR);

        return h2_dispatch(s, stream);
    }

    stream = h2stream_create(s, stream_id);
    if (stream == NULL) return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

    h2_stream_recv_init(s, stream);

    if (stream_id > s->last_stream_id) s->last_stream_id = stream_id;

    const h2_request_status_e status = h2_build_request(s, stream, block, len);
    if (status != H2_REQUEST_OK)
        return h2_request_failed(s, stream, status);

    stream->headers_done = 1;

    if (!end_stream) return H2_FRAME_OK;

    return h2_dispatch(s, stream);
}

static h2_frame_result_e h2_on_headers(h2session_t* s, const h2_frame_t* frame) {
    /* §5.1.1: client-initiated streams are odd-numbered, and ids only ever
     * increase — reusing a closed one is a connection error. */
    if ((frame->stream_id & 1) == 0) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    const h2stream_state_e state = h2_stream_state_of(s, frame->stream_id);
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
    const int refused = !trailers &&
        (h2stream_active_count(s) >= H2_MAX_CONCURRENT_STREAMS ||
         /* RFC 9113 §6.8: once GOAWAY(last_stream_id) is out, streams with a
          * higher id are out of bounds. Streams at or below the boundary that
          * the peer had in flight before seeing our GOAWAY are still served. */
         (s->goaway_sent && frame->stream_id > s->last_stream_id));
    if (self_dependent || refused) {
        if (frame->flags & H2_FLAG_END_HEADERS) {
            const h2_request_status_e status = h2_discard_header_block(s, block, block_len);
            if (status != H2_REQUEST_OK)
                return h2_conn_error(s, H2_ERR_COMPRESSION_ERROR);
        }

        if (frame->stream_id > s->last_stream_id) s->last_stream_id = frame->stream_id;

        return h2_stream_error(s, frame->stream_id,
                               refused ? H2_ERR_REFUSED_STREAM : H2_ERR_PROTOCOL_ERROR);
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
    /* Credit the connection window back regardless of what happens to the
     * payload: the peer counted it against our window either way. */
    h2_recv_credit(s, 0, &s->recv, frame->payload_len);

    /* §5.1: DATA on a stream that was never opened is a connection error; on
     * one that no longer accepts data it is a stream error. */
    const h2stream_state_e state = h2_stream_state_of(s, frame->stream_id);
    if (state == H2_STREAM_IDLE)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    h2stream_t* stream = h2stream_find(s, frame->stream_id);
    if (state != H2_STREAM_OPEN || stream == NULL)
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

    h2_recv_credit(s, stream->id, &stream->recv, frame->payload_len);

    if (!h2_body_append(stream, data, data_len))
        return h2_stream_error(s, stream->id, H2_ERR_INTERNAL_ERROR);

    if (!(frame->flags & H2_FLAG_END_STREAM)) return H2_FRAME_OK;

    return h2_dispatch(s, stream);
}

static h2_frame_result_e h2_handle_frame(h2session_t* s, const h2_frame_t* frame) {
    /* A header block must not be interleaved with any other frame (§6.10). */
    if (s->cont_active && frame->type != H2_FRAME_CONTINUATION)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    switch (frame->type) {
    case H2_FRAME_SETTINGS:
        return h2_on_settings(s, frame);

    case H2_FRAME_PING:
        if (frame->flags & H2_FLAG_ACK) {
            /* An ACK for our watchdog PING: clear it and refresh the idle
             * clock (hearing from the peer is activity). The opaque 8 bytes are
             * echoed verbatim, so a mismatched ACK is simply ignored — only the
             * one we actually sent retires the watchdog. */
            if (s->ping_sent_ms != 0 &&
                frame->payload_len == sizeof(s->ping_payload) &&
                memcmp(frame->payload, s->ping_payload, sizeof(s->ping_payload)) == 0) {
                s->ping_sent_ms = 0;
            }
            /* A tuning PING's ACK carries the path RTT the window tuner needs.
             * Millisecond resolution: a sub-millisecond round trip reads as 0
             * and leaves the kernel estimate in charge, which is right — at
             * that RTT there is no bandwidth-delay product to chase. */
            if (s->tune_ping_sent_ms != 0 &&
                frame->payload_len == sizeof(s->tune_ping_payload) &&
                memcmp(frame->payload, s->tune_ping_payload, sizeof(s->tune_ping_payload)) == 0) {
                const uint64_t now_ms = h2_now_ms();
                const uint64_t rtt_ms = now_ms - s->tune_ping_sent_ms;
                s->tune_ping_sent_ms = 0;
                s->tune_ping_done_ms = now_ms;
                if (rtt_ms > 0 && rtt_ms <= H2_TUNE_PING_TIMEOUT_MS)
                    s->rtt_us = (uint32_t)(rtt_ms * 1000);
            }
            s->last_activity_ms = h2_now_ms();
            return H2_FRAME_OK;
        }
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
 * keep going, 0 to close. Unlike Phase 3 this does not stop at the first
 * dispatched request — several streams may be accepted from one read. */
static int h2_process_buffer(h2session_t* s) {
    const uint8_t* p = s->read_buf;
    const uint8_t* end = s->read_buf + s->read_len;
    int result = 1;

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
    }

    const size_t consumed = (size_t)(p - s->read_buf);
    if (consumed > 0) {
        memmove(s->read_buf, s->read_buf + consumed, s->read_len - consumed);
        s->read_len -= consumed;
    }

    return result;
}

/* A stream is waiting for the write path. */
static int h2_has_writable(const h2session_t* s) {
    for (const h2stream_t* stream = s->streams; stream != NULL; stream = stream->next)
        if (stream->response_ready) return 1;

    return 0;
}

/* Stage bytes that arrived outside the h2 read loop — the h2c prior-knowledge
 * bootstrap, where __read had already recv'd the preface into connection->buffer
 * — and run the frame parser over them. On a connection error h2_fail() will have
 * queued a GOAWAY; the caller flushes it. Returns 0 on a connection error. */
static int h2_session_feed(h2session_t* s, const uint8_t* data, size_t len) {
    if (s->read_len + len > s->read_cap) {
        size_t cap = s->read_cap ? s->read_cap : 16384;
        while (cap < s->read_len + len) cap *= 2;
        uint8_t* buf = realloc(s->read_buf, cap);
        if (buf == NULL) return 0;
        s->read_buf = buf;
        s->read_cap = cap;
    }

    memcpy(s->read_buf + s->read_len, data, len);
    s->read_len += len;
    s->last_activity_ms = h2_now_ms();

    return h2_process_buffer(s);
}

/* Flush pending outbound frames and re-arm epoll for the next event: EPOLLOUT if
 * there is still data to send or a stream waiting on the write path, otherwise
 * EPOLLIN. The shared tail of the read loop and the h2c bootstrap. */
static int h2_drain_and_rearm(h2session_t* s, connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    if (h2_flush_out(s) == 0) return 0;

    /* Anything left to write — pending frames, or a response that the frames we
     * just consumed unblocked — needs an EPOLLOUT turn. */
    if (s->out_len > s->out_pos || h2_has_writable(s)) {
        ctx->need_write = 1;
        return rearm(connection, MPXOUT | MPXRDHUP);
    }

    return 1;
}

static int h2_read(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = ctx->parser;

    for (;;) {
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

        /* Any byte from the peer resets the idle/PING clocks (Phase 5). Writes
         * deliberately do not: a server-side response must not mask a client
         * that has gone silent. */
        s->last_activity_ms = h2_now_ms();

        if (!h2_process_buffer(s)) return 0;
    }

    /* Acks and window updates produced while parsing. */
    return h2_drain_and_rearm(s, connection);
}

/* ======================================================================= *
 *  Write path
 * ======================================================================= */

typedef enum {
    H2_WRITE_DONE = 0,    /* the stream's response is fully on the wire */
    H2_WRITE_SOCKET,      /* socket saturated mid-frame — resume this stream first */
    H2_WRITE_WINDOW,      /* out of flow-control window — try other streams */
    H2_WRITE_YIELD,       /* quantum spent on a frame boundary — try other streams */
    H2_WRITE_FAILED,
} h2_write_status_e;

/* Give one stream its turn: refill its quantum and run the filter chain until it
 * finishes, blocks, or spends the quantum.
 *
 * The three non-terminal outcomes differ in whether the socket is left mid-frame,
 * which is what decides if another stream may take over (see h2_write):
 *   SOCKET — stopped anywhere, possibly with half a frame written;
 *   WINDOW — stopped at a frame boundary, waiting on a WINDOW_UPDATE;
 *   YIELD  — stopped at a frame boundary with bytes still to send.
 * Only the header phase can report SOCKET without a frame boundary being
 * possible, and the two frame-boundary flags are set exclusively by the write
 * filter's DATA loop, so the mapping below is not ambiguous. */
static h2_write_status_e h2_write_stream(h2session_t* s, h2stream_t* stream) {
    stream->window_blocked = 0;
    stream->yielded = 0;
    stream->served = 1;
    stream->write_credit = h2_write_quantum;

    int r = __run_header_filters(stream->request, stream->response);
    if (r == CWF_ERROR) return H2_WRITE_FAILED;
    if (r == CWF_EVENT_AGAIN)
        return stream->window_blocked ? H2_WRITE_WINDOW : H2_WRITE_SOCKET;

    r = __run_body_filters(stream->request, stream->response);
    if (r == CWF_ERROR) return H2_WRITE_FAILED;
    if (r == CWF_EVENT_AGAIN) {
        if (stream->yielded) return H2_WRITE_YIELD;
        return stream->window_blocked ? H2_WRITE_WINDOW : H2_WRITE_SOCKET;
    }

    /* The filter chain emits no buffer at all for an empty body (and the
     * HEADERS frame only carries END_STREAM when we could prove up front that
     * no body follows), so close the stream explicitly when it is still open. */
    if (!stream->end_stream_sent) {
        if (!h2_session_queue_frame(s, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream->id, NULL, 0))
            return H2_WRITE_FAILED;

        stream->end_stream_sent = 1;
    }

    return H2_WRITE_DONE;
}

static int h2_write(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = ctx->parser;

    const int flushed = h2_flush_out(s);
    if (flushed == 0) return 0;
    if (flushed < 0) return rearm(connection, MPXOUT | MPXRDHUP);

    int socket_full = 0;
    int window_stalled = 0;
    int yielded = 0;

    /* One turn per ready stream. The flag is cleared up front rather than after
     * each turn because the rotation below appends served streams behind the
     * cursor, so the walk would otherwise reach them a second time. */
    for (h2stream_t* st = s->streams; st != NULL; st = st->next) st->served = 0;

    /* A stream that stopped *mid-frame* owns the socket until it finishes:
     * starting another one would splice its bytes into the unfinished frame.
     * Stopping on a frame boundary is a different matter — it releases the pin
     * and takes its place at the back of the rotation. */
    if (s->writing != NULL) {
        h2stream_t* stream = s->writing;
        const h2_write_status_e status = h2_write_stream(s, stream);

        switch (status) {
        case H2_WRITE_FAILED:
            s->writing = NULL;
            return h2_fail(s, H2_ERR_INTERNAL_ERROR);
        case H2_WRITE_SOCKET:
            /* Still mid-frame: nobody else may touch the socket. */
            if (h2_flush_out(s) == 0) return 0;
            ctx->need_write = 1;
            return rearm(connection, MPXOUT | MPXRDHUP);
        case H2_WRITE_WINDOW:
        case H2_WRITE_YIELD:
            s->writing = NULL;
            if (status == H2_WRITE_WINDOW) window_stalled = 1;
            else yielded = 1;
            h2stream_rotate(s, stream);
            break;
        case H2_WRITE_DONE:
            s->writing = NULL;
            stream->state = H2_STREAM_CLOSED;
            h2_session_drop_stream(s, stream);
            break;
        }
    }

    /* Then serve every other stream whose handler has come back, in table order
     * — which is round-robin order, since a stream that stops short goes to the
     * back. Each gets at most one quantum per turn. */
    h2stream_t* stream = s->streams;
    while (stream != NULL) {
        h2stream_t* next = stream->next;

        if (stream->served || !stream->response_ready || stream->response == NULL) {
            stream = next;
            continue;
        }

        const h2_write_status_e status = h2_write_stream(s, stream);

        if (status == H2_WRITE_FAILED)
            return h2_fail(s, H2_ERR_INTERNAL_ERROR);

        if (status == H2_WRITE_SOCKET) {
            s->writing = stream;
            socket_full = 1;
            break;
        }

        if (status == H2_WRITE_WINDOW || status == H2_WRITE_YIELD) {
            /* Stopped before any byte of the next frame went out, so another
             * stream may safely take the socket. Back of the queue. */
            if (status == H2_WRITE_WINDOW) window_stalled = 1;
            else yielded = 1;

            h2stream_rotate(s, stream);
            stream = next;
            continue;
        }

        stream->state = H2_STREAM_CLOSED;
        h2_session_drop_stream(s, stream);

        stream = next;
    }

    if (h2_flush_out(s) == 0) return 0;

    if (socket_full || s->out_len > s->out_pos) {
        ctx->need_write = 1;
        return rearm(connection, MPXOUT | MPXRDHUP);
    }

    /* Somebody spent their quantum with body left over: the socket still has
     * room, so come straight back for the next round. */
    if (yielded) {
        ctx->need_write = 1;
        return rearm(connection, MPXOUT | MPXRDHUP);
    }

    /* Every stream that could make progress has; the rest wait on a
     * WINDOW_UPDATE, which arrives on the read path. */
    if (window_stalled) {
        ctx->need_write = 1;
        return rearm(connection, MPXIN | MPXRDHUP);
    }

    /* Same teardown as h1.1 __write: drains any queued handler and re-arms
     * reading. ctx->request/response are NULL on an h2 connection — every
     * request lives on its stream — so the reset it performs is a no-op. */
    return connection_after_write(connection);
}

/* ======================================================================= *
 *  Handler hand-off
 * ======================================================================= */

void h2_server_attach_response(connection_t* connection, httprequest_t* request,
                               httpresponse_t* response) {
    h2session_t* s = h2_session_of(connection);
    if (s == NULL) return;

    for (h2stream_t* stream = s->streams; stream != NULL; stream = stream->next) {
        if (stream->request != request) continue;

        /* __handle may be re-entered for the same request (redirects); the
         * stream owns whichever response is current. */
        if (stream->response != NULL && stream->response != response)
            httpresponse_free(stream->response);

        stream->response = response;
        return;
    }
}

int h2_server_response_ready(connection_t* connection, httpresponse_t* response) {
    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = h2_session_of(connection);
    if (s == NULL) return 0;

    h2stream_t* stream = h2stream_find_by_response(s, response);
    if (stream == NULL) {
        /* The stream went away before its response was ready and nothing else
         * owns it now. */
        httpresponse_free(response);
        return connection_after_read(connection);
    }

    stream->handler_pending = 0;

    if (stream->cancelled) {
        h2_session_drop_stream(s, stream);
        return connection_after_read(connection);
    }

    stream->response_ready = 1;
    ctx->need_write = 1;

    /* More handlers are queued for this connection. Hand the worker slot on so
     * they run without waiting for this response to reach the socket — the
     * chain that connection_after_write drives for h1.1, which the h2 write
     * path cannot drive because it may stop early on a saturated socket or an
     * exhausted flow-control window. */
    if (!cqueue_empty(ctx->queue)) {
        connection_queue_guard_append(connection);
        return rearm(connection, MPXONESHOT);
    }

    return connection_after_read(connection);
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

/* ======================================================================= *
 *  Lifecycle: idle timeout, PING watchdog, graceful shutdown (Phase 5)
 * ======================================================================= */

static void h2_send_watchdog_ping(h2session_t* s) {
    uint8_t payload[8];
    h2_fill_ping_payload(payload);

    memcpy(s->ping_payload, payload, sizeof payload);
    s->ping_sent_ms = h2_now_ms();

    (void)h2_session_queue_frame(s, H2_FRAME_PING, 0, 0, payload, sizeof payload);
}

/* Send GOAWAY(NO_ERROR) best-effort and close. Used for idle timeout, an
 * unanswered watchdog PING, and the tail of the shutdown drain. The caller
 * (h2_server_tick) already holds the connection lock, so the _locked close
 * variant avoids re-entering the non-recursive spinlock. */
static void h2_graceful_close_locked(h2session_t* s) {
    h2_queue_goaway(s, H2_ERR_NO_ERROR);
    (void)h2_flush_out(s);
    connection_close_locked(s->connection);
}

void h2_server_tick(connection_t* connection, int shutdown_now) {
    /* Owns the full lock lifecycle: a connection busy with a handler or I/O is
     * skipped this tick and revisited on the next one. Every exit path releases
     * the lock — either by closing (connection_close_locked frees/unlocks) or by
     * the explicit unlock at the end — so the caller must not touch the
     * connection afterwards (it may have been freed). */
    if (!connection_s_trylock(connection)) return;

    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = ctx->parser;
    const uint64_t now = h2_now_ms();

    if (shutdown_now) {
        /* Tell the peer we will accept no new streams, then let the ones in
         * flight finish (the worker keeps servicing events between ticks). Once
         * the table is empty the connection is torn down. h2_on_headers refuses
         * streams with id > last_stream_id once goaway_sent is set. */
        if (!s->goaway_sent) {
            h2_queue_goaway(s, H2_ERR_NO_ERROR);
            s->draining = 1;
            (void)h2_flush_out(s);
        }

        if (s->draining && s->stream_count == 0) {
            h2_graceful_close_locked(s);   /* releases the lock / frees */
            return;
        }

        connection_s_unlock(connection);
        return;
    }

    /* Idle timeout — only when nothing is in flight: a connection mid-request
     * or mid-response is not idle even if the peer has gone quiet (the PING
     * watchdog covers that case). */
    if (h2_idle_timeout_sec != 0 && s->stream_count == 0 &&
        now - s->last_activity_ms >= (uint64_t)h2_idle_timeout_sec * 1000u) {
        h2_graceful_close_locked(s);
        return;
    }

    if (h2_ping_interval_sec != 0) {
        /* Probe a peer that has been silent for the interval, then wait for the
         * ACK within its own (shorter) grace window. Only one PING outstanding. */
        if (s->ping_sent_ms == 0) {
            if (now - s->last_activity_ms >= (uint64_t)h2_ping_interval_sec * 1000u) {
                h2_send_watchdog_ping(s);
                (void)h2_flush_out(s);
            }
        }
        else if (now - s->ping_sent_ms >= (uint64_t)h2_ping_ack_timeout_sec * 1000u) {
            /* No ACK in time — the peer is gone. */
            h2_graceful_close_locked(s);
            return;
        }
    }

    connection_s_unlock(connection);
}

/* Server connection preface (§3.4): SETTINGS must be the first frame we send. */
static int h2_send_preface(h2session_t* s) {
    const uint32_t window = (uint32_t)h2_recv_window_initial;
    const uint8_t settings[] = {
        0x00, H2_SETTINGS_ENABLE_PUSH,            0x00, 0x00, 0x00, 0x00,
        0x00, H2_SETTINGS_MAX_CONCURRENT_STREAMS,
            (uint8_t)((H2_MAX_CONCURRENT_STREAMS >> 24) & 0xff),
            (uint8_t)((H2_MAX_CONCURRENT_STREAMS >> 16) & 0xff),
            (uint8_t)((H2_MAX_CONCURRENT_STREAMS >> 8) & 0xff),
            (uint8_t)(H2_MAX_CONCURRENT_STREAMS & 0xff),
        0x00, H2_SETTINGS_INITIAL_WINDOW_SIZE,
            (uint8_t)((window >> 24) & 0xff),
            (uint8_t)((window >> 16) & 0xff),
            (uint8_t)((window >> 8) & 0xff),
            (uint8_t)(window & 0xff),
    };

    if (!h2_session_queue_frame(s, H2_FRAME_SETTINGS, 0, 0, settings, sizeof(settings)))
        return 0;

    /* SETTINGS_INITIAL_WINDOW_SIZE governs streams only (§6.9.2); the
     * connection window moves by WINDOW_UPDATE alone. */
    if (h2_recv_window_initial > H2_DEFAULT_WINDOW)
        h2_queue_window_update(s, 0, (uint32_t)(h2_recv_window_initial - H2_DEFAULT_WINDOW));

    return 1;
}

/* Build an h2 session on `connection` and install its read/write guards. The
 * shared core of every entry point — TLS ALPN, h2c prior-knowledge, h2c Upgrade.
 * All three expect the 24-byte client connection preface: the Upgrade path too,
 * because §3.2 has the client send it immediately upon receiving the 101 (the
 * HTTP2-Settings header carries the settings *values* early, it does not replace
 * the preface or the SETTINGS frame that follows it). Queues (but does not
 * flush) the server connection preface; the caller drains as appropriate.
 * Returns the session or NULL on allocation failure. */
static h2session_t* h2_session_begin(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    h2_load_policy();

    h2session_t* s = calloc(1, sizeof(*s));
    if (s == NULL) return NULL;

    s->free = h2_session_free;
    s->connection = connection;
    s->read_cap = 16384;
    s->read_buf = malloc(s->read_cap);
    s->decoder = hpack_decoder_create(4096);
    s->encoder = hpack_encoder_create(4096);
    if (s->read_buf == NULL || s->decoder == NULL || s->encoder == NULL) {
        h2_session_free(s);
        return NULL;
    }

    h2frame_parser_init(&s->frame, 1, H2_MAX_FRAME_SIZE_DEFAULT); /* expect the client preface */
    s->peer_max_frame_size = H2_MAX_FRAME_SIZE_DEFAULT;
    s->peer_initial_window = H2_DEFAULT_WINDOW;
    s->peer_header_table_size = 4096;
    s->send_window = H2_DEFAULT_WINDOW;
    s->recv.size = h2_recv_window_initial;
    s->recv.epoch_ms = h2_now_ms();
    s->stream_recv_learned = h2_recv_window_initial;
    s->error_code = H2_ERR_PROTOCOL_ERROR;
    s->last_activity_ms = h2_now_ms();

    /* Server connection preface (§3.4): SETTINGS must be the first frame we send. */
    if (!h2_send_preface(s)) {
        h2_session_free(s);
        return NULL;
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

    return s;
}

int h2_server_set_http2(connection_t* connection) {
    h2session_t* s = h2_session_begin(connection);
    if (s == NULL) return 0;

    if (h2_flush_out(s) == 0) return 0;

    log_info("HTTP/2 session established (fd %d)\n", connection->fd);

    return 1;
}

int h2_server_set_http2_prior_knowledge(connection_t* connection, size_t len) {
    /* Called from __read under http_server_guard_read's lock. __read already
     * recv'd the client preface (and possibly the first SETTINGS/HEADERS in the
     * same packet) into connection->buffer; the session's frame parser expects
     * the 24-byte preface, so feeding those bytes consumes it and parses
     * whatever followed. */
    h2session_t* s = h2_session_begin(connection);
    if (s == NULL) return 0;

    if (!h2_session_feed(s, (const uint8_t*)connection->buffer, len)) {
        h2_flush_out(s); /* push any GOAWAY queued by the failure */
        return 0;
    }

    log_info("HTTP/2 (h2c prior-knowledge) session established (fd %d)\n", connection->fd);

    return h2_drain_and_rearm(s, connection);
}

void h2_upgrade_settings_free(void* data) {
    if (data == NULL) return;
    h2_upgrade_settings_t* ud = data;
    free(ud->payload);
    free(ud);
}

int h2_server_set_http2_upgrade(connection_t* connection, void* data) {
    /* switch_to_protocol callback (RFC 9113 §3.2): runs from
     * connection_after_write() under the connection lock, after the 101
     * Switching Protocols response is on the wire. The 101 was the HTTP/1.1
     * bridge; from here the connection speaks HTTP/2. */
    connection_server_ctx_t* ctx = connection->ctx;
    h2_upgrade_settings_t* ud = data;

    /* §3.2: upon receiving the 101 the client sends the connection preface —
     * magic + SETTINGS — exactly as on any other h2 connection, so the session
     * expects it. HTTP2-Settings only front-loads the settings values (applied
     * below) so the server can act on them while the 101 is still in flight. */
    h2session_t* s = h2_session_begin(connection);
    if (s == NULL)
        return 0;

    if (ud != NULL && ud->len > 0) {
        if (h2_apply_settings_payload(s, ud->payload, ud->len) != H2_FRAME_OK) {
            h2_fail(s, s->error_code); /* a bad setting is a connection error */
            h2_flush_out(s);
            return 0;
        }
    }

    /* Stream 1 is the upgraded request (RFC 7540 §3.2): its headers arrived as
     * HTTP/1.1 and are already parsed, so reuse that request rather than
     * decoding an HPACK block. __ctx_reset left ctx->request in place because a
     * protocol switch was pending; the stream owns it from here. */
    h2stream_t* stream = h2stream_create(s, 1);
    if (stream == NULL) {
        h2_fail(s, H2_ERR_INTERNAL_ERROR);
        h2_flush_out(s);
        return 0;
    }
    h2_stream_recv_init(s, stream);

    if (s->last_stream_id < 1) s->last_stream_id = 1;

    httprequest_free(stream->request); /* drop the empty one h2stream_create made */
    stream->request = ctx->request;
    ctx->request = NULL;
    stream->headers_done = 1;
    stream->content_length = -1;

    /* Run stream 1 through the same dispatch path as a fresh HEADERS frame; it
     * sets the half-closed-remote state, marks the handler pending, and queues
     * it. The response comes back as HEADERS/DATA frames on stream 1. */
    const h2_frame_result_e r = h2_dispatch(s, stream);
    if (r == H2_FRAME_ERROR) {
        h2_fail(s, s->error_code);
        h2_flush_out(s);
        return 0;
    }
    if (r == H2_FRAME_CLOSE) return 0;

    log_info("HTTP/2 (h2c upgrade) session established (fd %d)\n", connection->fd);

    return h2_drain_and_rearm(s, connection);
}

/* Case-insensitive "is `token` one of the comma-separated values in `list`"
 * (HTTP header lists — Upgrade, Connection — are token lists, §3.2.6). */
static int h2c_list_has_token(const char* list, const char* token) {
    const size_t tlen = strlen(token);
    const char* p = list;

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;

        const char* start = p;
        while (*p != '\0' && *p != ',') p++;
        const char* end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;

        if ((size_t)(end - start) == tlen && strncasecmp(start, token, tlen) == 0)
            return 1;

        if (*p == ',') p++;
    }

    return 0;
}

int h2c_upgrade(httpctx_t* ctx) {
    httprequest_t* request = ctx->request;
    httpresponse_t* response = ctx->response;

    /* The upgrade applies only to an HTTP/1.1 request. Stream 1 of an h2c
     * upgrade is dispatched through the same middleware chain as any h2 request,
     * and the upgraded HTTP/1.1 request still carries its Upgrade/HTTP2-Settings
     * headers — without this guard the middleware would re-stage a 101 onto the
     * h2 response (and :status would come back as 101). */
    connection_t* connection = response->connection;
    if (connection == NULL || connection->ctx == NULL) return 0;

    connection_server_ctx_t* conn_ctx = connection->ctx;
    if (conn_ctx->is_http2) return 0;

    const http_header_t* upgrade = request->get_headern(request, "Upgrade", 7);
    if (upgrade == NULL || !h2c_list_has_token(upgrade->value, "h2c"))
        return 0; /* not an h2c upgrade — handle as an ordinary request */

    /* RFC 7540 §3.2: the upgrade request MUST carry HTTP2-Settings, and the
     * Connection header MUST list it as connection-specific. */
    const http_header_t* h2settings = request->get_headern(request, "HTTP2-Settings", 14);
    if (h2settings == NULL)
        return 0;

    const http_header_t* connhdr = request->get_headern(request, "Connection", 10);
    if (connhdr == NULL || !h2c_list_has_token(connhdr->value, "HTTP2-Settings"))
        return 0;

    /* Decode the SETTINGS payload the peer folded into the header (base64url,
     * no padding — RFC 7540 §3.2.1). */
    h2_upgrade_settings_t* ud = NULL;
    if (h2settings->value_length > 0) {
        const int declen = base64url_decode_len(h2settings->value);
        uint8_t* buf = malloc(declen > 0 ? (size_t)declen : 1);
        if (buf == NULL) return 0;

        const int n = base64url_decode((char*)buf, h2settings->value);
        if (n < 0) { free(buf); return 0; } /* malformed → not an upgrade */

        ud = malloc(sizeof(*ud));
        if (ud == NULL) { free(buf); return 0; }
        ud->payload = buf;
        ud->len = (size_t)n;
    }

    /* Stage the 101 Switching Protocols response. The framework writes it, then
     * connection_after_write() runs the switch callback that builds the session. */
    response->add_headern(response, "Connection", 10, "Upgrade", 7);
    response->add_headern(response, "Upgrade", 7, "h2c", 3);
    response->status_code = 101;

    conn_ctx->switch_to_protocol.fn = h2_server_set_http2_upgrade;
    conn_ctx->switch_to_protocol.data = ud;
    conn_ctx->switch_to_protocol.data_free = h2_upgrade_settings_free;
    connection->keepalive = 1;

    return 1;
}

void h2_session_free(void* arg) {
    if (arg == NULL) return;

    h2session_t* s = arg;

    h2stream_free_all(s);

    free(s->read_buf);
    free(s->cont);
    free(s->out);
    if (s->decoder != NULL) hpack_decoder_free(s->decoder);
    if (s->encoder != NULL) hpack_encoder_free(s->encoder);
    h2frame_parser_free(&s->frame);

    free(s);
}

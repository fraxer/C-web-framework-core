#define _GNU_SOURCE
#include "h2session.h"

#include <errno.h>
#include <stdint.h>
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
#include "h2_write_filter.h"
#include "h2field.h"
#include "httpfields.h"

/* The decoded HPACK field array is handed to httpfields_to_request by viewing
 * it as httpfields_field_t. The two are layout-compatible by construction; this
 * guards against silent drift if either struct changes. */
_Static_assert(sizeof(hpack_header_t) == sizeof(httpfields_field_t),
               "hpack_header_t must stay layout-compatible with httpfields_field_t");
#include "h2ws.h"
#include "h2stream.h"
#include "httpserverhandlers.h"
#include "log.h"
#include "metrics.h"
#include "multiplexing.h"
#include "openssl.h"
#include "route.h"

/* HTTP/2 error codes (RFC 9113 §7). */
#define H2_ERR_NO_ERROR           0
#define H2_ERR_PROTOCOL_ERROR     1
#define H2_ERR_INTERNAL_ERROR     2
#define H2_ERR_FLOW_CONTROL_ERROR 3
#define H2_ERR_SETTINGS_TIMEOUT   4
#define H2_ERR_STREAM_CLOSED      5
#define H2_ERR_FRAME_SIZE_ERROR   6
#define H2_ERR_REFUSED_STREAM     7
#define H2_ERR_COMPRESSION_ERROR  9
#define H2_ERR_ENHANCE_YOUR_CALM  11

/* SETTINGS identifiers (RFC 9113 §6.5.2). */
#define H2_SETTINGS_HEADER_TABLE_SIZE      0x1
#define H2_SETTINGS_ENABLE_PUSH            0x2
#define H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define H2_SETTINGS_INITIAL_WINDOW_SIZE    0x4
#define H2_SETTINGS_MAX_FRAME_SIZE         0x5
#define H2_SETTINGS_MAX_HEADER_LIST_SIZE   0x6
#define H2_SETTINGS_ENABLE_CONNECT_PROTOCOL 0x8 /* RFC 8441 §3 */
#define H2_SETTINGS_NO_RFC7540_PRIORITIES   0x9 /* RFC 9218 §2.1 */

#define H2_MAX_WINDOW 2147483647LL /* 2^31 - 1 */

/* Give receive-window credit back once this much has been consumed, rather than
 * emitting a WINDOW_UPDATE per DATA frame. Scales with the window (an 8 MB
 * window returning credit every 16 KB would cost 512 frames per window), with
 * this as the floor. */
#define H2_WINDOW_UPDATE_MIN 16384
#define H2_WINDOW_UPDATE_DIVISOR 8

/* Absolute cap on a single header block (HEADERS + CONTINUATION*), in encoded
 * bytes. Bounds the CONTINUATION-flood attack noted in docs/http2/07 and, with
 * it, the work one block can cost the HPACK decoder. */
#define H2_MAX_HEADER_BLOCK (1u << 20)

/* ======================================================================= *
 *  Abuse limits (docs/http2/08-spec-gaps.md, phase A)
 * ======================================================================= *
 * Three of the four are thresholds guessed from what an honest client does, so
 * each is a knob and each one that fires is counted (metrics_h2_abuse) — an
 * operator otherwise cannot tell an attack from a limit set too tight.
 *
 * Stream aborts: a browser that leaves a page resets everything it had open at
 * once, so the burst has to be well above the concurrency limit; the sustained
 * rate is what separates that from a loop. */
#define H2_DEFAULT_ABORT_RATE  100   /* tokens/s */
#define H2_DEFAULT_ABORT_BURST 200   /* tokens */

/* Frames that produce an answer but no progress (docs/http2/10, R.2). An honest
 * client sends a PING every few seconds at most and a SETTINGS once or twice per
 * connection, so this is two orders of magnitude above ordinary use — the point
 * is to bound a loop, not to police pacing. */
#define H2_DEFAULT_CTRL_RATE  100  /* tokens/s */
#define H2_DEFAULT_CTRL_BURST 200  /* tokens */

/* Cap on frames queued for the peer but not yet written (docs/http2/10, R.1).
 * A peer that sends and never reads makes us hold its answers: the socket
 * buffer fills, and everything after that lands in s->out. One megabyte is far
 * above what any legitimate backlog reaches — the response headers and window
 * updates for a hundred concurrent streams are tens of kilobytes — and it is
 * the ceiling, not a target. */
#define H2_DEFAULT_MAX_OUT_BACKLOG (1024 * 1024)

/* Frames per header block. At the default max frame size this is the same 1 MB
 * H2_MAX_HEADER_BLOCK allows, approached from the other side: empty
 * CONTINUATION frames cost work without costing bytes. */
#define H2_DEFAULT_MAX_CONTINUATION_FRAMES 64

/* SETTINGS_MAX_HEADER_LIST_SIZE we advertise, and the hard multiple of it the
 * decoder is allowed to reach before the connection is written off. The soft
 * limit is answerable (431, the block is decoded to the end so the shared HPACK
 * table survives); the hard one is not — reaching it means aborting mid-block,
 * which desynchronises that table for good. */
#define H2_DEFAULT_MAX_HEADER_LIST_SIZE 32768
#define H2_HEADER_LIST_HARD_FACTOR 8

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

/* Grace for the peer to acknowledge our SETTINGS (§6.5.3) — docs/http2/08,
 * phase C.4. Generous: the ACK is due "as soon as possible", but a client that
 * is slow to start should not be cut off, and the failure this catches (a peer
 * that never acks at all) is not time-sensitive. */
#define H2_DEFAULT_SETTINGS_ACK_TIMEOUT_SEC 10

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

/* Set once per config load by h2_policy_init(), read by every worker and handler
 * thread afterwards. Plain (non-atomic) variables are safe only because of that
 * ordering: the write happens before any thread that reads them exists.
 *
 * This used to be a lazy first-session load, which was wrong on both counts —
 * two workers opening their first h2 connection at the same instant raced on the
 * guard flag and on the values, so the loser could start a session with a zero
 * receive window; and a config reload never re-read them. Defaults below are the
 * ones that apply when h2_policy_init() has not run at all. */
static uint32_t h2_idle_timeout_sec = H2_DEFAULT_IDLE_TIMEOUT_SEC;
static uint32_t h2_ping_interval_sec = 0;
static uint32_t h2_ping_ack_timeout_sec = H2_DEFAULT_PING_ACK_TIMEOUT_SEC;
static uint32_t h2_settings_ack_timeout_sec = H2_DEFAULT_SETTINGS_ACK_TIMEOUT_SEC;
static int64_t  h2_recv_window_initial = H2_DEFAULT_WINDOW;
static int64_t  h2_recv_window_max = H2_DEFAULT_RECV_WINDOW_MAX;
static int64_t  h2_write_quantum = H2_DEFAULT_WRITE_QUANTUM;
static int64_t  h2_abort_rate = H2_DEFAULT_ABORT_RATE;
static int64_t  h2_abort_burst = H2_DEFAULT_ABORT_BURST;
static int64_t  h2_ctrl_rate = H2_DEFAULT_CTRL_RATE;
static int64_t  h2_ctrl_burst = H2_DEFAULT_CTRL_BURST;
static size_t   h2_max_out_backlog = H2_DEFAULT_MAX_OUT_BACKLOG;
static uint32_t h2_max_continuation_frames = H2_DEFAULT_MAX_CONTINUATION_FRAMES;
static int64_t  h2_max_header_list_size = H2_DEFAULT_MAX_HEADER_LIST_SIZE;
static int64_t  h2_max_header_list_hard =
    (int64_t)H2_DEFAULT_MAX_HEADER_LIST_SIZE * H2_HEADER_LIST_HARD_FACTOR;

/* Cap on one header block for the limits actually configured.
 *
 * The block is measured in encoded bytes, the header-list cap in decoded ones,
 * and Huffman can expand at most 30 bits per byte — so nothing above four times
 * the hard cap could ever pass it, and decoding that far is work done for a
 * block already certain to be rejected. At the default settings this is the
 * same 1 MB the constant used to be; lowering http2_max_header_list_size now
 * lowers the decoder's worst case with it (docs/http2/10, H.2). */
static size_t h2_header_block_cap(void) {
    if (h2_max_header_list_hard <= 0) return H2_MAX_HEADER_BLOCK;

    const uint64_t cap = (uint64_t)h2_max_header_list_hard * 4;

    return cap < H2_MAX_HEADER_BLOCK ? (size_t)cap : H2_MAX_HEADER_BLOCK;
}

void h2_policy_init(void) {
    h2_idle_timeout_sec = (uint32_t)env_get_int("http2_idle_timeout_sec", H2_DEFAULT_IDLE_TIMEOUT_SEC);
    h2_ping_interval_sec = (uint32_t)env_get_int("http2_ping_interval_sec", 0);
    /* Default ack grace: the interval itself, capped so a stuck peer is caught
     * in bounded time even with long intervals. */
    uint32_t ack_default = h2_ping_interval_sec ? h2_ping_interval_sec : H2_DEFAULT_PING_ACK_TIMEOUT_SEC;
    if (ack_default > H2_DEFAULT_PING_ACK_TIMEOUT_SEC) ack_default = H2_DEFAULT_PING_ACK_TIMEOUT_SEC;
    h2_ping_ack_timeout_sec = (uint32_t)env_get_int("http2_ping_ack_timeout_sec", (int)ack_default);

    /* 0 disables the SETTINGS_TIMEOUT check — the idle timeout still reaps a
     * peer that goes on to do nothing. */
    h2_settings_ack_timeout_sec = (uint32_t)env_get_int("http2_settings_ack_timeout_sec",
                                                        H2_DEFAULT_SETTINGS_ACK_TIMEOUT_SEC);

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

    /* Abuse limits (phase A). Each takes 0 to mean "off", because every one of
     * them can in principle misfire on a client nobody has met yet, and an
     * operator needs a way to prove that before the fix ships. */
    h2_abort_rate = env_get_int("http2_abort_rate", H2_DEFAULT_ABORT_RATE);
    if (h2_abort_rate < 0) h2_abort_rate = 0;

    h2_abort_burst = env_get_int("http2_abort_burst", H2_DEFAULT_ABORT_BURST);
    /* A burst below the concurrency limit would fire on a client that merely
     * cancels everything it has open, which is ordinary behaviour. */
    if (h2_abort_burst < H2_MAX_CONCURRENT_STREAMS) h2_abort_burst = H2_MAX_CONCURRENT_STREAMS;

    h2_ctrl_rate = env_get_int("http2_ctrl_rate", H2_DEFAULT_CTRL_RATE);
    if (h2_ctrl_rate < 0) h2_ctrl_rate = 0;

    h2_ctrl_burst = env_get_int("http2_ctrl_burst", H2_DEFAULT_CTRL_BURST);
    if (h2_ctrl_burst < 1) h2_ctrl_burst = 1;

    /* 0 disables the backlog cap. Floored well above one maximum-size frame so
     * the limit can never fire on a single legitimate write. */
    h2_max_out_backlog = (size_t)env_get_int("http2_max_out_backlog",
                                             H2_DEFAULT_MAX_OUT_BACKLOG);
    if (h2_max_out_backlog != 0 && h2_max_out_backlog < 4 * H2_MAX_FRAME_SIZE_DEFAULT)
        h2_max_out_backlog = 4 * H2_MAX_FRAME_SIZE_DEFAULT;

    h2_max_continuation_frames = (uint32_t)env_get_int("http2_max_continuation_frames",
                                                       H2_DEFAULT_MAX_CONTINUATION_FRAMES);

    h2_max_header_list_size = env_get_int("http2_max_header_list_size",
                                          H2_DEFAULT_MAX_HEADER_LIST_SIZE);
    if (h2_max_header_list_size < 0) h2_max_header_list_size = 0;
    /* Clamped so the value can be advertised in a 32-bit SETTINGS field. */
    if (h2_max_header_list_size > UINT32_MAX) h2_max_header_list_size = UINT32_MAX;

    h2_max_header_list_hard = h2_max_header_list_size * H2_HEADER_LIST_HARD_FACTOR;
    if (h2_max_header_list_size == 0) h2_max_header_list_hard = 0; /* both off */
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
static h2_frame_result_e h2_reject_stream(h2session_t* s, h2stream_t* stream,
                                          int status_code, int end_stream);
static void h2_recv_settle(h2session_t* s);

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

    /* Whatever window credit is queued is on its way to the peer now — see
     * h2_recv_settle. Done here rather than in the callers because this is the
     * one place every path goes through on its way to the socket. */
    h2_recv_settle(s);

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

/* Grant `increment` more receive window on one flow. `w` is that flow's state:
 * the credit is added to it only if the frame was actually queued, which is what
 * keeps w->avail equal to what the peer has been told it may send. Crediting a
 * frame that never went out would make us accept bytes the peer was never
 * allowed to send — silently, and only under memory pressure. */
static void h2_queue_window_update(h2session_t* s, uint32_t stream_id,
                                   h2_recv_window_t* w, uint32_t increment) {
    if (increment == 0) return;

    const uint8_t payload[4] = {
        (uint8_t)((increment >> 24) & 0x7f),
        (uint8_t)((increment >> 16) & 0xff),
        (uint8_t)((increment >> 8) & 0xff),
        (uint8_t)(increment & 0xff),
    };

    if (!h2_session_queue_frame(s, H2_FRAME_WINDOW_UPDATE, 0, stream_id, payload, sizeof(payload)))
        return;

    w->credited += increment;
    /* Only a stream's credit needs the table walk in h2_recv_settle; the
     * connection's own window is settled unconditionally, being one field. */
    if (stream_id != 0) s->stream_credit_pending = 1;
}

/* Hand the queued window credit to the peer's account. Called as the outbound
 * buffer is about to go to the socket — deliberately without waiting to see how
 * much of it the socket took: crediting slightly early costs nothing (we accept
 * bytes the peer was about to be allowed to send anyway), while crediting late
 * would kill a connection whose peer used a window it had legitimately been
 * granted. The direction of the error matters more than its timing. */
static void h2_recv_settle(h2session_t* s) {
    s->recv.avail += s->recv.credited;
    s->recv.credited = 0;

    /* Guarded because this is on the write path's hot loop: with a hundred
     * streams on a connection, walking the table on every flush would cost more
     * than the accounting it exists for. Only an upload queues stream credit,
     * and most connections never send a byte of request body. */
    if (!s->stream_credit_pending) return;

    for (h2stream_t* stream = s->streams; stream != NULL; stream = stream->next) {
        stream->recv.avail += stream->recv.credited;
        stream->recv.credited = 0;
    }

    s->stream_credit_pending = 0;
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

    h2_queue_window_update(s, stream_id, w, (uint32_t)increment);
}

/* Debit a flow-controlled frame from one flow's window (§6.9.1). Returns 0 when
 * the peer overran it: everything the frame carried counts, padding included,
 * and it counts whatever we then do with the payload — the peer spent the credit
 * the moment it sent the frame. */
static int h2_recv_debit(h2_recv_window_t* w, uint32_t len) {
    w->avail -= (int64_t)len;

    return w->avail >= 0;
}

/* A fresh stream is credited up to the learned window (§6.9.2 lets SETTINGS set
 * only the initial value, so the difference has to go out as a WINDOW_UPDATE). */
static void h2_stream_recv_init(h2session_t* s, h2stream_t* stream) {
    stream->recv.epoch_ms = h2_now_ms();
    /* SETTINGS_INITIAL_WINDOW_SIZE is all the peer credits a new stream with;
     * anything this connection has already learned above that is only ours to
     * count once the WINDOW_UPDATE below has been queued. */
    stream->recv.avail = h2_recv_window_initial;

    if (stream->recv.size > h2_recv_window_initial)
        h2_queue_window_update(s, stream->id, &stream->recv,
                               (uint32_t)(stream->recv.size - h2_recv_window_initial));
}

/* Spend one token of a leaky bucket. The bucket is kept in milli-tokens so the
 * refill is exact integer arithmetic: a rate of R tokens per second is R
 * milli-tokens per elapsed millisecond, with no remainder to drop however often
 * this is called. `rate` of 0 disables the limit.
 *
 * Returns 0 when the budget is spent, and the caller ends the connection. */
static int h2_budget_spend(int64_t* tokens, uint64_t* epoch_ms,
                           int64_t rate, int64_t burst) {
    if (rate == 0) return 1; /* disabled */

    const uint64_t now = h2_now_ms();
    const uint64_t elapsed = now - *epoch_ms;
    const int64_t cap = burst * 1000;

    *epoch_ms = now;
    *tokens += (int64_t)elapsed * rate;
    if (*tokens > cap) *tokens = cap;

    if (*tokens < 1000) return 0;

    *tokens -= 1000;

    return 1;
}

/* Stream-abort budget (docs/http2/08, phase A.2).
 *
 * A stream that is opened and immediately reset costs a dispatch and an HPACK
 * decode while holding a concurrency slot for no measurable time, so
 * MAX_CONCURRENT_STREAMS bounds nothing at all — this is CVE-2023-44487. */
static int h2_abort_budget_spend(h2session_t* s) {
    return h2_budget_spend(&s->abort_tokens, &s->abort_epoch_ms,
                           h2_abort_rate, h2_abort_burst);
}

/* Budget for frames that make this server work without advancing anything
 * (docs/http2/10, R.2). Everything charged here is legal, cheap for the peer to
 * send, and either produces an answer of ours or is simply discarded:
 *
 *   PING without ACK      we must echo it back (CVE-2019-9512)
 *   SETTINGS without ACK  we must acknowledge it (CVE-2019-9515)
 *   DATA of zero length   costs no flow-control window at all (CVE-2019-9518)
 *   PRIORITY              deprecated by §5.3 and ignored here (CVE-2019-9513)
 *   WINDOW_UPDATE on a stream that no longer exists
 *
 * Deliberately a second bucket rather than a share of the abort one: an honest
 * client's rate of these is nothing like its rate of stream cancellations, and
 * one bucket for both would have to be set by the looser of the two. */
static int h2_ctrl_budget_spend(h2session_t* s) {
    return h2_budget_spend(&s->ctrl_tokens, &s->ctrl_epoch_ms,
                           h2_ctrl_rate, h2_ctrl_burst);
}

/* Bytes queued for the peer and not yet on the wire. */
static size_t h2_out_pending(const h2session_t* s) {
    return s->out_len > s->out_pos ? s->out_len - s->out_pos : 0;
}

static int rearm(connection_t* conn, int events) {
    connection_server_ctx_t* ctx = conn->ctx;

    /* Same guard as connection_after_read: never epoll_ctl a connection whose fd
     * has already been closed and whose number may now belong to somebody else. */
    if (atomic_load(&ctx->detached))
        return 1;

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

/* Common tail for a spent control budget: name the frame that ran it out, since
 * which one it was is the whole diagnosis, and end the connection. */
static h2_frame_result_e h2_ctrl_flood(h2session_t* s, const char* what) {
    metrics_h2_abuse(METRICS_H2_CTRL_FLOOD);
    log_error("h2: control-frame budget exhausted by %s (fd %d)\n", what, s->connection->fd);

    return h2_conn_error(s, H2_ERR_ENHANCE_YOUR_CALM);
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
 * ======================================================================= *
 *  The field list → httprequest_t rules live in protocols/http/httpfields.c,
 *  shared with HTTP/3 (docs/http3/05-http3.md §6.1). h2_build_request keeps
 *  only the HPACK-specific half: decode the block, enforce the header-list
 *  size, hand the decoded fields to httpfields_to_request, then select the
 *  virtual server (which needs the connection the shared builder does not). */


typedef enum {
    H2_REQUEST_OK = 0,
    H2_REQUEST_MALFORMED,   /* stream error: RST_STREAM(PROTOCOL_ERROR) */
    H2_REQUEST_COMPRESSION, /* connection error: the HPACK context is unusable */
    H2_REQUEST_INTERNAL,
    H2_REQUEST_TOO_LARGE,   /* over the advertised header list size → 431 */
    H2_REQUEST_TOO_LARGE_HARD, /* over the hard cap: decode aborted mid-block */
    H2_REQUEST_EXTENDED_CONNECT, /* RFC 8441 shape, protocol we do not serve → 501 */
    H2_REQUEST_WEBSOCKET,        /* RFC 8441 :protocol websocket — open a tunnel */
} h2_request_status_e;

/* Size of a decoded header list as RFC 9113 §6.5.2 counts it. */
static size_t h2_header_list_size(const hpack_header_t* headers, size_t count) {
    size_t total = 0;

    for (size_t i = 0; i < count; i++)
        total += headers[i].name_len + headers[i].value_len + 32;

    return total;
}

/* Map an HPACK failure onto the request outcome. TOO_LARGE is the hard cap only:
 * the decoder stopped in the middle of the block, so the dynamic table no longer
 * matches the peer's and the connection cannot continue. The soft limit is
 * checked by the caller, over a block that was decoded in full. */
static h2_request_status_e h2_hpack_failed(hpack_status_e st) {
    if (st == HPACK_ERR_TOO_LARGE) return H2_REQUEST_TOO_LARGE_HARD;
    if (st == HPACK_ERR_MEMORY) return H2_REQUEST_INTERNAL;

    return H2_REQUEST_COMPRESSION;
}

/* Fill an httprequest_t from a decoded HPACK block, applying the request
 * validity rules of RFC 9113 §8.3 / §8.2 on the way. Everything the h1.1 parser
 * derives from headers is derived here too. */
static h2_request_status_e h2_build_request(h2session_t* s, h2stream_t* stream,
                                            const uint8_t* block, size_t len) {
    httprequest_t* request = stream->request;
    hpack_header_t* headers = NULL;
    size_t count = 0;
    const hpack_status_e hst = hpack_decoder_decode(s->decoder, block, len,
                                                    (size_t)h2_max_header_list_hard,
                                                    &headers, &count);
    if (hst != HPACK_OK) return h2_hpack_failed(hst);

    /* §6.5.2: over what we advertised, but decoded in full — the connection
     * stays usable and the stream can be answered rather than reset. */
    if (h2_max_header_list_size != 0 &&
        h2_header_list_size(headers, count) > (size_t)h2_max_header_list_size) {
        hpack_headers_free(headers, count);
        return H2_REQUEST_TOO_LARGE;
    }

    int64_t content_length = -1;
    const http_fields_status_e fst = httpfields_to_request(
        request, (const httpfields_field_t*)headers, count, HTTP_FIELDS_H2, &content_length);
    hpack_headers_free(headers, count);
    stream->content_length = content_length;

    /* Map the shared builder's verdict onto the h2 stream outcomes. The two line
     * up 1:1; TOO_LARGE/COMPRESSION are HPACK-specific and handled above.
     * EXTENDED_CONNECT/WEBSOCKET reach h2ws.c unchanged. */
    h2_request_status_e status;
    switch (fst) {
    case HTTP_FIELDS_OK:               status = H2_REQUEST_OK;               break;
    case HTTP_FIELDS_INTERNAL:         status = H2_REQUEST_INTERNAL;         break;
    case HTTP_FIELDS_EXTENDED_CONNECT: status = H2_REQUEST_EXTENDED_CONNECT; break;
    case HTTP_FIELDS_WEBSOCKET:        status = H2_REQUEST_WEBSOCKET;        break;
    default:                           status = H2_REQUEST_MALFORMED;        break;
    }
    if (status != H2_REQUEST_OK) return status;

    /* :authority (now Host) selects the virtual server and must agree with SNI
     * (RFC 9110 §7.4). Kept here: it needs the connection the shared builder
     * deliberately does not take. */
    http_header_t* host = request->get_headern(request, "Host", 4);
    if (host == NULL) return H2_REQUEST_MALFORMED; /* §8.3.1: :authority or Host */
    if (httpparser_select_server(s->connection, host->value, host->value_length) != HTTP1PARSER_CONTINUE)
        return H2_REQUEST_MALFORMED;

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
    const hpack_status_e st = hpack_decoder_decode(s->decoder, block, len,
                                                   (size_t)h2_max_header_list_hard,
                                                   &headers, &count);
    if (st != HPACK_OK) return h2_hpack_failed(st);

    hpack_headers_free(headers, count);

    return H2_REQUEST_OK;
}

/* Trailers (a HEADERS frame after DATA). The block is fed to the decoder — the
 * shared HPACK context has to stay in sync whatever we do with the fields — and
 * the fields are handed to the request, where a handler can read them back
 * (docs/http2/10, T.1). They land in their own list, never merged into the
 * headers: everything a request is routed and authorised by was decided long
 * before these arrived. Pseudo-headers are forbidden here (§8.1), which makes
 * the request malformed.
 *
 * `stream` may be NULL when the caller only needs the decoder kept in step. */
static h2_request_status_e h2_consume_trailers(h2session_t* s, h2stream_t* stream,
                                               const uint8_t* block, size_t len) {
    hpack_header_t* headers = NULL;
    size_t count = 0;
    const hpack_status_e hst = hpack_decoder_decode(s->decoder, block, len,
                                                    (size_t)h2_max_header_list_hard,
                                                    &headers, &count);
    if (hst != HPACK_OK) return h2_hpack_failed(hst);

    h2_request_status_e status = H2_REQUEST_OK;
    for (size_t i = 0; i < count; i++) {
        /* Same octet rules as a header block (§8.2.1 does not distinguish), plus
         * §8.1: no pseudo-headers in trailers. */
        if (headers[i].name_len > 0 && headers[i].name[0] == ':') {
            status = H2_REQUEST_MALFORMED;
            break;
        }
        if (h2_field_validate(headers[i].name, headers[i].name_len,
                              headers[i].value, headers[i].value_len) != H2_FIELD_OK) {
            status = H2_REQUEST_MALFORMED;
            break;
        }

        /* Fields banned in a header block are no more welcome in a trailer
         * (§8.2.2), and §8.1 keeps out the ones that would change how the
         * message itself is read — by the time they arrive, it has been read. */
        if (httpfields_is_forbidden_header(headers[i].name, headers[i].name_len) ||
            (headers[i].name_len == 14 &&
             memcmp(headers[i].name, "content-length", 14) == 0)) {
            status = H2_REQUEST_MALFORMED;
            break;
        }

        if (stream == NULL) continue;

        if (httprequest_trailern_add(stream->request,
                                     headers[i].name, headers[i].name_len,
                                     headers[i].value, headers[i].value_len) != 0) {
            status = H2_REQUEST_INTERNAL;
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
    atomic_store_explicit(&stream->handler_pending, 1, memory_order_release);

    if (!http_server_dispatch(s->connection, stream->request)) {
        atomic_store_explicit(&stream->handler_pending, 0, memory_order_release);
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

                /* §6.9.2: a raise that pushes any stream window past 2^31-1 is
                 * a connection error. Reachable only in combination with
                 * WINDOW_UPDATE — the setting alone is bounded above — which is
                 * why the value check on entry is not enough. The deltas
                 * already applied are left as they are: the session is going
                 * away with this return. */
                if (stream->send_window > H2_MAX_WINDOW)
                    return h2_conn_error(s, H2_ERR_FLOW_CONTROL_ERROR);

                if (stream->send_window > 0) stream->window_blocked = 0;
            }
            break;
        }
        case H2_SETTINGS_MAX_FRAME_SIZE:
            if (value < H2_MAX_FRAME_SIZE_DEFAULT || value > H2_MAX_FRAME_SIZE_LIMIT)
                return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
            s->peer_max_frame_size = value;
            break;
        case H2_SETTINGS_NO_RFC7540_PRIORITIES:
            /* RFC 9218 §2.1: 0 or 1, and once a value has been sent it may not
             * change — a peer that flips it is signalling two different
             * prioritization schemes for one connection. */
            if (value > 1) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
            if (s->peer_no_rfc7540_priorities_seen &&
                s->peer_no_rfc7540_priorities != (int)value)
                return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

            s->peer_no_rfc7540_priorities = (int)value;
            s->peer_no_rfc7540_priorities_seen = 1;
            break;
        case H2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
            /* RFC 8441 §3: only 0 and 1 exist. The value itself says what the
             * *sender* supports, which for a client means nothing to us — we
             * are the one being connected to. Validated all the same, because
             * §3 makes anything else a connection error. */
            if (value > 1) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);
            break;
        case H2_SETTINGS_MAX_HEADER_LIST_SIZE:
            /* Advisory (§6.5.2): the peer cannot make this binding, since we may
             * have committed to a response before it arrives. Kept so an
             * oversize response can say so in the log instead of coming back as
             * an unexplained reset from the client. */
            s->peer_max_header_list_size = value;
            break;
        default:
            break; /* unknown settings must be ignored (§6.5.2) */
        }
    }

    return H2_FRAME_OK;
}

static h2_frame_result_e h2_on_settings(h2session_t* s, const h2_frame_t* frame) {
    if (frame->flags & H2_FLAG_ACK) {
        /* Retires the SETTINGS_TIMEOUT watch (§6.5.3). An ACK with a payload
         * never gets here — the frame validator rejects it with
         * FRAME_SIZE_ERROR (phase C.2), which is exactly the check this early
         * return used to swallow. */
        s->settings_sent_ms = 0;
        return H2_FRAME_OK;
    }

    /* Every SETTINGS costs us an ACK, and an empty one costs the peer nine
     * bytes (docs/http2/10, R.2). Charged before the payload is applied: a
     * settings flood is a flood whether or not the values are meaningful. */
    if (!h2_ctrl_budget_spend(s)) return h2_ctrl_flood(s, "SETTINGS");

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
    if (stream == NULL) {
        /* The stream is closed and gone: the update lands nowhere. A few of
         * these are ordinary — the peer credited a stream we had just finished —
         * which is why they are charged rather than refused (docs/http2/10, R.2). */
        if (!h2_ctrl_budget_spend(s)) return h2_ctrl_flood(s, "WINDOW_UPDATE on a closed stream");

        return H2_FRAME_OK;
    }

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

    /* Nothing here changes any state — §5.3 deprecated the scheme and we
     * advertise NO_RFC7540_PRIORITIES, so a conforming client sends none of
     * these at all (docs/http2/10, R.2). */
    if (!h2_ctrl_budget_spend(s)) return h2_ctrl_flood(s, "PRIORITY");

    return H2_FRAME_OK;
}

static h2_frame_result_e h2_on_rst_stream(h2session_t* s, const h2_frame_t* frame) {
    /* §6.4: RST_STREAM on an idle stream is a connection error. */
    if (h2_stream_state_of(s, frame->stream_id) == H2_STREAM_IDLE)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    h2stream_t* stream = h2stream_find(s, frame->stream_id);
    if (stream != NULL) {
        /* A reset before the response went out is the expensive kind: the work
         * was queued and is now thrown away. Resetting a stream that has already
         * been answered is what an ordinary client does when it stops reading,
         * and it costs the server nothing — so it costs no budget either. */
        if (!stream->end_stream_sent && !h2_abort_budget_spend(s)) {
            metrics_h2_abuse(METRICS_H2_RST_FLOOD);
            log_error("h2: stream-abort budget exhausted (fd %d)\n", s->connection->fd);
            return h2_conn_error(s, H2_ERR_ENHANCE_YOUR_CALM);
        }

        stream->state = H2_STREAM_CLOSED;
        h2_session_drop_stream(s, stream);
    }

    return H2_FRAME_OK;
}

/* Peer GOAWAY (§6.8) — docs/http2/08, phase C.3.
 *
 * This used to close the connection on the spot, which threw away every
 * response still owed to a stream the peer had asked for and was still waiting
 * on: GOAWAY means "I am going away", not "hang up on me now". What §6.8 asks
 * for is what the shutdown path already does — stop accepting new streams, let
 * the ones in flight finish, then close — so this reuses `draining` and lets
 * h2_server_tick do the closing once the table empties.
 *
 * The peer's last_stream_id bounds what IT will process, i.e. the responses it
 * has any use for; ours is unaffected. The code and the debug data are logged
 * because they are the only account we will ever get of what the client thought
 * we did wrong. */
static h2_frame_result_e h2_on_goaway(h2session_t* s, const h2_frame_t* frame) {
    const uint8_t* p = frame->payload;
    const uint32_t last_stream_id = ((uint32_t)(p[0] & 0x7f) << 24) |
                                    ((uint32_t)p[1] << 16) |
                                    ((uint32_t)p[2] << 8) | p[3];
    const uint32_t error_code = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                                ((uint32_t)p[6] << 8) | p[7];

    /* Debug data is opaque and attacker-controlled: length-bounded, and only
     * worth a line at all when the peer is reporting an actual error. */
    if (error_code != H2_ERR_NO_ERROR) {
        const size_t debug_len = frame->payload_len > 8 ? frame->payload_len - 8 : 0;
        log_error("h2: peer GOAWAY error=%u last_stream_id=%u (fd %d)%.*s%.*s\n",
                  error_code, last_stream_id, s->connection->fd,
                  debug_len > 0 ? 8 : 0, " debug=\"",
                  (int)(debug_len > 256 ? 256 : debug_len), (const char*)p + 8);
    }

    s->peer_goaway = 1;

    /* Nothing left to serve — close now rather than wait for a tick. */
    if (s->stream_count == 0) return H2_FRAME_CLOSE;

    /* Streams in flight: answer them, then go. h2_server_tick closes the
     * connection once the table is empty; the idle timeout is the backstop if
     * the peer stops reading and a response can never drain. */
    s->draining = 1;

    return H2_FRAME_OK;
}

/* Map a request-construction outcome onto the wire. */
static h2_frame_result_e h2_request_failed(h2session_t* s, h2stream_t* stream,
                                           h2_request_status_e status) {
    const uint32_t stream_id = stream->id;

    h2_session_drop_stream(s, stream);

    /* Anything that left the shared HPACK decoder mid-block, or out of step with
     * the peer, costs the connection: every later stream would decode garbage.
     * A merely malformed request costs only its own stream. */
    switch (status) {
    case H2_REQUEST_COMPRESSION:
        return h2_conn_error(s, H2_ERR_COMPRESSION_ERROR);
    case H2_REQUEST_INTERNAL:
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);
    case H2_REQUEST_TOO_LARGE_HARD:
        metrics_h2_abuse(METRICS_H2_HEADER_LIST_HARD);
        log_error("h2: header list over the hard cap on stream %u — closing connection\n", stream_id);
        return h2_conn_error(s, H2_ERR_ENHANCE_YOUR_CALM);
    default:
        return h2_stream_error(s, stream_id, H2_ERR_PROTOCOL_ERROR);
    }
}

/* Answer a request the session refuses to route, without running a handler.
 *
 * The stream keeps its slot until the write path has sent the response, so it
 * goes out the same way a handler's would. `rejected` is what makes the rest of
 * the request harmless: the peer may already be sending a body it could not know
 * we did not want, and that DATA has to keep being credited and discarded rather
 * than dispatched or treated as an error. */
/* Accept an extended CONNECT and turn the stream into a WebSocket tunnel
 * (RFC 8441) — docs/http2/09, step 2.
 *
 * Two things make this unlike every other response on an h2 stream, and both
 * are the tunnel's defining property rather than special cases:
 *   - the answer is 200 with no body and, crucially, **no END_STREAM**: the
 *     stream stays open in both directions, which is what a tunnel is;
 *   - the stream is not closed when that response has been written. The write
 *     path checks stream->ws for both (see h2_write_finished).
 *
 * END_STREAM on the request itself means a client that opened a tunnel and
 * immediately half-closed it. Legal, useless, and not worth a special path: the
 * tunnel opens and dies on the next sweep. */
static h2_frame_result_e h2_open_tunnel(h2session_t* s, h2stream_t* stream, int end_stream) {
    /* A vhost that declares no "websockets" section does not serve tunnels.
     * Worth checking rather than assuming, because advertising the capability
     * is per connection while serving it is per vhost, and it is the client
     * that now picks where to open one. 501: the request is fine, this endpoint
     * is not the place for it (docs/http2/09, step 8). */
    connection_server_ctx_t* conn_ctx = s->connection->ctx;
    if (conn_ctx->server == NULL || !conn_ctx->server->websockets.configured) {
        log_info("h2: extended CONNECT on a vhost without websockets (fd %d)\n",
                 s->connection->fd);
        return h2_reject_stream(s, stream, 501, end_stream);
    }

    /* Sec-WebSocket-Protocol picks the message protocol exactly as it does on
     * the HTTP/1.1 handshake (websocketsswitch.c): "resource" routes each message
     * by its own method+location, anything else goes to the default handler.
     * It is an ordinary header here — RFC 8441 changes the handshake, not the
     * subprotocol negotiation. */
    const http_header_t* subprotocol =
        stream->request->get_headern(stream->request, "Sec-WebSocket-Protocol", 22);
    const int resource = subprotocol != NULL && subprotocol->value != NULL &&
        strcmp(subprotocol->value, "resource") == 0;

    /* permessage-deflate is negotiated by an ordinary header here too, exactly
     * as in the HTTP/1.1 handshake (websocketsswitch.c) — RFC 8441 replaces the
     * upgrade, not the extension negotiation. */
    ws_deflate_config_t deflate_config;
    int deflate = 0;
    const http_header_t* extensions =
        stream->request->get_headern(stream->request, "Sec-WebSocket-Extensions", 24);
    if (extensions != NULL && extensions->value != NULL)
        deflate = ws_deflate_parse_header(extensions->value, &deflate_config);

    stream->ws = h2_ws_tunnel_create(s->connection, stream, resource, deflate ? &deflate_config : NULL);
    if (stream->ws == NULL) {
        h2_session_drop_stream(s, stream);
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);
    }

    httpresponse_t* response = httpresponse_create_h2(s->connection);
    if (response == NULL) {
        h2_session_drop_stream(s, stream);
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);
    }

    /* 200, not 101: HTTP/2 has no 101 at all (RFC 8441 §4). */
    response->status_code = 200;

    /* Echo the accepted subprotocol and extension, as the HTTP/1.1 handshake
     * does. Only what was actually accepted: the tunnel is already built, so
     * "negotiated" here means "in use". */
    if (resource)
        response->add_headern(response, "Sec-WebSocket-Protocol", 22, "resource", 8);

    if (deflate && stream->ws->parser->ws_deflate_enabled) {
        char ext[256];
        const int len = ws_deflate_build_header(&deflate_config, ext, sizeof(ext));
        if (len > 0)
            response->add_headern(response, "Sec-WebSocket-Extensions", 24, ext, (size_t)len);
    }

    stream->response = response;
    stream->headers_done = 1;
    if (end_stream) stream->state = H2_STREAM_HALF_CLOSED_REMOTE;

    log_info("h2: WebSocket tunnel opened on stream %u (fd %d)\n",
             stream->id, s->connection->fd);

    atomic_store_explicit(&stream->response_ready, 1, memory_order_release);

    return H2_FRAME_OK;
}

static h2_frame_result_e h2_reject_stream(h2session_t* s, h2stream_t* stream,
                                          int status_code, int end_stream) {
    httpresponse_t* response = httpresponse_create_h2(s->connection);
    if (response == NULL) {
        h2_session_drop_stream(s, stream);
        return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);
    }

    httpresponse_default(response, status_code);

    stream->response = response;
    stream->rejected = 1;
    stream->headers_done = 1;
    if (end_stream) stream->state = H2_STREAM_HALF_CLOSED_REMOTE;

    /* Release-store for symmetry with h2_publish_one: the write path loads this
     * with acquire, and must not see the flag before the response it announces. */
    atomic_store_explicit(&stream->response_ready, 1, memory_order_release);

    return H2_FRAME_OK;
}

static h2_frame_result_e h2_on_header_block(h2session_t* s, uint32_t stream_id,
                                            const uint8_t* block, size_t len,
                                            int end_stream) {
    h2stream_t* stream = h2stream_find(s, stream_id);

    /* A header block on a stream that is already open is trailers, not a new
     * request (§8.1). */
    if (stream != NULL && stream->state == H2_STREAM_OPEN && stream->headers_done) {
        /* The block must still be decoded to keep the HPACK context in sync,
         * even when the stream is about to be reset — and a stream that was
         * already answered without a handler has nobody to read the fields, so
         * it only gets the decode. */
        const h2_request_status_e status =
            h2_consume_trailers(s, stream->rejected ? NULL : stream, block, len);
        if (status != H2_REQUEST_OK)
            return h2_request_failed(s, stream, status);

        /* §8.1: trailers terminate the request; without END_STREAM this is a
         * second header block in mid-stream. */
        if (!end_stream)
            return h2_stream_error(s, stream_id, H2_ERR_PROTOCOL_ERROR);

        /* Already answered without a handler — the trailers were decoded to keep
         * the HPACK table in step, and that is all they were needed for. */
        if (stream->rejected) {
            stream->state = H2_STREAM_HALF_CLOSED_REMOTE;
            return H2_FRAME_OK;
        }

        return h2_dispatch(s, stream);
    }

    stream = h2stream_create(s, stream_id);
    if (stream == NULL) return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

    h2_stream_recv_init(s, stream);

    if (stream_id > s->last_stream_id) s->last_stream_id = stream_id;

    const h2_request_status_e status = h2_build_request(s, stream, block, len);
    if (status == H2_REQUEST_TOO_LARGE) {
        metrics_h2_abuse(METRICS_H2_HEADER_LIST);

        /* Charged like a refusal (phase A.2): the block was decoded in full,
         * which is the most expensive thing a peer can make this server do, and
         * a 431 is answered without the stream ever holding a slot. Without the
         * token an oversize block is free to repeat for as long as the client
         * likes (docs/http2/10, H.2). */
        if (!h2_abort_budget_spend(s)) {
            /* Its own counter although it spends the abort budget: the operator's
             * answer differs (raise http2_max_header_list_size, or treat it as an
             * attack), and "header_list_too_large" above only says a 431 went out,
             * not that the connection ended over it. */
            metrics_h2_abuse(METRICS_H2_HEADER_LIST_FLOOD);
            log_error("h2: oversize-header budget exhausted (fd %d)\n", s->connection->fd);
            return h2_conn_error(s, H2_ERR_ENHANCE_YOUR_CALM);
        }

        return h2_reject_stream(s, stream, 431, end_stream);
    }
    /* A tunnel request answered with a status: `rejected` makes whatever the
     * client already sent into the tunnel be credited and dropped rather than
     * treated as a request body (docs/http2/09, step 1). */
    if (status == H2_REQUEST_EXTENDED_CONNECT)
        return h2_reject_stream(s, stream, 501, end_stream);
    if (status == H2_REQUEST_WEBSOCKET)
        return h2_open_tunnel(s, stream, end_stream);
    if (status != H2_REQUEST_OK)
        return h2_request_failed(s, stream, status);

    stream->headers_done = 1;

    if (!end_stream) {
        /* A body is still to come and the client said it would wait for
         * permission (RFC 9110 §10.1.1) — docs/http2/10, T.2. Queued straight
         * away: h2_drain_and_rearm flushes the outbound buffer at the end of
         * this read, so the 100 is on the wire before the client's timer. */
        const http_header_t* expect =
            stream->request->get_headern(stream->request, "Expect", 6);

        if (expect != NULL && expect->value != NULL &&
            strcasecmp(expect->value, "100-continue") == 0)
            (void)h2_write_filter_continue(s, stream);

        return H2_FRAME_OK;
    }

    return h2_dispatch(s, stream);
}

static h2_frame_result_e h2_on_headers(h2session_t* s, const h2_frame_t* frame) {
    /* §5.1.1: client-initiated streams are odd-numbered, and ids only ever
     * increase — reusing a closed one is a connection error. */
    if ((frame->stream_id & 1) == 0) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    const h2stream_state_e state = h2_stream_state_of(s, frame->stream_id);
    /* §5.1 "closed": the stream is gone from the table, so there is nothing left
     * to reset and no way to tell a finished stream from a never-opened id —
     * both are a connection error here (the code that goes out is discussed in
     * docs/http2/10, S.4). */
    if (state == H2_STREAM_CLOSED) return h2_conn_error(s, H2_ERR_STREAM_CLOSED);

    const int trailers = (state == H2_STREAM_OPEN);
    /* §5.1 "half-closed (remote)": the peer already ended its side, so this
     * block is a violation — but a *stream* error, not a connection one. It has
     * to travel the same path as a refusal below, because the block still has to
     * reach the HPACK decoder: the table is shared with every other stream on
     * the connection, and skipping one block desynchronises it for good.
     * This used to kill the connection instead (docs/http2/10, S.3). */
    const int half_closed = (state == H2_STREAM_HALF_CLOSED_REMOTE);

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
    const int refused = !trailers && !half_closed &&
        (h2stream_active_count(s) >= H2_MAX_CONCURRENT_STREAMS ||
         /* RFC 9113 §6.8: once GOAWAY(last_stream_id) is out, streams with a
          * higher id are out of bounds. Streams at or below the boundary that
          * the peer had in flight before seeing our GOAWAY are still served. */
         (s->goaway_sent && frame->stream_id > s->last_stream_id) ||
         /* §6.8 also forbids the peer opening new streams once it has itself
          * announced it is going away. Refusing keeps the drain finite: every
          * accepted stream would push the close back another response. */
         s->peer_goaway);
    if (self_dependent || refused || half_closed) {
        if (frame->flags & H2_FLAG_END_HEADERS) {
            const h2_request_status_e status = h2_discard_header_block(s, block, block_len);
            if (status != H2_REQUEST_OK)
                return h2_conn_error(s, status == H2_REQUEST_TOO_LARGE_HARD ?
                                     H2_ERR_ENHANCE_YOUR_CALM : H2_ERR_COMPRESSION_ERROR);
        }

        if (frame->stream_id > s->last_stream_id) s->last_stream_id = frame->stream_id;

        /* A refusal is work the peer made us do for a stream it never got to
         * hold, exactly like a reset — same budget (phase A.2). Charged after
         * the block is decoded, so the HPACK table is in step either way.
         *
         * A half-closed stream is not charged: the reset below drops it from the
         * table, so the next block on that id is a "closed" stream and ends the
         * connection anyway. One per id is not a loop. */
        if (refused && !h2_abort_budget_spend(s)) {
            metrics_h2_abuse(METRICS_H2_RST_FLOOD);
            log_error("h2: refused-stream budget exhausted (fd %d)\n", s->connection->fd);
            return h2_conn_error(s, H2_ERR_ENHANCE_YOUR_CALM);
        }

        return h2_stream_error(s, frame->stream_id,
                               half_closed ? H2_ERR_STREAM_CLOSED :
                               refused ? H2_ERR_REFUSED_STREAM : H2_ERR_PROTOCOL_ERROR);
    }

    if (!(frame->flags & H2_FLAG_END_HEADERS)) {
        if (block_len > h2_header_block_cap()) return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

        uint8_t* buf = realloc(s->cont, block_len ? block_len : 1);
        if (buf == NULL) return h2_conn_error(s, H2_ERR_INTERNAL_ERROR);

        memcpy(buf, block, block_len);
        s->cont = buf;
        s->cont_len = block_len;
        s->cont_stream_id = frame->stream_id;
        s->cont_end_stream = end_stream;
        s->cont_active = 1;
        s->cont_frames = 1; /* this HEADERS counts towards the block's frame budget */

        return H2_FRAME_OK;
    }

    return h2_on_header_block(s, frame->stream_id, block, block_len, end_stream);
}

static h2_frame_result_e h2_on_continuation(h2session_t* s, const h2_frame_t* frame) {
    if (!s->cont_active || frame->stream_id != s->cont_stream_id)
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    if (s->cont_len + frame->payload_len > h2_header_block_cap())
        return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

    /* The byte limit above bounds memory, not work: an empty CONTINUATION adds
     * nothing to cont_len, so without a frame count the peer can keep this loop
     * running for as long as it likes (docs/http2/08, phase A.3). */
    if (h2_max_continuation_frames != 0 && ++s->cont_frames > h2_max_continuation_frames) {
        metrics_h2_abuse(METRICS_H2_CONT_FLOOD);
        log_error("h2: CONTINUATION flood on stream %u (fd %d)\n",
                  frame->stream_id, s->connection->fd);
        return h2_conn_error(s, H2_ERR_ENHANCE_YOUR_CALM);
    }

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
    /* Debit before anything else: the peer spent connection window the moment it
     * sent the frame, whatever we then decide to do with the payload. Overrunning
     * the connection window is a connection error (§6.9.1) — there is no way to
     * resynchronise a window the peer is not tracking. */
    if (!h2_recv_debit(&s->recv, frame->payload_len)) {
        metrics_h2_abuse(METRICS_H2_FLOW_CONN);
        log_error("h2: connection receive window overrun by %ld bytes (fd %d)\n",
                  (long)-s->recv.avail, s->connection->fd);
        return h2_conn_error(s, H2_ERR_FLOW_CONTROL_ERROR);
    }

    /* Credit the connection window back regardless of what happens to the
     * payload: the peer counted it against our window either way. */
    h2_recv_credit(s, 0, &s->recv, frame->payload_len);

    /* A DATA frame with no payload spends no window at all, so flow control —
     * the thing that bounds every other DATA frame — does not bound this one
     * (CVE-2019-9518). With END_STREAM it is meaningful: that is how a request
     * with no body ends. Without it, it is nine bytes of nothing. */
    if (frame->payload_len == 0 && !(frame->flags & H2_FLAG_END_STREAM) &&
        !h2_ctrl_budget_spend(s))
        return h2_ctrl_flood(s, "empty DATA");

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

    /* Same debit on the stream's own window. Only the stream dies here: the
     * connection window is still consistent, so the rest of it carries on. */
    if (!h2_recv_debit(&stream->recv, frame->payload_len)) {
        metrics_h2_abuse(METRICS_H2_FLOW_STREAM);
        return h2_stream_error(s, stream->id, H2_ERR_FLOW_CONTROL_ERROR);
    }

    h2_recv_credit(s, stream->id, &stream->recv, frame->payload_len);

    /* A tunnel: this DATA is not a request body, it is WebSocket frames
     * (RFC 8441). The payload buffer is the frame parser's own and is writable,
     * which the WebSocket parser needs — it unmasks in place, exactly as it
     * does with connection->buffer on the HTTP/1.1 path. */
    if (stream->ws != NULL) {
        if (!h2_ws_tunnel_feed(stream->ws, s->connection, (uint8_t*)data, data_len))
            return h2_stream_error(s, stream->id, H2_ERR_PROTOCOL_ERROR);

        if (frame->flags & H2_FLAG_END_STREAM) stream->state = H2_STREAM_HALF_CLOSED_REMOTE;

        return H2_FRAME_OK;
    }

    /* Answered already (431 from the header-list limit): the body is credited
     * like any other, then dropped. The peer could not have known. */
    if (stream->rejected) {
        if (frame->flags & H2_FLAG_END_STREAM) stream->state = H2_STREAM_HALF_CLOSED_REMOTE;
        return H2_FRAME_OK;
    }

    if (!h2_body_append(stream, data, data_len))
        return h2_stream_error(s, stream->id, H2_ERR_INTERNAL_ERROR);

    if (!(frame->flags & H2_FLAG_END_STREAM)) return H2_FRAME_OK;

    return h2_dispatch(s, stream);
}

static h2_frame_result_e h2_handle_frame(h2session_t* s, const h2_frame_t* frame) {
    /* §3.4: the client preface is the magic *followed by a SETTINGS frame*, and
     * an invalid preface is a connection error. The frame parser has consumed
     * the magic by now; this is the other half of the rule, which used to be
     * missing entirely — any frame at all was accepted first (docs/http2/10,
     * S.1). An ACK does not count: the preface SETTINGS is the peer's own, not
     * an acknowledgement of ours. */
    if (!s->peer_settings_seen) {
        if (frame->type != H2_FRAME_SETTINGS || (frame->flags & H2_FLAG_ACK))
            return h2_conn_error(s, H2_ERR_PROTOCOL_ERROR);

        s->peer_settings_seen = 1;
    }

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
        /* Every PING obliges us to send one back, which is what makes a flood
         * of them worth anything to an attacker (docs/http2/10, R.2). */
        if (!h2_ctrl_budget_spend(s)) return h2_ctrl_flood(s, "PING");

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
        return h2_on_goaway(s, frame);

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
            /* §4.2: a frame-size error on a frame that could change the state of
             * the whole connection is a connection error — which every frame
             * this parser rejects is, since it never got far enough to be tied
             * to a stream. Only the code differs (docs/http2/08, phase C.1). */
            uint32_t err = H2_ERR_PROTOCOL_ERROR;
            if (st == H2PARSE_OOM) err = H2_ERR_INTERNAL_ERROR;
            else if (st == H2PARSE_FRAME_SIZE) err = H2_ERR_FRAME_SIZE_ERROR;

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

        /* Answers pile up here when the peer stops reading (docs/http2/10,
         * R.1): the socket buffer fills, h2_flush_out can place nothing, and
         * every frame it owes goes on growing s->out. Checked per frame rather
         * than inside h2_session_queue_frame so the peer gets the honest error
         * code and one counter — a failed queue is an allocation problem, this
         * is a behaviour problem.
         *
         * Only the read path needs the check. The frames the write path queues
         * for itself (trailers, early hints) are bounded by the stream table,
         * and it drains to the socket in the same pass. */
        if (h2_max_out_backlog != 0 && h2_out_pending(s) > h2_max_out_backlog) {
            metrics_h2_abuse(METRICS_H2_OUT_BACKLOG);
            log_error("h2: %zu bytes queued for a peer that is not reading (fd %d)\n",
                      h2_out_pending(s), s->connection->fd);
            result = h2_fail(s, H2_ERR_ENHANCE_YOUR_CALM);
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

/* This stream has something to put on the wire: a response a handler finished,
 * or WebSocket frames queued on its tunnel. */
static int h2_stream_writable(const h2stream_t* stream) {
    /* Reset by the peer: whatever is queued is owed to nobody. */
    if (atomic_load_explicit(&stream->cancelled, memory_order_acquire)) return 0;

    /* Informational responses go out while the handler is still working — that
     * is the entire point of 103, so they make a stream writable on their own. */
    if (stream->early_hints != NULL) return 1;

    if (atomic_load_explicit(&stream->response_ready, memory_order_acquire)) return 1;

    return stream->ws != NULL && h2_ws_tunnel_has_output(stream->ws);
}

/* A stream is waiting for the write path. */
static int h2_has_writable(const h2session_t* s) {
    for (const h2stream_t* stream = s->streams; stream != NULL; stream = stream->next)
        if (h2_stream_writable(stream)) return 1;

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
        atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
        return rearm(connection, MPXOUT | MPXRDHUP);
    }

    /* Nothing to write, but handlers dispatched from this very read are still
     * running, so the connection is parked on a one-shot read that this event
     * has just spent. Re-arm it, or the next TCP segment would wait for the
     * first response to be written — the whole point of phase E
     * (docs/concurrency/01 §6). A no-op when the connection is not parked: then
     * it is live on level-triggered MPXIN and needs nothing. */
    return connection_park_rearm(connection);
}

/* The read path owns its lock lifecycle (docs/concurrency/01 §4.2, phase C). The
 * recv and the session-buffer accumulate are worker-only — §2.1: the connection
 * belongs to this thread, and connection->buffer is the per-worker scratch used
 * one connection at a time — so they run without connection_s_lock. The lock is
 * taken only around h2_process_buffer (which mutates the stream table and
 * dispatches handlers) and around the final drain/re-arm.
 *
 * Why the lock still guards the parse: handler threads re-arm under it, and on
 * the rare OOM push-fallback one walks the table under it; connection_close_locked
 * detaches under it, so the re-arm's detached check cannot race control_del
 * (00 §4.6, bug #2). The parser is worker-only, but it is kept inside the lock
 * with the table work it does per frame — splitting per-frame would churn the
 * lock for no gain and is the race §8 warns about. Returns with the lock
 * released; every exit path does. */
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

        /* Parse + dispatch under the lock: the stream table is walked and
         * mutated here, and handlers are queued. */
        connection_s_lock(connection, LOCK_SITE_H2_READ);
        const int ok = h2_process_buffer(s);
        connection_s_unlock(connection);
        if (!ok) return 0;
    }

    /* Acks and window updates produced while parsing. */
    connection_s_lock(connection, LOCK_SITE_H2_READ);
    const int r = h2_drain_and_rearm(s, connection);
    connection_s_unlock(connection);
    return r;
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

/* One response has fully left the stream.
 *
 * For an ordinary stream that is the end of it. A tunnel stays: its 200 was
 * only the handshake, and the stream goes on carrying WebSocket frames. The
 * response is retired all the same — leaving it staged would make the next
 * write pass re-run the filter chain and send a second HEADERS block. */
static void h2_write_finished(h2session_t* s, h2stream_t* stream) {
    /* A tunnel whose CLOSE frame has left carried END_STREAM out with it, so
     * the stream really is finished — the ordinary teardown applies. */
    if (stream->ws == NULL || stream->end_stream_sent) {
        stream->state = H2_STREAM_CLOSED;
        h2_session_drop_stream(s, stream);
        return;
    }

    atomic_store_explicit(&stream->response_ready, 0, memory_order_release);

    if (stream->response != NULL) {
        httpresponse_free(stream->response);
        stream->response = NULL;
    }
}

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

    /* A tunnel past its handshake has no response staged — its output is
     * WebSocket frames, framed by the same DATA writer the filter chain uses
     * (docs/http2/09 §4.3). */
    if (stream->ws != NULL && stream->response == NULL) {
        switch (h2_ws_tunnel_write(s, stream)) {
        case H2_DATA_DRAINED: return H2_WRITE_DONE;
        case H2_DATA_YIELD:   return H2_WRITE_YIELD;
        case H2_DATA_WINDOW:  return H2_WRITE_WINDOW;
        case H2_DATA_SOCKET:  return H2_WRITE_SOCKET;
        default:              return H2_WRITE_FAILED;
        }
    }

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

    /* A tunnel's handshake response ends there: no trailing empty DATA, because
     * that would carry END_STREAM and close the half of the stream the tunnel
     * exists to keep open (docs/http2/09). */
    if (stream->ws != NULL) return H2_WRITE_DONE;

    /* Trailing fields (RFC 9113 §8.1) close the stream instead of the empty
     * DATA frame below — docs/http2/08, phase E.1. */
    if (!stream->end_stream_sent && stream->response != NULL &&
        stream->response->trailer_ != NULL) {
        if (!h2_write_filter_trailers(s, stream, stream->response))
            return H2_WRITE_FAILED;

        return H2_WRITE_DONE;
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

/* Publish one ready response to its stream. Runs in the worker's single-threaded
 * write context — the drain — or the OOM fallback, both under connection_s_lock.
 * This is the work the handler used to do under the lock (docs/concurrency/01
 * §2.3): the stream-table walk and the cancelled/liveness check moved here, so a
 * handler thread no longer touches session internals.
 *
 * The response is still owned by its stream (h2_server_attach_response bound
 * it). On the cancelled/missing-stream paths the stream's own teardown (or this
 * drop) frees it; otherwise it stays with the stream until the write path drops
 * it after END_STREAM. */
static void h2_publish_one(h2session_t* s, httpresponse_t* response) {
    h2stream_t* stream = h2stream_find_by_response(s, response);
    if (stream == NULL) {
        /* The stream went away before its response was drained and nothing else
         * owns it now. */
        httpresponse_free(response);
        return;
    }

    /* handler_pending was set at dispatch and kept set through the push so that
     * a RST_STREAM arriving meanwhile could only mark the stream cancelled, not
     * free it out from under the queued response. Clearing it here is what
     * finally makes the stream eligible for destruction. */
    atomic_store_explicit(&stream->handler_pending, 0, memory_order_release);

    if (atomic_load_explicit(&stream->cancelled, memory_order_acquire)) {
        h2_session_drop_stream(s, stream);
        return;
    }

    /* Release-store so the write path, which loads this with acquire, cannot
     * observe the flag before the response body and headers the handler wrote. */
    atomic_store_explicit(&stream->response_ready, 1, memory_order_release);
}

/* Worker drains the publish queue at the start of every write pass. The worker
 * already holds connection_s_lock (h2_server_guard_write); the queue's own lock
 * only keeps the list consistent, in the connection_s_lock -> cqueue order the
 * WebSocket path already uses. */
static void h2_publish_drain(h2session_t* s) {
    if (s->publish_queue == NULL) return;

    cqueue_lock(s->publish_queue);
    void* response;
    while ((response = cqueue_pop(s->publish_queue)) != NULL)
        h2_publish_one(s, response);
    cqueue_unlock(s->publish_queue);
}

static int h2_write(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = ctx->parser;

    /* Bring any responses handlers pushed since the last turn onto their streams
     * before walking them: the write loop below consumes response_ready, which
     * the drain sets. (docs/concurrency/01 §4.1, phase B) */
    h2_publish_drain(s);

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

    /* Informational responses first, and outside the per-stream turn: a 103 is
     * a queued block, not a scheduled body, and it has to precede the final
     * HEADERS of its own stream (docs/http2/08, phase E.2). */
    for (h2stream_t* st = s->streams; st != NULL; st = st->next) {
        if (st->early_hints == NULL) continue;

        http_header_t* fields = st->early_hints;
        st->early_hints = NULL;
        st->last_early_hint = NULL;

        if (!st->response_headers_sent)
            (void)h2_write_filter_early_hints(s, st, fields);

        http_headers_free(fields);
    }

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
            atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
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
            h2_write_finished(s, stream);
            break;
        }
    }

    /* Then serve every other stream whose handler has come back, in table order
     * — which is round-robin order, since a stream that stops short goes to the
     * back. Each gets at most one quantum per turn. */
    h2stream_t* stream = s->streams;
    while (stream != NULL) {
        h2stream_t* next = stream->next;

        if (stream->served || !h2_stream_writable(stream)) {
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

        h2_write_finished(s, stream);

        stream = next;
    }

    if (h2_flush_out(s) == 0) return 0;

    if (socket_full || s->out_len > s->out_pos) {
        atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
        return rearm(connection, MPXOUT | MPXRDHUP);
    }

    /* Somebody spent their quantum with body left over: the socket still has
     * room, so come straight back for the next round. */
    if (yielded) {
        atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
        return rearm(connection, MPXOUT | MPXRDHUP);
    }

    /* Every stream that could make progress has; the rest wait on a
     * WINDOW_UPDATE, which arrives on the read path. */
    if (window_stalled) {
        atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
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

/* Handler thread: push the finished response onto the session's publish queue,
 * wake the worker, and re-arm. The stream-table walk is NOT done here — it runs
 * in the worker's drain (h2_publish_drain), so the handler never touches session
 * internals under the connection lock (docs/concurrency/01 §4.1, §2.3). The push
 * uses only the queue's own short lock; connection_s_lock is taken for the re-arm
 * alone. handler_pending is left set until the drain, which keeps the owning
 * stream (and the response this entry points at) alive across the handoff. */
static int h2_publish_push(h2session_t* s, httpresponse_t* response) {
    cqueue_lock(s->publish_queue);
    const int ok = cqueue_append(s->publish_queue, response);
    cqueue_unlock(s->publish_queue);
    return ok;
}

int h2_server_response_ready(connection_t* connection, httpresponse_t* response) {
    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = h2_session_of(connection);
    if (s == NULL) {
        httpresponse_free(response);
        return connection_after_read(connection);
    }

    if (!h2_publish_push(s, response)) {
        /* Queue-item allocation failed (OOM): publish inline rather than strand
         * the response. The caller does not hold connection_s_lock for h2 (see
         * __publish_response), and h2_publish_one mutates the stream table, so
         * take the lock here — this is exactly the old under-lock path. */
        connection_s_lock(connection, LOCK_SITE_H2_PUBLISH);
        h2_publish_one(s, response);
        connection_s_unlock(connection);
    }

    atomic_store_explicit(&ctx->need_write, 1, memory_order_release);

    /* The only thing that stays under connection_s_lock: the re-arm. It reads
     * ctx->detached, which connection_close_locked sets under the same lock, so
     * the test cannot go stale against epoll_ctl (00 §4.6, bug #2). */
    connection_s_lock(connection, LOCK_SITE_H2_REARM);
    const int r = connection_after_read(connection);
    connection_s_unlock(connection);

    return r;
}

int h2_server_publish_inline(connection_t* connection, httpresponse_t* response) {
    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = h2_session_of(connection);
    if (s == NULL) {
        httpresponse_free(response);
        return 1;
    }

    /* The worker is on the read path, holding connection_s_lock and sole owner
     * of the stream table, so skip the queue and publish straight to the stream.
     * No re-arm here: h2_drain_and_rearm at the end of h2_read sees the stream
     * become writable (h2_has_writable) and arms EPOLLOUT itself. */
    h2_publish_one(s, response);
    atomic_store_explicit(&ctx->need_write, 1, memory_order_release);

    return 1;
}

/* ======================================================================= *
 *  Guards + lifecycle
 * ======================================================================= */

int h2_server_guard_read(connection_t* connection) {
    /* h2_read manages connection_s_lock itself (phase C): the recv and buffer
     * work run lock-free, the lock is taken only around parsing and the re-arm. */
    return h2_read(connection);
}

int h2_server_guard_write(connection_t* connection) {
    if (connection == NULL) return 0;

    connection_s_lock(connection, LOCK_SITE_H2_WRITE);
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

int h2_server_early_hints(connection_t* connection, httpresponse_t* response,
                          http_header_t* fields) {
    if (connection == NULL || fields == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;
    h2session_t* s = h2_session_of(connection);
    if (s == NULL) return 0;

    /* The stream table belongs to the worker, so this walk is under the lock —
     * the same slow path h2_server_publish_inline takes. Early hints happen
     * once or twice per request, not per byte, so a lock here costs nothing
     * worth avoiding. */
    connection_s_lock(connection, LOCK_SITE_H2_PUBLISH);

    int ok = 0;
    h2stream_t* stream = h2stream_find_by_response(s, response);

    if (stream != NULL && !stream->response_headers_sent) {
        http_header_t* last = fields;
        while (last->next != NULL) last = last->next;

        if (stream->early_hints == NULL)
            stream->early_hints = fields;
        else
            stream->last_early_hint->next = fields;

        stream->last_early_hint = last;
        ok = 1;

        atomic_store_explicit(&ctx->need_write, 1, memory_order_release);
        connection_after_read(connection);
    }
    else if (stream != NULL) {
        log_error("h2: early hints after the response has started on stream %u — dropped\n",
                  stream->id);
    }

    connection_s_unlock(connection);

    return ok;
}

void h2_server_stream_release(connection_t* connection, h2stream_t* stream) {
    h2session_t* s = h2_session_of(connection);
    if (s == NULL || stream == NULL) return;

    /* handler_pending is already clear, so this really frees. */
    h2_session_drop_stream(s, stream);
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

    /* The peer said it is going away (§6.8) and we kept the connection up to
     * finish what it had already asked for. Close as soon as that is done — the
     * same drain as shutdown, reached from the other side. Nothing forces this
     * to complete: a peer that stops reading leaves a response undrainable, and
     * the idle timeout below is what eventually reaps that. */
    if (s->draining && s->peer_goaway && s->stream_count == 0) {
        h2_graceful_close_locked(s);
        return;
    }

    /* SETTINGS_TIMEOUT (§6.5.3) — docs/http2/08, phase C.4. Our SETTINGS is the
     * first frame of the server preface, and every one of them (window sizes,
     * concurrency, header list limit) only takes effect once the peer applies
     * it. A peer that never acks is not speaking HTTP/2 at us in any useful
     * sense, and until this check it could sit there until the idle timeout. */
    if (h2_settings_ack_timeout_sec != 0 && s->settings_sent_ms != 0 &&
        now - s->settings_sent_ms >= (uint64_t)h2_settings_ack_timeout_sec * 1000u) {
        log_error("h2: no SETTINGS ACK in %us (fd %d)\n",
                  h2_settings_ack_timeout_sec, connection->fd);
        h2_queue_goaway(s, H2_ERR_SETTINGS_TIMEOUT);
        (void)h2_flush_out(s);
        connection_close_locked(connection);
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
    const uint32_t header_list = (uint32_t)h2_max_header_list_size;
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
        /* §6.5.2: what a client is told here it can keep to, and a client that
         * does gets a 200 where it would otherwise have collected a 431. */
        0x00, H2_SETTINGS_MAX_HEADER_LIST_SIZE,
            (uint8_t)((header_list >> 24) & 0xff),
            (uint8_t)((header_list >> 16) & 0xff),
            (uint8_t)((header_list >> 8) & 0xff),
            (uint8_t)(header_list & 0xff),
        /* RFC 8441: WebSocket over HTTP/2 is available here. This is the last
         * thing the feature needed and deliberately the last thing added: a
         * browser that sees it stops opening a separate HTTP/1.1 connection for
         * wss:// and starts sending extended CONNECT instead. Advertising it
         * before the tunnel worked would have broken every such client
         * (docs/http2/09 §2). */
        0x00, H2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 0x00, 0x00, 0x00, 0x01,
        /* RFC 9218 §2.1: this server ignores RFC 7540 priority signals, which
         * RFC 9113 §5.3 deprecated. Saying so lets a client stop sending
         * PRIORITY frames and priority fields it will get nothing for; it is a
         * statement of fact, not a claim to implement RFC 9218 scheduling. */
        0x00, H2_SETTINGS_NO_RFC7540_PRIORITIES, 0x00, 0x00, 0x00, 0x01,
    };

    /* With the header-list limit disabled that setting is left out entirely —
     * advertising 0 would announce that no header at all is acceptable. It sits
     * before ENABLE_CONNECT_PROTOCOL in the block, so dropping it means moving
     * the tail up rather than shortening the frame. */
    uint8_t block[sizeof(settings)];
    size_t len = 0;

    if (h2_max_header_list_size == 0) {
        /* The header-list setting sits before the last two, so dropping it
         * means moving that tail up rather than shortening the frame. */
        memcpy(block, settings, sizeof(settings) - 18);
        memcpy(block + sizeof(settings) - 18, settings + sizeof(settings) - 12, 12);
        len = sizeof(settings) - 6;
    }
    else {
        memcpy(block, settings, sizeof(settings));
        len = sizeof(settings);
    }

    if (!h2_session_queue_frame(s, H2_FRAME_SETTINGS, 0, 0, block, len))
        return 0;

    /* Start the §6.5.3 clock. Timed from here rather than from the flush: the
     * frame is the first thing in the outbound buffer, and a socket that cannot
     * take nine bytes is a problem of its own. */
    s->settings_sent_ms = h2_now_ms();

    /* SETTINGS_INITIAL_WINDOW_SIZE governs streams only (§6.9.2); the
     * connection window moves by WINDOW_UPDATE alone. */
    if (h2_recv_window_initial > H2_DEFAULT_WINDOW)
        h2_queue_window_update(s, 0, &s->recv, (uint32_t)(h2_recv_window_initial - H2_DEFAULT_WINDOW));

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

    h2session_t* s = calloc(1, sizeof(*s));
    if (s == NULL) return NULL;

    s->free = h2_session_free;
    s->connection = connection;
    s->read_cap = 16384;
    s->read_buf = malloc(s->read_cap);
    s->decoder = hpack_decoder_create(4096);
    s->encoder = hpack_encoder_create(4096);
    s->publish_queue = cqueue_create();
    if (s->read_buf == NULL || s->decoder == NULL || s->encoder == NULL || s->publish_queue == NULL) {
        h2_session_free(s);
        return NULL;
    }

    h2frame_parser_init(&s->frame, 1, H2_MAX_FRAME_SIZE_DEFAULT); /* expect the client preface */
    s->peer_max_frame_size = H2_MAX_FRAME_SIZE_DEFAULT;
    s->peer_initial_window = H2_DEFAULT_WINDOW;
    s->peer_header_table_size = 4096;
    s->send_window = H2_DEFAULT_WINDOW;
    s->recv.size = h2_recv_window_initial;
    /* The connection window starts at the protocol default whatever we intend to
     * grow it to: SETTINGS cannot set it (§6.9.2), only the WINDOW_UPDATE that
     * h2_send_preface queues below, which credits avail as it goes. */
    s->recv.avail = H2_DEFAULT_WINDOW;
    s->recv.epoch_ms = h2_now_ms();
    s->stream_recv_learned = h2_recv_window_initial;
    s->error_code = H2_ERR_PROTOCOL_ERROR;
    s->last_activity_ms = h2_now_ms();
    s->abort_tokens = h2_abort_burst * 1000;
    s->abort_epoch_ms = s->last_activity_ms;
    s->ctrl_tokens = h2_ctrl_burst * 1000;
    s->ctrl_epoch_ms = s->last_activity_ms;

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

    /* The publish queue holds response pointers the streams above already
     * owned and freed, so free only the queue wrappers — never the data. */
    cqueue_free(s->publish_queue);

    free(s->read_buf);
    free(s->cont);
    free(s->out);
    if (s->decoder != NULL) hpack_decoder_free(s->decoder);
    if (s->encoder != NULL) hpack_encoder_free(s->encoder);
    h2frame_parser_free(&s->frame);

    free(s);
}

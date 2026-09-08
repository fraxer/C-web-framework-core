#define _GNU_SOURCE

#include "accesslog.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "appconfig.h"
#include "connection_s.h"
#include "multiplexing.h"
#include "route.h"

/* Nothing here allocates: the record is built in a stack buffer and appended to
 * this worker's batch. A response is on the hot path by definition, and an
 * access log that mallocs per request is one that gets switched off. */
#define ACCESS_LOG_BUF 4096

/* local7. The facility that separates these records from the event log; see
 * accesslog.h for why they are separated at all. */
#define ACCESS_LOG_FACILITY LOG_LOCAL7

/* Records are delivered a batch at a time, one syslog(3) call per batch.
 *
 * Not a micro-optimisation. journald charges per *entry*, not per byte, and one
 * call per response cost 4.3 us -- a quarter of this server's throughput on a
 * static benchmark (159.6k -> 121.6k requests/s, and half of it on a rig that
 * was answering faster). The same records handed over ~60 at a time cost about
 * 60 ns each, because the expensive part happens once for the batch. Measured
 * on the same machine:
 *
 *     1 record  per syslog(3) call:  4234 ns/record
 *     4 records per call:             772 ns/record
 *    16 records per call:             210 ns/record
 *    64 records per call:              58 ns/record
 *
 * Batching the *syscalls* instead does not help -- sendmmsg() with 64 messages
 * still costs 3417 ns per record, because what is expensive is journald taking
 * an entry, not the process making a call. Fewer, larger entries is the only
 * lever there is short of abandoning syslog for a file, which would mean owning
 * log rotation (docs/webserver/00 §3).
 *
 * What a batch looks like from outside: one journal entry holding several
 * newline-separated lines. `journalctl -o cat` -- what an analyser is fed --
 * prints them as the separate lines they are, and the default view indents the
 * continuations. Every record carries its own timestamp, so nothing about a
 * record depends on which batch carried it; only the interleaving of records
 * from *different* workers becomes batch-grained, which is the same property
 * nginx's per-worker buffers have.
 *
 * One per worker, which is what makes it lock-free: http_access_log() runs on
 * the worker that owns the connection -- every protocol's write path does, by
 * connection.h's write invariant -- and so does the flush.
 *
 * 8 KB is chosen to stay a comfortable datagram: journald swallows far more,
 * but a batch is one message and there is no reason to find the limit. */
#define ACCESS_LOG_BATCH 8192

/* Length of the Common Log Format timestamp, `[10/Oct/2026:13:55:36 +0300]`:
 * "[" 1 + day 2 + "/" 1 + month 3 + "/" 1 + year 4 + ":" 1 + hh 2 + ":" 1 +
 * mm 2 + ":" 1 + ss 2 + " " 1 + sign 1 + offset 4 + "]" 1. __build_stamp writes
 * exactly this many bytes and no terminator, so a field added there needs this
 * number changed with it. */
#define ACCESS_LOG_STAMP 28

/* The timestamp every record of one second shares; see __put_time. Its own
 * struct because a record with no worker behind it still needs one, and a
 * stack copy of this is forty bytes where a whole accesslog_t is eight KB. */
typedef struct {
    time_t second;
    size_t length;
    char text[ACCESS_LOG_STAMP];
} accesslog_stamp_t;

struct accesslog {
    char batch[ACCESS_LOG_BATCH];
    size_t batch_length;
    accesslog_stamp_t stamp;
};

accesslog_t* http_access_log_create(void) {
    accesslog_t* log = malloc(sizeof * log);
    if (log == NULL) return NULL;

    log->batch_length = 0;
    log->stamp.second = 0;
    log->stamp.length = 0;

    return log;
}

void http_access_log_free(accesslog_t* log) {
    free(log);
}

/* The staging area of the worker that owns this response.
 *
 * NULL is a legitimate answer, not a failure: a response built without a
 * connection (the HTTP client, the tests) or on a connection with no listener
 * behind it has no worker, and the caller delivers such a record directly. */
static accesslog_t* __log_of(const httpresponse_t* response) {
    const connection_t* connection = response->connection;
    if (connection == NULL) return NULL;

    const connection_server_ctx_t* ctx = connection->ctx;
    if (ctx == NULL || ctx->listener == NULL || ctx->listener->api == NULL)
        return NULL;

    return ctx->listener->api->access_log;
}

typedef struct {
    char* data;
    size_t capacity;
    size_t pos;
} accesslog_buf_t;

static void __put(accesslog_buf_t* buf, const char* data, size_t length) {
    if (data == NULL || length == 0) return;

    /* Truncation, not failure: a record cut short still names the request, and
     * the alternative is dropping it over an outsized User-Agent. One byte is
     * always kept back for the terminator. */
    const size_t left = buf->capacity - 1 - buf->pos;
    if (length > left) length = left;

    memcpy(buf->data + buf->pos, data, length);
    buf->pos += length;
}

static void __putc(accesslog_buf_t* buf, char c) {
    __put(buf, &c, 1);
}

static void __putz(accesslog_buf_t* buf, const char* string) {
    __put(buf, string, string != NULL ? strlen(string) : 0);
}

static void __putu(accesslog_buf_t* buf, uint64_t value) {
    char digits[24];
    size_t pos = sizeof(digits);

    do { digits[--pos] = (char)('0' + (value % 10)); value /= 10; } while (value > 0);

    __put(buf, digits + pos, sizeof(digits) - pos);
}

/* Everything a client controls goes through here: the request target, Referer
 * and User-Agent are all written by the peer, and a peer that puts a quote or a
 * newline in one must not be able to add a line of its own to the log. The
 * escapes are the ones nginx uses, so the result reads the same to a tool that
 * already knows these logs. */
static int __needs_escape(unsigned char c) {
    return c == '"' || c == '\\' || c < 0x20 || c == 0x7f;
}

static void __pute(accesslog_buf_t* buf, const char* value, size_t length) {
    static const char hex[] = "0123456789abcdef";

    /* Copied in runs. Almost nothing a client sends needs escaping -- a URI is
     * percent-encoded and a User-Agent is printable ASCII -- so the common case
     * is one memcpy per field instead of a call per byte, and the escaping loop
     * only pays for the bytes that actually need it. */
    size_t plain = 0;
    for (size_t i = 0; i < length; i++) {
        const unsigned char c = (unsigned char)value[i];
        if (!__needs_escape(c)) continue;

        __put(buf, value + plain, i - plain);
        plain = i + 1;

        if (c == '"' || c == '\\') {
            __putc(buf, '\\');
            __putc(buf, (char)c);
        }
        else {
            __put(buf, "\\x", 2);
            __putc(buf, hex[c >> 4]);
            __putc(buf, hex[c & 0x0f]);
        }
    }

    __put(buf, value + plain, length - plain);
}

static void __putq(accesslog_buf_t* buf, const char* value, size_t length) {
    __putc(buf, '"');

    if (value == NULL)
        __putc(buf, '-');
    else
        __pute(buf, value, length);

    __putc(buf, '"');
}

/* The header if the client sent one, "-" quoted otherwise. */
static void __put_header(accesslog_buf_t* buf, httprequest_t* request, const char* name, size_t name_length) {
    const http_header_t* header = request != NULL ?
        request->get_headern(request, name, name_length) : NULL;

    if (header == NULL || header->value == NULL) {
        __put(buf, "\"-\"", 3);
        return;
    }

    __putq(buf, header->value, header->value_length);
}

/* `[10/Oct/2026:13:55:36 +0300]`, the Common Log Format timestamp.
 *
 * Cached per worker and rebuilt when the second turns. Not premature: with the
 * delivery batched, building this was practically the whole cost of a record --
 * snprintf and localtime_r together came to about 7% of the worker on a static
 * benchmark, against 0.4% for actually handing the records to syslog. Every
 * record inside one second carries the same 28 bytes, so all but the first are
 * a memcpy. nginx caches its log time for the same reason.
 *
 * Built by hand rather than with strftime for a second reason: %b is
 * locale-dependent, and a server started under a Russian locale would write
 * month names no log analyser recognises. */
static char* __put2(char* out, unsigned value) {
    out[0] = (char)('0' + (value / 10) % 10);
    out[1] = (char)('0' + value % 10);

    return out + 2;
}

static void __build_stamp(accesslog_stamp_t* stamp, time_t second) {
    static const char months[12][3] = {
        {'J','a','n'}, {'F','e','b'}, {'M','a','r'}, {'A','p','r'},
        {'M','a','y'}, {'J','u','n'}, {'J','u','l'}, {'A','u','g'},
        {'S','e','p'}, {'O','c','t'}, {'N','o','v'}, {'D','e','c'}
    };

    struct tm tm;
    if (localtime_r(&second, &tm) == NULL) {
        stamp->length = 0;
        return;
    }

    long offset = tm.tm_gmtoff;
    const char sign = offset < 0 ? '-' : '+';
    if (offset < 0) offset = -offset;

    const unsigned year = (unsigned)(tm.tm_year + 1900);

    char* out = stamp->text;
    *out++ = '[';
    out = __put2(out, (unsigned)tm.tm_mday);
    *out++ = '/';
    memcpy(out, months[tm.tm_mon % 12], 3); out += 3;
    *out++ = '/';
    out = __put2(out, year / 100);
    out = __put2(out, year % 100);
    *out++ = ':';
    out = __put2(out, (unsigned)tm.tm_hour);
    *out++ = ':';
    out = __put2(out, (unsigned)tm.tm_min);
    *out++ = ':';
    out = __put2(out, (unsigned)tm.tm_sec);
    *out++ = ' ';
    *out++ = sign;
    out = __put2(out, (unsigned)(offset / 3600));
    out = __put2(out, (unsigned)((offset % 3600) / 60));
    *out++ = ']';

    stamp->length = (size_t)(out - stamp->text);
    stamp->second = second;
}

static void __put_time(accesslog_buf_t* buf, accesslog_stamp_t* stamp) {
    const time_t now = time(NULL);

    if (now != stamp->second || stamp->length == 0)
        __build_stamp(stamp, now);

    if (stamp->length == 0) {
        __putc(buf, '-');
        return;
    }

    __put(buf, stamp->text, stamp->length);
}

static const char* __method_name(int method) {
    switch (method) {
    case ROUTE_GET:     return "GET";
    case ROUTE_POST:    return "POST";
    case ROUTE_PUT:     return "PUT";
    case ROUTE_DELETE:  return "DELETE";
    case ROUTE_OPTIONS: return "OPTIONS";
    case ROUTE_PATCH:   return "PATCH";
    case ROUTE_HEAD:    return "HEAD";
    default:            return "-";
    }
}

/* Which protocol answered. HTTP/2 and HTTP/3 leave `request->version` at the
 * HTTP/1.1 value their builders set for the rest of the server, so the version
 * on the wire is the connection's, not the request's. */
static const char* __protocol_name(const connection_t* connection, const httprequest_t* request) {
    if (connection != NULL) {
        const connection_server_ctx_t* ctx = connection->ctx;

        if (ctx != NULL && ctx->is_http2) return "HTTP/2";
        if (connection->transport == CONN_TRANSPORT_QUIC) return "HTTP/3";
    }

    if (request != NULL && request->version == HTTP1_VER_1_0) return "HTTP/1.0";

    return "HTTP/1.1";
}

/* Seconds with milliseconds, the shape of nginx's $request_time. Measured from
 * the moment the response object was taken for this request, so it is the time
 * the server spent producing and writing the answer -- not the time spent
 * waiting for the client to finish sending one. */
static void __put_duration(accesslog_buf_t* buf, const struct timespec* started) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        __putc(buf, '-');
        return;
    }

    int64_t ms = (int64_t)(now.tv_sec - started->tv_sec) * 1000 +
                 (now.tv_nsec - started->tv_nsec) / 1000000;
    if (ms < 0) ms = 0;

    __putu(buf, (uint64_t)(ms / 1000));
    __putc(buf, '.');

    const uint64_t rest = (uint64_t)(ms % 1000);
    __putc(buf, (char)('0' + (rest / 100)));
    __putc(buf, (char)('0' + ((rest / 10) % 10)));
    __putc(buf, (char)('0' + (rest % 10)));
}

void http_access_log_start(httpresponse_t* response, const server_t* server) {
    if (response == NULL) return;

    response->access_log = 0;

    if (server == NULL || server->config == NULL) return;
    if (!server->config->env.main.log.access) return;

    /* The flag is read once, here, and carried on the response: the write path
     * that emits the record then tests one bit instead of walking back to the
     * configuration on a thread that may not be holding it. */
    response->access_log = 1;

    if (clock_gettime(CLOCK_MONOTONIC, &response->access_started) != 0) {
        response->access_started.tv_sec = 0;
        response->access_started.tv_nsec = 0;
    }
}

void http_access_log_keep_uri(httpresponse_t* response, const char* uri, size_t length) {
    if (response == NULL || !response->access_log) return;
    if (response->access_uri != NULL) return;
    if (uri == NULL || length == 0) return;

    char* copy = malloc(length + 1);
    if (copy == NULL) return;

    memcpy(copy, uri, length);
    copy[length] = 0;

    response->access_uri = copy;
    response->access_uri_length = length;
}

/* One journal entry, however many records it carries. */
static void __deliver(const char* data) {
    syslog(ACCESS_LOG_FACILITY | LOG_INFO, "%s", data);
}

void http_access_log_flush(accesslog_t* log) {
    if (log == NULL || log->batch_length == 0) return;

    log->batch[log->batch_length] = 0;
    log->batch_length = 0;

    __deliver(log->batch);
}

/* Append one finished record to this worker's batch, delivering what is already
 * there if the record would not fit. The reserve is two bytes: the separator
 * this record needs and the terminator the flush writes. A record can never be
 * larger than the batch -- ACCESS_LOG_BUF is half of it -- so the flush always
 * makes room.
 *
 * Without a worker there is nothing to batch into, and the record goes on its
 * own. That is the slow path by construction and it is meant to be: it exists
 * so such a record is delivered rather than dropped, not to be taken often. */
static void __stage(accesslog_t* log, char* record, size_t length) {
    if (log == NULL) {
        record[length] = 0;
        __deliver(record);
        return;
    }

    if (log->batch_length + length + 2 > sizeof(log->batch))
        http_access_log_flush(log);

    if (log->batch_length > 0)
        log->batch[log->batch_length++] = '\n';

    memcpy(log->batch + log->batch_length, record, length);
    log->batch_length += length;
}

void http_access_log(httprequest_t* request, httpresponse_t* response) {
    /* Nothing is formatted, and no clock is read, before this test. */
    if (response == NULL || !response->access_log) return;

    /* Once per response. The h1.1 write path can be re-entered after an EAGAIN,
     * and a retried flush must not produce a second record. */
    response->access_log = 0;

    char data[ACCESS_LOG_BUF];
    accesslog_buf_t buf = { .data = data, .capacity = sizeof(data), .pos = 0 };

    /* The worker that owns this connection, or NULL for a response with no
     * worker behind it -- __stage delivers that one on its own. */
    accesslog_t* log = __log_of(response);

    /* A record without a worker has nowhere to cache the second's timestamp;
     * it builds its own, which lives no longer than this call. */
    accesslog_stamp_t stamp_scratch = { .second = 0, .length = 0 };

    const connection_t* connection = response->connection;

    /* %v -- the authority this request was addressed to. Every protocol stores
     * it as a "Host" field (h2 and h3 fold :authority into one), so there is one
     * place to read it from. */
    const http_header_t* host = request != NULL ? request->get_headern(request, "Host", 4) : NULL;
    if (host != NULL && host->value != NULL && host->value_length > 0)
        __pute(&buf, host->value, host->value_length);
    else
        __putc(&buf, '-');

    __putc(&buf, ' ');

    /* %h -- the peer. %l and %u follow it as "- -": there is no identd and no
     * HTTP authentication in the core, and the two placeholders are what keeps
     * the record parseable by tools that expect the common format. */
    char address[IPADDR_STRLEN];
    __putz(&buf, connection != NULL ? ipaddr_text(&connection->remote_ip, address, sizeof(address)) : "-");

    __put(&buf, " - - ", 5);

    __put_time(&buf, log != NULL ? &log->stamp : &stamp_scratch);

    /* "%r" -- the request line, with the target exactly as it arrived: `uri`
     * and not `path`, so the query string is in the record. */
    __putc(&buf, ' ');
    __putc(&buf, '"');
    __putz(&buf, __method_name(request != NULL ? (int)request->method : ROUTE_NONE));
    __putc(&buf, ' ');
    if (response->access_uri != NULL)
        __pute(&buf, response->access_uri, response->access_uri_length);
    else if (request != NULL && request->uri != NULL)
        __pute(&buf, request->uri, request->uri_length);
    else
        __putc(&buf, '-');
    __putc(&buf, ' ');
    __putz(&buf, __protocol_name(connection, request));
    __putc(&buf, '"');

    __putc(&buf, ' ');
    __putu(&buf, (uint64_t)(response->status_code > 0 ? response->status_code : 0));

    /* %b -- body bytes, counted by the terminal write stage of each protocol,
     * so this is what gzip and Range actually left on the wire. */
    __putc(&buf, ' ');
    __putu(&buf, (uint64_t)response->body_bytes_sent);

    __putc(&buf, ' ');
    __put_header(&buf, request, "Referer", 7);

    __putc(&buf, ' ');
    __put_header(&buf, request, "User-Agent", 10);

    __putc(&buf, ' ');
    __put_duration(&buf, &response->access_started);

    __stage(log, buf.data, buf.pos);
}

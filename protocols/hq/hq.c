#include "hq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connection_s.h"
#include "log.h"
#include "quicconn.h"
#include "quicstream.h"
#include "server.h"

/* A request line is `GET <path>\r\n` and the runner's paths are short slugs. The
 * cap is what stops a peer from making us buffer while it never sends a newline:
 * past it the stream is answered with nothing and closed. */
#define HQ_REQUEST_MAX 512

/* One read from a stream, and one read from the file being served. The second
 * doubles as the largest chunk handed to the send buffer in a single turn --
 * the write-ahead budget below bounds how many of those a turn may do. */
#define HQ_CHUNK 16384

typedef struct hq_stream {
    /* The request line, until it is complete. */
    char     request[HQ_REQUEST_MAX];
    size_t   request_len;

    /* The file being sent, once the line has been understood. NULL before that,
     * and also after a request we refused -- refusing in HTTP/0.9 means sending
     * nothing at all, because there is no way to say anything else. */
    FILE*    file;

    /* Bytes handed to the send buffer. Only for the log line that tells "we
     * never wrote it" apart from "we wrote it and the transport did not get it
     * there" -- which is the whole question when a transfer stalls. */
    uint64_t sent;

    unsigned answered : 1;    /* the request line is dealt with, one way or another */
    unsigned finished : 1;    /* our side of the stream is closed */
} hq_stream_t;

static void __stream_free(void* p) {
    hq_stream_t* st = p;
    if (st == NULL) return;

    if (st->file != NULL) fclose(st->file);
    free(st);
}

/* The transport reaps a stream only when the layer above has let go of it. Ours
 * is done once the body has been written and the send side closed. */
static int __stream_done(void* p) {
    const hq_stream_t* st = p;
    if (st == NULL) return 1;

    return st->finished;
}

static hq_stream_t* __stream_of(quicstream_t* qs) {
    if (qs->app != NULL) return qs->app;

    hq_stream_t* st = calloc(1, sizeof * st);
    if (st == NULL) return NULL;

    qs->app = st;
    qs->app_free = __stream_free;
    qs->app_done = __stream_done;

    return st;
}

/* ---- The request line ---- */

/* Resolve `path` under the vhost root, refusing anything that could leave it.
 *
 * The runner only ever asks for a name it generated, so this is not the load
 * bearing part of the shim -- but a path check that exists only because the peer
 * is expected to behave is not a path check. `..` is refused outright rather
 * than resolved: there is no legitimate use for it here, and refusing beats
 * getting the resolution subtly wrong. */
static FILE* __open_under_root(const server_t* server, const char* path,
                               size_t path_len) {
    if (server == NULL || server->root == NULL) return NULL;
    if (path_len == 0 || path[0] != '/') return NULL;
    if (memchr(path, '\0', path_len) != NULL) return NULL;

    for (size_t i = 0; i + 1 < path_len; i++)
        if (path[i] == '.' && path[i + 1] == '.') return NULL;

    char full[1024];
    const int n = snprintf(full, sizeof full, "%.*s%.*s",
                           (int)server->root_length, server->root,
                           (int)path_len, path);
    if (n <= 0 || (size_t)n >= sizeof full) return NULL;

    return fopen(full, "rb");
}

/* Turn a complete request line into an open file, or into a refusal.
 *
 * Either way the stream is answered: HTTP/0.9 has no way to report a problem,
 * so a request for something that is not there is an empty body and a clean
 * end of stream -- which is exactly what the runner checks for when it expects
 * a transfer to fail. */
static void __answer(quicstream_t* qs, hq_stream_t* st, const server_t* server) {
    st->answered = 1;

    char* line = st->request;
    size_t len = st->request_len;

    /* Trim the terminator, whichever of the two the peer used. */
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) len--;

    static const char get[] = "GET ";
    if (len <= sizeof get - 1 || memcmp(line, get, sizeof get - 1) != 0) {
        log_info("hq: stream %llu: not a GET\n", (unsigned long long)qs->id);
        return;
    }

    const char* path = line + sizeof get - 1;
    const size_t path_len = len - (sizeof get - 1);

    st->file = __open_under_root(server, path, path_len);
    if (st->file == NULL) {
        log_info("hq: stream %llu: no such file \"%.*s\"\n",
                 (unsigned long long)qs->id, (int)path_len, path);
        return;
    }

    log_info("hq: stream %llu: GET \"%.*s\"\n",
             (unsigned long long)qs->id, (int)path_len, path);
}

/* Read what has arrived and, if the line is complete, answer it. */
static void __read(quicstream_t* qs, hq_stream_t* st, const server_t* server) {
    uint8_t buf[HQ_CHUNK];

    while (!st->answered) {
        const size_t n = quicstream_read(qs, buf, sizeof buf);
        if (n == 0) break;

        for (size_t i = 0; i < n && !st->answered; i++) {
            if (st->request_len < sizeof st->request)
                st->request[st->request_len++] = (char)buf[i];

            if (buf[i] == '\n') {
                __answer(qs, st, server);
                break;
            }

            /* A line longer than anything this protocol can carry. Answered
             * with nothing, so the peer is not left waiting. */
            if (st->request_len == sizeof st->request) {
                log_info("hq: stream %llu: request line too long\n",
                         (unsigned long long)qs->id);
                st->answered = 1;
            }
        }
    }

    /* The peer closed its side without a newline: whatever it sent is all there
     * will ever be, so it gets answered as it stands rather than hanging. */
    if (!st->answered && qs->recv_state == QUIC_RECV_DATA_READ)
        __answer(qs, st, server);
}

/* Push out as much of the body as the connection's write-ahead budget allows. */
static void __write(quicconn_t* conn, quicstream_t* qs, hq_stream_t* st) {
    if (!st->answered || st->finished) return;

    while (st->file != NULL) {
        const size_t room = quicconn_write_room(conn);
        if (room == 0) {
            log_info("hq: stream %llu: no write room at %llu bytes\n",
                     (unsigned long long)qs->id, (unsigned long long)st->sent);
            return;   /* asked for again next turn */
        }

        uint8_t buf[HQ_CHUNK];
        const size_t want = room < sizeof buf ? room : sizeof buf;
        const size_t n = fread(buf, 1, want, st->file);

        if (n > 0 && !quicstream_write(qs, buf, n)) return;
        st->sent += n;

        if (n < want) {
            fclose(st->file);
            st->file = NULL;
            break;
        }
    }

    quicstream_finish(qs);
    st->finished = 1;

    log_info("hq: stream %llu: handed %llu bytes to the transport\n",
             (unsigned long long)qs->id, (unsigned long long)st->sent);
}

/* ---- The turn ---- */

int hq_turn(quicconn_t* conn, uint64_t* error) {
    if (conn == NULL) return 1;
    if (error != NULL) *error = 0;

    const connection_server_ctx_t* ctx = conn->conn.ctx;
    const server_t* server = ctx != NULL ? ctx->server : NULL;

    /* Walking the list rather than a queue of ready streams: the runner opens a
     * handful, and a shim that needed its own scheduling would be a second
     * implementation of what h3conn already does properly. */
    for (quicstream_t* qs = conn->streams; qs != NULL; qs = qs->next) {
        /* Client-initiated bidirectional streams only. The peer's
         * unidirectional streams carry nothing in this protocol, and our own are
         * not opened at all. */
        if (!quic_stream_is_peer_initiated(qs->id) || quic_stream_is_uni(qs->id))
            continue;

        hq_stream_t* st = __stream_of(qs);
        if (st == NULL) {
            if (error != NULL) *error = 0x02;   /* INTERNAL_ERROR */
            return 0;
        }

        const uint64_t before = quicstream_readable(qs);
        __read(qs, st, server);
        if (before > 0) quicconn_consumed(conn, before - quicstream_readable(qs));

        /* Answered means __read never looks at this stream again, so anything
         * still held will never be delivered. The connection window is built on
         * what has been consumed, so those bytes have to be released here or
         * they hold their share of it for the life of the connection. */
        if (st->answered)
            quicconn_consumed(conn, quicflow_abandon(&qs->recv_flow, qs->recv_flow.used));

        __write(conn, qs, st);
    }

    return 1;
}

int hq_has_pending(quicconn_t* conn) {
    if (conn == NULL) return 0;

    for (const quicstream_t* qs = conn->streams; qs != NULL; qs = qs->next) {
        const hq_stream_t* st = qs->app;
        if (st == NULL) continue;

        if (st->answered && !st->finished) return 1;
    }

    return 0;
}

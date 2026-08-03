#include "h2data.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "connection_s.h"
#include "h2session.h"
#include "log.h"
#include "openssl.h"

void h2_data_writer_reset(h2_data_writer_t* w) {
    w->fh_len = 0;
    w->fh_pos = 0;
    w->frame_remaining = 0;
    w->frame_end_stream = 0;
}

/* Worker thread only — see the invariant on connection_data_write(). */
static ssize_t __raw_write(connection_t* connection, const char* data, size_t size) {
    return connection->ssl ?
        openssl_write(connection->ssl, data, size) :
        send(connection->fd, data, size, MSG_NOSIGNAL);
}

typedef enum { __IO_OK = 0, __IO_RETRY, __IO_BLOCKED, __IO_FATAL } __io_status_e;

/* Classify a failed write. EINTR is a retry of the same bytes; a full socket
 * buffer (or an SSL layer wanting more I/O) is not an error at all. */
static __io_status_e __io_status(connection_t* connection, ssize_t written) {
    if (connection->ssl != NULL) {
        switch (openssl_io_status(connection->ssl, (int)written)) {
        case OPENSSL_IO_WANT_READ:
        case OPENSSL_IO_WANT_WRITE:
            return __IO_BLOCKED;
        default:
            log_error("h2_data: ssl write failure\n");
            return __IO_FATAL;
        }
    }

    if (errno == EINTR) return __IO_RETRY;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return __IO_BLOCKED;

    log_error("h2_data: write error: %s\n", strerror(errno));

    return __IO_FATAL;
}

/* Drain w->fh[fh_pos..fh_len) — the 9-byte frame header. */
static h2_data_status_e __write_frame_header(h2_data_writer_t* w, connection_t* connection) {
    while (w->fh_pos < w->fh_len) {
        const ssize_t written = __raw_write(connection, (const char*)w->fh + w->fh_pos,
                                            w->fh_len - w->fh_pos);
        if (written < 0) {
            switch (__io_status(connection, written)) {
            case __IO_RETRY:   continue;
            case __IO_BLOCKED: return H2_DATA_SOCKET;
            default:           return H2_DATA_ERROR;
            }
        }
        if (written == 0) {
            log_error("h2_data: connection closed\n");
            return H2_DATA_ERROR;
        }

        w->fh_pos += (size_t)written;
    }

    return H2_DATA_DRAINED;
}

h2_data_status_e h2_data_write(h2_data_writer_t* w, h2session_t* s,
                               h2stream_t* stream, bufo_t* src) {
    connection_t* connection = s->connection;

    if (src == NULL) return H2_DATA_ERROR;

    for (;;) {
        /* Start a new DATA frame. */
        if (w->fh_len == 0) {
            const size_t remaining = src->size > src->pos ? src->size - src->pos : 0;

            /* Nothing left to frame. END_STREAM rides on the last non-empty
             * frame; a caller whose final buffer arrives empty appends its own
             * empty DATA frame instead. */
            if (remaining == 0) return H2_DATA_DRAINED;

            /* Quantum spent, and we are between frames — hand the socket back so
             * the other streams on this connection get a turn. Only ever here:
             * yielding mid-frame would splice another stream's bytes into ours,
             * and yielding during the header phase would let a second stream
             * encode a header block while this one's is still unsent, which
             * desyncs the peer's HPACK decoder (blocks must arrive in the order
             * they were encoded, RFC 9113 §4.3). */
            if (stream->write_credit <= 0) {
                stream->yielded = 1;
                return H2_DATA_YIELD;
            }

            size_t chunk = remaining;
            if (chunk > s->peer_max_frame_size)
                chunk = s->peer_max_frame_size;

            const int64_t window = s->send_window < stream->send_window ?
                s->send_window : stream->send_window;
            if (window <= 0) {
                /* Nothing may be sent until the peer enlarges a window. Waiting
                 * on EPOLLOUT would spin: the socket is writable already. */
                stream->window_blocked = 1;
                if (s->send_window <= 0) s->window_blocked = 1;
                return H2_DATA_WINDOW;
            }
            if ((int64_t)chunk > window)
                chunk = (size_t)window;

            w->frame_end_stream = (src->is_last && chunk == remaining) ? 1 : 0;
            w->frame_remaining = chunk;
            w->fh_pos = 0;
            w->fh_len = h2frame_encode_header(w->fh, H2_FRAME_DATA,
                                              w->frame_end_stream ? H2_FLAG_END_STREAM : 0,
                                              stream->id, chunk);
            if (w->fh_len == 0) return H2_DATA_ERROR;
        }

        const h2_data_status_e hdr = __write_frame_header(w, connection);
        if (hdr != H2_DATA_DRAINED) return hdr;

        /* Payload: written straight from the caller's buffer, no copy. */
        while (w->frame_remaining > 0) {
            const size_t chunk = bufo_chunk_size(src, w->frame_remaining);
            if (chunk == 0) {
                log_error("h2_data: DATA frame underrun\n");
                return H2_DATA_ERROR;
            }

            const ssize_t written = __raw_write(connection, bufo_data(src), chunk);
            if (written < 0) {
                switch (__io_status(connection, written)) {
                case __IO_RETRY:   continue;
                case __IO_BLOCKED: return H2_DATA_SOCKET;
                default:           return H2_DATA_ERROR;
                }
            }
            if (written == 0) {
                log_error("h2_data: connection closed\n");
                return H2_DATA_ERROR;
            }

            bufo_move_front_pos(src, (size_t)written);
            w->frame_remaining -= (size_t)written;
            s->send_window -= written;
            stream->send_window -= written;
            stream->write_credit -= written;
        }

        if (w->frame_end_stream)
            stream->end_stream_sent = 1;

        w->fh_len = 0;
        w->fh_pos = 0;
        w->frame_end_stream = 0;

        if (src->pos >= src->size) return H2_DATA_DRAINED;
    }
}

#include <stdlib.h>
#include <string.h>

#include "metrics.h"
#include "quicstream.h"

quicstream_t* quicstream_create(uint64_t id,
                                uint64_t recv_initial, uint64_t recv_max,
                                uint64_t send_initial) {
    quicstream_t* stream = malloc(sizeof * stream);
    if (stream == NULL) return NULL;

    metrics_quic(METRICS_QUIC_STREAMS_OPENED);

    memset(stream, 0, sizeof * stream);
    stream->id = id;

    /* The receive buffer's cap is the flow control window: a peer may reorder
     * within what it is allowed to send, but not beyond it, so anything past
     * the window is either a bug or an attempt to make us allocate. */
    quicrecvbuf_init(&stream->recv, (size_t)recv_max);
    quicsendbuf_init(&stream->send);

    quicflow_init_recv(&stream->recv_flow, recv_initial, recv_max);
    quicflow_init_send(&stream->send_flow, send_initial);

    return stream;
}

void quicstream_free(quicstream_t* stream) {
    if (stream == NULL) return;

    if (stream->app != NULL && stream->app_free != NULL) {
        stream->app_free(stream->app);
        stream->app = NULL;
    }

    quicrecvbuf_free(&stream->recv);
    quicsendbuf_free(&stream->send);
    free(stream);
}

int quicstream_can_receive(uint64_t id) {
    /* A server receives on client-initiated streams of either kind, and on the
     * bidirectional streams it opened itself. It never receives on its own
     * unidirectional streams. */
    if (quic_stream_is_peer_initiated(id)) return 1;

    return !quic_stream_is_uni(id);
}

int quicstream_can_send(uint64_t id) {
    /* Mirror image: never on the peer's unidirectional streams. */
    if (!quic_stream_is_peer_initiated(id)) return 1;

    return !quic_stream_is_uni(id);
}

quicstream_err_t quicstream_on_data(quicstream_t* stream, uint64_t offset,
                                    const uint8_t* data, size_t len, int fin) {
    if (stream == NULL) return QUIC_INTERNAL_ERROR;

    if (!quicstream_can_receive(stream->id)) return QUIC_STREAM_STATE_ERROR;

    /* After a reset the peer's data is irrelevant, but not an error: it was
     * already in flight when we reset. */
    if (stream->recv_state == QUIC_RECV_RESET_RECVD ||
        stream->recv_state == QUIC_RECV_RESET_READ)
        return QUICSTREAM_OK;

    const uint64_t end = offset + len;

    /* §4.5: the final size is fixed once known, and flow control counts the
     * highest offset rather than the bytes -- a retransmission must not consume
     * the window twice. */
    if (!quicflow_record_received(&stream->recv_flow, end))
        return QUIC_FLOW_CONTROL_ERROR;

    switch (quicrecvbuf_insert(&stream->recv, offset, data, len, fin)) {
    case QUICRECVBUF_OK:
        break;
    case QUICRECVBUF_FINAL_SIZE:
        return QUIC_FINAL_SIZE_ERROR;
    case QUICRECVBUF_TOO_MUCH:
        /* Within the flow control limit but spread far enough apart to cost
         * more memory than the window: still the peer overrunning what it was
         * allowed to make us hold. */
        return QUIC_FLOW_CONTROL_ERROR;
    default:
        return QUIC_INTERNAL_ERROR;
    }

    if (stream->recv.fin && stream->recv_state == QUIC_RECV_RECV)
        stream->recv_state = QUIC_RECV_SIZE_KNOWN;

    if (stream->recv_state == QUIC_RECV_SIZE_KNOWN &&
        stream->recv.contig_end >= stream->recv.final_size)
        stream->recv_state = QUIC_RECV_DATA_RECVD;

    return QUICSTREAM_OK;
}

quicstream_err_t quicstream_on_reset(quicstream_t* stream, uint64_t error_code,
                                     uint64_t final_size) {
    if (stream == NULL) return QUIC_INTERNAL_ERROR;

    if (!quicstream_can_receive(stream->id)) return QUIC_STREAM_STATE_ERROR;

    if (stream->recv_state == QUIC_RECV_RESET_RECVD ||
        stream->recv_state == QUIC_RECV_RESET_READ)
        return QUICSTREAM_OK;

    /* §4.5: the final size a RESET_STREAM declares has to agree with what has
     * already arrived. A smaller one would retroactively unsend data we have
     * already counted against flow control. */
    if (!quicflow_record_received(&stream->recv_flow, final_size))
        return QUIC_FLOW_CONTROL_ERROR;

    if (quicrecvbuf_set_final_size(&stream->recv, final_size) != QUICRECVBUF_OK)
        return QUIC_FINAL_SIZE_ERROR;

    stream->recv_state = QUIC_RECV_RESET_RECVD;
    stream->recv_reset_code = error_code;

    return QUICSTREAM_OK;
}

quicstream_err_t quicstream_on_stop_sending(quicstream_t* stream, uint64_t error_code) {
    if (stream == NULL) return QUIC_INTERNAL_ERROR;

    /* §19.5: only meaningful on a stream we can send on. Receiving it for a
     * peer-initiated unidirectional stream is a protocol violation. */
    if (!quicstream_can_send(stream->id)) return QUIC_STREAM_STATE_ERROR;

    stream->stop_sending_received = 1;
    stream->stop_sending_code = error_code;

    /* §3.5: the required response is to reset the stream, carrying the code
     * the peer asked for. Continuing to send would be ignored anyway. */
    if (stream->send_state != QUIC_SEND_RESET_SENT &&
        stream->send_state != QUIC_SEND_RESET_RECVD)
        quicstream_reset(stream, error_code);

    return QUICSTREAM_OK;
}

quicstream_err_t quicstream_on_max_data(quicstream_t* stream, uint64_t limit) {
    if (stream == NULL) return QUIC_INTERNAL_ERROR;

    /* §19.10: a limit for a stream we cannot send on says nothing and is a
     * state error. */
    if (!quicstream_can_send(stream->id)) return QUIC_STREAM_STATE_ERROR;

    quicflow_update_limit(&stream->send_flow, limit);

    return QUICSTREAM_OK;
}

void quicstream_reset(quicstream_t* stream, uint64_t error_code) {
    if (stream == NULL) return;
    if (stream->send_state == QUIC_SEND_RESET_SENT ||
        stream->send_state == QUIC_SEND_RESET_RECVD) return;

    /* Counted here rather than where the frame is written: the early return
     * above is what makes a reset idempotent, and counting past it would report
     * one abandoned stream twice. */
    metrics_quic(METRICS_QUIC_STREAMS_RESET_SENT);

    stream->send_state = QUIC_SEND_RESET_SENT;
    stream->send_reset_code = error_code;
    stream->send_reset_pending = 1;
}

void quicstream_stop_sending(quicstream_t* stream, uint64_t error_code) {
    if (stream == NULL) return;
    if (!quicstream_can_receive(stream->id)) return;

    /* Pointless once the receive side is finished one way or the other: the
     * peer has already stopped, and a STOP_SENDING for a stream it considers
     * closed is at best noise. */
    if (stream->recv_state == QUIC_RECV_RESET_RECVD ||
        stream->recv_state == QUIC_RECV_RESET_READ ||
        stream->recv_state == QUIC_RECV_DATA_RECVD ||
        stream->recv_state == QUIC_RECV_DATA_READ) return;

    if (stream->send_stop_sending_pending) return;

    stream->send_stop_sending_pending = 1;
    stream->send_stop_sending_code = error_code;
}

size_t quicstream_readable(const quicstream_t* stream) {
    if (stream == NULL) return 0;

    /* Nothing is readable after a reset: the data is incomplete by definition,
     * and handing over a prefix would look like a truncated message. */
    if (stream->recv_state == QUIC_RECV_RESET_RECVD ||
        stream->recv_state == QUIC_RECV_RESET_READ)
        return 0;

    return quicrecvbuf_readable(&stream->recv);
}

size_t quicstream_read(quicstream_t* stream, uint8_t* dst, size_t len) {
    if (stream == NULL) return 0;

    if (stream->recv_state == QUIC_RECV_RESET_RECVD) {
        stream->recv_state = QUIC_RECV_RESET_READ;
        return 0;
    }

    const size_t n = quicrecvbuf_read(&stream->recv, dst, len);

    /* Taking the bytes out is what frees the window they occupied; until the
     * flow object is told, the credit stays spent and the peer eventually runs
     * out of it for good. The connection-level half is the caller's, which is
     * why it is returned rather than done here -- this object does not know its
     * connection. */
    if (n > 0) quicflow_consumed(&stream->recv_flow, n, 0, 0);

    if (stream->recv_state == QUIC_RECV_DATA_RECVD &&
        quicrecvbuf_complete(&stream->recv))
        stream->recv_state = QUIC_RECV_DATA_READ;

    return n;
}

int quicstream_write(quicstream_t* stream, const uint8_t* data, size_t len) {
    if (stream == NULL) return 0;
    if (!quicstream_can_send(stream->id)) return 0;
    if (stream->send_state == QUIC_SEND_RESET_SENT ||
        stream->send_state == QUIC_SEND_RESET_RECVD) return 0;

    if (!quicsendbuf_write(&stream->send, data, len)) return 0;

    if (stream->send_state == QUIC_SEND_READY) stream->send_state = QUIC_SEND_SEND;

    return 1;
}

void quicstream_finish(quicstream_t* stream) {
    if (stream == NULL) return;

    quicsendbuf_finish(&stream->send);

    if (stream->send_state == QUIC_SEND_READY) stream->send_state = QUIC_SEND_SEND;
}

int quicstream_wants_send(const quicstream_t* stream) {
    if (stream == NULL) return 0;

    if (stream->send_reset_pending || stream->send_stop_sending_pending) return 1;

    /* A reset stream sends nothing further: the peer has been told to discard
     * whatever it holds. */
    if (stream->send_state == QUIC_SEND_RESET_SENT ||
        stream->send_state == QUIC_SEND_RESET_RECVD) return 0;

    if (!quicsendbuf_pending(&stream->send)) return 0;

    /* Blocked by flow control is not the same as having nothing to send, but
     * from the scheduler's point of view it is: there is no point picking this
     * stream until the peer raises the limit. */
    return quicflow_available(&stream->send_flow) > 0 ||
           (stream->send.fin && !stream->send.fin_sent);
}

int quicstream_is_finished(const quicstream_t* stream) {
    if (stream == NULL) return 0;

    const int send_done =
        stream->send_state == QUIC_SEND_DATA_RECVD ||
        stream->send_state == QUIC_SEND_RESET_RECVD ||
        !quicstream_can_send(stream->id);

    const int recv_done =
        stream->recv_state == QUIC_RECV_DATA_READ ||
        stream->recv_state == QUIC_RECV_RESET_READ ||
        !quicstream_can_receive(stream->id);

    return send_done && recv_done;
}

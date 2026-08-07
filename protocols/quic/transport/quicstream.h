#ifndef __QUICSTREAM__
#define __QUICSTREAM__

#include <stddef.h>
#include <stdint.h>

#include "quicerror.h"
#include "quicflow.h"
#include "quicrecvbuf.h"
#include "quicsendbuf.h"

/* QUIC streams (RFC 9000 §2, §3).
 *
 * ## Identifiers
 *
 * The two low bits of a stream id say who opened it and whether it is
 * bidirectional. The rest is a counter, so ids of one kind are 0, 4, 8, ...
 * That encoding has a consequence worth stating plainly: opening stream 12
 * *implicitly opens* streams 0, 4 and 8 of the same kind (§2.1). A server that
 * does not do this fails against real clients, because a client may skip ids
 * it decided not to use. */

#define QUIC_STREAM_BIT_SERVER 0x01
#define QUIC_STREAM_BIT_UNI    0x02

typedef enum {
    QUIC_STREAM_CLIENT_BIDI = 0x00,
    QUIC_STREAM_SERVER_BIDI = 0x01,
    QUIC_STREAM_CLIENT_UNI  = 0x02,
    QUIC_STREAM_SERVER_UNI  = 0x03
} quic_stream_kind_e;

static inline quic_stream_kind_e quic_stream_kind(uint64_t id) {
    return (quic_stream_kind_e)(id & 0x03);
}

static inline int quic_stream_is_uni(uint64_t id) {
    return (id & QUIC_STREAM_BIT_UNI) != 0;
}

/* From the server's point of view. */
static inline int quic_stream_is_peer_initiated(uint64_t id) {
    return (id & QUIC_STREAM_BIT_SERVER) == 0;
}

/* Position of a stream within its kind: 0, 4, 8, ... maps to 0, 1, 2, ... */
static inline uint64_t quic_stream_index(uint64_t id) {
    return id >> 2;
}

/* ---- State machines (§3.1, §3.2) ---- */

typedef enum {
    QUIC_SEND_READY = 0,   /* nothing sent yet */
    QUIC_SEND_SEND,        /* sending */
    QUIC_SEND_DATA_SENT,   /* everything including FIN is out, awaiting acks */
    QUIC_SEND_DATA_RECVD,  /* all acknowledged -- terminal */
    QUIC_SEND_RESET_SENT,
    QUIC_SEND_RESET_RECVD  /* terminal */
} quic_send_state_e;

typedef enum {
    QUIC_RECV_RECV = 0,    /* receiving */
    QUIC_RECV_SIZE_KNOWN,  /* FIN seen, still filling holes */
    QUIC_RECV_DATA_RECVD,  /* every byte is here */
    QUIC_RECV_DATA_READ,   /* and the application has taken it -- terminal */
    QUIC_RECV_RESET_RECVD,
    QUIC_RECV_RESET_READ   /* terminal */
} quic_recv_state_e;

typedef struct quicstream {
    uint64_t id;

    quic_send_state_e send_state;
    quic_recv_state_e recv_state;

    quicrecvbuf_t recv;
    quicsendbuf_t send;

    quicflow_t recv_flow;   /* what we allow the peer to send us */
    quicflow_t send_flow;   /* what the peer allows us */

    /* Set when we reset, or when the peer resets us. */
    uint64_t send_reset_code;
    uint64_t recv_reset_code;

    /* The peer asked us to stop sending (§3.5). Not itself a reset: the
     * application is told, and the stream is reset in response. */
    int      stop_sending_received;
    uint64_t stop_sending_code;

    /* Frames owed to the peer about this stream. */
    int      send_reset_pending;
    int      send_stop_sending_pending;
    uint64_t send_stop_sending_code;

    void*    app;   /* h3stream_t, phase 5 */

    struct quicstream* next;
    struct quicstream* send_next;   /* round-robin list of streams with data */
    int      in_send_list;
} quicstream_t;

/* Every error in this module is a transport error code, returned rather than
 * signalled, because the connection layer has to decide whether it kills the
 * stream or the connection. */
typedef uint64_t quicstream_err_t;
#define QUICSTREAM_OK 0

quicstream_t* quicstream_create(uint64_t id,
                                uint64_t recv_initial, uint64_t recv_max,
                                uint64_t send_initial);
void quicstream_free(quicstream_t* stream);

/* Whether this endpoint (a server) may receive on / send on this stream. A
 * unidirectional stream is one-way, and using it the wrong way is
 * STREAM_STATE_ERROR rather than merely odd. */
int quicstream_can_receive(uint64_t id);
int quicstream_can_send(uint64_t id);

/* Incoming STREAM frame. */
quicstream_err_t quicstream_on_data(quicstream_t* stream, uint64_t offset,
                                    const uint8_t* data, size_t len, int fin);

/* Incoming RESET_STREAM. */
quicstream_err_t quicstream_on_reset(quicstream_t* stream, uint64_t error_code,
                                     uint64_t final_size);

/* Incoming STOP_SENDING. */
quicstream_err_t quicstream_on_stop_sending(quicstream_t* stream, uint64_t error_code);

/* Incoming MAX_STREAM_DATA. */
quicstream_err_t quicstream_on_max_data(quicstream_t* stream, uint64_t limit);

/* The application abandons the stream: send RESET_STREAM. */
void quicstream_reset(quicstream_t* stream, uint64_t error_code);

/* Ask the peer to stop sending on this stream: send STOP_SENDING (§3.5).
 *
 * Not the same as resetting it, and the difference is the whole reason both
 * exist: RESET_STREAM abandons what *we* send, STOP_SENDING abandons what *we
 * receive*. HTTP/3 needs the second on its own for a unidirectional stream of
 * an unknown type (RFC 9114 §6.2.3), which has no send side to reset -- we
 * simply will not read it, and saying so stops the peer wasting the window. */
void quicstream_stop_sending(quicstream_t* stream, uint64_t error_code);

/* Bytes readable by the application. */
size_t quicstream_readable(const quicstream_t* stream);
size_t quicstream_read(quicstream_t* stream, uint8_t* dst, size_t len);

/* Queue data for sending; flow control is applied at packet build time. */
int quicstream_write(quicstream_t* stream, const uint8_t* data, size_t len);
void quicstream_finish(quicstream_t* stream);

/* Anything to put on the wire for this stream. */
int quicstream_wants_send(const quicstream_t* stream);

/* Both directions have reached a terminal state, so the stream can be
 * forgotten and its slot returned to the concurrency limit. */
int quicstream_is_finished(const quicstream_t* stream);

#endif

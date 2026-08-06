#ifndef __QUICFRAME__
#define __QUICFRAME__

#include <stddef.h>
#include <stdint.h>

#include "quic.h"

/* QUIC frames (RFC 9000 §19).
 *
 * Frames live in the decrypted payload of a packet, so unlike the header codec
 * this runs on bytes the AEAD has already authenticated. That removes the
 * hostile-input concern but not the malformed-input one: a peer may be buggy,
 * and every length here is still a varint that can point past the payload.
 *
 * Two rules distinguish this from the HTTP/3 frame layer, and confusing them is
 * a real hazard when writing both:
 *
 *  - An unknown frame type is a **connection error** (FRAME_ENCODING_ERROR),
 *    not something to skip. HTTP/3 does the opposite -- there, unknown frames
 *    must be ignored. There is no length prefix here to skip past anyway.
 *  - A frame type is admissible only in certain packet number spaces (§12.4).
 *    A STREAM frame in an Initial packet is a protocol violation. */

typedef enum {
    QUIC_FRAME_PADDING                = 0x00,
    QUIC_FRAME_PING                   = 0x01,
    QUIC_FRAME_ACK                    = 0x02,
    QUIC_FRAME_ACK_ECN                = 0x03,
    QUIC_FRAME_RESET_STREAM           = 0x04,
    QUIC_FRAME_STOP_SENDING           = 0x05,
    QUIC_FRAME_CRYPTO                 = 0x06,
    QUIC_FRAME_NEW_TOKEN              = 0x07,
    /* 0x08..0x0f: the low three bits are OFF, LEN and FIN. */
    QUIC_FRAME_STREAM                 = 0x08,
    QUIC_FRAME_MAX_DATA               = 0x10,
    QUIC_FRAME_MAX_STREAM_DATA        = 0x11,
    QUIC_FRAME_MAX_STREAMS_BIDI       = 0x12,
    QUIC_FRAME_MAX_STREAMS_UNI        = 0x13,
    QUIC_FRAME_DATA_BLOCKED           = 0x14,
    QUIC_FRAME_STREAM_DATA_BLOCKED    = 0x15,
    QUIC_FRAME_STREAMS_BLOCKED_BIDI   = 0x16,
    QUIC_FRAME_STREAMS_BLOCKED_UNI    = 0x17,
    QUIC_FRAME_NEW_CONNECTION_ID      = 0x18,
    QUIC_FRAME_RETIRE_CONNECTION_ID   = 0x19,
    QUIC_FRAME_PATH_CHALLENGE         = 0x1a,
    QUIC_FRAME_PATH_RESPONSE          = 0x1b,
    QUIC_FRAME_CONNECTION_CLOSE       = 0x1c,
    QUIC_FRAME_CONNECTION_CLOSE_APP   = 0x1d,
    QUIC_FRAME_HANDSHAKE_DONE         = 0x1e
} quic_frame_type_e;

#define QUIC_STREAM_FLAG_FIN 0x01
#define QUIC_STREAM_FLAG_LEN 0x02
#define QUIC_STREAM_FLAG_OFF 0x04

typedef struct quicframe {
    uint64_t type;   /* as it appeared on the wire, STREAM flags included */

    union {
        /* PADDING: how many consecutive padding bytes were folded into this
         * one frame. A 1200-byte Initial is mostly padding, and reporting it
         * byte by byte would turn one packet into a thousand iterations. */
        struct { uint64_t count; } padding;

        struct {
            uint64_t largest;
            uint64_t delay;        /* still scaled by ack_delay_exponent */
            uint64_t range_count;
            uint64_t first_range;
            /* The encoded ACK Range section, borrowed from the payload. Walk it
             * with quicframe_ack_iter_*; it is kept encoded because the number
             * of ranges is bounded only by the packet size. */
            const uint8_t* ranges;
            size_t   ranges_len;
            int      has_ecn;
            uint64_t ect0, ect1, ce;
        } ack;

        struct { uint64_t id, error, final_size; } reset_stream;
        struct { uint64_t id, error; } stop_sending;
        struct { uint64_t offset, len; const uint8_t* data; } crypto;
        struct { uint64_t len; const uint8_t* data; } new_token;
        struct {
            uint64_t id, offset, len;
            const uint8_t* data;
            int fin;
        } stream;
        struct { uint64_t max; } max_data;
        struct { uint64_t id, max; } max_stream_data;
        struct { uint64_t max; } max_streams;
        struct { uint64_t limit; } data_blocked;
        struct { uint64_t id, limit; } stream_data_blocked;
        struct { uint64_t limit; } streams_blocked;
        struct {
            uint64_t seq, retire_prior_to;
            quiccid_t cid;
            uint8_t token[16];
        } new_cid;
        struct { uint64_t seq; } retire_cid;
        struct { uint8_t data[8]; } path;
        struct {
            uint64_t error;
            uint64_t frame_type;   /* 0x1c only */
            const char* reason;
            size_t reason_len;
        } close;
    } u;
} quicframe_t;

typedef enum {
    QUICFRAME_OK = 0,
    QUICFRAME_DONE,           /* the payload is exhausted */
    QUICFRAME_ERR_ENCODING,   /* -> FRAME_ENCODING_ERROR */
    QUICFRAME_ERR_UNKNOWN     /* unknown type -> FRAME_ENCODING_ERROR */
} quicframe_status_e;

/* Read the next frame from a decrypted payload, advancing `*off`. */
quicframe_status_e quicframe_next(const uint8_t* buf, size_t len, size_t* off,
                                  quicframe_t* out);

/* True when a packet carrying this frame must be acknowledged (§13.2.1):
 * everything except ACK, PADDING and CONNECTION_CLOSE. */
int quicframe_is_ack_eliciting(uint64_t type);

/* Whether §12.4 permits this frame in that packet number space. */
int quicframe_allowed_in(uint64_t type, quic_enc_level_e level);

/* ---- ACK ranges (§19.3.1) ----
 *
 * The encoding is relative and every field is stored one less than it means,
 * which makes it the most off-by-one-prone structure in the protocol. Both
 * directions go through these so the arithmetic exists in exactly one place. */

typedef struct quicack_iter {
    const uint8_t* p;
    const uint8_t* end;
    uint64_t remaining;    /* encoded ranges still to read */
    uint64_t smallest;     /* lower edge of the block yielded last */
    uint64_t largest;      /* the frame's Largest Acknowledged */
    uint64_t first_range;  /* the frame's First ACK Range */
    /* The block described by Largest Acknowledged and First ACK Range has not
     * been yielded yet. Handling it inside the iterator rather than at the call
     * site is the point: it is the block whose arithmetic differs from all the
     * others, and every caller would otherwise repeat it. */
    int first;
} quicack_iter_t;

/* One acknowledged run, inclusive at both ends. */
typedef struct quicack_block {
    uint64_t largest;
    uint64_t smallest;
} quicack_block_t;

/* Start walking an ACK frame's ranges. The first block (largest and First ACK
 * Range) is yielded by the first _next call, so a caller never has to special
 * case it. */
void quicack_iter_init(const quicframe_t* frame, quicack_iter_t* it);

/* 1 if a block was produced, 0 when finished. Returns -1 on a malformed range
 * section -- a gap that would run the edges below zero, which is how a peer
 * would try to make the arithmetic wrap. */
int quicack_iter_next(quicack_iter_t* it, quicack_block_t* out);

/* ---- Writing ---- */

/* Serialize a frame. ACK is not accepted here -- its ranges are built from the
 * sender's own state rather than echoed, so it has its own writer below.
 * Returns bytes written, or 0 if it does not fit or a field is out of range. */
size_t quicframe_write(uint8_t* dst, size_t cap, const quicframe_t* frame);

/* Write an ACK frame from blocks ordered from the largest packet number
 * downwards, non-overlapping and non-adjacent. `delay` is already scaled by the
 * peer's ack_delay_exponent. Pass ecn = NULL for the 0x02 form. */
size_t quicframe_write_ack(uint8_t* dst, size_t cap,
                           const quicack_block_t* blocks, size_t block_count,
                           uint64_t delay, const uint64_t ecn[3]);

/* Write `count` PADDING bytes. */
size_t quicframe_write_padding(uint8_t* dst, size_t cap, size_t count);

#endif

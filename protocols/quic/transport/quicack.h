#ifndef __QUICACK__
#define __QUICACK__

#include <stddef.h>
#include <stdint.h>

#include "quic.h"
#include "quicframe.h"
#include "quicrange.h"

/* The receive side of acknowledgement (RFC 9000 §13.2).
 *
 * Records which packet numbers have arrived in one packet number space, decides
 * when an ACK frame is owed, and builds it.
 *
 * Two properties are doing real work here:
 *
 *  - **Duplicate detection.** A packet number that has already been processed
 *    must be dropped before its frames are applied, or a replayed packet
 *    applies its STREAM data twice. This is also the only defence against an
 *    attacker replaying a captured packet -- the AEAD cannot tell a replay from
 *    the original, since it is the original.
 *
 *  - **A cap on how many ranges are remembered.** A peer that loses every other
 *    packet creates one range per gap; unbounded, that is memory the peer
 *    controls, and an ACK frame listing hundreds of ranges is abusive in
 *    itself. The oldest are dropped, which costs nothing real: the peer has
 *    long since given up on them. */

/* Enough to describe a genuinely lossy path without letting a hostile one grow
 * the set without limit. */
#define QUICACK_MAX_RANGES 32

/* §13.2.1: at most this many ack-eliciting packets may arrive before an ACK
 * must be sent immediately rather than waiting for the timer. */
#define QUICACK_MAX_ELICITING_BEFORE_ACK 2

typedef struct quicack {
    quicrange_t received;

    uint64_t largest;             /* highest packet number seen */
    uint64_t largest_recv_us;     /* when it arrived, for the ack delay */

    /* Ack-eliciting packets received since the last ACK was sent. */
    unsigned eliciting_pending;
    /* An ACK is owed at this time; 0 = none owed. */
    uint64_t ack_deadline_us;
    /* Send one at the next opportunity regardless of the deadline. */
    int      ack_immediately;

    /* ECN counts to report (§13.4). Always zero until phase 9 turns ECN on;
     * the fields exist so the frame writer does not need two shapes. */
    uint64_t ect0, ect1, ce;
    int      has_ecn;

    int      any_received;
} quicack_t;

void quicack_init(quicack_t* ack);
void quicack_free(quicack_t* ack);

/* True if this packet number has already been processed -- check before
 * applying any of its frames. */
int quicack_is_duplicate(const quicack_t* ack, uint64_t pn);

/* Record a received packet.
 *
 * `max_ack_delay_us` is our own advertised delay, which bounds how long an ACK
 * may be held back. `level` decides whether it may be held back at all: in
 * Initial and Handshake an ACK is sent immediately, because delaying one there
 * directly lengthens the handshake. */
void quicack_on_received(quicack_t* ack, quic_enc_level_e level, uint64_t pn,
                         int ack_eliciting, uint64_t now_us,
                         uint64_t max_ack_delay_us);

/* Whether an ACK frame should go out now. */
int quicack_should_send(const quicack_t* ack, uint64_t now_us);

/* When an ACK is next owed, or 0 if none is pending. */
uint64_t quicack_deadline(const quicack_t* ack);

/* Write an ACK frame covering everything received. `ack_delay_exponent` is what
 * the peer advertised -- the delay field is scaled by it. Returns bytes
 * written, or 0 if the frame does not fit or nothing has been received. */
size_t quicack_write(const quicack_t* ack, uint8_t* dst, size_t cap,
                     uint64_t now_us, uint64_t ack_delay_exponent);

/* An ACK frame has gone out: clear what it satisfied. */
void quicack_on_sent(quicack_t* ack);

/* Forget packet numbers at or below `value`. Called when the peer acknowledges
 * our ACK, since it will never ask about them again (§13.2.4). */
void quicack_trim(quicack_t* ack, uint64_t value);

#endif

#ifndef __QUICLOSS__
#define __QUICLOSS__

#include <stddef.h>
#include <stdint.h>

#include "quic.h"
#include "quiccc.h"
#include "quicframe.h"
#include "quicrange.h"

/* Loss detection and recovery (RFC 9002).
 *
 * QUIC does not retransmit packets; it retransmits the *information* they
 * carried (§13.3). So a record of a sent packet is not the bytes but a list of
 * what it was carrying, enough to build the frames again -- and that is why
 * this module stores frame references rather than payloads.
 *
 * Everything here is defined in elapsed time, which is why the whole QUIC stack
 * takes its clock from quic_now_us: without an injectable clock none of this is
 * testable, and untested loss detection fails as "the network is slow
 * sometimes" rather than as anything anyone can debug. */

/* §6.1.1: three packets past a lost one is enough to declare it lost, rather
 * than merely reordered. */
#define QUICLOSS_PACKET_THRESHOLD 3
/* §6.1.2: the time threshold is 9/8 of the larger of the latest and smoothed
 * RTT, floored at the timer granularity. */
#define QUICLOSS_TIME_THRESHOLD_NUM 9
#define QUICLOSS_TIME_THRESHOLD_DEN 8
#define QUICLOSS_GRANULARITY_US     1000
/* §6.2.2: before any RTT sample exists. */
#define QUICLOSS_INITIAL_RTT_US     333000

/* What a sent packet was carrying, in the form needed to send it again.
 *
 * Deliberately not the encoded frames: a retransmitted MAX_DATA should carry
 * the *current* limit, not the stale one, and a stream range may have been
 * acknowledged in part meanwhile. Only enough to reconstruct. */
typedef struct quicframe_ref {
    uint64_t type;
    uint64_t stream_id;   /* STREAM, RESET_STREAM, MAX_STREAM_DATA, ... */
    uint64_t offset;      /* STREAM, CRYPTO */
    uint64_t len;
    int      fin;
    struct quicframe_ref* next;
} quicframe_ref_t;

typedef struct quicsent {
    uint64_t pn;
    uint64_t sent_us;
    size_t   size;             /* bytes on the wire, for the congestion window */
    int      ack_eliciting;
    int      in_flight;        /* counts against the congestion window */

    /* Delivery rate sampling (draft-cheng-iccrg-delivery-rate-estimation).
     *
     * A rate is bytes over an interval, and neither end of that interval is
     * knowable from the acknowledgement alone: the sender has to have written
     * down, at send time, where the connection's delivery counter stood and
     * when it last moved. These four fields are that note. They cost 25 bytes
     * per outstanding packet and are what makes a rate-based controller
     * possible at all -- without them BBR has nothing to build a model from. */
    uint64_t delivered;        /* the connection's delivered count when sent */
    uint64_t delivered_us;     /* when that count last advanced */
    uint64_t first_sent_us;    /* start of the send interval this packet is in */
    int      app_limited;      /* the sender was out of data, not out of window */

    quicframe_ref_t* frames;
    struct quicsent* next;     /* ascending by packet number */
} quicsent_t;

/* One packet number space. Initial, Handshake and Application each keep their
 * own numbering, their own sent list and their own timers (§12.3). */
typedef struct quicpnspace {
    uint64_t next_pn;
    uint64_t largest_acked;    /* QUICPKT_NO_ACKED while nothing is acknowledged */

    quicsent_t* sent;          /* ascending, unacknowledged only */
    quicsent_t* sent_tail;
    size_t   sent_count;

    uint64_t loss_time_us;     /* when the time threshold next fires; 0 = never */
    uint64_t last_ack_eliciting_sent_us;
    size_t   ack_eliciting_in_flight;
} quicpnspace_t;

typedef struct quicloss {
    quicpnspace_t space[QUIC_ENC_COUNT];

    /* §5. smoothed_rtt and rttvar are the estimator; min_rtt is kept separately
     * because it is the only figure an attacker cannot inflate. */
    uint64_t latest_rtt_us;
    uint64_t smoothed_rtt_us;
    uint64_t rttvar_us;
    uint64_t min_rtt_us;
    int      have_rtt_sample;

    uint64_t max_ack_delay_us;  /* what the peer advertised */

    uint32_t pto_count;         /* consecutive PTOs, for the backoff */

    /* Connection-wide delivery rate estimator. One per connection, not one per
     * packet number space: the path carries all three, and a rate measured over
     * one of them alone would be a fraction of the truth. */
    uint64_t delivered;         /* bytes acknowledged over this connection */
    uint64_t delivered_us;      /* when `delivered` last advanced */
    uint64_t first_sent_us;     /* start of the current send interval */
    /* The value `delivered` must pass before samples stop being marked
     * application-limited; 0 while the sender is keeping the path busy. */
    uint64_t app_limited;

    quiccc_t* cc;

    /* Set while the handshake is unconfirmed: §6.2.1 excludes the peer's
     * max_ack_delay from the PTO until then, since the peer is not yet
     * obliged to honour it. */
    int      handshake_confirmed;

    /* First four bytes of the connection's original DCID, for debug lines only.
     * Recovery is where the questions of docs/http3/08 §3m–3t are asked, and its
     * answers are unreadable without saying which of fifty interleaved
     * connections produced them -- the same reason the PTO line carries the tag.
     * A copy rather than a back-pointer: this module owes nothing upwards. */
    uint8_t  cid_tag[4];
} quicloss_t;

void quicloss_init(quicloss_t* loss, quiccc_t* cc, uint64_t max_ack_delay_us);
void quicloss_free(quicloss_t* loss);

/* Label this connection's debug lines. `cid` may be shorter than four bytes;
 * what is missing stays zero. Diagnostics only -- nothing branches on it. */
void quicloss_set_cid_tag(quicloss_t* loss, const uint8_t* cid, size_t len);

/* The sender stopped because it had nothing left to send, not because the
 * window or the pacer stopped it. Every rate sampled from here on describes how
 * fast the application produced data, and a controller that mistook that for
 * the path's capacity would spend the next ten round trips sending at the speed
 * of an idle moment. Ignored when the sender is in fact window-limited: then it
 * is the path being measured after all. */
void quicloss_app_limited(quicloss_t* loss);

/* Record a packet as sent. Takes ownership of `frames`. */
int quicloss_on_sent(quicloss_t* loss, quic_enc_level_e level, uint64_t pn,
                     size_t size, int ack_eliciting, int in_flight,
                     quicframe_ref_t* frames, uint64_t now_us);

/* What an ACK frame told us. `acked` is the set of packet numbers it covers.
 *
 * Both outcomes hand their frame references back, chained, and ownership passes
 * to the caller:
 *
 *   `out_lost`  -- packets declared lost, to be put back on the send queues;
 *   `out_acked` -- packets confirmed, so the sender can release what they
 *                  carried. May be NULL, and then those references are freed
 *                  here.
 *
 * The second one is not symmetry for its own sake. Stream data lives in a send
 * buffer until it is known to have arrived; without the acknowledgements coming
 * back the buffer never releases anything, the stream never reaches a terminal
 * state, and the connection's stream credit is never returned to the peer. All
 * three were true until this parameter existed (docs/http3/08 §7a).
 *
 * `ack_delay_us` is the peer's reported delay, already unscaled. */
int quicloss_on_ack(quicloss_t* loss, quic_enc_level_e level,
                    const quicrange_t* acked, uint64_t ack_delay_us,
                    uint64_t now_us, quicframe_ref_t** out_lost,
                    quicframe_ref_t** out_acked);

/* Run the loss detection timer. Returns 1 if it was a loss timer (frames are in
 * `out_lost`), 0 if it was a PTO -- in which case the caller must send one or
 * two ack-eliciting packets, which is what a PTO *is*: not a retransmission but
 * a probe to make the peer say something. */
int quicloss_on_timeout(quicloss_t* loss, uint64_t now_us,
                        quicframe_ref_t** out_lost, quic_enc_level_e* out_level);

/* When the next timer fires, or 0 if none is armed. */
uint64_t quicloss_timeout(const quicloss_t* loss, uint64_t now_us);

/* Throw away a packet number space (§4.9): its keys are gone, so nothing in it
 * can ever be acknowledged. Returns the frames that were still outstanding --
 * CRYPTO data must be resent at the next level, not dropped. */
quicframe_ref_t* quicloss_discard_space(quicloss_t* loss, quic_enc_level_e level);

uint64_t quicloss_pto_us(const quicloss_t* loss, quic_enc_level_e level);

quicframe_ref_t* quicframe_ref_new(uint64_t type);
void quicframe_ref_free(quicframe_ref_t* refs);

#endif

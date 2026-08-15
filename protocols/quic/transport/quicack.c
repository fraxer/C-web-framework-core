#include <string.h>

#include "quicack.h"

void quicack_init(quicack_t* ack) {
    if (ack == NULL) return;

    memset(ack, 0, sizeof * ack);
    quicrange_init(&ack->received, QUICACK_MAX_RANGES);
}

void quicack_free(quicack_t* ack) {
    if (ack == NULL) return;

    quicrange_free(&ack->received);
}

int quicack_is_duplicate(const quicack_t* ack, uint64_t pn) {
    if (ack == NULL) return 0;

    return quicrange_contains(&ack->received, pn);
}

void quicack_on_received(quicack_t* ack, quic_enc_level_e level, uint64_t pn,
                         int ack_eliciting, uint64_t now_us,
                         uint64_t max_ack_delay_us) {
    quicack_on_received_ecn(ack, level, pn, ack_eliciting, 0, now_us,
                            max_ack_delay_us);
}

void quicack_on_received_ecn(quicack_t* ack, quic_enc_level_e level, uint64_t pn,
                             int ack_eliciting, uint8_t ecn, uint64_t now_us,
                             uint64_t max_ack_delay_us) {
    if (ack == NULL) return;

    /* Reordering: a packet below the highest seen means the peer's packets are
     * arriving out of order, and §13.2.1 asks for an immediate ACK so the peer
     * learns about the gap without waiting. Computed before the range is
     * updated, since adding it would fill the gap being detected. */
    const int out_of_order = ack->any_received && pn < ack->largest;

    quicrange_add(&ack->received, pn, pn);

    if (!ack->any_received || pn > ack->largest) {
        ack->largest = pn;
        /* Only the largest packet's arrival time matters: it is the one the
         * ACK reports a delay for, and the peer takes its RTT sample from it. */
        ack->largest_recv_us = now_us;
    }

    ack->any_received = 1;

    switch (ecn & 0x03) {
    case 0x02: ack->ect0++; ack->has_ecn = 1; break;
    case 0x01: ack->ect1++; ack->has_ecn = 1; break;
    case 0x03: ack->ce++;   ack->has_ecn = 1; break;
    default: break;
    }

    if (!ack_eliciting) return;

    ack->eliciting_pending++;

    /* An ACK in the handshake spaces is never delayed: the peer is waiting on
     * it to make progress, and holding it back adds directly to the time to
     * first byte. Only 1-RTT ACKs may be batched. */
    if (level != QUIC_ENC_APP) {
        ack->ack_immediately = 1;
        return;
    }

    if (out_of_order) {
        ack->ack_immediately = 1;
        return;
    }

    if (ack->eliciting_pending >= QUICACK_MAX_ELICITING_BEFORE_ACK) {
        ack->ack_immediately = 1;
        return;
    }

    /* Otherwise hold it briefly, so one ACK covers several packets. The
     * deadline is set from the first unacknowledged packet, not refreshed by
     * each new one -- refreshing would let a steady stream postpone the ACK
     * indefinitely. */
    if (ack->ack_deadline_us == 0)
        ack->ack_deadline_us = now_us + max_ack_delay_us;
}

int quicack_should_send(const quicack_t* ack, uint64_t now_us) {
    if (ack == NULL || !ack->any_received) return 0;

    if (ack->ack_immediately) return 1;

    return ack->ack_deadline_us != 0 && now_us >= ack->ack_deadline_us;
}

int quicack_pending(const quicack_t* ack) {
    if (ack == NULL || !ack->any_received) return 0;

    /* Only ack-eliciting arrivals are owed an acknowledgement. Riding along on
     * the strength of anything else would answer the peer's own ACKs with ours,
     * for as long as both sides had a packet to send. */
    return ack->ack_immediately || ack->eliciting_pending > 0 ||
           ack->ack_deadline_us != 0;
}

uint64_t quicack_deadline(const quicack_t* ack) {
    if (ack == NULL) return 0;
    if (ack->ack_immediately) return 1;   /* "now" -- any past time works */

    return ack->ack_deadline_us;
}

size_t quicack_write(const quicack_t* ack, uint8_t* dst, size_t cap,
                     uint64_t now_us, uint64_t ack_delay_exponent) {
    if (ack == NULL || dst == NULL || !ack->any_received) return 0;
    if (quicrange_empty(&ack->received)) return 0;

    /* The delay we report is how long the largest packet has been held. Scaled
     * down by the exponent the peer advertised, which is how QUIC keeps the
     * field small while still expressing long delays. */
    const uint64_t held = now_us > ack->largest_recv_us
                          ? now_us - ack->largest_recv_us : 0;
    const uint64_t delay = held >> (ack_delay_exponent > 20 ? 20 : ack_delay_exponent);

    /* The range set is ascending; ACK frames run downward from the largest. */
    quicack_block_t blocks[QUICACK_MAX_RANGES];
    size_t count = quicrange_count(&ack->received);
    if (count > QUICACK_MAX_RANGES) count = QUICACK_MAX_RANGES;

    for (size_t i = 0; i < count; i++) {
        quicrange_span_t span;
        if (!quicrange_at_desc(&ack->received, i, &span)) return 0;

        blocks[i].largest = span.end;
        blocks[i].smallest = span.start;
    }

    const uint64_t ecn[3] = { ack->ect0, ack->ect1, ack->ce };

    return quicframe_write_ack(dst, cap, blocks, count, delay,
                               ack->has_ecn ? ecn : NULL);
}

void quicack_on_sent(quicack_t* ack) {
    if (ack == NULL) return;

    ack->eliciting_pending = 0;
    ack->ack_deadline_us = 0;
    ack->ack_immediately = 0;
}

void quicack_trim(quicack_t* ack, uint64_t value) {
    if (ack == NULL) return;

    quicrange_trim_below(&ack->received, value);
}

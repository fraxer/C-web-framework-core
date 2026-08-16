#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "metrics.h"
#include "quicloss.h"
#include "quicpacket.h"

quicframe_ref_t* quicframe_ref_new(uint64_t type) {
    quicframe_ref_t* ref = malloc(sizeof * ref);
    if (ref == NULL) return NULL;

    memset(ref, 0, sizeof * ref);
    ref->type = type;

    return ref;
}

void quicframe_ref_free(quicframe_ref_t* refs) {
    while (refs != NULL) {
        quicframe_ref_t* next = refs->next;
        free(refs);
        refs = next;
    }
}

static void __sent_free(quicsent_t* sent) {
    quicframe_ref_free(sent->frames);
    free(sent);
}

void quicloss_init(quicloss_t* loss, quiccc_t* cc, uint64_t max_ack_delay_us) {
    if (loss == NULL) return;

    memset(loss, 0, sizeof * loss);

    loss->cc = cc;
    loss->max_ack_delay_us = max_ack_delay_us;
    loss->min_rtt_us = UINT64_MAX;

    for (int i = 0; i < QUIC_ENC_COUNT; i++)
        loss->space[i].largest_acked = QUICPKT_NO_ACKED;
}

void quicloss_app_limited(quicloss_t* loss) {
    if (loss == NULL) return;

    const uint64_t in_flight = loss->cc != NULL ? loss->cc->bytes_in_flight : 0;

    /* Window-limited, not application-limited: the sender has data and the
     * controller is what is holding it back, so the samples in flight say
     * exactly what the path is doing and must be believed. */
    if (loss->cc != NULL && in_flight >= loss->cc->cwnd) return;

    /* Everything already in flight belongs to the idle period too, so the mark
     * is set past it: samples stop being application-limited only once the
     * connection has delivered more than was outstanding when it went quiet.
     * Never zero, which is the "not limited" value. */
    loss->app_limited = loss->delivered + in_flight;
    if (loss->app_limited == 0) loss->app_limited = 1;
}

void quicloss_set_cid_tag(quicloss_t* loss, const uint8_t* cid, size_t len) {
    if (loss == NULL || cid == NULL) return;

    if (len > sizeof loss->cid_tag) len = sizeof loss->cid_tag;

    memcpy(loss->cid_tag, cid, len);
}

void quicloss_free(quicloss_t* loss) {
    if (loss == NULL) return;

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        quicsent_t* sent = loss->space[i].sent;
        while (sent != NULL) {
            quicsent_t* next = sent->next;
            __sent_free(sent);
            sent = next;
        }
        loss->space[i].sent = NULL;
        loss->space[i].sent_tail = NULL;
    }
}

int quicloss_on_sent(quicloss_t* loss, quic_enc_level_e level, uint64_t pn,
                     size_t size, int ack_eliciting, int in_flight,
                     quicframe_ref_t* frames, uint64_t now_us) {
    if (loss == NULL || level >= QUIC_ENC_COUNT) {
        quicframe_ref_free(frames);
        return 0;
    }

    quicsent_t* sent = malloc(sizeof * sent);
    if (sent == NULL) {
        quicframe_ref_free(frames);
        return 0;
    }

    /* A connection with nothing in flight is starting a new send interval: the
     * gap before it is the application's idleness, not the path's, and counting
     * it would report a rate far below what the path can carry. */
    if (loss->cc == NULL || loss->cc->bytes_in_flight == 0) {
        loss->first_sent_us = now_us;
        loss->delivered_us = now_us;
    }

    memset(sent, 0, sizeof * sent);
    sent->pn = pn;
    sent->sent_us = now_us;
    sent->size = size;
    sent->ack_eliciting = ack_eliciting;
    sent->in_flight = in_flight;
    sent->delivered = loss->delivered;
    sent->delivered_us = loss->delivered_us;
    sent->first_sent_us = loss->first_sent_us;
    sent->app_limited = loss->app_limited != 0;
    sent->frames = frames;

    quicpnspace_t* space = &loss->space[level];

    /* Packet numbers only ever increase, so the list stays sorted by appending. */
    if (space->sent_tail != NULL) space->sent_tail->next = sent;
    else space->sent = sent;
    space->sent_tail = sent;
    space->sent_count++;

    if (pn >= space->next_pn) space->next_pn = pn + 1;

    if (ack_eliciting) {
        space->last_ack_eliciting_sent_us = now_us;
        space->ack_eliciting_in_flight++;
    }

    if (in_flight && loss->cc != NULL)
        loss->cc->ops->on_sent(loss->cc, size);

    return 1;
}

/* §5.3. The estimator is a moving average with a separate variance term; the
 * variance is what makes the PTO tolerant of a jittery path without making it
 * slow on a steady one. */
static void __update_rtt(quicloss_t* loss, quic_enc_level_e level, uint64_t pn,
                         uint64_t latest_rtt, uint64_t ack_delay) {
    /* The first sample is the one worth watching: §5.3 puts it into
     * smoothed_rtt whole, without the ack_delay adjustment, so everything
     * downstream -- the PTO, the loss time threshold -- inherits it. A first
     * sample of 1.2 s on a 33 ms path has been seen against quiche and makes the
     * connection slow enough to fail a timed test (docs/http3/08 §3p), and the
     * only way to tell a slow path from an acknowledgement that arrived late for
     * its own reasons is to print which packet it came from and when that packet
     * went out. */
    log_debug("quic: rtt cid=%02x%02x%02x%02x level=%d pn=%llu sample=%llu "
              "ack_delay=%llu srtt_prev=%llu min_prev=%llu first=%d\n",
              loss->cid_tag[0], loss->cid_tag[1], loss->cid_tag[2], loss->cid_tag[3],
              (int)level, (unsigned long long)pn,
              (unsigned long long)latest_rtt, (unsigned long long)ack_delay,
              (unsigned long long)loss->smoothed_rtt_us,
              (unsigned long long)(loss->have_rtt_sample ? loss->min_rtt_us : 0),
              !loss->have_rtt_sample);

    loss->latest_rtt_us = latest_rtt;

    /* The raw sample, not the smoothed estimate: the histogram is meant to show
     * the spread, and a moving average is the one thing guaranteed to hide it. */
    metrics_quic_rtt(latest_rtt);

    if (!loss->have_rtt_sample) {
        loss->min_rtt_us = latest_rtt;
        loss->smoothed_rtt_us = latest_rtt;
        loss->rttvar_us = latest_rtt / 2;
        loss->have_rtt_sample = 1;
        return;
    }

    if (latest_rtt < loss->min_rtt_us) loss->min_rtt_us = latest_rtt;

    /* §5.3: subtract the peer's reported delay, but only as far as min_rtt --
     * a peer that reports an inflated delay would otherwise be able to drive
     * our RTT estimate to nothing and make us declare loss constantly. Before
     * the handshake is confirmed the peer is not yet bound by its advertised
     * max_ack_delay, so the delay is not applied at all. */
    uint64_t adjusted = latest_rtt;
    if (loss->handshake_confirmed) {
        uint64_t delay = ack_delay;
        if (delay > loss->max_ack_delay_us) delay = loss->max_ack_delay_us;

        if (latest_rtt > loss->min_rtt_us + delay) adjusted = latest_rtt - delay;
    }

    /* rttvar = 3/4 rttvar + 1/4 |smoothed - adjusted| */
    const uint64_t diff = loss->smoothed_rtt_us > adjusted
                          ? loss->smoothed_rtt_us - adjusted
                          : adjusted - loss->smoothed_rtt_us;

    loss->rttvar_us = (loss->rttvar_us * 3 + diff) / 4;
    /* smoothed = 7/8 smoothed + 1/8 adjusted */
    loss->smoothed_rtt_us = (loss->smoothed_rtt_us * 7 + adjusted) / 8;
}

uint64_t quicloss_pto_us(const quicloss_t* loss, quic_enc_level_e level) {
    if (loss == NULL) return QUICLOSS_INITIAL_RTT_US;

    if (!loss->have_rtt_sample)
        return QUICLOSS_INITIAL_RTT_US * 2;

    uint64_t variance = loss->rttvar_us * 4;
    if (variance < QUICLOSS_GRANULARITY_US) variance = QUICLOSS_GRANULARITY_US;

    uint64_t pto = loss->smoothed_rtt_us + variance;

    /* §6.2.1: the peer's ack delay counts only in the application space -- it
     * does not delay acknowledgements during the handshake. */
    if (level == QUIC_ENC_APP && loss->handshake_confirmed)
        pto += loss->max_ack_delay_us;

    return pto;
}

/* The time threshold for declaring loss: 9/8 of the larger of the latest and
 * smoothed RTT, never below the timer granularity (§6.1.2). */
static uint64_t __loss_delay(const quicloss_t* loss) {
    uint64_t rtt = loss->latest_rtt_us > loss->smoothed_rtt_us
                   ? loss->latest_rtt_us : loss->smoothed_rtt_us;

    if (rtt == 0) rtt = QUICLOSS_INITIAL_RTT_US;

    uint64_t delay = rtt * QUICLOSS_TIME_THRESHOLD_NUM / QUICLOSS_TIME_THRESHOLD_DEN;
    if (delay < QUICLOSS_GRANULARITY_US) delay = QUICLOSS_GRANULARITY_US;

    return delay;
}

/* Detect losses in one space, unlink them, and chain their frame references
 * onto *out_lost. */
static void __detect_lost(quicloss_t* loss, quic_enc_level_e level,
                          uint64_t now_us, quicframe_ref_t** out_lost,
                          uint64_t* out_lost_bytes) {
    quicpnspace_t* space = &loss->space[level];
    if (space->largest_acked == QUICPKT_NO_ACKED) return;

    const uint64_t delay = __loss_delay(loss);
    space->loss_time_us = 0;

    /* Persistent congestion is measured over the lost packets themselves
     * (§7.6): if every ack-eliciting packet across a long enough span was lost,
     * the path is gone rather than congested. */
    uint64_t earliest_lost = 0;
    uint64_t latest_lost = 0;
    int lost_ack_eliciting = 0;

    /* The last packet kept, for the tail (see the removal below). */
    quicsent_t* kept = NULL;

    quicsent_t** link = &space->sent;
    while (*link != NULL) {
        quicsent_t* sent = *link;

        if (sent->pn > space->largest_acked) break;

        const int by_count = space->largest_acked - sent->pn >= QUICLOSS_PACKET_THRESHOLD;
        const int by_time = now_us >= sent->sent_us + delay;

        if (!by_count && !by_time) {
            /* Not lost yet, but it will be at sent_us + delay unless it is
             * acknowledged first -- that is what the loss timer is for. */
            const uint64_t when = sent->sent_us + delay;
            if (space->loss_time_us == 0 || when < space->loss_time_us)
                space->loss_time_us = when;

            kept = sent;
            link = &sent->next;
            continue;
        }

        *link = sent->next;

        /* Same reasoning as in quicloss_on_ack: only the tail can be removed
         * with nothing behind it, so the last packet kept is the new tail. The
         * list is not walked again to find it -- that rescan was most of this
         * function's cost on a large transfer (docs/http3/08 §7c). */
        if (space->sent_tail == sent) space->sent_tail = kept;

        space->sent_count--;

        if (sent->ack_eliciting) {
            if (space->ack_eliciting_in_flight > 0) space->ack_eliciting_in_flight--;

            if (!lost_ack_eliciting) earliest_lost = sent->sent_us;
            latest_lost = sent->sent_us;
            lost_ack_eliciting = 1;
        }

        metrics_quic(METRICS_QUIC_PACKETS_LOST);

        /* Which of the two rules fired matters when reading a stalled
         * connection: by_count means a later packet got through and this one
         * did not, by_time means nothing has been heard for a loss delay and
         * the declaration is a guess -- and a guess is what produces a
         * retransmission of data the peer already holds (§3t). */
        log_debug("quic: lost cid=%02x%02x%02x%02x level=%d pn=%llu age=%llu "
                  "by=%s\n",
                  loss->cid_tag[0], loss->cid_tag[1], loss->cid_tag[2],
                  loss->cid_tag[3], (int)level, (unsigned long long)sent->pn,
                  (unsigned long long)(now_us - sent->sent_us),
                  by_count ? "count" : "time");

        if (sent->in_flight) {
            if (out_lost_bytes != NULL) *out_lost_bytes += sent->size;

            if (loss->cc != NULL)
                loss->cc->ops->on_loss(loss->cc, sent->size, sent->sent_us, now_us);
        }

        /* Hand the frames back so the caller can queue them again. */
        if (sent->frames != NULL) {
            quicframe_ref_t* tail = sent->frames;
            while (tail->next != NULL) tail = tail->next;
            tail->next = *out_lost;
            *out_lost = sent->frames;
            sent->frames = NULL;
        }

        __sent_free(sent);
    }

    if (space->sent == NULL) space->sent_tail = NULL;

    if (lost_ack_eliciting && loss->cc != NULL && loss->have_rtt_sample) {
        const uint64_t pto = quicloss_pto_us(loss, level);
        const uint64_t threshold = pto * QUICCC_PERSISTENT_CONGESTION_THRESHOLD;

        if (latest_lost > earliest_lost && latest_lost - earliest_lost > threshold) {
            metrics_quic(METRICS_QUIC_PERSISTENT_CONGESTION);
            loss->cc->ops->on_persistent_congestion(loss->cc);
        }
    }
}

int quicloss_on_ack(quicloss_t* loss, quic_enc_level_e level,
                    const quicrange_t* acked, uint64_t ack_delay_us,
                    uint64_t now_us, quicframe_ref_t** out_lost,
                    quicframe_ref_t** out_acked) {
    if (loss == NULL || acked == NULL || out_lost == NULL) return 0;
    if (level >= QUIC_ENC_COUNT) return 0;
    if (quicrange_empty(acked)) return 1;

    quicpnspace_t* space = &loss->space[level];
    const uint64_t largest = quicrange_max(acked);

    int largest_newly_acked = 0;
    uint64_t largest_sent_us = 0;
    int largest_was_ack_eliciting = 0;

    /* What this acknowledgement will tell the controller once it has been
     * processed in full. Filled in as the walk goes; handed over at the end. */
    quiccc_sample_t sample;
    memset(&sample, 0, sizeof sample);
    sample.prior_in_flight = loss->cc != NULL ? loss->cc->bytes_in_flight : 0;

    /* The rate sample is taken from ONE packet -- the most recently sent of the
     * ones being acknowledged -- because that is the packet whose send interval
     * and delivery interval bracket the same stretch of the path. Averaging
     * over all of them would mix intervals that overlap. */
    int      rs_found = 0;
    uint64_t rs_prior_delivered = 0;
    uint64_t rs_send_elapsed = 0;
    uint64_t rs_ack_elapsed = 0;
    int      rs_app_limited = 0;

    /* The last packet this walk decided to keep, which is the new tail if the
     * walk removes the old one. */
    quicsent_t* kept = NULL;

    quicsent_t** link = &space->sent;
    while (*link != NULL) {
        quicsent_t* sent = *link;

        /* The list is ascending by packet number, so everything past the
         * largest acknowledged one is unreachable for this acknowledgement.
         *
         * Without the stop this loop walked every unacknowledged packet on
         * every acknowledgement, testing each against the range set -- work
         * proportional to the congestion window, repeated once per
         * acknowledgement, which is quadratic in the size of a transfer. On a
         * 16 MB file that was most of the server's CPU: 16.2 ms per megabyte
         * against 4.6 for HTTP/2, growing with the transfer (docs/http3/08
         * §7a). The packets are ordered and so is the answer; the loop just was
         * not using it. */
        if (sent->pn > largest) break;

        if (!quicrange_contains(acked, sent->pn)) {
            kept = sent;
            link = &sent->next;
            continue;
        }

        if (sent->pn == largest) {
            largest_newly_acked = 1;
            largest_sent_us = sent->sent_us;
            largest_was_ack_eliciting = sent->ack_eliciting;
        }

        if (sent->ack_eliciting && space->ack_eliciting_in_flight > 0)
            space->ack_eliciting_in_flight--;

        if (sent->in_flight) {
            /* The delivery counter advances by what actually arrived, which is
             * the numerator of every rate this connection will ever measure. */
            loss->delivered += sent->size;
            loss->delivered_us = now_us;
            sample.acked_bytes += sent->size;

            /* `delivered` at send time increases with send order, so the
             * largest is the most recently sent packet in this acknowledgement
             * -- found without knowing the send order itself. */
            if (!rs_found || sent->delivered > rs_prior_delivered) {
                rs_found = 1;
                rs_prior_delivered = sent->delivered;
                rs_app_limited = sent->app_limited;
                rs_send_elapsed = sent->sent_us > sent->first_sent_us
                                  ? sent->sent_us - sent->first_sent_us : 0;
                rs_ack_elapsed = loss->delivered_us > sent->delivered_us
                                 ? loss->delivered_us - sent->delivered_us : 0;

                /* The next send interval starts where this packet was sent. */
                loss->first_sent_us = sent->sent_us;
            }

            if (loss->cc != NULL)
                loss->cc->ops->on_ack(loss->cc, sent->size, sent->sent_us, now_us);
        }

        *link = sent->next;
        space->sent_count--;

        /* Only the tail can be removed with nothing behind it -- removals here
         * come from the prefix at or below `largest`, and the list is ascending
         * -- so the packet before it is the new tail. */
        if (space->sent_tail == sent) space->sent_tail = kept;

        /* Hand the frames to the caller so it can release what they carried;
         * with nowhere to put them they are freed as before. */
        if (out_acked != NULL && sent->frames != NULL) {
            quicframe_ref_t* tail = sent->frames;
            while (tail->next != NULL) tail = tail->next;
            tail->next = *out_acked;
            *out_acked = sent->frames;
            sent->frames = NULL;
        }

        __sent_free(sent);
    }

    /* The tail is maintained in the loop above, not rediscovered here.
     *
     * Rediscovering it walked the whole list on every acknowledgement, and that
     * list *is* the congestion window -- thousands of packets on a large
     * transfer. It is the same quadratic §7a removed from the acknowledgement
     * scan itself, left standing three lines below it: on a 64 MB response this
     * rescan and its twin in __detect_lost were 86 % of the server's CPU
     * (docs/http3/08 §7c). */
    if (space->sent == NULL) space->sent_tail = NULL;

    if (space->largest_acked == QUICPKT_NO_ACKED || largest > space->largest_acked)
        space->largest_acked = largest;

    /* §5.1: only the largest acknowledged packet gives an RTT sample, and only
     * when it is newly acknowledged and was ack-eliciting. Sampling from any
     * other packet measures the peer's acknowledgement policy, not the path. */
    if (largest_newly_acked && largest_was_ack_eliciting && now_us >= largest_sent_us) {
        __update_rtt(loss, level, largest, now_us - largest_sent_us, ack_delay_us);
        sample.rtt_us = loss->latest_rtt_us;
    }

    /* An acknowledgement means the peer is alive, so the backoff resets. */
    loss->pto_count = 0;

    __detect_lost(loss, level, now_us, out_lost, &sample.lost_bytes);

    /* The connection has delivered past the mark, so it is keeping the path
     * busy again and its samples measure the path once more. */
    if (loss->app_limited != 0 && loss->delivered > loss->app_limited)
        loss->app_limited = 0;

    if (rs_found) {
        /* The interval is the longer of the two the packet brackets: how long
         * the sender took to put those bytes out, and how long the receiver
         * took to acknowledge them. The longer one is the bottleneck; taking
         * the shorter would report the speed of whichever end was idle. */
        const uint64_t interval = rs_send_elapsed > rs_ack_elapsed
                                  ? rs_send_elapsed : rs_ack_elapsed;
        const uint64_t delivered = loss->delivered - rs_prior_delivered;

        /* Intervals below one round trip are noise: they time an
         * acknowledgement's arrival, not a path's throughput, and dividing by
         * them produces rates the path never carried. */
        const uint64_t floor = loss->have_rtt_sample && loss->min_rtt_us != UINT64_MAX
                               ? loss->min_rtt_us : QUICLOSS_GRANULARITY_US;

        if (interval >= floor && interval > 0 && delivered > 0)
            sample.delivery_rate = delivered * 1000000ULL / interval;

        sample.prior_delivered = rs_prior_delivered;
        sample.app_limited = rs_app_limited;
    }

    sample.delivered = loss->delivered;

    /* Everything this acknowledgement said, in one call, after the losses it
     * implied have been declared -- a controller that decides on rate has to
     * see the acknowledgement whole, and half of it is what was NOT there. */
    if (loss->cc != NULL && (sample.acked_bytes > 0 || sample.lost_bytes > 0))
        loss->cc->ops->on_ack_end(loss->cc, &sample, now_us);

    /* Sampled after the loss detection and the controller update above, so a
     * window that an ACK grew and the losses in the same ACK then cut is
     * recorded once, at the value the next packet will actually be sent
     * under. */
    if (loss->cc != NULL) metrics_quic_cwnd(loss->cc->cwnd);

    return 1;
}

/* The space whose loss timer fires first. */
static quic_enc_level_e __earliest_loss_time(const quicloss_t* loss, uint64_t* out) {
    quic_enc_level_e level = QUIC_ENC_INITIAL;
    uint64_t earliest = 0;

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        const uint64_t t = loss->space[i].loss_time_us;
        if (t == 0) continue;
        if (earliest == 0 || t < earliest) {
            earliest = t;
            level = (quic_enc_level_e)i;
        }
    }

    if (out != NULL) *out = earliest;

    return level;
}

/* The space whose PTO fires first, among those with something in flight. */
static quic_enc_level_e __earliest_pto(const quicloss_t* loss, uint64_t* out) {
    quic_enc_level_e level = QUIC_ENC_INITIAL;
    uint64_t earliest = 0;

    for (int i = 0; i < QUIC_ENC_COUNT; i++) {
        const quicpnspace_t* space = &loss->space[i];
        if (space->ack_eliciting_in_flight == 0) continue;

        /* §6.2.1: the application space's PTO is not armed until the handshake
         * is confirmed -- before that, handshake packets carry the urgency. */
        if (i == QUIC_ENC_APP && !loss->handshake_confirmed) continue;
        if (i == QUIC_ENC_EARLY) continue;   /* 0-RTT shares the app space */

        const uint64_t pto = quicloss_pto_us(loss, (quic_enc_level_e)i)
                             * (1ULL << loss->pto_count);
        const uint64_t when = space->last_ack_eliciting_sent_us + pto;

        if (earliest == 0 || when < earliest) {
            earliest = when;
            level = (quic_enc_level_e)i;
        }
    }

    if (out != NULL) *out = earliest;

    return level;
}

uint64_t quicloss_timeout(const quicloss_t* loss, uint64_t now_us) {
    (void)now_us;
    if (loss == NULL) return 0;

    uint64_t loss_time = 0;
    __earliest_loss_time(loss, &loss_time);

    /* The loss timer wins when it is armed: it fires sooner and does something
     * more specific than a probe. */
    if (loss_time != 0) return loss_time;

    uint64_t pto_time = 0;
    __earliest_pto(loss, &pto_time);

    return pto_time;
}

int quicloss_on_timeout(quicloss_t* loss, uint64_t now_us,
                        quicframe_ref_t** out_lost, quic_enc_level_e* out_level) {
    if (loss == NULL || out_lost == NULL) return 0;

    uint64_t loss_time = 0;
    const quic_enc_level_e loss_level = __earliest_loss_time(loss, &loss_time);

    if (loss_time != 0 && now_us >= loss_time) {
        __detect_lost(loss, loss_level, now_us, out_lost, NULL);
        if (out_level != NULL) *out_level = loss_level;
        return 1;
    }

    /* A PTO. Not a retransmission: §6.2 has the sender emit one or two
     * ack-eliciting packets to make the peer respond, because the alternative
     * -- assuming loss -- would collapse the window on a path that is merely
     * quiet. The caller decides what to put in them. */
    uint64_t pto_time = 0;
    const quic_enc_level_e pto_level = __earliest_pto(loss, &pto_time);

    if (pto_time != 0 && now_us >= pto_time) {
        loss->pto_count++;
        if (loss->cc != NULL) loss->cc->ops->on_pto(loss->cc);
        if (out_level != NULL) *out_level = pto_level;
    }

    return 0;
}

quicframe_ref_t* quicloss_discard_space(quicloss_t* loss, quic_enc_level_e level) {
    if (loss == NULL || level >= QUIC_ENC_COUNT) return NULL;

    quicpnspace_t* space = &loss->space[level];
    quicframe_ref_t* frames = NULL;

    quicsent_t* sent = space->sent;
    while (sent != NULL) {
        quicsent_t* next = sent->next;

        /* Those bytes are no longer in flight: nothing can ever acknowledge
         * them, so leaving them counted would shrink the usable window for the
         * rest of the connection. */
        if (sent->in_flight && loss->cc != NULL) {
            quiccc_t* cc = loss->cc;
            if (cc->bytes_in_flight >= sent->size) cc->bytes_in_flight -= sent->size;
            else cc->bytes_in_flight = 0;
        }

        if (sent->frames != NULL) {
            quicframe_ref_t* tail = sent->frames;
            while (tail->next != NULL) tail = tail->next;
            tail->next = frames;
            frames = sent->frames;
            sent->frames = NULL;
        }

        __sent_free(sent);
        sent = next;
    }

    memset(space, 0, sizeof * space);
    space->largest_acked = QUICPKT_NO_ACKED;

    return frames;
}

#include <string.h>

#include "quicflow.h"

void quicflow_init_send(quicflow_t* flow, uint64_t limit) {
    if (flow == NULL) return;

    memset(flow, 0, sizeof * flow);
    flow->limit = limit;
}

void quicflow_init_recv(quicflow_t* flow, uint64_t initial, uint64_t max_window) {
    if (flow == NULL) return;

    memset(flow, 0, sizeof * flow);
    flow->limit = initial;
    flow->auto_window = initial;
    flow->max_window = max_window < initial ? initial : max_window;
}

uint64_t quicflow_available(const quicflow_t* flow) {
    if (flow == NULL || flow->used >= flow->limit) return 0;

    return flow->limit - flow->used;
}

void quicflow_consume(quicflow_t* flow, uint64_t bytes) {
    if (flow == NULL) return;

    flow->used += bytes;
}

int quicflow_update_limit(quicflow_t* flow, uint64_t limit) {
    if (flow == NULL) return 0;

    /* §4.1: limits only ever increase. A reordered MAX_DATA carrying an older,
     * smaller value must be ignored rather than allowed to shrink the window --
     * shrinking it below what has already been sent would be unrecoverable. */
    if (limit <= flow->limit) return 0;

    flow->limit = limit;
    /* A new limit is worth reporting again if we block on it. */
    flow->blocked_sent = 0;

    return 1;
}

int quicflow_should_send_blocked(quicflow_t* flow) {
    if (flow == NULL) return 0;
    if (quicflow_available(flow) > 0) return 0;

    if (flow->blocked_sent && flow->blocked_at == flow->limit) return 0;

    flow->blocked_sent = 1;
    flow->blocked_at = flow->limit;

    return 1;
}

int quicflow_record_received(quicflow_t* flow, uint64_t highest_offset) {
    if (flow == NULL) return 0;

    /* Flow control counts the highest offset reached, not the bytes delivered:
     * a retransmission must not consume the window twice, and data received
     * out of order consumes it up to its far end. */
    if (highest_offset <= flow->used) return 1;

    if (highest_offset > flow->limit) return 0;

    flow->used = highest_offset;

    return 1;
}

void quicflow_consumed(quicflow_t* flow, uint64_t bytes,
                       uint64_t rtt_us, uint64_t elapsed_us) {
    if (flow == NULL) return;

    (void)bytes;

    /* Auto-tuning: if the peer can exhaust the whole window in less than two
     * round trips, the window is what is limiting the transfer rather than the
     * network, and doubling it costs only memory. Below that, leave it alone --
     * a window larger than the path needs is buffer nobody uses.
     *
     * The same reasoning as the HTTP/2 receive window scaling in this codebase. */
    if (rtt_us == 0 || elapsed_us == 0) return;
    if (flow->auto_window >= flow->max_window) return;

    if (elapsed_us < rtt_us * 2) {
        flow->auto_window *= 2;
        if (flow->auto_window > flow->max_window) flow->auto_window = flow->max_window;
    }
}

int quicflow_should_update(const quicflow_t* flow, uint64_t* out_limit) {
    if (flow == NULL) return 0;

    /* Advertise a window of auto_window bytes beyond what the peer has already
     * sent. Sent when more than half the current allowance is gone: any later
     * and the peer stalls waiting for credit it has earned, any earlier and we
     * spend frames saying nothing new. */
    const uint64_t remaining = flow->limit > flow->used ? flow->limit - flow->used : 0;
    if (remaining > flow->auto_window / 2) return 0;

    const uint64_t next = flow->used + flow->auto_window;
    if (next <= flow->limit) return 0;

    if (out_limit != NULL) *out_limit = next;

    return 1;
}

void quicflow_update_sent(quicflow_t* flow, uint64_t limit) {
    if (flow == NULL) return;

    if (limit > flow->limit) flow->limit = limit;
}

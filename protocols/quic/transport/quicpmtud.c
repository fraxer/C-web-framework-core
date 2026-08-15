#include <string.h>

#include "quicpmtud.h"

void quicpmtud_init(quicpmtud_t* p, size_t base, size_t ceiling) {
    if (p == NULL) return;
    memset(p, 0, sizeof *p);
    p->base = base;
    p->current = base;
    p->ceiling = ceiling > base ? ceiling : base;
}

int quicpmtud_should_probe(const quicpmtud_t* p, uint64_t now_us) {
    return p != NULL && !p->outstanding && p->current < p->ceiling &&
           now_us >= p->next_probe_us;
}

size_t quicpmtud_candidate(quicpmtud_t* p) {
    if (p == NULL) return 0;
    if (p->candidate > p->current) return p->candidate;
    /* Binary search avoids walking every possible MTU while still trying the
     * common 1500-byte link on the first probe (1350 -> 1472). */
    p->candidate = p->ceiling;
    return p->candidate;
}

void quicpmtud_on_probe_sent(quicpmtud_t* p, uint64_t pn,
                             uint64_t now_us, uint64_t pto_us) {
    if (p == NULL) return;
    p->probe_pn = pn;
    p->outstanding = 1;
    p->attempts++;
    p->deadline_us = now_us + 3 * pto_us;
}

int quicpmtud_on_ack(quicpmtud_t* p, uint64_t pn, uint64_t now_us,
                     uint64_t pto_us) {
    if (p == NULL || !p->outstanding || pn != p->probe_pn) return 0;
    p->current = p->candidate;
    p->candidate = 0;
    p->outstanding = 0;
    p->attempts = 0;
    p->deadline_us = 0;
    p->next_probe_us = now_us + 10 * pto_us;
    return 1;
}

void quicpmtud_on_timeout(quicpmtud_t* p, uint64_t now_us) {
    if (p == NULL || !p->outstanding || now_us < p->deadline_us) return;
    p->outstanding = 0;
    p->deadline_us = 0;
    if (p->attempts >= QUICPMTUD_MAX_PROBES) {
        p->ceiling = p->current;
        p->candidate = 0;
        p->attempts = 0;
    }
    p->next_probe_us = now_us;
}

void quicpmtud_on_blackhole(quicpmtud_t* p, uint64_t now_us, uint64_t pto_us) {
    if (p == NULL || p->current == p->base) return;
    const size_t failed = p->current;
    p->current = p->base;
    p->ceiling = failed - 1;
    p->candidate = 0;
    p->outstanding = 0;
    p->attempts = 0;
    p->deadline_us = 0;
    p->next_probe_us = now_us + 10 * pto_us;
}

uint64_t quicpmtud_deadline(const quicpmtud_t* p) {
    if (p == NULL) return 0;
    return p->outstanding ? p->deadline_us : 0;
}

#ifndef __QUICPMTUD__
#define __QUICPMTUD__

#include <stddef.h>
#include <stdint.h>

#define QUICPMTUD_MAX_PROBES 3

/* What a timeout did, as flags rather than a state: one call can both give up
 * on a probe and end the search, and the caller (metrics, qlog) has to be able
 * to report them apart. Without a return value neither event is observable at
 * all -- the search simply stops, and a connection stuck at the base size looks
 * the same as one whose path really is that small. */
#define QUICPMTUD_PROBE_LOST      0x01
#define QUICPMTUD_CEILING_LOWERED 0x02

typedef struct quicpmtud {
    size_t base;
    size_t current;
    size_t ceiling;
    size_t candidate;
    uint64_t probe_pn;
    uint64_t deadline_us;
    uint64_t next_probe_us;
    unsigned attempts;
    int outstanding;
} quicpmtud_t;

void quicpmtud_init(quicpmtud_t* pmtud, size_t base, size_t ceiling);
int quicpmtud_should_probe(const quicpmtud_t* pmtud, uint64_t now_us);
size_t quicpmtud_candidate(quicpmtud_t* pmtud);
void quicpmtud_on_probe_sent(quicpmtud_t* pmtud, uint64_t pn,
                             uint64_t now_us, uint64_t pto_us);
int quicpmtud_on_ack(quicpmtud_t* pmtud, uint64_t pn, uint64_t now_us,
                     uint64_t pto_us);
/* Returns the QUICPMTUD_* flags above, or 0 when nothing happened. */
int quicpmtud_on_timeout(quicpmtud_t* pmtud, uint64_t now_us);
/* Returns 1 when a raised size was actually taken back. */
int quicpmtud_on_blackhole(quicpmtud_t* pmtud, uint64_t now_us,
                           uint64_t pto_us);
uint64_t quicpmtud_deadline(const quicpmtud_t* pmtud);

#endif

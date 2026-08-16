#ifndef __H3PRIORITY__
#define __H3PRIORITY__

#include <stddef.h>
#include <stdint.h>

/* The Priority Field Value of RFC 9218 -- an RFC 8941 Dictionary with two
 * defined members, carried two ways that mean the same thing:
 *
 *   - the `priority` request header field (§5), which arrives with the request;
 *   - the PRIORITY_UPDATE frame (§7), which arrives on the control stream and
 *     may do so before the request stream exists or long after it did.
 *
 * Both are parsed here so the two paths cannot drift apart, and so the syntax
 * has one unit-testable home.
 *
 * ## What is and is not enforced
 *
 * Only the two defined members are interpreted: `u` (urgency, an integer 0..7)
 * and `i` (incremental, a boolean). §4.1 is explicit that an unknown member, or
 * one of the wrong type, is to be **ignored** rather than treated as an error --
 * priority signals are advisory, and a peer that invents a member must not have
 * its request killed for it. So a valid dictionary containing nothing we know
 * yields the defaults.
 *
 * What does fail is a value that is not a dictionary at all: a member with no
 * key, a key with no value after `=`, a stray comma. The distinction matters
 * because the PRIORITY_UPDATE path turns a parse failure into H3_FRAME_ERROR
 * and kills the connection, while the header-field path only shrugs.
 *
 * Parameters on a member (`u=1;q=0.5`) are accepted and skipped: they are legal
 * dictionary syntax and carry nothing we act on. */

#define H3_PRIORITY_URGENCY_DEFAULT 3
#define H3_PRIORITY_URGENCY_MAX     7

typedef struct {
    uint8_t urgency;        /* 0 is most urgent, 7 least, 3 the default */
    uint8_t incremental;    /* the response may be interleaved with its peers */

    /* Which of the two were actually present. A PRIORITY_UPDATE that says only
     * `u=5` must not silently reset an `i` the request header established --
     * §7 says the frame overrides the field, but only for the members it
     * carries. */
    uint8_t has_urgency;
    uint8_t has_incremental;
} h3priority_t;

/* Defaults, for a request that signalled nothing. */
void h3priority_defaults(h3priority_t* out);

/* Parse a Priority Field Value. Returns 1 when the value is a well-formed
 * dictionary -- `out` then holds whatever it defined, defaults for the rest --
 * and 0 when it is not parseable at all.
 *
 * An empty value is well formed and means the defaults (§4.1: an empty
 * dictionary is a dictionary). */
int h3priority_parse(const uint8_t* value, size_t len, h3priority_t* out);

/* Apply `update` on top of `base`, member by member. Only what the update
 * actually carried is overwritten. */
void h3priority_merge(h3priority_t* base, const h3priority_t* update);

#endif

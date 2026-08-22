#include "framework.h"

#include "h3priority.h"

#include <string.h>

/* The Priority Field Value of RFC 9218 §4 -- an RFC 8941 Dictionary.
 *
 * The line these cases draw is the one that matters at the call sites: a value
 * that is *not a dictionary* fails, because PRIORITY_UPDATE turns that into
 * H3_FRAME_ERROR and kills the connection; a value that is a dictionary but
 * says something we cannot use is accepted and ignored, because §4.1 says so
 * and because killing a connection over `u=9` turns a peer's cosmetic bug into
 * a failed page. */

static int parse(const char* value, h3priority_t* out) {
    return h3priority_parse((const uint8_t*)value, strlen(value), out);
}

TEST(test_h3priority_defined_members) {
    TEST_SUITE("h3priority");

    h3priority_t p;

    TEST_CASE("nothing at all is the default");
    TEST_ASSERT(parse("", &p) == 1, "empty is a dictionary");
    TEST_ASSERT(p.urgency == H3_PRIORITY_URGENCY_DEFAULT, "urgency 3");
    TEST_ASSERT(p.incremental == 0, "not incremental");
    TEST_ASSERT(!p.has_urgency && !p.has_incremental, "and nothing was said");

    TEST_CASE("urgency");
    TEST_ASSERT(parse("u=0", &p) == 1 && p.urgency == 0 && p.has_urgency, "most urgent");
    TEST_ASSERT(parse("u=7", &p) == 1 && p.urgency == 7, "least urgent");
    TEST_ASSERT(parse("u=3", &p) == 1 && p.urgency == 3 && p.has_urgency,
                "the default, said out loud, is still said");

    TEST_CASE("incremental is a boolean, and a bare key is true");
    TEST_ASSERT(parse("i", &p) == 1 && p.incremental == 1 && p.has_incremental, "bare");
    TEST_ASSERT(parse("i=?1", &p) == 1 && p.incremental == 1, "explicit true");
    TEST_ASSERT(parse("i=?0", &p) == 1 && p.incremental == 0 && p.has_incremental,
                "explicit false is a signal, not an absence");

    TEST_CASE("both, in either order, with the whitespace 8941 allows");
    TEST_ASSERT(parse("u=1, i", &p) == 1 && p.urgency == 1 && p.incremental, "u then i");
    TEST_ASSERT(parse("i=?1,u=6", &p) == 1 && p.urgency == 6 && p.incremental, "i then u");
    TEST_ASSERT(parse("  u=2 ,  i  ", &p) == 1 && p.urgency == 2 && p.incremental, "spaces");
}

TEST(test_h3priority_ignored) {
    TEST_SUITE("h3priority");

    h3priority_t p;

    /* Every case here is a *valid* dictionary that says something we do not
     * act on. All of them must parse, and none of them may move a value. */
    TEST_CASE("§4.1: what we cannot use is ignored, not refused");
    TEST_ASSERT(parse("u=9", &p) == 1 && p.urgency == H3_PRIORITY_URGENCY_DEFAULT &&
                !p.has_urgency, "urgency above the range");
    TEST_ASSERT(parse("u=-1", &p) == 1 && !p.has_urgency, "urgency below it");
    TEST_ASSERT(parse("u=abc", &p) == 1 && !p.has_urgency, "urgency of the wrong type");
    TEST_ASSERT(parse("i=3", &p) == 1 && !p.has_incremental, "incremental of the wrong type");
    TEST_ASSERT(parse("x=1, u=4", &p) == 1 && p.urgency == 4,
                "an unknown member does not spoil the known one");
    TEST_ASSERT(parse("u=4;q=0.5", &p) == 1 && p.urgency == 4, "parameters are skipped");
    TEST_ASSERT(parse("v=\"a, b\", u=5", &p) == 1 && p.urgency == 5,
                "a comma inside a string is not a member separator");

    TEST_CASE("the last mention of a member wins");
    TEST_ASSERT(parse("u=1, u=6", &p) == 1 && p.urgency == 6, "u");
}

TEST(test_h3priority_malformed) {
    TEST_SUITE("h3priority");

    h3priority_t p;

    /* These are connection-fatal through PRIORITY_UPDATE, which is exactly why
     * the list is short and every entry is a broken *structure* rather than an
     * unusable value. */
    TEST_CASE("a value that is not a dictionary is refused");
    TEST_ASSERT(parse("u=", &p) == 0, "member with no value");
    TEST_ASSERT(parse("u=1,", &p) == 0, "trailing comma");
    TEST_ASSERT(parse(",u=1", &p) == 0, "leading comma");
    TEST_ASSERT(parse("=1", &p) == 0, "value with no key");
    TEST_ASSERT(parse("U=1", &p) == 0, "keys are lowercase");
    TEST_ASSERT(parse("i=?2", &p) == 0, "a boolean that is neither");
    TEST_ASSERT(parse("v=\"unterminated", &p) == 0, "unterminated string");

    const uint8_t control[] = { 'u', '=', '1', ',', 'v', '=', 0x01 };
    TEST_ASSERT(h3priority_parse(control, sizeof control, &p) == 0, "control character");

    /* And a refusal leaves nothing behind. A dictionary that goes wrong *after*
     * a member we understood used to publish that member anyway, so `out` and
     * the return value disagreed about whether the value was usable. Found by
     * the fuzz target, not by this file (docs/http3/08 §7r). */
    TEST_CASE("a refused value leaves the defaults in place");
    TEST_ASSERT(parse("u=7;q=0.5, 7", &p) == 0, "refused");
    TEST_ASSERT(p.urgency == H3_PRIORITY_URGENCY_DEFAULT && !p.has_urgency,
                "the urgency it had already read is not published");
    TEST_ASSERT(parse("u=0, i, x=", &p) == 0, "refused later still");
    TEST_ASSERT(p.urgency == H3_PRIORITY_URGENCY_DEFAULT && p.incremental == 0 &&
                !p.has_incremental, "neither member is published");
}

TEST(test_h3priority_merge) {
    TEST_SUITE("h3priority");

    /* What §7 needs: a PRIORITY_UPDATE carrying only `u` must not reset an `i`
     * that the request header established. */
    TEST_CASE("a merge moves only what the update carried");
    h3priority_t base, update;

    TEST_ASSERT(parse("u=5, i", &base) == 1, "base");
    TEST_ASSERT(parse("u=1", &update) == 1, "update");

    h3priority_merge(&base, &update);

    TEST_ASSERT(base.urgency == 1, "urgency taken from the update");
    TEST_ASSERT(base.incremental == 1, "incremental kept from the base");

    TEST_ASSERT(parse("", &update) == 1, "an empty update");
    h3priority_merge(&base, &update);
    TEST_ASSERT(base.urgency == 1 && base.incremental == 1, "changes nothing");
}

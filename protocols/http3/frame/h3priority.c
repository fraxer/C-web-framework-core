#include "h3priority.h"

/* Dictionary keys are lowercase (RFC 8941 §3.2): lcalpha or "*" to begin,
 * then lcalpha, DIGIT, "_", "-", "." or "*". */
static int __key_char(uint8_t c, int first) {
    if (c >= 'a' && c <= 'z') return 1;
    if (c == '*') return 1;
    if (first) return 0;

    return (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

static int __visible(uint8_t c) {
    return c >= 0x20 && c <= 0x7e;
}

void h3priority_defaults(h3priority_t* out) {
    if (out == NULL) return;

    out->urgency = H3_PRIORITY_URGENCY_DEFAULT;
    out->incremental = 0;
    out->has_urgency = 0;
    out->has_incremental = 0;
}

/* One member's value, starting at `*i` (just past the "="). Reports what it
 * was, and advances `*i` past it. Returns 0 only when the value is not a value
 * at all -- an unterminated string, a "?" that is not a boolean -- because a
 * type we do not act on is not an error here (§4.1: ignore it). */
static int __read_value(const uint8_t* v, size_t len, size_t* i,
                        int* is_bool, int* bool_value,
                        int* is_int, long* int_value) {
    *is_bool = 0; *is_int = 0; *bool_value = 0; *int_value = 0;

    if (*i >= len) return 0;

    if (v[*i] == '?') {
        (*i)++;
        if (*i >= len || (v[*i] != '0' && v[*i] != '1')) return 0;

        *is_bool = 1;
        *bool_value = v[*i] == '1';
        (*i)++;

        return 1;
    }

    if (v[*i] == '"') {
        (*i)++;
        while (*i < len && v[*i] != '"') {
            if (v[*i] == '\\') (*i)++;      /* the escaped octet, whatever it is */
            if (*i >= len || !__visible(v[*i])) return 0;
            (*i)++;
        }
        if (*i >= len) return 0;            /* no closing quote */
        (*i)++;

        return 1;
    }

    /* Everything else -- integers, decimals, tokens, byte sequences -- runs to
     * the end of the member. Only the integer form is interpreted; the rest is
     * accepted and skipped, because refusing a legal value would kill a
     * connection over a member we were going to ignore anyway. */
    const size_t start = *i;
    size_t digits = start;
    int negative = 0;

    if (*i < len && v[*i] == '-') { negative = 1; digits = *i + 1; }

    /* The value ends at the member separator, at its first parameter, or at the
     * optional whitespace 8941 allows around the comma -- and that last one is
     * not a detail: with the space swallowed, "u=2 , i" left an integer that
     * did not parse as one, and the urgency was silently dropped. */
    while (*i < len && v[*i] != ',' && v[*i] != ';' && v[*i] != ' ') {
        if (!__visible(v[*i])) return 0;
        (*i)++;
    }

    if (*i == start) return 0;              /* "u=" with nothing after it */

    size_t j = digits;
    long value = 0;
    while (j < *i && v[j] >= '0' && v[j] <= '9') {
        value = value * 10 + (v[j] - '0');
        if (value > 1000000) value = 1000000;   /* saturate; out of range either way */
        j++;
    }

    if (j == *i && j > digits) {
        *is_int = 1;
        *int_value = negative ? -value : value;
    }

    return 1;
}

int h3priority_parse(const uint8_t* value, size_t len, h3priority_t* out) {
    if (out == NULL) return 0;

    h3priority_defaults(out);

    if (value == NULL) return len == 0;

    /* Members are collected here and published only on success. A dictionary
     * that goes wrong after a member we understood -- "u=7, 7;q=0.5" -- would
     * otherwise leave `out` holding that member while the return value says the
     * whole value was rejected, and a caller that trusts one and not the other
     * would prioritise a stream from a value it refused. No caller does today;
     * both discard `out` on 0. Found by tests/fuzz h3_priority in under a
     * minute, which is the argument for fixing the contract rather than the
     * callers (docs/http3/08 §7r). */
    h3priority_t result;
    h3priority_defaults(&result);

    size_t i = 0;
    while (i < len) {
        while (i < len && value[i] == ' ') i++;
        if (i == len) {                     /* blank, or trailing whitespace */
            *out = result;
            return 1;
        }

        const size_t key_start = i;
        if (!__key_char(value[i], 1)) return 0;
        while (++i < len && __key_char(value[i], 0)) {}
        const size_t key_len = i - key_start;

        /* A bare key is boolean true (§3.2), which is how `i` is normally
         * written -- "u=3, i" and "u=3, i=?1" are the same signal. */
        int is_bool = 1, bool_value = 1, is_int = 0;
        long int_value = 0;

        if (i < len && value[i] == '=') {
            i++;
            if (!__read_value(value, len, &i, &is_bool, &bool_value,
                              &is_int, &int_value))
                return 0;
        }

        /* Parameters (`;q=0.5`): legal, and nothing we act on. */
        while (i < len && value[i] != ',') {
            if (!__visible(value[i])) return 0;
            i++;
        }

        /* §4.1: a member of the wrong type, or out of range, is ignored -- not
         * an error. Killing a connection over `u=9` would turn a peer's
         * cosmetic bug into a failed page. */
        if (key_len == 1 && value[key_start] == 'u') {
            if (is_int && int_value >= 0 && int_value <= H3_PRIORITY_URGENCY_MAX) {
                result.urgency = (uint8_t)int_value;
                result.has_urgency = 1;
            }
        }
        else if (key_len == 1 && value[key_start] == 'i') {
            if (is_bool) {
                result.incremental = (uint8_t)(bool_value != 0);
                result.has_incremental = 1;
            }
        }

        if (i == len) {
            *out = result;
            return 1;
        }

        i++;                                /* the comma */
        if (i == len) return 0;             /* ... which must be followed by a member */
    }

    *out = result;

    return 1;
}

void h3priority_merge(h3priority_t* base, const h3priority_t* update) {
    if (base == NULL || update == NULL) return;

    if (update->has_urgency) {
        base->urgency = update->urgency;
        base->has_urgency = 1;
    }

    if (update->has_incremental) {
        base->incremental = update->incremental;
        base->has_incremental = 1;
    }
}

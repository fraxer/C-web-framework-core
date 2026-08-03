#include "h2field.h"

/* Field name octets (RFC 9110 §5.6.2 `tchar`, minus the uppercase letters that
 * RFC 9113 §8.2.1 bans on the wire).
 *
 * §8.2.1 itself only forbids 0x00-0x20, 0x41-0x5a and 0x7f-0xff, which would
 * leave ':', ',', '(' and friends legal inside a name. This table is the
 * stricter `tchar` rule instead, for two reasons: RFC 9110 §5.1 defines a field
 * name as a token in the first place, so nothing legitimate is lost; and a name
 * carrying an interior ':' is the h1.1 request-smuggling shape — "x:y: v"
 * re-serialised downstream reads as the field "x" with the value "y: v". It is
 * also what nghttp2 enforces, so it is the behaviour every browser is already
 * talking to.
 *
 * A leading ':' (pseudo-header) is handled separately, not by this table. */
static const unsigned char h2_tchar[256] = {
    /* 0x21 '!' */ ['!'] = 1, ['#'] = 1, ['$'] = 1, ['%'] = 1, ['&'] = 1,
    ['\''] = 1, ['*'] = 1, ['+'] = 1, ['-'] = 1, ['.'] = 1,
    ['^'] = 1, ['_'] = 1, ['`'] = 1, ['|'] = 1, ['~'] = 1,
    ['0'] = 1, ['1'] = 1, ['2'] = 1, ['3'] = 1, ['4'] = 1,
    ['5'] = 1, ['6'] = 1, ['7'] = 1, ['8'] = 1, ['9'] = 1,
    ['a'] = 1, ['b'] = 1, ['c'] = 1, ['d'] = 1, ['e'] = 1, ['f'] = 1,
    ['g'] = 1, ['h'] = 1, ['i'] = 1, ['j'] = 1, ['k'] = 1, ['l'] = 1,
    ['m'] = 1, ['n'] = 1, ['o'] = 1, ['p'] = 1, ['q'] = 1, ['r'] = 1,
    ['s'] = 1, ['t'] = 1, ['u'] = 1, ['v'] = 1, ['w'] = 1, ['x'] = 1,
    ['y'] = 1, ['z'] = 1,
};

int h2_field_name_valid(const char* name, size_t len) {
    if (name == NULL || len == 0) return 0;

    /* Pseudo-header: the ':' is part of the name, the remainder is an ordinary
     * token. ":" alone is not a name. */
    size_t i = 0;
    if (name[0] == ':') {
        if (len == 1) return 0;
        i = 1;
    }

    for (; i < len; i++)
        if (!h2_tchar[(unsigned char)name[i]]) return 0;

    return 1;
}

int h2_field_value_valid(const char* value, size_t len) {
    if (len == 0) return 1; /* an empty value is legal */
    if (value == NULL) return 0;

    /* §8.2.1: a value must not start or end with SP or HTAB. HPACK carries the
     * bytes verbatim, unlike HTTP/1.1 where the framing strips leading OWS, so
     * this is a check only HTTP/2 needs. */
    const char first = value[0];
    const char last = value[len - 1];
    if (first == ' ' || first == '\t' || last == ' ' || last == '\t') return 0;

    for (size_t i = 0; i < len; i++) {
        const unsigned char c = (unsigned char)value[i];

        /* NUL, CR and LF are named by §8.2.1. The rest of the C0 controls and
         * DEL go with them: they are not `field-vchar` (RFC 9110 §5.5) either,
         * and the same log- and terminal-mangling arguments apply. HTAB (0x09)
         * is legal inside a value and stays.
         *
         * 0x80-0xff are left alone — RFC 9110 allows obs-text, and rejecting it
         * would break clients that put raw UTF-8 in a filename. */
        if (c == 0x7f) return 0;
        if (c < 0x20 && c != '\t') return 0;
    }

    return 1;
}

h2_field_status_e h2_field_validate(const char* name, size_t name_len,
                                    const char* value, size_t value_len) {
    if (!h2_field_name_valid(name, name_len)) return H2_FIELD_BAD_NAME;
    if (!h2_field_value_valid(value, value_len)) return H2_FIELD_BAD_VALUE;

    return H2_FIELD_OK;
}

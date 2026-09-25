#include <stdlib.h>
#include <string.h>

#include "utf8.h"

#include "cstr.h"
#include "cstr_internal.h"

static int is_space_codepoint(uint32_t codepoint);

/**
 * @brief Whitespace in the Unicode sense, not the ASCII one.
 *
 * The set is spelled out rather than taken from utf8_is_space(): cleaning must
 * not change behaviour along with the libunistring version, and the makeup of
 * White_Space has been revised over the history of Unicode. Zero-width
 * characters and the BOM are not here -- formally they are not spaces, and
 * cstr_is_control_codepoint removes them.
 */
int is_space_codepoint(uint32_t codepoint) {
    if (codepoint == 0x20) return 1;
    if (codepoint >= 0x09 && codepoint <= 0x0D) return 1;     /* TAB..CR */
    if (codepoint >= 0x2000 && codepoint <= 0x200A) return 1; /* EN QUAD..HAIR SPACE */

    switch (codepoint) {
    case 0x85:      /* NEL */
    case 0xA0:      /* NBSP -- almost always arrives pasted from a word processor */
    case 0x1680:    /* OGHAM SPACE MARK */
    case 0x2028:    /* LINE SEPARATOR */
    case 0x2029:    /* PARAGRAPH SEPARATOR */
    case 0x202F:    /* NARROW NO-BREAK SPACE */
    case 0x205F:    /* MEDIUM MATHEMATICAL SPACE */
    case 0x3000:    /* IDEOGRAPHIC SPACE */
        return 1;
    default:
        return 0;
    }
}

/**
 * @brief A control or invisible character.
 *
 * Tab and the line breaks do not count: in a multi-line field they carry
 * meaning, and in a single-line one cstr_strip_newlines removes them
 * separately.
 */
int cstr_is_control_codepoint(uint32_t codepoint) {
    if (codepoint == 0x09 || codepoint == 0x0A || codepoint == 0x0D) return 0;

    if (codepoint < 0x20 || codepoint == 0x7F) return 1;      /* C0 and DEL */
    if (codepoint >= 0x80 && codepoint <= 0x9F) return 1;     /* C1 */
    if (codepoint >= 0x200B && codepoint <= 0x200F) return 1; /* ZWSP..RLM */
    if (codepoint >= 0x202A && codepoint <= 0x202E) return 1; /* LRE..RLO */
    if (codepoint >= 0x2066 && codepoint <= 0x2069) return 1; /* LRI..PDI */
    if (codepoint == 0xFEFF) return 1;                        /* BOM */

    return 0;
}

/* --- Cleaning ----------------------------------------------------------- */

char* cstr_clean(char* value, int flags) {
    if (value == NULL) return NULL;

    /* The order is fixed and does not depend on the order of the flags; it is
     * spelled out in the header too. Trimming is last -- until then spaces
     * keep appearing at the edges. */
    if (flags & CSTR_CLEAN_UTF8) value = cstr_sanitize_utf8(value);
    if (flags & CSTR_CLEAN_CONTROL) value = cstr_strip_control(value);
    if (flags & CSTR_CLEAN_NEWLINES) value = cstr_strip_newlines(value);
    if (flags & CSTR_CLEAN_COLLAPSE) value = cstr_collapse_spaces(value);
    if (flags & CSTR_CLEAN_LOWER) value = cstr_lower_ascii(value);
    if (flags & CSTR_CLEAN_TRIM) value = cstr_trim(value);

    return value;
}

char* cstr_clean_copy(const char* value, int flags) {
    if (value == NULL) return NULL;

    char* copy = strdup(value);
    if (copy == NULL) return NULL;

    char* cleaned = cstr_clean(copy, flags);

    /* cstr_trim moves the start into the buffer, and free() only accepts the
     * start of the block -- so the result moves back to the front of it. */
    if (cleaned != copy) memmove(copy, cleaned, strlen(cleaned) + 1);

    return copy;
}

char* cstr_ltrim(char* value) {
    if (value == NULL) return NULL;

    unsigned char* start = (unsigned char*)value;

    while (*start) {
        uint32_t codepoint;
        const size_t size = utf8_decode(start, &codepoint);

        /* A broken byte is not whitespace: trimming stops on it. */
        if (size == 0 || !is_space_codepoint(codepoint)) break;

        start += size;
    }

    return (char*)start;
}

char* cstr_rtrim(char* value) {
    if (value == NULL) return NULL;

    unsigned char* p = (unsigned char*)value;
    unsigned char* cut = p; /* end of the last non-space character */

    while (*p) {
        uint32_t codepoint;
        const size_t size = utf8_decode(p, &codepoint);

        if (size == 0) {
            p++;
            cut = p;
            continue;
        }

        p += size;
        if (!is_space_codepoint(codepoint)) cut = p;
    }

    *cut = 0;

    return value;
}

char* cstr_trim(char* value) {
    return cstr_ltrim(cstr_rtrim(value));
}

char* cstr_collapse_spaces(char* value) {
    if (value == NULL) return NULL;

    const unsigned char* in = (const unsigned char*)value;
    char* out = value;
    int previous_is_space = 0;

    while (*in) {
        uint32_t codepoint;
        const size_t size = utf8_decode(in, &codepoint);

        if (size > 0 && is_space_codepoint(codepoint)) {
            /* A run of any length made of any whitespace yields one 0x20 byte,
             * so writing never catches up with reading. */
            if (!previous_is_space) *out++ = ' ';

            previous_is_space = 1;
            in += size;
            continue;
        }

        previous_is_space = 0;

        const size_t step = size > 0 ? size : 1;
        for (size_t i = 0; i < step; i++) *out++ = (char)*in++;
    }

    *out = 0;

    return value;
}

char* cstr_strip_control(char* value) {
    if (value == NULL) return NULL;

    const unsigned char* in = (const unsigned char*)value;
    char* out = value;

    while (*in) {
        uint32_t codepoint;
        const size_t size = utf8_decode(in, &codepoint);

        /* A byte that belongs to no valid sequence goes too. Kept, it would
         * meet whatever follows the controls removed next to it: C2 [04] 80
         * came out as U+0080, a C1 control in a string just cleaned of them
         * (found by fuzz_text). */
        if (size == 0) {
            in++;
            continue;
        }

        if (cstr_is_control_codepoint(codepoint)) {
            in += size;
            continue;
        }

        for (size_t i = 0; i < size; i++) *out++ = (char)*in++;
    }

    *out = 0;

    return value;
}

char* cstr_strip_newlines(char* value) {
    if (value == NULL) return NULL;

    /* Byte-wise: CR and LF cannot occur inside a multi-byte sequence, every
     * byte of which has the high bit set. */
    const char* in = value;
    char* out = value;

    while (*in) {
        if (*in == '\r' || *in == '\n') {
            /* The run is skipped BEFORE writing: reading and writing share one
             * buffer, and a space put down earlier would be read right back as
             * the end of the run -- out would overtake in and leave the
             * buffer. */
            while (*in == '\r' || *in == '\n') in++;

            *out++ = ' ';
            continue;
        }

        *out++ = *in++;
    }

    *out = 0;

    return value;
}

char* cstr_sanitize_utf8(char* value) {
    if (value == NULL) return NULL;

    const unsigned char* in = (const unsigned char*)value;
    char* out = value;

    while (*in) {
        uint32_t codepoint;
        const size_t size = utf8_decode(in, &codepoint);

        if (size == 0) {
            in++;
            continue;
        }

        for (size_t i = 0; i < size; i++) *out++ = (char)*in++;
    }

    *out = 0;

    return value;
}

char* cstr_keep_chars(char* value, const char* charset) {
    if (value == NULL || charset == NULL) return value;

    const char* in = value;
    char* out = value;

    for (; *in; in++)
        if (strchr(charset, *in) != NULL) *out++ = *in;

    *out = 0;

    return value;
}

char* cstr_remove_chars(char* value, const char* charset) {
    if (value == NULL || charset == NULL) return value;

    const char* in = value;
    char* out = value;

    for (; *in; in++)
        if (strchr(charset, *in) == NULL) *out++ = *in;

    *out = 0;

    return value;
}

char* cstr_truncate(char* value, size_t max_length) {
    if (value == NULL) return NULL;

    unsigned char* p = (unsigned char*)value;

    for (size_t length = 0; *p && length < max_length; length++) {
        uint32_t codepoint;
        const size_t size = utf8_decode(p, &codepoint);

        p += size > 0 ? size : 1;
    }

    *p = 0;

    return value;
}

char* cstr_lower_ascii(char* value) {
    if (value == NULL) return NULL;

    for (char* p = value; *p; p++)
        if (*p >= 'A' && *p <= 'Z') *p = (char)(*p - 'A' + 'a');

    return value;
}

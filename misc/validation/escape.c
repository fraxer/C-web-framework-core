#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "escape.h"
#include "utf8.h"

static char* html_escape_impl(const char* value, int multiline);

/**
 * @brief The shared part of html_escape() and html_escape_multiline().
 *
 * @param multiline turn line breaks into <br> instead of passing them through
 */
char* html_escape_impl(const char* value, int multiline) {
    if (value == NULL) return NULL;

    /* Worst case is 6 bytes per source byte: &quot; and &amp; are the longest,
     * and a line break yields "<br>\n", which is 5. */
    const size_t length = strlen(value);
    if (length > (SIZE_MAX - 1) / 6) return NULL;

    char* result = malloc(length * 6 + 1);
    if (result == NULL) return NULL;

    char* out = result;
    for (const char* p = value; *p; p++) {
        if (multiline && (*p == '\r' || *p == '\n')) {
            /* CRLF is one break, not two. */
            if (*p == '\r' && p[1] == '\n') p++;

            memcpy(out, "<br>\n", 5);
            out += 5;
            continue;
        }

        switch (*p) {
        case '&':  memcpy(out, "&amp;", 5);  out += 5; break;
        case '<':  memcpy(out, "&lt;", 4);   out += 4; break;
        case '>':  memcpy(out, "&gt;", 4);   out += 4; break;
        case '"':  memcpy(out, "&quot;", 6); out += 6; break;
        case '\'': memcpy(out, "&#39;", 5);  out += 5; break;
        default:   *out++ = *p;
        }
    }
    *out = 0;

    return result;
}

char* html_escape(const char* value) {
    return html_escape_impl(value, 0);
}

char* html_escape_multiline(const char* value) {
    return html_escape_impl(value, 1);
}

char* log_escape(const char* value) {
    if (value == NULL) return NULL;

    static const char hex[] = "0123456789abcdef";

    /* Worst case is 4 bytes per byte (\xNN). */
    const size_t length = strlen(value);
    if (length > (SIZE_MAX - 1) / 4) return NULL;

    char* result = malloc(length * 4 + 1);
    if (result == NULL) return NULL;

    char* out = result;
    for (const unsigned char* p = (const unsigned char*)value; *p;) {
        /* Printable ASCII as it is. */
        if (*p >= 0x20 && *p < 0x7F) {
            *out++ = (char)*p++;
            continue;
        }

        /* A whole, valid UTF-8 sequence passes through too -- Cyrillic has to
         * stay readable in the journal -- unless it is a C1 control. U+009B is
         * CSI, and a terminal showing the journal would start an escape
         * sequence on it; found by fuzz_text. A byte that is not part of a
         * valid sequence is escaped on its own: a lone 0x9B is the same CSI to
         * an 8-bit terminal. */
        uint32_t codepoint = 0;
        const size_t length = *p >= 0x80 ? utf8_decode(p, &codepoint) : 0;
        if (length > 0 && codepoint > 0x9F) {
            memcpy(out, p, length);
            out += length;
            p += length;
            continue;
        }

        const size_t escaped = length > 0 ? length : 1;
        for (size_t i = 0; i < escaped; i++, p++) {
            *out++ = '\\';
            *out++ = 'x';
            *out++ = hex[*p >> 4];
            *out++ = hex[*p & 0x0F];
        }
    }
    *out = 0;

    return result;
}

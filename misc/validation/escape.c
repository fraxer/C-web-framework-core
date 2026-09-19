#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "escape.h"

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
    for (const unsigned char* p = (const unsigned char*)value; *p; p++) {
        /* Bytes with the high bit set pass through unchanged: they are parts
         * of UTF-8 sequences, and breaking them into \xNN would make Cyrillic
         * unreadable in the journal. */
        if (*p >= 0x20 && *p != 0x7F) {
            *out++ = (char)*p;
            continue;
        }

        *out++ = '\\';
        *out++ = 'x';
        *out++ = hex[*p >> 4];
        *out++ = hex[*p & 0x0F];
    }
    *out = 0;

    return result;
}

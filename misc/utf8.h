#ifndef __UTF8__
#define __UTF8__

#include <stdint.h>
#include <stddef.h>

/**
 * UTF-8 utility functions backed by libunistring.
 *
 * All functions accept const char* (null-terminated UTF-8 strings) and
 * are independent of the str_t type. Functions that return char* allocate
 * memory via malloc(); the caller must free() the result.
 *
 * NULL input is safe: functions return 0 or NULL as appropriate.
 */

/* Normalization forms for utf8_normalize() */
#define UTF8_NFC  0  /* Canonical Composition */
#define UTF8_NFD  1  /* Canonical Decomposition */

/* --- Character classification (operates on codepoints) --- */

int utf8_is_alpha(uint32_t codepoint);
int utf8_is_digit(uint32_t codepoint);
int utf8_is_space(uint32_t codepoint);
int utf8_is_upper(uint32_t codepoint);
int utf8_is_lower(uint32_t codepoint);
int utf8_is_punct(uint32_t codepoint);

/* --- String operations --- */

/**
 * Count Unicode characters (codepoints) in a UTF-8 string.
 * Returns 0 if str is NULL.
 */
size_t utf8_strlen(const char *str);

/**
 * Convert a UTF-8 string to uppercase.
 * Returns newly allocated string (caller must free), or NULL on error.
 */
char *utf8_toupper(const char *str);

/**
 * Convert a UTF-8 string to lowercase.
 * Returns newly allocated string (caller must free), or NULL on error.
 */
char *utf8_tolower(const char *str);

/**
 * Case-insensitive comparison of two UTF-8 strings.
 * Returns 0 if equal (ignoring case), negative if a < b, positive if a > b.
 * Returns 0 if either argument is NULL.
 */
int utf8_casecmp(const char *a, const char *b);

/**
 * Normalize a UTF-8 string (UTF8_NFC or UTF8_NFD).
 * Returns newly allocated string (caller must free), or NULL on error.
 */
char *utf8_normalize(const char *str, int form);

/* --- Codepoint iterator --- */

typedef struct {
    const uint8_t *pos;  /* Current position in the string */
    const uint8_t *end;  /* End of the string (null terminator) */
} utf8_iter_t;

/**
 * Initialize a codepoint iterator over a UTF-8 string.
 */
void utf8_iter_init(utf8_iter_t *iter, const char *str);

/**
 * Advance the iterator and return the next Unicode codepoint.
 * Returns 0 when iteration is complete.
 */
uint32_t utf8_iter_next(utf8_iter_t *iter);

#endif /* __UTF8__ */

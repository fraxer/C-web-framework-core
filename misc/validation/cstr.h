#ifndef CWFR_CSTR_H
#define CWFR_CSTR_H

#include <stddef.h>

/* Tidying up what arrived from a form.
 *
 * Cleaning works in place and only ever shortens the string, so calls can be
 * chained over one buffer and the result never has to be freed. A function
 * returns the start of the cleaned string -- it may move forward (cstr_trim),
 * so keep the original pointer for free() and carry on with the returned one.
 * NULL in, NULL out.
 *
 * Cleaning comes first, validation second; see validation.h. Validating a
 * dirty string produces false rejections -- "Ivan " is longer than it looks,
 * and "ivan@mail.ru\r\n" is not an address at all.
 *
 * Lengths are counted in UTF-8 CHARACTERS rather than bytes, because form
 * limits are written in characters and forms are filled in in Russian: by
 * bytes, "Александр" is already 18. A broken sequence counts as one character.
 */

/* --- Flags for cstr_clean ------------------------------------------------
 *
 * Applied in a fixed order regardless of how they are listed:
 * UTF8 -> CONTROL -> NEWLINES -> COLLAPSE -> LOWER -> TRIM. Trimming is last
 * so that it removes the spaces that appear at the edges once newlines have
 * been replaced and runs collapsed.
 */
#define CSTR_CLEAN_UTF8      (1 << 0)  /* drop invalid sequences */
#define CSTR_CLEAN_CONTROL   (1 << 1)  /* drop control and invisible characters */
#define CSTR_CLEAN_NEWLINES  (1 << 2)  /* a run of CR/LF becomes one space */
#define CSTR_CLEAN_COLLAPSE  (1 << 3)  /* a run of whitespace becomes one U+0020 */
#define CSTR_CLEAN_LOWER     (1 << 4)  /* ASCII letters to lower case */
#define CSTR_CLEAN_TRIM      (1 << 5)  /* strip whitespace at both ends */

/* A single-line text field: name, phone, subject, address. Such a field cannot
 * contain line breaks, so they turn into spaces -- which also closes header
 * injection if the value ends up in a mail subject. */
#define CSTR_CLEAN_TEXT      (CSTR_CLEAN_UTF8 | CSTR_CLEAN_CONTROL | \
                              CSTR_CLEAN_NEWLINES | CSTR_CLEAN_COLLAPSE | CSTR_CLEAN_TRIM)

/* A multi-line field: a comment, a message. Splitting into paragraphs is part
 * of the meaning, so CR/LF survive while the noise around them does not. */
#define CSTR_CLEAN_MULTILINE (CSTR_CLEAN_UTF8 | CSTR_CLEAN_CONTROL | CSTR_CLEAN_TRIM)

/* A mail address: a text field plus lower case. The domain is
 * case-insensitive per RFC 1035; the local part formally is not, but no mail
 * server in service makes use of that, and one spelling is what keeps
 * Ivan@mail.ru and ivan@mail.ru from being two different people in the
 * database. */
#define CSTR_CLEAN_EMAIL     (CSTR_CLEAN_TEXT | CSTR_CLEAN_LOWER)

/* --- Cleaning ----------------------------------------------------------- */

/* Applies a set of cleanings at once. This is what is wanted almost always;
 * the individual functions below are for the cases a set does not cover. */
char* cstr_clean(char* value, int flags);

/* The same, but on a copy: for a const source, or one that has to outlive the
 * cleaning. Returns an allocated string (free it) or NULL. */
char* cstr_clean_copy(const char* value, int flags);

/* Strips whitespace at the edges (the equivalent of Django's strip=True).
 * Whitespace means Unicode whitespace, not just ASCII: NBSP, the narrow
 * no-break space and whatever else arrives pasted from a word processor go
 * too. BOM and zero-width characters are NOT included here -- those are
 * cstr_strip_control's job. */
char* cstr_trim(char* value);
char* cstr_ltrim(char* value);
char* cstr_rtrim(char* value);

/* Replaces every run of whitespace with a single U+0020.
 * "Ivan   Petrov" and "Ivan\t Petrov" both become "Ivan Petrov". */
char* cstr_collapse_spaces(char* value);

/* Drops control characters (C0 except \t \n \r, DEL, C1) and invisible ones:
 * BOM, zero-width, the bidirectional marks. The last are worth removing for
 * more than tidiness -- an RLO reverses how a line is shown and passes one
 * string off as another in a letter a human reads. */
char* cstr_strip_control(char* value);

/* Replaces every run of CR/LF with a single space. Needed for anything that
 * may reach a mail header, where a line break starts a new header. */
char* cstr_strip_newlines(char* value);

/* Drops invalid UTF-8 sequences and keeps everything else. Without it, broken
 * input travels on into the JSON response and the body of the letter. */
char* cstr_sanitize_utf8(char* value);

/* Keeps only the bytes in the set / drops the bytes in the set. The set is an
 * ASCII string. The work is byte-wise: cstr_keep_chars drops any non-ASCII
 * character whole (which is what a phone needs --
 * cstr_keep_chars(phone, "0123456789+")), while cstr_remove_chars never
 * touches one. */
char* cstr_keep_chars(char* value, const char* charset);
char* cstr_remove_chars(char* value, const char* charset);

/* Keeps at most max_length characters, cutting on a character boundary rather
 * than a byte. Truncating instead of rejecting makes sense where the length
 * carries no meaning: a User-Agent going into a log, a mail subject. For a
 * form field, returning an error is the right answer. */
char* cstr_truncate(char* value, size_t max_length);

/* ASCII letters to lower case; bytes with the high bit set are left alone, so
 * Cyrillic survives unchanged. For Cyrillic there is utf8_tolower() in
 * utf8.h -- it allocates, which is why it cannot serve for cleaning in
 * place, and why both functions exist. */
char* cstr_lower_ascii(char* value);

#endif

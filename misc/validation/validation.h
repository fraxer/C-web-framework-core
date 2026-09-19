#ifndef CWFR_VALIDATION_H
#define CWFR_VALIDATION_H

#include <stddef.h>
#include <stdint.h>

/* Checking what arrived from a form.
 *
 * These functions change nothing and allocate nothing; each returns 1 (good)
 * or 0. NULL is always 0.
 *
 * Cleaning comes first, checking second -- see cstr.h. Checking a dirty string
 * produces false rejections: "Ivan " is longer than it looks, and
 * "ivan@mail.ru\r\n" is not an address at all.
 *
 * Lengths are counted in UTF-8 characters by utf8_strlen() from utf8.h, where
 * a broken sequence counts as one character.
 */

/* 1 if the string is valid UTF-8 throughout: no truncation, no overlong
 * forms, no surrogates and nothing above U+10FFFF. The alternative to
 * cstr_sanitize_utf8() where broken input is better rejected than quietly
 * repaired. */
int validate_utf8(const char* value);

/* 1 if the string is neither NULL nor empty. Called AFTER cleaning: a string
 * of nothing but spaces is already empty by then. */
int validate_not_empty(const char* value);

/* 1 if the length in characters falls within the bounds.
 * max_length == 0 means there is no upper bound. */
int validate_length(const char* value, size_t min_length, size_t max_length);

/* 1 if the address is syntactically correct (RFC 5322/1035 to the extent
 * worth checking on a feedback form). MX records are not consulted. */
int validate_email(const char* email);

/* 1 if this looks like a phone number: an optional leading "+", then digits
 * and the separators " ()-.", 7 to 15 digits in total (the E.164 ceiling).
 * The check is deliberately weak -- a strict one turns away real people with
 * an extension, and somebody is going to dial it by hand anyway. */
int validate_phone(const char* value);

/* 1 if this is an http/https link with a domain name (not an IP and not
 * localhost: the domain part is checked by the same code as in an address),
 * an optional port and printable ASCII in the remainder. */
int validate_url(const char* value);

/* 1 if the string holds no control or invisible characters -- the same ones
 * cstr_strip_control() removes. */
int validate_no_control(const char* value);

/* A codepoint predicate for validate_charset(). */
typedef int (*validate_char_fn)(uint32_t codepoint);

/* 1 if every character of the string is accepted by the predicate. A broken
 * sequence fails at once. An empty string passes: being required is a
 * separate check. */
int validate_charset(const char* value, validate_char_fn allowed);

/* Ready-made predicates. validate_char_letter leans on libunistring's
 * classification, so it knows about Cyrillic and not only about Latin. */
int validate_char_letter(uint32_t codepoint);
int validate_char_digit(uint32_t codepoint);
int validate_char_letter_or_digit(uint32_t codepoint);
/* Letters, the space and what actually occurs in names: the hyphen (Unicode
 * ones included), the apostrophe (the typographic one included), the dot. */
int validate_char_name(uint32_t codepoint);
int validate_char_phone(uint32_t codepoint);
int validate_char_ascii_printable(uint32_t codepoint);

/* Counts the links in a text: "http://", "https://" and "www." regardless of
 * case; whatever starts with any of them counts as one link up to the nearest
 * whitespace, so "https://www.example.com" is one and not two.
 *
 * A limit on the number of links is the cheapest spam filter there is, and it
 * catches what a per-IP limit does not: a distributed mailing arrives from a
 * different address every time, but a link in the text is there almost always.
 * The threshold belongs to the handler rather than to the validator: for a
 * feedback form "0 links" is usually right, for a job application it is
 * not. */
size_t count_links(const char* value);

#endif

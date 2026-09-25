#ifndef CWFR_ESCAPE_H
#define CWFR_ESCAPE_H

/* Escaping belongs to the PLACE OF OUTPUT, not to the field. The same value is
 * escaped differently in the body of a letter, in a link and in a log, which
 * is why "clean it on the way in and stop thinking about it" does not work:
 * cleaning removes rubbish, escaping decides how a particular recipient will
 * read the value. Hence the rule -- one function per context, called at the
 * moment of substitution.
 *
 * Only the contexts the core does not already cover live here. The rest:
 *
 *   JSON response  -- json_create_string() escapes while serializing;
 *                     escaping the value beforehand yields \\u0026.
 *   URL and query  -- urlencode() from helpers.h.
 *   Mail headers   -- mail.c encodes the subject and the sender name per
 *                     RFC 2047 (=?UTF-8?B?...?=), and base64 settles the
 *                     question of CRLF in a header along the way.
 *   SQL            -- there is no escaping and will not be: the model binds
 *                     values as named parameters (:name), and assembling a
 *                     query by string concatenation around that is not
 *                     allowed.
 */

/* HTML escaping for substitution into the body of a letter or into a page.
 * Escapes & < > " ', which covers both text and a quoted attribute value. For
 * an ADDRESS in href this is not enough: "javascript:..." contains none of
 * these characters -- the scheme is checked by validate_url().
 *
 * Returns an allocated string (free it) or NULL when out of memory. */
char* html_escape(const char* value);

/* The same, but line breaks turn into <br>. Needed for a multi-line field: in
 * HTML a line break is a space, and the paragraphs a person typed into the
 * form never reach the recipient. CRLF counts as one break. */
char* html_escape_multiline(const char* value);

/* Escaping for a log entry: control characters (C0, DEL and C1) and every
 * byte that is not part of a valid UTF-8 sequence turn into \xNN, and
 * everything else is left as it is (Cyrillic stays readable in the log). C1
 * matters as much as C0: U+009B is CSI to a terminal showing the journal.
 * Without it a line break inside a value forges a journal line -- the user
 * writes into the log whatever they like. Better to limit the length first
 * with cstr_truncate(): the journal does not need the whole field.
 *
 * Returns an allocated string (free it) or NULL when out of memory. */
char* log_escape(const char* value);

#endif

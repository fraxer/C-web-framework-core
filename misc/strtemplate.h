#ifndef __STRTEMPLATE__
#define __STRTEMPLATE__

#include <stddef.h>

/* A string with {N} placeholders, where N is the number of a PCRE capture
 * group. Two config settings share the syntax -- a redirect destination and a
 * route's static_file -- so the parse and the substitution live here rather
 * than in either of them.
 *
 * Only decimal digits make a placeholder: "{name}" and "{}" are literal text,
 * which is what keeps a template that merely contains braces from failing to
 * load. A number of more than two digits is an error, because no location has
 * a hundred capture groups and the value is far more likely to be a typo. */

typedef struct strtemplate strtemplate_t;

/* NULL on an empty source, a malformed placeholder, or allocation failure. */
strtemplate_t* strtemplate_create(const char* source);
void strtemplate_free(strtemplate_t* tpl);

/* How many placeholders the source had, and the largest group number among
 * them. Both are 0 for a template of plain text; the caller compares them with
 * the capture count of its compiled location. */
int strtemplate_params_count(const strtemplate_t* tpl);
int strtemplate_max_param(const strtemplate_t* tpl);

/* Expand against the output vector of a pcre_exec over `subject`. A group that
 * did not participate in the match contributes nothing, so the vector must have
 * its offsets pre-set to -1 for the groups pcre_exec left untouched. Returns a
 * new null-terminated string for the caller to free, or NULL on allocation
 * failure. `vector` may be NULL when the template has no placeholders. */
char* strtemplate_expand(const strtemplate_t* tpl, const char* subject, const int* vector);

#endif

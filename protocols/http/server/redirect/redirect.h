#ifndef __REDIRECT__
#define __REDIRECT__

#include <pcre2.h>
#include <stddef.h>

#include "strtemplate.h"

enum redirect_status {
    REDIRECT_OUT_OF_MEMORY,
    REDIRECT_LOOP_CYCLE,
    REDIRECT_FOUND,
    REDIRECT_NOT_FOUND,
    REDIRECT_BAD_REQUEST
};

typedef struct redirect {
    int location_erroffset;
    /* The location is plain text: matching it is a substring search, not a
     * regex run. Most redirects in a configuration look like "/user" —
     * running PCRE for them showed up on the request path next to the vhost
     * and route matching (docs/http2/10 §10.6). */
    int is_literal;
    char* literal;
    size_t literal_length;
    /* Placeholders in the destination; the http server sizes the pcre_exec
     * output vector from it, and redirect_create refuses a destination whose
     * count does not match the capture count of the location. */
    int params_count;
    const char* location_error;
    pcre2_code* location;
    strtemplate_t* destination;
    struct redirect* next;
} redirect_t;

redirect_t* redirect_create(const char*, const char*);

/* Does this redirect apply to `path`? Literal locations are searched for as a
 * substring — which is what an unanchored pattern of plain text means — and
 * everything else goes through PCRE, filling `vector` for the destination's
 * capture-group placeholders. */
int redirect_matches(redirect_t*, const char* path, size_t length, int* vector, int vector_size);

void redirect_free(redirect_t*);

char* redirect_get_uri(redirect_t*, const char*, int*);

/* The part of the request target a redirect to `target` should carry over: the
 * query string of `uri`, "?" included, or NULL when there is nothing to carry.
 *
 * Redirects are matched against the request's `path`, and the parser cut that
 * at the "?" (httpparser_set_uri): the query is kept apart, and the full target
 * lives in `request->uri`. Building the destination from `path` alone therefore
 * threw the query away -- `http://example.com/?utm_source=ya` arrived at
 * `https://example.com/`, and the label was gone. nginx writes the same rule
 * with $request_uri and keeps it.
 *
 * Nothing is carried onto a destination that has a query of its own: such a
 * destination states its parameters deliberately, and merging two sets would be
 * a surprise. Nor is a bare trailing "?" carried: it holds no parameters, and
 * appending it would leave a dangling character on the Location.
 *
 * The result points into `uri` and is not NUL-terminated; `*length` is how much
 * of it belongs to the query. */
const char* redirect_carry_query(const char* target, const char* uri, size_t uri_length, size_t* length);

/* redirect_get_uri with the request's query carried onto the result, by the
 * rule redirect_carry_query describes. This is what the http server calls: the
 * two steps are one function because the join reallocates the destination, and
 * an owner that changes hands mid-expression is the shape both a reader and
 * gcc's -fanalyzer have to squint at.
 *
 * `uri` is the request target as it arrived (query and all); `path` is the
 * matched path, which is what the destination's {N} placeholders expand
 * against. Returns a newly allocated string, or NULL when nothing could be
 * allocated. */
char* redirect_uri_with_query(redirect_t*, const char* path, int* vector,
                              const char* uri, size_t uri_length);

#endif

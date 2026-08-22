#ifndef __REDIRECT__
#define __REDIRECT__

#include <pcre.h>

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
    pcre* location;
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

#endif

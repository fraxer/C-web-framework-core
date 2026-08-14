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

void redirect_free(redirect_t*);

char* redirect_get_uri(redirect_t*, const char*, int*);

#endif

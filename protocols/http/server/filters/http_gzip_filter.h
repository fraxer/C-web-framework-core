#ifndef __HTTP_GZIP_FILTER__
#define __HTTP_GZIP_FILTER__

#include "httprequest.h"
#include "httpresponse.h"
#include "gzip.h"

/* Bodies smaller than this are not worth gzip's overhead, so the gzip filter
 * leaves them uncompressed. Shared with the not_modified filter, which must
 * predict the gzip filter's decision to tag the ETag (see HTTP_GZIP_ETAG). */
#define HTTP_GZIP_MIN_SIZE 1024

/* Suffix appended inside the ETag quotes for the gzipped representation, e.g.
 * W/"<mtime>-<size>" -> W/"<mtime>-<size>-gzip". Lets a revalidation tell the
 * gzip and identity representations of the same file apart. */
#define HTTP_GZIP_ETAG "-gzip"

typedef struct {
    http_module_t base;
    bufo_t* buf;
    gzip_t gzip;
} http_module_gzip_t;

http_filter_t* http_gzip_filter_create(void);

#endif

#ifndef __HTTP_GZIP_FILTER__
#define __HTTP_GZIP_FILTER__

#include "httpresponse.h"
#include "gzip.h"

typedef struct {
    http_module_t base;
    bufo_t* buf;
    gzip_t gzip;
} http_module_gzip_t;

http_filter_t* http_gzip_filter_create(void);

#endif

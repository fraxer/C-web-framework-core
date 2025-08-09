#ifndef __HTTP_RANGE_FILTER__
#define __HTTP_RANGE_FILTER__

#include "http1response.h"

typedef struct {
    http_module_t base;
    bufo_t* buf;
    size_t range_size;
    size_t range_pos;
} http_module_range_t;

http_filter_t* http_range_filter_create(void);

#endif

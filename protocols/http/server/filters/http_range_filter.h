#ifndef HTTP_RANGE_FILTER_H
#define HTTP_RANGE_FILTER_H

#include "httprequest.h"
#include "httpresponse.h"

typedef struct {
    http_module_t base;
    bufo_t* buf;
    size_t range_size;
    size_t range_pos;
} http_module_range_t;

http_filter_t* http_range_filter_create(void);

#endif

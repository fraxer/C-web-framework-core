#ifndef __HTTP_RANGE_FILTER__
#define __HTTP_RANGE_FILTER__

#include "http1response.h"

typedef struct {
    char* key;
    char* value;
    size_t key_length;
    size_t value_length;
} http_range_filter_t;

int http_range_header(http1response_t* response);
int http_range_body(http1response_t* response, bufo_t* buf);

#endif

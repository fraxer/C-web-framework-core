#ifndef __HTTP_NOT_MODIFIED_FILTER__
#define __HTTP_NOT_MODIFIED_FILTER__

#include "http1response.h"

typedef struct {
    char* key;
    char* value;
    size_t key_length;
    size_t value_length;
} http_not_modified_filter_t;

int http_not_modified_header(http1response_t* response);
int http_not_modified_body(http1response_t* response, bufo_t* buf);

#endif

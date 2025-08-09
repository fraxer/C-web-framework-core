#ifndef __HTTP_WRITE_FILTER__
#define __HTTP_WRITE_FILTER__

#include "http1response.h"

typedef struct {
    http_module_t base;
    bufo_t* buf;
} http_module_write_t;

http_filter_t* http_write_filter_create(void);
http_module_write_t* http_write_create(void);
void http_write_free(void* arg);
int http_write_header(http1response_t* response);
int http_write_body(http1response_t* response, bufo_t* buf);

#endif

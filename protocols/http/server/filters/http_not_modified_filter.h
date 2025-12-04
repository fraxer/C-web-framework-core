#ifndef __HTTP_NOT_MODIFIED_FILTER__
#define __HTTP_NOT_MODIFIED_FILTER__

#include "httpresponse.h"
#include "http_filter.h"

typedef struct {
    http_module_t base;
} http_module_not_modified_t;

http_filter_t* http_not_modified_filter_create(void);
http_module_not_modified_t* http_not_modified_create(void);
void http_not_modified_free(void* arg);
void http_not_modified_reset(void* arg);
int http_not_modified_header(httpresponse_t* response);
int http_not_modified_body(httpresponse_t* response, bufo_t* buf);

#endif

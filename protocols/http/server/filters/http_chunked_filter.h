#ifndef __HTTP_CHUNKED_FILTER__
#define __HTTP_CHUNKED_FILTER__

#include "httpresponse.h"

typedef enum {
    HTTP_MODULE_CHUNKED_SIZE = 0,
    HTTP_MODULE_CHUNKED_DATA,
    HTTP_MODULE_CHUNKED_SEP,
    HTTP_MODULE_CHUNKED_END,
} http_module_chunked_state_e;

typedef struct {
    http_module_t base;
    bufo_t* buf;
    http_module_chunked_state_e state;
    size_t state_pos;
    char* chunk_head;
    size_t chunk_head_size;
} http_module_chunked_t;

http_filter_t* http_chunked_filter_create(void);
http_module_chunked_t* http_chunked_create(void);
void http_chunked_free(void* arg);
int http_chunked_header(httpresponse_t* response);
int http_chunked_body(httpresponse_t* response, bufo_t* buf);

#endif

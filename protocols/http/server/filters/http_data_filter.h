#ifndef __HTTP_DATA_FILTER__
#define __HTTP_DATA_FILTER__

#include "httprequest.h"
#include "httpresponse.h"

typedef struct {
    http_module_t base;
    bufo_t* proxy_body_buf;
    /* Read position for the file path. pread() does not move the descriptor
     * offset, so progress is tracked here and reset to 0 between responses. */
    off_t file_offset;
} http_module_data_t;

http_filter_t* http_data_filter_create(void);

#endif

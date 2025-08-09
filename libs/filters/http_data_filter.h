#ifndef __HTTP_DATA_FILTER__
#define __HTTP_DATA_FILTER__

#include "http1response.h"

typedef struct {
    http_module_t base;
} http_module_data_t;

http_filter_t* http_data_filter_create(void);

#endif

#include "http_range_filter.h"

int http_range_header(http1response_t* response) {
    response->header_add(response, "Range", "bytes");

    if (response->cur_filter->next != NULL) {
        response->cur_filter = response->cur_filter->next;
        return response->cur_filter->handler_header(response);
    }

    return 0;
}

int http_range_body(http1response_t* response, bufo_t* buf) {
    return 0;
}

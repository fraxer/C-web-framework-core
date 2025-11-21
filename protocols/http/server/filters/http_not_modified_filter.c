#include "http_not_modified_filter.h"

int http_not_modified_header(httpresponse_t* response) {
    response->header_add(response, "Status", "304 Not Modified");

    if (response->cur_filter->next != NULL) {
        response->cur_filter = response->cur_filter->next;
        return response->cur_filter->handler_header(response);
    }

    return 0;
}

int http_not_modified_body(httpresponse_t* response, bufo_t* buf) {
    (void)response;
    (void)buf;

    return 0;
}

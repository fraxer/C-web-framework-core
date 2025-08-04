#include "http_filter.h"
#include "http_write_filter.h"
#include "http_chunked_filter.h"
#include "http_gzip_filter.h"
#include "http_range_filter.h"
#include "http_not_modified_filter.h"

http_filter_t* filters_create(void) {
    http_filter_t* filter_write = http_write_filter_create();
    http_filter_t* filter_chunked = http_chunked_filter_create();
    http_filter_t* filter_gzip = http_gzip_filter_create();

    filter_chunked->next = filter_write;
    filter_gzip->next = filter_chunked;

    return filter_gzip;
}

void filters_reset(http_filter_t* filter) {
    while (filter != NULL) {
        http_module_t* module = filter->module;
        module->reset(filter->module);

        filter = filter->next;
    }
}

void filters_free(http_filter_t* filter) {
    while (filter != NULL) {
        http_filter_t* next = filter->next;
        http_module_t* module = filter->module;
        module->free(filter->module);

        free(filter);

        filter = next;
    }
}

int filter_next_handler_header(http1response_t* response) {
    response->cur_filter = response->cur_filter->next;
    return response->cur_filter->handler_header(response);
}

int filter_next_handler_body(http1response_t* response, bufo_t* buf) {
    response->cur_filter = response->cur_filter->next;
    return response->cur_filter->handler_body(response, buf);
}

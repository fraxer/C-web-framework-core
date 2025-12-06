#include "http_filter.h"
#include "http_write_filter.h"
#include "http_chunked_filter.h"
#include "http_gzip_filter.h"
#include "http_data_filter.h"
#include "http_range_filter.h"
#include "http_not_modified_filter.h"

http_filter_t* filters_create(void) {
    http_filter_t* filter_write = http_write_filter_create();
    http_filter_t* filter_chunked = http_chunked_filter_create();
    http_filter_t* filter_gzip = http_gzip_filter_create();
    http_filter_t* filter_data = http_data_filter_create();
    http_filter_t* filter_range = http_range_filter_create();
    http_filter_t* filter_not_modified = http_not_modified_filter_create();

    filter_chunked->next = filter_write;
    filter_gzip->next = filter_chunked;
    filter_data->next = filter_gzip;
    filter_range->next = filter_data;
    filter_not_modified->next = filter_range;

    return filter_not_modified;
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

int filter_next_handler_header(struct httprequest* request, struct httpresponse* response) {
    response->cur_filter = response->cur_filter->next;
    return response->cur_filter->handler_header(request, response);
}

int filter_next_handler_body(struct httprequest* request, struct httpresponse* response, bufo_t* buf) {
    response->cur_filter = response->cur_filter->next;
    return response->cur_filter->handler_body(request, response, buf);
}

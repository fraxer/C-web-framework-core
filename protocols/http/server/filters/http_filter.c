#include "http_filter.h"
#include "http_write_filter.h"
#include "http_chunked_filter.h"
#include "http_gzip_filter.h"
#include "http_data_filter.h"
#include "http_range_filter.h"
#include "http_not_modified_filter.h"
#include "h2_write_filter.h"
#ifdef CWFR_HTTP3
#include "h3_write_filter.h"
#endif

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

http_filter_t* filters_create_h2(void) {
    http_filter_t* filter_write = h2_write_filter_create();
    http_filter_t* filter_gzip = http_gzip_filter_create();
    http_filter_t* filter_data = http_data_filter_create();
    http_filter_t* filter_range = http_range_filter_create();
    http_filter_t* filter_not_modified = http_not_modified_filter_create();

    if (filter_write == NULL || filter_gzip == NULL || filter_data == NULL ||
        filter_range == NULL || filter_not_modified == NULL) {
        /* Each stage is still detached (next == NULL), so free them one by one. */
        filters_free(filter_write);
        filters_free(filter_gzip);
        filters_free(filter_data);
        filters_free(filter_range);
        filters_free(filter_not_modified);
        return NULL;
    }

    filter_gzip->next = filter_write;
    filter_data->next = filter_gzip;
    filter_range->next = filter_data;
    filter_not_modified->next = filter_range;

    return filter_not_modified;
}

http_filter_t* filters_create_h3(void) {
#ifdef CWFR_HTTP3
    /* The same stages as h2 -- chunked is absent for the same reason, the body
     * is framed by the protocol -- with the h3 terminal stage. Kept as its own
     * function rather than a flag on filters_create_h2: the two terminal stages
     * share no code, and a build without HTTP/3 has no h3 stage to name. */
    http_filter_t* filter_write = h3_write_filter_create();
    http_filter_t* filter_gzip = http_gzip_filter_create();
    http_filter_t* filter_data = http_data_filter_create();
    http_filter_t* filter_range = http_range_filter_create();
    http_filter_t* filter_not_modified = http_not_modified_filter_create();

    if (filter_write == NULL || filter_gzip == NULL || filter_data == NULL ||
        filter_range == NULL || filter_not_modified == NULL) {
        filters_free(filter_write);
        filters_free(filter_gzip);
        filters_free(filter_data);
        filters_free(filter_range);
        filters_free(filter_not_modified);
        return NULL;
    }

    filter_gzip->next = filter_write;
    filter_data->next = filter_gzip;
    filter_range->next = filter_data;
    filter_not_modified->next = filter_range;

    return filter_not_modified;
#else
    return NULL;
#endif
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

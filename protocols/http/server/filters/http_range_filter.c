#include "string.h"

#include "http_range_filter.h"

#define BUF_SIZE 16384

static http_module_range_t* __create(void);
static void __free(void* arg);
static void __reset(void* arg);
static int __get_range(httprequest_t* request, httpresponse_t* response, http_module_range_t* module);
static ssize_t __get_file_range(httpresponse_t* response, http_module_range_t* module, size_t offset, size_t capacity, int* is_last);
static ssize_t __get_data_range(httpresponse_t* response, http_module_range_t* module, size_t offset, size_t capacity, int* is_last);
static int __header(httprequest_t* request, httpresponse_t* response);
static int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf);

http_filter_t* http_range_filter_create(void) {
    http_filter_t* filter = malloc(sizeof * filter);
    if (filter == NULL) return NULL;

    filter->handler_header = __header;
    filter->handler_body = __body;
    filter->module = __create();
    filter->next = NULL;

    if (filter->module == NULL) {
        free(filter);
        return NULL;
    }

    return filter;
}

http_module_range_t* __create(void) {
    http_module_range_t* module = malloc(sizeof * module);
    if (module == NULL) return NULL;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = __free;
    module->base.reset = __reset;
    module->buf = bufo_create();
    module->range_pos = 0;
    module->range_size = 0;

    if (module->buf == NULL) {
        __free(module);
        return NULL;
    }

    return module;
}

void __free(void* arg) {
    http_module_range_t* module = arg;

    bufo_free(module->buf);
    free(module);
}

void __reset(void* arg) {
    http_module_range_t* module = arg;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->range_pos = 0;
    module->range_size = 0;

    bufo_flush(module->buf);
}

int __get_range(httprequest_t* request, httpresponse_t* response, http_module_range_t* module) {
    const int is_file = response->file_.fd > -1;
    size_t data_size = response->body.size;
    if (is_file)
        data_size = response->file_.size;

    const ssize_t source_start = request->ranges->start;
    const ssize_t source_end = request->ranges->end;

    size_t start = (size_t)source_start;
    if (source_start == -1)
        start = data_size - (size_t)source_end;

    const size_t range_offset = start + module->range_pos;
    const size_t target_offset = range_offset < data_size ? range_offset : data_size;

    // Calculate remaining bytes to read
    const size_t remaining = module->range_size - module->range_pos;
    const size_t capacity = remaining < module->buf->capacity ? remaining : module->buf->capacity;

    int is_last = 0;
    const ssize_t r = is_file ? __get_file_range(response, module, target_offset, capacity, &is_last)
                             : __get_data_range(response, module, target_offset, capacity, &is_last);
    if (r < 0)
        return 0;

    module->range_pos += r;

    if (module->range_pos == module->range_size || is_last)
        module->buf->is_last = 1;

    bufo_reset_pos(module->buf);
    bufo_set_size(module->buf, r);

    return 1;
}

ssize_t __get_file_range(httpresponse_t* response, http_module_range_t* module, size_t offset, size_t capacity, int* is_last) {
    *is_last = 0;

    // Calculate how much data is actually available from the offset
    size_t available = 0;
    if (offset < response->file_.size) {
        available = response->file_.size - offset;
    }

    // Limit capacity to available data
    size_t read_size = capacity < available ? capacity : available;

    // If no data available from this offset, mark as last
    if (read_size == 0) {
        *is_last = 1;
        return 0;
    }

    lseek(response->file_.fd, offset, SEEK_SET);
    const ssize_t r = read(response->file_.fd, module->buf->data, read_size);

    // Check if we've read all remaining data
    if (r >= 0 && offset + (size_t)r >= response->file_.size)
        *is_last = 1;

    return r;
}

ssize_t __get_data_range(httpresponse_t* response, http_module_range_t* module, size_t offset, size_t capacity, int* is_last) {
    *is_last = 0;

    // Calculate how much data is actually available from the offset
    size_t available = 0;
    if (offset < response->body.size) {
        available = response->body.size - offset;
    }

    // Limit capacity to available data
    size_t copy_size = capacity < available ? capacity : available;

    if (copy_size > 0) {
        memcpy(module->buf->data, response->body.data + offset, copy_size);
    }

    // Check if we've copied all remaining data
    if (offset + copy_size >= response->body.size)
        *is_last = 1;

    return copy_size;
}

int __header(httprequest_t* request, httpresponse_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_range_t* module = cur_filter->module;

    if (request->ranges == NULL)
        return filter_next_handler_header(request, response);

    // Range requests only apply to successful responses (2xx)
    // Skip range processing for redirects (3xx), client errors (4xx), server errors (5xx)
    if (response->status_code < 200 || response->status_code >= 300)
        return filter_next_handler_header(request, response);

    if (response->last_modified)
        return filter_next_handler_header(request, response);

    int r = 0;

    if (module->base.cont)
        goto cont;

    response->content_encoding = CE_NONE;
    response->transfer_encoding = TE_NONE;
    response->range = 1;

    size_t data_size = response->body.size;
    if (response->file_.fd > -1)
        data_size = response->file_.size;

    const ssize_t source_start = request->ranges->start;
    const ssize_t source_end = request->ranges->end;

    if (source_start > (ssize_t)data_size)
        return CWF_ERROR;

    response->status_code = 206;

    size_t start = (size_t)source_start;
    size_t end = (size_t)source_end;
    if (source_start == -1) {
        end = data_size;
        start = data_size - (size_t)source_end;
    }
    else if (source_end == -1) {
        end = data_size;
    }
    else {
        // RFC 7233: end is inclusive in Range header, convert to exclusive
        end = end + 1;
        // Limit end to actual data size
        if (end > data_size) {
            end = data_size;
        }
    }

    module->range_size = end - start;

    char bytes[70] = {0};
    int size = snprintf(bytes, sizeof(bytes), "bytes %zu-%zu/%zu", start, end - 1, data_size);

    if (!response->add_headeru(response, "Content-Range", 13, bytes, size)) return CWF_ERROR;
    if (!response->add_content_length(response, end - start)) return CWF_ERROR;

    if (!bufo_alloc(module->buf, BUF_SIZE))
        return CWF_ERROR;

    cont:

    r = filter_next_handler_header(request, response);

    module->base.cont = 0;

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_range_t* module = cur_filter->module;
    module->base.parent_buf = parent_buf;

    if (!response->range)
        return filter_next_handler_body(request, response, parent_buf);

    if (response->last_modified)
        return filter_next_handler_body(request, response, parent_buf);

    int r = 0;
    bufo_t* buf = module->buf;

    if (module->base.cont)
        goto cont;

    bufo_reset_pos(buf);

    while (1) {
        response->cur_filter = cur_filter;

        if (!__get_range(request, response, module))
            return CWF_ERROR;

        bufo_reset_pos(buf);

        cont:

        r = filter_next_handler_body(request, response, buf);

        module->base.cont = 0;

        if (r == CWF_DATA_AGAIN) {
            if (buf->pos < buf->size)
                continue;

            if (buf->is_last)
                return CWF_OK;

            continue;
        }

        if (r == CWF_EVENT_AGAIN)
            module->base.cont = 1;

        return r;
    }

    return CWF_ERROR;
}

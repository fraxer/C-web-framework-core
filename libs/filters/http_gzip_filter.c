#include "http_gzip_filter.h"

#define BUF_SIZE 16384

static http_module_gzip_t* __create(void);
static void __free(void* arg);
static void __reset(void* arg);
static int __header(http1response_t* response);
static int __body(http1response_t* response, bufo_t* parent_buf);
static int __process(http_module_gzip_t* module, bufo_t* buf);

http_filter_t* http_gzip_filter_create(void) {
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

http_module_gzip_t* __create(void) {
    http_module_gzip_t* module = malloc(sizeof * module);
    if (module == NULL) return NULL;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = __free;
    module->base.reset = __reset;
    module->buf = bufo_create();

    if (module->buf == NULL) {
        __free(module);
        return NULL;
    }

    if (!gzip_init(&module->gzip)) {
        __free(module);
        return NULL;
    }

    return module;
}

void __free(void* arg) {
    http_module_gzip_t* module = arg;

    bufo_free(module->buf);
    gzip_free(&module->gzip);
    free(module);
}

void __reset(void* arg) {
    http_module_gzip_t* module = arg;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;

    bufo_flush(module->buf);
    gzip_free(&module->gzip);
}

int __header(http1response_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_gzip_t* module = cur_filter->module;

    if (response->content_encoding == CE_NONE)
        return filter_next_handler_header(response);

    int r = 0;

    if (module->base.cont)
        goto cont;

    if (response->header(response, "Content-Encoding") == NULL)
        response->header_add(response, "Content-Encoding", "gzip");

    response->transfer_encoding == TE_CHUNKED;

    if (!bufo_alloc(module->buf, BUF_SIZE))
        return CWF_ERROR;

    if (!gzip_deflate_init(&module->gzip))
        return CWF_ERROR;

    cont:

    r = filter_next_handler_header(response);

    module->base.cont = 0;

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int __body(http1response_t* response, bufo_t* parent_buf) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_gzip_t* module = cur_filter->module;
    module->base.parent_buf = parent_buf;

    if (response->content_encoding == CE_NONE)
        return filter_next_handler_body(response, parent_buf);

    int r = 0;
    bufo_t* buf = module->buf;

    if (module->base.cont)
        goto cont;

    bufo_reset_pos(buf);

    gzip_set_in(&module->gzip, parent_buf->data + parent_buf->pos, parent_buf->size - parent_buf->pos);

    while (1) {
        response->cur_filter = cur_filter;

        if (!__process(module, buf))
            return CWF_ERROR;

        bufo_reset_pos(buf);

        cont:

        r = filter_next_handler_body(response, buf);

        module->base.cont = 0;

        if (r == CWF_DATA_AGAIN) {
            if (gzip_want_continue(&module->gzip))
                continue;

            if (parent_buf->pos < parent_buf->size)
                continue;

            return r;
        }

        if (r == CWF_EVENT_AGAIN)
            module->base.cont = 1;

        return r;
    }

    return CWF_ERROR;
}

int __process(http_module_gzip_t* module, bufo_t* buf) {
    bufo_t* parent_buf = module->base.parent_buf;

    bufo_reset_pos(buf);
    bufo_reset_size(buf);

    const size_t compress_writed = gzip_deflate(&module->gzip, bufo_data(buf), buf->capacity, parent_buf->is_last);
    if (gzip_deflate_has_error(&module->gzip)) {
        printf("compress error\n");
        return 0;
    }

    const size_t processed = (parent_buf->size - parent_buf->pos) - module->gzip.stream.avail_in;

    bufo_set_size(buf, compress_writed);

    bufo_move_front_pos(parent_buf, processed);

    if (gzip_want_continue(&module->gzip))
        return 1;

    module->buf->is_last = parent_buf->is_last;

    return 1;
}
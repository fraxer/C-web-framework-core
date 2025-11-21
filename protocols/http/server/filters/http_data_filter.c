#include "http_data_filter.h"

#define BUF_SIZE 16384

static http_module_data_t* __create(void);
static void __free(void* arg);
static void __reset(void* arg);
static int __header(httpresponse_t* response);
static int __body(httpresponse_t* response, bufo_t* parent_buf);
static bufo_t* body_next_chunk_data(httpresponse_t* response, bufo_t* proxy_body_buf, int** ok);
static bufo_t* file_next_chunk_data(httpresponse_t* response, int** ok);
static bufo_t* next_chunk_data(httpresponse_t* response, bufo_t* proxy_body_buf, int* ok);

http_filter_t* http_data_filter_create(void) {
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

http_module_data_t* __create(void) {
    http_module_data_t* module = malloc(sizeof * module);
    if (module == NULL) return NULL;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = __free;
    module->base.reset = __reset;

    module->proxy_body_buf = bufo_create();
    if (module->proxy_body_buf == NULL) {
        __free(module);
        return NULL;
    }
    module->proxy_body_buf->is_proxy = 1;
    module->proxy_body_buf->capacity = BUF_SIZE;

    return module;
}

void __free(void* arg) {
    http_module_data_t* module = arg;

    if (module->proxy_body_buf != NULL)
        bufo_free(module->proxy_body_buf);

    free(module);
}

void __reset(void* arg) {
    http_module_data_t* module = arg;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;

    bufo_clear(module->proxy_body_buf);
    module->proxy_body_buf->is_proxy = 1;
}

int __header(httpresponse_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_data_t* module = cur_filter->module;
    int r = 0;

    if (module->base.cont)
        goto cont;

    if (!response->range && response->transfer_encoding == TE_NONE) {
        size_t data_size = response->body.size;
        if (response->file_.fd > -1)
            data_size = response->file_.size;

        if (!response->header_add_content_length(response, data_size))
            return CWF_ERROR;
    }

    cont:

    r = filter_next_handler_header(response);

    module->base.cont = 0;

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int __body(httpresponse_t* response, bufo_t* parent_buf) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_data_t* module = cur_filter->module;
    module->base.parent_buf = parent_buf;

    if (response->range)
        return filter_next_handler_body(response, parent_buf);

    int r = 0;
    int ok = 0;
    bufo_t* buf = &response->body;

    if (module->base.cont)
        goto cont;

    while (1) {
        response->cur_filter = cur_filter;

        buf = next_chunk_data(response, module->proxy_body_buf, &ok);
        if (!ok) /* alloc error */
            return CWF_ERROR;
        if (buf != NULL && (buf->pos == buf->size || buf->size == 0)) /* all data has been sent */
            return CWF_OK;

        cont:

        r = filter_next_handler_body(response, buf);

        module->base.cont = 0;

        if (r == CWF_DATA_AGAIN)
            continue;

        if (r == CWF_EVENT_AGAIN)
            module->base.cont = 1;

        return r;
    }

    return CWF_ERROR;
}

bufo_t* body_next_chunk_data(httpresponse_t* response, bufo_t* proxy_body_buf, int** ok) {
    **ok = 1;

    proxy_body_buf->data = response->body.data + response->body.pos;

    const size_t moved = bufo_move_front_pos(&response->body, BUF_SIZE);
    if (moved == 0) {
        **ok = 1;
        return proxy_body_buf;
    }

    bufo_set_size(proxy_body_buf, moved);
    bufo_reset_pos(proxy_body_buf);

    if (response->body.pos == response->body.size)
        proxy_body_buf->is_last = 1;

    return proxy_body_buf;
}

bufo_t* file_next_chunk_data(httpresponse_t* response, int** ok) {
    **ok = 0;

    if (!bufo_alloc(&response->body, BUF_SIZE)) return NULL;

    const ssize_t r = read(response->file_.fd, response->body.data, response->body.capacity);
    if (r < 0) {
        **ok = 1;
        return NULL;
    }

    size_t offset = lseek(response->file_.fd, 0, SEEK_CUR);

    if (offset == response->file_.size)
        response->body.is_last = 1;

    bufo_reset_pos(&response->body);
    bufo_set_size(&response->body, r);

    **ok = 1;

    return &response->body;
}

bufo_t* next_chunk_data(httpresponse_t* response, bufo_t* proxy_body_buf, int* ok) {
    if (response->file_.fd > -1)
        return file_next_chunk_data(response, &ok);

    return body_next_chunk_data(response, proxy_body_buf, &ok);
}

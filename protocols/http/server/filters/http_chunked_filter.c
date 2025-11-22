#include "http_chunked_filter.h"

#define BUF_SIZE 16384

int __chunk_head_create(http_module_chunked_t* module);
void __process(http_module_chunked_t* module, bufo_t* buf);
int __update_state(http_module_chunked_t* module, bufo_t* parent_buf);
void http_chunked_free(void* arg);
void http_chunked_reset(void* arg);

http_filter_t* http_chunked_filter_create(void) {
    http_filter_t* filter = malloc(sizeof * filter);
    if (filter == NULL) return NULL;

    filter->handler_header = http_chunked_header;
    filter->handler_body = http_chunked_body;
    filter->module = http_chunked_create();
    filter->next = NULL;

    if (filter->module == NULL) {
        free(filter);
        return NULL;
    }

    return filter;
}

http_module_chunked_t* http_chunked_create(void) {
    http_module_chunked_t* module = malloc(sizeof * module);
    if (module == NULL) return NULL;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = http_chunked_free;
    module->base.reset = http_chunked_reset;
    module->buf = bufo_create();
    module->state = HTTP_MODULE_CHUNKED_SIZE;
    module->state_pos = 0;
    module->chunk_head = NULL;
    module->chunk_head_size = 0;

    if (module->buf == NULL) {
        free(module);
        return NULL;
    }

    return module;
}

void http_chunked_free(void* arg) {
    http_module_chunked_t* module = arg;

    if (module->chunk_head != NULL)
        free(module->chunk_head);

    bufo_free(module->buf);

    free(module);
}

void http_chunked_reset(void* arg) {
    http_module_chunked_t* module = arg;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->state = HTTP_MODULE_CHUNKED_SIZE;
    module->chunk_head_size = 0;
    module->state_pos = 0;

    bufo_flush(module->buf);
}

int http_chunked_header(httpresponse_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_chunked_t* module = cur_filter->module;

    if (response->transfer_encoding == TE_NONE)
        return filter_next_handler_header(response);

    int r = 0;

    if (module->base.cont)
        goto cont;

    if (response->get_header(response, "Transfer-Encoding") == NULL)
        response->add_header(response, "Transfer-Encoding", "chunked");

    if (!bufo_alloc(module->buf, BUF_SIZE))
        return CWF_ERROR;

    cont:

    r = filter_next_handler_header(response);

    module->base.cont = 0;

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int http_chunked_body(httpresponse_t* response, bufo_t* parent_buf) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_chunked_t* module = cur_filter->module;
    module->base.parent_buf = parent_buf;

    if (response->transfer_encoding == TE_NONE)
        return filter_next_handler_body(response, parent_buf);

    int r = 0;
    bufo_t* buf = module->buf;

    if (module->base.cont)
        goto cont;

    bufo_reset_pos(buf);
    
    while (1) {
        response->cur_filter = cur_filter;

        __process(module, buf);

        bufo_reset_pos(buf);

        cont:

        r = filter_next_handler_body(response, buf);

        module->base.cont = 0;

        if (r == CWF_DATA_AGAIN) {
            // if (parent_buf->is_last && !module->base.done)
            //     continue;

            if (parent_buf->pos == parent_buf->size)
                return r;

            continue;
            // return r;
        }

        if (r == CWF_EVENT_AGAIN)
            module->base.cont = 1;

        return r;
    }

    return CWF_ERROR;
}

int __chunk_head_create(http_module_chunked_t* module) {
    module->chunk_head = malloc(18);
    if (module->chunk_head == NULL)
        return 0;

    return 1;
}

int __chunk_head_set(http_module_chunked_t* module) {
    const int chunk_head_size = snprintf(module->chunk_head, 18, "%zx\r\n", bufo_size(module->base.parent_buf));
    if (chunk_head_size == -1)
        return 0;

    // if (bufo_size(module->base.parent_buf) == 12) {
    //     int i = 0;
    // }

    module->chunk_head_size = chunk_head_size;

    return 1;
}

void __process(http_module_chunked_t* module, bufo_t* buf) {
    bufo_t* parent_buf = module->base.parent_buf;

    bufo_reset_pos(buf);
    bufo_reset_size(buf);

    while (1) {
        switch (module->state) {
            case HTTP_MODULE_CHUNKED_SIZE:
            {
                if (module->state_pos == 0)
                    if (!__update_state(module, parent_buf))
                        return;
                        // return CWF_ERROR;

                ssize_t writed = bufo_append(buf, module->chunk_head + module->state_pos, module->chunk_head_size - module->state_pos);

                module->state_pos += writed;

                // printf("%.*s", module->chunk_head_size, module->chunk_head);

                if (module->state_pos < module->chunk_head_size)
                    return;

                if (module->state_pos == module->chunk_head_size) {
                    module->state = HTTP_MODULE_CHUNKED_DATA;
                    module->state_pos = 0;
                }
                break;
            }
            case HTTP_MODULE_CHUNKED_DATA:
            {
                ssize_t writed = bufo_append(buf, bufo_data(parent_buf), bufo_size(parent_buf) - parent_buf->pos);

                module->state_pos += bufo_move_front_pos(parent_buf, writed);

                if (module->state_pos < bufo_size(parent_buf))
                    return;

                if (module->state_pos == bufo_size(parent_buf)) {
                    module->state = HTTP_MODULE_CHUNKED_SEP;
                    module->state_pos = 0;
                }
                break;
            }
            case HTTP_MODULE_CHUNKED_SEP:
            {
                const char* sep = "\r\n";
                const size_t sep_size = 2;

                ssize_t writed = bufo_append(buf, sep + module->state_pos, sep_size - module->state_pos);

                module->state_pos += writed;

                if (module->state_pos < sep_size)
                    return;

                if (module->state_pos == sep_size) {
                    module->state_pos = 0;
                    
                    if (parent_buf->is_last)
                        module->state = HTTP_MODULE_CHUNKED_END;
                    else {
                        module->state = HTTP_MODULE_CHUNKED_SIZE;

                        if (parent_buf->pos < parent_buf->size)
                            break;

                        return;
                    }
                }

                break;
            }
            case HTTP_MODULE_CHUNKED_END:
            {
                const char* value = "0\r\n\r\n";
                const size_t value_size = 5;                

                ssize_t writed = bufo_append(buf, value + module->state_pos, value_size - module->state_pos);

                module->state_pos += writed;
                if (module->state_pos < value_size)
                    return;

                if (module->state_pos == value_size) {
                    module->base.done = 1;
                    module->state_pos = 0;
                }

                return;
            }
        }
    }
}

int __update_state(http_module_chunked_t* module, bufo_t* parent_buf) {
    module->base.parent_buf = parent_buf;
    module->state = HTTP_MODULE_CHUNKED_SIZE;
    module->state_pos = 0;

    if (module->chunk_head == NULL)
        if (!__chunk_head_create(module))
            return 0;

    if (!__chunk_head_set(module))
        return 0;

    return 1;
}
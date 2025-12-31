#include "http_chunked_filter.h"

#define BUF_SIZE 16384
#define CHUNK_HEAD_MAX_SIZE 24

static int chunk_head_create(http_module_chunked_t* module);
static int chunk_head_set(http_module_chunked_t* module);
static void chunked_process(http_module_chunked_t* module, bufo_t* buf);
static int chunked_update_state(http_module_chunked_t* module, bufo_t* parent_buf);
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
    module->current_chunk_size = 0;

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
    module->current_chunk_size = 0;

    bufo_flush(module->buf);
}

int http_chunked_header(httprequest_t* request, httpresponse_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_chunked_t* module = cur_filter->module;

    if (response->transfer_encoding == TE_NONE)
        return filter_next_handler_header(request, response);

    if (response->last_modified)
        return filter_next_handler_header(request, response);

    int r = 0;

    if (module->base.cont)
        goto cont;

    if (response->get_header(response, "Transfer-Encoding") == NULL)
        response->add_header(response, "Transfer-Encoding", "chunked");

    if (!bufo_alloc(module->buf, BUF_SIZE))
        return CWF_ERROR;

    cont:

    r = filter_next_handler_header(request, response);

    module->base.cont = 0;

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int http_chunked_body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_chunked_t* module = cur_filter->module;
    module->base.parent_buf = parent_buf;

    if (response->transfer_encoding == TE_NONE)
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

        chunked_process(module, buf);

        bufo_reset_pos(buf);

        cont:

        r = filter_next_handler_body(request, response, buf);

        module->base.cont = 0;

        if (r == CWF_DATA_AGAIN) {

            if (parent_buf->pos == parent_buf->size)
                return r;

            continue;
        }

        if (r == CWF_EVENT_AGAIN)
            module->base.cont = 1;

        return r;
    }

}

static int chunk_head_create(http_module_chunked_t* module) {
    char* chunk_head = malloc(CHUNK_HEAD_MAX_SIZE);
    if (chunk_head == NULL)
        return 0;

    module->chunk_head = chunk_head;
    return 1;
}

static int chunk_head_set(http_module_chunked_t* module) {
    bufo_t* parent_buf = module->base.parent_buf;
    if (parent_buf == NULL)
        return 0;

    const size_t buf_size = bufo_size(parent_buf);
    if (parent_buf->pos > buf_size)
        return 0;

    const size_t chunk_size = buf_size - parent_buf->pos;
    const int chunk_head_size = snprintf(module->chunk_head, CHUNK_HEAD_MAX_SIZE, "%zx\r\n", chunk_size);
    if (chunk_head_size < 0 || chunk_head_size >= CHUNK_HEAD_MAX_SIZE)
        return 0;

    module->chunk_head_size = chunk_head_size;
    module->current_chunk_size = chunk_size;

    return 1;
}

static void chunked_process(http_module_chunked_t* module, bufo_t* buf) {
    bufo_t* parent_buf = module->base.parent_buf;

    bufo_reset_pos(buf);
    bufo_reset_size(buf);

    while (1) {
        switch (module->state) {
            case HTTP_MODULE_CHUNKED_SIZE:
            {
                if (module->state_pos == 0)
                    if (!chunked_update_state(module, parent_buf))
                        return;

                ssize_t written = bufo_append(buf, module->chunk_head + module->state_pos, module->chunk_head_size - module->state_pos);

                module->state_pos += written;

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
                ssize_t written = bufo_append(buf, bufo_data(parent_buf), bufo_size(parent_buf) - parent_buf->pos);

                module->state_pos += bufo_move_front_pos(parent_buf, written);

                if (module->state_pos < module->current_chunk_size)
                    return;

                if (module->state_pos == module->current_chunk_size) {
                    module->state = HTTP_MODULE_CHUNKED_SEP;
                    module->state_pos = 0;
                }
                break;
            }
            case HTTP_MODULE_CHUNKED_SEP:
            {
                const char* sep = "\r\n";
                const size_t sep_size = 2;

                ssize_t written = bufo_append(buf, sep + module->state_pos, sep_size - module->state_pos);

                module->state_pos += written;

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

                ssize_t written = bufo_append(buf, value + module->state_pos, value_size - module->state_pos);

                module->state_pos += written;
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

static int chunked_update_state(http_module_chunked_t* module, bufo_t* parent_buf) {
    module->base.parent_buf = parent_buf;
    module->state = HTTP_MODULE_CHUNKED_SIZE;
    module->state_pos = 0;

    if (module->chunk_head == NULL)
        if (!chunk_head_create(module))
            return 0;

    if (!chunk_head_set(module))
        return 0;

    return 1;
}
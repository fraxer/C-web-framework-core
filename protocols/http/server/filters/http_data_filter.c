#include "http_data_filter.h"

#include <errno.h>
#include <unistd.h>

#define BUF_SIZE 16384

static http_module_data_t* __create(void);
static void __free(void* arg);
static void __reset(void* arg);
static int __header(httprequest_t* request, httpresponse_t* response);
static int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf);
static bufo_t* body_next_chunk_data(httpresponse_t* response, bufo_t* proxy_body_buf, int** ok);
static bufo_t* file_next_chunk_data(httpresponse_t* response, http_module_data_t* module, int** ok);
static bufo_t* next_chunk_data(httpresponse_t* response, http_module_data_t* module, int* ok);

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
    module->file_offset = 0;

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
    /* bufo_clear() on a proxy buffer re-runs bufo_init(), which zeroes
     * capacity. body_next_chunk_data caps the chunk via bufo_set_size(),
     * which clamps to capacity — a zero capacity made every reuse produce
     * size == 0, so __body returned CWF_OK and dropped the body. */
    module->proxy_body_buf->capacity = BUF_SIZE;
    module->file_offset = 0;
}

int __header(httprequest_t* request, httpresponse_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_data_t* module = cur_filter->module;
    int r = 0;

    if (module->base.cont)
        goto cont;

    if (response->file_.fd > -1)
        if (!response->add_header(response, "Cache-Control", "no-cache"))
            return CWF_ERROR;

    // RFC 7232: 304 response MUST NOT contain Content-Length for body
    if (!response->range && response->transfer_encoding == TE_NONE && response->status_code != 304) {
        size_t data_size = response->body.size;
        if (response->file_.fd > -1)
            data_size = response->file_.size;

        if (!response->add_content_length(response, data_size))
            return CWF_ERROR;
    }

    cont:

    r = filter_next_handler_header(request, response);

    module->base.cont = 0;

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int __body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_data_t* module = cur_filter->module;

    if (response->range)
        return filter_next_handler_body(request, response, parent_buf);

    // RFC 7231: HEAD response MUST NOT contain a message body
    if (request != NULL && request->method == ROUTE_HEAD)
        return CWF_OK;

    // RFC 7232: 304 response MUST NOT contain a message body
    if (response->status_code == 304)
        return CWF_OK;

    int r = 0;
    int ok = 0;
    /* On a resume (CWF_EVENT_AGAIN) re-offer the exact buffer that was in
     * progress, not a freshly fetched one: body_next_chunk_data advances
     * response->body.pos by the whole chunk up front, so re-fetching would
     * point the proxy past the bytes the downstream filter still owes and
     * read out of bounds. parent_buf holds that in-progress buffer. */
    bufo_t* buf = module->base.parent_buf;

    if (module->base.cont)
        goto cont;

    while (1) {
        response->cur_filter = cur_filter;

        buf = next_chunk_data(response, module, &ok);
        if (!ok) /* alloc or read error */
            return CWF_ERROR;
        if (buf != NULL && (buf->pos == buf->size || buf->size == 0)) /* all data has been sent */
            return CWF_OK;

        module->base.parent_buf = buf; /* offer the same buffer again on resume */

        cont:

        r = filter_next_handler_body(request, response, buf);

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

bufo_t* file_next_chunk_data(httpresponse_t* response, http_module_data_t* module, int** ok) {
    **ok = 0;

    if (!bufo_alloc(&response->body, BUF_SIZE)) return NULL;

    /* pread() reads at an explicit offset and leaves the descriptor offset
     * untouched, so the read position is tracked in module->file_offset
     * (reset to 0 between responses) and EOF is derived from it instead of
     * a second lseek(). */
    ssize_t r;
    do {
        r = pread(response->file_.fd, response->body.data, response->body.capacity, module->file_offset);
    } while (r < 0 && errno == EINTR);

    /* Genuine read failure (EBADF, EIO, ...): leave **ok = 0 so __body maps
     * it to CWF_ERROR. Returning NULL with ok = 1 (an earlier version) made
     * __body skip the "all data sent" check and pass NULL to the next
     * filter — a NULL deref / corrupted stream. */
    if (r < 0)
        return NULL;

    module->file_offset += r;

    if (module->file_offset >= (off_t)response->file_.size)
        response->body.is_last = 1;

    bufo_reset_pos(&response->body);
    bufo_set_size(&response->body, r);

    **ok = 1;

    return &response->body;
}

bufo_t* next_chunk_data(httpresponse_t* response, http_module_data_t* module, int* ok) {
    if (response->file_.fd > -1)
        return file_next_chunk_data(response, module, &ok);

    return body_next_chunk_data(response, module->proxy_body_buf, &ok);
}

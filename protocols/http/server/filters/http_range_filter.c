#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

#include "http_range_filter.h"

#define BUF_SIZE 16384

/* RFC 9110 §14.2 lets a server ignore a Range header field it considers
 * excessive; cap the number of ranges so a short request header cannot
 * demand an amplified multipart response. Above the cap the header is
 * ignored and the full representation goes out as a plain 200. */
#define RANGE_MAX_PARTS 64

#define MP_CTYPE_DEFAULT "application/octet-stream"
#define MP_PART_HEADER_FMT "--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zu-%zu/%zu\r\n\r\n"
#define MP_CLOSE_FMT "--%s--\r\n"

/* multipart body generator states (module->mp_state) */
enum {
    MP_STATE_TEXT = 0,  /* draining staged text (part header / close delimiter) */
    MP_STATE_DATA,      /* draining the current part's byte range */
    MP_STATE_DONE
};

static http_module_range_t* range_module_create(void);
static void range_module_free(void* arg);
static void range_module_reset(void* arg);
static void range_module_clear(http_module_range_t* module);
static int range_resolve(ssize_t source_start, ssize_t source_end, size_t data_size, http_range_part_t* part);
static ssize_t range_read_data(httpresponse_t* response, char* dst, size_t offset, size_t size);
static int range_get_chunk(httpresponse_t* response, http_module_range_t* module);
static void mp_generate_boundary(http_module_range_t* module);
static ssize_t mp_part_header_length(const http_module_range_t* module, const http_range_part_t* part);
static int mp_stage_text(http_module_range_t* module, int lead_crlf);
static int mp_setup(httpresponse_t* response, http_module_range_t* module, size_t data_size);
static int mp_fill_chunk(httpresponse_t* response, http_module_range_t* module);
static int range_handler_header(httprequest_t* request, httpresponse_t* response);
static int range_handler_body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf);

http_filter_t* http_range_filter_create(void) {
    http_filter_t* filter = malloc(sizeof * filter);
    if (filter == NULL) return NULL;

    filter->handler_header = range_handler_header;
    filter->handler_body = range_handler_body;
    filter->module = range_module_create();
    filter->next = NULL;

    if (filter->module == NULL) {
        free(filter);
        return NULL;
    }

    return filter;
}

http_module_range_t* range_module_create(void) {
    http_module_range_t* module = malloc(sizeof * module);
    if (module == NULL) return NULL;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = range_module_free;
    module->base.reset = range_module_reset;
    module->buf = bufo_create();
    module->range_pos = 0;
    module->range_size = 0;
    module->range_start = 0;
    module->unsatisfiable = 0;
    module->mp_active = 0;
    module->parts = NULL;
    module->parts_count = 0;
    module->part_index = 0;
    module->mp_state = MP_STATE_TEXT;
    module->mp_total = 0;
    module->data_pos = 0;
    module->part_ctype = NULL;
    module->text = NULL;
    module->text_len = 0;
    module->text_pos = 0;
    module->boundary[0] = 0;

    if (module->buf == NULL) {
        free(module);
        return NULL;
    }

    return module;
}

void range_module_free(void* arg) {
    if (arg == NULL)
        return;

    http_module_range_t* module = arg;

    range_module_clear(module);
    bufo_free(module->buf);
    free(module);
}

void range_module_reset(void* arg) {
    http_module_range_t* module = arg;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;

    range_module_clear(module);

    bufo_flush(module->buf);
}

/* Release the per-response state (range plan, staged text, replayed
 * Content-Type) so the module can serve the next response on a keep-alive
 * connection. The chunk buffer allocation itself is kept for reuse. */
void range_module_clear(http_module_range_t* module) {
    free(module->parts);
    module->parts = NULL;
    module->parts_count = 0;
    module->part_index = 0;

    free(module->part_ctype);
    module->part_ctype = NULL;

    free(module->text);
    module->text = NULL;
    module->text_len = 0;
    module->text_pos = 0;

    module->mp_state = MP_STATE_TEXT;
    module->mp_total = 0;
    module->data_pos = 0;
    module->mp_active = 0;
    module->unsatisfiable = 0;
    module->boundary[0] = 0;
    module->range_pos = 0;
    module->range_size = 0;
    module->range_start = 0;
}

/*
 * Resolve one parsed range spec against the representation size.
 * start == -1 denotes a suffix range ("-N": the last N bytes), end == -1 an
 * open right side ("N-"). The parsed end is inclusive (RFC 9110 §14.1.2) and
 * is converted to an exclusive bound here.
 *
 * Returns 1 and fills `part` when the range is satisfiable, 0 when it is
 * syntactically fine but unsatisfiable (empty after clamping), -1 when the
 * spec is malformed and the whole Range header must be ignored.
 */
int range_resolve(ssize_t source_start, ssize_t source_end, size_t data_size, http_range_part_t* part) {
    if (source_start < -1 || source_end < -1)
        return -1;

    size_t start = 0;
    size_t end = 0; /* exclusive */

    if (source_start == -1) {
        /* Suffix range: a missing or zero length ("bytes=-0", "bytes=-")
         * selects nothing and is therefore unsatisfiable. */
        size_t suffix_len = source_end > 0 ? (size_t)source_end : 0;
        if (suffix_len > data_size)
            suffix_len = data_size;

        start = data_size - suffix_len;
        end = data_size;
    }
    else {
        start = (size_t)source_start;
        end = source_end == -1 ? data_size : (size_t)source_end + 1;
        if (end > data_size)
            end = data_size;
    }

    if (start >= end)
        return 0;

    part->start = start;
    part->size = end - start;

    return 1;
}

/*
 * Read `size` bytes of the served representation starting at `offset` into
 * dst — from the backing file when one is attached, from the response body
 * otherwise. Returns the byte count actually read or -1 on failure; a short
 * or zero count is only possible on the file path.
 */
ssize_t range_read_data(httpresponse_t* response, char* dst, size_t offset, size_t size) {
    if (size == 0)
        return 0;

    if (response->file_.fd > -1) {
        /* off_t is signed: reject offsets that would not survive the cast. */
        if (offset > (size_t)SSIZE_MAX)
            return -1;

        ssize_t r;
        do {
            r = pread(response->file_.fd, dst, size, (off_t)offset);
        } while (r == -1 && errno == EINTR);

        return r;
    }

    if (response->body.data == NULL)
        return -1;

    memcpy(dst, response->body.data + offset, size);

    return (ssize_t)size;
}

/* Produce the next chunk of a single-range response into module->buf.
 * Returns 1 on success (buf holds the chunk, is_last set on the final one),
 * 0 on failure. */
int range_get_chunk(httpresponse_t* response, http_module_range_t* module) {
    bufo_t* buf = module->buf;

    if (buf->data == NULL)
        return 0;

    if (module->range_pos > module->range_size)
        return 0;

    const size_t remaining = module->range_size - module->range_pos;
    const size_t take = remaining < buf->capacity ? remaining : buf->capacity;

    const ssize_t r = range_read_data(response, buf->data, module->range_start + module->range_pos, take);
    if (r < 0)
        return 0;

    module->range_pos += (size_t)r;

    /* EOF below the promised size means the backing file was truncated after
     * the headers were framed; end the stream instead of spinning forever. */
    if (module->range_pos == module->range_size || (r == 0 && take > 0))
        buf->is_last = 1;

    bufo_reset_pos(buf);
    bufo_set_size(buf, (size_t)r);

    return 1;
}

void mp_generate_boundary(http_module_range_t* module) {
    static const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const size_t chars_length = sizeof(chars) - 1;
    const size_t boundary_length = sizeof(module->boundary) - 1;

    for (size_t i = 0; i < boundary_length; i++)
        module->boundary[i] = chars[(size_t)rand() % chars_length];

    module->boundary[boundary_length] = 0;
}

ssize_t mp_part_header_length(const http_module_range_t* module, const http_range_part_t* part) {
    const int size = snprintf(NULL, 0, MP_PART_HEADER_FMT,
                              module->boundary, module->part_ctype,
                              part->start, part->start + part->size - 1, module->mp_total);

    return size < 0 ? -1 : (ssize_t)size;
}

/*
 * Stage the next piece of multipart framing text: the header of the part at
 * module->part_index, or the close delimiter once all parts are done. Each
 * part's data is followed by a CRLF, folded in here as the lead_crlf prefix.
 */
int mp_stage_text(http_module_range_t* module, int lead_crlf) {
    free(module->text);
    module->text = NULL;
    module->text_len = 0;
    module->text_pos = 0;

    const size_t prefix = lead_crlf ? 2 : 0;
    const int close_frame = module->part_index >= module->parts_count;

    ssize_t body_length;
    if (close_frame)
        body_length = (ssize_t)(strlen(module->boundary) + 6); /* "--" B "--\r\n" */
    else
        body_length = mp_part_header_length(module, &module->parts[module->part_index]);

    if (body_length < 0)
        return 0;

    char* text = malloc(prefix + (size_t)body_length + 1);
    if (text == NULL)
        return 0;

    if (prefix > 0)
        memcpy(text, "\r\n", prefix);

    int written;
    if (close_frame) {
        written = snprintf(text + prefix, (size_t)body_length + 1, MP_CLOSE_FMT, module->boundary);
    }
    else {
        const http_range_part_t* part = &module->parts[module->part_index];
        written = snprintf(text + prefix, (size_t)body_length + 1, MP_PART_HEADER_FMT,
                           module->boundary, module->part_ctype,
                           part->start, part->start + part->size - 1, module->mp_total);
    }

    if (written < 0 || written != (int)body_length) {
        free(text);
        return 0;
    }

    module->text = text;
    module->text_len = prefix + (size_t)body_length;

    return 1;
}

/*
 * Frame a multipart/byteranges response (RFC 9110 §14.6): move the original
 * Content-Type into the parts, install the multipart Content-Type with a
 * fresh boundary and add a Content-Length covering the exact framed body.
 * module->parts/parts_count must already hold the satisfiable ranges.
 */
int mp_setup(httpresponse_t* response, http_module_range_t* module, size_t data_size) {
    module->mp_active = 1;
    module->part_index = 0;
    module->data_pos = 0;
    module->mp_total = data_size;
    module->mp_state = MP_STATE_TEXT;

    mp_generate_boundary(module);

    const char* ctype = MP_CTYPE_DEFAULT;
    const http_header_t* origin = response->get_header(response, "Content-Type");
    if (origin != NULL && origin->value != NULL)
        ctype = origin->value;

    module->part_ctype = strdup(ctype);
    if (module->part_ctype == NULL)
        return 0;

    if (origin != NULL)
        response->remove_header(response, "Content-Type");

    char content_type[64] = {0};
    const int ct_size = snprintf(content_type, sizeof(content_type),
                                 "multipart/byteranges; boundary=%s", module->boundary);
    if (ct_size < 0 || (size_t)ct_size >= sizeof(content_type))
        return 0;

    if (!response->add_headeru(response, "Content-Type", 12, content_type, (size_t)ct_size))
        return 0;

    /* Content-Length must equal the framed body exactly: every part header,
     * its data, the CRLF after the data and the close delimiter. */
    size_t content_length = strlen(module->boundary) + 6;
    for (size_t i = 0; i < module->parts_count; i++) {
        const http_range_part_t* part = &module->parts[i];

        const ssize_t header_length = mp_part_header_length(module, part);
        if (header_length < 0)
            return 0;

        const size_t part_length = (size_t)header_length + part->size + 2;
        if (part_length < part->size || content_length > SIZE_MAX - part_length)
            return 0;

        content_length += part_length;
    }

    response->status_code = 206;

    if (!response->add_content_length(response, content_length))
        return 0;

    if (!bufo_alloc(module->buf, BUF_SIZE))
        return 0;

    /* Stage the opening part header so the body phase starts in text mode. */
    return mp_stage_text(module, 0);
}

/* Produce the next chunk of the multipart body into module->buf, weaving
 * staged framing text and part data until the buffer is full or the close
 * delimiter has been emitted. Returns 1 on success, 0 on failure. */
int mp_fill_chunk(httpresponse_t* response, http_module_range_t* module) {
    bufo_t* buf = module->buf;

    if (buf->data == NULL)
        return 0;

    size_t filled = 0;

    while (filled < buf->capacity && module->mp_state != MP_STATE_DONE) {
        const size_t space = buf->capacity - filled;

        if (module->mp_state == MP_STATE_TEXT) {
            if (module->text == NULL)
                return 0;

            const size_t left = module->text_len - module->text_pos;
            const size_t take = left < space ? left : space;

            memcpy(buf->data + filled, module->text + module->text_pos, take);
            filled += take;
            module->text_pos += take;

            if (module->text_pos == module->text_len) {
                module->mp_state = module->part_index < module->parts_count
                    ? MP_STATE_DATA
                    : MP_STATE_DONE;
                module->data_pos = 0;
            }

            continue;
        }

        /* MP_STATE_DATA */
        const http_range_part_t* part = &module->parts[module->part_index];
        const size_t left = part->size - module->data_pos;
        const size_t take = left < space ? left : space;

        const ssize_t r = range_read_data(response, buf->data + filled, part->start + module->data_pos, take);
        if (r < 0)
            return 0;

        /* The part header already promised part->size bytes: EOF below that
         * (a file truncated after the headers were framed) cannot be
         * recovered into valid multipart framing. */
        if (r == 0 && take > 0)
            return 0;

        filled += (size_t)r;
        module->data_pos += (size_t)r;

        if (module->data_pos == part->size) {
            module->part_index++;

            if (!mp_stage_text(module, 1))
                return 0;

            module->mp_state = MP_STATE_TEXT;
        }
    }

    if (module->mp_state == MP_STATE_DONE)
        buf->is_last = 1;

    bufo_reset_pos(buf);
    bufo_set_size(buf, filled);

    return 1;
}

int range_handler_header(httprequest_t* request, httpresponse_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    if (cur_filter == NULL || cur_filter->module == NULL)
        return CWF_ERROR;

    http_module_range_t* module = cur_filter->module;
    int r = 0;

    if (module->base.cont)
        goto cont;

    if (request == NULL || request->ranges == NULL)
        return filter_next_handler_header(request, response);

    /* Range requests only apply to successful responses (2xx).
     * Redirects (3xx), client errors (4xx) and server errors (5xx) go out
     * unmodified. */
    if (response->status_code < 200 || response->status_code >= 300)
        return filter_next_handler_header(request, response);

    if (response->last_modified)
        return filter_next_handler_header(request, response);

    size_t data_size = response->body.size;
    if (response->file_.fd > -1)
        data_size = response->file_.size;

    size_t requested = 0;
    for (http_ranges_t* range = request->ranges; range != NULL; range = range->next)
        requested++;

    if (requested > RANGE_MAX_PARTS)
        return filter_next_handler_header(request, response);

    /* Resolve the whole set before mutating the response, so an ignored or
     * malformed Range header leaves status, encodings and the range flag
     * untouched. Unsatisfiable ranges are dropped; the rest keep their
     * request order. */
    http_range_part_t* parts = malloc(requested * sizeof(*parts));
    if (parts == NULL)
        return CWF_ERROR;

    size_t count = 0;
    for (http_ranges_t* range = request->ranges; range != NULL; range = range->next) {
        const int resolved = range_resolve(range->start, range->end, data_size, &parts[count]);
        if (resolved < 0) {
            free(parts);
            return filter_next_handler_header(request, response);
        }

        if (resolved == 1)
            count++;
    }

    const int multipart = request->ranges->next != NULL;

    /* Ranges are served from the raw representation: no gzip, no chunked. */
    response->content_encoding = CE_NONE;
    response->transfer_encoding = TE_NONE;
    response->range = 1;

    if (count == 0) {
        /* No satisfiable range: 416 with the unsatisfied-range form and an
         * empty body (RFC 9110 §15.5.17). */
        free(parts);

        module->unsatisfiable = 1;
        response->status_code = 416;

        char bytes[70] = {0};
        const int size = snprintf(bytes, sizeof(bytes), "bytes */%zu", data_size);
        if (size < 0 || (size_t)size >= sizeof(bytes)) return CWF_ERROR;

        if (!response->add_headeru(response, "Content-Range", 13, bytes, (size_t)size)) return CWF_ERROR;
        if (!response->add_content_length(response, 0)) return CWF_ERROR;
    }
    else if (!multipart) {
        module->range_start = parts[0].start;
        module->range_size = parts[0].size;
        free(parts);

        response->status_code = 206;

        char bytes[70] = {0};
        const int size = snprintf(bytes, sizeof(bytes), "bytes %zu-%zu/%zu",
                                  module->range_start,
                                  module->range_start + module->range_size - 1,
                                  data_size);
        if (size < 0 || (size_t)size >= sizeof(bytes)) return CWF_ERROR;

        if (!response->add_headeru(response, "Content-Range", 13, bytes, (size_t)size)) return CWF_ERROR;
        if (!response->add_content_length(response, module->range_size)) return CWF_ERROR;

        if (!bufo_alloc(module->buf, BUF_SIZE)) return CWF_ERROR;
    }
    else {
        module->parts = parts;
        module->parts_count = count;

        if (!mp_setup(response, module, data_size))
            return CWF_ERROR;
    }

    cont:

    r = filter_next_handler_header(request, response);

    module->base.cont = 0;

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int range_handler_body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    http_filter_t* cur_filter = response->cur_filter;
    if (cur_filter == NULL || cur_filter->module == NULL)
        return CWF_ERROR;

    http_module_range_t* module = cur_filter->module;
    module->base.parent_buf = parent_buf;

    if (request == NULL || !response->range)
        return filter_next_handler_body(request, response, parent_buf);

    if (response->last_modified)
        return filter_next_handler_body(request, response, parent_buf);

    /* 416 framing carries no message body. */
    if (module->unsatisfiable)
        return CWF_OK;

    /* RFC 9110 §9.3.2: HEAD responses have no body even though the range
     * headers (206, Content-Range, Content-Length) are present. */
    if (request->method == ROUTE_HEAD)
        return CWF_OK;

    int r = 0;
    bufo_t* buf = module->buf;

    if (module->base.cont)
        goto cont;

    while (1) {
        response->cur_filter = cur_filter;

        const int filled = module->mp_active
            ? mp_fill_chunk(response, module)
            : range_get_chunk(response, module);
        if (!filled)
            return CWF_ERROR;

        cont:

        r = filter_next_handler_body(request, response, buf);

        module->base.cont = 0;

        if (r == CWF_DATA_AGAIN) {
            /* CWF_DATA_AGAIN promises the offered buffer was consumed in
             * full (the write filter drains or yields CWF_EVENT_AGAIN).
             * Leftover bytes would be overwritten by the next chunk, so a
             * violation is a hard error, not silent data loss. */
            if (buf->pos < buf->size)
                return CWF_ERROR;

            if (buf->is_last)
                return CWF_OK;

            continue;
        }

        if (r == CWF_EVENT_AGAIN)
            module->base.cont = 1;

        return r;
    }
}

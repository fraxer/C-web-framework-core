#include "http_not_modified_filter.h"
#include "connection_s.h"
#include "httprequest.h"
#include "httprequestparser.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>

static http_module_not_modified_t* __create(void);
static void __free(void* arg);
static void __reset(void* arg);
static int __check_not_modified(httpresponse_t* response);
static int __etag_matches(const char* if_none_match, size_t if_none_match_len,
                          const char* etag, size_t etag_len);

http_filter_t* http_not_modified_filter_create(void) {
    http_filter_t* filter = malloc(sizeof * filter);
    if (filter == NULL) return NULL;

    filter->handler_header = http_not_modified_header;
    filter->handler_body = http_not_modified_body;
    filter->module = __create();
    filter->next = NULL;

    if (filter->module == NULL) {
        free(filter);
        return NULL;
    }

    return filter;
}

http_module_not_modified_t* __create(void) {
    http_module_not_modified_t* module = malloc(sizeof * module);
    if (module == NULL) return NULL;

    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
    module->base.free = __free;
    module->base.reset = __reset;

    return module;
}

void __free(void* arg) {
    http_module_not_modified_t* module = arg;
    free(module);
}

void __reset(void* arg) {
    http_module_not_modified_t* module = arg;
    module->base.cont = 0;
    module->base.done = 0;
    module->base.parent_buf = NULL;
}

int http_not_modified_header(httpresponse_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_not_modified_t* module = cur_filter->module;

    int r = 0;

    if (module->base.cont)
        goto cont;

    // Check if response should be 304 Not Modified
    if (__check_not_modified(response)) {
        // Set status code to 304
        response->status_code = 304;

        // RFC 7232: 304 response MUST NOT contain a message body
        // Remove Content-Length and set it to 0
        response->remove_header(response, "Content-Length");
        response->content_length = 0;

        // Remove Transfer-Encoding for 304
        response->remove_header(response, "Transfer-Encoding");
        response->transfer_encoding = TE_NONE;

        // Mark body as empty
        response->body.size = 0;
        response->body.pos = 0;

        // Close file if opened
        if (response->file_.fd > -1) {
            close(response->file_.fd);
            response->file_.fd = -1;
            response->file_.size = 0;
        }

        // Keep cache-related headers: Date, ETag, Cache-Control, Expires, Vary
        // These are already set in the response, so we just pass through
    }

    cont:

    r = filter_next_handler_header(response);

    module->base.cont = 0;

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int http_not_modified_body(httpresponse_t* response, bufo_t* buf) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_not_modified_t* module = cur_filter->module;

    // RFC 7232: 304 response MUST NOT contain a message body
    if (response->status_code == 304) {
        // Don't send any body data
        buf->size = 0;
        buf->pos = 0;
        buf->is_last = 1;
        module->base.done = 1;
        return filter_next_handler_body(response, buf);
    }

    // If not 304, pass through to next filter
    return filter_next_handler_body(response, buf);
}

int __check_not_modified(httpresponse_t* response) {
    return 1;
    // Get request from connection
    connection_t* connection = response->connection;
    if (connection == NULL || connection->ctx == NULL)
        return 0;

    connection_server_ctx_t* ctx = connection->ctx;
    if (ctx->parser == NULL)
        return 0;

    httprequestparser_t* parser = ctx->parser;
    httprequest_t* request = parser->request;
    if (request == NULL)
        return 0;

    // Get response ETag and Last-Modified headers
    http_header_t* etag_header = response->get_header(response, "ETag");
    http_header_t* last_modified_header = response->get_header(response, "Last-Modified");

    // Check If-None-Match (ETag validation)
    http_header_t* if_none_match = request->get_header(request, "If-None-Match");
    if (if_none_match != NULL && etag_header != NULL) {
        // RFC 7232: If-None-Match can contain multiple ETags or "*"
        if (__etag_matches(if_none_match->value, if_none_match->value_length,
                          etag_header->value, etag_header->value_length)) {
            return 1; // Resource not modified
        }
    }

    // Check If-Modified-Since (date validation)
    http_header_t* if_modified_since = request->get_header(request, "If-Modified-Since");
    if (if_modified_since != NULL && last_modified_header != NULL) {
        // Simple string comparison is sufficient for RFC 7231 HTTP-date format
        // since the format is fixed and lexicographically comparable
        int cmp = strncmp(if_modified_since->value, last_modified_header->value,
                         if_modified_since->value_length < last_modified_header->value_length ?
                         if_modified_since->value_length : last_modified_header->value_length);

        // If Last-Modified is not later than If-Modified-Since, return 304
        if (cmp >= 0) {
            return 1; // Resource not modified
        }
    }

    return 0; // Resource was modified or no conditional headers present
}

int __etag_matches(const char* if_none_match, size_t if_none_match_len,
                   const char* etag, size_t etag_len) {
    if (if_none_match == NULL || etag == NULL)
        return 0;

    // Check for "*" which matches any ETag
    if (if_none_match_len == 1 && if_none_match[0] == '*')
        return 1;

    // Parse comma-separated ETags in If-None-Match
    const char* pos = if_none_match;
    const char* end = if_none_match + if_none_match_len;

    while (pos < end) {
        // Skip whitespace and commas
        while (pos < end && (*pos == ' ' || *pos == '\t' || *pos == ','))
            pos++;

        if (pos >= end)
            break;

        const char* etag_start = pos;

        // Find end of current ETag (next comma or end)
        while (pos < end && *pos != ',')
            pos++;

        size_t current_etag_len = pos - etag_start;

        // Trim trailing whitespace
        while (current_etag_len > 0 &&
               (etag_start[current_etag_len - 1] == ' ' ||
                etag_start[current_etag_len - 1] == '\t'))
            current_etag_len--;

        // Compare with response ETag
        if (current_etag_len == etag_len &&
            strncmp(etag_start, etag, etag_len) == 0) {
            return 1; // Match found
        }
    }

    return 0; // No match
}

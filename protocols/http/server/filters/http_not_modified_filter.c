#define _GNU_SOURCE
#include "http_not_modified_filter.h"
#include "connection_s.h"
#include "httprequest.h"
#include "httprequestparser.h"
#include "route.h"
#include "helpers.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static http_module_not_modified_t* __create(void);
static void __free(void* arg);
static void __reset(void* arg);
static int __check_not_modified(httprequest_t* request, httpresponse_t* response);
static int __etag_matches(const char* if_none_match, size_t if_none_match_len,
                           const char* etag, size_t etag_len);
static int __generate_etag(time_t mtime, off_t size, char* etag_buf, size_t etag_buf_size);
static time_t __parse_http_date(const char* date, size_t len);

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

int http_not_modified_header(httprequest_t* request, httpresponse_t* response) {
    http_filter_t* cur_filter = response->cur_filter;
    http_module_not_modified_t* module = cur_filter->module;

    int r = 0;

    if (module->base.cont)
        goto cont;

    // Add Last-Modified header for files with mtime
    if (response->file_.fd > -1 && response->file_.mtime > 0) {
        char last_modified[64];
        struct tm tm_buf;
        struct tm* tm = gmtime_r(&response->file_.mtime, &tm_buf);
        if (tm != NULL && http_format_date(tm, last_modified, sizeof(last_modified)) > 0) {
            response->add_header(response, "Last-Modified", last_modified);
        }

        // Generate and add ETag header
        char etag[64];
        if (__generate_etag(response->file_.mtime, response->file_.size, etag, sizeof(etag)) > 0) {
            response->add_header(response, "ETag", etag);
        }
    }

    // Check if response should be 304 Not Modified
    if (__check_not_modified(request, response)) {
        // Set status code to 304
        response->status_code = 304;

        // RFC 7232: 304 response MUST NOT contain a message body
        // Remove Content-Length and set it to 0
        response->remove_header(response, "Content-Length");
        response->content_length = 0;

        // Remove Transfer-Encoding for 304
        response->remove_header(response, "Transfer-Encoding");
        response->transfer_encoding = TE_NONE;

        // Remove Content-Encoding for 304
        response->remove_header(response, "Content-Encoding");
        response->content_encoding = CE_NONE;

        response->last_modified = 1;

        // Keep cache-related headers: Date, ETag, Cache-Control, Expires, Vary
        // These are already set in the response, so we just pass through
    }

    cont:

    r = filter_next_handler_header(request, response);

    if (r == CWF_EVENT_AGAIN)
        module->base.cont = 1;

    return r;
}

int http_not_modified_body(httprequest_t* request, httpresponse_t* response, bufo_t* parent_buf) {
    return filter_next_handler_body(request, response, parent_buf);
}

int __check_not_modified(httprequest_t* request, httpresponse_t* response) {
    if (request == NULL || response == NULL)
        return 0;

    // RFC 7232: Conditional requests apply only to GET and HEAD
    if (request->method != ROUTE_GET && request->method != ROUTE_HEAD)
        return 0;

    // Get response ETag and Last-Modified headers
    http_header_t* etag_header = response->get_header(response, "ETag");
    http_header_t* last_modified_header = response->get_header(response, "Last-Modified");

    // Check If-None-Match (ETag validation) - takes precedence over If-Modified-Since
    http_header_t* if_none_match = request->get_header(request, "If-None-Match");
    if (if_none_match != NULL && etag_header != NULL) {
        // RFC 7232: If-None-Match can contain multiple ETags or "*"
        if (__etag_matches(if_none_match->value, if_none_match->value_length,
                           etag_header->value, etag_header->value_length)) {
            return 1; // Resource not modified
        }
        // If If-None-Match is present but doesn't match, don't check If-Modified-Since
        return 0;
    }

    // Check If-Modified-Since (date validation)
    http_header_t* if_modified_since = request->get_header(request, "If-Modified-Since");
    if (if_modified_since != NULL && last_modified_header != NULL) {
        // Parse HTTP-date values and compare as time_t
        time_t req_time = __parse_http_date(if_modified_since->value, if_modified_since->value_length);
        time_t res_time = __parse_http_date(last_modified_header->value, last_modified_header->value_length);

        if (req_time != (time_t)-1 && res_time != (time_t)-1) {
            // If Last-Modified <= If-Modified-Since, return 304
            if (res_time <= req_time) {
                return 1; // Resource not modified
            }
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

int __generate_etag(time_t mtime, off_t size, char* etag_buf, size_t etag_buf_size) {
    if (etag_buf == NULL || etag_buf_size == 0)
        return -1;

    // Generate ETag in format: "mtime-size" (weak ETag)
    // Using weak ETag (W/) since we're using mtime which has 1-second granularity
    int n = snprintf(etag_buf, etag_buf_size, "W/\"%lx-%lx\"",
                     (unsigned long)mtime, (unsigned long)size);

    if (n < 0 || (size_t)n >= etag_buf_size)
        return -1;

    return n;
}

time_t __parse_http_date(const char* date, size_t len) {
    if (date == NULL || len == 0)
        return (time_t)-1;

    // Need null-terminated string for strptime
    char buf[64];
    if (len >= sizeof(buf))
        return (time_t)-1;

    memcpy(buf, date, len);
    buf[len] = '\0';

    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(tm_buf));

    // RFC 7231: HTTP-date = IMF-fixdate / obs-date
    // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT" (preferred)
    char* result = strptime(buf, "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);
    if (result == NULL) {
        // Try RFC 850 format: "Sunday, 06-Nov-94 08:49:37 GMT" (obsolete)
        memset(&tm_buf, 0, sizeof(tm_buf));
        result = strptime(buf, "%A, %d-%b-%y %H:%M:%S GMT", &tm_buf);
    }
    if (result == NULL) {
        // Try asctime format: "Sun Nov  6 08:49:37 1994" (obsolete)
        memset(&tm_buf, 0, sizeof(tm_buf));
        result = strptime(buf, "%a %b %d %H:%M:%S %Y", &tm_buf);
    }

    if (result == NULL)
        return (time_t)-1;

    // Convert to time_t (UTC)
    return timegm(&tm_buf);
}

#ifndef __HTTP_WRITE_FILTER__
#define __HTTP_WRITE_FILTER__

#include "httprequest.h"
#include "httpresponse.h"

/* How much of the first body chunk rides along with the head in one write.
 * Same value and same reasoning as H2_DATA_JOIN_MAX: past a couple of
 * kilobytes the copy costs more than the extra write saves, and the second
 * write is no longer the thing the client waits on. */
#define HTTP_WRITE_JOIN_MAX 2048

/* Small file bodies use the joined memory writer; multipart includes framing.
 * Build overrides are reserved for benchmark experiments. */
#ifndef HTTP_FILE_BUFFER_MAX
#define HTTP_FILE_BUFFER_MAX 2048
#endif
#ifndef HTTP_MULTIPART_BUFFER_MAX
#define HTTP_MULTIPART_BUFFER_MAX 16384
#endif

typedef struct {
    http_module_t base;
    bufo_t* buf;
} http_module_write_t;

http_filter_t* http_write_filter_create(void);
http_module_write_t* http_write_create(void);
void http_write_free(void* arg);
int http_write_header(httprequest_t* request, httpresponse_t* response);
int http_write_body(httprequest_t* request, httpresponse_t* response, bufo_t* buf);
int http_write_flush(httprequest_t* request, httpresponse_t* response);
int http_write_file(httprequest_t* request, httpresponse_t* response, off_t* offset);
int http_write_file_span(httprequest_t* request, httpresponse_t* response, off_t* offset, size_t end);
http_filter_t* http_file_writer(httpresponse_t* response, http_filter_t* filter);
int http_write_file_text(httpresponse_t* response, bufo_t* buf);

#endif

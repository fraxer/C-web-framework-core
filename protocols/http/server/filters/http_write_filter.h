#ifndef __HTTP_WRITE_FILTER__
#define __HTTP_WRITE_FILTER__

#include "httprequest.h"
#include "httpresponse.h"

/* How much of the first body chunk rides along with the head in one write.
 * Same value and same reasoning as H2_DATA_JOIN_MAX: past a couple of
 * kilobytes the copy costs more than the extra write saves, and the second
 * write is no longer the thing the client waits on. */
#define HTTP_WRITE_JOIN_MAX 2048

typedef struct {
    http_module_t base;
    bufo_t* buf;
} http_module_write_t;

http_filter_t* http_write_filter_create(void);
http_module_write_t* http_write_create(void);
void http_write_free(void* arg);
int http_write_header(httprequest_t* request, httpresponse_t* response);
int http_write_body(httprequest_t* request, httpresponse_t* response, bufo_t* buf);
/* Push out a head that no body pass claimed (HEAD, 304, 204, empty body).
 * Called once per response after the body filters — see __run_flush_filters. */
int http_write_flush(httprequest_t* request, httpresponse_t* response);

#endif

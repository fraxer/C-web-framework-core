#ifndef __HTTP_FILTER__
#define __HTTP_FILTER__

#include "bufo.h"

#define CWF_OK            0
#define CWF_ERROR        -1
#define CWF_EVENT_AGAIN  -2
#define CWF_DATA_AGAIN   -3

struct httprequest;
struct httpresponse;

typedef struct {
    unsigned cont : 1; /* continue if not all data sent */
    unsigned done : 1; /* module process all data from parent buffer */
    bufo_t* parent_buf;
    void(*reset)(void*);
    void(*free)(void*);
} http_module_t;

typedef struct http_filter {
    void* module; // http_module_t

    int(*handler_header)(struct httprequest* request, struct httpresponse* response);
    int(*handler_body)(struct httprequest* request, struct httpresponse* response, bufo_t* buf);

    struct http_filter* next;
} http_filter_t;

http_filter_t* filters_create(void);
/* Filter chain for an HTTP/2 connection: same not_modified/range/data/gzip
 * stages, but the chunked stage is dropped (h2 frames the body in DATA frames,
 * chunked transfer-encoding is forbidden by RFC 9113 §8.2.2) and the terminal
 * write stage emits HEADERS/DATA frames instead of a status line + raw bytes. */
http_filter_t* filters_create_h2(void);
void filters_reset(http_filter_t* filter);
void filters_free(http_filter_t* filter);
int filter_next_handler_header(struct httprequest* request, struct httpresponse* response);
int filter_next_handler_body(struct httprequest* request, struct httpresponse* response, bufo_t* buf);

#endif

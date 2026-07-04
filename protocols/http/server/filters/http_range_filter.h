#ifndef HTTP_RANGE_FILTER_H
#define HTTP_RANGE_FILTER_H

#include "httprequest.h"
#include "httpresponse.h"

/* One resolved (clamped, satisfiable) byte range of the representation. */
typedef struct {
    size_t start;   /* first byte position, inclusive */
    size_t size;    /* range length in bytes, always >= 1 */
} http_range_part_t;

typedef struct {
    http_module_t base;
    bufo_t* buf;
    size_t range_size;
    size_t range_pos;

    /* single-range mode: resolved first byte of the served range */
    size_t range_start;

    /* 416: headers are framed, but the body phase must emit nothing */
    unsigned unsatisfiable : 1;
    /* multipart/byteranges mode (the request carried several ranges) */
    unsigned mp_active : 1;

    /* multipart/byteranges state */
    http_range_part_t* parts;
    size_t parts_count;
    size_t part_index;
    int mp_state;
    size_t mp_total;        /* complete-length for Content-Range lines */
    size_t data_pos;        /* position inside the current part's data */
    char* part_ctype;       /* Content-Type replayed inside each part */
    char* text;             /* staged part header / close delimiter */
    size_t text_len;
    size_t text_pos;
    char boundary[17];
} http_module_range_t;

http_filter_t* http_range_filter_create(void);

#endif

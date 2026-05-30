#ifndef __HTTP1MULTIPARTPARSER__
#define __HTTP1MULTIPARTPARSER__

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "httpcommon.h"

typedef enum multipartstage {
    MP_STG_FIRST_SEPARATOR = 0,
    MP_STG_HEADER_KEY,
    MP_STG_HEADER_SPACE,
    MP_STG_HEADER_VALUE,
    MP_STG_HEADER_END,
    MP_STG_EXTRA_CR,
    MP_STG_EXTRA_LF,
    MP_STG_BODY,
    MP_STG_END_CR,
    MP_STG_END_LF,
} multipartstage_e;

typedef enum multipart_res {
    MP_RES_ERROR = 0,
    MP_RES_PARTIAL,
    MP_RES_DONE,
} multipart_res_e;

typedef struct multipartparser {
    const char* boundary;
    size_t payload_size;
    size_t payload_offset;
    size_t header_key_offset;
    size_t header_value_offset;
    size_t header_key_size;
    size_t header_value_size;
    size_t part_offset;
    size_t part_size;
    size_t separator_index;
    size_t first_separator_size;
    size_t intermediate_separator_size;
    multipartstage_e stage;
    http_payloadpart_t* part;
    http_payloadpart_t* last_part;
    http_header_t* header;
    http_header_t* last_header;
    int payload_fd;
    const char* error;
    int header_count;
    char prev_ch;
} multipartparser_t;

void multipartparser_init(multipartparser_t*, int, const char*);
multipart_res_e multipartparser_parse(multipartparser_t*, char*, size_t);
http_payloadpart_t* multipartparser_part(multipartparser_t*);
void multipartparser_clear(multipartparser_t*);

#endif
#ifndef __HTTP1URLENCODEDPARSER__
#define __HTTP1URLENCODEDPARSER__

#include <stdlib.h>
#include <stddef.h>

#include "httpcommon.h"

#define URLENCODEDPARSER_MAX_PARTS 256

typedef struct urlencodedparser {
    http_payloadpart_t* part;
    http_payloadpart_t* last_part;
    const char* error;
    size_t payload_size;
    size_t payload_offset;
    size_t offset;
    size_t size;
    int find_amp;
    int part_count;
    int limit_reached;
    int payload_fd;
} urlencodedparser_t;

void urlencodedparser_init(urlencodedparser_t* parser, int payload_fd, size_t payload_size);
int urlencodedparser_parse(urlencodedparser_t* parser, char* buffer, size_t buffer_size);
http_payloadpart_t* urlencodedparser_part(urlencodedparser_t* parser);

#endif
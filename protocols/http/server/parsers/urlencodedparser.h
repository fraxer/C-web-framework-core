#ifndef __HTTP1URLENCODEDPARSER__
#define __HTTP1URLENCODEDPARSER__

#include <stdlib.h>
#include <stddef.h>

#include "httpcommon.h"

#define URLENCODEDPARSER_MAX_PARTS 256

typedef struct urlencodedparser {
    http_payloadfield_t* field;
    http_payloadfield_t* last_field;
    const char* error;
    size_t payload_size;
    size_t payload_offset;
    size_t offset;
    size_t size;
    int find_amp;
    int field_count;
    int limit_reached;
    int payload_fd;
} urlencodedparser_t;

void urlencodedparser_init(urlencodedparser_t* parser, int payload_fd, size_t payload_size);
int urlencodedparser_parse(urlencodedparser_t* parser, char* buffer, size_t buffer_size);
http_payloadfield_t* urlencodedparser_field(urlencodedparser_t* parser);
void urlencodedparser_clear(urlencodedparser_t* parser);

#endif
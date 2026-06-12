#ifndef __HTTP1COOKIEPARSER__
#define __HTTP1COOKIEPARSER__

#include <stddef.h>

#include "httpcommon.h"

typedef struct cookieparser {
    const char* error;
    http_cookie_t* cookie;
    http_cookie_t* last_cookie;
} cookieparser_t;

void cookieparser_init(cookieparser_t* parser);
int cookieparser_parse(cookieparser_t* parser, const char* buffer, size_t buffer_size);
http_cookie_t* cookieparser_cookie(cookieparser_t* parser);

#endif
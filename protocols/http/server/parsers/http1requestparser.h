#ifndef __HTTP1REQUESTPARSER__
#define __HTTP1REQUESTPARSER__

#include "connection_s.h"
#include "http1parsercommon.h"
#include "http1request.h"
#include "bufferdata.h"

typedef enum http1requestparser_stage {
    HTTP1REQUESTPARSER_METHOD = 0,
    HTTP1REQUESTPARSER_URI,
    HTTP1REQUESTPARSER_PROTOCOL,
    HTTP1REQUESTPARSER_NEWLINE1,
    HTTP1REQUESTPARSER_HEADER_KEY,
    HTTP1REQUESTPARSER_HEADER_SPACE,
    HTTP1REQUESTPARSER_HEADER_VALUE,
    HTTP1REQUESTPARSER_NEWLINE2,
    HTTP1REQUESTPARSER_NEWLINE3,
    HTTP1REQUESTPARSER_PAYLOAD
} http1requestparser_stage_e;

typedef struct http1requestparser {
    requestparser_t base;
    char* buffer;
    bufferdata_t buf;
    size_t bytes_readed;
    size_t pos_start;
    size_t pos;
    connection_t* connection;
    http1request_t* request;
    http1requestparser_stage_e stage;
    int host_found;
    size_t content_length;
    size_t content_saved_length;
} http1requestparser_t;

http1requestparser_t* http1parser_create(connection_t* connection);
void http1parser_init(http1requestparser_t* parser, connection_t* connection);
void http1parser_free(void* arg);
void http1parser_reset(http1requestparser_t*);
int http1parser_run(http1requestparser_t* parser);
void http1parser_set_bytes_readed(http1requestparser_t*, int);
void http1parser_prepare_continue(http1requestparser_t* parser);
int http1parser_set_uri(http1request_t*, const char*, size_t);
void http1parser_append_query(http1request_t*, http1_query_t*);
http1_ranges_t* http1parser_parse_range(char*, size_t);

#endif
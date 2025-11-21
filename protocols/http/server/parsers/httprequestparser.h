#ifndef __HTTP1REQUESTPARSER__
#define __HTTP1REQUESTPARSER__

#include "connection_s.h"
#include "httpparsercommon.h"
#include "httprequest.h"
#include "bufferdata.h"

typedef enum httprequestparser_stage {
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
} httprequestparser_stage_e;

typedef struct httprequestparser {
    requestparser_t base;
    char* buffer;
    bufferdata_t buf;
    size_t bytes_readed;
    size_t pos_start;
    size_t pos;
    connection_t* connection;
    httprequest_t* request;
    httprequestparser_stage_e stage;
    int host_found;
    size_t content_length;
    size_t content_saved_length;
} httprequestparser_t;

httprequestparser_t* httpparser_create(connection_t* connection);
void httpparser_init(httprequestparser_t* parser, connection_t* connection);
void httpparser_free(void* arg);
void httpparser_reset(httprequestparser_t*);
int httpparser_run(httprequestparser_t* parser);
void httpparser_set_bytes_readed(httprequestparser_t*, int);
void httpparser_prepare_continue(httprequestparser_t* parser);
int httpparser_set_uri(httprequest_t*, const char*, size_t);
void httpparser_append_query(httprequest_t*, query_t*);
http_ranges_t* httpparser_parse_range(char*, size_t);

#endif
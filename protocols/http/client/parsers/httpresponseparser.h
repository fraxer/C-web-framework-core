#ifndef __HTTP1RESPONSEPARSER__
#define __HTTP1RESPONSEPARSER__

#include "connection_c.h"
#include "httpparsercommon.h"
#include "httpteparser.h"
#include "httpresponse.h"
#include "queryparser.h"
#include "bufferdata.h"
#include "gzip.h"

typedef enum httpresponseparser_stage {
    HTTP1RESPONSEPARSER_PROTOCOL = 0,
    HTTP1RESPONSEPARSER_STATUS_CODE,
    HTTP1RESPONSEPARSER_STATUS_TEXT,
    HTTP1RESPONSEPARSER_NEWLINE1,
    HTTP1RESPONSEPARSER_HEADER_KEY,
    HTTP1RESPONSEPARSER_HEADER_SPACE,
    HTTP1RESPONSEPARSER_HEADER_VALUE,
    HTTP1RESPONSEPARSER_NEWLINE2,
    HTTP1RESPONSEPARSER_NEWLINE3,
    HTTP1RESPONSEPARSER_PAYLOAD,
    HTTP1RESPONSEPARSER_COMPLETE
} httpresponseparser_stage_e;

typedef struct httpresponseparser {
    httpresponseparser_stage_e stage;
    bufferdata_t buf;
    size_t bytes_readed;
    size_t pos_start;
    size_t pos;
    size_t content_length;
    size_t content_saved_length;
    gzip_t gzip;
    char* buffer;
    connection_t* connection;
    httpteparser_t* teparser;
} httpresponseparser_t;

void httpresponseparser_init(httpresponseparser_t*);
void httpresponseparser_set_connection(httpresponseparser_t*, connection_t*);
void httpresponseparser_set_buffer(httpresponseparser_t*, char*);
void httpresponseparser_free(httpresponseparser_t*);
void httpresponseparser_reset(httpresponseparser_t*);
int httpresponseparser_run(httpresponseparser_t*);
void httpresponseparser_set_bytes_readed(httpresponseparser_t*, int);
void httpresponseparser_append_query(httpresponse_t*, query_t*);

#endif
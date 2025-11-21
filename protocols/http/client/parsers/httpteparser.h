#ifndef __HTTPTEPARSER__
#define __HTTPTEPARSER__

#include "connection_c.h"
#include "httpparsercommon.h"
#include "httpresponse.h"
#include "bufferdata.h"
#include "gzip.h"

typedef enum httpteparser_status {
    HTTP1TEPARSER_ERROR = 0,
    HTTP1TEPARSER_CONTINUE,
    HTTP1TEPARSER_COMPLETE
} httpteparser_status_e;

typedef enum httpteparser_stage {
    HTTP1TEPARSER_CHUNKSIZE = 0,
    HTTP1TEPARSER_CHUNKSIZE_NEWLINE,
    HTTP1TEPARSER_CHUNK,
    HTTP1TEPARSER_CHUNK_NEWLINE
} httpteparser_stage_e;

typedef struct httpteparser {
    httpteparser_stage_e stage;
    bufferdata_t buf;
    size_t bytes_readed;
    size_t pos_start;
    size_t pos;
    size_t chunk_size;
    size_t chunk_size_readed;
    gzip_t gzip;
    char* buffer;
    connection_t* connection;
} httpteparser_t;

httpteparser_t* httpteparser_init();
void httpteparser_free(httpteparser_t*);
void httpteparser_set_buffer(httpteparser_t*, char*, size_t);
int httpteparser_run(httpteparser_t*);

#endif
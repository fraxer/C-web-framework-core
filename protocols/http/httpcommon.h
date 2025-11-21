#ifndef __HTTP1COMMON__
#define __HTTP1COMMON__

#include <stddef.h>

#include "file.h"
#include "helpers.h"

typedef struct http_header {
    char* key;
    char* value;
    size_t key_length;
    size_t value_length;
    struct http_header* next;
} http_header_t, http_cookie_t;

typedef enum http_version {
    HTTP1_VER_NONE = 0,
    HTTP1_VER_1_0,
    HTTP1_VER_1_1
} http_version_e;

typedef enum http_content_encoding {
    CE_NONE = 0,
    CE_GZIP
} http_content_encoding_t;

typedef enum http_trunsfer_encoding {
    TE_NONE = 0,
    TE_CHUNKED,
    TE_GZIP
} http_trunsfer_encoding_t;

typedef struct http_ranges {
    ssize_t start;
    ssize_t end;
    struct http_ranges* next;
} http_ranges_t;

typedef struct http_payloadfield {
    char* key;
    char* value;
    size_t key_length;
    size_t value_length;
    struct http_payloadfield* next;
} http_payloadfield_t;

typedef struct http_payloadpart {
    size_t offset;
    size_t size;
    http_payloadfield_t* field;
    http_header_t* header;

    struct http_payloadpart* next;
} http_payloadpart_t;

typedef enum {
    NONE = 0,
    PLAIN,
    MULTIPART,
    URLENCODED
} http_payload_type_e;

typedef struct http_payload {
    size_t pos;
    file_t file;
    char* path;
    char* boundary;
    http_payloadpart_t* part;
    http_payload_type_e type;
} http_payload_t;

http_header_t* http_header_create(const char*, size_t, const char*, size_t);
void http_header_free(http_header_t*);
void http_headers_free(http_header_t*);
http_header_t* http_header_delete(http_header_t*, const char*);

http_payloadpart_t* http_payloadpart_create();
void http_payloadpart_free(http_payloadpart_t*);
http_payloadfield_t* http_payloadfield_create();
void http_payloadfield_free(http_payloadfield_t*);

http_cookie_t* http_cookie_create();
void http_cookie_free(http_cookie_t*);

void http_ranges_free(http_ranges_t* ranges);

#endif

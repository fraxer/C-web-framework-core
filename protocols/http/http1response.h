#ifndef __HTTP1RESPONSE__
#define __HTTP1RESPONSE__

#include "connection_s.h"
#include "server.h"
#include "http1common.h"
#include "array.h"
#include "json.h"
#include "response.h"
#include "http_filter.h"

typedef enum {
    FILE_OK = 0,
    FILE_FORBIDDEN,
    FILE_NOTFOUND,
} file_status_e;

typedef struct {
    const char* name;
    const char* value;
    int seconds;
    const char* path;
    const char* domain;
    int secure;
    int http_only;
    const char* same_site;
} cookie_t;

typedef struct http1response {
    response_t base;
    
    http1_header_t* header_;
    http1_header_t* last_header;
    http1_ranges_t* ranges;
    http_filter_t* filter;
    http_filter_t* cur_filter;
    

    void* parser;
    void* connection;

    void(*data)(struct http1response*, const char*);
    void(*datan)(struct http1response*, const char*, size_t);
    void(*view)(struct http1response*, json_doc_t* document, const char* storage_name, const char* path_format, ...);
    void(*def)(struct http1response*, int);
    void(*json)(struct http1response*, json_doc_t* document);
    void(*model)(struct http1response*, void* model, ...);
    void(*models)(struct http1response*, array_t* models, ...);

    void(*redirect)(struct http1response*, const char*, int);
    http1_header_t*(*header)(struct http1response*, const char*);
    int(*header_add)(struct http1response*, const char*, const char*);
    int(*headern_add)(struct http1response*, const char*, size_t, const char*, size_t);
    int(*headeru_add)(struct http1response*, const char*, size_t, const char*, size_t);
    int(*header_add_content_length)(struct http1response*, size_t);
    int(*header_remove)(struct http1response*, const char*);
    int(*headern_remove)(struct http1response*, const char*, size_t);
    void(*file)(struct http1response*, const char*);
    void(*filen)(struct http1response*, const char*, size_t);
    void(*filef)(struct http1response*, const char*, const char*, ...);
    void(*cookie_add)(struct http1response*, cookie_t);

    char*(*payload)(struct http1response*);
    file_content_t(*payload_file)(struct http1response*);
    json_doc_t*(*payload_json)(struct http1response*);
    
    size_t content_length;

    bufo_t body;
    file_t file_;

    http1_version_e version;
    http1_payload_t payload_;

    short status_code;

    unsigned transfer_encoding : 3;
    unsigned content_encoding : 2;
    unsigned event_again : 1;
    unsigned headers_sended : 1;
    unsigned range : 1;
} http1response_t;

http1response_t* http1response_create(connection_t* connection);
void http1response_free(void* arg);
void http1response_redirect(http1response_t* response, const char* path, int status_code);
http1_ranges_t* http1response_init_ranges(void);
void http1_ranges_free(http1_ranges_t* ranges);
int http1response_redirect_is_external(const char* url);
const char* http1response_status_string(int status_code);
int http1response_has_payload(http1response_t* response);
file_status_e http1_get_file_full_path(server_t* server, char* file_full_path, size_t file_full_path_size, const char* path, size_t length);
void http1_response_file(http1response_t* response, const char* file_full_path);
size_t http1response_status_length(int status_code);

void http1response_default(http1response_t* response, int status_code);

#endif

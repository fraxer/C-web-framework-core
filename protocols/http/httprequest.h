#ifndef __HTTP1REQUEST__
#define __HTTP1REQUEST__

#include "route.h"
#include "connection.h"
#include "httpcommon.h"
#include "queryparser.h"
#include "json.h"
#include "request.h"

typedef struct httprequest_head {
    size_t size;
    char* data;
} httprequest_head_t;

typedef struct httprequest {
    request_t base;

    const char* uri;
    const char* path;

    query_t* query_;
    query_t* last_query;
    http_header_t* header_;
    http_header_t* last_header;
    http_cookie_t* cookie_;
    http_ranges_t* ranges;

    connection_t* connection;

    /**
     * Get HTTP header by name.
     * @param request - HTTP request instance
     * @param name - header name (null-terminated string)
     * @return pointer to header structure or NULL if not found
     */
    http_header_t*(*get_header)(struct httprequest* request, const char* name);

    /**
     * Get HTTP header by name with length.
     * @param request - HTTP request instance
     * @param name - header name (not necessarily null-terminated)
     * @param name_length - length of header name
     * @return pointer to header structure or NULL if not found
     */
    http_header_t*(*get_headern)(struct httprequest* request, const char* name, size_t name_length);

    /**
     * Add new HTTP header to request.
     * @param request - HTTP request instance
     * @param name - header name (null-terminated string)
     * @param value - header value (null-terminated string)
     * @return 0 on success, -1 on error
     */
    int(*add_header)(struct httprequest* request, const char* name, const char* value);

    /**
     * Add new HTTP header with explicit lengths.
     * @param request - HTTP request instance
     * @param name - header name (not necessarily null-terminated)
     * @param name_length - length of header name
     * @param value - header value (not necessarily null-terminated)
     * @param value_length - length of header value
     * @return 0 on success, -1 on error
     */
    int(*add_headern)(struct httprequest* request, const char* name, size_t name_length, const char* value, size_t value_length);

    /**
     * Remove HTTP header by name.
     * @param request - HTTP request instance
     * @param name - header name to remove (null-terminated string)
     * @return 0 on success, -1 if not found
     */
    int(*remove_header)(struct httprequest* request, const char* name);

    /**
     * Get cookie value by name.
     * @param request - HTTP request instance
     * @param name - cookie name (null-terminated string)
     * @return pointer to cookie value or NULL if not found
     */
    const char*(*get_cookie)(struct httprequest* request, const char* name);

    /**
     * Get request payload as string.
     * @param request - HTTP request instance
     * @return pointer to payload data or NULL if no payload
     */
    char*(*get_payload)(struct httprequest* request);

    /**
     * Get specific field from request payload.
     * @param request - HTTP request instance
     * @param field - field name to extract (null-terminated string)
     * @return pointer to field value or NULL if not found
     */
    char*(*get_payloadf)(struct httprequest* request, const char* field);

    /**
     * Get request payload as file content.
     * @param request - HTTP request instance
     * @return file_content_t structure with payload data
     */
    file_content_t(*get_payload_file)(struct httprequest* request);

    /**
     * Get specific file field from multipart payload.
     * @param request - HTTP request instance
     * @param field - field name containing file (null-terminated string)
     * @return file_content_t structure with file data
     */
    file_content_t(*get_payload_filef)(struct httprequest* request, const char* field);

    /**
     * Get request payload as JSON document.
     * @param request - HTTP request instance
     * @return pointer to parsed JSON document or NULL on error
     */
    json_doc_t*(*get_payload_json)(struct httprequest* request);

    /**
     * Get specific field from payload as JSON.
     * @param request - HTTP request instance
     * @param field - field name containing JSON (null-terminated string)
     * @return pointer to parsed JSON document or NULL on error
     */
    json_doc_t*(*get_payload_jsonf)(struct httprequest* request, const char* field);

    /**
     * Append URL-encoded form field to request payload.
     * @param request - HTTP request instance
     * @param name - field name (null-terminated string)
     * @param value - field value (null-terminated string)
     * @return 0 on success, -1 on error
     */
    int(*append_urlencoded)(struct httprequest* request, const char* name, const char* value);

    /**
     * Append raw data as multipart form field.
     * @param request - HTTP request instance
     * @param name - field name (null-terminated string)
     * @param content_type - MIME type of data (null-terminated string)
     * @param data - raw data to append (null-terminated string)
     * @return 0 on success, -1 on error
     */
    int(*append_formdata_raw)(struct httprequest* request, const char* name, const char* content_type, const char* data);

    /**
     * Append text as multipart form field.
     * @param request - HTTP request instance
     * @param name - field name (null-terminated string)
     * @param text - text value (null-terminated string)
     * @return 0 on success, -1 on error
     */
    int(*append_formdata_text)(struct httprequest* request, const char* name, const char* text);

    /**
     * Append JSON document as multipart form field.
     * @param request - HTTP request instance
     * @param name - field name (null-terminated string)
     * @param json - JSON document to append
     * @return 0 on success, -1 on error
     */
    int(*append_formdata_json)(struct httprequest* request, const char* name, json_doc_t* json);

    /**
     * Append file from filesystem path as multipart form field.
     * @param request - HTTP request instance
     * @param name - field name (null-terminated string)
     * @param filepath - path to file on filesystem (null-terminated string)
     * @return 0 on success, -1 on error
     */
    int(*append_formdata_filepath)(struct httprequest* request, const char* name, const char* filepath);

    /**
     * Append file_t structure as multipart form field.
     * @param request - HTTP request instance
     * @param name - field name (null-terminated string)
     * @param file - pointer to file_t structure
     * @return 0 on success, -1 on error
     */
    int(*append_formdata_file)(struct httprequest* request, const char* name, file_t* file);

    /**
     * Append file content as multipart form field.
     * @param request - HTTP request instance
     * @param name - field name (null-terminated string)
     * @param content - pointer to file_content_t structure
     * @return 0 on success, -1 on error
     */
    int(*append_formdata_file_content)(struct httprequest* request, const char* name, file_content_t* content);

    /**
     * Set raw request payload with explicit content type and length.
     * @param request - HTTP request instance
     * @param content_type - MIME type of payload (null-terminated string)
     * @param length - length of payload data
     * @param data - raw payload data
     * @return 0 on success, -1 on error
     */
    int(*set_payload_raw)(struct httprequest* request, const char* content_type, const size_t length, const char* data);

    /**
     * Set plain text request payload.
     * @param request - HTTP request instance
     * @param text - text payload (null-terminated string)
     * @return 0 on success, -1 on error
     */
    int(*set_payload_text)(struct httprequest* request, const char* text);

    /**
     * Set JSON document as request payload.
     * @param request - HTTP request instance
     * @param json - JSON document to send
     * @return 0 on success, -1 on error
     */
    int(*set_payload_json)(struct httprequest* request, json_doc_t* json);

    /**
     * Set file from filesystem path as request payload.
     * @param request - HTTP request instance
     * @param filepath - path to file on filesystem (null-terminated string)
     * @return 0 on success, -1 on error
     */
    int(*set_payload_filepath)(struct httprequest* request, const char* filepath);

    /**
     * Set file_t structure as request payload.
     * @param request - HTTP request instance
     * @param file - pointer to file_t structure
     * @return 0 on success, -1 on error
     */
    int(*set_payload_file)(struct httprequest* request, const file_t* file);

    /**
     * Set file content as request payload.
     * @param request - HTTP request instance
     * @param content - pointer to file_content_t structure
     * @return 0 on success, -1 on error
     */
    int(*set_payload_file_content)(struct httprequest* request, const file_content_t* content);

    route_methods_e method;
    http_version_e version;
    http_payload_t payload_;
    http_trunsfer_encoding_t transfer_encoding;
    http_content_encoding_t content_encoding;

    size_t uri_length;
    size_t path_length;
} httprequest_t;

httprequest_t* httprequest_create(connection_t*);
void httprequest_free(void* arg);
char* httprequest_payload(httprequest_t*);
char* httprequest_payloadf(httprequest_t*, const char*);
file_content_t httprequest_payload_file(httprequest_t*);
file_content_t httprequest_payload_filef(httprequest_t*, const char*);
json_doc_t* httprequest_payload_json(httprequest_t*);
json_doc_t* httprequest_payload_jsonf(httprequest_t*, const char*);
int httprequest_allow_payload(httprequest_t*);
int httpparser_set_uri(httprequest_t*, const char*, size_t);
void httpparser_append_query(httprequest_t*, query_t*);
httprequest_head_t httprequest_create_head(httprequest_t*);

#endif

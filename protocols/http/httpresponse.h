#ifndef __HTTP1RESPONSE__
#define __HTTP1RESPONSE__

#include "connection_s.h"
#include "server.h"
#include "httpcommon.h"
#include "array.h"
#include "json.h"
#include "response.h"
#include "http_filter.h"

typedef enum {
    FILE_OK = 0,
    FILE_FORBIDDEN,
    FILE_NOTFOUND,
} file_status_e;

/*
 * HTTP cookie structure.
 * Used with response->add_cookie().
 */
typedef struct {
    const char* name;       /* Cookie name (required) */
    const char* value;      /* Cookie value (required) */
    int seconds;            /* Lifetime in seconds (0 = session cookie) */
    const char* path;       /* Cookie path (NULL to skip) */
    const char* domain;     /* Cookie domain (NULL to skip) */
    int secure;             /* 1 = HTTPS only */
    int http_only;          /* 1 = not accessible from JavaScript */
    const char* same_site;  /* "Strict", "Lax" or "None" (NULL to skip) */
} cookie_t;

typedef struct httpresponse {
    response_t base;

    http_header_t* header_;
    http_header_t* last_header;
    http_filter_t* filter;
    http_filter_t* cur_filter;

    void* parser;
    void* connection;

    /*
     * Send text data (null-terminated string).
     * Content-Type: text/html; charset=utf-8
     * @param response - pointer to httpresponse
     * @param data - null-terminated string to send
     */
    void(*send_data)(struct httpresponse* response, const char* data);

    /*
     * Send text data with specified length.
     * Content-Type: text/html; charset=utf-8
     * @param response - pointer to httpresponse
     * @param data - data to send
     * @param length - data length in bytes
     */
    void(*send_datan)(struct httpresponse* response, const char* data, size_t size);

    /*
     * Render and send HTML template (view).
     * @param response - pointer to httpresponse
     * @param document - JSON document with template data (can be NULL)
     * @param storage_name - template storage name
     * @param path_format - template path format (supports printf formatting)
     * @param ... - arguments for path formatting
     */
    void(*send_view)(struct httpresponse* response, json_doc_t* document, const char* storage_name, const char* path_format, ...);

    /*
     * Send default HTTP response with status code.
     * Generates HTML page with status text.
     * @param response - pointer to httpresponse
     * @param status_code - HTTP status code (200, 404, 500, etc.)
     */
    void(*send_default)(struct httpresponse* response, int status_code);

    /*
     * Send JSON document.
     * Content-Type: application/json
     * @param response - pointer to httpresponse
     * @param document - JSON document to serialize and send
     */
    void(*send_json)(struct httpresponse* response, json_doc_t* document);

    /*
     * Serialize model to JSON and send.
     * Content-Type: application/json
     * @param response - pointer to httpresponse
     * @param model - pointer to data model
     * @param ... - array of field names to display (char**), NULL for all fields
     */
    void(*send_model)(struct httpresponse* response, void* model, ...);

    /*
     * Serialize array of models to JSON array and send.
     * Content-Type: application/json
     * @param response - pointer to httpresponse
     * @param models - array of models (array_t*)
     * @param ... - array of field names to display (char**), NULL for all fields
     */
    void(*send_models)(struct httpresponse* response, array_t* models, ...);

    /*
     * Perform HTTP redirect.
     * @param response - pointer to httpresponse
     * @param path - redirect URL
     * @param status_code - HTTP redirect code (301, 302, 307, 308)
     */
    void(*redirect)(struct httpresponse* response, const char* path, int status_code);

    /*
     * Get response header by key.
     * @param response - pointer to httpresponse
     * @param key - header name (case-insensitive search)
     * @return pointer to header or NULL if not found
     */
    http_header_t*(*get_header)(struct httpresponse* response, const char* key);

    /*
     * Add header to response (null-terminated strings).
     * @param response - pointer to httpresponse
     * @param key - header name
     * @param value - header value
     * @return 1 on success, 0 on error
     */
    int(*add_header)(struct httpresponse* response, const char* key, const char* value);

    /*
     * Add header to response with specified lengths.
     * @param response - pointer to httpresponse
     * @param key - header name
     * @param key_length - header name length
     * @param value - header value
     * @param value_length - header value length
     * @return 1 on success, 0 on error
     */
    int(*add_headern)(struct httpresponse* response, const char* key, size_t key_length, const char* value, size_t value_length);

    /*
     * Add header if it doesn't already exist (unique).
     * @param response - pointer to httpresponse
     * @param key - header name
     * @param key_length - header name length
     * @param value - header value
     * @param value_length - header value length
     * @return 1 on success or if header already exists, 0 on error
     */
    int(*add_headeru)(struct httpresponse* response, const char* key, size_t key_length, const char* value, size_t value_length);

    /*
     * Add Content-Length header.
     * @param response - pointer to httpresponse
     * @param length - content size in bytes
     * @return 1 on success, 0 on error
     */
    int(*add_content_length)(struct httpresponse* response, size_t length);

    /*
     * Remove header from response.
     * @param response - pointer to httpresponse
     * @param key - header name to remove
     * @return 1 on success, 0 on error
     */
    int(*remove_header)(struct httpresponse* response, const char* key);

    /*
     * Send file by relative path (null-terminated).
     * Automatically detects Content-Type by file extension.
     * @param response - pointer to httpresponse
     * @param path - relative path to file from server root
     */
    void(*send_file)(struct httpresponse* response, const char* path);

    /*
     * Send file by relative path with specified length.
     * Automatically detects Content-Type by file extension.
     * @param response - pointer to httpresponse
     * @param path - relative path to file from server root
     * @param length - path length
     */
    void(*send_filen)(struct httpresponse* response, const char* path, size_t length);

    /*
     * Send file from storage with path formatting.
     * Automatically detects Content-Type by file extension.
     * @param response - pointer to httpresponse
     * @param storage_name - storage name
     * @param path_format - file path format (supports printf formatting)
     * @param ... - arguments for path formatting
     */
    void(*send_filef)(struct httpresponse* response, const char* storage_name, const char* path_format, ...);

    /*
     * Add cookie to response.
     * @param response - pointer to httpresponse
     * @param cookie - cookie_t structure with parameters
     */
    void(*add_cookie)(struct httpresponse* response, cookie_t cookie);

    /*
     * Get request body as string.
     * Returns a copy of data that must be freed with free().
     * @param response - pointer to httpresponse
     * @return null-terminated string or NULL on error
     */
    char*(*get_payload)(struct httpresponse* response);

    /*
     * Get request body as file.
     * @param response - pointer to httpresponse
     * @return file_content_t structure with file information
     */
    file_content_t(*get_payload_file)(struct httpresponse* response);

    /*
     * Parse request body as JSON.
     * Returns document that must be freed with json_free().
     * @param response - pointer to httpresponse
     * @return JSON document or NULL on parse error
     */
    json_doc_t*(*get_payload_json)(struct httpresponse* response);
    
    size_t content_length;

    bufo_t body;
    file_t file_;

    http_version_e version;
    http_payload_t payload_;

    short status_code;

    unsigned transfer_encoding : 3;
    unsigned content_encoding : 2;
    unsigned event_again : 1;
    unsigned headers_sended : 1;
    unsigned range : 1;
    unsigned last_modified : 1;
} httpresponse_t;

httpresponse_t* httpresponse_create(connection_t* connection);
void httpresponse_free(void* arg);
void httpresponse_redirect(httpresponse_t* response, const char* path, int status_code);
http_ranges_t* httpresponse_init_ranges(void);
void http_ranges_free(http_ranges_t* ranges);
int httpresponse_redirect_is_external(const char* url);
const char* httpresponse_status_string(int status_code);
int httpresponse_has_payload(httpresponse_t* response);
file_status_e http_get_file_full_path(server_t* server, char* file_full_path, size_t file_full_path_size, const char* path, size_t length);
void http_response_file(httpresponse_t* response, const char* file_full_path);
size_t httpresponse_status_length(int status_code);

void httpresponse_default(httpresponse_t* response, int status_code);

#endif

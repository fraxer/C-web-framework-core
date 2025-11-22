#ifndef __WEBSOCKETSPROTOCOLRESOURCE__
#define __WEBSOCKETSPROTOCOLRESOURCE__

#include "connection.h"
#include "route.h"
#include "websocketsrequest.h"

/**
 * Parser stages for resource protocol.
 * Message format: "METHOD /path?query DATA"
 */
typedef enum {
    WSPROTRESOURCE_METHOD = 0,  /**< Parsing HTTP method (GET, POST, PATCH, DELETE) */
    WSPROTRESOURCE_LOCATION,    /**< Parsing URI with path and query string */
    WSPROTRESOURCE_DATA         /**< Parsing payload body (for POST/PATCH) */
} websockets_protocol_resource_stage_e;

/**
 * Resource-based WebSocket protocol with HTTP-like routing.
 * Parses messages in format: "METHOD /path?query DATA"
 * Supports route matching, path parameters, and query strings.
 * Example: "POST /api/users?sort=name {\"name\":\"John\"}"
 */
typedef struct websockets_protocol_resource {
    /** Base protocol with common handlers */
    websockets_protocol_t base;

    /** HTTP method: ROUTE_GET, ROUTE_POST, ROUTE_PATCH, ROUTE_DELETE */
    route_methods_e method;

    /** Current parser stage (method -> location -> data) */
    websockets_protocol_resource_stage_e parser_stage;

    /** Length of raw URI string (before decoding) */
    size_t uri_length;

    /** Length of decoded path (without query string) */
    size_t path_length;

    /** Raw URI string including query (e.g., "/api/users?id=1") */
    char* uri;

    /** URL-decoded path without query (e.g., "/api/users") */
    char* path;

    /** Linked list of query parameters and route params */
    query_t* query_;

    /**
     * Extract payload as null-terminated string.
     * @param protocol Pointer to this protocol instance
     * @return Allocated string (caller must free), or NULL if no payload
     */
    char*(*get_payload)(struct websockets_protocol_resource* protocol);

    /**
     * Extract payload as file descriptor with metadata.
     * @param protocol Pointer to this protocol instance
     * @return file_content_t with fd, size, offset. Check .ok for validity
     */
    file_content_t(*get_payload_file)(struct websockets_protocol_resource* protocol);

    /**
     * Parse payload as JSON document.
     * @param protocol Pointer to this protocol instance
     * @return Parsed json_doc_t* (caller must free), or NULL on error
     */
    json_doc_t*(*get_payload_json)(struct websockets_protocol_resource* protocol);

    /**
     * Get query parameter or route parameter by key.
     * @param protocol Pointer to this protocol instance
     * @param key Parameter name to look up
     * @return Parameter value or NULL if not found
     */
    const char*(*get_query)(struct websockets_protocol_resource* protocol, const char* key);
} websockets_protocol_resource_t;

/**
 * Create resource WebSocket protocol instance.
 * @return Allocated protocol or NULL on failure
 */
websockets_protocol_t* websockets_protocol_resource_create(void);

/**
 * Configure connection to use resource WebSocket protocol.
 * Sets read/write handlers and creates parser with resource protocol.
 * @param connection Connection to configure
 * @return 1 on success, 0 on failure
 */
int set_websockets_resource(connection_t* connection);

#endif

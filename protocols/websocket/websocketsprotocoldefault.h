#ifndef __WEBSOCKETSPROTOCOLDEFAULT__
#define __WEBSOCKETSPROTOCOLDEFAULT__

#include "websocketsrequest.h"

/**
 * Default WebSocket protocol implementation.
 * Extends base protocol with payload extraction methods.
 * Stores payload data in temporary file with XOR mask decoding.
 */
typedef struct websockets_protocol_default {
    /** Base protocol with common handlers (parse, reset, free) */
    websockets_protocol_t base;

    /**
     * Extract payload as null-terminated string.
     * @param protocol Pointer to this protocol instance
     * @return Allocated string with payload content (caller must free), or NULL on error
     */
    char*(*get_payload)(struct websockets_protocol_default* protocol);

    /**
     * Extract payload as file descriptor with metadata.
     * @param protocol Pointer to this protocol instance
     * @return file_content_t with fd, size, offset. Check .ok field for validity
     */
    file_content_t(*get_payload_file)(struct websockets_protocol_default* protocol);

    /**
     * Parse payload as JSON document.
     * @param protocol Pointer to this protocol instance
     * @return Parsed json_doc_t* (caller must free), or NULL on parse error
     */
    json_doc_t*(*get_payload_json)(struct websockets_protocol_default* protocol);
} websockets_protocol_default_t;

/**
 * Create default WebSocket protocol instance.
 * @return Allocated protocol or NULL on allocation failure
 */
websockets_protocol_t* websockets_protocol_default_create(void);

/**
 * Configure connection to use default WebSocket protocol.
 * Sets read/write handlers and creates parser with default protocol.
 * @param connection Connection to configure
 * @return 1 on success, 0 on failure
 */
int set_websockets_default(connection_t* connection);

#endif

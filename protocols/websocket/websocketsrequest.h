#ifndef __WEBSOCKETSREQUEST__
#define __WEBSOCKETSREQUEST__

#include "route.h"
#include "connection_s.h"
#include "websocketscommon.h"
#include "json.h"
#include "request.h"
#include "file.h"

struct websocketsrequest;
struct websocketsparser;

/**
 * WebSocket protocol interface.
 * Defines how incoming frames are parsed and processed.
 * Can be extended for custom protocol implementations (e.g., JSON-RPC, binary protocols).
 */
typedef struct websockets_protocol {
    /** Temporary file storage for payload data (fd + path) */
    websockets_payload_t payload;

    /**
     * Parse incoming payload chunk (called during frame reception).
     * Typically decodes XOR mask and writes to temp file.
     * @param parser Parser with current frame state
     * @param data Raw masked data chunk
     * @param size Chunk size in bytes
     * @return 1 on success, 0 on failure (connection will be closed)
     */
    int(*payload_parse)(struct websocketsparser* parser, char* data, size_t size);

    /**
     * Route request to appropriate handler after frame is complete.
     * @param connection Client connection
     * @param request Parsed WebSocket request
     * @return Handler result code
     */
    int(*get_resource)(connection_t* connection, struct websocketsrequest* request);

    /**
     * Reset protocol state for next request (called between frames).
     * @param protocol Pointer to protocol instance (cast to concrete type)
     */
    void(*reset)(void* protocol);

    /**
     * Free protocol and all associated resources.
     * @param protocol Pointer to protocol instance
     */
    void(*free)(void* protocol);
} websockets_protocol_t;

/**
 * WebSocket request representing a single incoming frame/message.
 */
typedef struct websocketsrequest {
    /** Base request interface (reset/free callbacks) */
    request_t base;

    /** Frame type: TEXT, BINARY, PING, PONG, CLOSE, CONTINUE, or NONE */
    websockets_datatype_e type;

    /** Protocol handler for parsing and routing this request */
    websockets_protocol_t* protocol;

    /** If 0, skip reset on next call (used during fragmented messages) */
    int can_reset;

    /** Non-zero if message spans multiple frames (continuation frames) */
    int fragmented;

    /** Connection this request belongs to */
    connection_t* connection;
} websocketsrequest_t;

/**
 * Create WebSocket request.
 * @param connection Connection this request belongs to
 * @param protocol Protocol handler for parsing/routing
 * @return Allocated request or NULL on failure
 */
websocketsrequest_t* websocketsrequest_create(connection_t* connection, websockets_protocol_t* protocol);

/**
 * Reset request state for reuse (clears payload, resets type).
 * Respects can_reset flag for fragmented message handling.
 * @param request Request to reset
 */
void websocketsrequest_reset(websocketsrequest_t* request);

/**
 * Reset request for continuation frame (preserves fragmented state).
 * @param request Request to reset
 */
void websocketsrequest_reset_continue(websocketsrequest_t* request);

/**
 * Free request and associated protocol.
 * @param arg Request to free (cast to websocketsrequest_t*)
 */
void websocketsrequest_free(void* arg);

/**
 * Read payload as string from protocol's temp file.
 * @param protocol Protocol with payload data
 * @return Allocated null-terminated string (caller must free), or NULL on error
 */
char* websocketsrequest_payload(websockets_protocol_t* protocol);

/**
 * Get payload as file content descriptor.
 * @param protocol Protocol with payload data
 * @return file_content_t with fd, size, offset. Check .ok for validity
 */
file_content_t websocketsrequest_payload_file(websockets_protocol_t* protocol);

/**
 * Parse payload as JSON document.
 * @param protocol Protocol with payload data
 * @return Parsed json_doc_t* (caller must free), or NULL on error
 */
json_doc_t* websocketsrequest_payload_json(websockets_protocol_t* protocol);

/**
 * Initialize protocol payload fields (fd=0, path=NULL).
 * @param protocol Protocol to initialize
 */
void websockets_protocol_init_payload(websockets_protocol_t* protocol);

/**
 * Create temporary file for payload storage.
 * @param protocol Protocol to store fd/path in
 * @param tmp_dir Directory for temp file (e.g., "/tmp")
 * @return 1 on success (or if already created), 0 on failure
 */
int websockets_create_tmpfile(websockets_protocol_t* protocol, const char* tmp_dir);

#endif

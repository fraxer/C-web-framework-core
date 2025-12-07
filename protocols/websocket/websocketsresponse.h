#ifndef __WEBSOCKETSRESPONSE__
#define __WEBSOCKETSRESPONSE__

#include "connection_s.h"
#include "websocketscommon.h"
#include "response.h"
#include "ws_deflate.h"

struct wsctx;

/**
 * WebSocket response for sending data frames to client.
 * Supports text, binary, file transmission, and control frames (pong, close).
 */
typedef struct websocketsresponse {
    /** Base response interface (reset/free callbacks) */
    response_t base;

    /** WebSocket opcode: 0x81=text, 0x82=binary, 0x88=close, 0x8A=pong */
    unsigned char frame_code;

    /** Buffer for outgoing frame data (header + payload) */
    websockets_body_t body;

    /** File descriptor info for file-based responses */
    websockets_file_t file_;

    /** Connection to send response through */
    connection_t* connection;

    /**
     * Send null-terminated text message.
     * @param response This response instance
     * @param data Null-terminated text string
     */
    void(*send_text)(struct websocketsresponse* response, const char* data);

    /**
     * Send text message with explicit length.
     * @param response This response instance
     * @param data Text data (not required to be null-terminated)
     * @param length Number of bytes to send
     */
    void(*send_textn)(struct websocketsresponse* response, const char* data, size_t length);

    /**
     * Send null-terminated binary message.
     * @param response This response instance
     * @param data Binary data (uses strlen to determine length)
     */
    void(*send_binary)(struct websocketsresponse* response, const char* data);

    /**
     * Send binary message with explicit length.
     * @param response This response instance
     * @param data Binary data
     * @param length Number of bytes to send
     */
    void(*send_binaryn)(struct websocketsresponse* response, const char* data, size_t length);

    /**
     * Send data matching request type (text if request was text, binary otherwise).
     * @param ctx WebSocket context containing request and response
     * @param data Null-terminated data string
     */
    void(*send_data)(struct wsctx* ctx, const char* data);

    /**
     * Send data matching request type with explicit length.
     * @param ctx WebSocket context containing request and response
     * @param data Data buffer
     * @param length Number of bytes to send
     */
    void(*send_datan)(struct wsctx* ctx, const char* data, size_t length);

    /**
     * Send file as binary frame (path relative to server root).
     * @param response This response instance
     * @param path Null-terminated file path
     * @return 0 on success, -1 on error (file not found, forbidden, etc.)
     */
    int(*send_file)(struct websocketsresponse* response, const char* path);

    /**
     * Send file as binary frame with explicit path length.
     * @param response This response instance
     * @param path File path (not required to be null-terminated)
     * @param length Path length in bytes
     * @return 0 on success, -1 on error
     */
    int(*send_filen)(struct websocketsresponse* response, const char* path, size_t length);

    /** Pointer to compression context (owned by parser) */
    ws_deflate_t* ws_deflate;
} websocketsresponse_t;

/**
 * Create WebSocket response for connection.
 * @param connection Connection to create response for
 * @return Allocated response or NULL on failure
 */
websocketsresponse_t* websocketsresponse_create(connection_t* connection);

/**
 * Reset response and send text message (convenience wrapper).
 * @param response Response to reset and use
 * @param text Null-terminated message text
 */
void websocketsresponse_default(websocketsresponse_t* response, const char* text);

/**
 * Send PONG control frame (reply to PING).
 * @param response Response instance
 * @param data Ping payload to echo back
 * @param length Payload length
 */
void websocketsresponse_pong(websocketsresponse_t* response, const char* data, size_t length);

/**
 * Send CLOSE control frame to initiate connection close.
 * @param response Response instance
 * @param data Close reason/status (optional payload)
 * @param length Payload length (0 for no payload)
 */
void websocketsresponse_close(websocketsresponse_t* response, const char* data, size_t length);

#endif

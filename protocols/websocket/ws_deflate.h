#ifndef __WS_DEFLATE__
#define __WS_DEFLATE__

#include <zlib.h>
#include <stddef.h>

/**
 * WebSocket permessage-deflate extension (RFC 7692).
 * Uses raw deflate (no gzip/zlib headers) with sliding window.
 */

#define WS_DEFLATE_BUFFER_SIZE 16384

typedef struct ws_deflate_config {
    /** Server maximum window bits (8-15, default 15) */
    int server_max_window_bits;
    /** Client maximum window bits (8-15, default 15) */
    int client_max_window_bits;
    /** Server uses context takeover (reuse deflate state between messages) */
    int server_no_context_takeover;
    /** Client uses context takeover */
    int client_no_context_takeover;
} ws_deflate_config_t;

typedef struct ws_deflate {
    /** Compression stream (for outgoing messages) */
    z_stream deflate_stream;
    /** Decompression stream (for incoming messages) */
    z_stream inflate_stream;
    /** Whether deflate stream is initialized */
    int deflate_init;
    /** Whether inflate stream is initialized */
    int inflate_init;
    /** Extension configuration */
    ws_deflate_config_t config;
} ws_deflate_t;

/**
 * Initialize ws_deflate structure with default values.
 * @param deflate Structure to initialize
 */
void ws_deflate_init(ws_deflate_t* deflate);

/**
 * Initialize compression/decompression streams.
 * @param deflate Initialized ws_deflate structure
 * @return 1 on success, 0 on failure
 */
int ws_deflate_start(ws_deflate_t* deflate);

/**
 * Free compression/decompression resources.
 * @param deflate Structure to free
 */
void ws_deflate_free(ws_deflate_t* deflate);

/**
 * Reset deflate stream for new message (if no_context_takeover).
 * @param deflate Structure to reset
 */
void ws_deflate_reset_deflate(ws_deflate_t* deflate);

/**
 * Reset inflate stream for new message (if no_context_takeover).
 * @param deflate Structure to reset
 */
void ws_deflate_reset_inflate(ws_deflate_t* deflate);

/**
 * Compress data for outgoing WebSocket frame.
 * Appends 0x00 0x00 0xff 0xff trailer which must be removed before sending.
 * @param deflate Compression context
 * @param in Input data
 * @param in_len Input length
 * @param out Output buffer
 * @param out_len Output buffer size
 * @param final Whether this is the final chunk
 * @return Compressed size, or -1 on error
 */
ssize_t ws_deflate_compress(ws_deflate_t* deflate,
                            const char* in, size_t in_len,
                            char* out, size_t out_len,
                            int final);

/**
 * Decompress data from incoming WebSocket frame.
 * Caller must append 0x00 0x00 0xff 0xff before decompression.
 * @param deflate Decompression context
 * @param in Compressed input data
 * @param in_len Input length
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Decompressed size, or -1 on error
 */
ssize_t ws_deflate_decompress(ws_deflate_t* deflate,
                              const char* in, size_t in_len,
                              char* out, size_t out_len);

/**
 * Check if more output is available after compress/decompress.
 * @param deflate Context to check
 * @return 1 if more data available, 0 otherwise
 */
int ws_deflate_has_more(ws_deflate_t* deflate);

/**
 * Parse Sec-WebSocket-Extensions header value for permessage-deflate.
 * @param header Header value string
 * @param config Output configuration
 * @return 1 if permessage-deflate found and parsed, 0 otherwise
 */
int ws_deflate_parse_header(const char* header, ws_deflate_config_t* config);

/**
 * Generate Sec-WebSocket-Extensions response header value.
 * @param config Negotiated configuration
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Length of generated string, or -1 on error
 */
int ws_deflate_build_header(const ws_deflate_config_t* config, char* buf, size_t buf_size);

#endif

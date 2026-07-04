#include <string.h>
#include <zlib.h>

#include "appconfig.h"
#include "websocketsparser.h"
#include "connection_s.h"

int websocketsparser_parse_first_byte(websocketsparser_t*);
int websocketsparser_parse_second_byte(websocketsparser_t*);
int websocketsparser_parse_payload_length_126(websocketsparser_t*);
int websocketsparser_parse_payload_length_127(websocketsparser_t*);
int websocketsparser_parse_mask(websocketsparser_t*);
int websocketsparser_parse_payload(websocketsparser_t*);
int websocketsparser_decompress_chunk(websocketsparser_t*, const char*, size_t, int is_final);
int websocketsparser_string_append(websocketsparser_t*);
int websocketsparser_set_payload_length(websocketsparser_t*, int);
int websocketsparser_set_control_payload(websocketsparser_t*, const char*, size_t);
int websocketsparser_set_payload(websocketsparser_t*, const char*, size_t);
void websocketsparser_flush(websocketsparser_t*);
int websocketsparser_is_control_frame(websockets_frame_t*);
void websockets_frame_init(websockets_frame_t*);
static void __clear(websocketsparser_t* parser);
static int __clear_and_return(websocketsparser_t* parser, int error);
static int __frame_end(websocketsparser_t* parser);

/* UTF-8 validation for TEXT messages (RFC 6455 §8.1). Both are no-ops for
 * non-text messages and assume parser->request is set (data-frame path). */
static int websocketsparser_text_feed_ok(websocketsparser_t* parser, const char* data, size_t size) {
    if (parser->request->type != WEBSOCKETS_TEXT)
        return 1;
    return ws_utf8_validator_feed(&parser->utf8_validator, (const unsigned char*)data, size);
}

static int websocketsparser_text_finish_ok(websocketsparser_t* parser) {
    if (parser->request == NULL || parser->request->type != WEBSOCKETS_TEXT)
        return 1;
    return ws_utf8_validator_finish(&parser->utf8_validator);
}

websocketsparser_t* websocketsparser_create(connection_t* connection, websockets_protocol_t*(*protocol_create)(void)) {
    websocketsparser_t* parser = malloc(sizeof * parser);
    if (parser == NULL) return NULL;

    websocketsparser_init(parser);
    ws_deflate_init(&parser->ws_deflate);
    parser->ws_deflate_enabled = 0;
    parser->connection = connection;
    parser->protocol_create = protocol_create;
    parser->buffer = connection->buffer;

    return parser;
}

void websocketsparser_init(websocketsparser_t* parser) {
    parser->base.free = websocketsparser_free;
    parser->stage = WSPARSER_STAGE_FIRST_BYTE;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->payload_index = 0;
    parser->payload_saved_length = 0;
    parser->message_fragmented = 0;
    parser->request = NULL;
    bufo_init(&parser->compressed_buf);
    parser->compressed_buffered = 0;
    parser->compressed_consumed = 0;
    parser->decompressed_total = 0;
    ws_utf8_validator_reset(&parser->utf8_validator);

    websockets_frame_init(&parser->frame);
    bufferdata_init(&parser->buf);
}

void websocketsparser_free(void* arg) {
    websocketsparser_t* parser = arg;

    __clear(parser);
    ws_deflate_free(&parser->ws_deflate);
    bufo_clear(&parser->compressed_buf);
    free(parser);
}

void websocketsparser_reset(websocketsparser_t* parser) {
    websocketsparser_flush(parser);
}

int __clear_and_return(websocketsparser_t* parser, int error) {
    __clear(parser);
    return error;
}

void __clear(websocketsparser_t* parser) {
    // Clean up partially parsed request if it was created but not yet handled by connection layer
    // This prevents memory leaks when parsing fails early (e.g., invalid method, URI)
    if (parser->request != NULL) {
        // Only free if the request hasn't been registered with the connection yet
        // The connection layer will handle cleanup if the request was successfully registered
        websocketsrequest_free(parser->request);
        parser->request = NULL;
    }

    websocketsparser_reset(parser);
}

void websocketsparser_flush(websocketsparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;

    parser->stage = WSPARSER_STAGE_FIRST_BYTE;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->payload_index = 0;
    parser->payload_saved_length = 0;
    parser->message_fragmented = 0;
    parser->request = NULL;

    websockets_frame_init(&parser->frame);
    bufo_flush(&parser->compressed_buf);
    parser->compressed_buffered = 0;
    parser->compressed_consumed = 0;
    parser->decompressed_total = 0;
    bufferdata_reset(&parser->buf);
}

void websocketsparser_set_bytes_readed(websocketsparser_t* parser, size_t bytes_readed) {
	parser->bytes_readed = bytes_readed;
}

/**
 * Decide how a fully-received frame ends, given any data still left in the
 * read buffer. A frame yields WSPARSER_COMPLETE only when it is the final frame
 * of its message (fin=1), no fragmented data message is in progress, and there
 * is nothing pipelined behind it; otherwise the caller must keep parsing
 * (WSPARSER_HANDLE_AND_CONTINUE) so the next frame and any in-progress
 * fragmented request are preserved. Used by control frames and empty frames,
 * where parser->pos still points at the last consumed byte.
 */
int __frame_end(websocketsparser_t* parser) {
    const int has_remaining = parser->pos + 1 < parser->bytes_readed;

    if (parser->frame.fin && !parser->message_fragmented && !has_remaining)
        return WSPARSER_COMPLETE;

    /* Advance past the last consumed byte so prepare_remains resumes on the
     * next frame's first byte. */
    parser->pos += 1;

    return WSPARSER_HANDLE_AND_CONTINUE;
}

int websocketsparser_run(websocketsparser_t* parser) {
    if (parser->stage == WSPARSER_STAGE_PAYLOAD)
        return websocketsparser_parse_payload(parser);

    for (parser->pos = parser->pos_start; parser->pos < parser->bytes_readed; parser->pos++) {
        char ch = parser->buffer[parser->pos];

        switch (parser->stage) {
        case WSPARSER_STAGE_FIRST_BYTE:
        {
            /* The request is created lazily for data frames inside
             * websocketsparser_parse_first_byte. Control frames carry no
             * request and must not disturb an in-progress fragmented message. */
            bufferdata_push(&parser->buf, ch);

            parser->stage = WSPARSER_STAGE_SECOND_BYTE;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_first_byte(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_STAGE_SECOND_BYTE:
        {
            bufferdata_push(&parser->buf, ch);

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_second_byte(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            else if (parser->frame.payload_length == 126) {
                parser->stage = WSPARSER_STAGE_PAYLOAD_LEN_126;
            }
            else if (parser->frame.payload_length == 127) {
                parser->stage = WSPARSER_STAGE_PAYLOAD_LEN_127;
            }
            else {
                parser->stage = WSPARSER_STAGE_MASK_KEY;
            }

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_STAGE_PAYLOAD_LEN_126:
        {
            if (websocketsparser_is_control_frame(&parser->frame))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_push(&parser->buf, ch);

            if (bufferdata_writed(&parser->buf) < 2)
                break;

            parser->stage = WSPARSER_STAGE_MASK_KEY;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_payload_length_126(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_STAGE_PAYLOAD_LEN_127:
        {
            if (websocketsparser_is_control_frame(&parser->frame))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_push(&parser->buf, ch);

            if (bufferdata_writed(&parser->buf) < 8)
                break;

            parser->stage = WSPARSER_STAGE_MASK_KEY;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_payload_length_127(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_STAGE_MASK_KEY:
        {
            bufferdata_push(&parser->buf, ch);

            if (bufferdata_writed(&parser->buf) < 4)
                break;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_mask(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_reset(&parser->buf);

            if (parser->frame.payload_length == 0)
                return __frame_end(parser);

            break;
        }
        case WSPARSER_STAGE_CONTROL_PAYLOAD:
        {
            parser->payload_saved_length++;
            const int end = parser->payload_saved_length == parser->frame.payload_length;

            ch = ch ^ parser->frame.mask[parser->payload_index++ % 4];

            bufferdata_push(&parser->buf, ch);

            if (end) {
                bufferdata_complete(&parser->buf);
                return __frame_end(parser);
            }

            break;
        }
        case WSPARSER_STAGE_PAYLOAD:
            return websocketsparser_parse_payload(parser);
        default:
            break;
        }
    }

    return WSPARSER_CONTINUE;
}

void websocketsparser_prepare_remains(websocketsparser_t* parser) {
    /* A non-control final data frame closes its message: drop the per-message
     * streaming state (inflate backlog, decompressed total, UTF-8 validator) so
     * a pipelined following message starts clean. Control frames are fin=1 but
     * never close a data message, and non-final fragments keep the message open,
     * so neither resets here. Checked before websockets_frame_init zeroes frame. */
    if (!websocketsparser_is_control_frame(&parser->frame) && parser->frame.fin) {
        parser->compressed_buffered = 0;
        parser->compressed_consumed = 0;
        parser->decompressed_total = 0;
        ws_utf8_validator_reset(&parser->utf8_validator);
    }

    bufferdata_clear(&parser->buf);
    websockets_frame_init(&parser->frame);

    parser->stage = WSPARSER_STAGE_FIRST_BYTE;
    parser->pos_start = parser->pos;
    parser->payload_index = 0;
    parser->payload_saved_length = 0;

    /* Preserve the request only while a fragmented data message is still in
     * progress (RFC 6455 §5.4: control frames may be injected mid-message).
     * Once the final frame has been dispatched, ownership of the request has
     * passed to the queue, so the parser must drop its pointer here to avoid a
     * use-after-free on the next frame. */
    if (parser->request == NULL || !parser->message_fragmented)
        parser->request = NULL;

    /* Reset compressed buffer for next message */
    bufo_flush(&parser->compressed_buf);
}

int websocketsparser_parse_first_byte(websocketsparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    unsigned char c = string[0];

    parser->frame.fin = (c >> 7) & 0x01;
    parser->frame.rsv1 = (c >> 6) & 0x01;
    parser->frame.rsv2 = (c >> 5) & 0x01;
    parser->frame.rsv3 = (c >> 4) & 0x01;
    parser->frame.opcode = c & 0x0F;

    /* Reject reserved/unknown opcodes per RFC 6455 §5.2.
     * Only continuation, text, binary, close, ping and pong are defined. */
    switch (parser->frame.opcode) {
    case WSOPCODE_CONTINUE:
    case WSOPCODE_TEXT:
    case WSOPCODE_BINARY:
    case WSOPCODE_CLOSE:
    case WSOPCODE_PING:
    case WSOPCODE_PONG:
        break;
    default:
        return 0;
    }

    /* RSV2 and RSV3 are reserved and must be 0 (RFC 6455 §5.2). */
    if (parser->frame.rsv2 || parser->frame.rsv3)
        return 0;

    /* Control frames (close/ping/pong) carry no message state. They must be
     * final (§5.5) and uncompressed, may be interleaved inside a fragmented
     * data message, and never own parser->request - which may hold an
     * in-progress fragmented data message that must survive the control frame. */
    if (websocketsparser_is_control_frame(&parser->frame)) {
        if (!parser->frame.fin)
            return 0;
        if (parser->frame.rsv1)
            return 0;
        return 1;
    }

    /* --- Data frame: continuation / text / binary --- */

    /* Opcode sequencing for fragmented messages (RFC 6455 §5.4). */
    if (parser->frame.opcode == WSOPCODE_CONTINUE) {
        if (!parser->message_fragmented)
            return 0; /* continuation without an initial data frame */
        if (parser->frame.rsv1)
            return 0; /* RSV1 (permessage-deflate) is valid only on the first frame of a message (RFC 7692 §7.2) */
    }
    else if (parser->message_fragmented) {
        return 0; /* new data frame while a fragmented message is unfinished */
    }

    /* Create the request lazily on the first frame of a data message. */
    if (parser->request == NULL) {
        parser->request = websocketsrequest_create(parser->connection, parser->protocol_create());
        if (parser->request == NULL)
            return 0;
    }

    websocketsrequest_t* request = parser->request;

    if (parser->frame.rsv1) {
        /* RSV1 is used by the permessage-deflate extension and, per RFC 7692,
         * is only set on the first frame of a message. Continuation frames
         * carry rsv1=0, so this block runs exactly once per message. */
        if (!parser->ws_deflate_enabled)
            return 0;
        request->compressed = 1;
    }

    if (request->type == WEBSOCKETS_NONE)
        request->type = parser->frame.opcode + 0x80;

    /* A message is fragmented from its first non-final frame until the final
     * (fin=1) frame that closes it. */
    parser->message_fragmented = (parser->frame.fin == 0);
    request->fragmented = parser->message_fragmented;

    return 1;
}

int websocketsparser_parse_second_byte(websocketsparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    unsigned char c = string[0];

    parser->frame.masked = (c >> 7) & 0x01;
    parser->frame.payload_length = c & (~0x80);

    if (!parser->frame.masked) return 0;

    return 1;
}

int websocketsparser_parse_payload_length_126(websocketsparser_t* parser) {
    int byte_count = 2;
    return websocketsparser_set_payload_length(parser, byte_count);
}

int websocketsparser_parse_payload_length_127(websocketsparser_t* parser) {
    int byte_count = 8;
    return websocketsparser_set_payload_length(parser, byte_count);
}

int websocketsparser_set_payload_length(websocketsparser_t* parser, int byte_count) {
    const unsigned char* value = (const unsigned char*)bufferdata_get(&parser->buf);
    size_t length = 0;

    for (int i = 0; i < byte_count; i++)
        length = (length << 8) | value[i];

    parser->frame.payload_length = length;

    return 1;
}

int websocketsparser_parse_mask(websocketsparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);

    /* The mask is exactly 4 bytes; this stage is only reached once 4 bytes
     * are buffered. Bound the copy explicitly to never overrun frame.mask[4]. */
    for (size_t i = 0; i < 4; i++)
        parser->frame.mask[i] = string[i];

    if (websocketsparser_is_control_frame(&parser->frame))
        parser->stage = WSPARSER_STAGE_CONTROL_PAYLOAD;
    else
        parser->stage = WSPARSER_STAGE_PAYLOAD;

    return 1;
}

int websocketsparser_parse_payload(websocketsparser_t* parser) {
    websocketsrequest_t* request = parser->request;

    size_t size = parser->bytes_readed - parser->pos;
    int has_data_for_next_request = 0;

    if (size + parser->payload_saved_length > parser->frame.payload_length) {
        size = parser->frame.payload_length - parser->payload_saved_length;
        has_data_for_next_request = 1;
    }

    if (parser->payload_saved_length + size > env()->main.client_max_body_size)
        return __clear_and_return(parser, WSPARSER_PAYLOAD_LARGE);

    parser->payload_saved_length += size;

    char* payload_data = &parser->buffer[parser->pos];
    size_t payload_size = size;
    int is_final = parser->payload_saved_length == parser->frame.payload_length;

    /* For compressed messages: streaming decompress and pass to payload_parse */
    if (request->compressed) {
        int is_message_final = is_final && parser->frame.fin;
        if (!websocketsparser_decompress_chunk(parser, payload_data, payload_size, is_message_final))
            return __clear_and_return(parser, WSPARSER_ERROR);
    } else {
        const int unmasking = 1;
        /* Uncompressed: pass directly to payload_parse (unmasks in place). */
        if (!request->protocol->payload_parse(parser, payload_data, payload_size, unmasking))
            return __clear_and_return(parser, WSPARSER_ERROR);
        /* payload_data now holds the unmasked bytes; validate TEXT (RFC 6455 §8.1). */
        if (!websocketsparser_text_feed_ok(parser, payload_data, payload_size))
            return __clear_and_return(parser, WSPARSER_ERROR);
    }

    if (has_data_for_next_request) {
        parser->pos += size;
        /* A final frame with pipelined data behind it closes its message here
         * (no COMPLETE return), so finish the UTF-8 validator explicitly. */
        if (parser->frame.fin && !websocketsparser_text_finish_ok(parser))
            return __clear_and_return(parser, WSPARSER_ERROR);
        return WSPARSER_HANDLE_AND_CONTINUE;
    }

    /* This frame's payload is not fully received yet - wait for the next read. */
    if (!is_final)
        return WSPARSER_CONTINUE;

    /* The frame is complete. Only a final (fin=1) frame finishes the message;
     * a non-final fragment must keep the request alive for the continuation
     * frames that follow (handled via prepare_remains). */
    if (parser->frame.fin) {
        if (!websocketsparser_text_finish_ok(parser))
            return __clear_and_return(parser, WSPARSER_ERROR);
        return WSPARSER_COMPLETE;
    }

    return WSPARSER_HANDLE_AND_CONTINUE;
}

int websocketsparser_is_control_frame(websockets_frame_t* frame) {
    switch (frame->opcode) {
    case WSOPCODE_CLOSE:
    case WSOPCODE_PING:
    case WSOPCODE_PONG:
        return 1;
    }

    return 0;
}

/**
 * Streaming decompress: unmask, decompress, and pass to payload_parse in chunks.
 *
 * The inflate stream is stateful across reads and fragments within a message, so
 * any bytes inflate could not yet decode (a partial deflate code straddling a
 * chunk or fragment boundary) must be retained at the front of compressed_buf and
 * re-fed together with the next chunk. compressed_buffered/compressed_consumed
 * track that input window; they reset only between messages (flush), never between
 * fragments (prepare_remains), because one message is exactly one deflate stream.
 *
 * Per RFC 7692 the 0x00 0x00 0xff 0xff trailer is appended once, on the final chunk.
 *
 * @param parser Parser context
 * @param data Masked compressed data (this chunk only)
 * @param size Data size
 * @param is_final Final chunk of the message (fin=1 and last frame data)
 * @return 1 on success, 0 on failure
 */
int websocketsparser_decompress_chunk(websocketsparser_t* parser, const char* data, size_t size, int is_final) {
    ws_deflate_t* deflate = &parser->ws_deflate;
    websocketsrequest_t* request = parser->request;
    bufo_t* buf = &parser->compressed_buf;
    z_stream* stream = &deflate->inflate_stream;

    /* Bytes inflate could not consume last time (a partial deflate code). They
     * stay at the front of the buffer so the stream resumes seamlessly. */
    size_t backlog = parser->compressed_buffered - parser->compressed_consumed;
    const size_t trailer = is_final ? 4 : 0;

    /* Layout for this call: [backlog + new chunk + trailer][inflate output].
     * ensure_capacity may realloc, so every buf->data pointer is derived below
     * rather than held across the call. */
    if (!bufo_ensure_capacity(buf, backlog + size + trailer + WS_DEFLATE_BUFFER_SIZE))
        return 0;

    /* Drop the already-consumed prefix; inflate has folded those bytes into its
     * window, so the buffer must not grow unbounded across a large message. */
    if (parser->compressed_consumed > 0) {
        memmove(buf->data, buf->data + parser->compressed_consumed, backlog);
        parser->compressed_consumed = 0;
        parser->compressed_buffered = backlog;
    }

    /* Append the new chunk, unmasking into place. The mask keystream is
     * continuous across the whole frame's payload (payload_index is per-frame). */
    char* in = buf->data + parser->compressed_buffered;
    for (size_t i = 0; i < size; i++)
        in[i] = data[i] ^ parser->frame.mask[parser->payload_index++ % 4];
    parser->compressed_buffered += size;

    /* Append the deflate flush trailer on the final chunk (RFC 7692). */
    if (is_final) {
        buf->data[parser->compressed_buffered + 0] = 0x00;
        buf->data[parser->compressed_buffered + 1] = 0x00;
        buf->data[parser->compressed_buffered + 2] = (char)0xff;
        buf->data[parser->compressed_buffered + 3] = (char)0xff;
        parser->compressed_buffered += 4;
    }

    /* Output area follows the input; inflate reads input and writes output
     * concurrently with no overlap. */
    char* decomp_area = buf->data + parser->compressed_buffered;
    stream->next_in = (Bytef*)(buf->data + parser->compressed_consumed);
    stream->avail_in = (uInt)(parser->compressed_buffered - parser->compressed_consumed);

    while (stream->avail_in > 0) {
        stream->next_out = (Bytef*)decomp_area;
        stream->avail_out = (uInt)WS_DEFLATE_BUFFER_SIZE;

        const uInt in_before = stream->avail_in;
        int status = inflate(stream, Z_SYNC_FLUSH);
        if (status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR)
            return 0;

        size_t decompressed_size = WS_DEFLATE_BUFFER_SIZE - stream->avail_out;
        if (decompressed_size > 0) {
            /* A compressed payload must not bypass the body limit by expanding
             * server-side; bound the decompressed size, not just the wire size. */
            if (parser->decompressed_total + decompressed_size > env()->main.client_max_body_size)
                return 0;
            parser->decompressed_total += decompressed_size;

            /* Validate decompressed TEXT before dispatch (RFC 6455 §8.1). */
            if (!websocketsparser_text_feed_ok(parser, decomp_area, decompressed_size))
                return 0;

            if (!request->protocol->payload_parse(parser, decomp_area, decompressed_size, 0))
                return 0;
        }

        /* Record what inflate actually swallowed. */
        parser->compressed_consumed += (size_t)(in_before - stream->avail_in);

        if (status == Z_STREAM_END)
            break;

        /* No input consumed and no output produced: the remainder is a partial
         * code that needs more input from the next read/fragment. Stop here
         * rather than spinning (Z_BUF_ERROR is tolerated above). */
        if (stream->avail_in == in_before)
            break;
    }

    /* Reset the inflate stream only when context takeover is disabled. */
    if (is_final)
        ws_deflate_reset_inflate(deflate);

    return 1;
}

void websockets_frame_init(websockets_frame_t* frame) {
    frame->fin = 0;
    frame->rsv1 = 0;
    frame->rsv2 = 0;
    frame->rsv3 = 0;
    frame->opcode = 0;
    frame->masked = 0;
    frame->mask[0] = 0;
    frame->mask[1] = 0;
    frame->mask[2] = 0;
    frame->mask[3] = 0;
    frame->payload_length = 0;
}

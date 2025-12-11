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
int websocketsparser_parse_method(websocketsparser_t*);
int websocketsparser_parse_location(websocketsparser_t*);
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
    parser->stage = WSPARSER_FIRST_BYTE;
    parser->mask_index = 0;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->payload_index = 0;
    parser->payload_saved_length = 0;
    parser->request = NULL;
    bufo_init(&parser->compressed_buf);

    websockets_frame_init(&parser->frame);
    bufferdata_init(&parser->buf);
}

void websocketsparser_free(void* arg) {
    websocketsparser_t* parser = arg;

    __clear(parser);
    ws_deflate_free(&parser->ws_deflate);
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

    parser->stage = WSPARSER_FIRST_BYTE;
    parser->mask_index = 0;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->payload_index = 0;
    parser->payload_saved_length = 0;
    parser->request = NULL;

    websockets_frame_init(&parser->frame);
    bufo_flush(&parser->compressed_buf);
    bufferdata_reset(&parser->buf);
}

void websocketsparser_set_bytes_readed(websocketsparser_t* parser, size_t bytes_readed) {
	parser->bytes_readed = bytes_readed;
}

int websocketsparser_run(websocketsparser_t* parser) {
    if (parser->stage == WSPARSER_PAYLOAD)
        return websocketsparser_parse_payload(parser);

    for (parser->pos = parser->pos_start; parser->pos < parser->bytes_readed; parser->pos++) {
        char ch = parser->buffer[parser->pos];

        switch (parser->stage) {
        case WSPARSER_FIRST_BYTE:
        {
            if (parser->request == NULL)
                parser->request = websocketsrequest_create(parser->connection, parser->protocol_create());

            bufferdata_push(&parser->buf, ch);

            parser->stage = WSPARSER_SECOND_BYTE;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_first_byte(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_SECOND_BYTE:
        {
            bufferdata_push(&parser->buf, ch);

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_second_byte(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            else if (parser->frame.payload_length == 126) {
                parser->stage = WSPARSER_PAYLOAD_LEN_126;
            }
            else if (parser->frame.payload_length == 127) {
                parser->stage = WSPARSER_PAYLOAD_LEN_127;
            }
            else {
                parser->stage = WSPARSER_MASK_KEY;
            }

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_PAYLOAD_LEN_126:
        {
            if (websocketsparser_is_control_frame(&parser->frame))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_push(&parser->buf, ch);

            if (bufferdata_writed(&parser->buf) < 2)
                break;

            parser->stage = WSPARSER_MASK_KEY;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_payload_length_126(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_PAYLOAD_LEN_127:
        {
            if (websocketsparser_is_control_frame(&parser->frame))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_push(&parser->buf, ch);

            if (bufferdata_writed(&parser->buf) < 8)
                break;

            parser->stage = WSPARSER_MASK_KEY;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_payload_length_127(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_MASK_KEY:
        {
            bufferdata_push(&parser->buf, ch);

            if (bufferdata_writed(&parser->buf) < 4)
                break;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_mask(parser))
                return __clear_and_return(parser, WSPARSER_BAD_REQUEST);

            bufferdata_reset(&parser->buf);

            if (parser->frame.payload_length == 0)
                return WSPARSER_COMPLETE;

            break;
        }
        case WSPARSER_CONTROL_PAYLOAD:
        {
            parser->payload_saved_length++;
            const int end = parser->payload_saved_length == parser->frame.payload_length;

            ch = ch ^ parser->frame.mask[parser->payload_index++ % 4];

            bufferdata_push(&parser->buf, ch);

            if (end) {
                bufferdata_complete(&parser->buf);
                return WSPARSER_COMPLETE;
            }

            break;
        }
        case WSPARSER_PAYLOAD:
            return websocketsparser_parse_payload(parser);
        default:
            break;
        }
    }

    return WSPARSER_CONTINUE;
}

void websocketsparser_prepare_remains(websocketsparser_t* parser) {
    bufferdata_clear(&parser->buf);
    websockets_frame_init(&parser->frame);

    parser->stage = WSPARSER_FIRST_BYTE;
    parser->pos_start = parser->pos;
    parser->mask_index = 0;
    parser->payload_index = 0;
    parser->payload_saved_length = 0;

    /* Preserve request context for fragmented messages (RFC 6455 §5.4:
     * control frames may be injected in the middle of a fragmented message) */
    if (parser->request == NULL || !parser->request->fragmented)
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

    websocketsrequest_t* request = parser->request;

    /* Validate RSV bits per RFC 6455 / RFC 7692 */
    if (parser->frame.rsv2 || parser->frame.rsv3) {
        /* RSV2 and RSV3 are reserved and must be 0 */
        return 0;
    }

    /* Control frames MUST NOT be fragmented (RFC 6455 §5.5) */
    if (websocketsparser_is_control_frame(&parser->frame) && !parser->frame.fin) {
        return 0;
    }

    if (parser->frame.fin == 0)
        request->fragmented = 1;

    if (parser->frame.rsv1) {
        /* RSV1 is used by permessage-deflate extension */
        if (!parser->ws_deflate_enabled) {
            /* Extension not negotiated, RSV1 must be 0 */
            return 0;
        }
        /* Mark message as compressed (only first frame in fragmented message) */
        if (!request->fragmented) {
            request->compressed = 1;
        }
    }

    if (request->type == WEBSOCKETS_NONE)
        request->type = parser->frame.opcode + 0x80;

    if (request->fragmented)
        request->can_reset = 0;

    if (parser->frame.fin == 1 || parser->frame.opcode == WSOPCODE_CLOSE)
        request->can_reset = 1;

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

    for (size_t i = 0; i < bufferdata_writed(&parser->buf); i++) 
        parser->frame.mask[i] = string[i];

    if (websocketsparser_is_control_frame(&parser->frame))
        parser->stage = WSPARSER_CONTROL_PAYLOAD;
    else
        parser->stage = WSPARSER_PAYLOAD;

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
        /* Uncompressed: pass directly to payload_parse */
        if (!request->protocol->payload_parse(parser, payload_data, payload_size, unmasking))
            return __clear_and_return(parser, WSPARSER_ERROR);
    }

    if (has_data_for_next_request) {
        parser->pos += size;
        return WSPARSER_HANDLE_AND_CONTINUE;
    }

    if (is_final)
        return WSPARSER_COMPLETE;

    return WSPARSER_CONTINUE;
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
 * Per RFC 7692: append 0x00 0x00 0xff 0xff trailer on final chunk.
 * @param parser Parser context
 * @param data Masked compressed data
 * @param size Data size
 * @param is_final Whether this is the final chunk of the message (fin=1 and last frame data)
 * @return 1 on success, 0 on failure
 */
int websocketsparser_decompress_chunk(websocketsparser_t* parser, const char* data, size_t size, int is_final) {
    ws_deflate_t* deflate = &parser->ws_deflate;
    websocketsrequest_t* request = parser->request;
    bufo_t* buf = &parser->compressed_buf;

    /* Prepare input: unmask data + optional trailer */
    size_t input_size = size + (is_final ? 4 : 0);

    /* Buffer layout: [input data + trailer] [decompression output area]
     * Decompression output starts after input to avoid overwriting */
    const size_t decomp_buf_size = WS_DEFLATE_BUFFER_SIZE;
    size_t total_needed = input_size + decomp_buf_size;

    if (!bufo_ensure_capacity(buf, total_needed))
        return 0;

    /* Unmask data into buffer */
    for (size_t i = 0; i < size; i++)
        buf->data[i] = data[i] ^ parser->frame.mask[parser->payload_index++ % 4];

    /* Append deflate trailer on final chunk per RFC 7692 */
    if (is_final) {
        buf->data[size] = 0x00;
        buf->data[size + 1] = 0x00;
        buf->data[size + 2] = (char)0xff;
        buf->data[size + 3] = (char)0xff;
    }

    /* Decompress and pass to payload_parse in chunks */
    z_stream* stream = &deflate->inflate_stream;
    stream->next_in = (Bytef*)buf->data;
    stream->avail_in = (uInt)input_size;

    char* decomp_area = buf->data + input_size;
    const int unmasking = 0;
    while (stream->avail_in > 0) {
        stream->next_out = (Bytef*)decomp_area;
        stream->avail_out = (uInt)decomp_buf_size;

        int status = inflate(stream, Z_SYNC_FLUSH);
        if (status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR)
            return 0;

        size_t decompressed_size = decomp_buf_size - stream->avail_out;
        if (decompressed_size > 0)
            if (!request->protocol->payload_parse(parser, decomp_area, decompressed_size, unmasking))
                return 0;

        if (status == Z_STREAM_END)
            break;
    }

    /* Reset inflate stream if client_no_context_takeover */
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

#include <string.h>

#include "appconfig.h"
#include "websocketsparser.h"

int websocketsparser_parse_first_byte(websocketsparser_t*);
int websocketsparser_parse_second_byte(websocketsparser_t*);
int websocketsparser_parse_payload_length_126(websocketsparser_t*);
int websocketsparser_parse_payload_length_127(websocketsparser_t*);
int websocketsparser_parse_mask(websocketsparser_t*);
int websocketsparser_parse_method(websocketsparser_t*);
int websocketsparser_parse_location(websocketsparser_t*);
int websocketsparser_parse_payload(websocketsparser_t*);
int websocketsparser_string_append(websocketsparser_t*);
int websocketsparser_set_payload_length(websocketsparser_t*, int);
int websocketsparser_set_control_payload(websocketsparser_t*, const char*, size_t);
int websocketsparser_set_payload(websocketsparser_t*, const char*, size_t);
void websocketsparser_flush(websocketsparser_t*);
int websocketsparser_is_control_frame(websockets_frame_t*);
void websockets_frame_init(websockets_frame_t*);

websocketsparser_t* websocketsparser_create(connection_t* connection, websockets_protocol_t*(*protocol_create)(void)) {
    websocketsparser_t* parser = malloc(sizeof * parser);
    if (parser == NULL) return NULL;

    websocketsparser_init(parser);
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

    websockets_frame_init(&parser->frame);
    bufferdata_init(&parser->buf);
}

void websocketsparser_free(void* arg) {
    websocketsparser_t* parser = arg;

    websocketsparser_flush(parser);
    free(parser);
}

void websocketsparser_reset(websocketsparser_t* parser) {
    websocketsparser_flush(parser);
    websocketsparser_init(parser);
}

void websocketsparser_flush(websocketsparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;
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
                return WSPARSER_BAD_REQUEST;

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_SECOND_BYTE:
        {
            bufferdata_push(&parser->buf, ch);

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_second_byte(parser))
                return WSPARSER_BAD_REQUEST;

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
                return WSPARSER_BAD_REQUEST;

            bufferdata_push(&parser->buf, ch);

            if (bufferdata_writed(&parser->buf) < 2)
                break;

            parser->stage = WSPARSER_MASK_KEY;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_payload_length_126(parser))
                return WSPARSER_BAD_REQUEST;

            bufferdata_reset(&parser->buf);

            break;
        }
        case WSPARSER_PAYLOAD_LEN_127:
        {
            if (websocketsparser_is_control_frame(&parser->frame))
                return WSPARSER_BAD_REQUEST;

            bufferdata_push(&parser->buf, ch);

            if (bufferdata_writed(&parser->buf) < 8)
                break;

            parser->stage = WSPARSER_MASK_KEY;

            bufferdata_complete(&parser->buf);
            if (!websocketsparser_parse_payload_length_127(parser))
                return WSPARSER_BAD_REQUEST;

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
                return WSPARSER_BAD_REQUEST;

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
    parser->request = NULL;
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

    if (parser->frame.fin == 0)
        request->fragmented = 1;

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
    parser->frame.payload_length = 0;

    int counter = byte_count;
    const int byte_left = 8;
    const unsigned char* value = (const unsigned char*)bufferdata_get(&parser->buf);
    const size_t num = value[byte_count - counter];

    do {
        parser->frame.payload_length |= num << (byte_left * counter - byte_left);
    } while (--counter > 0);

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
        // printf("has_data_for_next_request: %ld > %ld\n", size + parser->payload_saved_length, parser->frame.payload_length);
        size = parser->frame.payload_length - parser->payload_saved_length;
        has_data_for_next_request = 1;
    }

    if (parser->payload_saved_length + size > env()->main.client_max_body_size)
        return WSPARSER_PAYLOAD_LARGE;

    parser->payload_saved_length += size;

    if (!request->protocol->payload_parse(parser, &parser->buffer[parser->pos], size))
        return WSPARSER_ERROR;

    if (has_data_for_next_request) {
        parser->pos += size;

        return WSPARSER_HANDLE_AND_CONTINUE;
    }

    if (parser->payload_saved_length == parser->frame.payload_length)
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

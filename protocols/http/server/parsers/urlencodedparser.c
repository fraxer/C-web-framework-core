#include <unistd.h>

#include "urlencodedparser.h"

typedef struct urlencoded_value {
    char* value;
    size_t size;
} urlencoded_value_t;

static int __urlencodedparser_add_part(urlencodedparser_t* parser);
static int __urlencodedparser_set_field_key(urlencodedparser_t* parser);
static int __urlencodedparser_set_field_value(urlencodedparser_t* parser);
static int __urlencodedparser_set_empty_value(urlencodedparser_t* parser);
static int __urlencodedparser_set_field(urlencodedparser_t* parser, size_t offset, size_t size, urlencoded_value_t* result);
static int __urlencodedparser_flush(urlencodedparser_t* parser);

void urlencodedparser_init(urlencodedparser_t* parser, int payload_fd, size_t payload_size) {
    parser->payload_size = payload_size;
    parser->payload_offset = 0;
    parser->offset = 0;
    parser->size = 0;
    parser->part = NULL;
    parser->last_part = NULL;
    parser->find_amp = 1;
    parser->part_count = 0;
    parser->limit_reached = 0;
    parser->payload_fd = payload_fd;
    parser->error = NULL;
}

int urlencodedparser_parse(urlencodedparser_t* parser, char* buffer, size_t buffer_size) {
    if (parser->limit_reached) {
        parser->error = "urlencoded parser: part limit already reached";
        return 0;
    }

    for (size_t i = 0; i < buffer_size && parser->payload_offset < parser->payload_size; i++) {
        switch (buffer[i]) {
        case '=':
        {
            /* '=' внутри значения — обычный символ. */
            if (!parser->find_amp) {
                parser->size++;
                break;
            }
            parser->find_amp = 0;

            if (parser->part_count >= URLENCODEDPARSER_MAX_PARTS) {
                parser->limit_reached = 1;
                parser->error = "urlencoded parser: maximum number of parts exceeded";
                return 0;
            }

            if (!__urlencodedparser_add_part(parser)) return 0;
            if (!__urlencodedparser_set_field_key(parser)) return 0;

            break;
        }
        case '&':
        {
            if (!__urlencodedparser_flush(parser)) return 0;
            break;
        }
        default:
            parser->size++;
        }

        parser->payload_offset++;
    }

    if (parser->payload_offset >= parser->payload_size)
        if (!__urlencodedparser_flush(parser)) return 0;

    return 1;
}

http_payloadpart_t* urlencodedparser_part(urlencodedparser_t* parser) {
    return parser->part;
}

void urlencodedparser_clear(urlencodedparser_t* parser) {
    http_payloadpart_free(parser->part);
    urlencodedparser_init(parser, 0, 0);
}

static int __urlencodedparser_flush(urlencodedparser_t* parser) {
    if (parser->find_amp) {
        /* Сегмент без '=' — голый ключ ("foo&" или "foo" в конце payload). */
        if (parser->size == 0) {
            /* Пустая пара ("&&", ведущий '&', пустой хвост): ничего не создаём,
               лишь сдвигаем начало следующего сегмента. */
            parser->offset = parser->payload_offset + 1;
            parser->size = 0;
            return 1;
        }

        if (parser->part_count >= URLENCODEDPARSER_MAX_PARTS) {
            parser->limit_reached = 1;
            parser->error = "urlencoded parser: maximum number of parts exceeded";
            return 0;
        }

        if (!__urlencodedparser_add_part(parser)) return 0;
        if (!__urlencodedparser_set_field_key(parser)) return 0;
        if (!__urlencodedparser_set_empty_value(parser)) return 0;
    } else {
        /* Значение для ключа, part которого уже создан на '='.
           last_part здесь гарантированно != NULL. */
        if (!__urlencodedparser_set_field_value(parser))
            return 0;

        parser->offset = parser->payload_offset + 1;
        parser->size = 0;
        parser->find_amp = 1;
    }

    return 1;
}

static int __urlencodedparser_add_part(urlencodedparser_t* parser) {
    http_payloadpart_t* part = http_payloadpart_create();
    if (part == NULL) {
        parser->error = "urlencoded parser: failed to allocate payload part";
        return 0;
    }

    http_payloadfield_t* field = http_payloadfield_create();
    if (field == NULL) {
        parser->error = "urlencoded parser: failed to allocate payload field";
        http_payloadpart_free(part);
        return 0;
    }

    if (parser->part == NULL)
        parser->part = part;

    if (parser->last_part != NULL)
        parser->last_part->next = part;

    parser->last_part = part;

    part->offset = parser->offset;
    part->size = parser->size;
    part->field = field;

    parser->offset = parser->payload_offset + 1;
    parser->size = 0;
    parser->part_count++;

    return 1;
}

static int __urlencodedparser_set_field_key(urlencodedparser_t* parser) {
    http_payloadpart_t* part = parser->last_part;
    urlencoded_value_t result = {NULL, 0};

    if (!__urlencodedparser_set_field(parser, part->offset, part->size, &result)) {
        return 0;
    }

    part->field->key = result.value;
    part->field->key_length = result.size;

    return 1;
}

static int __urlencodedparser_set_field_value(urlencodedparser_t* parser) {
    http_payloadpart_t* part = parser->last_part;
    urlencoded_value_t result = {NULL, 0};

    if (!__urlencodedparser_set_field(parser, parser->offset, parser->size, &result)) {
        return 0;
    }

    part->field->value = result.value;
    part->field->value_length = result.size;

    return 1;
}

static int __urlencodedparser_set_empty_value(urlencodedparser_t* parser) {
    http_payloadpart_t* part = parser->last_part;
    char* value = copy_cstringn(NULL, 0);
    if (value == NULL) {
        parser->error = "urlencoded parser: failed to allocate empty field value";
        return 0;
    }

    part->field->value = value;
    part->field->value_length = 0;

    return 1;
}

static int __urlencodedparser_set_field(urlencodedparser_t* parser, size_t offset, size_t size, urlencoded_value_t* result) {
    char* value = malloc(size + 1);
    if (value == NULL) {
        parser->error = "urlencoded parser: failed to allocate buffer for field value";
        return 0;
    }

    size_t got = 0;
    while (got < size) {
        const ssize_t r = pread(parser->payload_fd, value + got, size - got, (off_t)(offset + got));
        if (r < 0) {
            parser->error = "urlencoded parser: failed to read payload data";
            free(value);
            return 0;
        }
        if (r == 0)
            break;

        got += (size_t)r;
    }

    value[got] = 0;

    size_t decoded_length = 0;
    char* decoded = urldecodel(value, got, &decoded_length);
    free(value);

    if (decoded == NULL) {
        parser->error = "urlencoded parser: URL decoding failed";
        return 0;
    }

    result->value = decoded;
    result->size = decoded_length;

    return 1;
}

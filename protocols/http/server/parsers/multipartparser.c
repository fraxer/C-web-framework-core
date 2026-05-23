#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include "log.h"
#include "formdataparser.h"
#include "multipartparser.h"

int multipartparser_create_part(multipartparser_t*);
int multipartparser_create_header(multipartparser_t*);
void multipartparser_reset_header(multipartparser_t*);
int multipartparser_write_header(int, char*, size_t, size_t);

void multipartparser_init(multipartparser_t* parser, int payload_fd, const char* boundary) {
    parser->boundary = boundary;
    parser->boundary_size = strlen(boundary);
    parser->payload_size = lseek(payload_fd, 0, SEEK_END);
    parser->payload_offset = 0;
    parser->boundary_offset = 0;
    parser->header_key_offset = 0;
    parser->header_value_offset = 0;
    parser->header_key_size = 0;
    parser->header_value_size = 0;
    parser->offset = 0;
    parser->size = 0;
    parser->stage = BOUNDARY_FN;
    parser->part = NULL;
    parser->last_part = NULL;
    parser->header = NULL;
    parser->last_header = NULL;
    parser->payload_fd = payload_fd;
    parser->error = 0;

    lseek(payload_fd, 0, SEEK_SET);
}

int multipartparser_parse(multipartparser_t* parser, char* buffer, size_t buffer_size) {
    for (size_t i = 0; i < buffer_size; i++) {
        char ch = buffer[i];

        switch (parser->stage) {
        case BODY:
            if (ch == '\r')
                parser->stage = BOUNDARY_FN;
            break;
        case BOUNDARY_FN:
            if (ch == '\r')
                break;
            else if (ch == '\n')
                parser->stage = FIRST_DASH;
            else if (ch == '-')
                parser->stage = SECOND_DASH;
            else
                parser->stage = BODY;
            break;
        case FIRST_DASH:
            if (ch == '\r')
                parser->stage = BOUNDARY_FN;
            else if (ch == '-')
                parser->stage = SECOND_DASH;
            else
                parser->stage = BODY;
            break;
        case SECOND_DASH:
            if (ch == '\r')
                parser->stage = BOUNDARY_FN;
            else if (ch == '-') {
                parser->boundary_offset = parser->payload_offset + 1;
                parser->stage = BOUNDARY;
            }
            else
                parser->stage = BODY;
            break;
        case BOUNDARY:
        {
            size_t pos = parser->payload_offset - parser->boundary_offset;

            if (pos < parser->boundary_size) {
                if (parser->boundary[pos] != ch) {
                    parser->stage = BODY;
                }
                else if (pos == parser->boundary_size - 1) {
                    parser->stage = BOUNDARY_FD;

                    if (parser->offset > 0)
                        if (!multipartparser_create_part(parser)) {
                            log_error("multipartparser: create_part failed\n");
                            parser->error = 1;
                            return 0;
                        }
                }
            }
            else
                parser->stage = BODY;
            break;
        }
        case BOUNDARY_FD:
            if (ch == '-')
                parser->stage = BOUNDARY_SD;
            else if (ch == '\r')
                parser->stage = BOUNDARY_NL;
            else
                parser->stage = BODY;
            break;
        case BOUNDARY_NL:
            if (ch == '\n') {
                parser->stage = HEADER_KEY;
                multipartparser_reset_header(parser);
            }
            else
                parser->stage = BODY;
            break;
        case BOUNDARY_SD:
            if (ch == '-')
                parser->stage = BODY;
            break;
        case HEADER_KEY:
            if (ch == ':') {
                parser->stage = HEADER_SPACE;
                parser->header_value_offset = parser->payload_offset + 1;
            }
            else if (ch == '\r')
                parser->stage = END_N;
            else
                parser->header_key_size++;
            break;
        case HEADER_SPACE:
            if (ch == ' ')
                parser->header_value_offset = parser->payload_offset + 1;
            else if (ch == '\r')
                parser->stage = HEADER_N;
            else {
                parser->stage = HEADER_VALUE;
                parser->header_value_size++;
            }
            break;
        case HEADER_VALUE:
            if (ch == '\r')
                parser->stage = HEADER_N;
            else
                parser->header_value_size++;
            break;
        case HEADER_N:
            if (ch == '\n') {
                if (!multipartparser_create_header(parser)) {
                    parser->error = 1;
                    return 0;
                }
            }
            else
                parser->stage = BODY;
            break;
        case END_N:
            if (ch == '\n') {
                parser->stage = BODY;
                parser->offset = parser->payload_offset + 1;
                parser->size = 0;
            }
            break;
        }
        
        parser->payload_offset++;
        parser->size++;
    }

    return 1;
}

http_payloadpart_t* multipartparser_part(multipartparser_t* parser) {
    return parser->part;
}

int multipartparser_create_part(multipartparser_t* parser) {
    http_header_t* header = parser->header;
    http_payloadfield_t* field = NULL;
    http_payloadfield_t* last_field = NULL;
    while (header) {
        if (header->key == NULL) {
            log_error("multipartparser: header key is NULL\n");
            break;
        }
        if (strcmp(header->key, "Content-Disposition") == 0) {
            formdataparser_t fdparser;
            formdataparser_init(&fdparser, "form-data");
            formdataparser_parse(&fdparser, header->value, header->value_length);

            formdatafield_t* hfield = formdataparser_first_field(&fdparser);
            while (hfield) {
                http_payloadfield_t* f = http_payloadfield_create();

                f->key_length = str_size(&hfield->key);
                f->key = copy_cstringn(str_get(&hfield->key), f->key_length);
                if (f->key == NULL) return 0;

                f->value_length = str_size(&hfield->value);
                f->value = copy_cstringn(str_get(&hfield->value), f->value_length);
                if (f->value == NULL) return 0;

                hfield = hfield->next;

                if (!field)
                    field = f;
                if (last_field)
                    last_field->next = f;
                last_field = f;
            }

            formdataparser_clear(&fdparser);
            break;
        }
        header = header->next;
    }

    http_payloadpart_t* part = http_payloadpart_create();
    if (part == NULL) return 0;

    part->offset = parser->offset;
    part->header = parser->header;
    part->field = field;
    part->size = parser->size - parser->boundary_size - 4;

    parser->header = NULL;
    parser->last_header = NULL;

    if (!parser->part)
        parser->part = part;
    if (parser->last_part)
        parser->last_part->next = part;
    parser->last_part = part;

    return 1;
}

int multipartparser_create_header(multipartparser_t* parser) {
    size_t key_offset = parser->header_key_offset;
    size_t key_size = parser->header_key_size;
    size_t value_offset = parser->header_value_offset;
    size_t value_size = parser->header_value_size;

    http_header_t* header = http_header_create(NULL, key_size, NULL, value_size);
    if (header == NULL) {
        log_error("multipartparser: header_create failed\n");
        return 0;
    }

    if (key_size && !multipartparser_write_header(parser->payload_fd, header->key, key_offset, key_size)) {
        log_error("multipartparser: write_header key failed\n");
        return 0;
    }
    if (value_size && !multipartparser_write_header(parser->payload_fd, header->value, value_offset, value_size)) {
        log_error("multipartparser: write_header val failed\n");
        return 0;
    }

    parser->stage = HEADER_KEY;
    multipartparser_reset_header(parser);

    if (!parser->header)
        parser->header = header;
    if (parser->last_header)
        parser->last_header->next = header;
    parser->last_header = header;

    return 1;
}

void multipartparser_reset_header(multipartparser_t* parser) {
    parser->header_key_offset = parser->payload_offset + 1;
    parser->header_key_size = 0;
    parser->header_value_offset = 0;
    parser->header_value_size = 0;
}

int multipartparser_write_header(int fd, char* value, size_t offset, size_t size) {
    off_t current_offset = lseek(fd, 0, SEEK_CUR);

    lseek(fd, offset, SEEK_SET);
    int r = read(fd, value, size);

    lseek(fd, current_offset, SEEK_SET);

    if (r < 0) return 0;

    value[size] = 0;

    return 1;
}

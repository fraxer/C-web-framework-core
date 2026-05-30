#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include "formdataparser.h"
#include "multipartparser.h"

typedef enum multipart_fs {
    MP_FS_ERROR = 0,
    MP_FS_PASS,
    MP_FS_DONE,
} multipart_fs_e;

typedef enum multipart_im {
    MP_IM_ERROR = 0,
    MP_IM_NOT_SEPARATOR,
    MP_IM_PASS,
    MP_IM_NEXT_PART,
    MP_IM_DONE,
} multipart_im_e;

multipart_fs_e __multipartparser_first_separator_check(char c, multipartparser_t* parser);
multipart_im_e __multipartparser_intermediate_separator_check(char c, multipartparser_t* parser);
int multipartparser_create_part(multipartparser_t*);
int multipartparser_create_header(multipartparser_t*);
void multipartparser_reset_header(multipartparser_t*);
int multipartparser_write_header(int, char*, size_t, size_t);

multipart_fs_e __multipartparser_first_separator_check(char c, multipartparser_t* parser) {
    const size_t index = parser->separator_index;
    const size_t separator_size = parser->first_separator_size;

    if (index > separator_size)
        return MP_FS_ERROR;

    if (index == 0 && c == '-')
        return MP_FS_PASS;
    else if (index == 1 && c == '-')
        return MP_FS_PASS;
    else if (index > 1 && index < separator_size - 1 && c == parser->boundary[index - 2])
        return MP_FS_PASS;
    else if (index == separator_size - 2 && c == '\r')
        return MP_FS_PASS;
    else if (index == separator_size - 1 && c == '\n')
        return MP_FS_DONE;

    return MP_FS_ERROR;
}

multipart_im_e __multipartparser_intermediate_separator_check(char c, multipartparser_t* parser) {
    const size_t index = parser->separator_index;
    const size_t separator_size = parser->intermediate_separator_size;

    if (index > separator_size)
        return MP_IM_ERROR;

    if (index == 0 && c != '\r')
        return MP_IM_NOT_SEPARATOR;

    if (index == 0 && c == '\r')
        return MP_IM_PASS;
    else if (index == 1 && c == '\n')
        return MP_IM_PASS;
    else if (index == 2 && c == '-')
        return MP_IM_PASS;
    else if (index == 3 && c == '-')
        return MP_IM_PASS;
    else if (index > 3 && index < separator_size - 1 && c == parser->boundary[index - 4])
        return MP_IM_PASS;
    else if (index == separator_size - 2 && (c == '\r' || c == '-'))
        return MP_IM_PASS;
    else if (index == separator_size - 1) {
        if (parser->prev_ch == '\r' && c == '\n')
            return MP_IM_NEXT_PART;
        else if (parser->prev_ch == '-' && c == '-')
            return MP_IM_DONE;
    }

    return MP_IM_NOT_SEPARATOR;
}

int is_valid_header_key_char(unsigned char c) {
    // Буквы и цифры разрешены всегда
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
        return 1;
    }
    // Разрешенные спецсимволы
    switch (c) {
        case '-': case '_': case '!': case '#': case '$': 
        case '%': case '&': case '\'': case '*': case '+': 
        case '.': case '^': case '`': case '|': case '~':
            return 1;
        default:
            return 0; // Все остальные символы (включая пробел, двоеточие, кириллицу) запрещены
    }
}

int is_valid_header_value_char(unsigned char c) {
    // Разрешены видимые ASCII (33-126), пробел (32), табуляция (9) 
    // и символы UTF-8 / расширенного ASCII (128-255)
    if (c >= 32 && c != 127) {
        return 1; // Сюда попадают все валидные символы и пробел
    }
    if (c == '\t') {
        return 1; // Горизонтальная табуляция разрешена
    }
    return 0; // Все управляющие символы (0-31), включая \r и \n, запрещены!
}

void multipartparser_init(multipartparser_t* parser, int payload_fd, const char* boundary) {
    const size_t boundary_size = strlen(boundary);

    parser->boundary = boundary;
    parser->payload_size = lseek(payload_fd, 0, SEEK_END);
    parser->payload_offset = 0;
    parser->header_key_offset = 0;
    parser->header_value_offset = 0;
    parser->header_key_size = 0;
    parser->header_value_size = 0;
    parser->part_offset = 0;
    parser->part_size = 0;
    parser->separator_index = 0;
    parser->first_separator_size = boundary_size + 4; // --<boundary>\r\n
    parser->intermediate_separator_size = boundary_size + 6; // \r\n--<boundary>\r\n
    parser->stage = MP_STG_FIRST_SEPARATOR;
    parser->part = NULL;
    parser->last_part = NULL;
    parser->header = NULL;
    parser->last_header = NULL;
    parser->payload_fd = payload_fd;
    parser->error = "";
    parser->header_count = 0;
    parser->prev_ch = '\0';

    lseek(payload_fd, 0, SEEK_SET);
}

multipart_res_e multipartparser_parse(multipartparser_t* parser, char* buffer, size_t buffer_size) {
    if (buffer_size == 0) {
        parser->error = "multipartparser: empty buffer";
        return MP_RES_ERROR;
    }

    for (size_t i = 0; i < buffer_size; i++) {
        char ch = buffer[i];

        switch (parser->stage) {
        case MP_STG_FIRST_SEPARATOR: {
            multipart_fs_e res = __multipartparser_first_separator_check(ch, parser);
            if (res == MP_FS_ERROR) {
                parser->error = "multipartparser: invalid first separator";
                return MP_RES_ERROR;
            }
            else if (res == MP_FS_PASS) {
                parser->separator_index++;
            }
            else if (res == MP_FS_DONE) {
                parser->stage = MP_STG_HEADER_KEY;
                parser->separator_index = 0;
                multipartparser_reset_header(parser);
                parser->header_key_offset = parser->payload_offset + 1;
            }
            break;
        }
        case MP_STG_HEADER_KEY: {
            if (ch == ':') {
                parser->stage = MP_STG_HEADER_SPACE;
                parser->header_value_offset = parser->payload_offset + 1;
            }
            else if (!is_valid_header_key_char(ch)) {
                parser->error = "multipartparser: invalid character in header key";
                return MP_RES_ERROR;
            }
            else {
                if (parser->header_key_size >= 1024) {
                    parser->error = "multipartparser: header key size exceeds limit";
                    return MP_RES_ERROR;
                }
                parser->header_key_size++;
            }
            break;
        }
        case MP_STG_HEADER_SPACE: {
            if (ch == ' ')
                parser->header_value_offset = parser->payload_offset + 1;
            else if (ch == '\r')
                parser->stage = MP_STG_HEADER_END;
            else {
                if (parser->header_value_size >= 4096) {
                    parser->error = "multipartparser: header value size exceeds limit (HEADER_SPACE)";
                    return MP_RES_ERROR;
                }
                parser->stage = MP_STG_HEADER_VALUE;
                parser->header_value_size++;
            }
            break;
        }
        case MP_STG_HEADER_VALUE: {
            if (ch == '\r')
                parser->stage = MP_STG_HEADER_END;
            else {
                if (parser->header_value_size >= 4096) {
                    parser->error = "multipartparser: header value size exceeds limit (HEADER_VALUE)";
                    return MP_RES_ERROR;
                }
                parser->header_value_size++;
            }
            break;
        }
        case MP_STG_HEADER_END: {
            if (ch == '\n') {
                if (!multipartparser_create_header(parser)) {
                    parser->error = "multipartparser: failed to create header";
                    return MP_RES_ERROR;
                }
                parser->stage = MP_STG_EXTRA_CR;
            }
            else {
                parser->error = "multipartparser: expected LF after CR in HEADER_END";
                return MP_RES_ERROR;
            }
            break;
        }
        case MP_STG_EXTRA_CR: {
            if (ch == '\r') {
                parser->stage = MP_STG_EXTRA_LF;
            }
            else {
                parser->stage = MP_STG_HEADER_KEY;
                multipartparser_reset_header(parser);
                parser->header_key_size++;
                parser->header_key_offset = parser->payload_offset;
            }
            break;
        }
        case MP_STG_EXTRA_LF: {
            if (ch == '\n') {
                parser->stage = MP_STG_BODY;
                parser->part_offset = parser->payload_offset + 1;
                parser->part_size = 0;
            }
            else {
                parser->error = "multipartparser: expected LF after CR in EXTRA_LF";
                return MP_RES_ERROR;
            }
            break;
        }
        case MP_STG_BODY: {
            multipart_im_e res = MP_IM_ERROR;

            res = __multipartparser_intermediate_separator_check(ch, parser);
            if (res == MP_IM_ERROR) {
                parser->error = "multipartparser: invalid intermediate separator";
                return MP_RES_ERROR;
            }
            else if (res == MP_IM_NOT_SEPARATOR) {
                parser->separator_index = 0;

                multipart_im_e r = __multipartparser_intermediate_separator_check(ch, parser);
                if (r == MP_IM_PASS)
                    parser->separator_index++;
            }
            else if (res == MP_IM_PASS) {
                parser->separator_index++;
            }
            else if (res == MP_IM_NEXT_PART) {
                if (!multipartparser_create_part(parser)) {
                    parser->error = "multipartparser: create_part failed (NEXT_PART)";
                    return MP_RES_ERROR;
                }

                parser->stage = MP_STG_HEADER_KEY;
                parser->separator_index = 0;
                multipartparser_reset_header(parser);
                parser->header_key_offset = parser->payload_offset + 1;
            }
            else if (res == MP_IM_DONE) {
                if (!multipartparser_create_part(parser)) {
                    parser->error = "multipartparser: create_part failed (DONE)";
                    return MP_RES_ERROR;
                }

                parser->stage = MP_STG_END_CR;
                parser->separator_index = 0;
            }
            break;
        }
        case MP_STG_END_CR: {
            if (ch == '\r') {
                parser->stage = MP_STG_END_LF;
            }
            else {
                parser->error = "multipartparser: expected LF after CR in END_CR";
                return MP_RES_ERROR;
            }
            break;
        }
        case MP_STG_END_LF: {
            if (ch == '\n') {
                if (i == buffer_size - 1)
                    return MP_RES_DONE;

                parser->error = "multipartparser: unexpected EOF in END_LF";
                return MP_RES_ERROR;
            }
            parser->error = "multipartparser: expected LF after CR in END_LF";
            return MP_RES_ERROR;
        }
        }

        parser->payload_offset++;
        parser->part_size++;
        parser->prev_ch = ch;
    }

    return MP_RES_PARTIAL;
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
            parser->error = "multipartparser: header key is NULL";
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
                if (f->key == NULL) {
                    parser->error = "multipartparser: failed to copy field key";
                    return 0;
                }

                f->value_length = str_size(&hfield->value);
                f->value = copy_cstringn(str_get(&hfield->value), f->value_length);
                if (f->value == NULL) {
                    parser->error = "multipartparser: failed to copy field value";
                    return 0;
                }

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
    if (part == NULL) {
        parser->error = "multipartparser: failed to create part";
        return 0;
    }

    part->offset = parser->part_offset;
    part->header = parser->header;
    part->field = field;
    part->size = parser->part_size - parser->intermediate_separator_size;

    parser->header = NULL;
    parser->last_header = NULL;

    if (!parser->part)
        parser->part = part;
    if (parser->last_part)
        parser->last_part->next = part;
    parser->last_part = part;

    parser->header_count = 0;

    return 1;
}

int multipartparser_create_header(multipartparser_t* parser) {
    if (parser->header_count > 10) {
        parser->error = "multipartparser: too many headers in part";
        return 0;
    }

    size_t key_offset = parser->header_key_offset;
    size_t key_size = parser->header_key_size;
    size_t value_offset = parser->header_value_offset;
    size_t value_size = parser->header_value_size;

    http_header_t* header = http_header_create(NULL, key_size, NULL, value_size);
    if (header == NULL) {
        parser->error = "multipartparser: header_create failed";
        return 0;
    }

    if (key_size && !multipartparser_write_header(parser->payload_fd, header->key, key_offset, key_size)) {
        parser->error = "multipartparser: write_header key failed";
        return 0;
    }
    if (value_size && !multipartparser_write_header(parser->payload_fd, header->value, value_offset, value_size)) {
        parser->error = "multipartparser: write_header val failed";
        return 0;
    }

    multipartparser_reset_header(parser);

    if (!parser->header)
        parser->header = header;
    if (parser->last_header)
        parser->last_header->next = header;
    parser->last_header = header;

    parser->header_count++;

    return 1;
}

void multipartparser_reset_header(multipartparser_t* parser) {
    parser->header_key_offset = 0;
    parser->header_key_size = 0;
    parser->header_value_offset = 0;
    parser->header_value_size = 0;
}

int multipartparser_write_header(int fd, char* value, size_t offset, size_t size) {
    off_t current_offset = lseek(fd, 0, SEEK_CUR);

    lseek(fd, offset, SEEK_SET);
    ssize_t r = read(fd, value, size);

    lseek(fd, current_offset, SEEK_SET);

    if (r < 0 || r != (ssize_t)size) return 0;

    value[size] = 0;

    return 1;
}

void multipartparser_clear(multipartparser_t* parser) {
    http_headers_free(parser->header);
    http_payloadpart_free(parser->part);
}
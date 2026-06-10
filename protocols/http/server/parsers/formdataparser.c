#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "log.h"
#include "formdataparser.h"

int formdataparser_save_key(formdataparser_t* parser);
int formdataparser_save_value(formdataparser_t* parser);

int formdataparser_init(formdataparser_t* parser, const char* disposition_type) {
    if (disposition_type == NULL) return 0;

    parser->disposition_type = disposition_type;
    parser->stage = FORMDATA_SEMICOLON;
    parser->quote = 0;
    parser->size = 0;
    parser->field = NULL;
    parser->last_field = NULL;
    parser->error = "";

    return 1;
}

void formdataparser_clear(formdataparser_t* parser) {
    formdatafield_t* field = parser->field;
    while (field) {
        formdatafield_t* next = field->next;

        str_clear(&field->key);
        str_clear(&field->value);
        free(field);

        field = next;
    }

    explicit_bzero(parser->buffer, FORMDATABUFSIZ);
    parser->field = NULL;
    parser->last_field = NULL;
    parser->size = 0;
    parser->stage = FORMDATA_SEMICOLON;
    parser->quote = 0;
}

int formdataparser_parse(formdataparser_t* parser, const char* buffer, size_t buffer_size) {
    if (buffer_size == 0) {
        log_error("formdataparser: buffer size is empty");
        parser->error = "formdataparser: buffer size is empty";
        return 0;
    }
    if (buffer_size > FORMDATABUFSIZ) {
        log_error("formdataparser: buffer size is too big");
        parser->error = "formdataparser: buffer size is too big";
        return 0;
    }

    size_t disposition_type_size = strlen(parser->disposition_type);
    size_t i = 0;
    for (; i < buffer_size && i < disposition_type_size; i++) {
        if (buffer[i] != parser->disposition_type[i]) {
            log_error("formdataparser: disposition type \"form-data\" invalid in header Content-Disposition: %s", buffer);
            parser->error = "formdataparser: disposition type \"form-data\" invalid in header Content-Disposition";
            return 0;
        }
    }

    int escaped = 0;
    for (; i < buffer_size; i++) {
        char c = buffer[i];

        switch (parser->stage) {
        case FORMDATA_SEMICOLON: {
            if (c == ';') {
                parser->stage = FORMDATA_SKIP;
            }
            else if (c == ' ') {}
            else if (isalpha((unsigned char)c)) {
                parser->stage = FORMDATA_KEY;
                parser->buffer[parser->size] = c;
                parser->size++;
            }
            else {
                log_error("formdataparser: get invalid character instead semicolon: %c", c);
                parser->error = "formdataparser: get invalid character instead semicolon";
                return 0;
            }
            break;
        }
        case FORMDATA_SKIP: {
            if (c == ' ') {}
            else if (isalpha((unsigned char)c) || c == '-' || c == '*') { // creation-date or filename*
                parser->stage = FORMDATA_KEY;
                parser->buffer[parser->size] = c;
                parser->size++;
            }
            else {
                log_error("formdataparser: get invalid character after semicolon: %c", c);
                parser->error = "formdataparser: get invalid character after semicolon";
                return 0;
            }
            break;
        }
        case FORMDATA_KEY: {
            if (c == '=') {
                parser->stage = FORMDATA_VALUE;
                if (!formdataparser_save_key(parser)) {
                    log_error("formdataparser: failed to save key before '='");
                    parser->error = "formdataparser: failed to save key";
                    return 0;
                }
            }
            else if (c == ';') {
                parser->stage = FORMDATA_SKIP;
                if (!formdataparser_save_key(parser)) {
                    log_error("formdataparser: failed to save key before ';'");
                    parser->error = "formdataparser: failed to save key";
                    return 0;
                }
            }
            else if (c == ' ') {
                // Пробел после имени ключа: "filename = ..."
                if (!formdataparser_save_key(parser)) {
                    log_error("formdataparser: failed to save key before space");
                    parser->error = "formdataparser: failed to save key";
                    return 0;
                }
                parser->stage = FORMDATA_EQUAL;
            }
            else if (isalpha((unsigned char)c) || c == '-' || c == '*') {
                parser->buffer[parser->size] = c;
                parser->size++;
            }
            else {
                log_error("formdataparser: get invalid character in key: %c", c);
                parser->error = "formdataparser: get invalid character in key";
                return 0;
            }
            break;
        }
        case FORMDATA_EQUAL: {
            if (c == ' ') {}
            else if (c == '=') {
                parser->stage = FORMDATA_VALUE;
            }
            else {
                log_error("formdataparser: expected '=' after key, got: %c", c);
                parser->error = "formdataparser: expected '=' after key";
                return 0;
            }
            break;
        }
        case FORMDATA_VALUE: {
            if (parser->quote) {
                // Внутри кавычек
                if (escaped) {
                    // Предыдущий символ — обратный слеш.
                    // Экранируются только \" и \\, иначе слеш литеральный.
                    if (c == '\"' || c == '\\') {
                        parser->buffer[parser->size++] = c;
                    }
                    else {
                        parser->buffer[parser->size++] = '\\';
                        parser->buffer[parser->size++] = c;
                    }
                    escaped = 0;
                }
                else if (c == '\\') {
                    escaped = 1;            // начало escape, слеш пока не пишем
                }
                else if (c == '\"') {
                    // Закрывающая кавычка
                    if (!formdataparser_save_value(parser))
                        return 0;
                    parser->stage = FORMDATA_AFTER_VALUE;
                    parser->quote = 0;
                }
                else {
                    parser->buffer[parser->size++] = c;
                }
            }
            else {
                // Вне кавычек
                if (c == '\"') {
                    if (parser->size == 0)
                        parser->quote = 1;                  // открывающая кавычка
                    else
                        parser->buffer[parser->size++] = c; // кавычка в середине значения
                }
                else if (c == ' ') {
                    if (parser->size == 0) {
                        // ведущий пробел перед значением (OWS после '=') — пропускаем
                    }
                    else {
                        if (!formdataparser_save_value(parser))
                            return 0;
                        parser->stage = FORMDATA_SEMICOLON;
                    }
                }
                else if (c == ';') {
                    if (!formdataparser_save_value(parser))
                        return 0;
                    parser->stage = FORMDATA_SEMICOLON;
                }
                else {
                    parser->buffer[parser->size++] = c;
                }
            }
            break;
        }
        case FORMDATA_AFTER_VALUE: {
            if (c == ' ') {}
            else if (c == ';') {
                parser->stage = FORMDATA_SKIP;
            }
            else {
                log_error("formdataparser: expected ';' after quoted value, got: %c", c);
                parser->error = "formdataparser: expected ';' after quoted value";
                return 0;
            }
            break;
        }
        }
    }

    if (parser->stage == FORMDATA_VALUE) {
        // Учесть наполовину открытую квотированную строку - это ошибка!
        if (parser->quote) {
            log_error("formdataparser: unclosed quoted string in value");
            parser->error = "formdataparser: unclosed quoted string in value";
            return 0;
        }

        if (!formdataparser_save_value(parser)) {
            log_error("formdataparser: failed to save value at end of parsing");
            parser->error = "formdataparser: failed to save value";
            return 0;
        }
    }
    else if (parser->stage == FORMDATA_KEY || parser->stage == FORMDATA_EQUAL) {
        log_error("formdataparser: key without value at end of parsing");
        parser->error = "formdataparser: key without value at end of parsing";
        return 0;
    }

    return 1;
}

const char* formdataparser_find_field(formdataparser_t* parser, const char* field) {
    // RFC 6266: key* has priority over key
    size_t field_len = strlen(field);

    formdatafield_t* pfield = parser->field;
    formdatafield_t* without_star = NULL;

    while (pfield != NULL) {
        const char* key = str_get(&pfield->key);
        size_t key_len = str_size(&pfield->key);

        if (strcmp(key, field) == 0) {
            without_star = pfield;
        }
        else if (key_len == field_len + 1 && key[field_len] == '*' && strncmp(key, field, field_len) == 0) {
            return str_get(&pfield->value);
        }

        pfield = pfield->next;
    }

    if (without_star) return str_get(&without_star->value);

    return NULL;
}

formdatafield_t* formdataparser_first_field(formdataparser_t* parser) {
    return parser->field;
}

int formdataparser_save_key(formdataparser_t* parser) {
    if (parser->size == 0) {
        log_error("formdataparser: key is empty");
        parser->error = "formdataparser: key is empty";
        return 0;
    }

    formdatafield_t* field = malloc(sizeof * field);
    if (field == NULL) {
        log_error("formdataparser: malloc failed for field");
        parser->error = "formdataparser: malloc failed for field";
        return 0;
    }

    str_init(&field->key, 20);
    str_init(&field->value, 128);
    field->next = NULL;

    str_assign(&field->key, parser->buffer, parser->size);

    if (parser->field == NULL)
        parser->field = field;

    if (parser->last_field != NULL)
        parser->last_field->next = field;

    parser->last_field = field;
    parser->size = 0;

    return 1;
}

static int formdataparser_hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int formdataparser_percent_decode(const char* src, size_t src_size, str_t* dst) {
    for (size_t i = 0; i < src_size; i++) {
        if (src[i] == '%') {
            if (i + 2 >= src_size) {
                log_error("formdataparser: incomplete percent-encoding at position %zu", i);
                return 0;
            }
            int hi = formdataparser_hex(src[i + 1]);
            int lo = formdataparser_hex(src[i + 2]);
            if (hi < 0 || lo < 0) {
                log_error("formdataparser: invalid hex in percent-encoding at position %zu", i);
                return 0;
            }
            str_appendc(dst, (char)((hi << 4) | lo));
            i += 2;
        }
        else {
            str_appendc(dst, src[i]);
        }
    }
    return 1;
}

int formdataparser_save_value(formdataparser_t* parser) {
    if (parser->last_field == NULL) {
        log_error("formdataparser: no field to save value");
        parser->error = "formdataparser: no field to save value";
        return 0;
    }

    formdatafield_t* field = parser->last_field;

    // RFC 5987: key* = charset'language'percent-encoded-value
    if (str_last(&field->key) == '*') {
        const char* buf = parser->buffer;
        size_t size = parser->size;

        // charset
        size_t i = 0;
        while (i < size && buf[i] != '\'') i++;
        // Skip unknown charset — percent-decode works for UTF-8 bytes regardless

        // language (skip between first and second quote)
        i++; // skip first '
        while (i < size && buf[i] != '\'') i++;
        // language is ignored per RFC 5987

        i++; // skip second '
        if (i >= size) {
            log_error("formdataparser: missing value after charset'language' in key*");
            parser->error = "formdataparser: missing value after charset'language' in key*";
            return 0;
        }

        // percent-decode the remaining value
        if (!formdataparser_percent_decode(buf + i, size - i, &field->value)) {
            parser->error = "formdataparser: invalid hex in percent-encoding";
            return 0;
        }
    }
    else {
        str_assign(&field->value, parser->buffer, parser->size);
    }

    parser->size = 0;

    return 1;
}

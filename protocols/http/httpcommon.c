#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "str.h"
#include "helpers.h"
#include "httpcommon.h"

http_header_t* http_header_alloc();
http_cookie_t* http_cookie_alloc();


http_header_t* http_header_alloc() {
    return malloc(sizeof(http_header_t));
}

http_header_t* http_header_create(const char* key, size_t key_length, const char* value, size_t value_length) {
    http_header_t* header = http_header_alloc();

    if (header == NULL) return NULL;

    header->key = NULL;
    header->key_length = key_length;
    header->value = NULL;
    header->value_length = value_length;
    header->next = NULL;

    if (key_length)
        header->key = copy_cstringn(key, key_length);

    if (value_length)
        header->value = copy_cstringn(value, value_length);

    return header;
}

void http_header_free(http_header_t* header) {
    if (header->key)
        free((void*)header->key);

    if (header->value)
        free((void*)header->value);

    free(header);
}

void http_headers_free(http_header_t* header) {
    while (header) {
        http_header_t* next = header->next;
        http_header_free(header);
        header = next;
    }
}

http_header_t* http_header_delete(http_header_t* header, const char* key) {
    if (header == NULL) return NULL;

    if (cmpstrn_lower(header->key, header->key_length, key, strlen(key))) {
        http_header_t* next = header->next;
        http_header_free(header);
        return next;
    }

    http_header_t* first_header = header;
    http_header_t* prev_header = header;

    header = header->next;

    while (header) {
        http_header_t* next = header->next;

        if (cmpstrn_lower(header->key, header->key_length, key, strlen(key))) {
            prev_header->next = next;
            http_header_free(header);
            break;
        }

        prev_header = header;
        header = next;
    }

    return first_header;
}

http_payloadpart_t* http_payloadpart_create() {
    http_payloadpart_t* part = malloc(sizeof * part);
    if (part == NULL) return NULL;

    part->field = NULL;
    part->next = NULL;
    part->header = NULL;
    part->offset = 0;
    part->size = 0;

    return part;
}

void http_payloadpart_free(http_payloadpart_t* part) {
    while (part) {
        http_payloadpart_t* next = part->next;

        http_payloadfield_free(part->field);

        http_header_t* header = part->header;
        while (header) {
            http_header_t* next = header->next;
            http_header_free(header);
            header = next;
        }

        free(part);

        part = next;
    }
}

http_payloadfield_t* http_payloadfield_create() {
    http_payloadfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;
    field->key = NULL;
    field->key_length = 0;
    field->value = NULL;
    field->value_length = 0;
    field->next = NULL;
    return field;
}

void http_payloadfield_free(http_payloadfield_t* field) {
    while (field) {
        http_payloadfield_t* next = field->next;

        if (field->key) free(field->key);
        if (field->value) free(field->value);
        free(field);

        field = next;
    }
}

http_cookie_t* http_cookie_alloc() {
    return malloc(sizeof(http_cookie_t));
}

http_cookie_t* http_cookie_create() {
    http_cookie_t* cookie = http_cookie_alloc();

    if (cookie == NULL) return NULL;

    cookie->key = NULL;
    cookie->key_length = 0;
    cookie->value = NULL;
    cookie->value_length = 0;
    cookie->next = NULL;

    return cookie;
}

void http_cookie_free(http_cookie_t* cookie) {
    while (cookie) {
        http_cookie_t* next = cookie->next;

        if (cookie->key) free(cookie->key);
        if (cookie->value) free(cookie->value);
        if (cookie) free(cookie);

        cookie = next;
    }
}

void http_ranges_free(http_ranges_t* ranges) {
    while (ranges != NULL) {
        http_ranges_t* next = ranges->next;
        free(ranges);
        ranges = next;
    }
}

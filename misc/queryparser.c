#include <stdlib.h>
#include <string.h>

#include "httpcommon.h"
#include "helpers.h"
#include "str.h"
#include "queryparser.h"

queryparser_result_t queryparser_parse(
    const char* string,
    size_t length,
    size_t start_pos,
    void* context,
    queryparser_append_fn append_fn,
    query_t** out_first_query,
    query_t** out_last_query
) {
    size_t pos = start_pos;
    size_t point_start = start_pos;

    enum { KEY, VALUE } stage = KEY;

    // Create first query node
    query_t* query = query_create(NULL, 0, NULL, 0);
    if (query == NULL) return QUERYPARSER_ERROR;

    *out_first_query = query;
    *out_last_query = query;

    // Notify context about first query
    if (append_fn != NULL && context != NULL)
        append_fn(context, query);

    for (; pos < length; pos++) {
        switch (string[pos]) {
        case '=':
            // Skip consecutive '=' characters
            if (pos > start_pos && string[pos - 1] == '=')
                continue;

            stage = VALUE;

            query->key = urldecode(&string[point_start], pos - point_start);
            if (query->key == NULL) return QUERYPARSER_ERROR;

            point_start = pos + 1;
            break;

        case '&':
            stage = KEY;

            query->value = urldecode(&string[point_start], pos - point_start);
            if (query->value == NULL) return QUERYPARSER_ERROR;

            // Create new query node
            query_t* query_new = query_create(NULL, 0, NULL, 0);
            if (query_new == NULL) return QUERYPARSER_ERROR;

            // Link to list
            (*out_last_query)->next = query_new;
            *out_last_query = query_new;

            // Notify context about new query
            if (append_fn != NULL && context != NULL)
                append_fn(context, query_new);

            query = query_new;
            point_start = pos + 1;
            break;

        case '#':
            // Fragment identifier - finish parsing
            if (stage == KEY) {
                query->key = urldecode(&string[point_start], pos - point_start);
                if (query->key == NULL) return QUERYPARSER_ERROR;
            }
            else if (stage == VALUE) {
                query->value = urldecode(&string[point_start], pos - point_start);
                if (query->value == NULL) return QUERYPARSER_ERROR;
            }

            return QUERYPARSER_OK;
        }
    }

    // Handle remaining data
    if (stage == KEY) {
        query->key = urldecode(&string[point_start], pos - point_start);
        if (query->key == NULL) return QUERYPARSER_ERROR;

        // Empty value for key-only parameters
        query->value = copy_cstringn("", 1);
        if (query->value == NULL) return QUERYPARSER_ERROR;
    }
    else if (stage == VALUE) {
        query->value = urldecode(&string[point_start], pos - point_start);
        if (query->value == NULL) return QUERYPARSER_ERROR;
    }

    return QUERYPARSER_OK;
}

query_t* query_create(const char* key, size_t key_length, const char* value, size_t value_length) {
    query_t* query = malloc(sizeof * query);

    if (query == NULL) return NULL;

    query->key = NULL;
    query->value = NULL;
    query->next = NULL;

    if (key && key_length)
        query->key = copy_cstringn(key, key_length);

    if (value && value_length)
        query->value = copy_cstringn(value, value_length);

    return query;
}

void query_free(query_t* query) {
    free((void*)query->key);
    free((void*)query->value);
    free(query);
}

void queries_free(query_t* query) {
    while (query != NULL) {
        query_t* next = query->next;
        query_free(query);
        query = next;
    }
}

char* query_stringify(query_t* query) {
    if (query == NULL) return NULL;

    str_t* uri = str_create_empty(256);
    if (uri == NULL) return NULL;

    while (query != NULL) {
        size_t key_length = 0;
        char* key = urlencodel(query->key, strlen(query->key), &key_length);
        if (key == NULL) return NULL;

        size_t value_length = 0;
        char* value = urlencodel(query->value, strlen(query->value), &value_length);
        if (value == NULL) return NULL;

        str_append(uri, key, key_length);
        str_appendc(uri, '=');
        str_append(uri, value, value_length);
        if (query->next != NULL)
            str_appendc(uri, '&');

        free(key);
        free(value);

        query = query->next;
    }

    char* string = str_copy(uri);
    str_free(uri);

    return string;
}

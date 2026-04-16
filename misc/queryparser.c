#include <stdlib.h>
#include <string.h>

#include "httpcommon.h"
#include "helpers.h"
#include "str.h"
#include "queryparser.h"

static int __append_query(query_t** first, query_t** last, void* context, queryparser_append_fn append_fn) {
    query_t* query = query_create(NULL, 0, NULL, 0);
    if (query == NULL) return 0;

    if (*last)
        (*last)->next = query;
    else
        *first = query;

    *last = query;

    if (append_fn && context)
        append_fn(context, query);

    return 1;
}

static int __finish_pair(query_t* query, const char* string,
                          size_t key_start, size_t key_end,
                          int has_value, size_t value_start, size_t value_end) {
    query->key = urldecode(&string[key_start], key_end - key_start);
    if (!query->key) return 0;

    if (has_value) {
        query->value = urldecode(&string[value_start], value_end - value_start);
        if (!query->value) return 0;
    }

    return 1;
}

queryparser_result_t queryparser_parse(
    const char* string,
    size_t length,
    size_t start_pos,
    void* context,
    queryparser_append_fn append_fn,
    query_t** out_first_query,
    query_t** out_last_query
) {
    query_t* first = NULL;
    query_t* last = NULL;

    size_t key_start = start_pos;
    size_t key_end = start_pos;
    int has_value = 0;
    size_t value_start = 0;

    if (!__append_query(&first, &last, context, append_fn))
        return QUERYPARSER_ERROR;

    for (size_t pos = start_pos; pos < length; pos++) {
        switch (string[pos]) {
        case '=':
            if (!has_value) {
                key_end = pos;
                has_value = 1;
                value_start = pos + 1;
            }
            break;

        case '&':
            if (!has_value) key_end = pos;
            if (!__finish_pair(last, string, key_start, key_end, has_value, value_start, pos))
                goto error;

            key_start = pos + 1;
            key_end = pos + 1;
            has_value = 0;

            if (!__append_query(&first, &last, context, append_fn))
                goto error;
            break;

        case '#':
            if (!has_value) key_end = pos;
            if (!__finish_pair(last, string, key_start, key_end, has_value, value_start, pos))
                goto error;

            *out_first_query = first;
            *out_last_query = last;
            return QUERYPARSER_OK;
        }
    }

    if (!has_value)
        key_end = length;

    if (!__finish_pair(last, string, key_start, key_end, has_value, value_start, length))
        goto error;

    *out_first_query = first;
    *out_last_query = last;
    return QUERYPARSER_OK;

error:
    queries_free(first);
    *out_first_query = NULL;
    *out_last_query = NULL;
    return QUERYPARSER_ERROR;
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
    if (!query) return;
    if (query->key) free((void*)query->key);
    if (query->value) free((void*)query->value);
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
        if (key == NULL) {
            str_free(uri);
            return NULL;
        }

        size_t value_length = 0;
        char* value = urlencodel(query->value, strlen(query->value), &value_length);
        if (value == NULL) {
            str_free(uri);
            free(key);
            return NULL;
        }

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

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <string.h>

#include "query.h"
#include "typecheck.h"

static const char* __value(query_t* query, const char* param_name) {
    while (query) {
        if (strcmp(param_name, query->key) == 0)
            return query->value;

        query = query->next;
    }

    return NULL;
}

static const char* __prepare_and_get_value(query_t* query, const char* param_name, int** ok) {
    if (ok == NULL)
        return NULL;

    **ok = 0;

    if (param_name == NULL)
        return NULL;

    const char* value = __value(query, param_name);
    if (value == NULL)
        return NULL;

    return value;
}

const char* query_param_char(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return NULL;

    *ok = 1;

    return value;
}

int query_param_int(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_int(value))
        return 0;

    *ok = 1;

    return atoi(value);
}

unsigned int query_param_uint(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_uint(value))
        return 0;

    *ok = 1;

    return strtoul(value, NULL, 10);
}

long query_param_long(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_long(value))
        return 0;

    *ok = 1;

    return strtol(value, NULL, 10);
}

unsigned long query_param_ulong(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_ulong(value))
        return 0;

    *ok = 1;

    return strtoul(value, NULL, 10);
}

float query_param_float(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_float(value))
        return 0;

    *ok = 1;

    return strtof(value, NULL);
}

double query_param_double(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_double(value))
        return 0;

    *ok = 1;

    return strtod(value, NULL);
}

long double query_param_ldouble(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_long_double(value))
        return 0;

    *ok = 1;

    return strtold(value, NULL);
}

json_doc_t* query_param_array(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return NULL;

    if (value == NULL || *value == '\0')
        return NULL;

    json_doc_t* document = json_parse(value);
    if (document == NULL)
        return NULL;

    json_token_t* array = json_root(document);
    if (!json_is_array(array)) {
        json_free(document);
        return NULL;
    }

    *ok = 1;

    return document;
}

json_doc_t* query_param_object(query_t* query, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(query, param_name, &ok);
    if (value == NULL)
        return NULL;

    if (value == NULL || *value == '\0')
        return NULL;

    json_doc_t* document = json_parse(value);
    if (document == NULL)
        return NULL;

    json_token_t* object = json_root(document);
    if (!json_is_object(object)) {
        json_free(document);
        return NULL;
    }

    *ok = 1;

    return document;
}

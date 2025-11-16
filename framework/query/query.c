#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <string.h>

#include "log.h"
#include "query.h"

const char* __value(http1request_t* request, const char* param_name) {
    query_t* query = request->query_;

    while (query) {
        if (strcmp(param_name, query->key) == 0)
            return query->value;

        query = query->next;
    }

    return NULL;
}

const char* __prepare_and_get_value(http1request_t* request, const char* param_name, int** ok) {
    if (ok == NULL)
        return NULL;

    **ok = 0;

    if (request == NULL)
        return NULL;

    if (param_name == NULL)
        return NULL;

    const char* value = __value(request, param_name);
    if (value == NULL)
        return NULL;

    return value;
}

int __is_int(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;
    long num = strtol(str, &endptr, 10);

    if (errno == ERANGE || num > INT_MAX || num < INT_MIN)
        return 0;

    if (endptr == str)
        return 0;  // Не было считано ни одной цифры

    while (*endptr != '\0') {
        if (!isspace((unsigned char)*endptr))
            return 0;  // Есть нечисловые символы после числа

        endptr++;
    }

    return 1;
}

int __is_uint(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    if (*str == '-')
        return 0;

    char* endptr = NULL;
    errno = 0;

    unsigned long val = strtoul(str, &endptr, 10);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE || val > UINT_MAX)
        return 0;

    return 1;
}

int __is_long(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;

    long val = strtol(str, &endptr, 10);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE || val > LONG_MAX || val < LONG_MIN)
        return 0;

    return 1;
}

int __is_ulong(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    if (*str == '-')
        return 0;

    char* endptr = NULL;
    errno = 0;

    unsigned long val = strtoul(str, &endptr, 10);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE || val > ULONG_MAX)
        return 0;

    return 1;
}

int __is_float(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;

    float val = strtof(str, &endptr);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE)
        return 0;

    if (isnan(val) || isinf(val))
        return 0;

    return 1;
}

int __is_double(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;

    float val = strtod(str, &endptr);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE)
        return 0;

    if (isnan(val) || isinf(val))
        return 0;

    return 1;
}

int __is_long_double(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;

    long double val = strtold(str, &endptr);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE)
        return 0;

    if (isnan(val) || isinf(val))
        return 0;

    return 1;
}

const char* query_param_char(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    *ok = 1;

    return value;
}

int query_param_int(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!__is_int(value))
        return 0;

    *ok = 1;

    return atoi(value);
}

unsigned int query_param_uint(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!__is_uint(value))
        return 0;

    *ok = 1;

    return strtoul(value, NULL, 10);
}

long query_param_long(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!__is_long(value))
        return 0;

    *ok = 1;

    return strtol(value, NULL, 10);
}

unsigned long query_param_ulong(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!__is_ulong(value))
        return 0;

    *ok = 1;

    return strtol(value, NULL, 10);
}

float query_param_float(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!__is_float(value))
        return 0;

    *ok = 1;

    return strtof(value, NULL);
}

double query_param_double(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!__is_double(value))
        return 0;

    *ok = 1;

    return strtod(value, NULL);
}

long double query_param_ldouble(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!__is_long_double(value))
        return 0;

    *ok = 1;

    return strtold(value, NULL);
}

json_doc_t* query_param_array(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
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

json_doc_t* query_param_object(http1request_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
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

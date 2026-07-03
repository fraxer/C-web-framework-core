#include <stdlib.h>

#include "typecheck.h"
#include "httppayload.h"
#include "httprequest.h"

/* Returns the field value as a heap-allocated string (get_payloadf contract);
 * every caller below owns it and must free it. `ok` may be NULL. */
static char* __prepare_and_get_value(httprequest_t* request, const char* param_name, int* ok) {
    if (ok != NULL)
        *ok = 0;

    if (request == NULL)
        return NULL;

    if (param_name == NULL)
        return NULL;

    return request->get_payloadf(request, param_name);
}

char* payload_param_char(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return NULL;

    if (ok != NULL)
        *ok = 1;

    return value;
}

int payload_param_int(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return 0;

    int result = 0;
    if (is_int(value)) {
        result = atoi(value);
        if (ok != NULL)
            *ok = 1;
    }

    free(value);

    return result;
}

unsigned int payload_param_uint(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return 0;

    unsigned int result = 0;
    if (is_uint(value)) {
        result = (unsigned int)strtoul(value, NULL, 10);
        if (ok != NULL)
            *ok = 1;
    }

    free(value);

    return result;
}

long payload_param_long(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return 0;

    long result = 0;
    if (is_long(value)) {
        result = strtol(value, NULL, 10);
        if (ok != NULL)
            *ok = 1;
    }

    free(value);

    return result;
}

unsigned long payload_param_ulong(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return 0;

    unsigned long result = 0;
    if (is_ulong(value)) {
        result = strtoul(value, NULL, 10);
        if (ok != NULL)
            *ok = 1;
    }

    free(value);

    return result;
}

float payload_param_float(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return 0;

    float result = 0;
    if (is_float(value)) {
        result = strtof(value, NULL);
        if (ok != NULL)
            *ok = 1;
    }

    free(value);

    return result;
}

double payload_param_double(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return 0;

    double result = 0;
    if (is_double(value)) {
        result = strtod(value, NULL);
        if (ok != NULL)
            *ok = 1;
    }

    free(value);

    return result;
}

long double payload_param_ldouble(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return 0;

    long double result = 0;
    if (is_long_double(value)) {
        result = strtold(value, NULL);
        if (ok != NULL)
            *ok = 1;
    }

    free(value);

    return result;
}

json_doc_t* payload_param_array(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return NULL;

    json_doc_t* document = json_parse(value);
    free(value);
    if (document == NULL)
        return NULL;

    if (!json_is_array(json_root(document))) {
        json_free(document);
        return NULL;
    }

    if (ok != NULL)
        *ok = 1;

    return document;
}

json_doc_t* payload_param_object(httprequest_t* request, const char* param_name, int* ok) {
    char* value = __prepare_and_get_value(request, param_name, ok);
    if (value == NULL)
        return NULL;

    json_doc_t* document = json_parse(value);
    free(value);
    if (document == NULL)
        return NULL;

    if (!json_is_object(json_root(document))) {
        json_free(document);
        return NULL;
    }

    if (ok != NULL)
        *ok = 1;

    return document;
}

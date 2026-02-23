#include "typecheck.h"
#include "httppayload.h"
#include "httprequest.h"

static const char* __prepare_and_get_value(httprequest_t* request, const char* param_name, int** ok) {
    if (ok == NULL)
        return NULL;

    **ok = 0;

    if (request == NULL)
        return NULL;

    if (param_name == NULL)
        return NULL;

    return request->get_payloadf(request, param_name);
}

const char* payload_param_char(httprequest_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return NULL;

    *ok = 1;

    return value;
}

int payload_param_int(httprequest_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_int(value))
        return 0;

    *ok = 1;

    return atoi(value);
}

unsigned int payload_param_uint(httprequest_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_uint(value))
        return 0;

    *ok = 1;

    return strtoul(value, NULL, 10);
}

long payload_param_long(httprequest_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_long(value))
        return 0;

    *ok = 1;

    return strtol(value, NULL, 10);
}

unsigned long payload_param_ulong(httprequest_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_ulong(value))
        return 0;

    *ok = 1;

    return strtoul(value, NULL, 10);
}

float payload_param_float(httprequest_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_float(value))
        return 0;

    *ok = 1;

    return strtof(value, NULL);
}

double payload_param_double(httprequest_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_double(value))
        return 0;

    *ok = 1;

    return strtod(value, NULL);
}

long double payload_param_ldouble(httprequest_t* request, const char* param_name, int* ok) {
    const char* value = __prepare_and_get_value(request, param_name, &ok);
    if (value == NULL)
        return 0;

    if (!is_long_double(value))
        return 0;

    *ok = 1;

    return strtold(value, NULL);
}

json_doc_t* payload_param_array(httprequest_t* request, const char* param_name, int* ok) {
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

json_doc_t* payload_param_object(httprequest_t* request, const char* param_name, int* ok) {
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
#ifndef __HTTP1PAYLOAD__
#define __HTTP1PAYLOAD__

#include "httprequest.h"
#include "json.h"

/**
 * Get payload parameter as string.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or error
 * @return pointer to parameter value or NULL if not found
 */
const char* payload_param_char(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as integer.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed integer value or 0 on error
 */
int payload_param_int(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as unsigned integer.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed unsigned integer value or 0 on error
 */
unsigned int payload_param_uint(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as long integer.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed long value or 0 on error
 */
long payload_param_long(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as unsigned long integer.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed unsigned long value or 0 on error
 */
unsigned long payload_param_ulong(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as float.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed float value or 0.0f on error
 */
float payload_param_float(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as double.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed double value or 0.0 on error
 */
double payload_param_double(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as long double.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed long double value or 0.0L on error
 */
long double payload_param_ldouble(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as JSON array.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or parse error
 * @return pointer to JSON document containing array or NULL on error. Caller must free the returned object.
 */
json_doc_t* payload_param_array(httprequest_t* request, const char* param_name, int* ok);

/**
 * Get payload parameter as JSON object.
 * @param request - HTTP request instance
 * @param param_name - name of the payload parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or parse error
 * @return pointer to JSON document containing object or NULL on error. Caller must free the returned object.
 */
json_doc_t* payload_param_object(httprequest_t* request, const char* param_name, int* ok);

#endif

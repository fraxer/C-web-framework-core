#ifndef __QUERY__
#define __QUERY__

#include "json.h"

typedef struct url_query {
    const char* key;
    const char* value;
    struct url_query* next;
} query_t;

/**
 * Get query parameter as string.
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or error
 * @return pointer to parameter value or NULL if not found
 */
const char* query_param_char(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as integer.
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed integer value or 0 on error
 */
int query_param_int(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as unsigned integer.
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed unsigned integer value or 0 on error
 */
unsigned int query_param_uint(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as long integer.
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed long value or 0 on error
 */
long query_param_long(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as unsigned long integer.
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed unsigned long value or 0 on error
 */
unsigned long query_param_ulong(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as float.
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed float value or 0.0f on error
 */
float query_param_float(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as double.
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed double value or 0.0 on error
 */
double query_param_double(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as long double.
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or conversion error
 * @return parsed long double value or 0.0L on error
 */
long double query_param_ldouble(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as JSON array.
 * Parses array format: ?param[]=val1&param[]=val2 or ?param=val1,val2
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or parse error
 * @return pointer to JSON document containing array or NULL on error. Caller must free the returned object.
 */
json_doc_t* query_param_array(query_t* query, const char* param_name, int* ok);

/**
 * Get query parameter as JSON object.
 * Parses object format: ?param[key1]=val1&param[key2]=val2
 * @param query - linked list of query parameters
 * @param param_name - name of the query parameter (null-terminated string)
 * @param ok - pointer to status flag: set to 1 on success, 0 if not found or parse error
 * @return pointer to JSON document containing object or NULL on error. Caller must free the returned object.
 */
json_doc_t* query_param_object(query_t* query, const char* param_name, int* ok);

#endif

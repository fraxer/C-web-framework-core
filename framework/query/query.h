#ifndef __QUERY__
#define __QUERY__

#include "http1request.h"
#include "json.h"

const char* query_param_char(http1request_t* request, const char* param_name, int* ok);
int query_param_int(http1request_t* request, const char* param_name, int* ok);
unsigned int query_param_uint(http1request_t* request, const char* param_name, int* ok);
long query_param_long(http1request_t* request, const char* param_name, int* ok);
unsigned long query_param_ulong(http1request_t* request, const char* param_name, int* ok);
float query_param_float(http1request_t* request, const char* param_name, int* ok);
double query_param_double(http1request_t* request, const char* param_name, int* ok);
long double query_param_ldouble(http1request_t* request, const char* param_name, int* ok);
jsondoc_t* query_param_array(http1request_t* request, const char* param_name, int* ok);
jsondoc_t* query_param_object(http1request_t* request, const char* param_name, int* ok);

#endif

#ifndef __ROUTE__
#define __ROUTE__

#include <pcre2.h>

#include "request.h"
#include "response.h"
#include "ratelimiter.h"
#include "strtemplate.h"

typedef enum route_methods {
    ROUTE_NONE = -1,
    ROUTE_GET = 0,
    ROUTE_POST,
    ROUTE_PUT,
    ROUTE_DELETE,
    ROUTE_OPTIONS,
    ROUTE_PATCH,
    ROUTE_HEAD
} route_methods_e;

typedef struct route_param {
    unsigned short int start;
    unsigned short int end;
    size_t string_len;
    char* string;
    struct route_param* next;
} route_param_t;

typedef struct route {
    int location_erroffset;
    int is_primitive;
    int params_count;
    char* path;
    size_t path_length;
    const char* location_error;
    pcre2_code* location;
    route_param_t* param;
    struct route* next;
    void(*handler[7])(void*);
    /* The served file, as a template: {N} stands for capture group N of the
     * location, so one route can cover a whole directory. A template without
     * placeholders is simply a constant path. */
    strtemplate_t* static_file[7];
    /* Cache-Control for whatever the route answers with. The response filter
     * applies it only when nothing else set one, so a handler still decides for
     * itself and this is the default for the route. */
    char* cache_control[7];
    ratelimiter_t* ratelimiter;
} route_t;

route_t* route_create(const char*);
int route_set_http_handler(route_t*, const char*, void(*)(void*), ratelimiter_t* ratelimiter);
int route_set_http_static(route_t*, const char* method, const char* static_file, ratelimiter_t* ratelimiter);
int route_set_http_cache_control(route_t*, const char* method, const char* cache_control);
int route_set_websockets_handler(route_t*, const char*, void(*)(void*), ratelimiter_t* ratelimiter);
void routes_free(route_t* route);
int route_compare_primitive(route_t*, const char*, size_t);

#endif

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
    size_t start;
    size_t end;
    /* The capture group that holds the value. Not the param's position: a
     * group inside an expression ("{lang|(en|ru)}") shifts every group after
     * it, so each param's group is named (_p1, _p2, ...) and looked up once
     * the location is compiled. */
    int group;
    size_t string_len;
    char* string;
    struct route_param* next;
} route_param_t;

typedef struct route {
    int is_primitive;
    int params_count;
    /* Capture groups of the compiled location, the params' included. */
    int captures;
    char* path;
    size_t path_length;
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
    /* Хранилище, из которого отдаётся static_file этого метода, или NULL —
     * тогда путь резолвится относительно server.root, как раньше. Имя, а не
     * указатель на storage_t: резолв по имени смотрит в активную конфигурацию
     * в момент запроса и потому переживает reload. */
    char* storage_name[7];
    ratelimiter_t* ratelimiter;
} route_t;

route_t* route_create(const char*);
int route_set_http_handler(route_t*, const char*, void(*)(void*), ratelimiter_t* ratelimiter);
int route_set_http_static(route_t*, const char* method, const char* static_file, const char* storage_name, ratelimiter_t* ratelimiter);
int route_set_http_cache_control(route_t*, const char* method, const char* cache_control);
int route_set_websockets_handler(route_t*, const char*, void(*)(void*), ratelimiter_t* ratelimiter);
void routes_free(route_t* route);
int route_compare_primitive(const route_t*, const char*, size_t);

/* The most capture groups a location may have; route_create refuses more.
 * The offsets route_match fills live on the stack of the worker matching the
 * request, and a pattern from the configuration must not decide how deep that
 * goes: callers size them by ROUTE_VECTOR_MAX, not by the route. */
#define ROUTE_MAX_CAPTURES 64
#define ROUTE_VECTOR_MAX ((ROUTE_MAX_CAPTURES + 1) * 2)

/* How many ints route_match writes: a (start, end) pair for the whole match
 * and one for each capture group. Never more than ROUTE_VECTOR_MAX. */
int route_vector_size(const route_t* route);

/* Does `path` match the route? `vector` receives the offsets route_vector_size
 * describes, -1 for a group that took no part; a param's value is the pair of
 * its `group`. A primitive route is answered by comparison and reports only the
 * whole path. Returns 1 on a match, 0 on none, -1 when out of memory. */
int route_match(const route_t* route, const char* path, size_t length,
                int* vector, int vector_size);

#endif

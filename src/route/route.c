#include <string.h>

#include "log.h"
#include "route.h"

#define ROUTE_EMPTY_PATH "Route error: Empty path\n"
#define ROUTE_OUT_OF_MEMORY "Route error: Out of memory\n"
#define ROUTE_EMPTY_TOKEN "Route error: Empty token in \"%s\"\n"
#define ROUTE_UNOPENED_TOKEN "Route error: Unopened token in \"%s\"\n"
#define ROUTE_UNCLOSED_TOKEN "Route error: Unclosed token in \"%s\"\n"
#define ROUTE_EMPTY_PARAM_NAME "Route error: Empty param name in \"%s\"\n"
#define ROUTE_EMPTY_PARAM_EXPRESSION "Route error: Empty param expression in \"%s\"\n"
#define ROUTE_PARAM_ONE_WORD "Route error: For param need one word in \"%s\"\n"
#define ROUTE_REGEX_AND_PARAMS "Route error: Can't use named params with regex \"%s\"\n"
#define ROUTE_BAD_STATIC_FILE "Route error: Bad static file template \"%s\"\n"

typedef struct route_parser {
    int is_primitive;
    int params_count;
    unsigned short int dirty_pos;
    unsigned short int pos;
    /* `location` is the pattern and `path` is the literal string a primitive
     * route is compared against, and they are no longer the same text: a dot is
     * escaped in the pattern and plain in the path. Two cursors, one pass. */
    unsigned short int path_pos;
    const char* dirty_location;
    char* path;
    char* location;
    route_param_t* first_param;
    route_param_t* last_param;
} route_parser_t;

route_t* route_init_route();
int route_init_parser(route_parser_t* parser, const char* dirty_location);
int route_parse_location(route_parser_t* parser);
int route_parse_token(route_parser_t* parser);
void route_insert_custom_symbol(route_parser_t* parser, char symbol);
void route_insert_symbol(route_parser_t* parser);
void route_insert_escaped_symbol(route_parser_t* parser);
int route_alloc_param(route_parser_t* parser);
int route_fill_param(route_parser_t* parser);
void route_parser_free(route_parser_t* parser);


route_t* route_create(const char* dirty_location) {
    if (dirty_location == NULL || dirty_location[0] == 0) {
        log_error(ROUTE_EMPTY_PATH);
        return NULL;
    }

    int result = -1;

    route_parser_t parser = {0};

    route_t* route = route_init_route();

    if (route == NULL) goto failed;

    if (route_init_parser(&parser, dirty_location) == -1) goto failed;

    if (route_parse_location(&parser) == -1) goto failed;

    route->location = pcre_compile(parser.location, 0, &route->location_error, &route->location_erroffset, NULL);

    if (route->location_error != NULL) goto failed;

    route->is_primitive = parser.is_primitive;
    route->params_count = parser.params_count;
    route->path = parser.path;
    route->path_length = strlen(parser.path);
    route->param = parser.first_param;
    parser.path = NULL;
    parser.first_param = NULL;

    result = 0;

    failed:

    if (result == -1 && route) {
        free(route);
        route = NULL;
    }

    route_parser_free(&parser);

    return route;
}

route_t* route_init_route() {
    route_t* route = (route_t*)malloc(sizeof(route_t));

    if (route == NULL) {
        log_error(ROUTE_OUT_OF_MEMORY);
        return NULL;
    }

    route->path = NULL;
    route->path_length = 0;
    route->location_error = NULL;

    route->handler[ROUTE_GET] = NULL;
    route->handler[ROUTE_POST] = NULL;
    route->handler[ROUTE_PUT] = NULL;
    route->handler[ROUTE_DELETE] = NULL;
    route->handler[ROUTE_OPTIONS] = NULL;
    route->handler[ROUTE_PATCH] = NULL;
    route->handler[ROUTE_HEAD] = NULL;

    for (int i = 0; i < 7; i++) {
        route->static_file[i] = NULL;
        route->cache_control[i] = NULL;
    }

    route->location_erroffset = 0;
    route->location = NULL;
    route->is_primitive = 0;
    route->params_count = 0;
    route->param = NULL;
    route->next = NULL;
    route->ratelimiter = NULL;

    return route;
}

int route_init_parser(route_parser_t* parser, const char* dirty_location) {
    parser->is_primitive = 0;
    parser->params_count = 0;
    parser->dirty_pos = 0;
    parser->pos = 0;
    parser->path_pos = 0;
    parser->dirty_location = dirty_location;
    /* Twice the input plus the anchors: escaping a metacharacter adds a byte,
     * and in the worst case every byte is one. */
    const size_t room = strlen(dirty_location) * 2 + 3; // + ^, + $, + \0
    parser->path = calloc(room, 1);
    parser->location = calloc(room, 1);
    parser->first_param = NULL;
    parser->last_param = NULL;

    if (parser->path == NULL || parser->location == NULL) {
        log_error(ROUTE_OUT_OF_MEMORY);
        return -1;
    }

    return 0;
}

/* Is this location plain text -- no {param} tokens and nothing PCRE reads as an
 * operator? Only then may '.' and '?' be taken literally: an operator anywhere
 * in the string means the author is writing a pattern, and "/assets/(.*)" must
 * keep meaning what it says.
 *
 * '.' and '?' are deliberately absent from this list: they are what the answer
 * decides about, and counting them would make every dotted path a pattern. */
static int __location_is_literal(const char* location) {
    for (const char* p = location; *p != 0; p++) {
        switch (*p) {
        case '{': case '}': case '*': case '+': case '(': case ')':
        case '[': case ']': case '|': case '^': case '$': case '\\':
            return 0;
        default:
            break;
        }
    }

    return 1;
}

int route_parse_location(route_parser_t* parser) {
    parser->is_primitive = 1;
    int has_regex_symbols = 0;
    const int literal = __location_is_literal(parser->dirty_location);

    for (; parser->dirty_location[parser->dirty_pos] != 0; parser->dirty_pos++) {
        switch (parser->dirty_location[parser->dirty_pos]) {
        case '{':
            if (route_parse_token(parser) == -1) return -1;
            parser->is_primitive = 0;
            break;
        case '\\':
            switch (parser->dirty_location[parser->dirty_pos + 1]) {
            case '{':
            case '}':
                route_insert_symbol(parser);
                parser->dirty_pos++;
                break;
            }
            route_insert_symbol(parser);
            /* The backslash reaches the compiled pattern, where it changes the
             * meaning of what follows ("\d" is a digit class, "\{" a literal
             * brace) -- and it also reaches `path`, which the primitive
             * comparison matches byte for byte. The two would disagree, so a
             * location with a backslash is not primitive. */
            parser->is_primitive = 0;
            break;
        case '}':
            log_error(ROUTE_UNOPENED_TOKEN, parser->dirty_location);
            return -1;
            break;
        case '*':
        case '[':
        case ']':
        case '(':
        case ')':
        case '+':
        case '^':
        case '|':
        case '$':
            has_regex_symbols = 1;
            route_insert_symbol(parser);
            parser->is_primitive = 0;
            break;
        /* '.' and '?' outside a {param} are literal characters of a path, not
         * regex operators: nobody writing "/api/v1.0" means "any character
         * here", and the route silently matching "/api/v1x0" was a defect
         * rather than a feature. Escaped into the pattern, kept plain in the
         * path — so the location stays eligible for the comparison shortcut.
         *
         * Inside a {name|pattern} token the opposite is true, and that text is
         * handled by route_parse_token, which never reaches this switch. */
        case '.':
        case '?':
            if (literal) {
                route_insert_escaped_symbol(parser);
                break;
            }

            /* Part of a pattern the author wrote on purpose: left as it was,
             * and the comparison shortcut is off — the pattern means more than
             * the string it is spelled with. */
            route_insert_symbol(parser);
            parser->is_primitive = 0;
            break;
        default:
            route_insert_symbol(parser);
        }
    }

    parser->path[parser->path_pos] = 0;

    if (!parser->is_primitive && parser->first_param != NULL) {
        memmove(parser->location + 1, parser->location, parser->pos);
        parser->pos++;
        parser->location[0] = '^';
        parser->location[parser->pos] = '$';
        parser->pos++;
    }
    else if (parser->is_primitive) {
        memmove(parser->location + 1, parser->location, parser->pos);
        parser->location[0] = '^';
        parser->pos++;
        parser->location[parser->pos] = '$';
        parser->pos++;
    }

    parser->location[parser->pos] = 0;

    if (parser->first_param != NULL && has_regex_symbols) {
        log_error(ROUTE_REGEX_AND_PARAMS, parser->dirty_location);
        return -1;
    }

    return 0;
}

int route_parse_token(route_parser_t* parser) {
    parser->dirty_pos++;

    int separator_found = 0;
    int brakets_count = 0;
    int start = parser->pos;
    int symbol_finded = 0;

    if (route_alloc_param(parser) == -1) return -1;

    for (; parser->dirty_location[parser->dirty_pos] != 0; parser->dirty_pos++) {
        char ch = parser->dirty_location[parser->dirty_pos];
        switch (ch) {
        case '{':
            if (!separator_found) {
                log_error(ROUTE_EMPTY_TOKEN, parser->dirty_location);
                return -1;
            }
            brakets_count++;
            route_insert_symbol(parser);
            break;
        case '}':
            if (!separator_found) {
                log_error(ROUTE_EMPTY_TOKEN, parser->dirty_location);
                return -1;
            }
            if (parser->pos - start <= 1) { // only "(" emitted, expression is empty
                log_error(ROUTE_EMPTY_PARAM_EXPRESSION, parser->dirty_location);
                return -1;
            }
            if (brakets_count == 0) {
                route_insert_custom_symbol(parser, ')');
                return 0;
            }
            brakets_count--;
            route_insert_symbol(parser);
            break;
        case '\\':
            switch (parser->dirty_location[parser->dirty_pos + 1]) {
            case '}':
                log_error(ROUTE_EMPTY_PARAM_EXPRESSION, parser->dirty_location);
                return -1;
                break;
            default:
                if (separator_found) {
                    route_insert_symbol(parser);
                }
            }
            break;
        case '\t':
        case '\r':
        case '\n':
        case ' ':
            if (!separator_found && symbol_finded) {
                switch (parser->dirty_location[parser->dirty_pos + 1]) {
                case '\t':
                case '\r':
                case '\n':
                case ' ':
                case '|':
                    break;
                default:
                    log_error(ROUTE_PARAM_ONE_WORD, parser->dirty_location);
                    return -1;
                }
            }
            break;
        case '|':
            if (separator_found) { // alternation inside the expression
                route_insert_symbol(parser);
                break;
            }
            separator_found = 1;
            symbol_finded = 0;
            if (route_fill_param(parser) == -1) return -1;
            parser->pos = start;
            route_insert_custom_symbol(parser, '(');
            break;
        default:
            route_insert_symbol(parser);
            symbol_finded = 1;
        }
    }

    log_error(ROUTE_UNCLOSED_TOKEN, parser->dirty_location);

    return -1;
}

void route_insert_custom_symbol(route_parser_t* parser, char symbol) {
    parser->location[parser->pos] = symbol;
    parser->pos++;
}

void route_insert_symbol(route_parser_t* parser) {
    const char ch = parser->dirty_location[parser->dirty_pos];

    parser->location[parser->pos] = ch;
    parser->pos++;

    /* The path is only ever read for a primitive location, where it is the same
     * text as the pattern; writing it unconditionally keeps the two cursors in
     * step without asking every call site whether it matters here. */
    parser->path[parser->path_pos] = ch;
    parser->path_pos++;
}

/* A character that means itself in the location but is a metacharacter to PCRE:
 * it goes escaped into the pattern and plain into the path. This is what makes
 * "/api/v1.0" match "/api/v1.0" and nothing else -- before it, the pattern was
 * "^/api/v1.0$" and matched "/api/v1x0" too. */
void route_insert_escaped_symbol(route_parser_t* parser) {
    parser->location[parser->pos] = '\\';
    parser->pos++;

    route_insert_symbol(parser);
}

int route_alloc_param(route_parser_t* parser) {
    route_param_t* param = malloc(sizeof * param);
    if (param == NULL) {
        log_error(ROUTE_OUT_OF_MEMORY);
        return -1;
    }

    param->start = parser->pos;
    param->end = parser->pos;
    param->string_len = 0;
    param->string = NULL;
    param->next = NULL;

    parser->params_count++;

    if (parser->first_param == NULL)
        parser->first_param = param;

    if (parser->last_param != NULL)
        parser->last_param->next = param;

    parser->last_param = param;

    return 0;
}

int route_fill_param(route_parser_t* parser) {
    route_param_t* param = parser->last_param;

    param->end = parser->pos;
    param->string_len = param->end - param->start;

    if (param->string_len == 0) {
        log_error(ROUTE_EMPTY_PARAM_NAME, parser->dirty_location);
        return -1;
    }

    char* string = malloc(param->string_len + 1);
    if (string == NULL) {
        log_error(ROUTE_OUT_OF_MEMORY);
        return -1;
    }

    strncpy(string, &parser->location[param->start], param->string_len);
    string[param->string_len] = 0;
    param->string = string;

    return 0;
}

void route_parser_free(route_parser_t* parser) {
    if (parser->path != NULL)
        free(parser->path);

    if (parser->location != NULL)
        free(parser->location);

    route_param_t* param = parser->first_param;
    while (param != NULL) {
        route_param_t* next = param->next;
        if (param->string != NULL)
            free(param->string);
        free(param);
        param = next;
    }
}

static int route_method_index(const char* method) {
    if (strcmp(method, "GET") == 0) return ROUTE_GET;
    if (strcmp(method, "POST") == 0) return ROUTE_POST;
    if (strcmp(method, "PUT") == 0) return ROUTE_PUT;
    if (strcmp(method, "DELETE") == 0) return ROUTE_DELETE;
    if (strcmp(method, "OPTIONS") == 0) return ROUTE_OPTIONS;
    if (strcmp(method, "PATCH") == 0) return ROUTE_PATCH;
    if (strcmp(method, "HEAD") == 0) return ROUTE_HEAD;
    return ROUTE_NONE;
}

static int route_ws_method_index(const char* method) {
    if (strcmp(method, "GET") == 0) return ROUTE_GET;
    if (strcmp(method, "POST") == 0) return ROUTE_POST;
    if (strcmp(method, "DELETE") == 0) return ROUTE_DELETE;
    if (strcmp(method, "PATCH") == 0) return ROUTE_PATCH;
    return ROUTE_NONE;
}

// The setters take ownership of ratelimiter in every outcome; a limiter that
// is not stored on the route must be freed here, not leaked.
static void route_own_ratelimiter(route_t* route, ratelimiter_t* ratelimiter) {
    if (ratelimiter == NULL || ratelimiter == route->ratelimiter) return;
    ratelimiter_free(route->ratelimiter);
    route->ratelimiter = ratelimiter;
}

static void route_drop_ratelimiter(route_t* route, ratelimiter_t* ratelimiter) {
    if (ratelimiter == route->ratelimiter) return;
    ratelimiter_free(ratelimiter);
}

int route_set_http_handler(route_t* route, const char* method, void(*function)(void*), ratelimiter_t* ratelimiter) {
    const int m = route_method_index(method);
    if (m == ROUTE_NONE) {
        route_drop_ratelimiter(route, ratelimiter);
        return 0;
    }

    if (route->handler[m]) {
        route_drop_ratelimiter(route, ratelimiter);
        return 1;
    }

    route->handler[m] = function;
    route_own_ratelimiter(route, ratelimiter);

    return 1;
}

int route_set_http_static(route_t* route, const char* method, const char* static_file, ratelimiter_t* ratelimiter) {
    const int m = route_method_index(method);
    if (m == ROUTE_NONE) {
        route_drop_ratelimiter(route, ratelimiter);
        return 0;
    }

    if (route->static_file[m]) {
        route_drop_ratelimiter(route, ratelimiter);
        return 1;
    }

    route->static_file[m] = strtemplate_create(static_file);
    if (route->static_file[m] == NULL) {
        log_error(ROUTE_BAD_STATIC_FILE, static_file);
        route_drop_ratelimiter(route, ratelimiter);
        return 0;
    }
    route_own_ratelimiter(route, ratelimiter);

    return 1;
}

int route_set_http_cache_control(route_t* route, const char* method, const char* cache_control) {
    const int m = route_method_index(method);
    if (m == ROUTE_NONE) return 0;

    if (route->cache_control[m]) return 1;

    const size_t len = strlen(cache_control);
    route->cache_control[m] = malloc(len + 1);
    if (route->cache_control[m] == NULL) {
        log_error(ROUTE_OUT_OF_MEMORY);
        return 0;
    }
    memcpy(route->cache_control[m], cache_control, len + 1);

    return 1;
}

int route_set_websockets_handler(route_t* route, const char* method, void(*function)(void*), ratelimiter_t* ratelimiter) {
    const int m = route_ws_method_index(method);
    if (m == ROUTE_NONE) {
        route_drop_ratelimiter(route, ratelimiter);
        return 0;
    }

    if (route->handler[m]) {
        route_drop_ratelimiter(route, ratelimiter);
        return 1;
    }

    route->handler[m] = function;
    route_own_ratelimiter(route, ratelimiter);

    return 1;
}

void routes_free(route_t* route) {
    while (route != NULL) {
        route_t* route_next = route->next;

        route_param_t* param = route->param;
        while (param != NULL) {
            route_param_t* param_next = param->next;

            free(param->string);
            free(param);

            param = param_next;
        }

        if (route->location != NULL)
            pcre_free(route->location);

        for (int i = 0; i < 7; i++) {
            strtemplate_free(route->static_file[i]);
            free(route->cache_control[i]);
        }

        free(route->path);
        ratelimiter_free(route->ratelimiter);
        free(route);

        route = route_next;
    }
}

int route_compare_primitive(route_t* route, const char* path, size_t length) {
    if (route->path_length != length) return 0;

    for (size_t i = 0; i < length; i++)
        if (route->path[i] != path[i]) return 0;

    return 1;
}
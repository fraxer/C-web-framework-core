#ifndef __JSON__
#define __JSON__

#include <stddef.h>

#include "str.h"

#define JSON_ERROR_BUFFER_SIZE 256

typedef enum {
    JSON_UNDEFINED = 0,
    JSON_OBJECT,
    JSON_ARRAY,
    JSON_STRING,
    JSON_BOOL,
    JSON_NULL,
    JSON_LLONG,
    JSON_INT,
    JSON_UINT,
    JSON_DOUBLE
} jsontype_t;

typedef union {
    int _int;
    unsigned int _uint;
    long long _llong;
    double _double;
    char *string;
} jsonv_u;

struct jsondoc;

/**
 * JSON token description.
 */
typedef struct jsontok {
    jsontype_t type;
    int start;
    int end;
    int size;
    int parent;
    jsonv_u value;
    struct jsontok *child;
    struct jsontok *sibling;
    struct jsontok *last_sibling;
    struct jsondoc *doc;
} jsontok_t;

/**
 * JSON parser. Contains an array of token blocks available. Also stores
 * the string being parsed now and current position in that string.
 */
typedef struct {
    unsigned int dirty_pos; /* offset in the JSON string */
    unsigned int pos;
    int toksuper; /* superior token node, e.g. parent object or array */
    size_t string_len;
    const char *string;
    char *string_internal;
    struct jsondoc *doc;
} jsonparser_t;

typedef struct {
    int detached;
    str_t string;
} jsonstr_t;

/**
 * JSON document
 */
typedef struct jsondoc {
    int ok;
    char error[JSON_ERROR_BUFFER_SIZE];
    unsigned int toknext; // next token to allocate
    unsigned int tokens_count;
    jsonparser_t parser;
    jsonstr_t stringify;
    jsontok_t **tokens; // array of pointers on the tokens
} jsondoc_t;

typedef struct {
    int ok;
    int index;
    jsontype_t type;
    jsontok_t* key;
    jsontok_t* value;
    jsontok_t* parent;
} jsonit_t;

/**
 * Create JSON document over an array of tokens
 */
jsondoc_t* json_init();
jsondoc_t* json_create(const char*);

/**
 * Run JSON parser.
 * It parses a JSON data string into and array of tokens, each describing
 * a single JSON object.
 */
int json_parse(jsondoc_t*, const char*);

/**
 * Free internal memory
 */
void json_clear(jsondoc_t*);
void json_free(jsondoc_t*);
void json_token_reset(jsontok_t*);

jsontok_t* json_root(const jsondoc_t*);
int json_ok(const jsondoc_t*);
const char* json_error(const jsondoc_t*);

/**
 * Get values
 */
int json_bool(const jsontok_t*);
int json_int(const jsontok_t*);
double json_double(const jsontok_t*);
long long json_llong(const jsontok_t*);
const char *json_string(const jsontok_t*);
unsigned int json_uint(const jsontok_t*);

/**
 * Check value type in token
 */
int json_is_bool(const jsontok_t*);
int json_is_null(const jsontok_t*);
int json_is_string(const jsontok_t*);
int json_is_llong(const jsontok_t*);
int json_is_int(const jsontok_t*);
int json_is_uint(const jsontok_t*);
int json_is_double(const jsontok_t*);
int json_is_object(const jsontok_t*);
int json_is_array(const jsontok_t*);

/**
 * Create token with same type
 */
jsontok_t* json_create_bool(jsondoc_t*, int);
jsontok_t* json_create_null(jsondoc_t*);
jsontok_t* json_create_string(jsondoc_t*, const char *);
jsontok_t* json_create_llong(jsondoc_t*, long long);
jsontok_t* json_create_int(jsondoc_t*, int);
jsontok_t* json_create_uint(jsondoc_t*, unsigned int);
jsontok_t* json_create_double(jsondoc_t*, double);
jsontok_t* json_create_object(jsondoc_t*);
jsontok_t* json_create_array(jsondoc_t*);

/**
 * Actions on array
 */
int json_array_prepend(jsontok_t*, jsontok_t*);
int json_array_append(jsontok_t*, jsontok_t*);
int json_array_append_to(jsontok_t*, int, jsontok_t*);
int json_array_erase(jsontok_t*, int, int);
int json_array_clear(jsontok_t*);
int json_array_size(const jsontok_t*);
jsontok_t* json_array_get(const jsontok_t*, int);

/**
 * Actions on object
 */
int json_object_set(jsontok_t*, const char *, jsontok_t*);
jsontok_t* json_object_get(const jsontok_t*, const char *);
int json_object_remove(jsontok_t*, const char *);
int json_object_size(const jsontok_t*);
int json_object_clear(jsontok_t*);

/**
 * Change value of a token with type
 */
void json_token_set_bool(jsontok_t*, int);
void json_token_set_null(jsontok_t*);
void json_token_set_string(jsontok_t*, const char *);
void json_token_set_llong(jsontok_t*, long long);
void json_token_set_int(jsontok_t*, int);
void json_token_set_uint(jsontok_t*, unsigned int);
void json_token_set_double(jsontok_t*, double);
void json_token_set_object(jsontok_t*, jsontok_t*);
void json_token_set_array(jsontok_t*, jsontok_t*);

/**
 * Init iterator for array and object
 */
jsonit_t json_init_it(const jsontok_t*);
int json_end_it(const jsonit_t*);
const void* json_it_key(const jsonit_t*);
jsontok_t* json_it_value(const jsonit_t*);
jsonit_t json_next_it(jsonit_t*);
void json_it_erase(jsonit_t*);

/**
 * Convert json document with tokens to string
 */
const char* json_stringify(jsondoc_t*);
size_t json_stringify_size(jsondoc_t*);
char* json_stringify_detach(jsondoc_t*);
int json_copy(jsondoc_t*, jsondoc_t*);

#endif
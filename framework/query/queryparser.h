#ifndef QUERYPARSER_H
#define QUERYPARSER_H

#include <stddef.h>

/**
 * Query parser result codes
 */
typedef enum {
    QUERYPARSER_OK = 0,
    QUERYPARSER_ERROR = -1
} queryparser_result_t;

typedef struct http1_query {
    const char* key;
    const char* value;
    struct http1_query* next;
} http1_query_t;

/**
 * Callback function type for appending query to a collection
 *
 * @param context - User-defined context (e.g., parser or request object)
 * @param query - Query to append
 */
typedef void (*queryparser_append_fn)(void* context, http1_query_t* query);

/**
 * Parses a query string in the format: key1=value1&key2=value2&key3
 *
 * This function parses URL-encoded query parameters and creates a linked list
 * of http1_query_t structures. It handles:
 * - Key-value pairs separated by '=' and '&'
 * - Keys without values (e.g., "key3" becomes {key: "key3", value: ""})
 * - Fragment identifiers starting with '#' (stops parsing)
 * - URL decoding of keys and values
 *
 * @param string - The full string containing the query (may include parts before '?')
 * @param length - Total length of the string
 * @param start_pos - Position where query parsing should start (usually after '?')
 * @param context - User context to pass to append_fn
 * @param append_fn - Callback to append new query items
 * @param out_first_query - Output: pointer to first query in the list
 * @param out_last_query - Output: pointer to last query in the list
 * @return QUERYPARSER_OK on success, QUERYPARSER_ERROR on failure
 */
queryparser_result_t queryparser_parse(
    const char* string,
    size_t length,
    size_t start_pos,
    void* context,
    queryparser_append_fn append_fn,
    http1_query_t** out_first_query,
    http1_query_t** out_last_query
);

http1_query_t* query_create(const char* key, size_t key_length, const char* value, size_t value_length);
void query_free(http1_query_t* query);
void queries_free(http1_query_t* query);
char* query_stringify(http1_query_t* query);

#endif // QUERYPARSER_H

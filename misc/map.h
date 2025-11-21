#ifndef __MAP__
#define __MAP__

#include <stdlib.h>
#include <stdint.h>

// Red-Black Tree colors
typedef enum {
    MAP_RED = 0,
    MAP_BLACK = 1
} map_color_t;

// Forward declarations
typedef struct map_node map_node_t;
typedef struct map map_t;
typedef struct map_iterator map_iterator_t;

// Comparison function type
// Returns: < 0 if a < b, 0 if a == b, > 0 if a > b
typedef int (*map_compare_fn)(const void* a, const void* b);

// Optional functions for memory management
typedef void* (*map_copy_fn)(const void* data);
typedef void (*map_free_fn)(void* data);

// Red-Black Tree node
struct map_node {
    void* key;
    void* value;
    map_node_t* parent;
    map_node_t* left;
    map_node_t* right;
    map_color_t color;
};

// Map structure
struct map {
    map_node_t* root;
    map_node_t* nil;        // Sentinel node (black leaf)
    size_t size;
    map_compare_fn compare; // Key comparison function
    map_copy_fn key_copy;   // Optional key copy function
    map_free_fn key_free;   // Optional key free function
    map_copy_fn value_copy; // Optional value copy function
    map_free_fn value_free; // Optional value free function
};

// Iterator structure
struct map_iterator {
    map_t* map;
    map_node_t* node;
};

// Map creation and destruction
map_t* map_create(map_compare_fn compare);
map_t* map_create_ex(map_compare_fn compare,
                     map_copy_fn key_copy, map_free_fn key_free,
                     map_copy_fn value_copy, map_free_fn value_free);
void map_clear(map_t* map);
void map_free(map_t* map);

// Map operations
int map_insert(map_t* map, const void* key, void* value);
int map_insert_or_assign(map_t* map, const void* key, void* value);
void* map_find(map_t* map, const void* key);
map_node_t* map_find_node(map_t* map, const void* key);
int map_erase(map_t* map, const void* key);
int map_contains(map_t* map, const void* key);
size_t map_size(const map_t* map);
int map_empty(const map_t* map);

// Iterator operations
map_iterator_t map_begin(map_t* map);
map_iterator_t map_end(map_t* map);
map_iterator_t map_next(map_iterator_t it);
map_iterator_t map_prev(map_iterator_t it);
int map_iterator_valid(map_iterator_t it);
void* map_iterator_key(map_iterator_t it);
void* map_iterator_value(map_iterator_t it);

// Common comparison functions
int map_compare_int(const void* a, const void* b);
int map_compare_string(const void* a, const void* b);
int map_compare_ptr(const void* a, const void* b);

void* map_copy_string(const void* a);

// Helper macros for integer keys
#define map_create_int() map_create(map_compare_int)
#define map_create_string() map_create(map_compare_string)
#define map_create_ptr() map_create(map_compare_ptr)

#define map_insert_int(m, k, v) map_insert(m, (void*)(intptr_t)(k), v)
#define map_insert_or_assign_int(m, k, v) map_insert_or_assign(m, (void*)(intptr_t)(k), v)
#define map_find_int(m, k) map_find(m, (void*)(intptr_t)(k))
#define map_erase_int(m, k) map_erase(m, (void*)(intptr_t)(k))
#define map_contains_int(m, k) map_contains(m, (void*)(intptr_t)(k))

#endif

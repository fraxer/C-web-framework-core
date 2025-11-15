#ifndef __HASHMAP__
#define __HASHMAP__

#include <stdlib.h>
#include <stdint.h>

// Forward declarations
typedef struct hashmap_entry hashmap_entry_t;
typedef struct hashmap hashmap_t;
typedef struct hashmap_iterator hashmap_iterator_t;

// Hash function type
// Returns: hash value for the key
typedef uint64_t (*hashmap_hash_fn)(const void* key);

// Comparison function type for keys
// Returns: 0 if equal, non-zero otherwise
typedef int (*hashmap_equals_fn)(const void* a, const void* b);

// Optional functions for memory management
typedef void* (*hashmap_copy_fn)(const void* data);
typedef void (*hashmap_free_fn)(void* data);

// Hash table entry (linked list node for collision resolution)
struct hashmap_entry {
    void* key;
    void* value;
    uint64_t hash;
    hashmap_entry_t* next;
};

// Hash map structure
struct hashmap {
    hashmap_entry_t** buckets;  // Array of bucket chains
    size_t capacity;             // Number of buckets
    size_t size;                 // Number of entries
    float load_factor;           // Threshold for resizing (default 0.75)
    hashmap_hash_fn hash;        // Hash function
    hashmap_equals_fn equals;    // Key equality function
    hashmap_copy_fn key_copy;    // Optional key copy function
    hashmap_free_fn key_free;    // Optional key free function
    hashmap_copy_fn value_copy;  // Optional value copy function
    hashmap_free_fn value_free;  // Optional value free function
};

// Iterator structure
struct hashmap_iterator {
    hashmap_t* map;
    size_t bucket_index;
    hashmap_entry_t* entry;
};

// HashMap creation and destruction
hashmap_t* hashmap_create(hashmap_hash_fn hash, hashmap_equals_fn equals);
hashmap_t* hashmap_create_ex(hashmap_hash_fn hash, hashmap_equals_fn equals,
                              size_t initial_capacity, float load_factor,
                              hashmap_copy_fn key_copy, hashmap_free_fn key_free,
                              hashmap_copy_fn value_copy, hashmap_free_fn value_free);
void hashmap_clear(hashmap_t* map);
void hashmap_free(hashmap_t* map);

// HashMap operations
int hashmap_insert(hashmap_t* map, void* key, void* value);
int hashmap_insert_or_assign(hashmap_t* map, void* key, void* value);
void* hashmap_find(hashmap_t* map, const void* key);
hashmap_entry_t* hashmap_find_entry(hashmap_t* map, const void* key);
int hashmap_erase(hashmap_t* map, const void* key);
int hashmap_contains(hashmap_t* map, const void* key);
size_t hashmap_size(const hashmap_t* map);
int hashmap_empty(const hashmap_t* map);
float hashmap_load_factor_current(const hashmap_t* map);

// Manual rehashing
int hashmap_rehash(hashmap_t* map, size_t new_capacity);
int hashmap_reserve(hashmap_t* map, size_t count);

// Iterator operations
hashmap_iterator_t hashmap_begin(hashmap_t* map);
hashmap_iterator_t hashmap_end(hashmap_t* map);
hashmap_iterator_t hashmap_next(hashmap_iterator_t it);
int hashmap_iterator_valid(hashmap_iterator_t it);
void* hashmap_iterator_key(hashmap_iterator_t it);
void* hashmap_iterator_value(hashmap_iterator_t it);

// Common hash functions
uint64_t hashmap_hash_int(const void* key);
uint64_t hashmap_hash_string(const void* key);
uint64_t hashmap_hash_ptr(const void* key);

// Common equality functions
int hashmap_equals_int(const void* a, const void* b);
int hashmap_equals_string(const void* a, const void* b);
int hashmap_equals_ptr(const void* a, const void* b);

// Helper macros for common types
#define hashmap_create_int() \
    hashmap_create(hashmap_hash_int, hashmap_equals_int)

#define hashmap_create_string() \
    hashmap_create(hashmap_hash_string, hashmap_equals_string)

#define hashmap_create_ptr() \
    hashmap_create(hashmap_hash_ptr, hashmap_equals_ptr)

#define hashmap_insert_int(m, k, v) \
    hashmap_insert(m, (void*)(intptr_t)(k), v)

#define hashmap_insert_or_assign_int(m, k, v) \
    hashmap_insert_or_assign(m, (void*)(intptr_t)(k), v)

#define hashmap_find_int(m, k) \
    hashmap_find(m, (void*)(intptr_t)(k))

#define hashmap_erase_int(m, k) \
    hashmap_erase(m, (void*)(intptr_t)(k))

#define hashmap_contains_int(m, k) \
    hashmap_contains(m, (void*)(intptr_t)(k))

// Iteration helper macro
#define hashmap_foreach(map, it) \
    for (hashmap_iterator_t it = hashmap_begin(map); \
         hashmap_iterator_valid(it); \
         it = hashmap_next(it))

#endif

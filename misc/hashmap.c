#include <string.h>
#include <stdio.h>
#include "hashmap.h"

// Default values
#define HASHMAP_DEFAULT_CAPACITY 16
#define HASHMAP_DEFAULT_LOAD_FACTOR 0.75f
#define HASHMAP_MAX_LOAD_FACTOR 1.0f

// Internal helper functions
static hashmap_entry_t* __hashmap_create_entry(hashmap_t* map, void* key, void* value, uint64_t hash);
static void __hashmap_free_entry(hashmap_t* map, hashmap_entry_t* entry);
static void __hashmap_free_bucket_chain(hashmap_t* map, hashmap_entry_t* entry);
static int __hashmap_resize(hashmap_t* map, size_t new_capacity);
static size_t __hashmap_bucket_index(uint64_t hash, size_t capacity);

// Create a new hashmap with hash and equals functions
hashmap_t* hashmap_create(hashmap_hash_fn hash, hashmap_equals_fn equals) {
    return hashmap_create_ex(hash, equals, HASHMAP_DEFAULT_CAPACITY,
                            HASHMAP_DEFAULT_LOAD_FACTOR, NULL, NULL, NULL, NULL);
}

// Create a new hashmap with extended options
hashmap_t* hashmap_create_ex(hashmap_hash_fn hash, hashmap_equals_fn equals,
                              size_t initial_capacity, float load_factor,
                              hashmap_copy_fn key_copy, hashmap_free_fn key_free,
                              hashmap_copy_fn value_copy, hashmap_free_fn value_free) {
    if (hash == NULL || equals == NULL)
        return NULL;

    if (initial_capacity == 0)
        initial_capacity = HASHMAP_DEFAULT_CAPACITY;

    if (load_factor <= 0.0f || load_factor > HASHMAP_MAX_LOAD_FACTOR)
        load_factor = HASHMAP_DEFAULT_LOAD_FACTOR;

    hashmap_t* map = malloc(sizeof(hashmap_t));
    if (map == NULL)
        return NULL;

    map->buckets = calloc(initial_capacity, sizeof(hashmap_entry_t*));
    if (map->buckets == NULL) {
        free(map);
        return NULL;
    }

    map->capacity = initial_capacity;
    map->size = 0;
    map->load_factor = load_factor;
    map->hash = hash;
    map->equals = equals;
    map->key_copy = key_copy;
    map->key_free = key_free;
    map->value_copy = value_copy;
    map->value_free = value_free;

    return map;
}

// Clear all entries from the hashmap
void hashmap_clear(hashmap_t* map) {
    if (map == NULL)
        return;

    for (size_t i = 0; i < map->capacity; i++) {
        if (map->buckets[i] != NULL) {
            __hashmap_free_bucket_chain(map, map->buckets[i]);
            map->buckets[i] = NULL;
        }
    }
    map->size = 0;
}

// Free the hashmap and all its entries
void hashmap_free(hashmap_t* map) {
    if (map == NULL)
        return;

    hashmap_clear(map);
    free(map->buckets);
    free(map);
}

// Insert a key-value pair (fails if key exists)
int hashmap_insert(hashmap_t* map, void* key, void* value) {
    if (map == NULL)
        return -1;

    // Check if we need to resize
    if ((float)(map->size + 1) / map->capacity > map->load_factor) {
        if (__hashmap_resize(map, map->capacity * 2) != 0)
            return -1;
    }

    uint64_t hash = map->hash(key);
    size_t index = __hashmap_bucket_index(hash, map->capacity);

    // Check if key already exists in the chain
    hashmap_entry_t* current = map->buckets[index];
    while (current != NULL) {
        if (current->hash == hash && map->equals(current->key, key) == 0)
            return 0; // Key already exists
        current = current->next;
    }

    // Create new entry and insert at the beginning of the chain
    hashmap_entry_t* entry = __hashmap_create_entry(map, key, value, hash);
    if (entry == NULL)
        return -1;

    entry->next = map->buckets[index];
    map->buckets[index] = entry;
    map->size++;

    return 1;
}

// Insert or update a key-value pair
int hashmap_insert_or_assign(hashmap_t* map, void* key, void* value) {
    if (map == NULL)
        return -1;

    uint64_t hash = map->hash(key);
    size_t index = __hashmap_bucket_index(hash, map->capacity);

    // Check if key already exists in the chain
    hashmap_entry_t* current = map->buckets[index];
    while (current != NULL) {
        if (current->hash == hash && map->equals(current->key, key) == 0) {
            // Update existing value
            if (map->value_free != NULL)
                map->value_free(current->value);

            if (map->value_copy != NULL)
                current->value = map->value_copy(value);
            else
                current->value = value;

            return 2; // Updated existing
        }
        current = current->next;
    }

    // Insert new entry
    return hashmap_insert(map, key, value);
}

// Find value by key
void* hashmap_find(hashmap_t* map, const void* key) {
    hashmap_entry_t* entry = hashmap_find_entry(map, key);
    if (entry == NULL)
        return NULL;
    return entry->value;
}

// Find entry by key
hashmap_entry_t* hashmap_find_entry(hashmap_t* map, const void* key) {
    if (map == NULL)
        return NULL;

    uint64_t hash = map->hash(key);
    size_t index = __hashmap_bucket_index(hash, map->capacity);

    hashmap_entry_t* current = map->buckets[index];
    while (current != NULL) {
        if (current->hash == hash && map->equals(current->key, key) == 0)
            return current;
        current = current->next;
    }

    return NULL;
}

// Erase an entry by key
int hashmap_erase(hashmap_t* map, const void* key) {
    if (map == NULL)
        return 0;

    uint64_t hash = map->hash(key);
    size_t index = __hashmap_bucket_index(hash, map->capacity);

    hashmap_entry_t* current = map->buckets[index];
    hashmap_entry_t* prev = NULL;

    while (current != NULL) {
        if (current->hash == hash && map->equals(current->key, key) == 0) {
            // Remove from chain
            if (prev == NULL)
                map->buckets[index] = current->next;
            else
                prev->next = current->next;

            __hashmap_free_entry(map, current);
            map->size--;
            return 1;
        }
        prev = current;
        current = current->next;
    }

    return 0; // Not found
}

// Check if key exists
int hashmap_contains(hashmap_t* map, const void* key) {
    return hashmap_find_entry(map, key) != NULL;
}

// Get hashmap size
size_t hashmap_size(const hashmap_t* map) {
    if (map == NULL)
        return 0;
    return map->size;
}

// Check if hashmap is empty
int hashmap_empty(const hashmap_t* map) {
    return hashmap_size(map) == 0;
}

// Get current load factor
float hashmap_load_factor_current(const hashmap_t* map) {
    if (map == NULL || map->capacity == 0)
        return 0.0f;
    return (float)map->size / map->capacity;
}

// Rehash with new capacity
int hashmap_rehash(hashmap_t* map, size_t new_capacity) {
    if (map == NULL || new_capacity == 0)
        return -1;

    return __hashmap_resize(map, new_capacity);
}

// Reserve space for at least count elements
int hashmap_reserve(hashmap_t* map, size_t count) {
    if (map == NULL)
        return -1;

    size_t required_capacity = (size_t)((float)count / map->load_factor) + 1;
    if (required_capacity > map->capacity)
        return __hashmap_resize(map, required_capacity);

    return 0;
}

// Iterator operations
hashmap_iterator_t hashmap_begin(hashmap_t* map) {
    hashmap_iterator_t it;
    it.map = map;
    it.bucket_index = 0;
    it.entry = NULL;

    if (map == NULL || map->size == 0)
        return it;

    // Find first non-empty bucket
    for (size_t i = 0; i < map->capacity; i++) {
        if (map->buckets[i] != NULL) {
            it.bucket_index = i;
            it.entry = map->buckets[i];
            break;
        }
    }

    return it;
}

hashmap_iterator_t hashmap_end(hashmap_t* map) {
    hashmap_iterator_t it;
    it.map = map;
    it.bucket_index = map ? map->capacity : 0;
    it.entry = NULL;
    return it;
}

hashmap_iterator_t hashmap_next(hashmap_iterator_t it) {
    if (it.map == NULL || it.entry == NULL)
        return it;

    // Try next entry in the same bucket
    if (it.entry->next != NULL) {
        it.entry = it.entry->next;
        return it;
    }

    // Move to next non-empty bucket
    it.bucket_index++;
    it.entry = NULL;

    for (size_t i = it.bucket_index; i < it.map->capacity; i++) {
        if (it.map->buckets[i] != NULL) {
            it.bucket_index = i;
            it.entry = it.map->buckets[i];
            break;
        }
    }

    return it;
}

int hashmap_iterator_valid(hashmap_iterator_t it) {
    return it.map != NULL && it.entry != NULL;
}

void* hashmap_iterator_key(hashmap_iterator_t it) {
    if (!hashmap_iterator_valid(it))
        return NULL;
    return it.entry->key;
}

void* hashmap_iterator_value(hashmap_iterator_t it) {
    if (!hashmap_iterator_valid(it))
        return NULL;
    return it.entry->value;
}

// Hash functions

// FNV-1a hash for integers
uint64_t hashmap_hash_int(const void* key) {
    intptr_t k = (intptr_t)key;
    uint64_t hash = 14695981039346656037ULL;

    for (size_t i = 0; i < sizeof(intptr_t); i++) {
        hash ^= (k & 0xFF);
        hash *= 1099511628211ULL;
        k >>= 8;
    }

    return hash;
}

// FNV-1a hash for strings
uint64_t hashmap_hash_string(const void* key) {
    const char* str = (const char*)key;
    uint64_t hash = 14695981039346656037ULL;

    while (*str) {
        hash ^= (uint64_t)*str++;
        hash *= 1099511628211ULL;
    }

    return hash;
}

// Simple pointer hash
uint64_t hashmap_hash_ptr(const void* key) {
    uintptr_t k = (uintptr_t)key;
    // MurmurHash3 finalizer
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

// Equality functions

int hashmap_equals_int(const void* a, const void* b) {
    return (intptr_t)a == (intptr_t)b ? 0 : 1;
}

int hashmap_equals_string(const void* a, const void* b) {
    return strcmp((const char*)a, (const char*)b);
}

int hashmap_equals_ptr(const void* a, const void* b) {
    return a == b ? 0 : 1;
}

// Internal helper functions

static hashmap_entry_t* __hashmap_create_entry(hashmap_t* map, void* key, void* value, uint64_t hash) {
    hashmap_entry_t* entry = malloc(sizeof(hashmap_entry_t));
    if (entry == NULL)
        return NULL;

    if (map->key_copy != NULL)
        entry->key = map->key_copy(key);
    else
        entry->key = key;

    if (map->value_copy != NULL)
        entry->value = map->value_copy(value);
    else
        entry->value = value;

    entry->hash = hash;
    entry->next = NULL;

    return entry;
}

static void __hashmap_free_entry(hashmap_t* map, hashmap_entry_t* entry) {
    if (entry == NULL)
        return;

    if (map->key_free != NULL)
        map->key_free(entry->key);

    if (map->value_free != NULL)
        map->value_free(entry->value);

    free(entry);
}

static void __hashmap_free_bucket_chain(hashmap_t* map, hashmap_entry_t* entry) {
    while (entry != NULL) {
        hashmap_entry_t* next = entry->next;
        __hashmap_free_entry(map, entry);
        entry = next;
    }
}

static int __hashmap_resize(hashmap_t* map, size_t new_capacity) {
    if (new_capacity < map->size)
        return -1;

    // Allocate new buckets
    hashmap_entry_t** new_buckets = calloc(new_capacity, sizeof(hashmap_entry_t*));
    if (new_buckets == NULL)
        return -1;

    // Rehash all entries
    for (size_t i = 0; i < map->capacity; i++) {
        hashmap_entry_t* entry = map->buckets[i];
        while (entry != NULL) {
            hashmap_entry_t* next = entry->next;

            // Reinsert into new bucket array
            size_t new_index = __hashmap_bucket_index(entry->hash, new_capacity);
            entry->next = new_buckets[new_index];
            new_buckets[new_index] = entry;

            entry = next;
        }
    }

    // Replace old buckets with new ones
    free(map->buckets);
    map->buckets = new_buckets;
    map->capacity = new_capacity;

    return 0;
}

static size_t __hashmap_bucket_index(uint64_t hash, size_t capacity) {
    return hash % capacity;
}

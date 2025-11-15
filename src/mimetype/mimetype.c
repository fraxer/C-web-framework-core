#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "mimetype.h"

// Helper function to free a nested map (for table_type values)
static void __mimetype_free_extensions_map(void* extensions_map) {
    if (extensions_map != NULL) {
        map_free((map_t*)extensions_map);
    }
}

// Helper function to create a new extensions set (inner map)
static map_t* __mimetype_create_extensions_set(void) {
    // Create a map to act as a set of extensions
    // key = extension (string), value = extension (string) - used as a set
    return map_create_ex(
        map_compare_string,
        map_copy_string,
        free,
        map_copy_string,
        free
    );
}

mimetype_t* mimetype_create(void) {
    mimetype_t* mimetype = malloc(sizeof(mimetype_t));
    if (mimetype == NULL) {
        log_error("mimetype_create: failed to allocate mimetype structure\n");
        return NULL;
    }

    // Create map for extension -> mimetype lookups (simple string -> string)
    mimetype->table_ext = map_create_ex(
        map_compare_string,
        map_copy_string,
        free,
        map_copy_string,
        free
    );

    if (mimetype->table_ext == NULL) {
        log_error("mimetype_create: failed to create table_ext\n");
        free(mimetype);
        return NULL;
    }

    // Create map for mimetype -> extensions set (string -> map_t*)
    // Note: values are map_t* pointers, we don't copy them, just store pointers
    mimetype->table_type = map_create_ex(
        map_compare_string,
        map_copy_string,               // copy key (mimetype)
        free,                          // free key
        NULL,                          // don't copy value (map_t*)
        __mimetype_free_extensions_map // free value (map_t*)
    );

    if (mimetype->table_type == NULL) {
        log_error("mimetype_create: failed to create table_type\n");
        map_free(mimetype->table_ext);
        free(mimetype);
        return NULL;
    }

    return mimetype;
}

void mimetype_destroy(mimetype_t* mimetype) {
    if (mimetype == NULL) return;

    // map_free will automatically free all keys and values using the registered free functions
    if (mimetype->table_ext != NULL) {
        map_free(mimetype->table_ext);
    }

    if (mimetype->table_type != NULL) {
        map_free(mimetype->table_type);
    }

    free(mimetype);
}

int mimetype_add(mimetype_t* mimetype, mimetype_table_type_t table_type, const char* key, const char* value) {
    if (mimetype == NULL) {
        log_error("mimetype_add: mimetype is NULL\n");
        return 0;
    }

    if (key == NULL || value == NULL) {
        log_error("mimetype_add: key or value is NULL\n");
        return 0;
    }

    if (table_type == MIMETYPE_TABLE_TYPE) {
        // Adding to table_type: mimetype -> extensions
        // key = mimetype, value = extension

        // Find or create the extensions set for this mimetype
        map_t* extensions_set = (map_t*)map_find(mimetype->table_type, key);

        if (extensions_set == NULL) {
            // Create new extensions set for this mimetype
            extensions_set = __mimetype_create_extensions_set();
            if (extensions_set == NULL) {
                log_error("mimetype_add: failed to create extensions set for '%s'\n", key);
                return 0;
            }

            // Insert the new set into table_type
            if (map_insert(mimetype->table_type, key, extensions_set) == 0) {
                log_error("mimetype_add: failed to insert mimetype '%s'\n", key);
                map_free(extensions_set);
                return 0;
            }
        }

        // Add extension to the set (duplicates are OK, map_insert will ignore them)
        map_insert(extensions_set, value, (void*)value);

    } else if (table_type == MIMETYPE_TABLE_EXT) {
        // Adding to table_ext: extension -> mimetype
        // key = extension, value = mimetype

        // Keep first value for duplicate keys
        map_insert(mimetype->table_ext, key, (void*)value);

    } else {
        log_error("mimetype_add: invalid table_type %d\n", table_type);
        return 0;
    }

    return 1;
}

const char* mimetype_find_ext(mimetype_t* mimetype, const char* key) {
    if (mimetype == NULL) return NULL;
    if (key == NULL) return NULL;

    // Find in table_type (mimetype -> extensions set)
    map_t* extensions_set = (map_t*)map_find(mimetype->table_type, key);
    if (extensions_set == NULL) return NULL;

    // Return the first extension from the set
    map_iterator_t it = map_begin(extensions_set);
    if (!map_iterator_valid(it)) return NULL;

    return (const char*)map_iterator_key(it);
}

const char* mimetype_find_type(mimetype_t* mimetype, const char* key) {
    if (mimetype == NULL) return NULL;
    if (key == NULL) return NULL;

    // Find in table_ext (extension -> mimetype)
    const char* result = (const char*)map_find(mimetype->table_ext, key);
    return result;
}

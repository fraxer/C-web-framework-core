#ifndef __MIMETYPE__
#define __MIMETYPE__

#include <stdlib.h>
#include "map.h"

typedef enum {
    MIMETYPE_TABLE_TYPE = 0,  // mimetype -> extension mapping
    MIMETYPE_TABLE_EXT = 1    // extension -> mimetype mapping
} mimetype_table_type_t;

typedef struct {
    map_t* table_ext;   // extension -> mimetype (string -> string)
    map_t* table_type;  // mimetype -> set of extensions (string -> map_t*)
} mimetype_t;

mimetype_t* mimetype_create(void);
void mimetype_destroy(mimetype_t* mimetype);
int mimetype_add(mimetype_t* mimetype, mimetype_table_type_t table_type, const char* key, const char* value);
const char* mimetype_find_ext(mimetype_t* mimetype, const char* key);
const char* mimetype_find_type(mimetype_t* mimetype, const char* key);

#endif

#ifndef __MSCHEMA__
#define __MSCHEMA__

#include "mfield.h"

/* ---------------------------------------------------------------------------
 * mschema.h — schema/record layer (R1)
 *
 * Splits the immutable, compile-time schema (shared via a single `static const`
 * per model type) from the per-instance row data. Replaces the legacy
 * per-instance vtable of 5 function pointers + inline table/primary_key arrays
 * with one `const mschema_t*`, and lets each cell's name point at the schema
 * instead of carrying a 128-byte inline copy.
 * ------------------------------------------------------------------------- */
typedef struct mcolumn {
    const char* name;
    mtype_e type;
    unsigned is_primary : 1;
    unsigned has_default : 1;       /* DB provides a default: cell starts skipped on INSERT until set */
    unsigned nullable : 1;          /* numeric/temporal column starts NULL (mirrors mfield_x(name, NULL)) */
    unsigned auto_increment : 1;    /* SERIAL/AUTO_INCREMENT PK: generated key read back on model_create */
    const char* const* enum_values; /* MODEL_ENUM only, else NULL */
    int enum_count;
} mcolumn_t;

typedef struct mschema {
    const char* table;
    const mcolumn_t* columns;
    int columns_count;
    const int* primary_keys;        /* indexes into columns */
    int primary_keys_count;
} mschema_t;

typedef struct model {
    const mschema_t* schema;
    mfield_t* fields;               /* columns_count cells, heap-allocated */
    const char* table;              /* effective table; defaults to schema->table, per-instance overridable */
} model_t;

/* Initialize an embedded record: allocates and default-inits the cell array
   from the schema. The record must be the first member of the concrete model
   struct, so a concrete pointer can be passed wherever `void* arg` is taken. */
int model_init(model_t* record, const mschema_t* schema);
/* Cell accessor by column index (use generated column-index enums). */
mfield_t* model_field(void* arg, int index);

#endif /* __MSCHEMA__ */

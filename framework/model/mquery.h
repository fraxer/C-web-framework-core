#ifndef __MQUERY__
#define __MQUERY__

#include "mschema.h"

/* ---------------------------------------------------------------------------
 * mquery.h — typed query builder (R4)
 *
 * A compact, type-safe WHERE/ORDER/LIMIT/OFFSET builder that emits a fully
 * parameterized query (positional $N + an ordered bind array, like R2). It
 * replaces the hand-written SQL that leaked out of the typed path for ranges,
 * IN, LIKE, ordering and pagination. v1 joins conditions with AND only; OR,
 * grouping and JOIN stay on model_one/list with explicit SQL.
 *
 * Identifiers (table, column names) come from the compile-time schema by index
 * and are escaped; condition values are always bound, never interpolated.
 * ------------------------------------------------------------------------- */
typedef enum {
    MOP_EQ = 0,    // Equal
    MOP_NE,        // Not equal
    MOP_LT,        // Less than
    MOP_LE,        // Less than or equal
    MOP_GT,        // Greater than
    MOP_GE,        // Greater than or equal
    MOP_IN,        // IN
    MOP_LIKE,      // LIKE
    MOP_IS_NULL,   // IS NULL
    MOP_NOT_NULL   // IS NOT NULL
} mop_e;

typedef struct mcond {
    int column;            /* index into schema->columns (use generated *_COL_* enums) */
    mop_e op;              /* condition operator */
    mfield_t* value;       /* bound value; for MOP_IN points to value_count cells */
    int value_count;       /* MOP_IN: number of cells in `value`; ignored otherwise */
} mcond_t;

typedef enum { MORDER_ASC = 0, MORDER_DESC } morder_e;

typedef struct mquery {
    const mcond_t* conds;
    int conds_count;       /* conditions joined with AND; 0 = no WHERE */
    int order_column;      /* index into schema->columns; <0 = no ORDER BY */
    morder_e order_dir;
    int limit;             /* <0 = no LIMIT */
    int offset;            /* <0 = no OFFSET */
} mquery_t;

void* model_find_one(const char* dbid, void*(create_instance)(void), const mquery_t* query);
array_t* model_find_list(const char* dbid, void*(create_instance)(void), const mquery_t* query);

#endif /* __MQUERY__ */

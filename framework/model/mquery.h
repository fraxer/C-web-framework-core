#ifndef __MQUERY__
#define __MQUERY__

#include "mschema.h"

/* ---------------------------------------------------------------------------
 * mquery.h — typed query builder (R4)
 *
 * A compact, type-safe WHERE/ORDER/LIMIT/OFFSET builder that emits a fully
 * parameterized query (positional $N + an ordered bind array, like R2). It
 * replaces the hand-written SQL that leaked out of the typed path for ranges,
 * IN, LIKE, ordering and pagination.
 *
 * v2 adds OR and grouping: top-level conditions join via `mquery_t.combine`
 * (AND by default), and an `MOP_GROUP` condition wraps a sub-expression
 * rendered in parentheses with its own combinator, so `(a AND b) OR c` is
 * expressible. JOIN stays on model_one/list with explicit SQL.
 *
 * Identifiers (table, column names) come from the compile-time schema by index
 * and are escaped; condition values are always bound, never interpolated.
 * ------------------------------------------------------------------------- */

/* How a sequence of conditions is joined. 0 = AND, so existing mquery_t
   initializers that omit `combine` keep the historical AND semantics. */
typedef enum { MCOMBINE_AND = 0, MCOMBINE_OR } mcombine_e;

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
    MOP_NOT_NULL,  // IS NOT NULL
    MOP_GROUP      // Parenthesized sub-expression: see `group` / `group_count` / `group_combine`
} mop_e;

typedef struct mcond {
    int column;            /* index into schema->columns (use generated *_COL_* enums) */
    mop_e op;              /* condition operator */
    mfield_t* value;       /* bound value; for MOP_IN points to value_count cells */
    int value_count;       /* MOP_IN: number of cells in `value`; ignored otherwise */
    const struct mcond* group; /* MOP_GROUP only: sub-conditions rendered inside parentheses */
    int group_count;       /* MOP_GROUP only: number of entries in `group` */
    mcombine_e group_combine; /* MOP_GROUP only: how `group` entries join (AND/OR) */
} mcond_t;

typedef enum { MORDER_ASC = 0, MORDER_DESC } morder_e;

typedef struct mquery {
    const mcond_t* conds;
    int conds_count;       /* top-level conditions; 0 = no WHERE */
    mcombine_e combine;    /* how top-level conditions join (AND by default) */
    int order_column;      /* index into schema->columns; <0 = no ORDER BY */
    morder_e order_dir;
    int limit;             /* <0 = no LIMIT */
    int offset;            /* <0 = no OFFSET */
} mquery_t;

void* model_find_one(const char* dbid, void*(create_instance)(void), const mquery_t* query);
array_t* model_find_list(const char* dbid, void*(create_instance)(void), const mquery_t* query);

#endif /* __MQUERY__ */

#ifndef __DBRESULT_VIEW_INTERNAL__
#define __DBRESULT_VIEW_INTERNAL__

#include "dbresult.h"

/* Driver callbacks and owners stay private; no existing public layout changes.
 * Callbacks are immutable, with static lifetime. Each owner must remain valid
 * independently of its connection. The driver supplies validated dimensions.
 */
typedef struct {
    const char* (*col_name)(const void* owner, int col);
    void (*cell)(const void* owner, int row, int col, const char** value, size_t* length);
    void (*free)(void* owner);
} dbresult_view_ops_t;

dbresult_view_t* dbresult_view_create(void);
/* Ownership transfers only on success. No allocations/copies per cell. */
int dbresult_view_append(dbresult_view_t*, void* owner,
                         const dbresult_view_ops_t*, int rows, int cols);
void dbresult_view_set_ok(dbresult_view_t*);
/* First error wins. Copies text before the driver clears the source. */
void dbresult_view_set_error(dbresult_view_t*, const char*);

#endif

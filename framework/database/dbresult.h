#ifndef __DBRESULT__
#define __DBRESULT__

#include "database.h"

/* Read-only result, separate from the mutable materialized dbresult_t API.
 * It owns each driver's result until dbresult_view_free(). Returned names and
 * values must not be changed or freed; they survive cursor movement and later
 * queries/connection closure. Concurrent reads after construction are allowed,
 * but cursor changes and destruction require external synchronization.
 */
typedef struct dbresult_view dbresult_view_t;

int dbresult_view_ok(const dbresult_view_t*);
const char* dbresult_view_error(const dbresult_view_t*);
int dbresult_view_rows(const dbresult_view_t*);
int dbresult_view_cols(const dbresult_view_t*);
const char* dbresult_view_col_name(const dbresult_view_t*, int col);
/* Returns 1 for a valid cell, including SQL NULL (*value=NULL, *length=0).
 * Empty strings have a non-NULL value and length 0. Invalid arguments/indices
 * return 0 and reset any supplied outputs to NULL/0; no cursor is changed.
 * Length is the driver's byte length, never inferred using strlen().
 */
int dbresult_view_cell(const dbresult_view_t*, int row, int col,
                       const char** value, size_t* length);
int dbresult_view_query_first(dbresult_view_t*);
int dbresult_view_query_next(dbresult_view_t*);
void dbresult_view_free(dbresult_view_t*);

dbresult_t* dbresult_create(void);

dbresultquery_t* dbresult_query_create(int, int);
void dbresult_query_free(dbresultquery_t*);

int dbresult_cell_create(db_table_cell_t*, const char*, size_t);

void dbresult_query_value_insert(dbresultquery_t*, const char*, size_t, int, int);

void dbresult_query_field_insert(dbresultquery_t*, const char*, int);

int dbresult_ok(dbresult_t*);

// Driver error text for the last failed query, or NULL when ok/unavailable.
const char* dbresult_error(dbresult_t*);
// Store (copy) a driver error message; replaces any previous text.
void dbresult_set_error(dbresult_t*, const char*);

// Last generated auto-increment / identity key, or 0 when unavailable.
long long dbresult_insert_id(dbresult_t*);

void dbresult_free(dbresult_t*);

int dbresult_row_next(dbresult_t*);

int dbresult_col_next(dbresult_t*);

int dbresult_row_set(dbresult_t*, int);

int dbresult_col_set(dbresult_t*, int);

dbresultquery_t* dbresult_query_next(dbresult_t*);

int dbresult_query_rows(dbresult_t*);

int dbresult_query_cols(dbresult_t*);

// Name of result column `col` (the field header), or NULL if out of range /
// when the result has no field headers. Wraps the driver-specific header
// layout so callers need not reach into dbresult internals.
const char* dbresult_col_name(dbresult_t*, int col);

db_table_cell_t* dbresult_field(dbresult_t*, const char*);

db_table_cell_t* dbresult_cell(dbresult_t*, int, int);

int dbresult_query_first(dbresult_t*);

int dbresult_row_first(dbresult_t*);

int dbresult_col_first(dbresult_t*);

#endif

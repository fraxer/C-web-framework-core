#include <stdlib.h>
#include <string.h>

#include "dbresult_view_internal.h"

typedef struct dbresult_view_query {
    void* owner;
    const dbresult_view_ops_t* ops;
    int rows;
    int cols;
    struct dbresult_view_query* next;
} dbresult_view_query_t;

struct dbresult_view {
    int ok;
    int failed;
    char* error;
    dbresult_view_query_t* first;
    dbresult_view_query_t* last;
    dbresult_view_query_t* current;
};

dbresult_view_t* dbresult_view_create(void) {
    return calloc(1, sizeof(dbresult_view_t));
}

int dbresult_view_append(dbresult_view_t* view, void* owner,
                         const dbresult_view_ops_t* ops, int rows, int cols) {
    if (!view || view->failed || !owner || !ops || !ops->col_name ||
        !ops->cell || !ops->free || rows < 0 || cols < 0) return 0;
    dbresult_view_query_t* query = calloc(1, sizeof(*query));
    if (!query) return 0;
    query->owner = owner;
    query->ops = ops;
    query->rows = rows;
    query->cols = cols;
    if (view->last) view->last->next = query;
    else view->first = view->current = query;
    view->last = query;
    return 1;
}

void dbresult_view_set_ok(dbresult_view_t* view) {
    if (view && !view->failed) view->ok = 1;
}

void dbresult_view_set_error(dbresult_view_t* view, const char* error) {
    if (!view || view->failed) return;
    view->ok = 0;
    view->failed = 1;
    view->error = strdup(error && *error ? error : "Database result view failed");
}

int dbresult_view_ok(const dbresult_view_t* view) {
    return view && view->ok;
}

const char* dbresult_view_error(const dbresult_view_t* view) {
    if (!view || !view->failed) return NULL;
    return view->error ? view->error : "Out of memory";
}

int dbresult_view_rows(const dbresult_view_t* view) {
    return view && view->current ? view->current->rows : 0;
}

int dbresult_view_cols(const dbresult_view_t* view) {
    return view && view->current ? view->current->cols : 0;
}

const char* dbresult_view_col_name(const dbresult_view_t* view, int col) {
    if (!view || !view->current || col < 0 || col >= view->current->cols) return NULL;
    return view->current->ops->col_name(view->current->owner, col);
}

int dbresult_view_cell(const dbresult_view_t* view, int row, int col,
                       const char** value, size_t* length) {
    if (value) *value = NULL;
    if (length) *length = 0;
    if (!value || !length || !view || !view->current || row < 0 || col < 0 ||
        row >= view->current->rows || col >= view->current->cols) return 0;
    view->current->ops->cell(view->current->owner, row, col, value, length);
    return 1;
}

int dbresult_view_query_first(dbresult_view_t* view) {
    if (!view || !view->first) return 0;
    view->current = view->first;
    return 1;
}

int dbresult_view_query_next(dbresult_view_t* view) {
    if (!view || !view->current || !view->current->next) return 0;
    view->current = view->current->next;
    return 1;
}

void dbresult_view_free(dbresult_view_t* view) {
    if (!view) return;
    dbresult_view_query_t* query = view->first;
    while (query) {
        dbresult_view_query_t* next = query->next;
        query->ops->free(query->owner);
        free(query);
        query = next;
    }
    free(view->error);
    free(view);
}

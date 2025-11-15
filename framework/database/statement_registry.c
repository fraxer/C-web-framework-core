#include <stdlib.h>
#include <string.h>
#include "statement_registry.h"
#include "log.h"

/* ============= CONFIGURATION ============= */
#define MAX_PREPARED_STATEMENTS 256

/* ============= STATIC REGISTRY DATA ============= */
static prepare_stmt_handler __statements[MAX_PREPARED_STATEMENTS];
static int __statement_count = 0;

/* ============= REGISTRY IMPLEMENTATION ============= */

int pstmt_registry_register(prepare_stmt_handler handler) {
    if (handler == NULL) {
        log_error("pstmt_registry_register: handler cannot be NULL\n");
        return 0;
    }

    if (__statement_count >= MAX_PREPARED_STATEMENTS) {
        log_error("pstmt_registry_register: registry is full (max %d statements)\n", MAX_PREPARED_STATEMENTS);
        return 0;
    }

    __statements[__statement_count++] = handler;
    return 1;
}

void pstmt_registry_clear(void) {
    __statement_count = 0;
    memset(__statements, 0, sizeof(__statements));
}

prepare_stmt_handler* pstmt_list(void) {
    return __statements;
}

int pstmt_count(void) {
    return __statement_count;
}

prepare_stmt_t* pstmt_create(void) {
    prepare_stmt_t* stmt = malloc(sizeof * stmt);
    if (stmt == NULL) {
        log_error("pstmt_create: memory allocation failed\n");
        return NULL;
    }

    stmt->name = NULL;
    stmt->query = NULL;
    stmt->params = NULL;

    return stmt;
}

void pstmt_free(void* arg) {
    prepare_stmt_t* stmt = (prepare_stmt_t*)arg;
    if (stmt == NULL)
        return;

    str_free(stmt->name);
    str_free(stmt->query);
    array_free(stmt->params);
    free(stmt);
}

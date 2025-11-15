#ifndef STATEMENT_REGISTRY_H
#define STATEMENT_REGISTRY_H

#include "appconfig.h"
#include "model.h"

/**
 * Initialize and register all application prepared statements
 * Called from moduleloader during initialization
 *
 * @return 1 on success, 0 on error
 */
int prepare_statements_init(void);

/* Forward declaration of prepare_stmt_t */
typedef struct {
    str_t* name;
    str_t* query;
    array_t* params;
} prepare_stmt_t;

/* Handler function type for prepared statements */
typedef prepare_stmt_t*(*prepare_stmt_handler)(void);

/* ============= CORE REGISTRY INTERFACE ============= */

/**
 * Get list of all registered prepared statement handlers
 * @return Pointer to array of handlers
 */
prepare_stmt_handler* pstmt_list(void);

/**
 * Get count of registered prepared statements
 * @return Number of handlers
 */
int pstmt_count(void);

/**
 * Create new prepared statement structure
 * @return Pointer to new structure or NULL on error
 */
prepare_stmt_t* pstmt_create(void);

/**
 * Free prepared statement memory
 * @param arg Pointer to prepare_stmt_t structure
 */
void pstmt_free(void* arg);

/* ============= NEW REGISTRATION INTERFACE ============= */

/**
 * Register a prepared statement handler
 * Called by application during initialization
 *
 * @param handler Function that creates and returns prepare_stmt_t
 * @return 1 on success, 0 if registry is full or handler is NULL
 */
int pstmt_registry_register(prepare_stmt_handler handler);

/**
 * Clear the registry (used during config reload)
 */
void pstmt_registry_clear(void);

#endif /* STATEMENT_REGISTRY_H */

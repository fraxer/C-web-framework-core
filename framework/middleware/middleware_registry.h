#ifndef MIDDLEWARE_REGISTRY_H
#define MIDDLEWARE_REGISTRY_H

#include "middleware.h"

/**
 * Initialize and register all application middlewares
 * Called from moduleloader during initialization
 *
 * @return 1 on success, 0 on error
 */
int middlewares_init(void);

/* ============= REGISTRY ENTRY STRUCTURE ============= */

/**
 * Structure for middleware registry entry
 */
typedef struct {
    const char* name;           /* Middleware identifier */
    middleware_fn_p handler;    /* Handler function */
} middleware_registry_entry_t;

/* ============= CORE REGISTRY INTERFACE ============= */

/**
 * Get middleware by name
 * Search in registered middlewares
 *
 * @param name Middleware name (e.g. "cors", "auth", "ratelimit")
 * @return Function pointer or NULL if not found
 */
middleware_fn_p middleware_by_name(const char* name);

/* ============= NEW REGISTRATION INTERFACE ============= */

/**
 * Register a middleware
 * Called by application during initialization
 *
 * @param name Unique middleware name
 * @param handler Handler function
 * @return 1 on success, 0 on error (full, duplicate, etc.)
 */
int middleware_registry_register(const char* name, middleware_fn_p handler);

/**
 * Get all registered middlewares
 *
 * @param out_count Pointer to save count of middlewares
 * @return Array of middleware_registry_entry_t structures
 */
middleware_registry_entry_t* middleware_registry_get_all(int* out_count);

/**
 * Clear the registry (used during config reload)
 */
void middleware_registry_clear(void);

#endif /* MIDDLEWARE_REGISTRY_H */

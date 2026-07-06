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

#define MIDDLEWARE_REGISTRY_MAX 256   /* Registry capacity */
#define MIDDLEWARE_NAME_MAX     128   /* Max name length including '\0' */

/**
 * Structure for middleware registry entry
 */
typedef struct {
    char name[MIDDLEWARE_NAME_MAX];   /* Middleware identifier (owned copy) */
    middleware_fn_p handler;          /* Handler function */
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
 * The name is copied into the registry, so the caller's string
 * does not need to outlive the call.
 *
 * @param name Unique non-empty middleware name, shorter than MIDDLEWARE_NAME_MAX
 * @param handler Handler function
 * @return 1 on success, 0 on error (full, duplicate, empty or too long name, etc.)
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

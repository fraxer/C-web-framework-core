#include <stdlib.h>
#include <string.h>
#include "middleware_registry.h"
#include "log.h"

/* ============= CONFIGURATION ============= */
#define MAX_MIDDLEWARES 256

/* ============= STATIC REGISTRY DATA ============= */
static middleware_registry_entry_t __middleware_list[MAX_MIDDLEWARES];
static int __middleware_count = 0;

/* ============= REGISTRY IMPLEMENTATION ============= */

int middleware_registry_register(const char* name, middleware_fn_p handler) {
    if (name == NULL || handler == NULL) {
        log_error("middleware_registry_register: name and handler cannot be NULL\n");
        return 0;
    }

    /* Check for overflow */
    if (__middleware_count >= MAX_MIDDLEWARES) {
        log_error("middleware_registry_register: registry is full (max %d middlewares)\n", MAX_MIDDLEWARES);
        return 0;
    }

    /* Check for duplicates */
    for (int i = 0; i < __middleware_count; i++) {
        if (strcmp(__middleware_list[i].name, name) == 0) {
            log_error("middleware_registry_register: middleware '%s' already registered\n", name);
            return 0;
        }
    }

    __middleware_list[__middleware_count].name = name;
    __middleware_list[__middleware_count].handler = handler;
    __middleware_count++;

    return 1;
}

middleware_fn_p middleware_by_name(const char* name) {
    if (name == NULL)
        return NULL;

    for (int i = 0; i < __middleware_count; i++) {
        if (strcmp(__middleware_list[i].name, name) == 0) {
            return __middleware_list[i].handler;
        }
    }

    return NULL;
}

middleware_registry_entry_t* middleware_registry_get_all(int* out_count) {
    if (out_count != NULL)
        *out_count = __middleware_count;
    return __middleware_list;
}

void middleware_registry_clear(void) {
    __middleware_count = 0;
    memset(__middleware_list, 0, sizeof(__middleware_list));
}

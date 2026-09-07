#include <stdlib.h>
#include <string.h>
#include "middleware_registry.h"
#include "log.h"

/* log_error_stderr, not log_error: a rejected registration makes app_init() fail,
 * which refuses the whole start-up or reload -- exactly the case where losing the
 * message leaves a failure with no explanation. On a first start the logger is
 * not even configured yet (misc/log.h). */

/* ============= STATIC REGISTRY DATA ============= */
static middleware_registry_entry_t __middleware_list[MIDDLEWARE_REGISTRY_MAX];
static int __middleware_count = 0;

/* ============= REGISTRY IMPLEMENTATION ============= */

int middleware_registry_register(const char* name, middleware_fn_p handler) {
    if (name == NULL || handler == NULL) {
        log_error_stderr("middleware_registry_register: name and handler cannot be NULL\n");
        return 0;
    }

    const size_t name_length = strlen(name);
    if (name_length == 0) {
        log_error_stderr("middleware_registry_register: name cannot be empty\n");
        return 0;
    }
    if (name_length >= MIDDLEWARE_NAME_MAX) {
        log_error_stderr("middleware_registry_register: name is too long (max %d chars)\n", MIDDLEWARE_NAME_MAX - 1);
        return 0;
    }

    /* Check for overflow */
    if (__middleware_count >= MIDDLEWARE_REGISTRY_MAX) {
        log_error_stderr("middleware_registry_register: registry is full (max %d middlewares)\n", MIDDLEWARE_REGISTRY_MAX);
        return 0;
    }

    /* Check for duplicates */
    for (int i = 0; i < __middleware_count; i++) {
        if (strcmp(__middleware_list[i].name, name) == 0) {
            log_error_stderr("middleware_registry_register: middleware '%s' already registered\n", name);
            return 0;
        }
    }

    memcpy(__middleware_list[__middleware_count].name, name, name_length + 1);
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

struct middleware_registry_snapshot {
    middleware_registry_entry_t list[MIDDLEWARE_REGISTRY_MAX];
    int count;
};

middleware_registry_snapshot_t* middleware_registry_save(void) {
    middleware_registry_snapshot_t* snapshot = malloc(sizeof * snapshot);
    if (snapshot == NULL) {
        log_error_stderr("middleware_registry_save: memory alloc error\n");
        return NULL;
    }

    memcpy(snapshot->list, __middleware_list, sizeof __middleware_list);
    snapshot->count = __middleware_count;

    middleware_registry_clear();

    return snapshot;
}

void middleware_registry_restore(middleware_registry_snapshot_t* snapshot) {
    if (snapshot == NULL) return;

    memcpy(__middleware_list, snapshot->list, sizeof __middleware_list);
    __middleware_count = snapshot->count;

    free(snapshot);
}

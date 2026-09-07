#ifndef __ROUTELOADER__
#define __ROUTELOADER__

#include "shadowload.h"

#define ROUTELOADER_LIB_NOT_FOUND "Route loader: library \"%s\" not loaded: %s\n"
#define ROUTELOADER_FUNCTION_NOT_FOUND "Route loader: Function \"%s\" not found in \"%s\"\n"
#define ROUTELOADER_OUT_OF_MEMORY "Route loader: Out of memory\n"

typedef struct routeloader_lib {
    char* filepath;
    void* pointer;

    struct routeloader_lib* next;
} routeloader_lib_t;

/**
 * Load a handler .so, picking it up again after it has been rebuilt in place.
 *
 * `tmpdir` is where the shadow copy goes when the module's own directory is not
 * writable -- config->env.main.tmp, which is parsed before `servers` is.
 * `sonames` is the generation's SONAME map: a handler that needs an application
 * module which was rebuilt has to be copied too, so that its DT_NEEDED can be
 * pointed at that generation's module rather than at the previous one. See
 * shadowload.h.
 */
routeloader_lib_t* routeloader_load_lib(const char* filepath, const char* tmpdir,
                                        const shadow_sonames_t* sonames);

void* routeloader_get_handler(routeloader_lib_t*, const char*, const char*);

void routeloader_free(routeloader_lib_t*);

int routeloader_has_lib(routeloader_lib_t*, const char*);

routeloader_lib_t* routeloader_get_last(routeloader_lib_t*);

#endif

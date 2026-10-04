#ifndef CWFR_BODYSTORE_H
#define CWFR_BODYSTORE_H

#include <stddef.h>

#define BODY_STORE_FILE_THRESHOLD ((size_t)1048576)

typedef enum {
    BODY_STORE_EMPTY,
    BODY_STORE_MEMORY,
    BODY_STORE_FILE
} body_store_state_t;

/* Owned incoming bytes, independent of framing/content type. Initialize before
 * use; do not copy this structure. fd/path belong to the store until reset.
 * A failed prepare/append/materialize poisons reads until reset, so callers
 * cannot dispatch a partial body. Callers remain responsible for protocol
 * length checks and mapping failure to their existing error path. */
typedef struct body_store {
    body_store_state_t state;
    size_t size;
    size_t capacity;                 /* allocated bytes, including trailing NUL */
    size_t max_size;
    char* data;
    char* path;
    int fd;
    int failed;
} body_store_t;

void body_store_init(body_store_t* store, size_t max_size);
void body_store_reset(body_store_t* store);
/* Optional length hint, only before receiving bytes. Not a length validator.
 * Small known lengths reserve exactly length+1; large lengths create a file. */
int body_store_prepare(body_store_t* store, size_t length, const char* tmp_dir);
int body_store_append(body_store_t* store, const void* data, size_t size, const char* tmp_dir);
int body_store_read(const body_store_t* store, size_t offset, void* data, size_t size);
/* Returns a caller-owned binary copy with an extra NUL, including empty bodies. */
char* body_store_copy(const body_store_t* store, size_t offset, size_t size);
int body_store_materialize(body_store_t* store, const char* tmp_dir);

#endif

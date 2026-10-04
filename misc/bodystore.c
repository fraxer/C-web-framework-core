#define _GNU_SOURCE

#include "bodystore.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int body_store_fail(body_store_t* store) {
    store->failed = 1;
    return 0;
}

void body_store_init(body_store_t* store, size_t max_size) {
    *store = (body_store_t){
        .max_size = max_size,
        .fd = -1
    };
}

void body_store_reset(body_store_t* store) {
    if (store->fd >= 0)
        close(store->fd);

    if (store->path != NULL)
        unlink(store->path);

    free(store->path);
    free(store->data);

    body_store_init(store, store->max_size);
}

static int write_range(int fd, size_t offset, const char* data, size_t size) {
    while (size != 0) {
        size_t chunk = size > (size_t)SSIZE_MAX ? (size_t)SSIZE_MAX : size;
        ssize_t n = pwrite(fd, data, chunk, (off_t)offset);
        if (n < 0 && errno == EINTR)
            continue;

        if (n <= 0)
            return 0;

        offset += (size_t)n;
        data += n;
        size -= (size_t)n;
    }

    return 1;
}

int body_store_materialize(body_store_t* store, const char* tmp_dir) {
    if (store->failed)
        return 0;

    if (store->state == BODY_STORE_FILE)
        return 1;

    if (tmp_dir == NULL)
        return body_store_fail(store);

    const char suffix[] = "/cwfr-body-XXXXXX";
    size_t len = strnlen(tmp_dir, PATH_MAX);
    if (len > PATH_MAX - sizeof(suffix))
        return body_store_fail(store);

    char* path = malloc(len + sizeof(suffix));
    if (path == NULL)
        return body_store_fail(store);

    memcpy(path, tmp_dir, len);
    memcpy(path + len, suffix, sizeof(suffix));

    int fd = mkstemp(path);
    if (fd < 0) {
        free(path);
        return body_store_fail(store);
    }

    if (!write_range(fd, 0, store->data, store->size)) {
        close(fd);
        unlink(path);
        free(path);
        return body_store_fail(store);
    }

    store->fd = fd;
    store->path = path;
    store->state = BODY_STORE_FILE;
    free(store->data);
    store->data = NULL;
    store->capacity = 0;

    return 1;
}

static int reserve(body_store_t* store, size_t capacity) {
    if (capacity <= store->capacity)
        return 1;

    char* data = realloc(store->data, capacity);
    if (data == NULL)
        return body_store_fail(store);

    store->data = data;
    store->capacity = capacity;
    store->data[store->size] = '\0';
    store->state = BODY_STORE_MEMORY;

    return 1;
}

int body_store_prepare(body_store_t* store, size_t length, const char* tmp_dir) {
    if (store->failed)
        return 0;

    if (store->state != BODY_STORE_EMPTY || store->size != 0 || length > store->max_size || length > INT64_MAX)
        return body_store_fail(store);

    if (length >= BODY_STORE_FILE_THRESHOLD)
        return body_store_materialize(store, tmp_dir);

    return reserve(store, length + 1);
}

int body_store_append(body_store_t* store, const void* data, size_t size, const char* tmp_dir) {
    if (store->failed)
        return 0;

    if ((data == NULL && size != 0) || store->size > store->max_size ||
        size > store->max_size - store->size || store->size > INT64_MAX ||
        size > (uintmax_t)INT64_MAX - store->size)
        return body_store_fail(store);

    if (size == 0)
        return 1;

    size_t total = store->size + size;
    if (total >= BODY_STORE_FILE_THRESHOLD && !body_store_materialize(store, tmp_dir))
        return 0;

    if (store->state == BODY_STORE_FILE) {
        if (!write_range(store->fd, store->size, data, size))
            return body_store_fail(store);
    } else {
        size_t capacity = store->capacity ? store->capacity : 256;
        while (capacity < total + 1) {
            capacity = capacity > BODY_STORE_FILE_THRESHOLD / 2
                ? BODY_STORE_FILE_THRESHOLD
                : capacity * 2;
        }

        if (!reserve(store, capacity))
            return 0;

        memcpy(store->data + store->size, data, size);
        store->data[total] = '\0';
    }

    store->size = total;

    return 1;
}

int body_store_read(const body_store_t* store, size_t offset, void* data, size_t size) {
    if (store->failed || offset > store->size || size > store->size - offset || (data == NULL && size != 0))
        return 0;

    if (size == 0)
        return 1;

    if (store->state == BODY_STORE_MEMORY) {
        memcpy(data, store->data + offset, size);
        return 1;
    }

    if (store->state != BODY_STORE_FILE)
        return 0;

    char* out = data;
    while (size != 0) {
        size_t chunk = size > (size_t)SSIZE_MAX
            ? (size_t)SSIZE_MAX
            : size;
        ssize_t n = pread(store->fd, out, chunk, (off_t)offset);
        if (n < 0 && errno == EINTR)
            continue;

        if (n <= 0)
            return 0;

        offset += (size_t)n;
        out += n;
        size -= (size_t)n;
    }

    return 1;
}

char* body_store_copy(const body_store_t* store, size_t offset, size_t size) {
    if (store->failed || size == SIZE_MAX || offset > store->size || size > store->size - offset)
        return NULL;

    char* copy = malloc(size + 1);
    if (copy == NULL)
        return NULL;

    if (!body_store_read(store, offset, copy, size)) {
        free(copy);
        return NULL;
    }

    copy[size] = '\0';

    return copy;
}

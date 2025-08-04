#include <string.h>

#include "bufo.h"

bufo_t* bufo_create(void) {
    bufo_t* buf = malloc(sizeof * buf);
    if (buf == NULL) return NULL;

    bufo_init(buf);

    return buf;
}

void bufo_init(bufo_t* buf) {
    buf->data = NULL;
    buf->capacity = 0;

    bufo_flush(buf);
}

void bufo_clear(bufo_t* buf) {
    if (buf->is_proxy) {
        bufo_init(buf);
        return;
    }

    if (buf->data != NULL)
        free(buf->data);

    bufo_init(buf);
}

void bufo_flush(bufo_t* buf) {
    buf->size = 0;
    buf->pos = 0;
    buf->is_proxy = 0;
    buf->is_last = 0;
}

void bufo_free(bufo_t* buf) {
    if (buf == NULL)
        return;

    if (buf->is_proxy) {
        free(buf);
        return;
    }

    if (buf->data != NULL)
        free(buf->data);

    free(buf);
}

size_t bufo_chunk_size(bufo_t* buf, size_t size) {
    if (buf->pos + size >= buf->size)
        return buf->size - buf->pos;

    return size;
}

char* bufo_data(bufo_t* buf) {
    return buf->data + buf->pos;
}

size_t bufo_size(bufo_t* buf) {
    return buf->size;
}

size_t bufo_move_front_pos(bufo_t* buf, size_t size) {
    size_t s = 0;

    if (buf->pos + size >= buf->size) {
        s = buf->size - buf->pos;
        buf->pos = buf->size;
    }
    else {
        s = size;
        buf->pos += size;
    }

    return s;
}

void bufo_set_size(bufo_t* buf, size_t size) {
    buf->size = size;
}

int bufo_alloc(bufo_t* buf, size_t capacity) {
    if (buf->data != NULL) 
        return 1;

    buf->data = malloc(capacity);
    if (buf->data == NULL)
        return 0;

    buf->capacity = capacity;

    return 1;
}

ssize_t bufo_append(bufo_t* buf, const char* data, size_t size) {
    if (buf->is_proxy)
        return 0;

    if (size == 0)
        return 0;

    if (buf->data == NULL)
        return -1;

    size_t max_size = buf->capacity - buf->pos;
    if (size < max_size)
        max_size = size;

    memcpy(buf->data + buf->pos, data, max_size);

    buf->size += max_size;

    return bufo_move_front_pos(buf, max_size);
}

void bufo_reset_pos(bufo_t* buf) {
    buf->pos = 0;
}

void bufo_reset_size(bufo_t* buf) {
    buf->size = 0;
}

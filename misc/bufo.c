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
    if (buf->pos >= buf->size)
        return 0;

    const size_t remaining = buf->size - buf->pos;

    return (size < remaining) ? size : remaining;
}

char* bufo_data(bufo_t* buf) {
    if (buf->data == NULL)
        return NULL;

    return buf->data + buf->pos;
}

size_t bufo_size(bufo_t* buf) {
    return buf->size;
}

size_t bufo_move_front_pos(bufo_t* buf, size_t size) {
    size_t s = 0;

    // Проверяем что pos не вышла за границы size (защита от underflow)
    if (buf->pos >= buf->size)
        return 0;

    if (buf->pos + size >= buf->size) {
        s = buf->size - buf->pos;  // Теперь безопасно: pos < size
        buf->pos = buf->size;
    }
    else {
        s = size;
        buf->pos += size;
    }

    return s;
}

void bufo_set_size(bufo_t* buf, size_t size) {
    // Limit the size to the buffer capacity
    if (size > buf->capacity)
        size = buf->capacity;

    buf->size = size;
}

int bufo_alloc(bufo_t* buf, size_t capacity) {
    if (buf->data != NULL)
        return 1;

    const size_t max_capacity = 10 * 1024 * 1024; // 10 Mb
    if (capacity > max_capacity)
        return 0;

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

    if (buf->pos >= buf->capacity)
        return 0;

    const size_t available = buf->capacity - buf->pos;
    if (available == 0)
        return 0;
    
    const size_t to_copy = (size < available) ? size : available;

    memcpy(buf->data + buf->pos, data, to_copy);

    buf->pos += to_copy;
    if (buf->pos > buf->size)
        buf->size = buf->pos;

    return to_copy;
}

void bufo_reset_pos(bufo_t* buf) {
    buf->pos = 0;
}

void bufo_reset_size(bufo_t* buf) {
    buf->size = 0;
}

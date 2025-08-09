#ifndef __BUFFER_OUTPUT__
#define __BUFFER_OUTPUT__

#include <stdlib.h>
#include <sys/types.h>

typedef struct bufo {
    unsigned is_proxy : 1;
    unsigned is_last : 1;

    char* data;
    size_t capacity;
    size_t size;
    size_t pos;
} bufo_t;

bufo_t* bufo_create(void);
void bufo_init(bufo_t* buf);
void bufo_clear(bufo_t* buf);
void bufo_flush(bufo_t* buf);
void bufo_free(bufo_t* buf);
size_t bufo_chunk_size(bufo_t* buf, size_t size);
char* bufo_data(bufo_t* buf);
size_t bufo_size(bufo_t* buf);
size_t bufo_move_front_pos(bufo_t* buf, size_t size);

void bufo_set_size(bufo_t* buf, size_t size);
int bufo_alloc(bufo_t* buf, size_t size);
ssize_t bufo_append(bufo_t* buf, const char* data, size_t size);
void bufo_reset_pos(bufo_t* buf);
void bufo_reset_size(bufo_t* buf);

#endif

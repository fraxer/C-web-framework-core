#include <stdlib.h>
#include <string.h>

#include "bufferdata.h"

void bufferdata_init(bufferdata_t* buffer) {
    if (buffer == NULL) return;

    buffer->dynamic_buffer = NULL;
    buffer->offset_sbuffer = 0;
    buffer->offset_dbuffer = 0;
    buffer->dbuffer_size = 0;
    buffer->type = BUFFERDATA_STATIC;
    buffer->static_buffer[0] = 0;
}

int bufferdata_push(bufferdata_t* buffer, char ch) {
    if (buffer == NULL) return 0;

    // Check if static buffer is full BEFORE writing to prevent buffer overflow
    if (buffer->offset_sbuffer >= BUFFERDATA_SIZE) {
        bufferdata_type_e prev_type = buffer->type;
        if (buffer->type == BUFFERDATA_STATIC)
            buffer->type = BUFFERDATA_DYNAMIC;

        // Move existing data to dynamic buffer
        if (!bufferdata_move(buffer)) {
            buffer->type = prev_type;
            return 0;
        }
    }

    buffer->static_buffer[buffer->offset_sbuffer] = ch;
    buffer->offset_sbuffer++;

    if (buffer->offset_sbuffer < BUFFERDATA_SIZE)
        buffer->static_buffer[buffer->offset_sbuffer] = 0;

    return 1;
}

// NOTE: dynamic_buffer is intentionally NOT freed here for reuse optimization
// Call bufferdata_clear() to release all memory
void bufferdata_reset(bufferdata_t* buffer) {
    if (buffer == NULL) return;

    buffer->offset_dbuffer = 0;
    buffer->offset_sbuffer = 0;
    buffer->type = BUFFERDATA_STATIC;
}

void bufferdata_clear(bufferdata_t* buffer) {
    if (buffer == NULL) return;

    bufferdata_reset(buffer);

    if (buffer->dynamic_buffer != NULL)
        free(buffer->dynamic_buffer);

    buffer->dynamic_buffer = NULL;
    buffer->dbuffer_size = 0;
}

size_t bufferdata_writed(bufferdata_t* buffer) {
    if (buffer == NULL) return 0;

    if (buffer->type == BUFFERDATA_DYNAMIC)
        return buffer->offset_dbuffer + buffer->offset_sbuffer;

    return buffer->offset_sbuffer;
}

int bufferdata_complete(bufferdata_t* buffer) {
    if (buffer == NULL) return 0;

    if (buffer->type == BUFFERDATA_DYNAMIC)
        return bufferdata_move(buffer);

    return 1;
}

int bufferdata_move(bufferdata_t* buffer) {
    if (buffer == NULL) return 0;

    if (buffer->type != BUFFERDATA_DYNAMIC)
        return 1;

    size_t dbuffer_length = buffer->offset_dbuffer + buffer->offset_sbuffer;

    if (buffer->dbuffer_size <= dbuffer_length) {
        char* data = realloc(buffer->dynamic_buffer, dbuffer_length + 1);
        if (data == NULL) return 0;

        buffer->dbuffer_size = dbuffer_length + 1;
        buffer->dynamic_buffer = data;
    }

    memcpy(&buffer->dynamic_buffer[buffer->offset_dbuffer], buffer->static_buffer, buffer->offset_sbuffer);

    buffer->dynamic_buffer[dbuffer_length] = 0;
    buffer->offset_dbuffer = dbuffer_length;
    buffer->offset_sbuffer = 0;

    return 1;
}

int bufferdata_move_data_to_start(bufferdata_t* buffer, size_t offset, size_t size) {
    if (buffer == NULL) return 0;

    // Validate bounds based on buffer type
    if (buffer->type == BUFFERDATA_STATIC) {
        // Check individual bounds to prevent overflow
        if (offset > BUFFERDATA_SIZE || size > BUFFERDATA_SIZE)
            return 0;

        // Safe check for offset + size now that we know both are <= BUFFERDATA_SIZE
        if (offset + size > BUFFERDATA_SIZE)
            return 0;

        memmove(buffer->static_buffer, buffer->static_buffer + offset, size);
        buffer->static_buffer[size] = 0;
        buffer->offset_sbuffer = size;
        buffer->offset_dbuffer = 0;
    }
    else {
        // Check bounds for dynamic buffer
        size_t current_size = buffer->offset_dbuffer;

        // Special case: if size is 0, we can move from any offset <= current_size
        if (size == 0) {
            if (offset > current_size)
                return 0;

            buffer->offset_dbuffer = 0;
            buffer->offset_sbuffer = 0;
            return 1;
        }

        // For non-zero size: offset must be strictly less than current_size
        // (can't start reading at or past the end)
        if (offset >= current_size)
            return 0;

        // Check for integer overflow: offset + size
        // Safe because we know offset < current_size <= SIZE_MAX
        if (size > current_size - offset)
            return 0;

        memmove(buffer->dynamic_buffer, buffer->dynamic_buffer + offset, size);

        char* data = realloc(buffer->dynamic_buffer, size + 1);
        if (data == NULL) return 0;

        buffer->dbuffer_size = size + 1;
        buffer->dynamic_buffer = data;
        buffer->dynamic_buffer[size] = 0;
        buffer->offset_dbuffer = size;
        buffer->offset_sbuffer = 0;
    }

    return 1;
}

char* bufferdata_get(bufferdata_t* buffer) {
    if (buffer == NULL) return NULL;

    if (buffer->type == BUFFERDATA_DYNAMIC)
        return buffer->dynamic_buffer;

    return buffer->static_buffer;
}

char* bufferdata_copy(bufferdata_t* buffer) {
    if (buffer == NULL) return NULL;

    char* string = bufferdata_get(buffer);
    if (string == NULL) return NULL;

    size_t length = bufferdata_writed(buffer);

    char* data = malloc(length + 1);
    if (data == NULL) return NULL;

    memcpy(data, string, length);
    data[length] = 0;

    return data;
}

char bufferdata_back(bufferdata_t* buffer) {
    if (buffer == NULL) return 0;
    if (bufferdata_writed(buffer) == 0) return 0;

    if (buffer->offset_sbuffer > 0)
        return buffer->static_buffer[buffer->offset_sbuffer - 1];

    if (buffer->dynamic_buffer == NULL)
        return 0;

    return buffer->dynamic_buffer[buffer->offset_dbuffer - 1];
}

char bufferdata_pop_back(bufferdata_t* buffer) {
    if (buffer == NULL) return 0;
    if (bufferdata_writed(buffer) == 0) return 0;

    char c = 0;
    if (buffer->offset_sbuffer > 0) {
        c = buffer->static_buffer[buffer->offset_sbuffer - 1];
        buffer->static_buffer[buffer->offset_sbuffer - 1] = 0;
        buffer->offset_sbuffer--;
    }
    else {
        if (buffer->dynamic_buffer == NULL)
            return 0;

        c = buffer->dynamic_buffer[buffer->offset_dbuffer - 1];
        buffer->dynamic_buffer[buffer->offset_dbuffer - 1] = 0;
        buffer->offset_dbuffer--;
    }

    return c;
}

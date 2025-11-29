#define _GNU_SOURCE
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "str.h"

// Forward declarations
static int __str_expand_buffer(str_t* str, const size_t extra_size);
static int __str_switch_to_dynamic(str_t* str, size_t required_size);
static inline char* __str_get_buffer(str_t* str);
static inline size_t __str_get_capacity(str_t* str);

str_t* str_create(const char* string) {
    if (string == NULL) return str_create_empty(0);

    return str_createn(string, strlen(string));
}

str_t* str_createn(const char* string, const size_t size) {
    str_t* data = str_create_empty(size);
    if (data == NULL) return NULL;

    if (string == NULL) return data;

    if (!str_assign(data, string, size)) {
        str_free(data);
        return NULL;
    }

    return data;
}

str_t* str_create_empty(int init_capacity) {
    str_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    str_init(data, init_capacity);

    if (!str_reset(data)) {
        str_free(data);
        return NULL;
    }

    return data;
}

int str_init(str_t* str, int init_capacity) {
    if (str == NULL) return 0;

    // Initialize in SSO mode
    str->sso_buffer[0] = '\0';
    str->dynamic_buffer = NULL;
    str->size = 0;
    str->capacity = 0;
    str->is_dynamic = 0;  // Start with SSO
    str->init_capacity = init_capacity < 16384 ? init_capacity : 16384;

    return 1;
}

int str_reset(str_t* str) {
    // Free dynamic buffer if allocated
    if (str->is_dynamic && str->dynamic_buffer != NULL) {
        explicit_bzero(str->dynamic_buffer, str->capacity);
        free(str->dynamic_buffer);
        str->dynamic_buffer = NULL;
    }

    // Wipe SSO buffer
    explicit_bzero(str->sso_buffer, STR_SSO_SIZE);

    // Reset to SSO mode
    str->size = 0;
    str->capacity = 0;
    str->is_dynamic = 0;

    return 1;
}

int str_reserve(str_t* str, size_t capacity) {
    if (str == NULL) return 0;

    // If requested capacity fits in SSO buffer, nothing to do
    if (capacity <= STR_SSO_SIZE)
        return 1;

    // If already in dynamic mode with enough capacity, do nothing
    if (str->is_dynamic && str->capacity >= capacity)
        return 1;

    // Need to switch to dynamic or expand dynamic buffer
    if (!str->is_dynamic) {
        // Switch from SSO to dynamic
        char* data = malloc(capacity);
        if (data == NULL) return 0;

        // Copy existing data from SSO buffer
        if (str->size > 0)
            memcpy(data, str->sso_buffer, str->size);
        data[str->size] = '\0';

        // Wipe SSO buffer after copying
        explicit_bzero(str->sso_buffer, STR_SSO_SIZE);

        str->dynamic_buffer = data;
        str->capacity = capacity;
        str->is_dynamic = 1;
    } else {
        // Expand dynamic buffer
        void* data = realloc(str->dynamic_buffer, capacity);
        if (data == NULL) return 0;

        str->dynamic_buffer = data;
        str->capacity = capacity;
    }

    return 1;
}

void str_clear(str_t* str) {
    if (str == NULL) return;

    if (str->is_dynamic && str->dynamic_buffer != NULL) {
        explicit_bzero(str->dynamic_buffer, str->capacity);
        free(str->dynamic_buffer);
    }

    // Wipe SSO buffer
    explicit_bzero(str->sso_buffer, STR_SSO_SIZE);

    str_init(str, str->init_capacity);
}

void str_free(str_t* str) {
    if (str == NULL) return;

    str_clear(str);
    explicit_bzero(str, sizeof(str_t));
    free(str);
}

size_t str_size(const str_t* str) {
    if (str == NULL)
        return 0;

    return str->size;
}

int str_insertc(str_t* str, char ch, size_t pos) {
    if (str == NULL)
        return 0;

    if (pos > str->size)
        return 0;

    // Fast path: append to SSO buffer
    if (!str->is_dynamic && pos == str->size && str->size < STR_SSO_SIZE - 1) {
        str->sso_buffer[str->size++] = ch;
        str->sso_buffer[str->size] = '\0';
        return 1;
    }

    // Check if we need to expand buffer
    size_t current_capacity = __str_get_capacity(str);
    if (str->size + 1 >= current_capacity) {
        if (!__str_expand_buffer(str, 1))
            return 0;
    }

    // Get the buffer pointer
    char* buffer = __str_get_buffer(str);

    // Insert character
    memmove(buffer + pos + 1, buffer + pos, str->size - pos);
    buffer[pos] = ch;
    str->size++;
    buffer[str->size] = '\0';

    return 1;
}

int str_prependc(str_t* str, char ch) {
    return str_insertc(str, ch, 0);
}

int str_appendc(str_t* str, char ch) {
    if (str == NULL) return 0;
    return str_insertc(str, ch, str->size);
}

int str_insert(str_t* str, const char* string, size_t size, size_t pos) {
    if (str == NULL || string == NULL)
        return 0;

    if (pos > str->size)
        return 0;

    // Fast path: append to SSO buffer
    if (!str->is_dynamic && pos == str->size && str->size + size < STR_SSO_SIZE) {
        memcpy(str->sso_buffer + str->size, string, size);
        str->size += size;
        str->sso_buffer[str->size] = '\0';
        return 1;
    }

    // Check if we need to expand buffer
    size_t current_capacity = __str_get_capacity(str);
    if (str->size + size + 1 >= current_capacity) {
        if (!__str_expand_buffer(str, size))
            return 0;
    }

    // Get the buffer pointer
    char* buffer = __str_get_buffer(str);

    // Insert string
    memmove(buffer + pos + size, buffer + pos, str->size - pos);
    memcpy(buffer + pos, string, size);
    str->size += size;
    buffer[str->size] = '\0';

    return 1;
}

int str_prepend(str_t* str, const char* string, size_t size) {
    return str_insert(str, string, size, 0);
}

int str_append(str_t* str, const char* string, size_t size) {
    if (str == NULL) return 0;
    return str_insert(str, string, size, str->size);
}

int str_appendf(str_t* str, const char* format, ...) {
    if (str == NULL || format == NULL) return 0;

    va_list args, args_copy;
    va_start(args, format);

    // Make a copy of args for the second vsnprintf call
    va_copy(args_copy, args);

    // First call to determine required size
    int needed_size = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (needed_size < 0) {
        va_end(args_copy);
        return 0;
    }

    // Allocate temporary buffer
    char* buffer = malloc(needed_size + 1);
    if (buffer == NULL) {
        va_end(args_copy);
        return 0;
    }

    // Format the string
    vsnprintf(buffer, needed_size + 1, format, args_copy);
    va_end(args_copy);

    // Append to str
    int result = str_append(str, buffer, needed_size);

    // Free temporary buffer
    free(buffer);

    return result;
}

int str_assign(str_t* str, const char* string, size_t size) {
    if (str == NULL) return 0;

    str->size = 0;

    return str_insert(str, string, size, 0);
}

int str_move(str_t* srcstr, str_t* dststr) {
    if (srcstr == NULL || dststr == NULL)
        return 0;

    // Clear destination
    if (dststr->is_dynamic && dststr->dynamic_buffer != NULL)
        free(dststr->dynamic_buffer);

    if (srcstr->is_dynamic) {
        // Move dynamic buffer
        dststr->dynamic_buffer = srcstr->dynamic_buffer;
        dststr->capacity = srcstr->capacity;
        dststr->is_dynamic = 1;
    } else {
        // Copy SSO buffer
        memcpy(dststr->sso_buffer, srcstr->sso_buffer, srcstr->size + 1);
        dststr->dynamic_buffer = NULL;
        dststr->capacity = 0;
        dststr->is_dynamic = 0;
    }

    dststr->size = srcstr->size;
    dststr->init_capacity = srcstr->init_capacity;

    return str_init(srcstr, srcstr->init_capacity);
}

int str_cmp(str_t* srcstr, str_t* dststr) {
    return str_cmpc(srcstr, str_get(dststr));
}

int str_cmpc(str_t* srcstr, const char* dststr) {
    if (srcstr == NULL || dststr == NULL)
        return 0;

    return strcmp(str_get(srcstr), dststr);
}

char* str_get(str_t* str) {
    if (str == NULL)
        return NULL;

    if (str->size == 0)
        return "";

    return str->is_dynamic ? str->dynamic_buffer : str->sso_buffer;
}

char* str_copy(str_t* str) {
    if (str == NULL)
        return NULL;

    char* string = str_get(str);
    size_t length = str_size(str);

    char* data = malloc(length + 1);
    if (data == NULL) return NULL;

    memcpy(data, string, length);
    data[length] = 0;

    return data;
}

static int __str_expand_buffer(str_t* str, const size_t extra_size) {
    size_t required_size = str->size + extra_size + 1; // +1 for null terminator
    size_t target_size;

    // Minimum reasonable growth to avoid too many reallocs
    #define MIN_STR_GROWTH 32

    if (!str->is_dynamic) {
        // Switch from SSO to dynamic
        return __str_switch_to_dynamic(str, required_size);
    }

    // Already in dynamic mode - expand
    // Growth strategy: double the capacity or use required size (whichever is larger)

    // SECURITY FIX: Check for integer overflow before doubling
    if (str->capacity > SIZE_MAX / 2) {
        // Cannot safely double - use required_size or max safe value
        target_size = required_size;

        // Additional safety check: refuse unreasonably large allocations
        if (target_size > SIZE_MAX - 1024) {
            return 0;  // Request too large
        }
    } else {
        target_size = str->capacity * 2;
    }

    // Ensure minimum growth to avoid many small reallocs
    if (target_size < str->capacity + MIN_STR_GROWTH) {
        target_size = str->capacity + MIN_STR_GROWTH;
    }

    if (target_size < required_size) {
        target_size = required_size;
    }

    void* data = realloc(str->dynamic_buffer, target_size);
    if (data == NULL) return 0;

    str->dynamic_buffer = data;
    str->capacity = target_size;

    return 1;
}

// Helper function to switch from SSO to dynamic mode
static int __str_switch_to_dynamic(str_t* str, size_t required_size) {
    // Determine target capacity
    size_t target_size = str->init_capacity > 0 ? str->init_capacity : 64;

    // Ensure target is at least the required size
    if (target_size < required_size)
        target_size = required_size;

    // Allocate dynamic buffer
    char* new_buffer = malloc(target_size);
    if (new_buffer == NULL)
        return 0;

    // Copy existing data from SSO buffer
    if (str->size > 0)
        memcpy(new_buffer, str->sso_buffer, str->size);
    new_buffer[str->size] = '\0';

    // Switch to dynamic mode
    str->dynamic_buffer = new_buffer;
    str->capacity = target_size;
    str->is_dynamic = 1;

    return 1;
}

// Helper function to get current buffer pointer
static inline char* __str_get_buffer(str_t* str) {
    return str->is_dynamic ? str->dynamic_buffer : str->sso_buffer;
}

// Helper function to get current capacity
static inline size_t __str_get_capacity(str_t* str) {
    return str->is_dynamic ? str->capacity : STR_SSO_SIZE;
}

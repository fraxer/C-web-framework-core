#ifndef __STR__
#define __STR__

#include <stdlib.h>
#include <stdint.h>

// Small String Optimization (SSO) buffer size
// Optimized for typical JSON strings (keys and short values)
#define STR_SSO_SIZE 32

typedef struct {
    // SSO buffer - used for small strings (< 24 bytes)
    char sso_buffer[STR_SSO_SIZE];

    // Dynamic buffer - used for large strings (>= 24 bytes)
    char* dynamic_buffer;

    size_t size;         // Current string size (without null terminator)
    size_t capacity;     // Capacity of dynamic buffer (0 if using SSO)
    uint8_t is_dynamic;  // 0 = using sso_buffer, 1 = using dynamic_buffer
    int init_capacity;   // Initial capacity for dynamic allocation
} str_t;

str_t* str_create(const char* string, const size_t size);
str_t* str_create_empty(int init_capacity);
int str_init(str_t* str, int init_capacity);
int str_reset(str_t* str);
int str_reserve(str_t* str, size_t capacity);
void str_clear(str_t* str);
void str_free(str_t* str);

size_t str_size(const str_t* str);
int str_insertc(str_t* str, char ch, size_t pos);
int str_prependc(str_t* str, char ch);
int str_appendc(str_t* str, char ch);
int str_insert(str_t* str, const char* string, size_t size, size_t pos);
int str_prepend(str_t* str, const char* string, size_t size);
int str_append(str_t* str, const char* string, size_t size);
int str_assign(str_t* str, const char* string, size_t size);
int str_move(str_t* srcstr, str_t* dststr);

char* str_get(str_t* str);
char* str_copy(str_t* str);
int str_modify_add_symbols_before(str_t* str, char add_symbol, char before_symbol);

#endif
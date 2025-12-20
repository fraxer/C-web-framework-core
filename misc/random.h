#ifndef __RANDOM__
#define __RANDOM__

#include <stddef.h>
#include <stdint.h>

int random_init(void);
int random_bytes(void* buffer, size_t length);
uint32_t random_uint32(void);
uint32_t random_uint32_range(uint32_t min, uint32_t max);
uint64_t random_uint64(void);
uint64_t random_uint64_range(uint64_t min, uint64_t max);
int random_string(char* buffer, size_t length);
int random_string_hex(char* buffer, size_t length);
int random_string_alphanum(char* buffer, size_t length);

#endif

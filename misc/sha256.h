#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

#define SHA256_BLOCK_SIZE 32
#define SHA256_HEX_SIZE 65 // 64 + '\0'

typedef unsigned char SHA256_BYTE;
typedef unsigned int  SHA256_WORD;

typedef struct {
	SHA256_BYTE data[64];
	SHA256_WORD datalen;
	unsigned long long bitlen;
	SHA256_WORD state[8];
} sha256_t;

void sha256(const unsigned char* data, size_t size, unsigned char* result);
void sha256_hex(const unsigned char* data, size_t size, char* result);

#endif

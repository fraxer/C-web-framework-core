#include <stdio.h>

#include "uuid.h"
#include "random.h"

int uuid4_generate(char* buffer) {
    if (buffer == NULL) return 0;

    unsigned char bytes[16];
    if (!random_bytes(bytes, sizeof(bytes)))
        return 0;

    // Version 4: set bits 4-7 of byte 6 to 0100
    bytes[6] = (bytes[6] & 0x0F) | 0x40;

    // Variant 1: set bits 6-7 of byte 8 to 10
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    snprintf(buffer, UUID4_SIZE,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);

    return 1;
}

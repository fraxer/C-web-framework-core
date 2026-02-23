#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/random.h>

#include "random.h"
#include "log.h"

static const char charset_base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char charset_hex[] = "0123456789abcdef";
static const char charset_alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static int __random_string_charset(char* buffer, size_t length, const char* charset, size_t charset_len);

int random_init(void) {
    unsigned int seed;
    if (random_bytes(&seed, sizeof(seed)) != 1) {
        return 0;
    }
    srand(seed);
    return 1;
}

int random_bytes(void* buffer, size_t length) {
    if (buffer == NULL) return 0;
    if (length == 0) return 1;

    ssize_t result = getrandom(buffer, length, 0);
    if (result < 0) {
        log_error("getrandom failed: %s\n", strerror(errno));
        return 0;
    }

    if ((size_t)result != length) {
        log_error("getrandom returned incomplete data\n");
        return 0;
    }

    return 1;
}

uint32_t random_uint32(void) {
    uint32_t value;
    if (random_bytes(&value, sizeof(value)) != 1) {
        return 0;
    }
    return value;
}

uint32_t random_uint32_range(uint32_t min, uint32_t max) {
    if (min >= max) return min;

    uint32_t range = max - min;
    uint32_t threshold = (-range) % range;
    uint32_t value;

    do {
        value = random_uint32();
    } while (value < threshold);

    return min + (value % range);
}

uint64_t random_uint64(void) {
    uint64_t value;
    if (random_bytes(&value, sizeof(value)) != 1) {
        return 0;
    }
    return value;
}

uint64_t random_uint64_range(uint64_t min, uint64_t max) {
    if (min >= max) return min;

    uint64_t range = max - min;
    uint64_t threshold = (-range) % range;
    uint64_t value;

    do {
        value = random_uint64();
    } while (value < threshold);

    return min + (value % range);
}

int random_string(char* buffer, size_t length) {
    return __random_string_charset(buffer, length, charset_base64, sizeof(charset_base64) - 1);
}

int random_string_hex(char* buffer, size_t length) {
    return __random_string_charset(buffer, length, charset_hex, sizeof(charset_hex) - 1);
}

int random_string_alphanum(char* buffer, size_t length) {
    return __random_string_charset(buffer, length, charset_alphanum, sizeof(charset_alphanum) - 1);
}

int __random_string_charset(char* buffer, size_t length, const char* charset, size_t charset_len) {
    if (buffer == NULL) return 0;
    if (length == 0) {
        buffer[0] = '\0';
        return 1;
    }

    unsigned char* random_data = malloc(length);
    if (random_data == NULL) return 0;

    if (random_bytes(random_data, length) != 1) {
        free(random_data);
        return 0;
    }

    for (size_t i = 0; i < length; i++) {
        buffer[i] = charset[random_data[i] % charset_len];
    }
    buffer[length] = '\0';

    free(random_data);
    return 1;
}

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <string.h>
#include <limits.h>

#include "typecheck.h"


int is_int(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;
    long num = strtol(str, &endptr, 10);

    if (errno == ERANGE || num > INT_MAX || num < INT_MIN)
        return 0;

    if (endptr == str)
        return 0;  // Не было считано ни одной цифры

    while (*endptr != '\0') {
        if (!isspace((unsigned char)*endptr))
            return 0;  // Есть нечисловые символы после числа

        endptr++;
    }

    return 1;
}

int is_uint(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    if (*str == '-')
        return 0;

    char* endptr = NULL;
    errno = 0;

    unsigned long val = strtoul(str, &endptr, 10);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE || val > UINT_MAX)
        return 0;

    return 1;
}

int is_long(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;

    strtol(str, &endptr, 10);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE)
        return 0;

    return 1;
}

int is_ulong(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    if (*str == '-')
        return 0;

    char* endptr = NULL;
    errno = 0;

    strtoul(str, &endptr, 10);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE)
        return 0;

    return 1;
}

int is_float(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;

    float val = strtof(str, &endptr);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE)
        return 0;

    if (isnan(val) || isinf(val))
        return 0;

    return 1;
}

int is_double(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;

    double val = strtod(str, &endptr);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE)
        return 0;

    if (isnan(val) || isinf(val))
        return 0;

    return 1;
}

int is_long_double(const char* str) {
    if (str == NULL || *str == '\0')
        return 0;

    char* endptr = NULL;
    errno = 0;

    long double val = strtold(str, &endptr);

    if (*endptr != '\0')
        return 0;

    if (errno == ERANGE)
        return 0;

    if (isnan(val) || isinf(val))
        return 0;

    return 1;
}
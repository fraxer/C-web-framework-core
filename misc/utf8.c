#include <stdlib.h>
#include <string.h>

#include <unistr.h>
#include <unicase.h>
#include <uninorm.h>
#include <unictype.h>

#include "utf8.h"

/* --- Character classification --- */

int utf8_is_alpha(uint32_t codepoint) {
    return uc_is_alpha(codepoint);
}

int utf8_is_digit(uint32_t codepoint) {
    return uc_is_digit(codepoint);
}

int utf8_is_space(uint32_t codepoint) {
    return uc_is_space(codepoint);
}

int utf8_is_upper(uint32_t codepoint) {
    return uc_is_upper(codepoint);
}

int utf8_is_lower(uint32_t codepoint) {
    return uc_is_lower(codepoint);
}

int utf8_is_punct(uint32_t codepoint) {
    return uc_is_punct(codepoint);
}

/* --- String operations --- */

size_t utf8_strlen(const char *str) {
    if (str == NULL) return 0;

    size_t count = 0;
    const uint8_t *p = (const uint8_t *)str;

    while (*p) {
        if (*p < 0x80) {
            p++;
        } else if ((*p & 0xE0) == 0xC0) {
            p += 2;
        } else if ((*p & 0xF0) == 0xE0) {
            p += 3;
        } else if ((*p & 0xF8) == 0xF0) {
            p += 4;
        } else {
            p++;
        }
        count++;
    }

    return count;
}

char *utf8_toupper(const char *str) {
    if (str == NULL) return NULL;

    size_t len = strlen(str);
    size_t result_len = 0;

    uint8_t *buf = malloc(len + 1);
    if (buf == NULL) return NULL;

    uint8_t *result = u8_toupper((const uint8_t *)str, len, NULL, NULL, buf, &result_len);
    if (result == NULL) {
        free(buf);
        return NULL;
    }

    /* If libunistring reused our buffer (no realloc), there's room for '\0'.
       Otherwise it reallocated to exactly result_len — grow by 1. */
    if (result == buf) {
        result[result_len] = '\0';
    }
    else {
        free(buf);
        uint8_t *terminated = realloc(result, result_len + 1);
        if (terminated == NULL) {
            free(result);
            return NULL;
        }
        terminated[result_len] = '\0';
        result = terminated;
    }

    return (char *)result;
}

char *utf8_tolower(const char *str) {
    if (str == NULL) return NULL;

    size_t len = strlen(str);
    size_t result_len = 0;

    uint8_t *buf = malloc(len + 1);
    if (buf == NULL) return NULL;

    uint8_t *result = u8_tolower((const uint8_t*)str, len, NULL, NULL, buf, &result_len);
    if (result == NULL) {
        free(buf);
        return NULL;
    }

    if (result == buf) {
        result[result_len] = '\0';
    }
    else {
        free(buf);
        uint8_t *terminated = realloc(result, result_len + 1);
        if (terminated == NULL) {
            free(result);
            return NULL;
        }
        terminated[result_len] = '\0';
        result = terminated;
    }

    return (char*)result;
}

int utf8_casecmp(const char *a, const char *b) {
    if (a == NULL || b == NULL) return 0;

    size_t len_a = strlen(a);
    size_t len_b = strlen(b);

    int result = 0;
    u8_casecmp((const uint8_t *)a, len_a,
               (const uint8_t *)b, len_b,
               NULL, NULL, &result);

    return result;
}

char *utf8_normalize(const char *str, int form) {
    if (str == NULL) return NULL;

    uninorm_t norm;
    switch (form) {
        case UTF8_NFC: norm = UNINORM_NFC; break;
        case UTF8_NFD: norm = UNINORM_NFD; break;
        default:       return NULL;
    }

    size_t len = strlen(str);
    size_t result_len = 0;

    uint8_t *buf = malloc(len + 1);
    if (buf == NULL) return NULL;

    uint8_t *result = u8_normalize(norm, (const uint8_t*)str, len, buf, &result_len);
    if (result == NULL) {
        free(buf);
        return NULL;
    }

    if (result == buf) {
        result[result_len] = '\0';
    }
    else {
        free(buf);
        uint8_t *terminated = realloc(result, result_len + 1);
        if (terminated == NULL) { free(result); return NULL; }
        terminated[result_len] = '\0';
        result = terminated;
    }

    return (char*)result;
}

/* --- Codepoint iterator --- */

void utf8_iter_init(utf8_iter_t *iter, const char *str) {
    if (iter == NULL) return;

    if (str == NULL) {
        iter->pos = NULL;
        iter->end = NULL;
        return;
    }

    iter->pos = (const uint8_t *)str;
    iter->end = (const uint8_t *)str + strlen(str);
}

uint32_t utf8_iter_next(utf8_iter_t *iter) {
    if (iter == NULL || iter->pos == NULL || iter->pos >= iter->end) {
        return 0;
    }

    ucs4_t codepoint;
    int bytes = u8_mbtouc_unsafe(&codepoint, iter->pos, iter->end - iter->pos);

    if (bytes <= 0) {
        iter->pos = iter->end;
        return 0xFFFD;  /* Unicode replacement character */
    }

    iter->pos += bytes;
    return (uint32_t)codepoint;
}

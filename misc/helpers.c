#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "log.h"
#include "helpers.h"

static int __hex_char_to_int(char c);
static char __byte_to_hex(unsigned char);

int helpers_mkdir(const char* path) {
    if (path == NULL) return 0;
    if (path[0] == 0) return 0;

    return helpers_base_mkdir("/", path);
}

int helpers_base_mkdir(const char* base_path, const char* path) {
    if (strlen(path) == 0)
        return 0;

    const size_t base_path_len = strlen(base_path);

    /* Защита от переполнения local_path: base + '/' + path + '\0'. */
    if (base_path_len + strlen(path) + 2 > PATH_MAX)
        return 0;

    char local_path[PATH_MAX] = {0};

    strcpy(local_path, base_path);
    if (base_path[base_path_len - 1] != '/' && path[0] != '/')
        strcat(local_path, "/");

    const char* p_path = path;
    char* p_local_path = &local_path[strlen(local_path)];

    if (*p_path == '/') {
        *p_local_path++ = *p_path;
        p_path++;
    }

    while (*p_path) {
        *p_local_path++ = *p_path;

        if (*p_path == '/') {
            p_path++;
            break;
        }

        p_path++;
    }

    *p_local_path = 0;

    struct stat stat_obj;
    if (stat(local_path, &stat_obj) == -1)
        /* EEXIST — каталог успел создать кто-то другой между stat и mkdir,
           это не ошибка. */
        if (mkdir(local_path, S_IRWXU) == -1 && errno != EEXIST)
            return 0;

    if (*p_path != 0)
        if (!helpers_base_mkdir(local_path, p_path)) return 0;

    return 1;
}

int cmpstr_lower(const char* a, const char* b) {
    return cmpstrn_lower(a, strlen(a), b, strlen(b));
}

int cmpstrn_lower(const char *a, size_t a_length, const char *b, size_t b_length) {
    if (a_length != b_length) return 0;

    for (size_t i = 0; i < a_length; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;

    return 1;
}

char* create_tmppath(const char* tmp_path)
{
    const char* template = "tmp.XXXXXX";
    const size_t path_length = strlen(tmp_path) + strlen(template) + 2; // "/", "\0"
    char* path = malloc(path_length);
    if (path == NULL)
        return NULL;

    snprintf(path, path_length, "%s/%s", tmp_path, template);

    return path;
}

const char* file_extension(const char* path) {
    if (path == NULL) return NULL;

    const size_t length = strlen(path);
    if (length == 0) return NULL;

    for (size_t i = length - 1; ; i--) {
        switch (path[i]) {
        case '.':
            // If nothing after the dot, return NULL
            if (i + 1 >= length || path[i + 1] == '\0') {
                return NULL;
            }
            return &path[i + 1];
        case '/':
            return NULL;
        }
        if (i == 0) break;  // Safe exit for size_t to avoid underflow
    }

    return NULL;
}

int cmpsubstr_lower(const char* a, const char* b) {
    size_t a_length = strlen(a);
    size_t b_length = strlen(b);
    size_t cmpsize = 0;

    for (size_t i = 0, j = 0; i < a_length && j < b_length; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[j])) {
            cmpsize = 0;
            j = 0;
            continue;
        }

        cmpsize++;
        j++;

        if (cmpsize == b_length) return 1;
    }

    return cmpsize == b_length;
}

int timezone_offset() {
    const time_t epoch_plus_11h = 60 * 60 * 11;

    struct tm local_tm;
    struct tm gm_tm;

    if (localtime_r(&epoch_plus_11h, &local_tm) == NULL) return 0;
    if (gmtime_r(&epoch_plus_11h, &gm_tm) == NULL) return 0;

    return local_tm.tm_hour - gm_tm.tm_hour;
}

int __hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char* hex, unsigned char* raw, size_t raw_size) {
    if (hex == NULL || raw == NULL) return 0;

    const size_t len = strlen(hex);
    if (len % 2 != 0) {
        log_error("Error: Hex string length must be even\n");
        return 0;
    }

    if (len / 2 > raw_size) {
        log_error("Error: Output buffer too small for hex string\n");
        return 0;
    }

    for (size_t i = 0; i < len; i += 2) {
        int high = __hex_char_to_int(hex[i]);
        int low = __hex_char_to_int(hex[i + 1]);

        if (high == -1 || low == -1) {
            log_error("Error: Invalid hex character\n");
            return 0;
        }

        raw[i / 2] = (unsigned char)((high << 4) | low); // Combine high and low nibble
    }

    return 1;
}

void bytes_to_hex(const unsigned char* raw, size_t raw_length, char* hex) {
    const char* hexChars = "0123456789abcdef";
    for (size_t i = 0; i < raw_length; i++) {
        // Convert each byte to two hexadecimal characters
        hex[i * 2] = hexChars[(raw[i] >> 4) & 0xF]; // High nibble
        hex[i * 2 + 1] = hexChars[raw[i] & 0xF];    // Low nibble
    }
    hex[raw_length * 2] = '\0'; // Null-terminate the hex string
}

char* urlencode(const char* string, size_t length) {
    return urlencodel(string, length, NULL);
}

char* urlencodel(const char* string, size_t length, size_t* output_length) {
    if (string == NULL) return NULL;

    char* buffer = malloc(length * 3 + 1);
    if (buffer == NULL) return NULL;

    char* pbuffer = buffer;
    for (size_t i = 0; i < length; i++) {
        const unsigned char ch = (unsigned char)string[i];

        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~')
            *pbuffer++ = (char)ch;
        else if (ch == ' ')
            *pbuffer++ = '+';
        else {
            *pbuffer++ = '%';
            *pbuffer++ = __byte_to_hex(ch >> 4);
            *pbuffer++ = __byte_to_hex(ch & 15);
        }
    }

    *pbuffer = 0;

    if (output_length != NULL)
        *output_length = pbuffer - buffer;

    return buffer;
}

char* urldecode(const char* string, size_t length) {
    return urldecodel(string, length, NULL);
}

char* urldecodel(const char* string, size_t length, size_t* output_length) {
    if (string == NULL) return NULL;

    char* buffer = malloc(length + 1);
    if (buffer == NULL) return NULL;

    char* pbuffer = buffer;
    for (size_t i = 0; i < length; i++) {
        char ch = string[i];
        if (ch == '%') {
            if (i + 2 < length) {
                int hi = __hex_char_to_int(string[i + 1]);
                int lo = __hex_char_to_int(string[i + 2]);
                if (hi >= 0 && lo >= 0) {
                    *pbuffer++ = (char)((hi << 4) | lo);
                    i += 2;
                } else {
                    *pbuffer++ = '%';   // битый %XX — оставляем литералом
                }
            } else {
                *pbuffer++ = '%';
            }
        } else if (ch == '+') {
            *pbuffer++ = ' ';
        } else {
            *pbuffer++ = ch;
        }
    }

    *pbuffer = 0;

    if (output_length != NULL)
        *output_length = pbuffer - buffer;

    return buffer;
}

char __byte_to_hex(unsigned char code) {
    static char hex[] = "0123456789ABCDEF";
    return hex[code & 0x0F];
}

int data_append(char* data, size_t* pos, const char* string, size_t length) {
    if (data == NULL) return 0;
    if (string == NULL) return 0;

    memcpy(&data[*pos], string, length);
    *pos += length;

    return 1;
}

int data_appendn(char* data, size_t* pos, size_t max, const char* string, size_t length) {
    if (data == NULL) return 0;
    if (string == NULL) return 0;

    /* Без переполнения size_t: сначала убеждаемся, что *pos в пределах max. */
    if (*pos >= max) return 0;
    if (length >= max - *pos) return 0;

    memcpy(&data[*pos], string, length);
    *pos += length;

    return 1;
}

int is_path_traversal(const char* string, size_t length) {
    char ch_1 = 0;
    char ch_2 = 0;
    char ch_3 = '/';

    for (size_t i = 0; i < length; i++) {
        char c = string[i];

        if (ch_1 == '/' && ch_2 == '.' && ch_3 == '.' && c == '/')
            return 1;

        ch_1 = ch_2;
        ch_2 = ch_3;
        ch_3 = c;
    }

    if (ch_1 == '/' && ch_2 == '.' && ch_3 == '.')
        return 1;

    return 0;
}

char* copy_cstringn(const char* string, size_t length) {
    char* value = malloc(length + 1);
    if (value == NULL) return value;

    if (string != NULL)
        memcpy(value, string, length);

    value[length] = 0;

    return value;
}

size_t http_format_date(time_t time, char* buf, size_t buf_size) {
    if (buf == NULL || buf_size == 0)
        return 0;

    struct tm tm_buf;
    struct tm* tm = gmtime_r(&time, &tm_buf);
    if (tm == NULL)
        return 0;

    return strftime(buf, buf_size, "%a, %d %b %Y %H:%M:%S GMT", tm);
}

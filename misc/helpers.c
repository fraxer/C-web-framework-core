#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>

#include "log.h"
#include "helpers.h"

static int __hex_char_to_int(char c);
static char __hex_to_byte(char);
static char __byte_to_hex(char);

int helpers_mkdir(const char* path) {
    if (path == NULL) return 0;
    if (path[0] == 0) return 0;

    return helpers_base_mkdir("/", path);
}

int helpers_base_mkdir(const char* base_path, const char* path) {
    if (strlen(path) == 0)
        return 0;

    char local_path[PATH_MAX] = {0};
    size_t base_path_len = strlen(base_path);

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
    if(stat(local_path, &stat_obj) == -1)
        if(mkdir(local_path, S_IRWXU) == -1) return 1;

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
        if (tolower(a[i]) != tolower(b[i])) return 0;

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

const char* file_extention(const char* path) {
    const size_t length = strlen(path);
    for (size_t i = length - 1; i > 0; i--) {
        switch (path[i]) {
        case '.':
            return &path[i + 1];
        case '/':
            return NULL;
        }
    }

    return NULL;
}

int cmpsubstr_lower(const char* a, const char* b) {
    size_t a_length = strlen(a);
    size_t b_length = strlen(b);
    size_t cmpsize = 0;

    for (size_t i = 0, j = 0; i < a_length && j < b_length; i++) {
        if (tolower(a[i]) != tolower(b[j])) {
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
    const int local_time = localtime(&epoch_plus_11h)->tm_hour;
    const int gm_time = gmtime(&epoch_plus_11h)->tm_hour;

    return local_time - gm_time;
}

int __hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char* hex, unsigned char* raw) {
    int len = strlen(hex);
    if (len % 2 != 0) {
        log_error("Error: Hex string length must be even\n");
        return 0;
    }

    for (int i = 0; i < len; i += 2) {
        int high = __hex_char_to_int(hex[i]);
        int low = __hex_char_to_int(hex[i + 1]);

        if (high == -1 || low == -1) {
            log_error("Error: Invalid hex character\n");
            return 0;
        }

        raw[i / 2] = (high << 4) | low; // Combine high and low nibble
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
        char ch = string[i];

        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~')
            *pbuffer++ = ch;
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
    char* buffer = malloc(length + 1);
    if (buffer == NULL) return NULL;

    char* pbuffer = buffer;
    for (size_t i = 0; i < length; i++) {
        char ch = string[i];
        if (ch == '%') {
            if (string[i + 1] && string[i + 2]) {
                *pbuffer++ = __hex_to_byte(string[i + 1]) << 4 | __hex_to_byte(string[i + 2]);
                i += 2;
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

char __hex_to_byte(char hex) {
    return hex <= '9' ? hex - '0' : 
           hex <= 'F' ? hex - 'A' + 10 : 
           hex - 'a' + 10;
}

char __byte_to_hex(char code) {
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
    if (*pos + length >= max) return 0;

    memcpy(&data[*pos], string, length);
    *pos += length;

    return 1;
}

int is_path_traversal(const char* string, size_t length) {
    char ch_1 = 0;
    char ch_2 = 0;
    char ch_3 = 0;
    for (size_t i = 0; i <= length; i++) {
        if (ch_1 == '/' && ch_2 == '.' && ch_3 == '.' && string[i] == '/')
            return 1;
        else if (ch_1 == '/' && ch_2 == '.' && ch_3 == '.' && string[i] == '\0')
            return 1;

        ch_1 = ch_2;
        ch_2 = ch_3;
        ch_3 = string[i];
    }

    return 0;
}

char* copy_cstringn(const char* string, size_t length) {
    char* value = malloc(length + 1);
    if (value == NULL) return value;

    if (string != NULL) {
        memcpy(value, string, length);
        value[length] = 0;
    }

    return value;
}

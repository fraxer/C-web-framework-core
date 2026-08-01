#include <stdlib.h>
#include <string.h>

#include "base64.h"

static const unsigned char pr2six[256] = {
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64url_decode_len(const char* bufcoded) {
    /* base64url carries no '=' padding, so the decoded length is just the input
     * length scaled by 3/4. +1 for the trailing NUL the caller's buffer needs. */
    size_t len = 0;
    while (bufcoded[len] != '\0') len++;

    return (int)((len * 3) / 4) + 1;
}

int base64url_decode(char* bufplain, const char* bufcoded) {
    /* Translate to the standard alphabet and re-add the '=' padding that
     * base64_decode expects, then reuse it. The input is short (an HTTP2-Settings
     * payload is a handful of 6-byte settings), so a small heap buffer is fine. */
    size_t len = 0;
    while (bufcoded[len] != '\0') len++;

    char* tmp = malloc(len + 4); /* up to 2 '=' + NUL + slack */
    if (tmp == NULL) return -1;

    for (size_t i = 0; i < len; i++) {
        char c = bufcoded[i];
        if (c == '-') tmp[i] = '+';
        else if (c == '_') tmp[i] = '/';
        else tmp[i] = c;
    }

    const size_t pad = (4 - (len % 4)) % 4;
    for (size_t i = 0; i < pad; i++)
        tmp[len + i] = '=';
    tmp[len + pad] = '\0';

    const int n = base64_decode(bufplain, tmp);
    free(tmp);
    return n;
}

int __base64_encode_intenal_len(const int len, const int wrap);
int __base64_encode_internal(char* encoded, const char* string, const int string_len, const int wrap);

int base64_encode_len(const int len) {
    const int wrap = 0;

    return __base64_encode_intenal_len(len, wrap);
}

int base64_encode(char* encoded, const char* string, const int string_len) {
    const int wrap = 0;

    return __base64_encode_internal(encoded, string, string_len, wrap);
}

int base64_encode_nl_len(const int len, const int wrap) {
    return __base64_encode_intenal_len(len, wrap);
}

int base64_encode_nl(char* encoded, const char* string, const int string_len, const int wrap) {
    return __base64_encode_internal(encoded, string, string_len, wrap);
}

int base64_decode_len(const char* bufcoded) {
    register int nprbytes = 0;
    register const unsigned char* bufin = (const unsigned char*)bufcoded;

    while (1) {
        if (*bufin == '\r' || *bufin == '\n') {
            bufin++;
            continue;
        }
        if (pr2six[*bufin++] > 63)
            break;

        nprbytes++;
    }

    return (((nprbytes + 3) / 4) * 3) + 1;
}

int base64_decode(char* bufplain, const char* bufcoded) {
    register int nprbytes = 0;
    register const unsigned char* bufin = (const unsigned char*)bufcoded;

    while (1) {
        if (*bufin == '\r' || *bufin == '\n') {
            bufin++;
            continue;
        }
        if (pr2six[*bufin++] > 63)
            break;

        nprbytes++;
    }

    int nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    register unsigned char* bufout = (unsigned char*)bufplain;
    bufin = (const unsigned char*)bufcoded;

    while (nprbytes > 4) {
        if (*bufin == '\r' || *bufin == '\n') {
            bufin++;
            continue;
        }

        *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);

        bufin += 4;
        nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1)
        *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);

    if (nprbytes > 2)
        *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);

    if (nprbytes > 3)
        *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;

    return nbytesdecoded;
}

int __base64_encode_intenal_len(const int len, const int wrap) {
    const int inline_len = ((len + 2) / 3 * 4) + 1;

    if (wrap > 0) {
        int nl = (inline_len / wrap) * 2;
        if  (nl > 1 && inline_len % wrap == 0)
            nl -= 2;

        return inline_len + nl;
    }

    return inline_len;
}

int __base64_encode_internal(char* encoded, const char* string, const int string_len, const int wrap) {
    int i;
    int pc = 0;
    char* p = encoded;

    for (i = 0; i < string_len - 2; i += 3) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        *p++ = basis_64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                        ((int) (string[i + 2] & 0xC0) >> 6)];
        *p++ = basis_64[string[i + 2] & 0x3F];

        if (wrap > 0) {
            pc += 4;
            if (pc % wrap == 0) {
                *p++ = '\r';
                *p++ = '\n';
            }
        }
    }

    if (i < string_len) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        if (i == (string_len - 1)) {
            *p++ = basis_64[((string[i] & 0x3) << 4)];
            *p++ = '=';
        }
        else {
            *p++ = basis_64[((string[i] & 0x3) << 4) |
                            ((int) (string[i + 1] & 0xF0) >> 4)];
            *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
        }
        *p++ = '=';
    }

    *p++ = '\0';

    return (p - encoded) - 1;
}

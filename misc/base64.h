#ifndef __BASE64__
#define __BASE64__

#include "file.h"

int base64_encode_len(const int len);
int base64_encode(char* encoded, const char* string, const int string_len);

int base64_encode_nl_len(const int len, int wrap);
int base64_encode_nl(char* encoded, const char* string, const int string_len, const int wrap);

int base64_decode_len(const char* bufcoded);
int base64_decode(char* bufplain, const char* bufcoded);

/* base64url (RFC 4648 §5 / RFC 7540 §3.2.1): the URL- and filename-safe alphabet
 * that uses '-' and '_' instead of '+' and '/' and omits the '=' padding. Used
 * by the HTTP2-Settings header in an h2c Upgrade request. */
int base64url_decode_len(const char* bufcoded);
int base64url_decode(char* bufplain, const char* bufcoded);

#endif
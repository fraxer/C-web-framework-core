#ifndef __HELPERS__
#define __HELPERS__

#include <stddef.h>
#include <time.h>

int helpers_mkdir(const char* path);
int helpers_base_mkdir(const char* base_path, const char* path);
int cmpstr_lower(const char* a, const char* b);
int cmpstrn_lower(const char* a, size_t a_length, const char* b, size_t b_length);
char* create_tmppath(const char*);
const char* file_extension(const char* path);
int cmpsubstr_lower(const char* a, const char* b);
int timezone_offset();
int hex_char_to_int(char c);
int hex_to_bytes(const char* hex, unsigned char* raw, size_t raw_size);
void bytes_to_hex(const unsigned char* raw, size_t raw_length, char* hex);

/* Comparison whose running time does not depend on where the two sides
 * differ. An ordinary memcmp() or strcmp() returns at the first difference,
 * and the response time then gives a secret away one character at a time.
 *
 * The contents are hidden, the length is not: secure_compare() calls strlen()
 * on both sides anyway. For a fixed-length token -- a CSRF value, a webhook
 * signature, an admin key, all of which arrive as a hex or base64 string --
 * that is enough, and comparing secrets of different lengths is meaningless.
 *
 * secure_compare_bytes() is the one to use for a buffer of known length that
 * may contain zero bytes, such as a signature. */
int secure_compare_bytes(const void* a, const void* b, size_t size);
int secure_compare(const char* a, const char* b);
char* urlencode(const char* string, size_t length);
char* urlencodel(const char* string, size_t length, size_t* output_length);
char* urldecode(const char* string, size_t length);
char* urldecodel(const char* string, size_t length, size_t* output_length);
int data_append(char* data, size_t* pos, const char* string, size_t length);
int data_appendn(char* data, size_t* pos, size_t max, const char* string, size_t length);
int is_path_traversal(const char* string, size_t length);
char* copy_cstringn(const char*, size_t);
size_t http_format_date(time_t time, char* buf, size_t buf_size);

#endif

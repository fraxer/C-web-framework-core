#ifndef __HELPERS__
#define __HELPERS__

int helpers_mkdir(const char* path);
int helpers_base_mkdir(const char* base_path, const char* path);
int cmpstr(const char* a, const char* b);
int cmpstr_lower(const char* a, const char* b);
int cmpstrn_lower(const char* a, size_t a_length, const char* b, size_t b_length);
char* create_tmppath(const char*);
const char* file_extention(const char* path);
int cmpsubstr_lower(const char* a, const char* b);
int starts_with_substr(const char* string, const char* substring);
int timezone_offset();
int hex_to_bytes(const char* hex, unsigned char* raw);
void bytes_to_hex(const unsigned char* raw, size_t raw_length, char* hex);
char* urlencode(const char* string, size_t length);
char* urlencodel(const char* string, size_t length, size_t* output_length);
char* urldecode(const char* string, size_t length);
char* urldecodel(const char* string, size_t length, size_t* output_length);
int data_append(char* data, size_t* pos, const char* string, size_t length);
int data_appendn(char* data, size_t* pos, size_t max, const char* string, size_t length);

#endif
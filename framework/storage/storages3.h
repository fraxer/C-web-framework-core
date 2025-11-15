#ifndef __STORAGES3__
#define __STORAGES3__

#include "storage.h"
#include "str.h"

typedef struct {
    storage_t base;
    str_t access_id;
    str_t access_secret;
    str_t protocol;
    str_t host;
    str_t port;
    str_t bucket;
    str_t region;
} storages3_t;

storages3_t* storage_create_s3(const char* storage_name, const char* access_id, const char* access_secret, const char* protocol, const char* host, const char* port, const char* bucket, const char* region);

#endif
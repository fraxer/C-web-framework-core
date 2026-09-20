#ifndef __STORAGES3__
#define __STORAGES3__

#include "storage.h"
#include "str.h"
#include "file.h"

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

// Порция, которой тянется тело объекта. На порцию, а не на объект, рассчитан и
// таймаут: полный GET видео не уложился бы в него никогда.
#define STORAGES3_CHUNK_LIMIT (8 * 1024 * 1024)
#define STORAGES3_TIMEOUT 15

typedef struct {
    int status;              // HTTP-статус ответа S3; 0 — транспортная ошибка или таймаут
    char* etag;
    char* last_modified;
    char* content_type;
    size_t total_size;       // объект целиком
    size_t size;             // сколько получено в этот раз
    file_t file;             // tmpfile с телом; file.ok == 0, если тела нет или оно в памяти
    char* body;              // тело в памяти или NULL
} s3fetch_t;

// Только метаданные: один короткий запрос, тело не скачивается. Условные
// заголовки проксируются в S3, его 304 ретранслируется как есть.
// 1 — объект есть (200) или не изменился (304).
int storages3_head(const char* storage_name, const char* path,
                   const char* if_none_match, const char* if_modified_since,
                   s3fetch_t* out);

// Тело объекта. whole != 0 — объект целиком (start/end игнорируются), иначе
// диапазон [start, end] включительно. И то и другое тянется порциями.
int storages3_fetch(const char* storage_name, const char* path,
                    size_t start, size_t end, int whole, s3fetch_t* out);

void storages3_fetch_free(s3fetch_t* fetch);

// Чистые хелперы — отдельно от сети, чтобы их можно было проверить юнит-тестом.
int storages3_range_format(char* out, size_t out_size, size_t start, size_t end);
int storages3_content_range_parse(const char* value, size_t* start, size_t* end, size_t* total);
int storages3_http_status(int s3_status);
// Размер порции с оглядкой на main.client_max_body_size: клиент отбивает ответ
// крупнее лимита, так что порция сверх него не скачалась бы вообще.
size_t storages3_chunk_size(size_t client_max_body_size);

#endif
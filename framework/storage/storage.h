#ifndef __STORAGE__
#define __STORAGE__

#include <stdio.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/sendfile.h>

#include "array.h"
#include "file.h"
#include "helpers.h"

typedef enum {
    STORAGE_TYPE_FS = 0,
    STORAGE_TYPE_S3,
} storage_type_e;

// Что лежит по пути в хранилище
typedef enum {
    STORAGE_ENTRY_NONE = 0,   // ничего нет, путь недопустим или хранилище недоступно
    STORAGE_ENTRY_FILE,       // обычный файл (в S3 — объект)
    STORAGE_ENTRY_DIRECTORY,  // каталог (в S3 — префикс, под которым есть хотя бы один объект)
    STORAGE_ENTRY_OTHER       // что-то другое: символьная ссылка, сокет, устройство
} storage_entry_e;

typedef struct storage {
    storage_type_e type;
    void(*free)(void* storage);
    char name[NAME_MAX];

    file_t(*file_get)(void* storage, const char* path);
    int(*file_put)(void* storage, const file_t* file, const char* path);
    int(*file_content_put)(void* storage, const file_content_t* file_content, const char* path);
    int(*file_data_put)(void* storage, const char* data, const size_t data_size, const char* path);
    int(*file_remove)(void* storage, const char* path);
    int(*file_exist)(void* storage, const char* path);
    storage_entry_e(*entry_type)(void* storage, const char* path);
    array_t*(*file_list)(void* storage, const char* path);
    /* Полный путь объекта на файловой системе. NULL у хранилищ, у которых
     * путей на ФС нет (S3): вызывающий обязан проверять указатель. */
    int(*path_resolve)(void* storage, const char* path, char* out, size_t out_size);

    struct storage* next;
} storage_t;

file_t storage_file_get(const char* storage_name, const char* path_format, ...);
int storage_file_put(const char* storage_name, file_t* file, const char* path_format, ...);
int storage_file_content_put(const char* storage_name, file_content_t* file_content, const char* path_format, ...);
int storage_file_data_put(const char* storage_name, const char* data, const size_t data_size, const char* path_format, ...);
int storage_file_remove(const char* storage_name, const char* path_format, ...);
int storage_file_exist(const char* storage_name, const char* path_format, ...);
// Тип объекта по пути. Символьные ссылки не разыменовываются: для них STORAGE_ENTRY_OTHER
storage_entry_e storage_entry_type(const char* storage_name, const char* path_format, ...);
int storage_file_duplicate(const char* from_storage_name, const char* to_storage_name, const char* path_format, ...);
array_t* storage_file_list(const char* storage_name, const char* path_format, ...);
/* Тип хранилища из ЗАДАННОГО списка. Нужен валидатору конфига: он проверяет
 * загружаемую конфигурацию, а storage_* работают с активной (appconfig()), и
 * при reload это разные списки. 1 — имя найдено. */
int storage_type_in(storage_t* list, const char* name, storage_type_e* out);
// Полный путь объекта внутри файлового хранилища. 1 — путь построен;
// 0 — хранилища нет, оно не файловое, или путь недопустим.
// Резолв отдельно от открытия: file_t хранит от пути один basename, а
// gzip_static ищет ".gz"-двойника по полному пути.
int storage_resolve_path(const char* storage_name, const char* path, char* out, size_t out_size);
void storages_free(storage_t* storage);
void storage_merge_slash(char* path);

#endif

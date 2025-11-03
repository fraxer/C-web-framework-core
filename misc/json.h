#ifndef __JSON__
#define __JSON__

#include <stddef.h>
#include <stdint.h>

#include "str.h"

// Количество токенов в одном блоке памяти
#define TOKENS_PER_BLOCK 4096

typedef struct memory_block {
    void* memory;                    // Указатель на память
    void* free_list;                 // Односвязный список свободных слотов
    size_t capacity;                 // Общее количество слотов
    size_t used_count;               // Количество используемых слотов
    struct memory_block* next;       // Следующий блок в списке
} memory_block_t;

typedef struct {
    memory_block_t* token_blocks;    // Цепочка списоков блоков для токенов
    memory_block_t* current_block;   // Кэш последнего блока с свободными слотами (оптимизация)
} json_manager_t;

typedef enum {
    JSON_OBJECT = 0,
    JSON_ARRAY,
    JSON_STRING,
    JSON_BOOL,
    JSON_NULL,
    JSON_NUMBER
} json_token_type_t;

typedef union {
    int _int;
    double _double;
    str_t _string;
} json_value_u;

typedef struct json_token {
    memory_block_t* block;           // Блок, в котором находится токен
    struct json_token* child;       // Используется для типа JSON_OBJECT или JSON_ARRAY
    struct json_token* sibling;
    struct json_token* last_sibling;
    struct json_token* parent;      // Родительский токен (для iter2 алгоритма)
    size_t size;                     // Количество элементов в массиве или ключей у объекта
    json_value_u value;             // Значение простого типа
    json_token_type_t type;         // Тип токена
} json_token_t;

typedef struct {
    json_token_t* root;
    str_t stringify;
    int ascii_mode;                  // 0 = UTF-8 mode (default), 1 = ASCII-only mode (encode all non-ASCII as \uXXXX)
} json_doc_t;

typedef struct {
    const char* json;                // указатель на начало JSON-строки
    const char* ptr;                 // указатель на текущую позицию (изначально равен json)
    const char* end;                 // указатель на конец буфера (json + strlen(json)) для защиты от buffer overread
    json_doc_t* doc;                // указатель на документ
    char* error;                     // NULL или сообщение об ошибке
    size_t json_size;                // размер JSON-строки
} json_parser_t;

typedef struct {
    json_token_t* key;
    json_token_t* value;
    json_token_t* parent;
    json_token_type_t type;
    int ok;
    int index;
} json_it_t;

// Вспомогательные функции для работы с блоками
memory_block_t* memory_block_create(size_t element_size, size_t capacity);
void memory_block_destroy(memory_block_t* block);
int memory_block_alloc_slot(memory_block_t* block, size_t* slot_index);
void memory_block_free_slot(memory_block_t* block, json_token_t* token);
int memory_block_is_empty(memory_block_t* block);
int memory_block_is_full(memory_block_t* block);


json_manager_t* json_manager_create(void);
// Инициализация менеджера токенов
void json_manager_init(json_manager_t* manager);
void json_manager_free(json_manager_t* manager);
// Освобождение менеджера токенов
void json_manager_destroy(json_manager_t* manager);
// Освобождение пустых блоков
size_t json_manager_destroy_empty_blocks(void);


// Выделение токена
json_token_t* json_token_alloc(json_token_type_t type);
// Освобождение токена
void json_token_free(json_token_t* token);

// Парсинг JSON
json_doc_t* json_parse(const char* string);
json_doc_t* json_create_empty(void);

// Освобождение памяти JSON документа
void json_clear(json_doc_t* document);
void json_free(json_doc_t* document);

/**
 * Получение значения токена
 */
json_token_t* json_root(const json_doc_t* document);
int json_bool(const json_token_t* token);
int json_int(const json_token_t* token, int* ok);
double json_double(const json_token_t* token);
long long json_llong(const json_token_t* token, int* ok);
const char* json_string(const json_token_t* token);
size_t json_string_size(const json_token_t* token);
unsigned int json_uint(const json_token_t* token, int* ok);

/**
 * Проверка типа
 */
int json_is_bool(const json_token_t* token);
int json_is_null(const json_token_t* token);
int json_is_string(const json_token_t* token);
int json_is_number(const json_token_t* token);
int json_is_object(const json_token_t* token);
int json_is_array(const json_token_t* token);

/**
 * Создание токена
 */
json_token_t* json_create_bool(int value);
json_token_t* json_create_null(void);
json_token_t* json_create_string(const char* value);
json_token_t* json_create_number(double value);
json_token_t* json_create_object(void);
json_token_t* json_create_array(void);
json_doc_t* json_root_create_object(void);
json_doc_t* json_root_create_array(void);

/**
 * Работа с массивами
 */
int json_array_prepend(json_token_t* token_array, json_token_t* token_append);
int json_array_append(json_token_t* token_array, json_token_t* token_append);
int json_array_append_to(json_token_t* token_array, int index, json_token_t* token_append);
int json_array_erase(json_token_t* token_array, int index, int count);
int json_array_clear(json_token_t* token_array);
int json_array_size(const json_token_t* token_array);
json_token_t* json_array_get(const json_token_t* token_array, int index);

/**
 * Работа с объектами
 */
int json_object_set(json_token_t* token_object, const char* key, json_token_t* token);
json_token_t* json_object_get(const json_token_t* token_object, const char* key);
int json_object_remove(json_token_t* token_object, const char* key);
int json_object_size(const json_token_t* token_object);
int json_object_clear(json_token_t* token_object);

/**
 * Изменить значение токена с типом
 */
void json_token_set_bool(json_token_t* token, int value);
void json_token_set_null(json_token_t* token);
void json_token_set_string(json_token_t* token, const char* value);
void json_token_set_llong(json_token_t* token, long long value);
void json_token_set_int(json_token_t* token, int value);
void json_token_set_uint(json_token_t* token, unsigned int value);
void json_token_set_double(json_token_t* token, double value);
void json_token_set_object(json_token_t* token, json_token_t* token_object);
void json_token_set_array(json_token_t* token, json_token_t* token_array);

/**
 * Инициализация итератора для массива и объекта
 */
json_it_t json_create_empty_it(const json_token_t* token);
int json_end_it(const json_it_t* iterator);
const void* json_it_key(const json_it_t* iterator);
json_token_t* json_it_value(const json_it_t* iterator);
json_it_t json_next_it(json_it_t* iterator);
void json_it_erase(json_it_t* iterator);

/**
 * Преобразовать JSON-документ с токенами в строку
 */
const char* json_stringify(json_doc_t* document);
size_t json_stringify_size(json_doc_t* document);
char* json_stringify_detach(json_doc_t* document);
int json_copy(json_doc_t* from, json_doc_t* to);

#endif
#ifndef __JSON2__
#define __JSON2__

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
} json2_manager_t;

typedef enum {
    JSON2_OBJECT = 0,
    JSON2_ARRAY,
    JSON2_STRING,
    JSON2_BOOL,
    JSON2_NULL,
    JSON2_NUMBER
} json2_token_type_t;

typedef union {
    int _int;
    double _double;
    str_t _string;
} json2_value_u;

typedef struct json2_token {
    memory_block_t* block;           // Блок, в котором находится токен
    struct json2_token* child;       // Используется для типа JSON_OBJECT или JSON_ARRAY
    struct json2_token* sibling;
    struct json2_token* last_sibling;
    struct json2_token* parent;      // Родительский токен (для iter2 алгоритма)
    size_t size;                     // Количество элементов в массиве или ключей у объекта
    json2_value_u value;             // Значение простого типа
    json2_token_type_t type;         // Тип токена
} json2_token_t;

typedef struct {
    json2_token_t* root;
    str_t stringify;
    int ascii_mode;                  // 0 = UTF-8 mode (default), 1 = ASCII-only mode (encode all non-ASCII as \uXXXX)
} json2_doc_t;

typedef struct {
    const char* json;                // указатель на начало JSON-строки
    const char* ptr;                 // указатель на текущую позицию (изначально равен json)
    const char* end;                 // указатель на конец буфера (json + strlen(json)) для защиты от buffer overread
    json2_doc_t* doc;                // указатель на документ
    char* error;                     // NULL или сообщение об ошибке
    size_t json_size;                // размер JSON-строки
} json2_parser_t;

typedef struct {
    json2_token_t* key;
    json2_token_t* value;
    json2_token_t* parent;
    json2_token_type_t type;
    int ok;
    int index;
} json2_it_t;

// Вспомогательные функции для работы с блоками
memory_block_t* memory_block_create(size_t element_size, size_t capacity);
void memory_block_destroy(memory_block_t* block);
int memory_block_alloc_slot(memory_block_t* block, size_t* slot_index);
void memory_block_free_slot(memory_block_t* block, json2_token_t* token);
int memory_block_is_empty(memory_block_t* block);
int memory_block_is_full(memory_block_t* block);


json2_manager_t* json2_manager_create(void);
// Инициализация менеджера токенов
void json2_manager_init(json2_manager_t* manager);
void json2_manager_free(json2_manager_t* manager);
// Освобождение менеджера токенов
void json2_manager_destroy(json2_manager_t* manager);
// Освобождение пустых блоков
size_t json2_manager_destroy_empty_blocks(void);


// Выделение токена
json2_token_t* json2_token_alloc(json2_token_type_t type);
// Освобождение токена
void json2_token_free(json2_token_t* token);

// Парсинг JSON
json2_doc_t* json2_parse(const char* string);
json2_doc_t* json2_create_empty(void);

// Освобождение памяти JSON документа
void json2_free(json2_doc_t* document);

/**
 * Получение значения токена
 */
json2_token_t* json2_root(const json2_doc_t* document);
int json2_bool(const json2_token_t* token);
int json2_int(const json2_token_t* token, int* ok);
double json2_double(const json2_token_t* token, int* ok);
long long json2_llong(const json2_token_t* token, int* ok);
const char* json2_string(const json2_token_t* token);
unsigned int json2_uint(const json2_token_t* token, int* ok);

/**
 * Проверка типа
 */
int json2_is_bool(const json2_token_t* token);
int json2_is_null(const json2_token_t* token);
int json2_is_string(const json2_token_t* token);
int json2_is_number(const json2_token_t* token);
int json2_is_object(const json2_token_t* token);
int json2_is_array(const json2_token_t* token);

/**
 * Создание токена
 */
json2_token_t* json2_create_bool(int value);
json2_token_t* json2_create_null(void);
json2_token_t* json2_create_string(const char* value);
json2_token_t* json2_create_number(double value);
json2_token_t* json2_create_object(void);
json2_token_t* json2_create_array(void);

/**
 * Работа с массивами
 */
int json2_array_prepend(json2_token_t* token_array, json2_token_t* token_append);
int json2_array_append(json2_token_t* token_array, json2_token_t* token_append);
int json2_array_append_to(json2_token_t* token_array, int index, json2_token_t* token_append);
int json2_array_erase(json2_token_t* token_array, int index, int count);
int json2_array_clear(json2_token_t* token_array);
int json2_array_size(const json2_token_t* token_array);
json2_token_t* json2_array_get(const json2_token_t* token_array, int index);

/**
 * Работа с объектами
 */
int json2_object_set(json2_token_t* token_object, const char* key, json2_token_t* token);
json2_token_t* json2_object_get(const json2_token_t* token_object, const char* key);
int json2_object_remove(json2_token_t* token_object, const char* key);
int json2_object_size(const json2_token_t* token_object);
int json2_object_clear(json2_token_t* token_object);

/**
 * Изменить значение токена с типом
 */
void json2_token_set_bool(json2_token_t* token, int value);
void json2_token_set_null(json2_token_t* token);
void json2_token_set_string(json2_token_t* token, const char* value);
void json2_token_set_llong(json2_token_t* token, long long value);
void json2_token_set_int(json2_token_t* token, int value);
void json2_token_set_uint(json2_token_t* token, unsigned int value);
void json2_token_set_double(json2_token_t* token, double value);
void json2_token_set_object(json2_token_t* token, json2_token_t* token_object);
void json2_token_set_array(json2_token_t* token, json2_token_t* token_array);

/**
 * Инициализация итератора для массива и объекта
 */
json2_it_t json2_init_it(const json2_token_t* token);
int json2_end_it(const json2_it_t* iterator);
const void* json2_it_key(const json2_it_t* iterator);
json2_token_t* json2_it_value(const json2_it_t* iterator);
json2_it_t json2_next_it(json2_it_t* iterator);
void json2_it_erase(json2_it_t* iterator);

/**
 * Преобразовать JSON-документ с токенами в строку
 */
const char* json2_stringify(json2_doc_t* document);
size_t json2_stringify_size(json2_doc_t* document);
char* json2_stringify_detach(json2_doc_t* document);
int json2_copy(json2_doc_t* from, json2_doc_t* to);

#endif
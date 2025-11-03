#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <math.h>

#include "log.h"
#include "json.h"

// Type-generic min функция (C11)
static inline int min_int(int a, int b) { return a < b ? a : b; }
static inline long min_long(long a, long b) { return a < b ? a : b; }
static inline long long min_llong(long long a, long long b) { return a < b ? a : b; }
static inline unsigned int min_uint(unsigned int a, unsigned int b) { return a < b ? a : b; }
static inline unsigned long min_ulong(unsigned long a, unsigned long b) { return a < b ? a : b; }
static inline unsigned long long min_ullong(unsigned long long a, unsigned long long b) { return a < b ? a : b; }
static inline float min_float(float a, float b) { return a < b ? a : b; }
static inline double min_double(double a, double b) { return a < b ? a : b; }

#define min(a, b) _Generic((a), \
    int: min_int, \
    long: min_long, \
    long long: min_llong, \
    unsigned int: min_uint, \
    unsigned long: min_ulong, \
    unsigned long long: min_ullong, \
    float: min_float, \
    double: min_double \
)((a), (b))

typedef enum state {
    JSON_STATE_OPEN_OBJECT,         // Открыть объект и начать обработку ключей
    JSON_STATE_PROCESS_OBJECT_KEY,  // Начать обработку ключей
    JSON_STATE_OPEN_ARRAY,          // Открыть массив и начать обработку элементов
    JSON_STATE_PROCESS_PRIMITIVE,   // Обработать примитивное значение (string, number, bool, null)
    JSON_STATE_CLOSE_CONTAINER      // Закрыть контейнер
} state_t;

static _Thread_local json_manager_t* manager = NULL;
static _Thread_local short free_blocks_counter = 0;

static const char escape_table[256] = {
    ['b'] = '\b', ['f'] = '\f', ['n'] = '\n', 
    ['r'] = '\r', ['t'] = '\t', ['"'] = '"',
    ['\\'] = '\\', ['/'] = '/'
};

static json_token_t* __parse_value(json_parser_t* parser);
static json_token_t* __parse_object(json_parser_t* parser);
static json_token_t* __parse_array(json_parser_t* parser);
static json_token_t* __parse_string(json_parser_t* parser);
static json_token_t* __parse_number(json_parser_t* parser);
static json_token_t* __parse_null(json_parser_t* parser);
static json_token_t* __parse_true(json_parser_t* parser);
static json_token_t* __parse_false(json_parser_t* parser);
static void __set_child_or_sibling(json_token_t* token_src, json_token_t* token_dst);
static void __init_token(json_token_t* token, memory_block_t* block, json_token_type_t type);

// ============================================================================
// Функции для работы с блоками памяти (free-list)
// ============================================================================

// Используем первые 8 байт каждого свободного токена для хранения указателя на следующий
typedef union {
    json_token_t token;
    void* next_free;  // Указатель на следующий свободный слот
} free_slot_t;

memory_block_t* memory_block_create(size_t element_size, size_t capacity) {
    memory_block_t* block = malloc(sizeof * block);
    if (block == NULL) return NULL;

    size_t memory_size = element_size * capacity;
    block->memory = malloc(memory_size);
    if (!block->memory) {
        free(block);
        return NULL;
    }

    block->capacity = capacity;
    block->used_count = 0;
    block->next = NULL;

    // Инициализируем free-list: создаём цепочку всех слотов
    // Каждый слот указывает на следующий: slot[0] -> slot[1] -> ... -> slot[N-1] -> NULL
    // Используем element_size для вычисления позиций слотов
    char* memory_bytes = (char*)block->memory;
    block->free_list = block->memory;  // Голова списка - первый слот

    for (size_t i = 0; i < capacity - 1; i++) {
        void** current_slot = (void**)(memory_bytes + i * element_size);
        void* next_slot = memory_bytes + (i + 1) * element_size;
        *current_slot = next_slot;
    }

    // Последний слот указывает на NULL
    void** last_slot = (void**)(memory_bytes + (capacity - 1) * element_size);
    *last_slot = NULL;

    return block;
}

void memory_block_destroy(memory_block_t* block) {
    if (block == NULL) return;

    free(block->memory);
    free(block);
}

int memory_block_alloc_slot(memory_block_t* block, size_t* slot_index) {
    if (block == NULL || block->free_list == NULL)
        return 0;

    // Берём первый свободный слот из головы списка - O(1)!
    free_slot_t* free_slot = (free_slot_t*)block->free_list;
    void* next_free = free_slot->next_free;

    // Вычисляем индекс слота
    free_slot_t* slots = (free_slot_t*)block->memory;
    *slot_index = free_slot - slots;

    // Обновляем голову списка - теперь она указывает на следующий свободный слот
    block->free_list = next_free;
    block->used_count++;

    return 1;
}

void memory_block_free_slot(memory_block_t* block, json_token_t* token) {
    if (block == NULL || token == NULL)
        return;

    // Преобразуем токен в free_slot_t и вычисляем его индекс
    free_slot_t* freed_slot = (free_slot_t*)token;

    // Освобождённый слот указывает на текущую голову списка
    freed_slot->next_free = block->free_list;

    // Теперь освобождённый слот становится новой головой списка
    block->free_list = freed_slot;
    block->used_count--;
}

int memory_block_is_empty(memory_block_t* block) {
    return block != NULL && block->used_count == 0;
}

int memory_block_is_full(memory_block_t* block) {
    return block != NULL && block->used_count == block->capacity;
}

// ============================================================================
// Функции для работы с менеджером токенов
// ============================================================================

json_manager_t* json_manager_create(void) {
    manager = malloc(sizeof * manager);
    if (manager == NULL) return NULL;

    json_manager_init(manager);

    return manager;
}

void json_manager_init(json_manager_t* manager) {
    if (manager == NULL)
        return;

    manager->token_blocks = NULL;
    manager->current_block = NULL;  // Инициализируем кэш
}

void json_manager_free(json_manager_t* manager) {
    if (manager == NULL)
        return;

    json_manager_destroy(manager);
    free(manager);
}

void json_manager_destroy(json_manager_t* manager) {
    if (manager == NULL)
        return;

    // Освобождаем все блоки
    memory_block_t* current = manager->token_blocks;
    while (current != NULL) {
        memory_block_t* next = current->next;
        memory_block_destroy(current);
        current = next;
    }

    memset(manager, 0, sizeof(json_manager_t));
}

size_t json_manager_destroy_empty_blocks(void) {
    if (manager == NULL) return 0;

    free_blocks_counter++;
    if (free_blocks_counter < 1000)
        return 0;

    free_blocks_counter = 0;

    size_t freed_blocks = 0;
    memory_block_t* current = manager->token_blocks;
    memory_block_t* prev = NULL;

    while (current) {
        memory_block_t* next = current->next;

        if (memory_block_is_empty(current)) {
            // Блок пустой, можно освободить

            // Удаляем из односвязного списка
            if (prev != NULL)
                prev->next = next;
            else
                manager->token_blocks = next;

            // Если удаляемый блок был в кэше, сбрасываем кэш
            if (manager->current_block == current)
                manager->current_block = NULL;

            // Освобождаем блок
            memory_block_destroy(current);
            freed_blocks++;

            // prev остается тем же
        } else {
            prev = current;
        }

        current = next;
    }

    return freed_blocks;
}

// ============================================================================
// Функции для работы с парсером
// ============================================================================

static inline void skip_ws(json_parser_t* parser) {
    while (*parser->ptr == ' ' || *parser->ptr == '\t' || *parser->ptr == '\n' || *parser->ptr == '\r') {
        parser->ptr++;
    }
}

json_token_t* __parse_value(json_parser_t* parser) {
    skip_ws(parser);

    // Проверка на конец строки
    if (parser->ptr >= parser->end) {
        parser->error = "Unexpected end of input";
        return NULL;
    }

    if (*parser->ptr == '\0') {
        parser->error = "Unexpected end of input";
        return NULL;
    }

    switch (*parser->ptr) {
        case 'n': return __parse_null(parser);
        case 't': return __parse_true(parser);
        case 'f': return __parse_false(parser);
        case '"': return __parse_string(parser);
        case '[': return __parse_array(parser);
        case '{': return __parse_object(parser);
        case '-':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            return __parse_number(parser);
        default:
            parser->error = "Unexpected character";
            return NULL;
    }
}

json_token_t* __parse_object(json_parser_t* parser) {
    json_token_t* token = json_token_alloc(JSON_OBJECT);
    if (token == NULL) {
        parser->error = "Out of memory";
        return NULL;
    }

    if (*parser->ptr != '{') {
        parser->error = "Expected '{'";
        return token;
    }

    parser->ptr++;

    skip_ws(parser);

    if (*parser->ptr == '}') {
        parser->ptr++;
        return token;
    }

    while (1) {
        skip_ws(parser);

        json_token_t* key = __parse_string(parser);
        if (parser->error) {
            json_token_free(key);
            return token;
        }

        __set_child_or_sibling(token, key);

        skip_ws(parser);

        if (*parser->ptr != ':') {
            parser->error = "Expected ':'";
            return token;
        }

        parser->ptr++;

        json_token_t* val = __parse_value(parser);
        if (parser->error) {
            json_token_free(val);
            return token;
        }

        __set_child_or_sibling(key, val);

        skip_ws(parser);

        if (*parser->ptr == ',') {
            parser->ptr++;
            continue;
        }
        if (*parser->ptr == '}') {
            parser->ptr++;
            break;
        }

        parser->error = "Expected ',' or '}'";
        return token;
    }

    return token;
}

json_token_t* __parse_array(json_parser_t* parser) {
    json_token_t* token = json_token_alloc(JSON_ARRAY);
    if (token == NULL) {
        parser->error = "Out of memory";
        return NULL;
    }

    if (*parser->ptr != '[') {
        parser->error = "Expected '['";
        return token;
    }
    parser->ptr++;

    skip_ws(parser);

    if (*parser->ptr == ']') {
        parser->ptr++;
        return token;
    }

    while (1) {
        json_token_t* val = __parse_value(parser);
        if (parser->error) {
            json_token_free(val);
            return token;
        }

        __set_child_or_sibling(token, val);

        skip_ws(parser);

        if (*parser->ptr == ',') {
            parser->ptr++;
            continue;
        }
        if (*parser->ptr == ']') {
            parser->ptr++;
            break;
        }

        parser->error = "Expected ',' or ']'";
        return token;
    }

    return token;
}

json_token_t* __parse_null(json_parser_t* parser) {
    json_token_t* token = json_token_alloc(JSON_NULL);
    if (token == NULL) return NULL;

    const char* expected = "null";

    for (int i = 0; i < 4; i++) {
        if (parser->ptr[i] == '\0' || parser->ptr[i] != expected[i]) {
            parser->error = "Expected 'null'";
            return token;
        }
    }

    parser->ptr += 4;

    return token;
}

json_token_t* __parse_true(json_parser_t* parser) {
    json_token_t* token = json_token_alloc(JSON_BOOL);
    if (token == NULL) return NULL;

    const char* expected = "true";

    for (int i = 0; i < 4; i++) {
        if (parser->ptr[i] == '\0' || parser->ptr[i] != expected[i]) {
            parser->error = "Expected 'true'";
            return token;
        }
    }

    token->value._int = 1;

    parser->ptr += 4;

    return token;
}

json_token_t* __parse_false(json_parser_t* parser) {
    json_token_t* token = json_token_alloc(JSON_BOOL);
    if (token == NULL) return NULL;

    const char* expected = "false";

    for (int i = 0; i < 4; i++) {
        if (parser->ptr[i] == '\0' || parser->ptr[i] != expected[i]) {
            parser->error = "Expected 'false'";
            return token;
        }
    }

    token->value._int = 0;

    parser->ptr += 5;

    return token;
}

json_token_t* __parse_number(json_parser_t* parser) {
    json_token_t* token = json_token_alloc(JSON_NUMBER);
    if (token == NULL) return NULL;

    const char* start = parser->ptr;
    char* end = NULL;

    token->value._double = strtod(start, &end);

    if (end == start) {
        parser->error = "Invalid number";
        return token;
    }

    parser->ptr = end;

    return token;
}

json_token_t* __parse_string(json_parser_t* parser) {
    json_token_t* token = json_token_alloc(JSON_STRING);
    if (token == NULL) return NULL;

    int result = 0;

    if (*parser->ptr != '"') {
        parser->error = "Expected '\"'";
        return token;
    }

    parser->ptr++;

    // Проверка, что у нас есть хотя бы один символ после открывающей кавычки
    if (parser->ptr >= parser->end) {
        parser->error = "Unterminated string (unexpected end)";
        return token;
    }

    const char* scan = parser->ptr;
    str_t* str = str_create_empty(128);
    if (str == NULL) {
        parser->error = "Out of memory";
        return token;
    }

    while (1) {
        // Проверка границ буфера ДО разыменования
        if (scan >= parser->end) {
            parser->error = "Unterminated string (unexpected end)";
            goto failed;
        }

        // Проверка конца строки
        if (*scan == '\0') {
            parser->error = "Unterminated string (unexpected null)";
            goto failed;
        }

        // Проверка закрывающей кавычки
        if (*scan == '"') {
            break;
        }

        // Проверка управляющих символов (RFC 8259: символы 0x00-0x1F должны быть экранированы)
        if ((unsigned char)*scan < 0x20) {
            parser->error = "Unescaped control character in string";
            goto failed;
        }

        if (*scan == '\\') {
            scan++;

            // Проверка границ буфера ДО разыменования
            if (scan >= parser->end) {
                parser->error = "Unterminated string (incomplete escape)";
                goto failed;
            }

            // Проверка конца строки после backslash
            if (*scan == '\0') {
                parser->error = "Unterminated string (incomplete escape)";
                goto failed;
            }

            if (*scan == 'u') {
                // Unicode escape \uXXXX
                scan++;

                // Проверка границ буфера для 4 hex-символов
                // Нужно проверить, что у нас есть минимум 4 байта: scan, scan+1, scan+2, scan+3
                if (scan + 4 > parser->end) {
                    parser->error = "Unterminated string (incomplete \\uXXXX escape)";
                    goto failed;
                }

                if (*scan == '\0') {
                    parser->error = "Unterminated string (incomplete escape)";
                    goto failed;
                }

                uint32_t codepoint = 0;
                for (int i = 0; i < 4; i++) {
                    // Дополнительная проверка границ внутри цикла
                    // if (scan >= parser->end) {
                    //     parser->error = "Unterminated string (incomplete \\uXXXX escape)";
                    //     goto failed;
                    // }

                    if (*scan == '\0') {
                        parser->error = "Unterminated string (incomplete \\uXXXX escape)";
                        goto failed;
                    }

                    char c = *scan;
                    scan++;
                    codepoint <<= 4;

                    if (c >= '0' && c <= '9') codepoint |= c - '0';
                    else if (c >= 'a' && c <= 'f') codepoint |= c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') codepoint |= c - 'A' + 10;
                    else {
                        parser->error = "Invalid hex digit in \\uXXXX escape";
                        goto failed;
                    }
                }

                // RFC 8259: Обработка суррогатных пар UTF-16 (0xD800-0xDFFF)
                if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
                    // High surrogate (0xD800-0xDBFF)
                    // Должен следовать low surrogate в виде \uXXXX
                    uint32_t high_surrogate = codepoint;

                    // Проверяем, что следом идет \u
                    if (scan + 2 > parser->end) {
                        parser->error = "Invalid surrogate pair (incomplete)";
                        goto failed;
                    }

                    if (*scan != '\\' || *(scan + 1) != 'u') {
                        parser->error = "Invalid surrogate pair (expected \\uXXXX after high surrogate)";
                        goto failed;
                    }

                    scan += 2; // Пропускаем \u

                    // Проверка границ для следующих 4 hex-символов
                    if (scan + 4 > parser->end) {
                        parser->error = "Invalid surrogate pair (incomplete low surrogate)";
                        goto failed;
                    }

                    // Читаем low surrogate
                    uint32_t low_surrogate = 0;
                    for (int i = 0; i < 4; i++) {
                        // if (scan >= parser->end) {
                        //     parser->error = "Invalid surrogate pair (incomplete low surrogate)";
                        //     goto failed;
                        // }

                        if (*scan == '\0') {
                            parser->error = "Invalid surrogate pair (incomplete low surrogate)";
                            goto failed;
                        }

                        char c = *scan;
                        scan++;
                        low_surrogate <<= 4;

                        if (c >= '0' && c <= '9') low_surrogate |= c - '0';
                        else if (c >= 'a' && c <= 'f') low_surrogate |= c - 'a' + 10;
                        else if (c >= 'A' && c <= 'F') low_surrogate |= c - 'A' + 10;
                        else {
                            parser->error = "Invalid hex digit in surrogate pair";
                            goto failed;
                        }
                    }

                    // Проверяем, что low_surrogate находится в правильном диапазоне
                    if (low_surrogate < 0xDC00 || low_surrogate > 0xDFFF) {
                        parser->error = "Invalid surrogate pair (expected low surrogate 0xDC00-0xDFFF)";
                        goto failed;
                    }

                    // Декодируем суррогатную пару в полный Unicode кодпоинт
                    // Формула: 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                    codepoint = 0x10000 + ((high_surrogate - 0xD800) << 10) + (low_surrogate - 0xDC00);

                } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
                    // Low surrogate без предшествующего high surrogate - ошибка
                    parser->error = "Invalid surrogate pair (unexpected low surrogate)";
                    goto failed;
                }

                // Конвертация в UTF-8 с валидацией
                if (codepoint < 0x80) {
                    // 1-байтовая UTF-8 последовательность (ASCII)
                    str_appendc(str, codepoint);
                } else if (codepoint < 0x800) {
                    // 2-байтовая UTF-8 последовательность
                    str_appendc(str, 0xC0 | (codepoint >> 6));
                    str_appendc(str, 0x80 | (codepoint & 0x3F));
                } else if (codepoint < 0x10000) {
                    // 3-байтовая UTF-8 последовательность
                    str_appendc(str, 0xE0 | (codepoint >> 12));
                    str_appendc(str, 0x80 | ((codepoint >> 6) & 0x3F));
                    str_appendc(str, 0x80 | (codepoint & 0x3F));
                } else if (codepoint <= 0x10FFFF) {
                    // 4-байтовая UTF-8 последовательность
                    str_appendc(str, 0xF0 | (codepoint >> 18));
                    str_appendc(str, 0x80 | ((codepoint >> 12) & 0x3F));
                    str_appendc(str, 0x80 | ((codepoint >> 6) & 0x3F));
                    str_appendc(str, 0x80 | (codepoint & 0x3F));
                } else {
                    parser->error = "Invalid Unicode codepoint (out of range)";
                    goto failed;
                }
            } else {
                // Все escape-последовательности обрабатываются через lookup table
                char escaped = escape_table[(uint8_t)*scan];
                if (escaped) {
                    str_appendc(str, escaped);
                    scan++;
                } else {
                    // Неизвестная escape-последовательность
                    parser->error = "Invalid escape sequence";
                    goto failed;
                }
            }
        } else {
            // Обычный символ - валидация UTF-8 на лету
            unsigned char c = (unsigned char)*scan;

            if (c < 0x80) {
                // ASCII символ
                str_appendc(str, c);
                scan++;
            } else if ((c & 0xE0) == 0xC0) {
                // 2-байтовая UTF-8 последовательность (RFC 3629)

                // Проверка на недопустимые байты (0xC0, 0xC1 - overlong encodings)
                if (c < 0xC2) {
                    parser->error = "Invalid UTF-8 sequence (overlong encoding)";
                    goto failed;
                }

                // Проверка границ буфера ДО разыменования
                // Нужен доступ к scan+1, поэтому проверяем scan + 2 > end
                if (scan + 2 > parser->end) {
                    parser->error = "Invalid UTF-8 sequence (unexpected end)";
                    goto failed;
                }

                // Проверка корректности продолжающего байта
                unsigned char next = (unsigned char)*(scan + 1);
                if (next == '\0' || next == '"' || (next & 0xC0) != 0x80) {
                    parser->error = "Invalid UTF-8 sequence (invalid continuation byte)";
                    goto failed;
                }

                str_appendc(str, *scan++);
                str_appendc(str, *scan++);
            } else if ((c & 0xF0) == 0xE0) {
                // 3-байтовая UTF-8 последовательность (RFC 3629)

                // Проверка границ буфера ДО разыменования
                // Нужен доступ к scan+1 и scan+2, поэтому проверяем scan + 3 > end
                if (scan + 3 > parser->end) {
                    parser->error = "Invalid UTF-8 sequence (unexpected end)";
                    goto failed;
                }

                // Проверка корректности продолжающих байтов
                unsigned char next1 = (unsigned char)*(scan + 1);
                unsigned char next2 = (unsigned char)*(scan + 2);

                if (next1 == '\0' || next1 == '"' || (next1 & 0xC0) != 0x80) {
                    parser->error = "Invalid UTF-8 sequence (invalid continuation byte)";
                    goto failed;
                }

                if (next2 == '\0' || next2 == '"' || (next2 & 0xC0) != 0x80) {
                    parser->error = "Invalid UTF-8 sequence (invalid continuation byte)";
                    goto failed;
                }

                // Проверка на overlong encoding (RFC 3629)
                uint32_t codepoint = ((c & 0x0F) << 12) |
                                     ((next1 & 0x3F) << 6) |
                                     (next2 & 0x3F);
                if (codepoint < 0x800) {
                    parser->error = "Invalid UTF-8 sequence (overlong encoding)";
                    goto failed;
                }

                // Проверка на UTF-16 суррогаты (0xD800-0xDFFF) - RFC 3629
                if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
                    parser->error = "Invalid UTF-8 sequence (UTF-16 surrogate)";
                    goto failed;
                }

                str_appendc(str, *scan++);
                str_appendc(str, *scan++);
                str_appendc(str, *scan++);
            } else if ((c & 0xF8) == 0xF0) {
                // 4-байтовая UTF-8 последовательность (RFC 3629)

                // Проверка на недопустимые байты (0xF5-0xFF выходят за пределы Unicode)
                if (c > 0xF4) {
                    parser->error = "Invalid UTF-8 sequence (byte out of range)";
                    goto failed;
                }

                // Проверка границ буфера ДО разыменования
                // Нужен доступ к scan+1, scan+2, scan+3, поэтому проверяем scan + 4 > end
                if (scan + 4 > parser->end) {
                    parser->error = "Invalid UTF-8 sequence (unexpected end)";
                    goto failed;
                }

                // Проверка корректности продолжающих байтов
                unsigned char next1 = (unsigned char)*(scan + 1);
                unsigned char next2 = (unsigned char)*(scan + 2);
                unsigned char next3 = (unsigned char)*(scan + 3);

                if (next1 == '\0' || next1 == '"' || (next1 & 0xC0) != 0x80) {
                    parser->error = "Invalid UTF-8 sequence (invalid continuation byte)";
                    goto failed;
                }

                if (next2 == '\0' || next2 == '"' || (next2 & 0xC0) != 0x80) {
                    parser->error = "Invalid UTF-8 sequence (invalid continuation byte)";
                    goto failed;
                }

                if (next3 == '\0' || next3 == '"' || (next3 & 0xC0) != 0x80) {
                    parser->error = "Invalid UTF-8 sequence (invalid continuation byte)";
                    goto failed;
                }

                // Проверка на overlong encoding и допустимый диапазон Unicode (RFC 3629)
                uint32_t codepoint = ((c & 0x07) << 18) |
                                     ((next1 & 0x3F) << 12) |
                                     ((next2 & 0x3F) << 6) |
                                     (next3 & 0x3F);
                if (codepoint < 0x10000) {
                    parser->error = "Invalid UTF-8 sequence (overlong encoding)";
                    goto failed;
                }
                if (codepoint > 0x10FFFF) {
                    parser->error = "Invalid UTF-8 sequence (codepoint out of range)";
                    goto failed;
                }

                str_appendc(str, *scan++);
                str_appendc(str, *scan++);
                str_appendc(str, *scan++);
                str_appendc(str, *scan++);
            } else {
                // Неправильный UTF-8 байт (0x80-0xBF без начала последовательности,
                // или 0xC0-0xC1, или 0xF5-0xFF)
                parser->error = "Invalid UTF-8 sequence (invalid start byte)";
                goto failed;
            }
        }
    }

    // Проверка, что строка завершена корректно
    if (*scan != '"') {
        parser->error = "Unterminated string";
        goto failed;
    }

    // Move string data into embedded structure
    str_move(str, &token->value._string);
    str_free(str);  // Free the temporary structure

    parser->ptr = scan + 1;

    result = 1;

    failed:

    if (result == 0) {
        str_free(str);
    }

    return token;
}

void __set_child_or_sibling(json_token_t* token_src, json_token_t* token_dst) {
    if (!token_src->child)
        token_src->child = token_dst;
    else
        token_src->last_sibling->sibling = token_dst;

    token_src->last_sibling = token_dst;

    // Устанавливаем parent для token_dst
    token_dst->parent = token_src;

    if (token_src->type == JSON_OBJECT || token_src->type == JSON_ARRAY)
        token_src->size++;
}

void __init_token(json_token_t* token, memory_block_t* block, json_token_type_t type) {
    token->block = block;
    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->size = 0;
    token->type = type;

    // Initialize union based on type
    if (type == JSON_STRING) {
        // Initialize embedded str_t structure
        str_init(&token->value._string, 0);
    } else {
        // For other types, just zero out the value
        token->value._int = 0;
    }
}

// ============================================================================
// Функции для работы с json
// ============================================================================

json_doc_t* json_parse(const char* json_str) {
    // Инициализация глобального менеджера при первом использовании
    if (manager == NULL) {
        manager = json_manager_create();
        if (manager == NULL) {
            return NULL;
        }
    }

    json_doc_t* doc = malloc(sizeof * doc);
    if (doc == NULL) return NULL;

    doc->root = NULL;
    doc->ascii_mode = 0;  // По умолчанию UTF-8 режим
    str_init(&doc->stringify, 4096);

    const size_t json_size = strlen(json_str);

    json_parser_t parser = {
        .json = json_str,
        .ptr = json_str,
        .end = json_str + json_size,
        .doc = doc,
        .error = NULL,
        .json_size = json_size
    };

    json_token_t* toksuper = NULL;   // Текущий родительский токен
    json_token_t* last_token = NULL; // Последний добавленный токен
    size_t pos = 0;

    // Основной цикл парсинга - проходим по каждому символу
    for (pos = 0; pos < json_size && json_str[pos] != '\0'; pos++) {
        char c = json_str[pos];
        parser.ptr = json_str + pos;

        switch (c) {
            case '{':
            case '[': {
                // Создаем токен для объекта или массива
                json_token_t* token = json_token_alloc(
                    c == '{' ? JSON_OBJECT : JSON_ARRAY
                );
                if (!token) {
                    parser.error = "Out of memory";
                    goto failed;
                }

                // Добавляем токен к родителю
                if (toksuper) {
                    // В строгом режиме объект/массив не может быть ключом
                    if (toksuper->type == JSON_OBJECT) {
                        parser.error = "Object/array cannot be a key";
                        goto failed;
                    }

                    token->parent = toksuper;
                    __set_child_or_sibling(toksuper, token);
                }

                // Если это первый токен - это корень
                if (doc->root == NULL) {
                    doc->root = token;
                }

                // Запоминаем последний токен
                last_token = token;

                // Этот токен становится новым родителем
                toksuper = token;
                break;
            }

            case '}':
            case ']': {
                json_token_type_t expected_type = (c == '}' ? JSON_OBJECT : JSON_ARRAY);

                // Проверяем текущий родитель
                if (!toksuper) {
                    parser.error = "Unexpected closing bracket";
                    goto failed;
                }

                // Поднимаемся по цепочке родителей, пока не найдём нужный контейнер
                json_token_t* container = toksuper;
                while (container && container->type != expected_type) {
                    // Если в объекте, то toksuper может указывать на ключ
                    // Нужно подняться к родительскому объекту
                    if (container->parent && container->parent->type == expected_type) {
                        container = container->parent;
                        break;
                    }
                    container = container->parent;
                }

                if (!container || container->type != expected_type) {
                    parser.error = "Mismatched brackets";
                    goto failed;
                }

                // Закрываем найденный контейнер и поднимаемся к его родителю
                toksuper = container->parent;
                break;
            }

            case '"': {
                // Используем существующую функцию парсинга строк
                parser.ptr = json_str + pos;
                json_token_t* token = __parse_string(&parser);

                if (parser.error) {
                    json_token_free(token);
                    goto failed;
                }

                // Обновляем позицию в цикле
                pos = parser.ptr - json_str - 1;  // -1 потому что цикл добавит +1

                // Добавляем к родителю
                if (toksuper) {
                    token->parent = toksuper;
                    __set_child_or_sibling(toksuper, token);
                }

                // Если это первый токен - это корень
                if (doc->root == NULL) {
                    doc->root = token;
                }

                // Запоминаем последний токен
                last_token = token;
                break;
            }

            case '\t':
            case '\r':
            case '\n':
            case ' ':
                // Пропускаем пробельные символы
                break;

            case ':':
                // После двоеточия следует значение для ключа
                // Последний токен (ключ) становится родителем для значения
                if (last_token) {
                    toksuper = last_token;
                }
                break;

            case ',':
                // Запятая разделяет элементы
                // Поднимаемся к родителю, если мы не в массиве/объекте
                if (toksuper &&
                    toksuper->type != JSON_ARRAY &&
                    toksuper->type != JSON_OBJECT) {
                    toksuper = toksuper->parent;
                }
                break;

            // Примитивы: числа и boolean
            case '-':
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
            case 't':
            case 'f':
            case 'n': {
                // Примитив не может быть ключом объекта
                if (toksuper && toksuper->type == JSON_OBJECT) {
                    parser.error = "Primitive cannot be a key";
                    goto failed;
                }

                json_token_t* token = NULL;
                // Парсим примитив
                parser.ptr = json_str + pos;

                if (c == 't' || c == 'f') {
                    token = (c == 't') ?
                        __parse_true(&parser) : __parse_false(&parser);

                    if (parser.error) {
                        json_token_free(token);
                        goto failed;
                    }
                } else if (c == 'n') {
                    token = __parse_null(&parser);

                    if (parser.error) {
                        json_token_free(token);
                        goto failed;
                    }
                } else {
                    // Число
                    token = __parse_number(&parser);

                    if (parser.error) {
                        json_token_free(token);
                        goto failed;
                    }
                }

                // Обновляем позицию в цикле
                pos = parser.ptr - json_str - 1;  // -1 потому что цикл добавит +1

                // Добавляем к родителю
                if (toksuper) {
                    token->parent = toksuper;
                    __set_child_or_sibling(toksuper, token);
                }

                // Если это первый токен - это корень
                if (doc->root == NULL) {
                    doc->root = token;
                }

                // Запоминаем последний токен
                last_token = token;
                break;
            }

            default:
                parser.error = "Unexpected character";
                goto failed;
        }
    }

    // Проверяем, что все контейнеры закрыты
    if (toksuper != NULL) {
        parser.error = "Unclosed object or array";
        goto failed;
    }

    return doc;

    failed:

    if (parser.error) {
        log_error("JSON Error: %s\n    %.*s\n    ^\n",
                 parser.error,
                 min(15, parser.end - parser.ptr),
                 parser.ptr);
    }

    json_free(doc);

    return NULL;
}

json_doc_t* json_create_empty(void) {
    // Инициализация глобального менеджера при первом использовании
    if (manager == NULL) {
        manager = json_manager_create();
        if (manager == NULL) {
            return NULL;
        }
    }

    json_doc_t* doc = malloc(sizeof * doc);
    if (doc == NULL) return NULL;

    doc->root = NULL;
    doc->ascii_mode = 0;  // По умолчанию UTF-8 режим
    str_init(&doc->stringify, 4096);

    return doc;
}

json_token_t* json_token_alloc(json_token_type_t type) {
    // Инициализация глобального менеджера при первом использовании
    if (manager == NULL) {
        manager = json_manager_create();
        if (manager == NULL) {
            return NULL;
        }
    }

    memory_block_t* block = NULL;
    size_t slot_index = 0;
    json_token_t* token = NULL;

    // 1. ОПТИМИЗАЦИЯ: Сначала пробуем кэшированный блок - O(1) в 99% случаев!
    if (manager->current_block && !memory_block_is_full(manager->current_block)) {
        if (memory_block_alloc_slot(manager->current_block, &slot_index)) {
            block = manager->current_block;
            goto found_slot;
        }
    }

    // 2. Кэш не сработал - ищем блок со свободными слотами
    block = manager->token_blocks;
    while (block) {
        if (!memory_block_is_full(block)) {
            if (memory_block_alloc_slot(block, &slot_index)) {
                manager->current_block = block;  // Обновляем кэш!
                goto found_slot;
            }
        }
        block = block->next;
    }

    // 3. Не нашли свободный слот - создаём новый блок
    block = memory_block_create(sizeof(json_token_t), TOKENS_PER_BLOCK);
    if (block == NULL) return NULL;

    // Добавляем блок в начало списка
    block->next = manager->token_blocks;
    manager->token_blocks = block;
    manager->current_block = block;  // Обновляем кэш!

    // Выделяем первый слот в новом блоке
    if (!memory_block_alloc_slot(block, &slot_index))
        return NULL;

    found_slot:

    // Инициализируем токен
    token = (json_token_t*)block->memory + slot_index;
    __init_token(token, block, type);

    return token;
}

void json_token_free(json_token_t* token) {
    if (!manager || !token || !token->block)
        return;

    // Очистить содержимое токена
    if (token->type == JSON_STRING)
        str_clear(&token->value._string);

    // Освобождаем слот в блоке
    memory_block_free_slot(token->block, token);

    // ОПТИМИЗАЦИЯ: Если блок стал не полным, кэшируем его для быстрой аллокации
    if (!memory_block_is_full(token->block))
        manager->current_block = token->block;

    json_manager_destroy_empty_blocks();
}

// Рекурсивная функция для освобождения дерева токенов
static void __free_token_tree(json_token_t* token) {
    if (token == NULL) return;

    // Сохраняем ссылки на child и sibling перед обнулением
    json_token_t* child = token->child;
    json_token_t* sibling = token->sibling;
    memory_block_t* block = token->block;

    // Освобождаем значение токена (если это строка)
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    // Обнуляем все поля токена
    token->block = NULL;
    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->size = 0;
    token->value._int = 0;
    token->type = 0;

    // Помечаем слот как свободный в блоке памяти
    if (block != NULL) {
        memory_block_free_slot(block, token);
    }

    // Рекурсивно освобождаем дочерние токены
    __free_token_tree(child);

    // Рекурсивно освобождаем сиблингов
    __free_token_tree(sibling);
}

void json_clear(json_doc_t* document) {
    if (document == NULL) return;

    // Освобождаем дерево токенов
    __free_token_tree(document->root);
    document->root = NULL;

    // Освобождаем буфер stringify
    str_clear(&document->stringify);
}

void json_free(json_doc_t* document) {
    if (document == NULL) return;

    json_clear(document);
    free(document);
}

json_token_t* json_root(const json_doc_t* document) {
    if (document == NULL) return NULL;

    return document->root;
}

int json_bool(const json_token_t* token) {
    if (token == NULL) return 0;

    return token->value._int;
}

int json_int(const json_token_t* token, int* ok) {
    // Проверка на NULL
    if (token == NULL) {
        if (ok) *ok = 0;
        return 0;
    }

    // Проверка типа токена
    if (token->type != JSON_NUMBER) {
        if (ok) *ok = 0;
        return 0;
    }

    double val = token->value._double;

    // Проверка на NaN (Not a Number)
    if (isnan(val)) {
        if (ok) *ok = 0;
        return 0;
    }

    // Проверка на бесконечность
    if (isinf(val)) {
        if (ok) *ok = 0;
        // Если +бесконечность, возвращаем максимальное значение
        // Если -бесконечность, возвращаем минимальное значение
        return (val > 0) ? INT_MAX : INT_MIN;
    }

    // Проверка на переполнение int (сверху)
    if (val > (double)INT_MAX) {
        if (ok) *ok = 0;
        return INT_MAX;
    }

    // Проверка на переполнение int (снизу)
    if (val < (double)INT_MIN) {
        if (ok) *ok = 0;
        return INT_MIN;
    }

    // Успешная конвертация
    if (ok) *ok = 1;
    // Безопасная конвертация с округлением вниз
    return (int)val;
}

double json_double(const json_token_t* token) {
    if (token == NULL)
        return 0.0;

    if (token->type != JSON_NUMBER)
        return 0.0;

    return token->value._double;
}

long long json_llong(const json_token_t* token, int* ok) {
    // Проверка на NULL
    if (token == NULL) {
        if (ok) *ok = 0;
        return 0;
    }

    // Проверка типа токена
    if (token->type != JSON_NUMBER) {
        if (ok) *ok = 0;
        return 0;
    }

    double val = token->value._double;

    // Проверка на NaN (Not a Number)
    if (isnan(val)) {
        if (ok) *ok = 0;
        return 0;
    }

    // Проверка на бесконечность
    if (isinf(val)) {
        if (ok) *ok = 0;
        // Если +бесконечность, возвращаем максимальное значение
        // Если -бесконечность, возвращаем минимальное значение
        return (val > 0) ? LLONG_MAX : LLONG_MIN;
    }

    // Проверка на переполнение long long (сверху)
    if (val > (double)LLONG_MAX) {
        if (ok) *ok = 0;
        return LLONG_MAX;
    }

    // Проверка на переполнение long long (снизу)
    if (val < (double)LLONG_MIN) {
        if (ok) *ok = 0;
        return LLONG_MIN;
    }

    // Успешная конвертация
    if (ok) *ok = 1;
    // Безопасная конвертация с округлением вниз
    return (long long)val;
}

const char* json_string(const json_token_t* token) {
    if (token == NULL) return NULL;

    return str_get((str_t*)&token->value._string);
}

size_t json_string_size(const json_token_t* token) {
    if (token == NULL) return 0;

    return str_size(&token->value._string);
}

unsigned int json_uint(const json_token_t* token, int* ok) {
    // Проверка на NULL
    if (token == NULL) {
        if (ok) *ok = 0;
        return 0;
    }

    // Проверка типа токена
    if (token->type != JSON_NUMBER) {
        if (ok) *ok = 0;
        return 0;
    }

    double val = token->value._double;

    // Проверка на NaN (Not a Number)
    if (isnan(val)) {
        if (ok) *ok = 0;
        return 0;
    }

    // Проверка на бесконечность
    if (isinf(val)) {
        if (ok) *ok = 0;
        // Если +бесконечность, возвращаем максимальное значение
        // Если -бесконечность, возвращаем 0
        return (val > 0) ? UINT_MAX : 0;
    }

    // Проверка на отрицательные значения
    if (val < 0) {
        if (ok) *ok = 0;
        return 0;
    }

    // Проверка на переполнение unsigned int
    if (val > (double)UINT_MAX) {
        if (ok) *ok = 0;
        return UINT_MAX;
    }

    // Успешная конвертация
    if (ok) *ok = 1;
    // Безопасная конвертация с округлением вниз
    return (unsigned int)val;
}

int json_is_bool(const json_token_t* token) {
    if (token == NULL) return 0;

    return token->type == JSON_BOOL;
}

int json_is_null(const json_token_t* token) {
    if (token == NULL) return 0;

    return token->type == JSON_NULL;
}

int json_is_string(const json_token_t* token) {
    if (token == NULL) return 0;

    return token->type == JSON_STRING;
}

int json_is_number(const json_token_t* token) {
    if (token == NULL) return 0;

    return token->type == JSON_NUMBER;
}

int json_is_object(const json_token_t* token) {
    if (token == NULL) return 0;

    return token->type == JSON_OBJECT;
}

int json_is_array(const json_token_t* token) {
    if (token == NULL) return 0;

    return token->type == JSON_ARRAY;
}

json_token_t* json_create_bool(int value) {
    json_token_t* token = json_token_alloc(JSON_BOOL);
    if (token == NULL) return NULL;

    token->value._int = value ? 1 : 0;

    return token;
}

json_token_t* json_create_null(void) {
    json_token_t* token = json_token_alloc(JSON_NULL);
    if (token == NULL) return NULL;

    token->value._int = 0;

    return token;
}

json_token_t* json_create_string(const char* value) {
    if (value == NULL) return NULL;

    json_token_t* token = json_token_alloc(JSON_STRING);
    if (token == NULL) return NULL;

    // Инициализируем str_t структуру
    str_init(&token->value._string, 64);

    // Присваиваем значение строки
    size_t len = strlen(value);
    if (str_assign(&token->value._string, value, len) == 0) {
        // str_assign вернул 0 - ошибка
        json_token_free(token);
        return NULL;
    }

    return token;
}

json_token_t* json_create_number(double value) {
    json_token_t* token = json_token_alloc(JSON_NUMBER);
    if (token == NULL) return NULL;

    token->value._double = value;

    return token;
}

json_token_t* json_create_object(void) {
    return json_token_alloc(JSON_OBJECT);
}

json_token_t* json_create_array(void) {
    return json_token_alloc(JSON_ARRAY);
}

json_doc_t* json_root_create_object(void) {
    json_doc_t* doc = json_create_empty();
    if (doc == NULL) return NULL;

    json_token_t* token = json_create_array();
    if (token == NULL) {
        json_free(doc);
        return NULL;
    }

    doc->root = token;

    return doc;
}

json_doc_t* json_root_create_array(void) {
    json_doc_t* doc = json_create_empty();
    if (doc == NULL) return NULL;

    json_token_t* token = json_create_object();
    if (token == NULL) {
        json_free(doc);
        return NULL;
    }

    doc->root = token;

    return doc;
}

int json_array_prepend(json_token_t* token_array, json_token_t* token_append) {
    if (token_array == NULL || token_append == NULL) return 0;

    return json_array_append_to(token_array, 0, token_append);
}

int json_array_append(json_token_t* token_array, json_token_t* token_append) {
    if (token_array == NULL || token_append == NULL) return 0;

    __set_child_or_sibling(token_array, token_append);

    return 1;
}

int json_array_append_to(json_token_t* token_array, int index, json_token_t* token_append) {
    if (token_array == NULL || token_append == NULL) return 0;

    json_token_t* token = token_array->child;
    if (token == NULL) {
        token_array->child = token_append;
        token_array->last_sibling = token_append;
        token_array->size = 1;
        return 1;
    }

    json_token_t* token_prev = NULL;
    int find_index = 0;
    int i = 0;
    while (token) {
        if (i == index) {
            find_index = 1;

            if (token_prev == NULL)
                token_array->child = token_append;
            else
                token_prev->sibling = token_append;

            token_append->sibling = token;
            token_array->size++;
            break;
        }

        token_prev = token;
        token = token->sibling;
        i++;
    }

    if (!find_index || (i < index)) {
        __set_child_or_sibling(token_array, token_append);
    }

    return 1;
}

int json_array_erase(json_token_t* token_array, int index, int count) {
    if (token_array == NULL) return 0;

    json_token_t* token = token_array->child;
    if (token == NULL) return 1;
    if (count == 0) return 0;
    if (index < 0 || index >= (int)token_array->size) return 0;

    json_token_t* token_prev = NULL;
    json_token_t* token_start = NULL;
    int find_index = 0;
    int i = 0;
    while (token) {
        if (i == index) {
            find_index = 1;
            if (token_prev)
                token_start = token_prev;
        }
        else if (find_index) {
            if (count == i - index) break;
        }

        token_prev = token;
        token = token->sibling;
        i++;
    }

    if (!find_index) return 0;

    if (token_start == NULL)
        token_array->child = token;
    else
        token_start->sibling = token;

    token_array->size = token_array->size - (i - index);

    return 1;
}

int json_array_clear(json_token_t* token_array) {
    if (token_array == NULL) return 0;

    token_array->child = NULL;
    token_array->last_sibling = NULL;
    token_array->size = 0;
    return 1;
}

int json_array_size(const json_token_t* token_array) {
    if (token_array == NULL) return 0;

    return token_array->size;
}

json_token_t* json_array_get(const json_token_t* token_array, int index) {
    if (token_array == NULL) return NULL;

    json_token_t* token = token_array->child;
    if (token == NULL) return NULL;

    int i = 0;
    while (token) {
        if (i == index) return token;

        token = token->sibling;
        i++;
    }

    return NULL;
}

int json_object_set(json_token_t* token_object, const char* key, json_token_t* token) {
    if (token_object == NULL || key == NULL || token == NULL) return 0;

    json_token_t* token_key = json_create_string(key);
    if (token_key == NULL) return 0;

    __set_child_or_sibling(token_key, token);
    __set_child_or_sibling(token_object, token_key);

    return 1;
}

json_token_t* json_object_get(const json_token_t* token_object, const char* key) {
    if (token_object == NULL || key == NULL) return NULL;

    json_token_t* token = token_object->child;
    if (token == NULL) return NULL;

    while (token) {
        const char* token_key = json_string(token);
        if (token_key && strcmp(token_key, key) == 0) {
            return token->child;
        }

        token = token->sibling;
    }

    return NULL;
}

int json_object_remove(json_token_t* token_object, const char* key) {
    if (token_object == NULL || key == NULL) return 0;

    json_token_t* token_prev = NULL;
    json_token_t* token = token_object->child;
    if (token == NULL) return 0;

    while (token) {
        const char* token_key = json_string(token);
        if (token_key && strcmp(token_key, key) == 0) {
            if (token_prev)
                token_prev->sibling = token->sibling;
            else
                token_object->child = token->sibling;

            token_object->size--;
            return 1;
        }

        token_prev = token;
        token = token->sibling;
    }

    return 0;
}

int json_object_size(const json_token_t* token_object) {
    if (token_object == NULL) return 0;

    return token_object->size;
}

int json_object_clear(json_token_t* token_object) {
    if (token_object == NULL) return 0;

    token_object->child = NULL;
    token_object->last_sibling = NULL;
    token_object->size = 0;
    return 1;
}

// ============================================================================
// Функции для изменения значения токена
// ============================================================================

void json_token_set_bool(json_token_t* token, int value) {
    if (token == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->type = JSON_BOOL;
    token->size = 0;
    token->value._int = value ? 1 : 0;
}

void json_token_set_null(json_token_t* token) {
    if (token == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->type = JSON_NULL;
    token->size = 0;
    token->value._int = 0;
}

void json_token_set_string(json_token_t* token, const char* value) {
    if (token == NULL || value == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    } else {
        // Обнуляем union для безопасности
        token->value._int = 0;
    }

    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->type = JSON_STRING;
    token->size = 0;

    // Инициализируем строку
    str_init(&token->value._string, 64);
    size_t len = strlen(value);
    str_assign(&token->value._string, value, len);
}

void json_token_set_llong(json_token_t* token, long long value) {
    if (token == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->type = JSON_NUMBER;
    token->size = 0;
    token->value._double = (double)value;
}

void json_token_set_int(json_token_t* token, int value) {
    if (token == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->type = JSON_NUMBER;
    token->size = 0;
    token->value._double = (double)value;
}

void json_token_set_uint(json_token_t* token, unsigned int value) {
    if (token == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->type = JSON_NUMBER;
    token->size = 0;
    token->value._double = (double)value;
}

void json_token_set_double(json_token_t* token, double value) {
    if (token == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    token->child = NULL;
    token->sibling = NULL;
    token->last_sibling = NULL;
    token->parent = NULL;
    token->type = JSON_NUMBER;
    token->size = 0;
    token->value._double = value;
}

void json_token_set_object(json_token_t* token, json_token_t* token_object) {
    if (token == NULL || token_object == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    token->child = token_object->child;
    token->last_sibling = token_object->last_sibling;
    token->parent = NULL;
    token->type = JSON_OBJECT;
    token->size = token_object->size;
    token->value._int = 0;
}

void json_token_set_array(json_token_t* token, json_token_t* token_array) {
    if (token == NULL || token_array == NULL) return;

    // Очищаем старое значение если это была строка
    if (token->type == JSON_STRING) {
        str_clear(&token->value._string);
    }

    token->child = token_array->child;
    token->last_sibling = token_array->last_sibling;
    token->parent = NULL;
    token->type = JSON_ARRAY;
    token->size = token_array->size;
    token->value._int = 0;
}

// ============================================================================
// Функции для работы с итератором
// ============================================================================

json_it_t json_init_it(const json_token_t* token) {
    json_it_t it = {
        .ok = 0,
        .index = 0,
        .type = JSON_NULL,
        .key = NULL,
        .value = NULL,
        .parent = NULL
    };

    if (token == NULL) return it;

    it.ok = 1;
    it.index = 0;
    it.type = token->type;
    it.key = token->child;
    it.parent = (json_token_t*)token;

    if (token->type == JSON_OBJECT) {
        if (token->child) {
            it.value = token->child->child;
        }
    }
    else if (token->type == JSON_ARRAY) {
        it.value = token->child;
    }
    else {
        it.ok = 0;
    }

    return it;
}

int json_end_it(const json_it_t* iterator) {
    if (iterator == NULL) return 1;
    if (iterator->parent == NULL) return 1;

    return iterator->index == (int)iterator->parent->size;
}

const void* json_it_key(const json_it_t* iterator) {
    if (iterator == NULL)
        return NULL;

    if (iterator->type == JSON_OBJECT)
        return json_string(iterator->key);
    else if (iterator->type == JSON_ARRAY)
        return &iterator->index;

    return NULL;
}

json_token_t* json_it_value(const json_it_t* iterator) {
    if (iterator == NULL) return NULL;

    return iterator->value;
}

json_it_t json_next_it(json_it_t* iterator) {
    if (iterator == NULL) return (json_it_t){0};

    iterator->index++;

    if (json_end_it(iterator)) return *iterator;

    iterator->key = iterator->key->sibling;

    if (iterator->type == JSON_OBJECT)
        iterator->value = iterator->key->child;
    else if (iterator->type == JSON_ARRAY)
        iterator->value = iterator->key;

    return *iterator;
}

void json_it_erase(json_it_t* iterator) {
    if (iterator == NULL) return;

    if (iterator->type == JSON_OBJECT) {
        const char* key = json_string(iterator->key);
        if (key) {
            json_object_remove(iterator->parent, key);
        }
    }
    else if (iterator->type == JSON_ARRAY) {
        json_array_erase(iterator->parent, iterator->index, 1);
    }

    iterator->index--;
}

// ============================================================================
// Функции для преобразования JSON в строку (stringify)
// ============================================================================

// Вспомогательная функция для декодирования UTF-8 последовательности в Unicode кодпоинт
// Возвращает количество байт, использованных для декодирования (1-4), или 0 в случае ошибки
static int __utf8_decode(const unsigned char* str, size_t len, uint32_t* codepoint) {
    if (len == 0) return 0;

    unsigned char c = str[0];

    // 1-байтовая последовательность (ASCII: 0x00-0x7F)
    if (c < 0x80) {
        *codepoint = c;
        return 1;
    }

    // 2-байтовая последовательность (0xC0-0xDF)
    if ((c & 0xE0) == 0xC0) {
        if (len < 2) return 0;
        if (c < 0xC2) return 0; // Overlong encoding

        unsigned char c1 = str[1];
        if ((c1 & 0xC0) != 0x80) return 0; // Неверный continuation byte

        *codepoint = ((c & 0x1F) << 6) | (c1 & 0x3F);
        return 2;
    }

    // 3-байтовая последовательность (0xE0-0xEF)
    if ((c & 0xF0) == 0xE0) {
        if (len < 3) return 0;

        unsigned char c1 = str[1];
        unsigned char c2 = str[2];

        if ((c1 & 0xC0) != 0x80) return 0;
        if ((c2 & 0xC0) != 0x80) return 0;

        *codepoint = ((c & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F);

        // Проверка на overlong encoding
        if (*codepoint < 0x800) return 0;

        // Проверка на UTF-16 суррогаты (0xD800-0xDFFF) - запрещены в UTF-8
        if (*codepoint >= 0xD800 && *codepoint <= 0xDFFF) return 0;

        return 3;
    }

    // 4-байтовая последовательность (0xF0-0xF4)
    if ((c & 0xF8) == 0xF0) {
        if (len < 4) return 0;
        if (c > 0xF4) return 0; // Выход за пределы Unicode

        unsigned char c1 = str[1];
        unsigned char c2 = str[2];
        unsigned char c3 = str[3];

        if ((c1 & 0xC0) != 0x80) return 0;
        if ((c2 & 0xC0) != 0x80) return 0;
        if ((c3 & 0xC0) != 0x80) return 0;

        *codepoint = ((c & 0x07) << 18) | ((c1 & 0x3F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);

        // Проверка на overlong encoding
        if (*codepoint < 0x10000) return 0;

        // Проверка на максимальное значение Unicode
        if (*codepoint > 0x10FFFF) return 0;

        return 4;
    }

    // Неверный старт UTF-8 последовательности
    return 0;
}

// Вспомогательная функция для кодирования Unicode кодпоинта в \uXXXX последовательность
// Для кодпоинтов > 0xFFFF используются суррогатные пары (RFC 8259)
static int __unicode_encode_escape(uint32_t codepoint, str_t* dest) {
    char buffer[13]; // Максимум: \uXXXX\uYYYY + null terminator

    if (codepoint <= 0xFFFF) {
        // Простой случай: один \uXXXX
        int written = snprintf(buffer, sizeof(buffer), "\\u%04x", codepoint);
        if (written < 0 || (size_t)written >= sizeof(buffer)) return 0;
        return str_append(dest, buffer, (size_t)written);
    } else if (codepoint <= 0x10FFFF) {
        // Суррогатная пара для кодпоинтов > 0xFFFF
        // Формула: high = 0xD800 + ((codepoint - 0x10000) >> 10)
        //          low  = 0xDC00 + ((codepoint - 0x10000) & 0x3FF)
        uint32_t adjusted = codepoint - 0x10000;
        uint32_t high = 0xD800 + (adjusted >> 10);
        uint32_t low = 0xDC00 + (adjusted & 0x3FF);

        int written = snprintf(buffer, sizeof(buffer), "\\u%04x\\u%04x", high, low);
        if (written < 0 || (size_t)written >= sizeof(buffer)) return 0;
        return str_append(dest, buffer, (size_t)written);
    }

    return 0; // Недопустимый кодпоинт
}

// Вспомогательная функция для экранирования строки при stringify
// Параметр encode_unicode:
//   0 = сохранять UTF-8 как есть (только обязательные escape-последовательности)
//   1 = кодировать все не-ASCII символы в \uXXXX последовательности
static int __json_process_string_escapes(const char* source_str, size_t source_length, str_t* dest, int encode_unicode) {
    size_t i = 0;

    while (i < source_length) {
        unsigned char ch = (unsigned char)source_str[i];

        // Обработка специальных символов (всегда экранируются)
        switch (ch) {
            case '"':
                if (!str_append(dest, "\\\"", 2)) return 0;
                i++;
                continue;
            case '\\':
                if (!str_append(dest, "\\\\", 2)) return 0;
                i++;
                continue;
            case '\b':
                if (!str_append(dest, "\\b", 2)) return 0;
                i++;
                continue;
            case '\f':
                if (!str_append(dest, "\\f", 2)) return 0;
                i++;
                continue;
            case '\n':
                if (!str_append(dest, "\\n", 2)) return 0;
                i++;
                continue;
            case '\r':
                if (!str_append(dest, "\\r", 2)) return 0;
                i++;
                continue;
            case '\t':
                if (!str_append(dest, "\\t", 2)) return 0;
                i++;
                continue;
        }

        // Управляющие символы (0x00-0x1F) ОБЯЗАТЕЛЬНО кодируются в \uXXXX (RFC 8259)
        if (ch < 0x20) {
            char unicode[7]; // \uXXXX + null
            int written = snprintf(unicode, sizeof(unicode), "\\u%04x", ch);
            if (written < 0 || (size_t)written >= sizeof(unicode)) return 0;
            if (!str_append(dest, unicode, (size_t)written)) return 0;
            i++;
            continue;
        }

        // ASCII символы (0x20-0x7F кроме обработанных выше)
        if (ch < 0x80) {
            if (!str_appendc(dest, ch)) return 0;
            i++;
            continue;
        }

        // UTF-8 многобайтовые последовательности
        uint32_t codepoint = 0;
        int bytes = __utf8_decode((const unsigned char*)(source_str + i), source_length - i, &codepoint);

        if (bytes == 0) {
            // SECURITY FIX #3: Ошибка декодирования UTF-8 - кодируем как \uFFFD (replacement character)
            // Пропускаем всю невалидную последовательность, а не только первый байт
            if (!__unicode_encode_escape(0xFFFD, dest)) return 0;
            i++;
            // Пропускаем continuation bytes (0x80-0xBF) для избежания множественных replacement characters
            while (i < source_length && ((unsigned char)source_str[i] & 0xC0) == 0x80) {
                i++;
            }
            continue;
        }

        // Если encode_unicode == 1, кодируем в \uXXXX
        if (encode_unicode) {
            if (!__unicode_encode_escape(codepoint, dest)) return 0;
            i += bytes;
        } else {
            // Иначе копируем UTF-8 байты как есть (валидно по RFC 8259)
            if (!str_append(dest, source_str + i, bytes)) return 0;
            i += bytes;
        }
    }

    return 1;
}

// Вспомогательная функция для вставки обработанной строки
static int __json_stringify_insert_processed(json_doc_t* document, const char* string, size_t length) {
    // Используем режим из документа:
    //   0 = UTF-8 mode (сохранять UTF-8 как есть) - компактнее
    //   1 = ASCII-only mode (кодировать все не-ASCII в \uXXXX) - для совместимости
    return __json_process_string_escapes(string, length, &document->stringify, document->ascii_mode);
}

// Вспомогательная функция для вставки строки без обработки
static int __json_stringify_insert(json_doc_t* document, const char* string, size_t length) {
    return str_append(&document->stringify, string, length);
}

static int __json_stringify_token(json_doc_t* document) {
    if (document == NULL) return 0;

    json_token_t* token = document->root;
    if (token == NULL) return 0;

    state_t state = JSON_STATE_PROCESS_PRIMITIVE;
    if (token->type == JSON_OBJECT)
        state = JSON_STATE_OPEN_OBJECT;
    else if (token->type == JSON_ARRAY)
        state = JSON_STATE_OPEN_ARRAY;

    while (token != NULL) {
        switch (state) {
        case JSON_STATE_OPEN_OBJECT:
            {
                if (!__json_stringify_insert(document, "{", 1)) return 0;

                if (token->child == NULL) {
                    if (!__json_stringify_insert(document, "}", 1)) return 0;
                }
                else {
                    token = token->child;
                    state = JSON_STATE_PROCESS_OBJECT_KEY;
                    break;
                }

                // Навигация после пустого объекта
                if (token->sibling == NULL) {
                    token = token->parent;
                    state = JSON_STATE_CLOSE_CONTAINER;
                    break;
                } else {
                    // Если parent - массив, добавляем запятую перед следующим элементом
                    if (token->parent && token->parent->type == JSON_ARRAY) {
                        if (!__json_stringify_insert(document, ",", 1)) return 0;
                    }

                    token = token->sibling;

                    state = JSON_STATE_PROCESS_PRIMITIVE;
                    if (token->type == JSON_OBJECT)
                        state = JSON_STATE_OPEN_OBJECT;
                    else if (token->type == JSON_ARRAY)
                        state = JSON_STATE_OPEN_ARRAY;

                    break;
                }
            }
            break;
        case JSON_STATE_PROCESS_OBJECT_KEY:
            {
                json_token_t* key = token;

                // Валидация ключа
                if (key->type != JSON_STRING) return 0;  // Ключ должен быть строкой
                if (key->child == NULL) return 0;         // У ключа должно быть значение

                // Записываем ключ
                if (!__json_stringify_insert(document, "\"", 1)) return 0;
                const char* key_str = json_string(key);
                if (key_str == NULL) return 0;

                const size_t key_len = str_size(&key->value._string);
                if (!__json_stringify_insert_processed(document, key_str, key_len)) return 0;
                if (!__json_stringify_insert(document, "\":", 2)) return 0;

                // Переключаемся на запись значения
                token = key->child;

                state = JSON_STATE_PROCESS_PRIMITIVE;
                if (token->type == JSON_OBJECT)
                    state = JSON_STATE_OPEN_OBJECT;
                else if (token->type == JSON_ARRAY)
                    state = JSON_STATE_OPEN_ARRAY;
            }
            break;
        case JSON_STATE_OPEN_ARRAY:
            {
                if (!__json_stringify_insert(document, "[", 1)) return 0;

                if (token->child == NULL) {
                    if (!__json_stringify_insert(document, "]", 1)) return 0;
                }
                else {
                    // Переходим к первому элементу
                    token = token->child;

                    // Определяем состояние для первого элемента
                    state = JSON_STATE_PROCESS_PRIMITIVE;
                    if (token->type == JSON_OBJECT)
                        state = JSON_STATE_OPEN_OBJECT;
                    else if (token->type == JSON_ARRAY)
                        state = JSON_STATE_OPEN_ARRAY;
                    break;
                }

                // Навигация после пустого массива
                if (token->sibling == NULL) {
                    token = token->parent;
                    state = JSON_STATE_CLOSE_CONTAINER;
                    break;
                } else {
                    // Если parent - массив, добавляем запятую перед следующим элементом
                    if (token->parent && token->parent->type == JSON_ARRAY) {
                        if (!__json_stringify_insert(document, ",", 1)) return 0;
                    }

                    token = token->sibling;
                }

                state = JSON_STATE_PROCESS_PRIMITIVE;
                if (token->type == JSON_OBJECT)
                    state = JSON_STATE_OPEN_OBJECT;
                else if (token->type == JSON_ARRAY)
                    state = JSON_STATE_OPEN_ARRAY;
            }
            break;
        case JSON_STATE_PROCESS_PRIMITIVE:
            {
                switch (token->type) {
                case JSON_STRING:
                    {
                        const char* value = json_string(token);

                        if (!__json_stringify_insert(document, "\"", 1)) return 0;
                        if (value) {
                            // Вычисляем size только если value != NULL
                            size_t size = str_size(&token->value._string);
                            if (!__json_stringify_insert_processed(document, value, size)) return 0;
                        }
                        if (!__json_stringify_insert(document, "\"", 1)) return 0;
                    }
                    break;

                case JSON_BOOL:
                    {
                        const char* value = token->value._int ? "true" : "false";
                        int size = token->value._int ? 4 : 5;

                        if (!__json_stringify_insert(document, value, size)) return 0;
                    }
                    break;

                case JSON_NULL:
                    {
                        if (!__json_stringify_insert(document, "null", 4)) return 0;
                    }
                    break;

                case JSON_NUMBER:
                    {
                        size_t buffer_size = 64;
                        char buffer[buffer_size];

                        // Проверяем, является ли число целым
                        double value = token->value._double;

                        // Улучшенная проверка на целое число с учетом диапазона long long
                        int is_integer = 0;
                        if (!isinf(value) && !isnan(value)) {
                            // Проверяем, что число в диапазоне long long и является целым
                            if (value >= (double)LLONG_MIN && value <= (double)LLONG_MAX) {
                                long long int_value = (long long)value;
                                // Проверяем, что после конвертации значение не изменилось
                                if (value == (double)int_value) {
                                    is_integer = 1;
                                }
                            }
                        }

                        // Проверка возвращаемого значения snprintf (int → size_t)
                        int written;
                        if (is_integer) {
                            // Целое число
                            written = snprintf(buffer, sizeof(buffer), "%.0f", value);
                        } else {
                            // Пункт 7: Дробное число с полной точностью (17 значащих цифр для double)
                            written = snprintf(buffer, sizeof(buffer), "%.17g", value);
                        }

                        // Пункт 4: Проверка на переполнение буфера и ошибки snprintf
                        if (written < 0 || (size_t)written >= sizeof(buffer)) return 0;

                        size_t size = (size_t)written;

                        if (!__json_stringify_insert(document, buffer, size)) return 0;
                    }
                    break;
                default:
                    return 0;
                }

                if (token->sibling == NULL) {
                    token = token->parent;
                    state = JSON_STATE_CLOSE_CONTAINER;
                    break;
                } else {
                    token = token->sibling;

                    if (token->parent && token->parent->type == JSON_ARRAY)
                        if (!__json_stringify_insert(document, ",", 1)) return 0;

                    if (token->parent && token->parent->type == JSON_STRING && token->parent->sibling != NULL) {
                        if (!__json_stringify_insert(document, ",", 1)) return 0;

                        state = JSON_STATE_PROCESS_PRIMITIVE;
                        if (token->parent->type == JSON_OBJECT)
                            state = JSON_STATE_OPEN_OBJECT;
                        else if (token->parent->type == JSON_ARRAY)
                            state = JSON_STATE_OPEN_ARRAY;


                        break;
                    }

                    state = JSON_STATE_PROCESS_PRIMITIVE;
                    if (token->type == JSON_OBJECT)
                        state = JSON_STATE_OPEN_OBJECT;
                    else if (token->type == JSON_ARRAY)
                        state = JSON_STATE_OPEN_ARRAY;

                    break;
                }
            }
            break;
        case JSON_STATE_CLOSE_CONTAINER:
            {
                // Если parent - ключ объекта, добавляем запятую если есть следующий ключ
                if (token && token->type == JSON_STRING && token->sibling != NULL) {
                    if (!__json_stringify_insert(document, ",", 1)) return 0;

                    token = token->sibling;
                    state = JSON_STATE_PROCESS_OBJECT_KEY;
                    break;
                }

                // Закрываем контейнеры, поднимаясь вверх
                while (token != NULL) {
                    if (token->type == JSON_OBJECT) {
                        if (!__json_stringify_insert(document, "}", 1)) return 0;
                    } else if (token->type == JSON_ARRAY) {
                        if (!__json_stringify_insert(document, "]", 1)) return 0;
                    }

                    if (token->sibling != NULL) {
                        // Добавляем запятую если:
                        // 1. parent - массив (элементы массива разделяются запятыми), ИЛИ
                        // 2. текущий токен - ключ объекта (пары ключ-значение разделяются запятыми)
                        if ((token->parent && token->parent->type == JSON_ARRAY) ||
                            (token->type == JSON_STRING)) {
                            if (!__json_stringify_insert(document, ",", 1)) return 0;
                        }

                        token = token->sibling;

                        // Если следующий токен - ключ объекта, переходим к обработке ключа
                        if (token->type == JSON_STRING) {
                            state = JSON_STATE_PROCESS_OBJECT_KEY;
                        } else {
                            state = JSON_STATE_PROCESS_PRIMITIVE;
                            if (token->type == JSON_OBJECT)
                                state = JSON_STATE_OPEN_OBJECT;
                            else if (token->type == JSON_ARRAY)
                                state = JSON_STATE_OPEN_ARRAY;
                        }
                        break;
                    }

                    token = token->parent;
                }

                if (token == NULL)
                    return 1;
            }
            break;
        }
    }

    return 1;
}

const char* json_stringify(json_doc_t* document) {
    if (document == NULL) return NULL;
    if (document->root == NULL) return NULL;

    str_reset(&document->stringify);

    if (!__json_stringify_token(document)) {
        str_clear(&document->stringify);
        return NULL;
    }

    return str_get(&document->stringify);
}

size_t json_stringify_size(json_doc_t* document) {
    if (document == NULL) return 0;

    return str_size(&document->stringify);
}

char* json_stringify_detach(json_doc_t* document) {
    if (document == NULL) return NULL;

    // Сначала вызываем stringify для генерации строки
    const char* result = json_stringify(document);
    if (result == NULL) return NULL;

    // Копируем строку
    char* detached = str_copy(&document->stringify);

    // Очищаем stringify буфер
    str_clear(&document->stringify);

    return detached;
}

int json_copy(json_doc_t* from, json_doc_t* to) {
    if (from == NULL || to == NULL) return 0;

    char* data = json_stringify_detach(from);
    if (data == NULL) return 0;

    json_doc_t* parsed = json_parse(data);
    free(data);

    if (parsed == NULL || parsed->root == NULL) {
        if (parsed) json_free(parsed);
        return 0;
    }

    // Копируем корневой токен
    to->root = parsed->root;
    parsed->root = NULL;

    // Освобождаем временный документ
    json_free(parsed);

    return 1;
}

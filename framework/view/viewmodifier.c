#define _GNU_SOURCE
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "numlocale.h"
#include "utf8.h"
#include "viewmodifier.h"

#define VIEWMODIFIER_NUMBER_BUFFER_SIZE 64

static viewexpr_value_t __viewmodifier_null(void) {
    viewexpr_value_t value;
    value.type = VIEWEXPR_NULL;
    value.boolean = 0;
    value.number = 0;
    value.string = NULL;
    value.token = NULL;
    value.length = 0;
    return value;
}

/* Strings are NUL-terminated at `length` and may hold NUL bytes before it:
 * every modifier works on the length, never up to the first NUL. */
static viewexpr_value_t __viewmodifier_string(const char* string, size_t length) {
    if (string == NULL) return __viewmodifier_null();

    viewexpr_value_t value = __viewmodifier_null();
    value.type = VIEWEXPR_STRING;
    value.string = string;
    value.length = length;
    return value;
}

/**
 * Converts a scalar value to text the way a {{ }} tag prints it.
 *
 * @param value The value.
 * @param buffer Storage for the text form of a number.
 * @param length The text length in bytes, NUL bytes included.
 * @return The text (NUL-terminated at *length), or NULL for null,
 *         containers and non-finite numbers.
 */
static const char* __viewmodifier_text(const viewexpr_value_t* value, char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE], size_t* length) {
    switch (value->type)
    {
    case VIEWEXPR_STRING:
        *length = value->length;
        return value->string;
    case VIEWEXPR_NUMBER:
        *length = viewexpr_number_format(value->number, buffer, VIEWMODIFIER_NUMBER_BUFFER_SIZE);
        return *length > 0 ? buffer : NULL;
    case VIEWEXPR_BOOL:
        *length = value->boolean ? 4 : 5;
        return value->boolean ? "true" : "false";
    default:
        return NULL;
    }
}

/**
 * Copies a byte range into the arena as a string value.
 *
 * @param arena The arena (may be NULL).
 * @param string The bytes (NULL gives null).
 * @param length The number of bytes.
 * @return The string value, or null without an arena or on allocation failure.
 */
static viewexpr_value_t __viewmodifier_copy(arena_t* arena, const char* string, size_t length) {
    if (arena == NULL || string == NULL) return __viewmodifier_null();

    return __viewmodifier_string(arena_strndup(arena, string, length), length);
}

/* A byte buffer that grows with realloc; `failed` sticks once an append
 * could not grow it, and the result is then dropped. */
typedef struct viewmodifier_bytes {
    char* data;
    size_t size;
    size_t capacity;
    int failed;
} viewmodifier_bytes_t;

static void __viewmodifier_bytes_put(viewmodifier_bytes_t* bytes, const char* data, size_t size) {
    if (bytes->failed) return;

    if (bytes->size + size + 1 > bytes->capacity) {
        size_t capacity = bytes->capacity > 0 ? bytes->capacity : 64;
        while (capacity < bytes->size + size + 1) capacity *= 2;

        char* grown = realloc(bytes->data, capacity);
        if (grown == NULL) {
            bytes->failed = 1;
            return;
        }

        bytes->data = grown;
        bytes->capacity = capacity;
    }

    memcpy(bytes->data + bytes->size, data, size);
    bytes->size += size;
}

/**
 * Moves the bytes into the arena as a string value and releases the buffer.
 *
 * @return The string value, or null if an append or the copy failed.
 */
static viewexpr_value_t __viewmodifier_bytes_finish(viewmodifier_bytes_t* bytes, arena_t* arena) {
    viewexpr_value_t result = __viewmodifier_null();
    if (!bytes->failed)
        result = __viewmodifier_copy(arena, bytes->data != NULL ? bytes->data : "", bytes->size);

    free(bytes->data);
    bytes->data = NULL;

    return result;
}

/**
 * Returns the byte length of the character at `string`: a broken UTF-8
 * sequence counts as one byte, as in utf8_strlen().
 *
 * @param string The position, not at the terminator.
 * @param codepoint The decoded codepoint, 0xFFFFFFFF for a broken sequence.
 * @return The byte length of the character.
 */
static size_t __viewmodifier_char(const char* string, uint32_t* codepoint) {
    const size_t size = utf8_decode((const unsigned char*)string, codepoint);
    if (size > 0) return size;

    *codepoint = 0xFFFFFFFF;
    return 1;
}

/**
 * Applies a case conversion to the text of a value. The converters take C
 * strings, so each run between NUL bytes is converted on its own and the NUL
 * bytes are kept. A run the converter refuses is kept unchanged rather than
 * lost.
 *
 * @param arena The arena.
 * @param input The input value.
 * @param convert utf8_toupper or utf8_tolower.
 * @return The converted string, or null.
 */
static viewexpr_value_t __viewmodifier_case(arena_t* arena, const viewexpr_value_t* input, char* (*convert)(const char*)) {
    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t length = 0;
    const char* text = __viewmodifier_text(input, buffer, &length);
    if (text == NULL || arena == NULL) return __viewmodifier_null();

    viewmodifier_bytes_t bytes = { NULL, 0, 0, 0 };

    // every run ends at a NUL byte: an inner one or the terminator at length
    for (size_t start = 0; start <= length;) {
        const size_t run = strlen(text + start);

        char* converted = run > 0 ? convert(text + start) : NULL;
        if (converted != NULL) __viewmodifier_bytes_put(&bytes, converted, strlen(converted));
        else __viewmodifier_bytes_put(&bytes, text + start, run);
        free(converted);

        start += run;
        if (start < length) __viewmodifier_bytes_put(&bytes, "", 1); // the inner NUL
        start++;
    }

    return __viewmodifier_bytes_finish(&bytes, arena);
}

static viewexpr_value_t __viewmodifier_upper(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)args; (void)argc;
    return __viewmodifier_case(arena, input, utf8_toupper);
}

static viewexpr_value_t __viewmodifier_lower(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)args; (void)argc;
    return __viewmodifier_case(arena, input, utf8_tolower);
}

/**
 * Upper-cases the first character and keeps the rest as it is.
 */
static viewexpr_value_t __viewmodifier_capitalize(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)args; (void)argc;

    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t length = 0;
    const char* text = __viewmodifier_text(input, buffer, &length);
    if (text == NULL || arena == NULL) return __viewmodifier_null();

    // a NUL byte first is not a letter (utf8_decode would read it as U+0000)
    if (length == 0 || text[0] == 0) return __viewmodifier_copy(arena, text, length);

    uint32_t codepoint = 0;
    const size_t first_size = utf8_decode((const unsigned char*)text, &codepoint);
    if (first_size == 0) return __viewmodifier_copy(arena, text, length);

    char first[5];
    memcpy(first, text, first_size);
    first[first_size] = 0;

    char* upper = utf8_toupper(first);
    if (upper == NULL) return __viewmodifier_copy(arena, text, length);

    const size_t upper_size = strlen(upper);
    const size_t rest_size = length - first_size;

    char* result = arena_alloc(arena, upper_size + rest_size + 1);
    if (result != NULL) {
        memcpy(result, upper, upper_size);
        memcpy(result + upper_size, text + first_size, rest_size);
        result[upper_size + rest_size] = 0;
    }

    free(upper);

    return __viewmodifier_string(result, upper_size + rest_size);
}

/**
 * utf8_is_space() plus the no-break spaces it leaves out (U+00A0, U+2007,
 * U+202F): a value pasted from a word processor often ends in one.
 */
static int __viewmodifier_is_space(uint32_t codepoint) {
    return utf8_is_space(codepoint) || codepoint == 0x00A0 || codepoint == 0x2007 || codepoint == 0x202F;
}

/**
 * Removes whitespace characters (including no-break spaces) from both ends.
 */
static viewexpr_value_t __viewmodifier_trim(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)args; (void)argc;

    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t length = 0;
    const char* text = __viewmodifier_text(input, buffer, &length);
    if (text == NULL || arena == NULL) return __viewmodifier_null();

    size_t start = 0;
    size_t end = 0;
    int seen = 0;

    for (size_t pos = 0; pos < length;) {
        uint32_t codepoint = 0;
        const size_t size = __viewmodifier_char(text + pos, &codepoint);
        const int space = codepoint != 0xFFFFFFFF && __viewmodifier_is_space(codepoint);

        if (!space) {
            if (!seen) start = pos;
            seen = 1;
            end = pos + size;
        }

        pos += size;
    }

    if (!seen) return __viewmodifier_copy(arena, text, 0);

    return __viewmodifier_copy(arena, text + start, end - start);
}

/**
 * Returns a non-negative integral number argument.
 *
 * @param value The argument.
 * @param result The integer.
 * @return 1 on success, 0 if the argument is not such a number.
 */
static int __viewmodifier_count(const viewexpr_value_t* value, size_t* result) {
    if (value->type != VIEWEXPR_NUMBER) return 0;

    const long double number = value->number;
    if (!isfinite(number) || number < 0 || floorl(number) != number) return 0;
    if (number > (long double)(SIZE_MAX / 2)) return 0;

    *result = (size_t)number;
    return 1;
}

/**
 * Cuts the text to `n` characters and appends the suffix ("…" by default)
 * when something was cut. The suffix is not counted in `n`.
 */
static viewexpr_value_t __viewmodifier_truncate(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t length = 0;
    const char* text = __viewmodifier_text(input, buffer, &length);
    if (text == NULL || arena == NULL) return __viewmodifier_null();

    size_t limit = 0;
    if (argc < 1 || !__viewmodifier_count(&args[0], &limit)) return __viewmodifier_null();

    char suffix_buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    const char* suffix = "…";
    size_t suffix_size = strlen(suffix);
    if (argc > 1) {
        suffix = __viewmodifier_text(&args[1], suffix_buffer, &suffix_size);
        if (suffix == NULL) return __viewmodifier_null();
    }

    size_t pos = 0;
    for (size_t count = 0; count < limit && pos < length; count++) {
        uint32_t codepoint = 0;
        pos += __viewmodifier_char(text + pos, &codepoint);
    }

    if (pos >= length) return __viewmodifier_copy(arena, text, length);

    char* result = arena_alloc(arena, pos + suffix_size + 1);
    if (result == NULL) return __viewmodifier_null();

    memcpy(result, text, pos);
    memcpy(result + pos, suffix, suffix_size);
    result[pos + suffix_size] = 0;

    return __viewmodifier_string(result, pos + suffix_size);
}

/**
 * Finds `from` in [pos, end). memmem, not strstr: strstr is given no end, so
 * each call costs the rest of the string under sanitizers, and a plain
 * compare at every byte is quadratic when the text keeps almost matching a
 * long pattern ('a' * n against 'a' * m + 'b'). memmem is linear in both.
 *
 * @return The match, or NULL.
 */
static const char* __viewmodifier_search(const char* pos, const char* end, const char* from, size_t from_size) {
    return memmem(pos, (size_t)(end - pos), from, from_size);
}

/**
 * Replaces every occurrence of `from` with `to`, left to right, without overlap.
 */
static viewexpr_value_t __viewmodifier_replace(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    char from_buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    char to_buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];

    if (argc < 2) return __viewmodifier_null();

    size_t text_size = 0, from_size = 0, to_size = 0;
    const char* text = __viewmodifier_text(input, buffer, &text_size);
    const char* from = __viewmodifier_text(&args[0], from_buffer, &from_size);
    const char* to = __viewmodifier_text(&args[1], to_buffer, &to_size);
    if (text == NULL || from == NULL || to == NULL || arena == NULL) return __viewmodifier_null();

    if (from_size == 0) return __viewmodifier_copy(arena, text, text_size);

    const char* end = text + text_size;

    size_t count = 0;
    for (const char* p = __viewmodifier_search(text, end, from, from_size); p != NULL;
         p = __viewmodifier_search(p + from_size, end, from, from_size))
        count++;

    const size_t result_size = text_size - count * from_size + count * to_size;

    char* result = arena_alloc(arena, result_size + 1);
    if (result == NULL) return __viewmodifier_null();

    char* out = result;
    const char* p = text;
    for (const char* found = __viewmodifier_search(p, end, from, from_size); found != NULL;
         found = __viewmodifier_search(p, end, from, from_size)) {
        memcpy(out, p, (size_t)(found - p));
        out += found - p;
        memcpy(out, to, to_size);
        out += to_size;
        p = found + from_size;
    }

    const size_t tail = (size_t)(end - p);
    memcpy(out, p, tail);
    out[tail] = 0;

    return __viewmodifier_string(result, result_size);
}

/**
 * Returns the argument when the input is null or an empty string, otherwise
 * the input. Allocates nothing.
 */
static viewexpr_value_t __viewmodifier_default(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)arena;

    if (argc < 1) return *input;

    const int empty = input->type == VIEWEXPR_NULL
        || (input->type == VIEWEXPR_STRING && (input->string == NULL || input->length == 0));

    return empty ? args[0] : *input;
}

/**
 * Returns an integral number argument in 0..15 (places for round and number).
 *
 * @param value The argument.
 * @param result The number of places.
 * @return 1 on success, 0 if the argument is out of range.
 */
static int __viewmodifier_places(const viewexpr_value_t* value, int* result) {
    size_t places = 0;
    if (!__viewmodifier_count(value, &places) || places > 15) return 0;

    *result = (int)places;
    return 1;
}

static viewexpr_value_t __viewmodifier_number_value(long double number) {
    viewexpr_value_t value = __viewmodifier_null();
    value.type = VIEWEXPR_NUMBER;
    value.number = number;
    return value;
}

static viewexpr_value_t __viewmodifier_abs(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)arena; (void)args; (void)argc;

    if (input->type != VIEWEXPR_NUMBER) return __viewmodifier_null();

    return __viewmodifier_number_value(fabsl(input->number));
}

#ifdef LDBL_DECIMAL_DIG
#define VIEWMODIFIER_LDBL_DIGITS LDBL_DECIMAL_DIG
#else
#define VIEWMODIFIER_LDBL_DIGITS 36
#endif

/* Fraction digits that hold every long double >= 2^-50 exactly: its lowest
 * bit is 2^-(49 + LDBL_MANT_DIG) at the smallest. */
#define VIEWMODIFIER_EXACT_PLACES (LDBL_MANT_DIG + 64)

/**
 * The exact decimal expansion of a value of at least 2^-50 (see
 * VIEWMODIFIER_EXACT_PLACES), as digits without the point.
 *
 * @param value A finite, non-negative number.
 * @param digits The number of digits.
 * @param exponent The power of ten of the first digit (integer digits - 1).
 * @return The malloc'ed digits, or NULL on failure.
 */
static char* __viewmodifier_exact(long double value, size_t* digits, int* exponent) {
    const int size = snprintf(NULL, 0, "%.*Lf", VIEWMODIFIER_EXACT_PLACES, value);
    if (size <= 0) return NULL;

    char* text = malloc((size_t)size + 1);
    if (text == NULL) return NULL;

    snprintf(text, (size_t)size + 1, "%.*Lf", VIEWMODIFIER_EXACT_PLACES, value);

    char* point = strchr(text, '.');
    if (point == NULL) {
        free(text);
        return NULL;
    }

    *exponent = (int)(point - text) - 1;
    memmove(point, point + 1, strlen(point + 1) + 1);
    *digits = (size_t)size - 1;

    return text;
}

/**
 * Rounds |value| to `places` decimals, half away from zero. Works on decimal
 * digits, not on value * 10^places: that product runs past the 64-bit
 * mantissa for large values (1000000001 with 15 places).
 *
 * When the shortest decimal that reads back as the same long double -- the
 * digits the template author wrote and sees printed -- has digits past the
 * requested place, those are rounded: 2.675 gives 2.68, although the binary
 * value is 2.67499... When it ends at or before that place, its padding zeros
 * would stand for digits the value does have (1000000001.000030517578125
 * reads back from 1000000001.0000305176), so the exact expansion is rounded.
 * Within the precision of a long double both agree.
 *
 * Call in the C numeric locale (numeric_locale()).
 *
 * @param value A finite number.
 * @param places Decimals to keep, 0..15.
 * @return A malloc'ed "integer[.fraction]" string with exactly `places`
 *         fraction digits, or NULL on allocation failure.
 */
static char* __viewmodifier_decimal(long double value, int places) {
    value = fabsl(value);

    // the shortest round-trip mantissa digits and the decimal exponent of the first
    char shortest[VIEWMODIFIER_LDBL_DIGITS + 1];
    const char* mantissa = shortest;
    char* exact = NULL;
    size_t digits = 0;
    int exponent = 0;

    if (value == 0) {
        shortest[digits++] = '0';
    }
    else {
        char text[VIEWMODIFIER_LDBL_DIGITS + 16];
        for (int precision = 1; precision <= VIEWMODIFIER_LDBL_DIGITS; precision++) {
            snprintf(text, sizeof(text), "%.*Le", precision - 1, value);
            if (strtold(text, NULL) == value) break;
        }

        const char* p = text;
        for (; *p != 0 && *p != 'e'; p++)
            if (*p >= '0' && *p <= '9' && digits < VIEWMODIFIER_LDBL_DIGITS)
                shortest[digits++] = *p;

        if (*p == 'e') exponent = atoi(p + 1);

        // fraction digits of the shortest form; <= places: nothing left to round there
        if ((long)digits - 1 - exponent <= (long)places) {
            exact = __viewmodifier_exact(value, &digits, &exponent);
            if (exact == NULL) return NULL;
            mantissa = exact;
        }
    }

    const size_t integer_size = exponent >= 0 ? (size_t)exponent + 1 : 1;
    const size_t fraction_size = (size_t)places;

    // one spare digit in front for a carry out of the integer part
    char* result = malloc(1 + integer_size + 1 + fraction_size + 1);
    if (result == NULL) {
        free(exact);
        return NULL;
    }

    // the digit of 10^power: mantissa digit i stands for 10^(exponent - i)
    #define VIEWMODIFIER_DIGIT(power) \
        ((long)exponent - (long)(power) >= 0 && (long)exponent - (long)(power) < (long)digits \
            ? mantissa[exponent - (power)] : '0')

    char* out = result;
    *out++ = '0';
    for (long power = (long)integer_size - 1; power >= 0; power--)
        *out++ = VIEWMODIFIER_DIGIT(power);

    if (places > 0) {
        *out++ = '.';
        for (long power = -1; power >= -(long)places; power--)
            *out++ = VIEWMODIFIER_DIGIT(power);
    }

    const int round_up = VIEWMODIFIER_DIGIT(-(long)places - 1) >= '5';
    #undef VIEWMODIFIER_DIGIT

    free(exact);

    *out = 0;

    if (round_up) {
        for (char* p = out - 1; p >= result; p--) {
            if (*p == '.') continue;
            if (*p != '9') {
                (*p)++;
                break;
            }
            *p = '0';
        }
    }

    if (result[0] == '0')
        memmove(result, result + 1, (size_t)(out - result));

    return result;
}

/**
 * Rounds to `n` places (0 by default), half away from zero. Allocates nothing
 * in the arena.
 */
static viewexpr_value_t __viewmodifier_round(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)arena;

    if (input->type != VIEWEXPR_NUMBER || !isfinite(input->number)) return __viewmodifier_null();

    int places = 0;
    if (argc > 0 && !__viewmodifier_places(&args[0], &places)) return __viewmodifier_null();

    const locale_t previous = uselocale(numeric_locale());
    char* decimal = __viewmodifier_decimal(input->number, places);
    const long double rounded = decimal != NULL ? strtold(decimal, NULL) : NAN;
    uselocale(previous);

    if (decimal == NULL) return __viewmodifier_null();
    free(decimal);

    if (!isfinite(rounded)) return __viewmodifier_null();

    return __viewmodifier_number_value(input->number < 0 ? -rounded : rounded);
}

/**
 * Formats a number with fixed decimals (half away from zero), a decimal
 * separator and a thousands separator between groups of three integer digits.
 */
static viewexpr_value_t __viewmodifier_number(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    if (input->type != VIEWEXPR_NUMBER || !isfinite(input->number) || arena == NULL)
        return __viewmodifier_null();

    int places = 0;
    if (argc > 0 && !__viewmodifier_places(&args[0], &places)) return __viewmodifier_null();

    char point_buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    char thousands_buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t point_length = 1, thousands_size = 0;
    const char* point = argc > 1 ? __viewmodifier_text(&args[1], point_buffer, &point_length) : ".";
    const char* thousands = argc > 2 ? __viewmodifier_text(&args[2], thousands_buffer, &thousands_size) : "";
    if (point == NULL || thousands == NULL) return __viewmodifier_null();

    const locale_t previous = uselocale(numeric_locale());
    char* decimal = __viewmodifier_decimal(input->number, places);
    uselocale(previous);
    if (decimal == NULL) return __viewmodifier_null();

    const char* dot = strchr(decimal, '.');
    const size_t integer_size = dot != NULL ? (size_t)(dot - decimal) : strlen(decimal);
    const char* fraction = dot != NULL ? dot + 1 : "";
    const size_t fraction_size = strlen(fraction);
    const size_t point_size = places > 0 ? point_length : 0;
    const size_t groups = (integer_size - 1) / 3;
    const int negative = input->number < 0 && strspn(decimal, "0.") != strlen(decimal); // -0 prints as 0

    const size_t result_size = (size_t)negative + integer_size + groups * thousands_size + point_size + fraction_size;
    char* result = arena_alloc(arena, result_size + 1);
    if (result == NULL) {
        free(decimal);
        return __viewmodifier_null();
    }

    char* out = result;
    if (negative) *out++ = '-';

    for (size_t i = 0; i < integer_size; i++) {
        *out++ = decimal[i];

        const size_t left = integer_size - i - 1;
        if (left > 0 && left % 3 == 0) {
            memcpy(out, thousands, thousands_size);
            out += thousands_size;
        }
    }

    if (places > 0) {
        memcpy(out, point, point_size);
        out += point_size;
        memcpy(out, fraction, fraction_size);
        out += fraction_size;
    }

    *out = 0;
    free(decimal);

    return __viewmodifier_string(result, result_size);
}

/**
 * Characters of a string, elements of an array or object, characters of the
 * text form of a number or bool; 0 for null. Allocates nothing.
 */
static viewexpr_value_t __viewmodifier_length(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)arena; (void)args; (void)argc;

    if (input->type == VIEWEXPR_TOKEN) {
        const json_token_t* token = input->token;
        if (token->type == JSON_ARRAY) return __viewmodifier_number_value(json_array_size(token));
        if (token->type == JSON_OBJECT) return __viewmodifier_number_value(json_object_size(token));
        return __viewmodifier_number_value(0);
    }

    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t length = 0;
    const char* text = __viewmodifier_text(input, buffer, &length);
    if (text == NULL) return __viewmodifier_number_value(0);

    // characters as utf8_strlen() counts them, but over the whole length:
    // a NUL byte is one character, not the end
    size_t count = 0;
    for (size_t pos = 0; pos < length; count++) {
        uint32_t codepoint = 0;
        pos += __viewmodifier_char(text + pos, &codepoint);
    }

    return __viewmodifier_number_value(count);
}

/**
 * First (`last` = 0) or last element of an array or object, or character of
 * a string; null for anything else. Elements are borrowed from the document;
 * a character needs the arena.
 */
static viewexpr_value_t __viewmodifier_edge(arena_t* arena, const viewexpr_value_t* input, int last) {
    if (input->type == VIEWEXPR_TOKEN) {
        const json_token_t* edge = NULL;
        for (json_it_t it = json_init_it(input->token); !json_end_it(&it); it = json_next_it(&it)) {
            edge = json_it_value(&it);
            if (!last) break;
        }

        return viewexpr_value_from_token(edge);
    }

    // a number or bool has no characters to pick: `false | first` must not be "f"
    if (input->type != VIEWEXPR_STRING) return __viewmodifier_null();

    const char* text = input->string;
    const size_t length = input->length;
    if (text == NULL || length == 0 || arena == NULL) return __viewmodifier_null();

    size_t start = 0;
    size_t size = 0;
    for (size_t pos = 0; pos < length;) {
        uint32_t codepoint = 0;
        const size_t char_size = __viewmodifier_char(text + pos, &codepoint);

        start = pos;
        size = char_size;
        if (!last) break;

        pos += char_size;
    }

    return __viewmodifier_copy(arena, text + start, size);
}

static viewexpr_value_t __viewmodifier_first(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)args; (void)argc;
    return __viewmodifier_edge(arena, input, 0);
}

static viewexpr_value_t __viewmodifier_last(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)args; (void)argc;
    return __viewmodifier_edge(arena, input, 1);
}

/**
 * Joins the values of an array or object as text with a separator; null and
 * nested containers are empty pieces. A scalar input gives its own text.
 */
static viewexpr_value_t __viewmodifier_join(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    if (arena == NULL) return __viewmodifier_null();

    char separator_buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t separator_size = 0;
    const char* separator = argc > 0 ? __viewmodifier_text(&args[0], separator_buffer, &separator_size) : "";
    if (separator == NULL) return __viewmodifier_null();

    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t text_size = 0;
    if (input->type != VIEWEXPR_TOKEN) {
        const char* text = __viewmodifier_text(input, buffer, &text_size);
        if (text == NULL) return __viewmodifier_null();
        return __viewmodifier_copy(arena, text, text_size);
    }

    // two passes: the size first, then the bytes
    size_t size = 0;
    size_t count = 0;
    for (json_it_t it = json_init_it(input->token); !json_end_it(&it); it = json_next_it(&it)) {
        const viewexpr_value_t item = viewexpr_value_from_token(json_it_value(&it));
        const char* text = __viewmodifier_text(&item, buffer, &text_size);
        size += text != NULL ? text_size : 0;
        count++;
    }

    if (count > 1) size += (count - 1) * separator_size;

    char* result = arena_alloc(arena, size + 1);
    if (result == NULL) return __viewmodifier_null();

    char* out = result;
    count = 0;
    for (json_it_t it = json_init_it(input->token); !json_end_it(&it); it = json_next_it(&it)) {
        if (count++ > 0) {
            memcpy(out, separator, separator_size);
            out += separator_size;
        }

        const viewexpr_value_t item = viewexpr_value_from_token(json_it_value(&it));
        const char* text = __viewmodifier_text(&item, buffer, &text_size);
        if (text == NULL) continue;

        memcpy(out, text, text_size);
        out += text_size;
    }

    *out = 0;

    return __viewmodifier_string(result, size);
}

static void __viewmodifier_write(str_t* buf, const char* text, size_t size) {
    str_append(buf, text, size);
}

/**
 * Writes `length` bytes of text. VIEW_ESCAPE replaces & < > " ' with HTML
 * entities, which covers element text and a quoted attribute value. A NUL
 * byte becomes U+FFFD in both modes: render() hands out a C string, which a
 * raw NUL would cut, and in HTML a browser makes the same replacement.
 *
 * @param buf The output buffer.
 * @param text The text (NULL writes nothing).
 * @param length The text length in bytes, NUL bytes included.
 * @param escape The escape mode.
 * @return void
 */
void viewmodifier_write_text(str_t* buf, const char* text, size_t length, view_escape_e escape) {
    if (text == NULL) return;

    for (size_t i = 0; i < length; i++) {
        const char ch = text[i];

        if (ch == 0) {
            __viewmodifier_write(buf, "\xEF\xBF\xBD", 3);
            continue;
        }

        if (escape == VIEW_ESCAPE) {
            switch (ch)
            {
            case '&':  __viewmodifier_write(buf, "&amp;", 5);  continue;
            case '<':  __viewmodifier_write(buf, "&lt;", 4);   continue;
            case '>':  __viewmodifier_write(buf, "&gt;", 4);   continue;
            case '"':  __viewmodifier_write(buf, "&quot;", 6); continue;
            case '\'': __viewmodifier_write(buf, "&#39;", 5);  continue;
            default: break;
            }
        }

        str_appendc(buf, ch);
    }
}

/**
 * Percent-encodes everything except A-Z a-z 0-9 - _ . ~ (a space becomes
 * %20, valid in a path as well as in a query).
 */
static viewexpr_value_t __viewmodifier_url(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)args; (void)argc;

    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t size = 0;
    const char* text = __viewmodifier_text(input, buffer, &size);
    if (text == NULL || arena == NULL) return __viewmodifier_null();

    static const char hex[] = "0123456789ABCDEF";

    char* result = arena_alloc(arena, size * 3 + 1);
    if (result == NULL) return __viewmodifier_null();

    char* out = result;
    for (size_t i = 0; i < size; i++) {
        const unsigned char ch = (unsigned char)text[i];
        const int unreserved = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
            || ch == '-' || ch == '_' || ch == '.' || ch == '~';

        if (unreserved) {
            *out++ = (char)ch;
            continue;
        }

        *out++ = '%';
        *out++ = hex[ch >> 4];
        *out++ = hex[ch & 15];
    }

    *out = 0;

    return __viewmodifier_string(result, (size_t)(out - result));
}

#define VIEWMODIFIER_JSON_MAX_DEPTH 32

/* Where JSON goes: with out == NULL bytes are only counted. json() runs the
 * serializer twice, to size one arena block and then to fill it, so no write
 * can fail half way and leave a truncated document. */
typedef struct viewmodifier_sink {
    char* out;
    size_t size;
} viewmodifier_sink_t;

static void __viewmodifier_sink_put(viewmodifier_sink_t* sink, const char* text, size_t size) {
    if (sink->out != NULL) memcpy(sink->out + sink->size, text, size);
    sink->size += size;
}

static void __viewmodifier_sink_char(viewmodifier_sink_t* sink, char ch) {
    __viewmodifier_sink_put(sink, &ch, 1);
}

/**
 * Writes a JSON string literal of `size` bytes. Besides the standard escapes
 * (NUL included, as \u0000), < > & ' and U+2028/U+2029 become \u sequences,
 * so the output is safe to place inside <script> as is and cannot close the
 * element.
 */
static void __viewmodifier_json_string(viewmodifier_sink_t* sink, const char* text, size_t size) {
    static const char hex[] = "0123456789abcdef";

    __viewmodifier_sink_char(sink, '"');

    const unsigned char* end = (const unsigned char*)text + size;
    for (const unsigned char* p = (const unsigned char*)text; p < end; p++) {
        const unsigned char ch = *p;

        if (ch == 0xE2 && end - p >= 3 && p[1] == 0x80 && (p[2] == 0xA8 || p[2] == 0xA9)) {
            __viewmodifier_sink_put(sink, p[2] == 0xA8 ? "\\u2028" : "\\u2029", 6);
            p += 2;
            continue;
        }

        switch (ch)
        {
        case '"':  __viewmodifier_sink_put(sink, "\\\"", 2); continue;
        case '\\': __viewmodifier_sink_put(sink, "\\\\", 2); continue;
        case '\n': __viewmodifier_sink_put(sink, "\\n", 2);  continue;
        case '\r': __viewmodifier_sink_put(sink, "\\r", 2);  continue;
        case '\t': __viewmodifier_sink_put(sink, "\\t", 2);  continue;
        case '\b': __viewmodifier_sink_put(sink, "\\b", 2);  continue;
        case '\f': __viewmodifier_sink_put(sink, "\\f", 2);  continue;
        default: break;
        }

        if (ch < 0x20 || ch == '<' || ch == '>' || ch == '&' || ch == '\'') {
            const char escaped[6] = { '\\', 'u', '0', '0', hex[ch >> 4], hex[ch & 15] };
            __viewmodifier_sink_put(sink, escaped, 6);
            continue;
        }

        __viewmodifier_sink_char(sink, (char)ch);
    }

    __viewmodifier_sink_char(sink, '"');
}

/**
 * Writes a number so that it reads back as the same long double:
 * viewexpr_number_format() stops at 17 significant digits, which is right
 * for a page but loses the low digits of a document value. Integers below
 * 2^64 are written exactly, others in the shortest form that round-trips.
 * Non-finite numbers have no JSON form and become null.
 */
static void __viewmodifier_json_number(viewmodifier_sink_t* sink, long double number) {
    char buffer[VIEWMODIFIER_LDBL_DIGITS + 32];

    if (!isfinite(number)) {
        __viewmodifier_sink_put(sink, "null", 4);
        return;
    }

    if (number == 0) {
        __viewmodifier_sink_char(sink, '0'); // -0 too
        return;
    }

    // JSON has a decimal point whatever the application's locale
    const locale_t previous = uselocale(numeric_locale());

    int written = 0;
    if (floorl(number) == number && fabsl(number) < 18446744073709551616.0L)
        written = snprintf(buffer, sizeof(buffer), "%.0Lf", number);
    else {
        for (int precision = 1; precision <= VIEWMODIFIER_LDBL_DIGITS; precision++) {
            written = snprintf(buffer, sizeof(buffer), "%.*Lg", precision, number);
            if (strtold(buffer, NULL) == number) break;
        }
    }

    uselocale(previous);

    if (written <= 0 || (size_t)written >= sizeof(buffer)) {
        __viewmodifier_sink_put(sink, "null", 4);
        return;
    }

    __viewmodifier_sink_put(sink, buffer, (size_t)written);
}

/**
 * Serializes a value as JSON into the sink.
 *
 * @return 1 on success, 0 if containers nest deeper than VIEWMODIFIER_JSON_MAX_DEPTH.
 */
static int __viewmodifier_json_value(viewmodifier_sink_t* sink, const viewexpr_value_t* value, int depth) {
    switch (value->type)
    {
    case VIEWEXPR_STRING:
    {
        if (value->string != NULL)
            __viewmodifier_json_string(sink, value->string, value->length);
        else
            __viewmodifier_json_string(sink, "", 0);
        return 1;
    }
    case VIEWEXPR_NUMBER:
        __viewmodifier_json_number(sink, value->number);
        return 1;
    case VIEWEXPR_BOOL:
        if (value->boolean) __viewmodifier_sink_put(sink, "true", 4);
        else __viewmodifier_sink_put(sink, "false", 5);
        return 1;
    case VIEWEXPR_TOKEN:
    {
        if (depth >= VIEWMODIFIER_JSON_MAX_DEPTH) return 0;

        const json_token_t* token = value->token;
        const int object = token->type == JSON_OBJECT;

        __viewmodifier_sink_char(sink, object ? '{' : '[');

        int first = 1;
        for (json_it_t it = json_init_it(token); !json_end_it(&it); it = json_next_it(&it)) {
            if (!first) __viewmodifier_sink_char(sink, ',');
            first = 0;

            if (object) {
                const char* key = json_string(it.key);
                __viewmodifier_json_string(sink, key != NULL ? key : "", key != NULL ? json_string_size(it.key) : 0);
                __viewmodifier_sink_char(sink, ':');
            }

            const viewexpr_value_t item = viewexpr_value_from_token(json_it_value(&it));
            if (!__viewmodifier_json_value(sink, &item, depth + 1)) return 0;
        }

        __viewmodifier_sink_char(sink, object ? '}' : ']');
        return 1;
    }
    default:
        __viewmodifier_sink_put(sink, "null", 4);
        return 1;
    }
}

static viewexpr_value_t __viewmodifier_json(arena_t* arena, const viewexpr_value_t* input, const viewexpr_value_t* args, size_t argc) {
    (void)args; (void)argc;

    if (arena == NULL) return __viewmodifier_null();

    viewmodifier_sink_t sink = { NULL, 0 };
    if (!__viewmodifier_json_value(&sink, input, 0)) return __viewmodifier_null();

    char* result = arena_alloc(arena, sink.size + 1);
    if (result == NULL) return __viewmodifier_null();

    const size_t size = sink.size;
    sink.out = result;
    sink.size = 0;
    __viewmodifier_json_value(&sink, input, 0);
    result[size] = 0;

    return __viewmodifier_string(result, size);
}

/**
 * VIEW_ESCAPE: HTML-escapes the text and turns every line break (CRLF, LF
 * or CR) into "<br>\n". VIEW_RAW: writes the text as is. NUL bytes become
 * U+FFFD in both modes, as in viewmodifier_write_text().
 */
static void __viewmodifier_nl2br(str_t* buf, const viewexpr_value_t* input, view_escape_e escape) {
    char buffer[VIEWMODIFIER_NUMBER_BUFFER_SIZE];
    size_t length = 0;
    const char* text = __viewmodifier_text(input, buffer, &length);
    if (text == NULL) return;

    if (escape == VIEW_RAW) {
        viewmodifier_write_text(buf, text, length, VIEW_RAW);
        return;
    }

    // runs between line breaks are written escaped, each break as <br>
    size_t start = 0;
    for (size_t i = 0; i < length; i++) {
        if (text[i] != '\r' && text[i] != '\n') continue;

        viewmodifier_write_text(buf, text + start, i - start, VIEW_ESCAPE);
        __viewmodifier_write(buf, "<br>\n", 5);

        if (text[i] == '\r' && i + 1 < length && text[i + 1] == '\n') i++;
        start = i + 1;
    }

    viewmodifier_write_text(buf, text + start, length - start, VIEW_ESCAPE);
}

static const viewmodifier_t __viewmodifiers[] = {
    { "raw",        0, 0, VIEWMOD_RAW,   NULL,                      NULL },
    { "upper",      0, 0, VIEWMOD_VALUE, __viewmodifier_upper,      NULL },
    { "lower",      0, 0, VIEWMOD_VALUE, __viewmodifier_lower,      NULL },
    { "capitalize", 0, 0, VIEWMOD_VALUE, __viewmodifier_capitalize, NULL },
    { "trim",       0, 0, VIEWMOD_VALUE, __viewmodifier_trim,       NULL },
    { "truncate",   1, 2, VIEWMOD_VALUE, __viewmodifier_truncate,   NULL },
    { "replace",    2, 2, VIEWMOD_VALUE, __viewmodifier_replace,    NULL },
    { "default",    1, 1, VIEWMOD_VALUE, __viewmodifier_default,    NULL },
    { "abs",        0, 0, VIEWMOD_VALUE, __viewmodifier_abs,        NULL },
    { "round",      0, 1, VIEWMOD_VALUE, __viewmodifier_round,      NULL },
    { "number",     0, 3, VIEWMOD_VALUE, __viewmodifier_number,     NULL },
    { "length",     0, 0, VIEWMOD_VALUE, __viewmodifier_length,     NULL },
    { "first",      0, 0, VIEWMOD_VALUE, __viewmodifier_first,      NULL },
    { "last",       0, 0, VIEWMOD_VALUE, __viewmodifier_last,       NULL },
    { "join",       0, 1, VIEWMOD_VALUE, __viewmodifier_join,       NULL },
    { "url",        0, 0, VIEWMOD_VALUE, __viewmodifier_url,        NULL },
    { "json",       0, 0, VIEWMOD_VALUE, __viewmodifier_json,       NULL },
    { "nl2br",      0, 0, VIEWMOD_SAFE,  NULL,                      __viewmodifier_nl2br },
};

/**
 * Looks a modifier up by name.
 *
 * @param name The name (does not need to be NUL-terminated).
 * @param length The name length in bytes.
 * @return The registry entry, or NULL if there is no such modifier.
 */
const viewmodifier_t* viewmodifier_find(const char* name, size_t length) {
    if (name == NULL) return NULL;

    for (size_t i = 0; i < sizeof(__viewmodifiers) / sizeof(__viewmodifiers[0]); i++) {
        const viewmodifier_t* modifier = &__viewmodifiers[i];
        if (strlen(modifier->name) == length && memcmp(modifier->name, name, length) == 0)
            return modifier;
    }

    return NULL;
}

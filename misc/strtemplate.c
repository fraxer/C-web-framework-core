#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "strtemplate.h"

#define STRTEMPLATE_OUT_OF_MEMORY "Template error: Out of memory\n"
#define STRTEMPLATE_BIG_VALUE_PARAM "Template error: Big number in param \"%s\"\n"

#define STRTEMPLATE_MAX_NUMBER_LENGTH 2

typedef struct strtemplate_param {
    int number;
    size_t start;
    size_t end;
    struct strtemplate_param* next;
} strtemplate_param_t;

struct strtemplate {
    int params_count;
    int max_param;
    char* source;
    size_t source_length;
    strtemplate_param_t* param;
    strtemplate_param_t* last_param;
};

static int __parse(strtemplate_t* tpl);
static int __parse_token(strtemplate_t* tpl, size_t* pos);
static int __alloc_param(strtemplate_t* tpl, size_t start, size_t end, int number);
static void __append(char* out, size_t* offset, const char* string, size_t length);

strtemplate_t* strtemplate_create(const char* source) {
    if (source == NULL || source[0] == 0) return NULL;

    strtemplate_t* tpl = malloc(sizeof * tpl);
    if (tpl == NULL) {
        log_error(STRTEMPLATE_OUT_OF_MEMORY);
        return NULL;
    }

    tpl->params_count = 0;
    tpl->max_param = 0;
    tpl->source_length = strlen(source);
    tpl->param = NULL;
    tpl->last_param = NULL;

    tpl->source = malloc(tpl->source_length + 1);
    if (tpl->source == NULL) {
        log_error(STRTEMPLATE_OUT_OF_MEMORY);
        free(tpl);
        return NULL;
    }
    memcpy(tpl->source, source, tpl->source_length + 1);

    if (__parse(tpl) == -1) {
        strtemplate_free(tpl);
        return NULL;
    }

    return tpl;
}

void strtemplate_free(strtemplate_t* tpl) {
    if (tpl == NULL) return;

    strtemplate_param_t* param = tpl->param;
    while (param != NULL) {
        strtemplate_param_t* next = param->next;
        free(param);
        param = next;
    }

    free(tpl->source);
    free(tpl);
}

int strtemplate_params_count(const strtemplate_t* tpl) {
    return tpl != NULL ? tpl->params_count : 0;
}

int strtemplate_max_param(const strtemplate_t* tpl) {
    return tpl != NULL ? tpl->max_param : 0;
}

int __parse(strtemplate_t* tpl) {
    for (size_t pos = 0; tpl->source[pos] != 0; pos++) {
        if (tpl->source[pos] != '{') continue;

        if (__parse_token(tpl, &pos) == -1) return -1;
    }

    return 0;
}

/* On entry `*pos` is the opening brace. On return it is the last character the
 * caller's loop has consumed: the closing brace of a placeholder, or -- when
 * the braces turned out to hold something that is not a number -- the character
 * before whatever ended the run, so the same character is examined again as
 * plain text. */
int __parse_token(strtemplate_t* tpl, size_t* pos) {
    const size_t start = *pos;

    (*pos)++;

    for (; tpl->source[*pos] != 0; (*pos)++) {
        const char c = tpl->source[*pos];

        if (c == '}') {
            const size_t digits = *pos - (start + 1);

            /* "{}" is not a placeholder, it is two literal characters. */
            if (digits == 0) return 0;

            if (digits > STRTEMPLATE_MAX_NUMBER_LENGTH) {
                log_error(STRTEMPLATE_BIG_VALUE_PARAM, &tpl->source[start]);
                return -1;
            }

            char number[STRTEMPLATE_MAX_NUMBER_LENGTH + 1] = {0};
            memcpy(number, &tpl->source[start + 1], digits);

            return __alloc_param(tpl, start, *pos + 1, atoi(number));
        }

        if (c == '{' || !isdigit((unsigned char)c)) {
            (*pos)--;
            return 0;
        }
    }

    /* Unterminated: `*pos` sits on the null terminator. Step back so the
     * caller's increment lands on it rather than past it. */
    (*pos)--;

    return 0;
}

int __alloc_param(strtemplate_t* tpl, size_t start, size_t end, int number) {
    strtemplate_param_t* param = malloc(sizeof * param);
    if (param == NULL) {
        log_error(STRTEMPLATE_OUT_OF_MEMORY);
        return -1;
    }

    param->number = number;
    param->start = start;
    param->end = end;
    param->next = NULL;

    if (tpl->param == NULL)
        tpl->param = param;
    else
        tpl->last_param->next = param;

    tpl->last_param = param;

    tpl->params_count++;
    if (number > tpl->max_param) tpl->max_param = number;

    return 0;
}

/* Length of capture group `number`; a group that did not participate has its
 * offsets left at -1 by the caller. */
static size_t __param_length(const int* vector, int number) {
    if (vector == NULL) return 0;

    const int start = vector[number * 2];
    const int end = vector[number * 2 + 1];

    if (start < 0 || end < start) return 0;

    return (size_t)(end - start);
}

char* strtemplate_expand(const strtemplate_t* tpl, const char* subject, const int* vector) {
    if (tpl == NULL) return NULL;

    if (tpl->param == NULL) {
        char* out = malloc(tpl->source_length + 1);
        if (out == NULL) return NULL;

        memcpy(out, tpl->source, tpl->source_length + 1);

        return out;
    }

    size_t length = 0;
    size_t start_pos = 0;

    for (const strtemplate_param_t* param = tpl->param; param; param = param->next) {
        length += param->start - start_pos;
        length += __param_length(vector, param->number);

        start_pos = param->end;
    }

    if (start_pos < tpl->source_length)
        length += tpl->source_length - start_pos;

    char* out = malloc(length + 1);
    if (out == NULL) return NULL;

    length = 0;
    start_pos = 0;

    for (const strtemplate_param_t* param = tpl->param; param; param = param->next) {
        __append(out, &length, &tpl->source[start_pos], param->start - start_pos);

        const size_t param_length = __param_length(vector, param->number);
        if (param_length > 0)
            __append(out, &length, &subject[vector[param->number * 2]], param_length);

        start_pos = param->end;
    }

    if (start_pos < tpl->source_length)
        __append(out, &length, &tpl->source[start_pos], tpl->source_length - start_pos);

    out[length] = 0;

    return out;
}

void __append(char* out, size_t* offset, const char* string, size_t length) {
    memcpy(&out[*offset], string, length);

    *offset += length;
    out[*offset] = 0;
}

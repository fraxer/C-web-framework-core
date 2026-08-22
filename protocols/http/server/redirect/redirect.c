#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "redirect.h"

#define REDIRECT_ERROR_OUT_OF_MEMORY "Redirect error: Out of memory\n"
#define REDIRECT_ERROR_CHECK_PARAM "Redirect error: params count is not equal substrings count in location \"%s\"\n"
#define REDIRECT_ERROR_PARAM_NUMBER "Redirect error: param number exceeds captures count in location \"%s\"\n"

static redirect_t* redirect_init(const char* destination);
static int redirect_check_params(redirect_t* redirect, const char* destination);

/* Nothing PCRE reads as an operator: then the pattern means the string it is
 * spelled with, and an unanchored match of it is a substring search. */
static int __location_is_literal(const char* location) {
    for (const char* p = location; *p != 0; p++) {
        switch (*p) {
        case '^': case '$': case '.': case '*': case '+': case '?':
        case '(': case ')': case '[': case ']': case '{': case '}':
        case '|': case '\\':
            return 0;
        default:
            break;
        }
    }

    return 1;
}

static int __contains(const char* haystack, size_t haystack_length,
                      const char* needle, size_t needle_length) {
    if (needle_length == 0) return 1;
    if (needle_length > haystack_length) return 0;

    const size_t last = haystack_length - needle_length;
    for (size_t i = 0; i <= last; i++)
        if (memcmp(haystack + i, needle, needle_length) == 0) return 1;

    return 0;
}

int redirect_matches(redirect_t* redirect, const char* path, size_t length,
                     int* vector, int vector_size) {
    if (redirect == NULL || path == NULL) return 0;

    if (redirect->is_literal)
        return __contains(path, length, redirect->literal, redirect->literal_length);

    return pcre_exec(redirect->location, NULL, path, (int)length, 0, 0, vector, vector_size) >= 0;
}

redirect_t* redirect_create(const char* location, const char* destination) {
    redirect_t* result = NULL;

    redirect_t* redirect = redirect_init(destination);

    if (redirect == NULL) goto failed;

    redirect->location = pcre_compile(location, 0, &redirect->location_error, &redirect->location_erroffset, NULL);

    if (redirect->location == NULL) goto failed;
    if (redirect->location_error != NULL) goto failed;

    if (redirect_check_params(redirect, destination) == -1) goto failed;

    /* Only without capture groups: a destination that expands {1} needs the
     * offsets PCRE fills in, and a literal location has none to give. */
    if (redirect->params_count == 0 && __location_is_literal(location)) {
        redirect->literal_length = strlen(location);
        redirect->literal = malloc(redirect->literal_length + 1);
        if (redirect->literal == NULL) goto failed;

        memcpy(redirect->literal, location, redirect->literal_length + 1);
        redirect->is_literal = 1;
    }

    result = redirect;

    failed:

    if (result == NULL) {
        redirect_free(redirect);
    }

    return result;
}

redirect_t* redirect_init(const char* destination) {
    redirect_t* redirect = (redirect_t*)malloc(sizeof(redirect_t));

    if (redirect == NULL) {
        log_error(REDIRECT_ERROR_OUT_OF_MEMORY);
        return NULL;
    }

    redirect->location_error = NULL;
    redirect->is_literal = 0;
    redirect->literal = NULL;
    redirect->literal_length = 0;
    redirect->params_count = 0;
    redirect->location_erroffset = 0;
    redirect->location = NULL;
    redirect->destination = NULL;
    redirect->next = NULL;

    redirect->destination = strtemplate_create(destination);
    if (redirect->destination == NULL) {
        free(redirect);
        return NULL;
    }

    redirect->params_count = strtemplate_params_count(redirect->destination);

    return redirect;
}

/* Every capture group of the location must be spent by the destination, and no
 * placeholder may name a group that does not exist: either way the redirect
 * would silently produce a URI the operator did not write. */
int redirect_check_params(redirect_t* redirect, const char* destination) {
    int where = 0;

    if (pcre_fullinfo(redirect->location, NULL, PCRE_INFO_CAPTURECOUNT, &where) != 0) return -1;

    if (where != redirect->params_count) {
        log_error(REDIRECT_ERROR_CHECK_PARAM, destination);
        return -1;
    }

    if (strtemplate_max_param(redirect->destination) > where) {
        log_error(REDIRECT_ERROR_PARAM_NUMBER, destination);
        return -1;
    }

    return 0;
}

void redirect_free(redirect_t* redirect) {
    while (redirect != NULL) {
        redirect_t* redirect_next = redirect->next;

        if (redirect->location) pcre_free(redirect->location);

        free(redirect->literal);
        strtemplate_free(redirect->destination);
        free(redirect);

        redirect = redirect_next;
    }
}

char* redirect_get_uri(redirect_t* redirect, const char* string, int* vector) {
    return strtemplate_expand(redirect->destination, string, vector);
}

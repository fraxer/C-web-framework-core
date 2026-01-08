#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "i18n.h"
#include "http.h"
#include "map.h"
#include "translation.h"

// Get language from request (query param > Accept-Language > default)
static char* get_lang(httpctx_t* ctx) {
    int ok = 0;
    const char* lang = query_param_char(ctx->request, "lang", &ok);
    if (ok && lang != NULL) return strdup(lang);

    http_header_t* header = ctx->request->get_header(ctx->request, "Accept-Language");
    if (header != NULL)
        return i18n_parse_accept_language(header->value);

    return strdup("en");
}

// Find i18n instance by domain name
static i18n_t* find_i18n(const char* domain) {
    map_t* translations = appconfig()->translations;
    if (translations == NULL || domain == NULL) return NULL;

    return map_find(translations, domain);
}

// Replace {placeholders} with values
static char* replace_placeholders(const char* template, va_list args) {
    if (template == NULL) return NULL;

    // Collect key-value pairs
    typedef struct { const char* key; const char* value; } pair_t;
    pair_t pairs[16];
    size_t pair_count = 0;

    while (pair_count < 16) {
        const char* key = va_arg(args, const char*);
        if (key == NULL) break;

        const char* value = va_arg(args, const char*);
        if (value == NULL) break;

        pairs[pair_count].key = key;
        pairs[pair_count].value = value;
        pair_count++;
    }

    // Calculate result size
    size_t result_size = 0;
    const char* p = template;

    while (*p) {
        if (*p == '{') {
            const char* start = p + 1;
            const char* end = strchr(start, '}');

            if (end != NULL) {
                size_t key_len = end - start;

                int found = 0;
                for (size_t i = 0; i < pair_count; i++) {
                    if (strlen(pairs[i].key) == key_len && strncmp(pairs[i].key, start, key_len) == 0) {
                        result_size += strlen(pairs[i].value);
                        found = 1;
                        break;
                    }
                }

                if (!found) {
                    result_size += (end - p + 1);
                }

                p = end + 1;
                continue;
            }
        }

        result_size++;
        p++;
    }

    // Build result
    char* result = malloc(result_size + 1);
    if (result == NULL) return NULL;

    char* out = result;
    p = template;

    while (*p) {
        if (*p == '{') {
            const char* start = p + 1;
            const char* end = strchr(start, '}');

            if (end != NULL) {
                size_t key_len = end - start;

                int found = 0;
                for (size_t i = 0; i < pair_count; i++) {
                    if (strlen(pairs[i].key) == key_len && strncmp(pairs[i].key, start, key_len) == 0) {
                        size_t val_len = strlen(pairs[i].value);
                        memcpy(out, pairs[i].value, val_len);
                        out += val_len;
                        found = 1;
                        break;
                    }
                }

                if (!found) {
                    size_t chunk_len = end - p + 1;
                    memcpy(out, p, chunk_len);
                    out += chunk_len;
                }

                p = end + 1;
                continue;
            }
        }

        *out++ = *p++;
    }

    *out = '\0';
    return result;
}

const char* tr(httpctx_t* ctx, const char* domain, const char* msgid) {
    i18n_t* i18n = find_i18n(domain);
    if (i18n == NULL) return msgid;

    char* lang = get_lang(ctx);
    const char* result = i18n_get(i18n, msgid, lang);
    free(lang);

    return result;
}

char* trf(httpctx_t* ctx, const char* domain, const char* msgid, ...) {
    const char* template = tr(ctx, domain, msgid);

    va_list args;
    va_start(args, msgid);
    char* result = replace_placeholders(template, args);
    va_end(args);

    return result;
}

const char* trn(httpctx_t* ctx, const char* domain, const char* singular, const char* plural, unsigned long n) {
    i18n_t* i18n = find_i18n(domain);
    if (i18n == NULL) return n == 1 ? singular : plural;

    char* lang = get_lang(ctx);
    const char* result = i18n_nget(i18n, singular, plural, n, lang);
    free(lang);

    return result;
}

char* trnf(httpctx_t* ctx, const char* domain, const char* singular, const char* plural, unsigned long n, ...) {
    const char* template = trn(ctx, domain, singular, plural, n);

    va_list args;
    va_start(args, n);
    char* result = replace_placeholders(template, args);
    va_end(args);

    return result;
}

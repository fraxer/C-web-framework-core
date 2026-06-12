#include "cookieparser.h"

void cookieparser_init(cookieparser_t* parser) {
    parser->error = NULL;
    parser->cookie = NULL;
    parser->last_cookie = NULL;
}

int cookieparser_parse(cookieparser_t* parser, const char* buffer, size_t buffer_size) {
    if (buffer == NULL) {
        if (parser) parser->error = "cookie parser: invalid arguments";
        return 0;
    }
    if (parser == NULL) {
        return 0;
    }

    size_t token_start = 0;
    size_t eq_pos = 0;
    int has_eq = 0;

    for (size_t i = 0; ; i++) {
        const int at_end = (i == buffer_size);
        const char ch = at_end ? '\0' : buffer[i];

        if (!at_end && ch == '=' && !has_eq) {
            eq_pos = i;
            has_eq = 1;
        }
        else if (at_end || ch == ';') {
            /* Токен без '=' или с пустым ключом молча пропускаем,
               не ломая разбор последующих пар. */
            if (has_eq) {
                size_t key_start = token_start;
                while (key_start < eq_pos && buffer[key_start] == ' ')
                    key_start++;

                const size_t key_length = eq_pos - key_start;
                const size_t value_start = eq_pos + 1;
                const size_t value_length = i - value_start;

                if (key_length > 0) {
                    http_cookie_t* cookie = http_cookie_create();
                    if (cookie == NULL) {
                        parser->error = "cookie parser: failed to allocate cookie";
                        return 0;
                    }

                    cookie->key = copy_cstringn(&buffer[key_start], key_length);
                    cookie->value = copy_cstringn(&buffer[value_start], value_length);

                    if (cookie->key == NULL || cookie->value == NULL) {
                        http_cookie_free(cookie);
                        parser->error = "cookie parser: failed to allocate key or value";
                        return 0;
                    }

                    cookie->key_length = key_length;
                    cookie->value_length = value_length;

                    if (parser->last_cookie != NULL)
                        parser->last_cookie->next = cookie;
                    else
                        parser->cookie = cookie;

                    parser->last_cookie = cookie;
                }
            }

            token_start = i + 1;
            has_eq = 0;
        }

        if (at_end) return 1;
    }

    parser->error = "cookie parser: failed to parse cookie";
    return 0;
}

http_cookie_t* cookieparser_cookie(cookieparser_t* parser) {
    return parser->cookie;
}
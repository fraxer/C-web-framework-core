#define _GNU_SOURCE
#include "i18n.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Thread-local locale for each thread
static _Thread_local locale_t thread_locale = (locale_t)0;

// Map short lang code to system locale name
static const char* get_locale_name(const char* lang) {
    if (strcmp(lang, "ru") == 0) return "ru_RU.utf8";
    if (strcmp(lang, "en") == 0) return "en_US.utf8";
    if (strcmp(lang, "de") == 0) return "de_DE.utf8";
    if (strcmp(lang, "fr") == 0) return "fr_FR.utf8";
    if (strcmp(lang, "es") == 0) return "es_ES.utf8";
    if (strcmp(lang, "zh") == 0) return "zh_CN.utf8";
    if (strcmp(lang, "ja") == 0) return "ja_JP.utf8";
    // fallback: try lang_LANG.utf8 pattern
    return NULL;
}

static void set_thread_locale(const char* lang) {
    if (lang == NULL || *lang == '\0') return;

    // Free previous locale if exists
    if (thread_locale != (locale_t)0) {
        freelocale(thread_locale);
        thread_locale = (locale_t)0;
    }

    const char* locale_name = get_locale_name(lang);

    if (locale_name != NULL) {
        thread_locale = newlocale(LC_MESSAGES_MASK, locale_name, (locale_t)0);
    }

    // Fallback: try constructed name like "ru_RU.utf8"
    if (thread_locale == (locale_t)0) {
        char constructed[32];
        snprintf(constructed, sizeof(constructed), "%s_%s.utf8",
                 lang,
                 (strcmp(lang, "en") == 0) ? "US" :
                 (strcmp(lang, "ru") == 0) ? "RU" : "");
        thread_locale = newlocale(LC_MESSAGES_MASK, constructed, (locale_t)0);
    }

    // Last fallback: C.UTF-8
    if (thread_locale == (locale_t)0) {
        thread_locale = newlocale(LC_MESSAGES_MASK, "C.UTF-8", (locale_t)0);
    }

    if (thread_locale != (locale_t)0) {
        uselocale(thread_locale);
    }
}

i18n_t* i18n_create(const char* locale_dir, const char* domain, const char* default_lang) {
    if (domain == NULL || default_lang == NULL) return NULL;

    i18n_t* i18n = calloc(1, sizeof(i18n_t));
    if (i18n == NULL) return NULL;

    i18n->domain = strdup(domain);
    if (i18n->domain == NULL) {
        free(i18n);
        return NULL;
    }

    if (locale_dir != NULL) {
        i18n->locale_dir = strdup(locale_dir);
        if (i18n->locale_dir == NULL) {
            free(i18n->domain);
            free(i18n);
            return NULL;
        }

        bindtextdomain(domain, locale_dir);
        bind_textdomain_codeset(domain, "UTF-8");
    }

    strncpy(i18n->default_lang, default_lang, sizeof(i18n->default_lang) - 1);
    i18n->default_lang[sizeof(i18n->default_lang) - 1] = '\0';

    // Initialize locale system
    setlocale(LC_ALL, "");

    return i18n;
}

const char* i18n_get(i18n_t* i18n, const char* msgid, const char* lang) {
    if (i18n == NULL || msgid == NULL) return msgid;

    const char* effective_lang = lang ? lang : i18n->default_lang;

    set_thread_locale(effective_lang);

    const char* result = dgettext(i18n->domain, msgid);

    // if translation not found (returns msgid) and lang != default, try default
    if (result == msgid && lang != NULL && strcmp(lang, i18n->default_lang) != 0) {
        set_thread_locale(i18n->default_lang);
        result = dgettext(i18n->domain, msgid);
    }

    return result;
}

const char* i18n_nget(i18n_t* i18n, const char* singular, const char* plural,
                      unsigned long n, const char* lang) {
    if (i18n == NULL || singular == NULL || plural == NULL) {
        return n == 1 ? singular : plural;
    }

    const char* effective_lang = lang ? lang : i18n->default_lang;

    set_thread_locale(effective_lang);

    const char* result = dngettext(i18n->domain, singular, plural, n);

    // if not translated, try default language
    if ((result == singular || result == plural) &&
        lang != NULL && strcmp(lang, i18n->default_lang) != 0) {
        set_thread_locale(i18n->default_lang);
        result = dngettext(i18n->domain, singular, plural, n);
    }

    return result;
}

char* i18n_parse_accept_language(const char* header) {
    if (header == NULL || *header == '\0') return strdup("en");

    const char* p = header;

    while (*p == ' ') p++;

    const char* start = p;
    while (*p && *p != '-' && *p != ',' && *p != ';' && *p != ' ') p++;

    size_t len = p - start;
    if (len == 0) return strdup("en");

    char* result = malloc(len + 1);
    if (result == NULL) return NULL;

    memcpy(result, start, len);
    result[len] = '\0';

    return result;
}

void i18n_free(i18n_t* i18n) {
    if (i18n == NULL) return;

    free(i18n->domain);
    free(i18n->locale_dir);
    free(i18n);
}

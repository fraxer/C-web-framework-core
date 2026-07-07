#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "i18n.h"

// Thread-local locale for each thread
static _Thread_local locale_t thread_locale = (locale_t)0;

// Locale mapping entry
typedef struct {
    const char* lang;
    const char* country;
    const char* locale_name;
} locale_entry_t;

// Supported locales mapping
static const locale_entry_t locale_map[] = {
    {"en", "US", "en_US.utf8"},
    {"ru", "RU", "ru_RU.utf8"},
    {"de", "DE", "de_DE.utf8"},
    {"fr", "FR", "fr_FR.utf8"},
    {"es", "ES", "es_ES.utf8"},
    {"zh", "CN", "zh_CN.utf8"},
    {"ja", "JP", "ja_JP.utf8"},
    {NULL, NULL, NULL}  // terminator
};

// Find locale entry by language code.
// Case-insensitive: Accept-Language tags are case-insensitive (RFC 5646),
// so "RU" and "en-US" must resolve the same locale as "ru"/"en".
static const locale_entry_t* find_locale_entry(const char* lang) {
    for (const locale_entry_t* entry = locale_map; entry->lang != NULL; entry++) {
        if (strcasecmp(entry->lang, lang) == 0) {
            return entry;
        }
    }
    return NULL;
}

// Map short lang code to system locale name
static const char* get_locale_name(const char* lang) {
    const locale_entry_t* entry = find_locale_entry(lang);
    return entry ? entry->locale_name : NULL;
}

// Map language code to country/territory code
static const char* get_country_code(const char* lang) {
    const locale_entry_t* entry = find_locale_entry(lang);
    return entry ? entry->country : NULL;
}

static void set_thread_locale(const char* lang) {
    if (lang == NULL || *lang == '\0') return;

    // Free previous locale if exists; detach it first — freeing the locale
    // currently installed by uselocale() is undefined behavior
    if (thread_locale != (locale_t)0) {
        uselocale(LC_GLOBAL_LOCALE);
        freelocale(thread_locale);
        thread_locale = (locale_t)0;
    }

    const char* locale_name = get_locale_name(lang);
    if (locale_name != NULL)
        thread_locale = newlocale(LC_MESSAGES_MASK, locale_name, (locale_t)0);

    // Fallback: try constructed name like "ru_RU.utf8"
    if (thread_locale == (locale_t)0) {
        const char* country = get_country_code(lang);
        if (country != NULL) {
            char constructed[32];
            snprintf(constructed, sizeof(constructed), "%s_%s.utf8", lang, country);
            thread_locale = newlocale(LC_MESSAGES_MASK, constructed, (locale_t)0);
        }
    }

    // Last fallback: C.UTF-8
    if (thread_locale == (locale_t)0)
        thread_locale = newlocale(LC_MESSAGES_MASK, "C.UTF-8", (locale_t)0);

    if (thread_locale != (locale_t)0)
        uselocale(thread_locale);
}

i18n_t* i18n_create(const char* locale_dir, const char* domain, const char* default_lang) {
    // dgettext("") behavior is unspecified — an empty domain must be rejected
    if (domain == NULL || *domain == '\0' || default_lang == NULL) return NULL;

    i18n_t* i18n = calloc(1, sizeof(i18n_t));
    if (i18n == NULL) return NULL;

    size_t default_lang_len = strlen(default_lang);
    if (default_lang_len == 0 || default_lang_len >= sizeof(i18n->default_lang)) {
        free(i18n);
        return NULL;
    }

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

    memcpy(i18n->default_lang, default_lang, default_lang_len);
    i18n->default_lang[default_lang_len] = '\0';

    return i18n;
}

const char* i18n_get(i18n_t* i18n, const char* msgid, const char* lang) {
    if (i18n == NULL || msgid == NULL) return msgid;

    // An empty lang must resolve to the default language: set_thread_locale("")
    // is a no-op, so passing it through would silently reuse whatever locale the
    // previous call on this thread installed.
    const char* effective_lang = (lang != NULL && *lang != '\0') ? lang : i18n->default_lang;

    set_thread_locale(effective_lang);

    const char* result = dgettext(i18n->domain, msgid);

    // if translation not found (returns msgid) and lang != default, try default
    if (result == msgid && strcasecmp(effective_lang, i18n->default_lang) != 0) {
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

    // see i18n_get: empty lang must not reuse the previous thread locale
    const char* effective_lang = (lang != NULL && *lang != '\0') ? lang : i18n->default_lang;

    set_thread_locale(effective_lang);

    const char* result = dngettext(i18n->domain, singular, plural, n);

    // if not translated, try default language
    if ((result == singular || result == plural) &&
        strcasecmp(effective_lang, i18n->default_lang) != 0) {
        set_thread_locale(i18n->default_lang);
        result = dngettext(i18n->domain, singular, plural, n);
    }

    return result;
}

// Parse a q=... parameter value; p points just past "q=".
// Returns q in [0,1]; a malformed value is treated as 1.0 (parameter ignored).
static double parse_qvalue(const char* p) {
    if (*p != '0' && *p != '1') return 1.0;

    double q = *p - '0';
    p++;
    if (*p == '.') {
        p++;
        double scale = 0.1;
        while (*p >= '0' && *p <= '9') {
            q += (*p - '0') * scale;
            scale /= 10.0;
            p++;
        }
    }

    return q > 1.0 ? 1.0 : q;
}

char* i18n_parse_accept_language(const char* header) {
    const char* best = NULL;
    size_t best_len = 0;
    // q=0 means "not acceptable" (RFC 7231), so entries only win with q > 0;
    // ties keep the earlier entry (client's listing order)
    double best_q = 0.0;

    if (header != NULL) {
        const char* p = header;
        while (*p != '\0') {
            while (*p == ' ' || *p == '\t' || *p == ',') p++;
            if (*p == '\0') break;

            // primary language subtag ("ru-RU" -> "ru")
            const char* start = p;
            while (*p != '\0' && *p != '-' && *p != ',' && *p != ';' && *p != ' ' && *p != '\t') p++;
            const size_t len = p - start;

            // skip the rest of the language-range up to parameters / next entry
            while (*p != '\0' && *p != ';' && *p != ',') p++;

            double q = 1.0;
            while (*p == ';') {
                p++;
                while (*p == ' ' || *p == '\t') p++;
                if ((*p == 'q' || *p == 'Q') && *(p + 1) == '=')
                    q = parse_qvalue(p + 2);
                while (*p != '\0' && *p != ';' && *p != ',') p++;
            }

            // "*" is a wildcard, not a concrete language — let it fall through
            // to the default
            if (len > 0 && !(len == 1 && *start == '*') && q > best_q) {
                best = start;
                best_len = len;
                best_q = q;
            }
        }
    }

    if (best == NULL) return strdup("en");

    char* result = malloc(best_len + 1);
    if (result == NULL) return NULL;

    // language tags are case-insensitive (RFC 5646): normalize for callers
    // that compare lang codes directly
    for (size_t i = 0; i < best_len; i++)
        result[i] = (char)tolower((unsigned char)best[i]);
    result[best_len] = '\0';

    return result;
}

void i18n_free(i18n_t* i18n) {
    if (i18n == NULL) return;

    free(i18n->domain);
    free(i18n->locale_dir);
    free(i18n);
}

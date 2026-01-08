#ifndef __I18N__
#define __I18N__

#include <libintl.h>
#include <locale.h>
#include <stdlib.h>

/**
 * i18n - Internationalization module using gettext
 *
 * Uses standard gettext for translations.
 * File structure: locale_dir/<lang>/LC_MESSAGES/<domain>.mo
 */

typedef struct i18n {
    char* domain;           // domain name (e.g., "identity")
    char* locale_dir;       // path to locale directory
    char default_lang[8];   // default language code (e.g., "en")
} i18n_t;

/**
 * Create i18n instance and bind textdomain.
 * @param locale_dir Path to locale directory (e.g., "backend/identity/locale")
 * @param domain Domain name for translations (e.g., "identity")
 * @param default_lang Default language code (e.g., "en")
 * @return i18n instance or NULL on error
 */
i18n_t* i18n_create(const char* locale_dir, const char* domain, const char* default_lang);

/**
 * Get translation by msgid and language.
 * Falls back to default language if translation not found.
 * Falls back to msgid itself if no translation exists.
 * @param i18n i18n instance
 * @param msgid Message identifier
 * @param lang Language code (e.g., "en", "ru")
 * @return Translated string (do not free)
 */
const char* i18n_get(i18n_t* i18n, const char* msgid, const char* lang);

/**
 * Get plural translation.
 * @param i18n i18n instance
 * @param singular Singular form msgid
 * @param plural Plural form msgid
 * @param n Count for plural selection
 * @param lang Language code
 * @return Translated string (do not free)
 */
const char* i18n_nget(i18n_t* i18n, const char* singular, const char* plural,
                      unsigned long n, const char* lang);

/**
 * Parse Accept-Language header and return primary language code.
 * Example: "ru-RU,ru;q=0.9,en-US;q=0.8" -> "ru"
 * @param header Accept-Language header value
 * @return Language code (caller must free) or NULL on allocation failure
 */
char* i18n_parse_accept_language(const char* header);

/**
 * Free i18n instance.
 * @param i18n i18n instance
 */
void i18n_free(i18n_t* i18n);

#endif

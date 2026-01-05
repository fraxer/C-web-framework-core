#ifndef __I18N__
#define __I18N__

#include "json.h"
#include "hashmap.h"

/**
 * i18n - Internationalization module
 *
 * Loads translations from JSON files in a locale directory.
 * File naming: <lang>.json (e.g., en.json, ru.json)
 *
 * JSON format:
 * {
 *     "key": "translated string",
 *     "another_key": "another translation"
 * }
 */

typedef struct i18n {
    hashmap_t* translations;     // key: "lang:message_key", value: char*
    char default_lang[8];        // default language code (e.g., "en")
} i18n_t;

/**
 * Create i18n instance and optionally load translations from directory.
 * @param locale_dir Path to directory containing JSON translation files (can be NULL)
 * @param default_lang Default language code (e.g., "en")
 * @return i18n instance or NULL on error
 */
i18n_t* i18n_create(const char* locale_dir, const char* default_lang);

/**
 * Load translations from a directory into existing i18n instance.
 * @param i18n i18n instance
 * @param locale_dir Path to directory containing JSON translation files
 * @return 1 on success, 0 on error
 */
int i18n_load_directory(i18n_t* i18n, const char* locale_dir);

/**
 * Get translation by key and language.
 * Falls back to default language if translation not found.
 * Falls back to key itself if no translation exists.
 * @param i18n i18n instance
 * @param key Message key
 * @param lang Language code (e.g., "en", "ru")
 * @return Translated string (do not free)
 */
const char* i18n_get(i18n_t* i18n, const char* key, const char* lang);

/**
 * Parse Accept-Language header and return primary language code.
 * Example: "ru-RU,ru;q=0.9,en-US;q=0.8" -> "ru"
 * @param header Accept-Language header value
 * @return Language code (caller must free) or NULL on allocation failure
 */
char* i18n_parse_accept_language(const char* header);

/**
 * Free i18n instance and all loaded translations.
 * @param i18n i18n instance
 */
void i18n_free(i18n_t* i18n);

#endif

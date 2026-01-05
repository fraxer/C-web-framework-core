#include "i18n.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "file.h"


// Create composite key "lang:message_key"
static char* make_key(const char* lang, const char* message_key) {
    size_t lang_len = strlen(lang);
    size_t key_len = strlen(message_key);
    char* composite = malloc(lang_len + 1 + key_len + 1);
    if (composite == NULL) return NULL;

    memcpy(composite, lang, lang_len);
    composite[lang_len] = ':';
    memcpy(composite + lang_len + 1, message_key, key_len);
    composite[lang_len + 1 + key_len] = '\0';

    return composite;
}

// Load translations from a single JSON file
static int load_translations_file(i18n_t* i18n, const char* filepath, const char* lang) {
    file_t file = file_open(filepath, O_RDONLY);
    if (!file.ok) return 0;

    char* content = file.content(&file);
    file.close(&file);

    if (content == NULL) return 0;

    json_doc_t* doc = json_parse(content);
    free(content);

    if (doc == NULL) return 0;

    json_token_t* root = json_root(doc);
    if (!json_is_object(root)) {
        json_free(doc);
        return 0;
    }

    // Iterate over all key-value pairs
    json_it_t it = json_init_it(root);
    while (!json_end_it(&it)) {
        const char* msg_key = json_it_key(&it);
        json_token_t* value = json_it_value(&it);

        if (json_is_string(value) && msg_key != NULL) {
            char* composite_key = make_key(lang, msg_key);
            if (composite_key != NULL) {
                const char* translation = json_string(value);
                char* translation_copy = strdup(translation);
                if (translation_copy != NULL) {
                    hashmap_insert(i18n->translations, composite_key, translation_copy);
                } else {
                    free(composite_key);
                }
            }
        }

        it = json_next_it(&it);
    }

    json_free(doc);
    return 1;
}

// Extract language code from filename (e.g., "en.json" -> "en")
static int extract_lang_from_filename(const char* filename, char* lang, size_t lang_size) {
    const char* dot = strrchr(filename, '.');
    if (dot == NULL) return 0;

    // Check extension is .json
    if (strcmp(dot, ".json") != 0) return 0;

    size_t lang_len = dot - filename;
    if (lang_len == 0 || lang_len >= lang_size) return 0;

    memcpy(lang, filename, lang_len);
    lang[lang_len] = '\0';

    return 1;
}

i18n_t* i18n_create(const char* locale_dir, const char* default_lang) {
    if (default_lang == NULL) return NULL;

    i18n_t* i18n = calloc(1, sizeof(i18n_t));
    if (i18n == NULL) return NULL;

    // Set default language
    strncpy(i18n->default_lang, default_lang, sizeof(i18n->default_lang) - 1);
    i18n->default_lang[sizeof(i18n->default_lang) - 1] = '\0';

    // Create hashmap with string keys
    i18n->translations = hashmap_create_ex(
        hashmap_hash_string,
        hashmap_equals_string,
        64,     // initial capacity
        0.75f,  // load factor
        NULL,   // key_copy (we manage keys ourselves)
        free,   // key_free
        NULL,   // value_copy
        free    // value_free
    );

    if (i18n->translations == NULL) {
        free(i18n);
        return NULL;
    }

    // Load translations from directory if provided
    if (locale_dir != NULL) {
        i18n_load_directory(i18n, locale_dir);
    }

    return i18n;
}

int i18n_load_directory(i18n_t* i18n, const char* locale_dir) {
    if (i18n == NULL || locale_dir == NULL) return 0;

    DIR* dir = opendir(locale_dir);
    if (dir == NULL) return 0;

    struct dirent* entry;
    char filepath[PATH_MAX];
    char lang[8];
    int loaded = 0;

    while ((entry = readdir(dir)) != NULL) {
        // Skip directories
        if (entry->d_type == DT_DIR) continue;

        // Extract language from filename
        if (!extract_lang_from_filename(entry->d_name, lang, sizeof(lang))) continue;

        // Build full path
        snprintf(filepath, sizeof(filepath), "%s/%s", locale_dir, entry->d_name);

        // Load translations
        if (load_translations_file(i18n, filepath, lang)) {
            loaded = 1;
        }
    }

    closedir(dir);

    return loaded;
}

const char* i18n_get(i18n_t* i18n, const char* key, const char* lang) {
    if (i18n == NULL || key == NULL) return key;

    const char* effective_lang = lang ? lang : i18n->default_lang;

    // Try requested language first
    char* composite_key = make_key(effective_lang, key);
    if (composite_key != NULL) {
        const char* result = hashmap_find(i18n->translations, composite_key);
        free(composite_key);
        if (result != NULL) return result;
    }

    // Fallback to default language
    if (lang != NULL && strcmp(lang, i18n->default_lang) != 0) {
        composite_key = make_key(i18n->default_lang, key);
        if (composite_key != NULL) {
            const char* result = hashmap_find(i18n->translations, composite_key);
            free(composite_key);
            if (result != NULL) return result;
        }
    }

    // Return key itself as last resort
    return key;
}

char* i18n_parse_accept_language(const char* header) {
    if (header == NULL || *header == '\0') return strdup("en");

    // Parse first language code from Accept-Language
    // Format: "ru-RU,ru;q=0.9,en-US;q=0.8"
    const char* p = header;

    // Skip whitespace
    while (*p == ' ') p++;

    // Find end of language code (stop at '-', ',', ';', or end)
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

    if (i18n->translations != NULL) {
        hashmap_free(i18n->translations);
    }

    free(i18n);
}

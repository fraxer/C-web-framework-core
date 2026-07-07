/*
 * Unit tests for misc/i18n.c: i18n_create, i18n_get, i18n_nget,
 * i18n_parse_accept_language, i18n_free.
 *
 * Catalog-independent paths (create/free guards, Accept-Language parsing)
 * always run. Lookup tests build minimal .mo catalogs (written byte-by-byte,
 * no msgfmt dependency) for a private domain in a temp directory and
 * self-skip when the ru_RU.utf8/en_US.utf8 system locales are unavailable.
 *
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - i18n_get/i18n_nget with an empty lang ("") reused the locale left on
 *     the thread by the previous call, returning another request's language;
 *     the fallback-to-default was also skipped when that stale catalog had
 *     the msgid.
 *   - The locale map lookup was case-sensitive, so lang "RU" (Accept-Language
 *     tags are case-insensitive per RFC 5646) silently fell back to the
 *     default language instead of the russian catalog.
 *   - i18n_parse_accept_language ignored q-values ("en;q=0.5,ru;q=0.9" picked
 *     "en"), returned the "*" wildcard literally, selected q=0 entries that
 *     RFC 7231 marks "not acceptable", did not treat tabs as whitespace and
 *     did not lowercase the result.
 *   - i18n_create accepted an empty domain, for which dgettext("") behavior
 *     is unspecified.
 */

#define _GNU_SOURCE
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "framework.h"
#include "i18n.h"

// ============================================================================
// Minimal .mo catalog writer (GNU gettext binary format, host byte order)
// ============================================================================

typedef struct {
    const char* msgid;
    size_t msgid_len;
    const char* msgstr;
    size_t msgstr_len;
} mo_entry_t;

// sizeof-based length keeps embedded NULs of plural entries ("one\0many")
#define MO(s) (s), sizeof(s) - 1

static int write_mo(const char* path, const mo_entry_t* e, uint32_t n) {
    FILE* f = fopen(path, "wb");
    if (f == NULL) return 0;

    const uint32_t orig_off = 28;
    const uint32_t trans_off = orig_off + 8 * n;
    const uint32_t data_off = trans_off + 8 * n;

    const uint32_t header[7] = {0x950412de, 0, n, orig_off, trans_off, 0, data_off};
    int ok = fwrite(header, sizeof(uint32_t), 7, f) == 7;

    uint32_t off = data_off;
    for (uint32_t i = 0; i < n && ok; i++) {
        const uint32_t rec[2] = {(uint32_t)e[i].msgid_len, off};
        ok = fwrite(rec, sizeof(uint32_t), 2, f) == 2;
        off += e[i].msgid_len + 1;
    }
    for (uint32_t i = 0; i < n && ok; i++) {
        const uint32_t rec[2] = {(uint32_t)e[i].msgstr_len, off};
        ok = fwrite(rec, sizeof(uint32_t), 2, f) == 2;
        off += e[i].msgstr_len + 1;
    }
    for (uint32_t i = 0; i < n && ok; i++)
        ok = fwrite(e[i].msgid, 1, e[i].msgid_len + 1, f) == e[i].msgid_len + 1;
    for (uint32_t i = 0; i < n && ok; i++)
        ok = fwrite(e[i].msgstr, 1, e[i].msgstr_len + 1, f) == e[i].msgstr_len + 1;

    fclose(f);
    return ok;
}

// Entries must stay sorted ascending by msgid (gettext requirement)
static const mo_entry_t i18n_mo_ru[] = {
    {MO(""), MO("Content-Type: text/plain; charset=UTF-8\n"
                "Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : "
                "n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);\n")},
    {MO("apple\0apples"), MO("яблоко\0яблока\0яблок")},
    {MO("hello"), MO("привет")},
    {MO("only.ru"), MO("только по-русски")},
};

static const mo_entry_t i18n_mo_en[] = {
    {MO(""), MO("Content-Type: text/plain; charset=UTF-8\n"
                "Plural-Forms: nplurals=2; plural=(n != 1);\n")},
    {MO("apple\0apples"), MO("apple [en]\0apples [en]")},
    {MO("hello"), MO("hello [en]")},
};

// ============================================================================
// One-time catalog environment (temp locale dir + i18n instance)
// ============================================================================

#define I18N_DOMAIN "cwfr_i18ntest"

static char i18n_root[64] = "";
static i18n_t* i18n_inst = NULL;
static int i18n_ready = 0;

static int i18n_locale_available(const char* name) {
    locale_t loc = newlocale(LC_MESSAGES_MASK, name, (locale_t)0);
    if (loc == (locale_t)0) return 0;
    freelocale(loc);
    return 1;
}

static void i18n_env_teardown(void) {
    if (i18n_inst != NULL) { i18n_free(i18n_inst); i18n_inst = NULL; }

    if (i18n_root[0] != '\0') {
        const char* langs[] = {"ru", "en"};
        char path[160];
        for (size_t i = 0; i < 2; i++) {
            snprintf(path, sizeof(path), "%s/%s/LC_MESSAGES/" I18N_DOMAIN ".mo", i18n_root, langs[i]);
            unlink(path);
            snprintf(path, sizeof(path), "%s/%s/LC_MESSAGES", i18n_root, langs[i]);
            rmdir(path);
            snprintf(path, sizeof(path), "%s/%s", i18n_root, langs[i]);
            rmdir(path);
        }
        rmdir(i18n_root);
        i18n_root[0] = '\0';
    }
}

static int i18n_make_catalog(const char* lang, const mo_entry_t* entries, uint32_t n) {
    char path[160];

    snprintf(path, sizeof(path), "%s/%s", i18n_root, lang);
    if (mkdir(path, 0755) != 0) return 0;

    snprintf(path, sizeof(path), "%s/%s/LC_MESSAGES", i18n_root, lang);
    if (mkdir(path, 0755) != 0) return 0;

    snprintf(path, sizeof(path), "%s/%s/LC_MESSAGES/" I18N_DOMAIN ".mo", i18n_root, lang);
    return write_mo(path, entries, n);
}

static void i18n_env_setup(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    // LANGUAGE overrides the thread locale in gettext lookups
    unsetenv("LANGUAGE");

    if (!i18n_locale_available("ru_RU.utf8") || !i18n_locale_available("en_US.utf8"))
        return;

    strcpy(i18n_root, "/tmp/cwfr_i18n_XXXXXX");
    if (mkdtemp(i18n_root) == NULL) {
        i18n_root[0] = '\0';
        return;
    }

    if (!i18n_make_catalog("ru", i18n_mo_ru, sizeof(i18n_mo_ru) / sizeof(i18n_mo_ru[0])) ||
        !i18n_make_catalog("en", i18n_mo_en, sizeof(i18n_mo_en) / sizeof(i18n_mo_en[0]))) {
        i18n_env_teardown();
        return;
    }

    i18n_inst = i18n_create(i18n_root, I18N_DOMAIN, "en");
    if (i18n_inst == NULL) {
        i18n_env_teardown();
        return;
    }

    atexit(i18n_env_teardown);
    i18n_ready = 1;
}

// Gettext-dependent tests self-skip when system locales are missing
#define REQUIRE_I18N_CATALOGS() do { \
    i18n_env_setup(); \
    if (!i18n_ready) { \
        TEST_ASSERT(1, "skipped: ru_RU.utf8/en_US.utf8 locales unavailable"); \
        return; \
    } \
} while (0)

// ============================================================================
// i18n_create / i18n_free
// ============================================================================

TEST(test_i18n_create_stores_fields) {
    TEST_CASE("i18n_create copies domain, locale_dir and default_lang");

    const char* domain = "i18n_test_domain";
    const char* dir = "/tmp/i18n_test_locale";

    i18n_t* i18n = i18n_create(dir, domain, "ru");
    TEST_REQUIRE_NOT_NULL(i18n, "i18n_create should succeed");

    TEST_ASSERT_STR_EQUAL(domain, i18n->domain, "domain should be stored");
    TEST_ASSERT(i18n->domain != domain, "domain must be a heap copy");
    TEST_ASSERT_STR_EQUAL(dir, i18n->locale_dir, "locale_dir should be stored");
    TEST_ASSERT(i18n->locale_dir != dir, "locale_dir must be a heap copy");
    TEST_ASSERT_STR_EQUAL("ru", i18n->default_lang, "default_lang should be stored");

    i18n_free(i18n);
}

TEST(test_i18n_create_null_locale_dir) {
    TEST_CASE("i18n_create allows a NULL locale_dir");

    i18n_t* i18n = i18n_create(NULL, "i18n_test_domain", "en");
    TEST_REQUIRE_NOT_NULL(i18n, "NULL locale_dir should be accepted");
    TEST_ASSERT_NULL(i18n->locale_dir, "locale_dir should stay NULL");
    i18n_free(i18n);
}

TEST(test_i18n_create_rejects_bad_args) {
    TEST_CASE("i18n_create rejects NULL/empty domain and NULL default_lang");

    TEST_ASSERT_NULL(i18n_create(NULL, NULL, "en"), "NULL domain must be rejected");
    // REGRESSION: an empty domain was accepted; dgettext("") is unspecified
    TEST_ASSERT_NULL(i18n_create(NULL, "", "en"), "empty domain must be rejected");
    TEST_ASSERT_NULL(i18n_create(NULL, "i18n_test_domain", NULL),
                     "NULL default_lang must be rejected");
}

TEST(test_i18n_create_default_lang_bounds) {
    TEST_CASE("i18n_create enforces default_lang length bounds");

    TEST_ASSERT_NULL(i18n_create(NULL, "i18n_test_domain", ""),
                     "empty default_lang must be rejected");

    // sizeof(default_lang) == 8: 7 characters fit, 8 do not
    i18n_t* i18n = i18n_create(NULL, "i18n_test_domain", "abcdefg");
    TEST_REQUIRE_NOT_NULL(i18n, "7-char default_lang should be accepted");
    TEST_ASSERT_STR_EQUAL("abcdefg", i18n->default_lang, "no truncation allowed");
    i18n_free(i18n);

    TEST_ASSERT_NULL(i18n_create(NULL, "i18n_test_domain", "abcdefgh"),
                     "8-char default_lang must be rejected");
}

TEST(test_i18n_free_null) {
    TEST_CASE("i18n_free(NULL) is a no-op");

    i18n_free(NULL);
    TEST_ASSERT(1, "i18n_free(NULL) should not crash");
}

// ============================================================================
// i18n_parse_accept_language (no catalogs needed)
// ============================================================================

TEST(test_i18n_parse_accept_language_basic) {
    TEST_CASE("i18n_parse_accept_language extracts the primary language");

    struct { const char* header; const char* expected; } cases[] = {
        {NULL, "en"},
        {"", "en"},
        {"   ", "en"},
        {"ru", "ru"},
        {"ru-RU", "ru"},
        {"ru-RU,ru;q=0.9,en-US;q=0.8", "ru"},
        {"  en-US", "en"},
        {"de;q=0.7", "de"},
        {"-", "en"},
        {",de", "de"},
        {"zh-Hant-TW", "zh"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char* lang = i18n_parse_accept_language(cases[i].header);
        TEST_REQUIRE_NOT_NULL(lang, "parser should return a string");
        TEST_ASSERT_STR_EQUAL(cases[i].expected, lang, "parsed language should match");
        free(lang);
    }
}

// REGRESSION: the parser took the first entry verbatim, ignoring q-values.
TEST(test_i18n_parse_accept_language_qvalues) {
    TEST_CASE("i18n_parse_accept_language picks the highest q-value");

    struct { const char* header; const char* expected; } cases[] = {
        {"en;q=0.5,ru;q=0.9", "ru"},
        {"da, en-gb;q=0.8, en;q=0.7", "da"},
        {"zh-Hant-TW;q=0.9,ja", "ja"},
        {"fr;q=0.300,es;q=0.301", "es"},
        // equal q keeps the earlier entry
        {"de;q=0.8,fr;q=0.8", "de"},
        // parameters other than q are skipped
        {"de;foo=bar;q=0.1,es", "es"},
        // malformed q counts as 1.0
        {"de;q=oops,en;q=0.9", "de"},
        // q > 1 is clamped, not preferred over a listed-earlier q=1 entry
        {"fr,de;q=1.5", "fr"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char* lang = i18n_parse_accept_language(cases[i].header);
        TEST_REQUIRE_NOT_NULL(lang, "parser should return a string");
        TEST_ASSERT_STR_EQUAL(cases[i].expected, lang, "q-value selection should match");
        free(lang);
    }
}

// REGRESSION: q=0 entries ("not acceptable" per RFC 7231) were selected and
// the "*" wildcard was returned literally.
TEST(test_i18n_parse_accept_language_q0_and_wildcard) {
    TEST_CASE("i18n_parse_accept_language skips q=0 entries and the wildcard");

    struct { const char* header; const char* expected; } cases[] = {
        {"ru;q=0", "en"},
        {"ru;q=0,de;q=0.5", "de"},
        {"ru;q=0.000", "en"},
        {"*", "en"},
        {"*;q=1,ru;q=0.5", "ru"},
        {"*, fr;q=0.9", "fr"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char* lang = i18n_parse_accept_language(cases[i].header);
        TEST_REQUIRE_NOT_NULL(lang, "parser should return a string");
        TEST_ASSERT_STR_EQUAL(cases[i].expected, lang, "q=0/wildcard handling should match");
        free(lang);
    }
}

// REGRESSION: the result kept the client's case ("RU-ru" -> "RU"), which
// never matched the case-sensitive locale map; tabs were not whitespace.
TEST(test_i18n_parse_accept_language_case_and_whitespace) {
    TEST_CASE("i18n_parse_accept_language lowercases and handles tabs");

    struct { const char* header; const char* expected; } cases[] = {
        {"RU-ru", "ru"},
        {"EN-us,RU;q=0.9", "en"},
        {"\tru", "ru"},
        {"en\t,\tru;q=0.9", "en"},
        {"de ;q=0.3,fr", "fr"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char* lang = i18n_parse_accept_language(cases[i].header);
        TEST_REQUIRE_NOT_NULL(lang, "parser should return a string");
        TEST_ASSERT_STR_EQUAL(cases[i].expected, lang, "case/whitespace handling should match");
        free(lang);
    }
}

// ============================================================================
// i18n_get (needs system locales + catalogs)
// ============================================================================

TEST(test_i18n_get_null_args) {
    TEST_CASE("i18n_get guards NULL i18n and NULL msgid");

    const char* msgid = "some message";
    TEST_ASSERT(i18n_get(NULL, msgid, "ru") == msgid, "NULL i18n should return the msgid");

    i18n_t* i18n = i18n_create(NULL, "i18n_test_domain", "en");
    TEST_REQUIRE_NOT_NULL(i18n, "i18n_create should succeed");
    TEST_ASSERT_NULL(i18n_get(i18n, NULL, "ru"), "NULL msgid should return NULL");
    i18n_free(i18n);
}

TEST(test_i18n_get_translates) {
    TEST_CASE("i18n_get returns the requested language's translation");

    REQUIRE_I18N_CATALOGS();

    TEST_ASSERT_STR_EQUAL("привет", i18n_get(i18n_inst, "hello", "ru"),
                          "lang=ru should give the russian catalog");
    TEST_ASSERT_STR_EQUAL("hello [en]", i18n_get(i18n_inst, "hello", "en"),
                          "lang=en should give the english catalog");
}

TEST(test_i18n_get_null_lang_uses_default) {
    TEST_CASE("i18n_get with NULL lang uses the default language");

    REQUIRE_I18N_CATALOGS();

    // warm the thread locale with another language first
    TEST_ASSERT_STR_EQUAL("привет", i18n_get(i18n_inst, "hello", "ru"), "warm-up in ru");

    TEST_ASSERT_STR_EQUAL("hello [en]", i18n_get(i18n_inst, "hello", NULL),
                          "NULL lang should resolve to the default catalog");
}

// REGRESSION: lang="" left the previous call's thread locale installed, so
// this returned "привет" — another request's language.
TEST(test_i18n_get_empty_lang_uses_default) {
    TEST_CASE("i18n_get with an empty lang uses the default language");

    REQUIRE_I18N_CATALOGS();

    TEST_ASSERT_STR_EQUAL("привет", i18n_get(i18n_inst, "hello", "ru"), "warm-up in ru");

    TEST_ASSERT_STR_EQUAL("hello [en]", i18n_get(i18n_inst, "hello", ""),
                          "empty lang must not reuse the previous locale");
}

// REGRESSION: the locale map lookup was case-sensitive, so "RU" silently
// fell back to the default language.
TEST(test_i18n_get_lang_case_insensitive) {
    TEST_CASE("i18n_get treats language codes case-insensitively");

    REQUIRE_I18N_CATALOGS();

    TEST_ASSERT_STR_EQUAL("привет", i18n_get(i18n_inst, "hello", "RU"),
                          "lang=RU should give the russian catalog");
    TEST_ASSERT_STR_EQUAL("привет", i18n_get(i18n_inst, "hello", "Ru"),
                          "lang=Ru should give the russian catalog");
}

TEST(test_i18n_get_unknown_lang_falls_back_to_default) {
    TEST_CASE("i18n_get falls back to the default language for unknown langs");

    REQUIRE_I18N_CATALOGS();

    TEST_ASSERT_STR_EQUAL("hello [en]", i18n_get(i18n_inst, "hello", "xx"),
                          "unknown lang should fall back to the default catalog");
}

TEST(test_i18n_get_missing_msgid_passthrough) {
    TEST_CASE("i18n_get returns the msgid when no catalog has a translation");

    REQUIRE_I18N_CATALOGS();

    const char* msgid = "no.such.msgid";
    TEST_ASSERT(i18n_get(i18n_inst, msgid, "ru") == msgid,
                "untranslated msgid should pass through unchanged");
}

TEST(test_i18n_get_msgid_missing_in_default) {
    TEST_CASE("i18n_get handles a msgid present only in a non-default catalog");

    REQUIRE_I18N_CATALOGS();

    TEST_ASSERT_STR_EQUAL("только по-русски", i18n_get(i18n_inst, "only.ru", "ru"),
                          "ru-only msgid should translate for lang=ru");

    const char* msgid = "only.ru";
    TEST_ASSERT(i18n_get(i18n_inst, msgid, "en") == msgid,
                "ru-only msgid should pass through for the default lang");
}

// ============================================================================
// i18n_nget (needs system locales + catalogs)
// ============================================================================

TEST(test_i18n_nget_null_args) {
    TEST_CASE("i18n_nget guards select the english plural rule");

    const char* singular = "one file";
    const char* plural = "many files";

    TEST_ASSERT(i18n_nget(NULL, singular, plural, 1, "ru") == singular, "n=1 gives singular");
    TEST_ASSERT(i18n_nget(NULL, singular, plural, 0, "ru") == plural, "n=0 gives plural");
    TEST_ASSERT(i18n_nget(NULL, singular, plural, 2, "ru") == plural, "n=2 gives plural");

    i18n_t* i18n = i18n_create(NULL, "i18n_test_domain", "en");
    TEST_REQUIRE_NOT_NULL(i18n, "i18n_create should succeed");
    TEST_ASSERT(i18n_nget(i18n, NULL, plural, 2, "ru") == plural,
                "NULL singular should fall back to the raw plural");
    TEST_ASSERT(i18n_nget(i18n, singular, NULL, 1, "ru") == singular,
                "NULL plural should fall back to the raw singular");
    i18n_free(i18n);
}

TEST(test_i18n_nget_russian_plurals) {
    TEST_CASE("i18n_nget selects the correct russian plural form");

    REQUIRE_I18N_CATALOGS();

    TEST_ASSERT_STR_EQUAL("яблоко", i18n_nget(i18n_inst, "apple", "apples", 1, "ru"), "n=1 -> form 0");
    TEST_ASSERT_STR_EQUAL("яблока", i18n_nget(i18n_inst, "apple", "apples", 2, "ru"), "n=2 -> form 1");
    TEST_ASSERT_STR_EQUAL("яблок", i18n_nget(i18n_inst, "apple", "apples", 5, "ru"), "n=5 -> form 2");
    TEST_ASSERT_STR_EQUAL("яблок", i18n_nget(i18n_inst, "apple", "apples", 11, "ru"), "n=11 -> form 2");
    TEST_ASSERT_STR_EQUAL("яблоко", i18n_nget(i18n_inst, "apple", "apples", 21, "ru"), "n=21 -> form 0");

    // REGRESSION: uppercase lang fell back to the default language
    TEST_ASSERT_STR_EQUAL("яблок", i18n_nget(i18n_inst, "apple", "apples", 5, "RU"),
                          "lang=RU should use russian plural forms");
}

TEST(test_i18n_nget_unknown_lang_falls_back_to_default) {
    TEST_CASE("i18n_nget falls back to the default language for unknown langs");

    REQUIRE_I18N_CATALOGS();

    TEST_ASSERT_STR_EQUAL("apple [en]", i18n_nget(i18n_inst, "apple", "apples", 1, "xx"),
                          "unknown lang, n=1 should give the english singular");
    TEST_ASSERT_STR_EQUAL("apples [en]", i18n_nget(i18n_inst, "apple", "apples", 2, "xx"),
                          "unknown lang, n=2 should give the english plural");
}

// REGRESSION: like i18n_get, an empty lang reused the previous thread locale.
TEST(test_i18n_nget_empty_lang_uses_default) {
    TEST_CASE("i18n_nget with an empty lang uses the default language");

    REQUIRE_I18N_CATALOGS();

    TEST_ASSERT_STR_EQUAL("яблок", i18n_nget(i18n_inst, "apple", "apples", 5, "ru"), "warm-up in ru");

    TEST_ASSERT_STR_EQUAL("apples [en]", i18n_nget(i18n_inst, "apple", "apples", 5, ""),
                          "empty lang must not reuse the previous locale");
}

TEST(test_i18n_nget_missing_msgid_passthrough) {
    TEST_CASE("i18n_nget returns raw forms when no catalog has a translation");

    REQUIRE_I18N_CATALOGS();

    const char* singular = "no.such.one";
    const char* plural = "no.such.many";
    TEST_ASSERT(i18n_nget(i18n_inst, singular, plural, 1, "ru") == singular,
                "untranslated n=1 should give the raw singular");
    TEST_ASSERT(i18n_nget(i18n_inst, singular, plural, 5, "ru") == plural,
                "untranslated n=5 should give the raw plural");
}

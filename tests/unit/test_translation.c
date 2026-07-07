/*
 * Unit tests for framework/translation/translation.c (tr/trf/trn/trnf) and
 * the i18n.c pieces they depend on.
 *
 * The placeholder engine and the msgid-fallback paths are tested without any
 * catalogs. Tests that need real translations build minimal .mo catalogs
 * (written byte-by-byte, no msgfmt dependency) for a private domain in a temp
 * directory and register an i18n_t in appconfig()->translations; they
 * self-skip when the ru_RU.utf8/en_US.utf8 system locales are unavailable.
 *
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - i18n_create truncated default_lang by one char ("en" -> "e"), breaking
 *     the fallback-to-default-language path of every tr/trn call; an empty
 *     default_lang wrote one byte out of bounds (default_lang[-1]).
 *   - get_lang used the ?lang= query value verbatim, so "?lang=ru-RU" never
 *     matched a locale while the equivalent Accept-Language header worked,
 *     and "?lang=" (empty) kept the locale left over from the previous
 *     request served by the same thread.
 *   - get_lang dereferenced ctx/ctx->request without a NULL check.
 */

#define _GNU_SOURCE
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "framework.h"
#include "appconfig.h"
#include "httpcontext.h"
#include "i18n.h"
#include "map.h"
#include "query.h"
#include "translation.h"

// ============================================================================
// Mock HTTP context: hand-built request with query list and header list
// ============================================================================

typedef struct {
    httprequest_t request;
    httpctx_t ctx;
    query_t query;
    http_header_t header;
} tr_env_t;

static http_header_t* mock_get_header(httprequest_t* request, const char* name) {
    for (http_header_t* h = request->header_; h != NULL; h = h->next)
        if (strcasecmp(h->key, name) == 0)
            return h;

    return NULL;
}

// query_lang / accept_language may be NULL to omit the query param / header
static httpctx_t* tr_ctx(tr_env_t* env, const char* query_lang, const char* accept_language) {
    memset(env, 0, sizeof(*env));

    env->request.get_header = mock_get_header;

    if (query_lang != NULL) {
        env->query.key = "lang";
        env->query.value = query_lang;
        env->request.query_ = &env->query;
    }

    if (accept_language != NULL) {
        env->header.key = "Accept-Language";
        env->header.value = (char*)accept_language;
        env->header.key_length = strlen(env->header.key);
        env->header.value_length = strlen(accept_language);
        env->request.header_ = &env->header;
    }

    env->ctx.request = &env->request;

    return &env->ctx;
}

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
static const mo_entry_t mo_ru[] = {
    {MO(""), MO("Content-Type: text/plain; charset=UTF-8\n"
                "Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : "
                "n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);\n")},
    {MO("apple\0apples"), MO("яблоко\0яблока\0яблок")},
    {MO("greeting"), MO("Привет, {name}!")},
    {MO("hello"), MO("привет")},
    {MO("{n} apple\0{n} apples"), MO("{n} яблоко\0{n} яблока\0{n} яблок")},
};

static const mo_entry_t mo_en[] = {
    {MO(""), MO("Content-Type: text/plain; charset=UTF-8\n"
                "Plural-Forms: nplurals=2; plural=(n != 1);\n")},
    {MO("greeting"), MO("Hello, {name}!")},
    {MO("hello"), MO("hello [en]")},
};

// ============================================================================
// One-time catalog environment (temp locale dir + i18n instance + domain map)
// ============================================================================

#define TR_DOMAIN "cwfr_trtest"

static char tr_root[64] = "";
static i18n_t* tr_i18n = NULL;
static map_t* tr_map = NULL;
static int tr_ready = 0;

static int locale_available(const char* name) {
    locale_t loc = newlocale(LC_MESSAGES_MASK, name, (locale_t)0);
    if (loc == (locale_t)0) return 0;
    freelocale(loc);
    return 1;
}

static void tr_teardown(void) {
    if (tr_map != NULL) { map_free(tr_map); tr_map = NULL; }
    if (tr_i18n != NULL) { i18n_free(tr_i18n); tr_i18n = NULL; }

    if (tr_root[0] != '\0') {
        const char* langs[] = {"ru", "en"};
        char path[160];
        for (size_t i = 0; i < 2; i++) {
            snprintf(path, sizeof(path), "%s/%s/LC_MESSAGES/" TR_DOMAIN ".mo", tr_root, langs[i]);
            unlink(path);
            snprintf(path, sizeof(path), "%s/%s/LC_MESSAGES", tr_root, langs[i]);
            rmdir(path);
            snprintf(path, sizeof(path), "%s/%s", tr_root, langs[i]);
            rmdir(path);
        }
        rmdir(tr_root);
        tr_root[0] = '\0';
    }
}

static int make_catalog(const char* lang, const mo_entry_t* entries, uint32_t n) {
    char path[160];

    snprintf(path, sizeof(path), "%s/%s", tr_root, lang);
    if (mkdir(path, 0755) != 0) return 0;

    snprintf(path, sizeof(path), "%s/%s/LC_MESSAGES", tr_root, lang);
    if (mkdir(path, 0755) != 0) return 0;

    snprintf(path, sizeof(path), "%s/%s/LC_MESSAGES/" TR_DOMAIN ".mo", tr_root, lang);
    return write_mo(path, entries, n);
}

static void tr_setup(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    // LANGUAGE overrides the thread locale in gettext lookups
    unsetenv("LANGUAGE");

    if (!locale_available("ru_RU.utf8") || !locale_available("en_US.utf8"))
        return;

    strcpy(tr_root, "/tmp/cwfr_tr_XXXXXX");
    if (mkdtemp(tr_root) == NULL) {
        tr_root[0] = '\0';
        return;
    }

    if (!make_catalog("ru", mo_ru, sizeof(mo_ru) / sizeof(mo_ru[0])) ||
        !make_catalog("en", mo_en, sizeof(mo_en) / sizeof(mo_en[0]))) {
        tr_teardown();
        return;
    }

    tr_i18n = i18n_create(tr_root, TR_DOMAIN, "en");
    if (tr_i18n == NULL) {
        tr_teardown();
        return;
    }

    tr_map = map_create_string();
    if (tr_map == NULL || map_insert(tr_map, TR_DOMAIN, tr_i18n) != 1) {
        tr_teardown();
        return;
    }

    atexit(tr_teardown);
    tr_ready = 1;
}

// Gettext-dependent tests self-skip when system locales are missing
#define REQUIRE_CATALOGS() do { \
    tr_setup(); \
    if (!tr_ready) { \
        TEST_ASSERT(1, "skipped: ru_RU.utf8/en_US.utf8 locales unavailable"); \
        return; \
    } \
    appconfig()->translations = tr_map; \
} while (0)

#define RELEASE_CATALOGS() do { appconfig()->translations = NULL; } while (0)

// ============================================================================
// Placeholder engine via trf (no catalogs: template == msgid)
// ============================================================================

TEST(test_trf_basic_replacement) {
    TEST_CASE("trf replaces a single placeholder");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "Hello, {name}!", "name", "World", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("Hello, World!", result, "placeholder should be replaced");
    free(result);
}

TEST(test_trf_multiple_and_repeated) {
    TEST_CASE("trf replaces multiple and repeated placeholders");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "{a} and {b} and {a}", "a", "1", "b", "2", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("1 and 2 and 1", result, "every occurrence should be replaced");
    free(result);
}

TEST(test_trf_unknown_placeholder_kept) {
    TEST_CASE("trf keeps unknown placeholders verbatim");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "{a} {missing}", "a", "x", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("x {missing}", result, "unknown placeholder should stay");
    free(result);
}

TEST(test_trf_unmatched_brace_literal) {
    TEST_CASE("trf copies an unmatched '{' as a literal");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "brace { end", "k", "v", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("brace { end", result, "lone '{' should be kept");
    free(result);

    result = trf(ctx, "nodomain", "{open", "open", "x", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("{open", result, "trailing unmatched '{key' should be kept");
    free(result);
}

TEST(test_trf_no_pairs) {
    TEST_CASE("trf without pairs returns a copy of the template");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    const char* template = "plain {text}";
    char* result = trf(ctx, "nodomain", template, NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL(template, result, "template should be unchanged");
    TEST_ASSERT(result != template, "result must be a heap copy the caller can free");
    free(result);
}

TEST(test_trf_empty_template) {
    TEST_CASE("trf handles an empty template");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "", "k", "v", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("", result, "empty template gives empty result");
    free(result);
}

TEST(test_trf_value_sizes) {
    TEST_CASE("trf handles empty and longer-than-key values");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "[{k}]", "k", "", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("[]", result, "empty value should erase the placeholder");
    free(result);

    result = trf(ctx, "nodomain", "[{k}]", "k", "0123456789", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("[0123456789]", result, "value longer than key should expand");
    free(result);
}

TEST(test_trf_value_not_rescanned) {
    TEST_CASE("trf does not expand placeholders inside substituted values");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "{a}", "a", "{b}", "b", "X", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("{b}", result, "value must be copied verbatim, not re-expanded");
    free(result);
}

TEST(test_trf_adjacent_and_edges) {
    TEST_CASE("trf handles adjacent placeholders and placeholders at the edges");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "{a}{b}", "a", "1", "b", "2", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("12", result, "adjacent placeholders should both expand");
    free(result);

    result = trf(ctx, "nodomain", "{a} middle {b}", "a", "start", "b", "end", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("start middle end", result, "edge placeholders should expand");
    free(result);
}

TEST(test_trf_utf8_values) {
    TEST_CASE("trf substitutes multibyte UTF-8 values");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "Привет, {name}!", "name", "Мир", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("Привет, Мир!", result, "UTF-8 value should be substituted");
    free(result);
}

TEST(test_trf_double_brace_is_not_escape) {
    TEST_CASE("trf treats '{{name}}' as key '{name' (no escape syntax)");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", "{{name}}", "name", "W", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("{{name}}", result, "doubled braces should pass through unchanged");
    free(result);
}

TEST(test_trf_pair_limit_32) {
    TEST_CASE("trf caps varargs at 32 pairs without corrupting memory");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    // 33 pairs: the first 32 are collected, pair "z9" (33rd) is ignored
    char* result = trf(ctx, "nodomain", "{a}{z9}",
        "a", "A", "p02", "x", "p03", "x", "p04", "x", "p05", "x", "p06", "x",
        "p07", "x", "p08", "x", "p09", "x", "p10", "x", "p11", "x", "p12", "x",
        "p13", "x", "p14", "x", "p15", "x", "p16", "x", "p17", "x", "p18", "x",
        "p19", "x", "p20", "x", "p21", "x", "p22", "x", "p23", "x", "p24", "x",
        "p25", "x", "p26", "x", "p27", "x", "p28", "x", "p29", "x", "p30", "x",
        "p31", "x", "p32", "x", "z9", "Z", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("A{z9}", result, "pairs beyond the 32nd should be ignored");
    free(result);
}

TEST(test_trf_null_msgid) {
    TEST_CASE("trf with NULL msgid returns NULL");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trf(ctx, "nodomain", NULL, NULL);
    TEST_ASSERT_NULL(result, "NULL msgid should give NULL");
}

// ============================================================================
// tr/trn fallback paths (no catalogs configured)
// ============================================================================

TEST(test_tr_no_translations_returns_msgid) {
    TEST_CASE("tr without configured translations returns the msgid pointer");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    const char* msgid = "untranslated";
    const char* result = tr(ctx, "identity", msgid);
    TEST_ASSERT(result == msgid, "msgid pointer should be returned as-is");
}

TEST(test_tr_null_domain) {
    TEST_CASE("tr with NULL domain returns the msgid");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    const char* msgid = "some message";
    TEST_ASSERT(tr(ctx, NULL, msgid) == msgid, "NULL domain should fall back to msgid");
}

TEST(test_tr_unknown_domain_with_map) {
    TEST_CASE("tr with a populated map but unknown domain returns the msgid");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    map_t* map = map_create_string();
    TEST_REQUIRE_NOT_NULL(map, "map_create_string should succeed");
    appconfig()->translations = map;

    const char* msgid = "message";
    TEST_ASSERT(tr(ctx, "no_such_domain", msgid) == msgid,
                "unknown domain should fall back to msgid");

    appconfig()->translations = NULL;
    map_free(map);
}

TEST(test_trn_no_translations_plural_selection) {
    TEST_CASE("trn without translations picks singular for n==1, plural otherwise");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    const char* singular = "one file";
    const char* plural = "many files";
    TEST_ASSERT(trn(ctx, "nodomain", singular, plural, 1) == singular, "n=1 gives singular");
    TEST_ASSERT(trn(ctx, "nodomain", singular, plural, 0) == plural, "n=0 gives plural");
    TEST_ASSERT(trn(ctx, "nodomain", singular, plural, 2) == plural, "n=2 gives plural");
    TEST_ASSERT(trn(ctx, "nodomain", singular, plural, 5) == plural, "n=5 gives plural");
}

TEST(test_trnf_fallback_formats_plural) {
    TEST_CASE("trnf without translations formats the selected form");

    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    char* result = trnf(ctx, "nodomain", "{n} apple", "{n} apples", 2, "n", "2", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trnf should return a string");
    TEST_ASSERT_STR_EQUAL("2 apples", result, "plural form should be formatted");
    free(result);

    result = trnf(ctx, "nodomain", "{n} apple", "{n} apples", 1, "n", "1", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trnf should return a string");
    TEST_ASSERT_STR_EQUAL("1 apple", result, "singular form should be formatted");
    free(result);
}

// ============================================================================
// Language selection and real catalog lookups (need system locales)
// ============================================================================

TEST(test_tr_query_lang_ru) {
    TEST_CASE("tr uses the ?lang= query parameter");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, "ru", NULL);

    TEST_ASSERT_STR_EQUAL("привет", tr(ctx, TR_DOMAIN, "hello"),
                          "query lang=ru should give the russian catalog");
    RELEASE_CATALOGS();
}

TEST(test_tr_header_accept_language_ru) {
    TEST_CASE("tr falls back to the Accept-Language header");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, "ru-RU,ru;q=0.9,en-US;q=0.8");

    TEST_ASSERT_STR_EQUAL("привет", tr(ctx, TR_DOMAIN, "hello"),
                          "Accept-Language ru-RU should give the russian catalog");
    RELEASE_CATALOGS();
}

TEST(test_tr_query_beats_header) {
    TEST_CASE("tr prefers the query parameter over Accept-Language");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, "en", "ru-RU,ru;q=0.9");

    TEST_ASSERT_STR_EQUAL("hello [en]", tr(ctx, TR_DOMAIN, "hello"),
                          "query lang must win over the header");
    RELEASE_CATALOGS();
}

TEST(test_tr_no_lang_uses_default) {
    TEST_CASE("tr without query/header uses the default language");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, NULL, NULL);

    TEST_ASSERT_STR_EQUAL("hello [en]", tr(ctx, TR_DOMAIN, "hello"),
                          "default language catalog should be used");
    RELEASE_CATALOGS();
}

// REGRESSION: i18n_create stored "e" instead of "en" as default_lang, so the
// fallback lookup ran with a bogus language and returned the raw msgid.
TEST(test_tr_unknown_lang_falls_back_to_default) {
    TEST_CASE("tr with an unknown language falls back to the default catalog");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, "xx", NULL);

    TEST_ASSERT_STR_EQUAL("hello [en]", tr(ctx, TR_DOMAIN, "hello"),
                          "unknown lang should fall back to the default language");
    RELEASE_CATALOGS();
}

// REGRESSION: the query value was used verbatim, so "?lang=ru-RU" never
// matched the "ru" locale entry while the equivalent header worked.
TEST(test_tr_query_lang_with_region) {
    TEST_CASE("tr normalizes a region-qualified query lang (ru-RU -> ru)");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, "ru-RU", NULL);

    TEST_ASSERT_STR_EQUAL("привет", tr(ctx, TR_DOMAIN, "hello"),
                          "query lang=ru-RU should resolve to the russian catalog");
    RELEASE_CATALOGS();
}

// REGRESSION: an empty ?lang= left the thread locale from the previous
// request in place, leaking another user's language into the response.
TEST(test_tr_empty_query_lang_uses_default) {
    TEST_CASE("tr with an empty ?lang= uses the default language");

    REQUIRE_CATALOGS();
    tr_env_t env;

    // poison the thread locale with a russian request first
    httpctx_t* ctx = tr_ctx(&env, "ru", NULL);
    TEST_ASSERT_STR_EQUAL("привет", tr(ctx, TR_DOMAIN, "hello"), "warm-up request in ru");

    ctx = tr_ctx(&env, "", NULL);
    TEST_ASSERT_STR_EQUAL("hello [en]", tr(ctx, TR_DOMAIN, "hello"),
                          "empty lang must not reuse the previous request's locale");
    RELEASE_CATALOGS();
}

// REGRESSION: get_lang crashed on a NULL ctx/request.
TEST(test_tr_null_ctx_uses_default) {
    TEST_CASE("tr with NULL ctx uses the default language");

    REQUIRE_CATALOGS();

    TEST_ASSERT_STR_EQUAL("hello [en]", tr(NULL, TR_DOMAIN, "hello"),
                          "NULL ctx should not crash and should use the default");
    RELEASE_CATALOGS();
}

TEST(test_tr_missing_msgid_returns_msgid) {
    TEST_CASE("tr returns the msgid when no catalog has a translation");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, "ru", NULL);

    TEST_ASSERT_STR_EQUAL("no.such.msgid", tr(ctx, TR_DOMAIN, "no.such.msgid"),
                          "untranslated msgid should pass through");
    RELEASE_CATALOGS();
}

TEST(test_trf_translated_template) {
    TEST_CASE("trf substitutes placeholders inside a translated template");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, "ru", NULL);

    char* result = trf(ctx, TR_DOMAIN, "greeting", "name", "Мир", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trf should return a string");
    TEST_ASSERT_STR_EQUAL("Привет, Мир!", result, "translated template should be formatted");
    free(result);
    RELEASE_CATALOGS();
}

TEST(test_trn_russian_plurals) {
    TEST_CASE("trn selects the correct russian plural form");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, "ru", NULL);

    TEST_ASSERT_STR_EQUAL("яблоко", trn(ctx, TR_DOMAIN, "apple", "apples", 1), "n=1 -> form 0");
    TEST_ASSERT_STR_EQUAL("яблока", trn(ctx, TR_DOMAIN, "apple", "apples", 2), "n=2 -> form 1");
    TEST_ASSERT_STR_EQUAL("яблок", trn(ctx, TR_DOMAIN, "apple", "apples", 5), "n=5 -> form 2");
    TEST_ASSERT_STR_EQUAL("яблок", trn(ctx, TR_DOMAIN, "apple", "apples", 11), "n=11 -> form 2");
    TEST_ASSERT_STR_EQUAL("яблоко", trn(ctx, TR_DOMAIN, "apple", "apples", 21), "n=21 -> form 0");
    RELEASE_CATALOGS();
}

TEST(test_trnf_translated_plural_with_placeholder) {
    TEST_CASE("trnf formats a translated plural template");

    REQUIRE_CATALOGS();
    tr_env_t env;
    httpctx_t* ctx = tr_ctx(&env, "ru", NULL);

    char* result = trnf(ctx, TR_DOMAIN, "{n} apple", "{n} apples", 5, "n", "5", NULL);
    TEST_REQUIRE_NOT_NULL(result, "trnf should return a string");
    TEST_ASSERT_STR_EQUAL("5 яблок", result, "translated plural should be formatted");
    free(result);
    RELEASE_CATALOGS();
}

// ============================================================================
// i18n.c regression guards for bugs found during the translation.c review
// ============================================================================

// REGRESSION: default_lang[len - 1] = '\0' truncated the last character.
TEST(test_i18n_create_keeps_default_lang) {
    TEST_CASE("i18n_create stores default_lang without truncation");

    i18n_t* i18n = i18n_create(NULL, "i18n_test_domain", "en");
    TEST_REQUIRE_NOT_NULL(i18n, "i18n_create should succeed");
    TEST_ASSERT_STR_EQUAL("en", i18n->default_lang, "default_lang must keep every character");
    i18n_free(i18n);
}

// REGRESSION: an empty default_lang wrote to default_lang[-1].
TEST(test_i18n_create_rejects_empty_default_lang) {
    TEST_CASE("i18n_create rejects an empty default language");

    TEST_ASSERT_NULL(i18n_create(NULL, "i18n_test_domain", ""),
                     "empty default_lang must be rejected");
    TEST_ASSERT_NULL(i18n_create(NULL, "i18n_test_domain", "toolonglang"),
                     "overlong default_lang must be rejected");
}

TEST(test_i18n_parse_accept_language) {
    TEST_CASE("i18n_parse_accept_language extracts the primary language");

    struct { const char* header; const char* expected; } cases[] = {
        {NULL, "en"},
        {"", "en"},
        {"ru", "ru"},
        {"ru-RU,ru;q=0.9,en-US;q=0.8", "ru"},
        {"  en-US", "en"},
        {"de;q=0.7", "de"},
        {"-", "en"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char* lang = i18n_parse_accept_language(cases[i].header);
        TEST_REQUIRE_NOT_NULL(lang, "parser should return a string");
        TEST_ASSERT_STR_EQUAL(cases[i].expected, lang, "parsed language should match");
        free(lang);
    }
}

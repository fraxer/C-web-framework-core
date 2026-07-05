#include "framework.h"
#include "view.h"
#include "viewstore.h"
#include "storagefs.h"
#include "appconfig.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

/* env()/appconfig() are provided as weak test doubles by
 * test_httprequestparser.c; appconfig()->viewstore and ->storages start NULL,
 * each test installs its own store/storage and restores NULL afterwards. */
extern appconfig_t* appconfig(void);

#define VIEW_TEST_STORAGE "view_test_storage"

// ============================================================================
// Helpers: temp dir with template files + appconfig environment
// ============================================================================

static const char* view_test_root(void) {
    static char root[PATH_MAX] = {0};
    static int ready = 0;

    if (!ready) {
        snprintf(root, sizeof(root), "/tmp/cwfr_view_test_XXXXXX");
        if (mkdtemp(root) == NULL) return NULL;
        ready = 1;
    }

    return root;
}

static int view_write_template(const char* name, const char* content) {
    const char* root = view_test_root();
    if (root == NULL) return 0;

    char path[PATH_MAX + NAME_MAX + 2];
    snprintf(path, sizeof(path), "%s/%s", root, name);

    FILE* f = fopen(path, "w");
    if (f == NULL) return 0;

    const size_t size = strlen(content);
    const size_t written = fwrite(content, 1, size, f);
    fclose(f);

    return written == size;
}

typedef struct {
    viewstore_t* store;
    storagefs_t* fs;
} view_env_t;

static int view_env_init(view_env_t* env) {
    env->store = NULL;
    env->fs = NULL;

    const char* root = view_test_root();
    if (root == NULL) return 0;

    env->store = viewstore_create();
    if (env->store == NULL) return 0;

    env->fs = storage_create_fs(VIEW_TEST_STORAGE, root);
    if (env->fs == NULL) {
        viewstore_destroy(env->store);
        env->store = NULL;
        return 0;
    }

    appconfig()->viewstore = env->store;
    appconfig()->storages = (storage_t*)env->fs;

    return 1;
}

static void view_env_free(view_env_t* env) {
    appconfig()->viewstore = NULL;
    appconfig()->storages = NULL;

    if (env->store != NULL) viewstore_destroy(env->store);
    if (env->fs != NULL) env->fs->base.free(env->fs);

    env->store = NULL;
    env->fs = NULL;
}

// ============================================================================
// Статический текст и переменные
// ============================================================================

TEST(test_view_render_static_text) {
    TEST_CASE("Render template without tags");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("static.html", "Hello, world!"),
                      "Template should be written", cleanup);

    char* result = render(NULL, VIEW_TEST_STORAGE, "/static.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup);
    TEST_ASSERT_STR_EQUAL("Hello, world!", result, "Static text should be rendered as is");

    free(result);

cleanup:
    view_env_free(&env);
}

TEST(test_view_render_empty_template) {
    TEST_CASE("Render empty template");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("empty.html", ""),
                      "Template should be written", cleanup);

    char* result = render(NULL, VIEW_TEST_STORAGE, "/empty.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup);
    TEST_ASSERT_STR_EQUAL("", result, "Empty template should render to empty string");

    free(result);

cleanup:
    view_env_free(&env);
}

TEST(test_view_render_variable) {
    TEST_CASE("Render simple variable");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("var.html", "Hello, {{ name }}!"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"name\":\"world\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/var.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("Hello, world!", result, "Variable should be substituted");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_multiple_variables) {
    TEST_CASE("Render several variables in one template");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("vars.html", "A{{ x }}B{{ y }}C"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"x\":\"1\",\"y\":\"2\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/vars.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("A1B2C", result, "All variables should be substituted in order");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_nested_path) {
    TEST_CASE("Render variable with dot path");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("dot.html", "{{ user.profile.name }}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"user\":{\"profile\":{\"name\":\"bob\"}}}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/dot.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("bob", result, "Nested path should be resolved");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_array_index) {
    TEST_CASE("Render variable with array index");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("index.html", "{{ items[1] }}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"items\":[\"a\",\"b\",\"c\"]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/index.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("b", result, "Indexed element should be substituted");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_nested_array_index) {
    TEST_CASE("Render variable with chained array indexes");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("matrix.html", "{{ matrix[1][0] }}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"matrix\":[[\"a\",\"b\"],[\"c\",\"d\"]]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/matrix.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("c", result, "Chained indexes should be resolved");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_missing_variable) {
    TEST_CASE("Missing variable renders as empty string");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("missing.html", "[{{ missing }}]"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"name\":\"world\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/missing.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("[]", result, "Missing variable should render as empty");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_null_document) {
    TEST_CASE("Render template with tags and NULL document does not crash");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("nulldoc.html",
                                          "A{{ name }}B{% if flag %}X{% endif %}C"),
                      "Template should be written", cleanup);

    char* result = render(NULL, VIEW_TEST_STORAGE, "/nulldoc.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render with NULL document should succeed", cleanup);
    TEST_ASSERT_STR_EQUAL("ABC", result, "Tags should render as empty with NULL document");

    free(result);

cleanup:
    view_env_free(&env);
}

TEST(test_view_render_empty_document) {
    TEST_CASE("Render with empty json document");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("emptydoc.html", "[{{ a.b.c }}]"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/emptydoc.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("[]", result, "Unresolvable path should render as empty");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

// ============================================================================
// Условия
// ============================================================================

TEST(test_view_render_condition_true) {
    TEST_CASE("Condition renders body when flag is true");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("if_true.html", "A{% if flag %}YES{% endif %}B"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"flag\":true}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/if_true.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("AYESB", result, "True condition should render its body");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_condition_false) {
    TEST_CASE("Condition skips body when flag is false");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("if_false.html", "A{% if flag %}YES{% endif %}B"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"flag\":false}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/if_false.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("AB", result, "False condition should skip its body");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_condition_inverse) {
    TEST_CASE("Inverse condition renders body when flag is false");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("if_inv.html", "A{% if !flag %}NO{% endif %}B"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"flag\":false}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/if_inv.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("ANOB", result, "Inverse condition should render on false flag");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_condition_else) {
    TEST_CASE("Else branch renders when condition is false");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("if_else.html",
                                          "{% if flag %}YES{% else %}NO{% endif %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"flag\":false}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/if_else.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("NO", result, "Else branch should be rendered");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_condition_elseif) {
    TEST_CASE("Elseif branch renders when first condition is false");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("if_elseif.html",
                                          "{% if a %}A{% elseif b %}B{% else %}C{% endif %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"a\":false,\"b\":true}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/if_elseif.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("B", result, "Elseif branch should be rendered");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_condition_nested_path) {
    TEST_CASE("Condition with dot path");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("if_dot.html",
                                          "{% if user.active %}on{% else %}off{% endif %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"user\":{\"active\":true}}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/if_dot.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("on", result, "Nested condition path should be resolved");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_condition_non_bool) {
    TEST_CASE("Condition on non-bool value is treated as false");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("if_str.html",
                                          "{% if name %}YES{% else %}NO{% endif %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"name\":\"bob\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/if_str.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("NO", result, "Non-bool condition should be false");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

// ============================================================================
// Циклы
// ============================================================================

TEST(test_view_render_loop_array) {
    TEST_CASE("Loop over array of strings");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_arr.html",
                                          "[{% for item in items %}{{ item }};{% endfor %}]"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"items\":[\"a\",\"b\",\"c\"]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/for_arr.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("[a;b;c;]", result, "Loop should render every element");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_loop_empty_array) {
    TEST_CASE("Loop over empty array renders nothing");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_empty.html",
                                          "[{% for item in items %}{{ item }};{% endfor %}]"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"items\":[]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/for_empty.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("[]", result, "Empty array loop should render surrounding text only");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_loop_default_index) {
    TEST_CASE("Loop exposes default index variable");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_index.html",
                                          "{% for item in items %}{{ index }}:{{ item }} {% endfor %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"items\":[\"a\",\"b\"]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/for_index.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("0:a 1:b ", result, "Default index should be rendered per element");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_loop_object_keys) {
    TEST_CASE("Loop over object exposes keys");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_obj.html",
                                          "{% for v, k in user %}{{ k }}={{ v }};{% endfor %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"user\":{\"name\":\"bob\",\"city\":\"NY\"}}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/for_obj.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("name=bob;city=NY;", result, "Object loop should render key=value pairs");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_loop_element_field) {
    TEST_CASE("Loop element field access");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_field.html",
                                          "{% for u in users %}{{ u.name }},{% endfor %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"users\":[{\"name\":\"bob\"},{\"name\":\"jim\"}]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/for_field.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("bob,jim,", result, "Element fields should be resolved");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_nested_loops) {
    TEST_CASE("Nested loops over nested arrays");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_nested.html",
                                          "{% for row in rows %}{% for cell in row %}{{ cell }};{% endfor %}|{% endfor %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"rows\":[[\"a\",\"b\"],[\"c\"]]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/for_nested.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("a;b;|c;|", result, "Nested loops should render inner and outer elements");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_condition_inside_loop) {
    TEST_CASE("Condition inside loop uses loop element");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_if.html",
                                          "{% for u in users %}{% if u.active %}{{ u.name }};{% endif %}{% endfor %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse(
        "{\"users\":[{\"name\":\"bob\",\"active\":true},"
        "{\"name\":\"jim\",\"active\":false},"
        "{\"name\":\"ann\",\"active\":true}]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/for_if.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("bob;ann;", result, "Only active elements should be rendered");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_loop_long_object_key) {
    TEST_CASE("Loop over object with key longer than key buffer");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_longkey.html",
                                          "{% for v, k in obj %}{{ k }}={{ v }}{% endfor %}"),
                      "Template should be written", cleanup);

    // ключ длиннее VIEWPARSER_VARIABLE_ITEM_NAME_SIZE (80): до фикса sprintf
    // переполнял key_value (heap overflow под ASan), после — усечение
    char long_key[161];
    memset(long_key, 'k', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = 0;

    char json[512];
    snprintf(json, sizeof(json), "{\"obj\":{\"%s\":\"v\"}}", long_key);

    json_doc_t* doc = json_parse(json);
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/for_longkey.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should not crash on long keys", cleanup_doc);

    // ключ усечён до 79 символов + "=v"
    char expected[128];
    snprintf(expected, sizeof(expected), "%.79s=v", long_key);
    TEST_ASSERT_STR_EQUAL(expected, result, "Long key should be truncated, not overflow");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

// ============================================================================
// Include
// ============================================================================

TEST(test_view_render_include) {
    TEST_CASE("Include renders partial with its own variables");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("inc_part.html", "hello {{ name }}"),
                      "Partial should be written", cleanup);
    TEST_REQUIRE_GOTO(view_write_template("inc_main.html", "A[{* include /inc_part.html *}]B"),
                      "Main template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"name\":\"world\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_TEST_STORAGE, "/inc_main.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("A[hello world]B", result, "Included partial should be rendered in place");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_include_missing_file) {
    TEST_CASE("Include of missing file fails render");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("inc_bad.html", "A{* include /no_such_part.html *}B"),
                      "Template should be written", cleanup);

    char* result = render(NULL, VIEW_TEST_STORAGE, "/inc_bad.html");
    TEST_ASSERT_NULL(result, "Render should fail when included file is missing");
    free(result);

cleanup:
    view_env_free(&env);
}

// ============================================================================
// Кэширование, форматирование пути и ошибки
// ============================================================================

TEST(test_view_render_caches_view) {
    TEST_CASE("Second render reuses cached view");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("cache.html", "X{{ name }}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"name\":\"1\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* first = render(doc, VIEW_TEST_STORAGE, "/cache.html");
    TEST_REQUIRE_NOT_NULL_GOTO(first, "First render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("X1", first, "First render should substitute value");
    free(first);

    view_t* cached = viewstore_get_view(env.store, "/cache.html");
    TEST_ASSERT_NOT_NULL(cached, "View should be cached in the store");

    char* second = render(doc, VIEW_TEST_STORAGE, "/cache.html");
    TEST_REQUIRE_NOT_NULL_GOTO(second, "Second render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("X1", second, "Cached render should produce the same content");
    free(second);

    TEST_ASSERT(env.store->view == env.store->last_view,
                "Repeated render must not add a duplicate view");

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_path_format) {
    TEST_CASE("Path format arguments are applied");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("fmt_7.html", "seven"),
                      "Template should be written", cleanup);

    char* result = render(NULL, VIEW_TEST_STORAGE, "/fmt_%d.html", 7);
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup);
    TEST_ASSERT_STR_EQUAL("seven", result, "Formatted path should resolve the template");

    free(result);

cleanup:
    view_env_free(&env);
}

TEST(test_view_render_missing_template) {
    TEST_CASE("Missing template returns NULL");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");

    char* result = render(NULL, VIEW_TEST_STORAGE, "/no_such_template.html");
    TEST_ASSERT_NULL(result, "Render of missing template should return NULL");
    free(result);

    view_env_free(&env);
}

TEST(test_view_render_unknown_storage) {
    TEST_CASE("Unknown storage returns NULL");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("storage.html", "content"),
                      "Template should be written", cleanup);

    char* result = render(NULL, "no_such_storage", "/storage.html");
    TEST_ASSERT_NULL(result, "Render with unknown storage should return NULL");
    free(result);

cleanup:
    view_env_free(&env);
}

TEST(test_view_render_null_viewstore) {
    TEST_CASE("Render without viewstore returns NULL and does not leak");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("nostore.html", "content"),
                      "Template should be written", cleanup);

    appconfig()->viewstore = NULL;

    char* result = render(NULL, VIEW_TEST_STORAGE, "/nostore.html");
    TEST_ASSERT_NULL(result, "Render without viewstore should return NULL");
    free(result);

cleanup:
    view_env_free(&env);
}

TEST(test_view_render_broken_template) {
    TEST_CASE("Template with broken syntax returns NULL");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("broken.html", "A{% unknown %}B"),
                      "Template should be written", cleanup);

    char* result = render(NULL, VIEW_TEST_STORAGE, "/broken.html");
    TEST_ASSERT_NULL(result, "Render of broken template should return NULL");
    free(result);

cleanup:
    view_env_free(&env);
}

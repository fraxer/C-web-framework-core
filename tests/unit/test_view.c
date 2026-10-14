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
#include <unistd.h>

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

    char* result = render(NULL, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/static.html");
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

    char* result = render(NULL, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/empty.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/var.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/vars.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/dot.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/index.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/matrix.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/missing.html");
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

    char* result = render(NULL, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/nulldoc.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/emptydoc.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/if_true.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/if_false.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/if_inv.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/if_else.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/if_elseif.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/if_dot.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("on", result, "Nested condition path should be resolved");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_condition_truthiness) {
    TEST_CASE("Non-bool values follow truthiness rules in conditions");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("if_str.html",
                                          "{% if name %}YES{% else %}NO{% endif %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse(
        "{\"name\":\"bob\",\"empty\":\"\",\"zero\":0,\"num\":5,\"none\":null}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/if_str.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("YES", result, "Non-empty string should be truthy");
    free(result);

    TEST_REQUIRE_GOTO(view_write_template("if_str2.html",
                                          "{% if empty %}1{% else %}0{% endif %}"
                                          "{% if zero %}1{% else %}0{% endif %}"
                                          "{% if num %}1{% else %}0{% endif %}"
                                          "{% if none %}1{% else %}0{% endif %}"
                                          "{% if missing %}1{% else %}0{% endif %}"),
                      "Template should be written", cleanup_doc);

    result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/if_str2.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("00100", result,
                          "Empty string, zero, null and missing should be falsy; non-zero number truthy");
    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

// ============================================================================
// Нестроковые значения и выражения
// ============================================================================

TEST(test_view_render_number_and_bool_values) {
    TEST_CASE("Numbers and booleans render in canonical text form");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("values.html",
                                          "{{ count }}|{{ price }}|{{ flag }}|{{ neg }}|{{ none }}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse(
        "{\"count\":42,\"price\":9.99,\"flag\":true,\"neg\":-3,\"none\":null}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/values.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("42|9.99|true|-3|", result,
                          "Integral numbers without fraction, floats shortest, bool as word, null empty");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_arithmetic_expression) {
    TEST_CASE("Arithmetic expressions are evaluated with precedence");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("arith.html",
                                          "{{ a + b * 2 }}|{{ (a + b) * 2 }}|{{ b / a }}|{{ b % a }}|{{ -a + 1 }}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"a\":4,\"b\":10}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/arith.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("24|28|2.5|2|-3", result, "Expressions should follow standard precedence");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_comparison_and_logic) {
    TEST_CASE("Comparisons and logical operators drive conditions");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("logic.html",
                                          "{% if age >= 18 %}adult{% else %}minor{% endif %};"
                                          "{% if role == 'admin' %}admin{% endif %};"
                                          "{% if active && age < 65 %}working{% endif %};"
                                          "{% if role != 'guest' || banned %}member{% endif %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse(
        "{\"age\":30,\"role\":\"admin\",\"active\":true,\"banned\":false}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/logic.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("adult;admin;working;member", result,
                          "All comparison and logic branches should evaluate");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_division_by_zero) {
    TEST_CASE("Division by zero renders as empty, not a crash");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("divzero.html", "[{{ a / b }}][{{ a % b }}]"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"a\":5,\"b\":0}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/divzero.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("[][]", result, "Division and modulo by zero should render empty");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_string_literal_and_concat_guard) {
    TEST_CASE("String literals render as is; string arithmetic renders empty");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("strlit.html", "[{{ 'a}}b' }}][{{ name + 1 }}]"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"name\":\"bob\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/strlit.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("[a}}b][]", result,
                          "Quoted braces should render; string + number should render empty");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_dynamic_index_expression) {
    TEST_CASE("Array index may be a runtime expression");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("dynidx.html",
                                          "{{ items[pos] }}|{{ items[pos + 1] }}|{{ items[99] }}|{{ obj[key] }}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse(
        "{\"items\":[\"a\",\"b\",\"c\"],\"pos\":1,\"obj\":{\"k\":\"v\"},\"key\":\"k\"}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/dynidx.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("b|c||v", result,
                          "Indexes should evaluate at render time; out of range renders empty");

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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_arr.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_empty.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_index.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("0:a 1:b ", result, "Default index should be rendered per element");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_loop_index_arithmetic) {
    TEST_CASE("Loop index participates in expressions");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_idx_expr.html",
                                          "{% for item in items %}{{ index + 1 }}.{{ item }} {% endfor %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse("{\"items\":[\"a\",\"b\"]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_idx_expr.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("1.a 2.b ", result, "Index should be a number usable in arithmetic");

    free(result);

cleanup_doc:
    json_free(doc);
cleanup:
    view_env_free(&env);
}

TEST(test_view_render_loop_element_expression) {
    TEST_CASE("Loop element fields work in comparisons");

    view_env_t env;
    TEST_REQUIRE(view_env_init(&env), "Environment should be initialized");
    TEST_REQUIRE_GOTO(view_write_template("for_el_expr.html",
                                          "{% for u in users %}{% if u.age >= 18 %}{{ u.name }};{% endif %}{% endfor %}"),
                      "Template should be written", cleanup);

    json_doc_t* doc = json_parse(
        "{\"users\":[{\"name\":\"bob\",\"age\":30},"
        "{\"name\":\"kid\",\"age\":10},"
        "{\"name\":\"ann\",\"age\":18}]}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_el_expr.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("bob;ann;", result, "Only adults should be rendered");

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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_obj.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_field.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_nested.html");
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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_if.html");
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

    // ключ длиннее VIEWPARSER_VARIABLE_ITEM_NAME_SIZE (80): сначала sprintf
    // переполнял key_value (heap overflow под ASan), потом ключ усекался до
    // 79 байт — данные документа выходили искажёнными (цель view). Теперь
    // ключ берётся из документа как есть.
    char long_key[161];
    memset(long_key, 'k', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = 0;

    char json[512];
    snprintf(json, sizeof(json), "{\"obj\":{\"%s\":\"v\"}}", long_key);

    json_doc_t* doc = json_parse(json);
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "Document should be parsed", cleanup);

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/for_longkey.html");
    TEST_REQUIRE_NOT_NULL_GOTO(result, "Render should not crash on long keys", cleanup_doc);

    char expected[200];
    snprintf(expected, sizeof(expected), "%s=v", long_key);
    TEST_ASSERT_STR_EQUAL(expected, result, "Long key should be rendered whole");

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

    char* result = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/inc_main.html");
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

    char* result = render(NULL, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/inc_bad.html");
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

    char* first = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/cache.html");
    TEST_REQUIRE_NOT_NULL_GOTO(first, "First render should succeed", cleanup_doc);
    TEST_ASSERT_STR_EQUAL("X1", first, "First render should substitute value");
    free(first);

    view_t* cached = viewstore_get_view(env.store, "/cache.html");
    TEST_ASSERT_NOT_NULL(cached, "View should be cached in the store");

    char* second = render(doc, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/cache.html");
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

    char* result = render(NULL, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/fmt_%d.html", 7);
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

    char* result = render(NULL, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/no_such_template.html");
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

    char* result = render(NULL, VIEW_ESCAPE, "no_such_storage", "/storage.html");
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

    char* result = render(NULL, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/nostore.html");
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

    char* result = render(NULL, VIEW_ESCAPE, VIEW_TEST_STORAGE, "/broken.html");
    TEST_ASSERT_NULL(result, "Render of broken template should return NULL");
    free(result);

cleanup:
    view_env_free(&env);
}

// ============================================================================
// Экранирование и модификаторы
// ============================================================================

/* Writes `template` to `name`, renders it against the JSON text `json` (NULL
 * for no document) in `mode` and returns the result (free it), or NULL when
 * the environment, the document or the render fails. */
static char* view_render_with(const char* name, const char* template, const char* json, view_escape_e mode) {
    view_env_t env;
    if (!view_env_init(&env)) return NULL;

    char* result = NULL;
    json_doc_t* doc = NULL;

    if (!view_write_template(name, template)) goto cleanup;

    if (json != NULL) {
        doc = json_parse(json);
        if (doc == NULL) goto cleanup;
    }

    char path[NAME_MAX + 2];
    snprintf(path, sizeof(path), "/%s", name);
    result = render(doc, mode, VIEW_TEST_STORAGE, "%s", path);

cleanup:
    if (doc != NULL) json_free(doc);
    view_env_free(&env);

    return result;
}

/* Renders and compares with `expected`; NULL `expected` means render must fail. */
#define VIEW_ASSERT_RENDER(name, template, json, mode, expected, message) do { \
    char* __result = view_render_with(name, template, json, mode); \
    if ((expected) == NULL) { \
        TEST_ASSERT_NULL(__result, message); \
    } \
    else { \
        TEST_ASSERT_STR_EQUAL((expected) != NULL ? (expected) : "", __result != NULL ? __result : "<NULL>", message); \
    } \
    free(__result); \
} while (0)

TEST(test_view_escape_default) {
    TEST_CASE("Output is HTML-escaped by default");

    VIEW_ASSERT_RENDER("esc_default.html", "<p title=\"{{ t }}\">{{ s }}</p>",
        "{\"t\":\"\\\"x' y\\\"\",\"s\":\"<script>&\"}", VIEW_ESCAPE,
        "<p title=\"&quot;x&#39; y&quot;\">&lt;script&gt;&amp;</p>", "Text and attribute values are escaped");
}

TEST(test_view_escape_raw_modifier) {
    TEST_CASE("raw disables escaping");

    VIEW_ASSERT_RENDER("esc_raw1.html", "{{ s | raw }}", "{\"s\":\"<b>\"}", VIEW_ESCAPE, "<b>", "raw writes the string as is");
    VIEW_ASSERT_RENDER("esc_raw2.html", "{{ n | raw }}", "{\"n\":5}", VIEW_ESCAPE, "5", "raw of a number");
    VIEW_ASSERT_RENDER("esc_raw3.html", "[{{ missing | raw }}]", "{}", VIEW_ESCAPE, "[]", "raw of a missing value");
    VIEW_ASSERT_RENDER("esc_raw4.html", "{{ s | upper | raw }}", "{\"s\":\"<b>\"}", VIEW_ESCAPE, "<B>", "raw after another modifier");
    VIEW_ASSERT_RENDER("esc_raw5.html", "{{ s | upper }}", "{\"s\":\"<b>\"}", VIEW_ESCAPE, "&lt;B&gt;", "Modifier output is escaped");
}

TEST(test_view_escape_mode_raw) {
    TEST_CASE("VIEW_RAW writes values as is");

    VIEW_ASSERT_RENDER("esc_mode_raw.html", "{{ s }}|{{ s | raw }}", "{\"s\":\"a&b\"}", VIEW_RAW, "a&b|a&b", "No escaping in VIEW_RAW");
}

TEST(test_view_escape_nl2br) {
    TEST_CASE("nl2br in both modes");

    VIEW_ASSERT_RENDER("esc_nl2br.html", "{{ s | nl2br }}", "{\"s\":\"a<\\nb\"}", VIEW_ESCAPE, "a&lt;<br>\nb", "Escaped with <br>");
    VIEW_ASSERT_RENDER("esc_nl2br.html", "{{ s | nl2br }}", "{\"s\":\"a<\\nb\"}", VIEW_RAW, "a<\nb", "As is in VIEW_RAW");
}

TEST(test_view_escape_json_in_script) {
    TEST_CASE("json inside <script> and in an attribute");

    VIEW_ASSERT_RENDER("esc_json1.html", "<script>var d = {{ d | json | raw }};</script>",
        "{\"d\":{\"x\":\"</script><b>\"}}", VIEW_ESCAPE,
        "<script>var d = {\"x\":\"\\u003c/script\\u003e\\u003cb\\u003e\"};</script>", "</script> cannot close the element");
    VIEW_ASSERT_RENDER("esc_json2.html", "<div data-d=\"{{ d | json }}\">",
        "{\"d\":{\"x\":\"</script><b>\"}}", VIEW_ESCAPE,
        "<div data-d=\"{&quot;x&quot;:&quot;\\u003c/script\\u003e\\u003cb\\u003e&quot;}\">", "Quotes are escaped in an attribute");
}

TEST(test_view_escape_loop_key) {
    TEST_CASE("Object loop keys are escaped");

    VIEW_ASSERT_RENDER("esc_loop_key.html", "{% for v, k in o %}{{ k }}={{ v }};{% endfor %}",
        "{\"o\":{\"<k>\":\"<v>\"}}", VIEW_ESCAPE, "&lt;k&gt;=&lt;v&gt;;", "Key and value are escaped");
}

TEST(test_view_modifier_in_condition_and_loop) {
    TEST_CASE("Modifiers in if and for");

    const char* condition = "{% if items | length > 2 %}many{% else %}few{% endif %}";
    VIEW_ASSERT_RENDER("mod_if.html", condition, "{\"items\":[1,2,3]}", VIEW_ESCAPE, "many", "Modifier in a condition");
    VIEW_ASSERT_RENDER("mod_if.html", condition, "{}", VIEW_ESCAPE, "few", "Missing field has length 0");
    VIEW_ASSERT_RENDER("mod_for.html", "{% for t in tags | default(fallback) %}{{ t }}{% endfor %}",
        "{\"tags\":null,\"fallback\":[\"a\",\"b\"]}", VIEW_ESCAPE, "ab", "Modifier in a loop collection");
    VIEW_ASSERT_RENDER("mod_if_raw.html", "{% if s | raw %}x{% endif %}", "{\"s\":\"a\"}", VIEW_ESCAPE, NULL,
        "raw in a condition is a parse error");
}

TEST(test_view_modifier_literal_syntax_inside_tag) {
    TEST_CASE("Tag syntax inside string arguments");

    VIEW_ASSERT_RENDER("mod_lit1.html", "{{ s | replace('|', '/') }}", "{\"s\":\"a|b\"}", VIEW_ESCAPE, "a/b", "| inside a literal");
    VIEW_ASSERT_RENDER("mod_lit2.html", "{{ missing | default('}}') }}", "{}", VIEW_ESCAPE, "}}", "}} inside a literal");
    VIEW_ASSERT_RENDER("mod_lit3.html", "{{ missing | default('a, b') }}", "{}", VIEW_ESCAPE, "a, b", ", inside a literal");
}

TEST(test_view_include_inherits_mode) {
    TEST_CASE("Included templates use the mode of the render");

    TEST_REQUIRE(view_write_template("mode_inc.html", "{{ s }}"), "Include should be written");
    VIEW_ASSERT_RENDER("mode_main.html", "[{* include /mode_inc.html *}]", "{\"s\":\"<\"}", VIEW_ESCAPE, "[&lt;]", "Escaped include");
    VIEW_ASSERT_RENDER("mode_main.html", "[{* include /mode_inc.html *}]", "{\"s\":\"<\"}", VIEW_RAW, "[<]", "Raw include");
}

TEST(test_view_modifier_large_loop_arena) {
    TEST_CASE("Modifier inside a long loop");

    const size_t count = 10000;
    char* json = malloc(count * 5 + 16);
    TEST_REQUIRE_NOT_NULL(json, "Allocation should succeed");

    char* p = json;
    p += sprintf(p, "{\"a\":[");
    for (size_t i = 0; i < count; i++)
        p += sprintf(p, "%s\"ab\"", i > 0 ? "," : "");
    sprintf(p, "]}");

    char* result = view_render_with("mod_loop.html", "{% for x in a %}{{ x | upper }}{% endfor %}", json, VIEW_ESCAPE);
    free(json);
    TEST_REQUIRE_NOT_NULL(result, "Render should succeed");

    TEST_ASSERT_EQUAL_SIZE(count * 2, strlen(result), "Every element is written");

    int only_upper = 1;
    for (size_t i = 0; result[i] != 0; i++)
        if (result[i] != (i % 2 == 0 ? 'A' : 'B')) only_upper = 0;
    TEST_ASSERT(only_upper, "Every element is upper-cased");

    free(result);
}

TEST(test_view_render_unknown_modifier) {
    TEST_CASE("Unknown modifier fails the render");

    VIEW_ASSERT_RENDER("mod_unknown.html", "{{ s | nope }}", "{\"s\":\"a\"}", VIEW_ESCAPE, NULL, "Unknown modifier");
}

/* Resident set size of this process, in bytes; 0 if unknown. */
static size_t view_rss_bytes(void) {
    FILE* f = fopen("/proc/self/statm", "r");
    if (f == NULL) return 0;

    unsigned long size = 0, resident = 0;
    const int read = fscanf(f, "%lu %lu", &size, &resident);
    fclose(f);

    return read == 2 ? (size_t)resident * (size_t)sysconf(_SC_PAGESIZE) : 0;
}

TEST(test_view_loop_collection_arena_is_reset) {
    TEST_CASE("A loop collection with an allocating modifier does not grow memory per iteration");

    /* 1000 outer iterations, each evaluating `big | truncate(...)` (64 KiB,
     * allocated only in the arena -- a malloc'ing modifier would measure the
     * allocator's free lists instead, and replace() over a string of matches
     * is quadratic under ASan's strstr interceptor) for the inner loop's
     * collection.
     * Without a reset after the collection the arena keeps all of them,
     * ~64 MiB, and the memory stays resident after the render (ASan keeps
     * freed blocks in quarantine), so the RSS difference shows it. With the
     * reset the arena holds one block. */
    const size_t big_size = 64 * 1024;
    const size_t rows = 1000;

    char* json = malloc(big_size + rows * 3 + 64);
    TEST_REQUIRE_NOT_NULL(json, "Allocation should succeed");

    char* p = json;
    p += sprintf(p, "{\"big\":\"");
    memset(p, 'A', big_size);
    p += big_size;
    p += sprintf(p, "\",\"rows\":[");
    for (size_t i = 0; i < rows; i++)
        p += sprintf(p, "%s{}", i > 0 ? "," : "");
    sprintf(p, "]}");

    const size_t before = view_rss_bytes();
    char* result = view_render_with("mod_loop_collection.html",
        "{% for r in rows %}{% for t in r.tags | default(big | truncate(65535)) %}x{% endfor %}{% endfor %}",
        json, VIEW_ESCAPE);
    const size_t after = view_rss_bytes();
    free(json);

    TEST_REQUIRE_NOT_NULL(result, "Render should succeed");
    TEST_ASSERT_STR_EQUAL("", result, "The inner loops have nothing to iterate");
    free(result);

    TEST_REQUIRE(before > 0 && after > 0, "RSS should be readable");
    if (after > before + 32 * 1024 * 1024)
        printf("loop collection arena: RSS grew by %zu bytes\n", after - before);
    TEST_ASSERT(after <= before + 32 * 1024 * 1024, "RSS grows by less than 32 MiB");
}

TEST(test_view_path_after_modifier) {
    TEST_CASE("Path after a modifier in tags and loops");

    VIEW_ASSERT_RENDER("mod_path1.html", "{{ (users | first).name }}|{{ users | last.name }}",
        "{\"users\":[{\"name\":\"<A>\"},{\"name\":\"B\"}]}", VIEW_ESCAPE, "&lt;A&gt;|B", "Field of first/last is escaped");
    VIEW_ASSERT_RENDER("mod_path2.html", "{% for t in (groups | first).tags %}{{ t }}{% endfor %}",
        "{\"groups\":[{\"tags\":[\"a\",\"b\"]}]}", VIEW_ESCAPE, "ab", "Loop over a path after a modifier");
}

TEST(test_view_first_last_scalars) {
    TEST_CASE("first / last of a number or bool is null");

    VIEW_ASSERT_RENDER("edge_scalar1.html", "[{{ n | first }}|{{ n | last }}|{{ flag | first }}]",
        "{\"n\":42,\"flag\":false}", VIEW_ESCAPE, "[||]", "Scalars give empty output");
    VIEW_ASSERT_RENDER("edge_scalar2.html", "{% if flag | first %}YES{% else %}NO{% endif %}",
        "{\"flag\":false}", VIEW_ESCAPE, "NO", "first of false is not truthy");
}

TEST(test_view_modifier_whitespace_in_tags) {
    TEST_CASE("Whitespace and line breaks around | in a rendered tag");

    VIEW_ASSERT_RENDER("mod_ws1.html", "{{a|upper}}", "{\"a\":\"x\"}", VIEW_ESCAPE, "X", "No spaces");
    VIEW_ASSERT_RENDER("mod_ws2.html", "{{ a |upper( ) }}", "{\"a\":\"x\"}", VIEW_ESCAPE, "X", "Space inside parentheses");
    VIEW_ASSERT_RENDER("mod_ws3.html", "{{ a\n| upper }}", "{\"a\":\"x\"}", VIEW_ESCAPE, "X", "Line break before |");
    VIEW_ASSERT_RENDER("mod_ws4.html", "{{\n  a |\n  upper\n}}", "{\"a\":\"x\"}", VIEW_ESCAPE, "X", "Line breaks inside the tag");
    VIEW_ASSERT_RENDER("mod_ws5.html", "{{\ta\t|\tupper\t}}", "{\"a\":\"x\"}", VIEW_ESCAPE, "X", "Tabs inside the tag");
}

TEST(test_view_arena_reset_bounds_retained_memory) {
    TEST_CASE("Growing modifier results do not keep a block each after a reset");

    /* arena_reset() keeps blocks for reuse, and a request larger than every
     * spare block takes a new one: increasing sizes would keep their sum. */
    arena_t arena;
    arena_init(&arena);

    for (size_t size = 50; size <= 100000; size += 50) {
        TEST_REQUIRE_NOT_NULL(arena_alloc(&arena, size), "Allocation should succeed");
        view_arena_reset(&arena);
    }

    TEST_ASSERT(arena.total_bytes <= VIEW_ARENA_RETAIN, "The arena keeps at most VIEW_ARENA_RETAIN bytes");

    // a small arena keeps its block: the reuse the arena exists for
    TEST_REQUIRE_NOT_NULL(arena_alloc(&arena, 100), "Allocation should succeed");
    view_arena_reset(&arena);
    const size_t kept = arena.total_bytes;
    TEST_ASSERT(kept > 0, "A small arena is kept for reuse");
    TEST_REQUIRE_NOT_NULL(arena_alloc(&arena, 100), "Allocation should succeed");
    TEST_ASSERT_EQUAL_SIZE(kept, arena.total_bytes, "The kept block is reused");

    arena_free(&arena);
}

TEST(test_view_output_with_nul) {
    TEST_CASE("NUL bytes in output become U+FFFD; json keeps them as \\u0000");

    const char* doc = "{\"s\":\"a\\u0000b<\",\"o\":{\"a\\u0000b\":1}}";
    VIEW_ASSERT_RENDER("nul1.html", "[{{ s }}]", doc, VIEW_ESCAPE, "[a\xEF\xBF\xBD" "b&lt;]", "Escaped output");
    VIEW_ASSERT_RENDER("nul1.html", "[{{ s }}]", doc, VIEW_RAW, "[a\xEF\xBF\xBD" "b<]", "Raw mode output");
    VIEW_ASSERT_RENDER("nul2.html", "[{{ s | raw }}]", doc, VIEW_ESCAPE, "[a\xEF\xBF\xBD" "b<]", "raw modifier");
    VIEW_ASSERT_RENDER("nul3.html", "{{ s | upper | json | raw }}", doc, VIEW_ESCAPE, "\"A\\u0000B\\u003c\"", "Modifier chain into json");
    VIEW_ASSERT_RENDER("nul4.html", "{% for v, k in o %}{{ k | json | raw }}{% endfor %}", doc, VIEW_ESCAPE, "\"a\\u0000b\"", "Loop key keeps its NUL");
    VIEW_ASSERT_RENDER("nul5.html", "{% if s == 'a' %}eq{% else %}ne{% endif %}", doc, VIEW_ESCAPE, "ne", "Comparison sees the NUL");
}

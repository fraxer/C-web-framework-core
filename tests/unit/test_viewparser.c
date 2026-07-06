#include "framework.h"
#include "viewparser.h"
#include "storagefs.h"
#include "appconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

/* env()/appconfig() are provided as weak test doubles by
 * test_httprequestparser.c; appconfig()->storages starts NULL,
 * each test installs its own storage and restores NULL afterwards. */
extern appconfig_t* appconfig(void);

#define VP_TEST_STORAGE "viewparser_test_storage"

// ============================================================================
// Helpers: temp dir with template files + appconfig environment
// ============================================================================

static const char* vp_test_root(void) {
    static char root[PATH_MAX] = {0};
    static int ready = 0;

    if (!ready) {
        snprintf(root, sizeof(root), "/tmp/cwfr_viewparser_test_XXXXXX");
        if (mkdtemp(root) == NULL) return NULL;
        ready = 1;
    }

    return root;
}

static int vp_write_template(const char* name, const char* content) {
    const char* root = vp_test_root();
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

static storagefs_t* vp_env_init(void) {
    const char* root = vp_test_root();
    if (root == NULL) return NULL;

    storagefs_t* fs = storage_create_fs(VP_TEST_STORAGE, root);
    if (fs == NULL) return NULL;

    appconfig()->storages = (storage_t*)fs;

    return fs;
}

static void vp_env_free(storagefs_t* fs) {
    appconfig()->storages = NULL;

    if (fs != NULL) fs->base.free(fs);
}

/* Writes the template, runs the parser on it and returns viewparser_run's
 * result (1 parsed, 0 rejected); -1 on test-infrastructure failure. */
static int vp_parse(const char* name, const char* content) {
    if (!vp_write_template(name, content)) return -1;

    char path[NAME_MAX + 2];
    snprintf(path, sizeof(path), "/%s", name);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, path);
    if (parser == NULL) return -1;

    const int ok = viewparser_run(parser);
    viewparser_free(parser);

    return ok;
}

static const char* vp_tag_content(view_tag_t* tag) {
    bufferdata_complete(&tag->result_content);
    return bufferdata_get(&tag->result_content);
}

// ============================================================================
// Дерево тегов: корректные шаблоны
// ============================================================================

TEST(test_viewparser_static_text_tree) {
    TEST_CASE("Plain text goes to the root tag as is");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_static.html", "Hello, {braces} kept!"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_static.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should succeed", cleanup_parser);

    view_tag_t* root = parser->root_tag;
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_INC, root->type, "Root tag should be include type");
    TEST_ASSERT_NULL(root->child, "Plain text should not create child tags");
    TEST_ASSERT_STR_EQUAL("Hello, {braces} kept!", vp_tag_content(root),
                          "Root content should keep text and single braces");

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_variable_tree) {
    TEST_CASE("Variable with dot path builds a variable expression");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_var.html", "A{{ user.name }}B"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_var.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should succeed", cleanup_parser);

    view_tag_t* root = parser->root_tag;
    TEST_ASSERT_STR_EQUAL("AB", vp_tag_content(root), "Root content should hold surrounding text");

    view_tag_t* var = root->child;
    TEST_REQUIRE_NOT_NULL_GOTO(var, "Variable tag should be created", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_VAR, var->type, "Child tag should be a variable");
    TEST_ASSERT_EQUAL_SIZE(0, var->parent_text_offset, "Variable should start at offset 0");
    TEST_ASSERT_EQUAL_SIZE(1, var->parent_text_size, "Variable should follow one char of text");

    viewexpr_node_t* expr = var->expr;
    TEST_REQUIRE_NOT_NULL_GOTO(expr, "Expression should be attached to the tag", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEWEXPR_NODE_VARIABLE, expr->type, "Expression should be a variable");

    viewexpr_segment_t* segment = expr->path;
    TEST_REQUIRE_NOT_NULL_GOTO(segment, "First path segment should exist", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("user", segment->name, "First path segment should be 'user'");

    TEST_REQUIRE_NOT_NULL_GOTO(segment->next, "Second path segment should exist", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("name", segment->next->name, "Second path segment should be 'name'");
    TEST_ASSERT_NULL(segment->next->next, "Path should contain exactly two segments");

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_variable_index_tree) {
    TEST_CASE("Variable with chained indexes builds index segments");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_idx.html", "{{ items[10][2] }}"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_idx.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should succeed", cleanup_parser);

    view_tag_t* var = parser->root_tag->child;
    TEST_REQUIRE_NOT_NULL_GOTO(var, "Variable tag should be created", cleanup_parser);
    TEST_REQUIRE_NOT_NULL_GOTO(var->expr, "Expression should be attached", cleanup_parser);

    viewexpr_segment_t* segment = var->expr->path;
    TEST_REQUIRE_NOT_NULL_GOTO(segment, "Name segment should exist", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("items", segment->name, "Name segment should be 'items'");

    viewexpr_segment_t* first_index = segment->next;
    TEST_REQUIRE_NOT_NULL_GOTO(first_index, "First index segment should exist", cleanup_parser);
    TEST_REQUIRE_NOT_NULL_GOTO(first_index->index, "First index expression should exist", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEWEXPR_NODE_LITERAL, first_index->index->type, "First index should be a literal");
    TEST_ASSERT_EQUAL(10, (int)first_index->index->literal.number, "First index should be 10");

    viewexpr_segment_t* second_index = first_index->next;
    TEST_REQUIRE_NOT_NULL_GOTO(second_index, "Second index segment should exist", cleanup_parser);
    TEST_REQUIRE_NOT_NULL_GOTO(second_index->index, "Second index expression should exist", cleanup_parser);
    TEST_ASSERT_EQUAL(2, (int)second_index->index->literal.number, "Second index should be 2");
    TEST_ASSERT_NULL(second_index->next, "There should be exactly two index segments");

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_condition_tree) {
    TEST_CASE("if/elseif/else builds condition tag with three branches");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_cond.html",
                                        "{% if !a %}X{% elseif b %}Y{% else %}Z{% endif %}D"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_cond.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should succeed", cleanup_parser);

    view_tag_t* root = parser->root_tag;
    TEST_ASSERT_STR_EQUAL("D", vp_tag_content(root), "Trailing text should stay in root");

    view_tag_t* cond = root->child;
    TEST_REQUIRE_NOT_NULL_GOTO(cond, "Condition tag should be created", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_COND, cond->type, "Wrapper tag should be condition type");

    view_condition_item_t* tag_if = (view_condition_item_t*)cond->child;
    TEST_REQUIRE_NOT_NULL_GOTO(tag_if, "If branch should exist", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_COND_IF, tag_if->base.type, "First branch should be if");
    TEST_REQUIRE_NOT_NULL_GOTO(tag_if->base.expr, "If branch should have an expression", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEWEXPR_NODE_UNARY, tag_if->base.expr->type, "!a should parse to a unary node");
    TEST_ASSERT_EQUAL(VIEWEXPR_OP_NOT, tag_if->base.expr->op, "!a should use the NOT operator");
    TEST_REQUIRE_NOT_NULL_GOTO(tag_if->base.expr->left, "NOT should have an operand", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEWEXPR_NODE_VARIABLE, tag_if->base.expr->left->type, "NOT operand should be a variable");
    TEST_ASSERT_STR_EQUAL("a", tag_if->base.expr->left->path->name, "If branch should test variable 'a'");
    TEST_ASSERT_STR_EQUAL("X", vp_tag_content(&tag_if->base), "If branch body should be 'X'");

    view_condition_item_t* tag_elseif = (view_condition_item_t*)tag_if->base.next;
    TEST_REQUIRE_NOT_NULL_GOTO(tag_elseif, "Elseif branch should exist", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_COND_ELSEIF, tag_elseif->base.type, "Second branch should be elseif");
    TEST_REQUIRE_NOT_NULL_GOTO(tag_elseif->base.expr, "Elseif branch should have an expression", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEWEXPR_NODE_VARIABLE, tag_elseif->base.expr->type, "Elseif expression should be a variable");
    TEST_ASSERT_STR_EQUAL("b", tag_elseif->base.expr->path->name, "Elseif branch should test variable 'b'");
    TEST_ASSERT_STR_EQUAL("Y", vp_tag_content(&tag_elseif->base), "Elseif branch body should be 'Y'");

    view_condition_item_t* tag_else = (view_condition_item_t*)tag_elseif->base.next;
    TEST_REQUIRE_NOT_NULL_GOTO(tag_else, "Else branch should exist", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_COND_ELSE, tag_else->base.type, "Third branch should be else");
    TEST_ASSERT_EQUAL(1, tag_else->always_true, "Else should be always true");
    TEST_ASSERT_STR_EQUAL("Z", vp_tag_content(&tag_else->base), "Else branch body should be 'Z'");
    TEST_ASSERT_NULL(tag_else->base.next, "There should be exactly three branches");

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_loop_tree) {
    TEST_CASE("for builds loop tag with element, default key and collection");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_for.html",
                                        "{% for item in data.items %}{{ item }}{% endfor %}"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_for.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should succeed", cleanup_parser);

    view_loop_t* loop = (view_loop_t*)parser->root_tag->child;
    TEST_REQUIRE_NOT_NULL_GOTO(loop, "Loop tag should be created", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_LOOP, loop->base.type, "Child tag should be a loop");
    TEST_ASSERT_STR_EQUAL("item", loop->element_name, "Element name should be 'item'");
    TEST_ASSERT_STR_EQUAL("index", loop->key_name, "Default key name should be 'index'");

    TEST_REQUIRE_NOT_NULL_GOTO(loop->base.expr, "Collection expression should exist", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEWEXPR_NODE_VARIABLE, loop->base.expr->type, "Collection should be a variable");

    viewexpr_segment_t* segment = loop->base.expr->path;
    TEST_REQUIRE_NOT_NULL_GOTO(segment, "Collection path should exist", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("data", segment->name, "Collection path should start with 'data'");
    TEST_REQUIRE_NOT_NULL_GOTO(segment->next, "Second path segment should exist", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("items", segment->next->name, "Collection path should end with 'items'");

    view_tag_t* var = loop->base.child;
    TEST_REQUIRE_NOT_NULL_GOTO(var, "Loop body variable should exist", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_VAR, var->type, "Loop body child should be a variable");
    TEST_ASSERT(var->data_parent == (view_tag_t*)loop,
                "Loop body variable should have the loop as data parent");

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_loop_explicit_key) {
    TEST_CASE("for with explicit key fills element and key names");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_forkey.html",
                                        "{% for v, k in obj %}{% endfor %}"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_forkey.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should succeed", cleanup_parser);

    view_loop_t* loop = (view_loop_t*)parser->root_tag->child;
    TEST_REQUIRE_NOT_NULL_GOTO(loop, "Loop tag should be created", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("v", loop->element_name, "Element name should be 'v'");
    TEST_ASSERT_STR_EQUAL("k", loop->key_name, "Key name should be 'k'");
    TEST_REQUIRE_NOT_NULL_GOTO(loop->base.expr, "Collection expression should exist", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("obj", loop->base.expr->path->name, "Collection should be 'obj'");

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_loop_extra_spaces) {
    TEST_CASE("for tolerates repeated spaces between words");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_forsp.html",
                                        "{% for  item  in  items %}x{% endfor %}"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_forsp.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    // до фикса двойной пробел после "for"/"item" ломал разбор: пустое имя
    // элемента уводило парсер в LOOP_IN, где "item" не проходил как "in"
    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should tolerate double spaces", cleanup_parser);

    view_loop_t* loop = (view_loop_t*)parser->root_tag->child;
    TEST_REQUIRE_NOT_NULL_GOTO(loop, "Loop tag should be created", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("item", loop->element_name, "Element name should survive extra spaces");
    TEST_ASSERT_STR_EQUAL("index", loop->key_name, "Default key should be set");
    TEST_REQUIRE_NOT_NULL_GOTO(loop->base.expr, "Collection expression should exist", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("items", loop->base.expr->path->name, "Collection should survive extra spaces");

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_include_tree) {
    TEST_CASE("include loads partial into a child include tag");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_inc_part.html", "P{{ x }}Q"),
                      "Partial should be written", cleanup);
    TEST_REQUIRE_GOTO(vp_write_template("vp_inc_main.html",
                                        "A{* include /vp_inc_part.html *}B"),
                      "Main template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_inc_main.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should succeed", cleanup_parser);

    view_tag_t* root = parser->root_tag;
    TEST_ASSERT_STR_EQUAL("AB", vp_tag_content(root), "Root should keep surrounding text");

    view_tag_t* inc = root->child;
    TEST_REQUIRE_NOT_NULL_GOTO(inc, "Include tag should be created", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_INC, inc->type, "Child tag should be include type");
    TEST_ASSERT_STR_EQUAL("PQ", vp_tag_content(inc), "Partial text should live in the include tag");

    view_tag_t* var = inc->child;
    TEST_REQUIRE_NOT_NULL_GOTO(var, "Partial variable should exist", cleanup_parser);
    TEST_ASSERT_EQUAL(VIEW_TAGTYPE_VAR, var->type, "Partial child should be a variable");
    TEST_REQUIRE_NOT_NULL_GOTO(var->expr, "Partial variable expression should exist", cleanup_parser);
    TEST_ASSERT_STR_EQUAL("x", var->expr->path->name, "Partial variable should be 'x'");

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_move_root_tag) {
    TEST_CASE("move_root_tag transfers ownership of the tree");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_move.html", "text"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_move.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_REQUIRE_GOTO(viewparser_run(parser), "Parse should succeed", cleanup_parser);

    view_tag_t* root = viewparser_move_root_tag(parser);
    TEST_ASSERT_NOT_NULL(root, "Moved root tag should be returned");
    TEST_ASSERT_NULL(parser->root_tag, "Parser should give up the root tag");
    TEST_ASSERT_NULL(parser->current_tag, "Parser should give up the current tag");

    if (root != NULL)
        root->free(root);

cleanup_parser:
    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_free_null) {
    TEST_CASE("viewparser_free(NULL) is a no-op");

    viewparser_free(NULL);
    TEST_ASSERT(1, "Freeing NULL parser should not crash");
}

// ============================================================================
// Ошибочные шаблоны: парсер должен отклонять, а не падать/молчать
// ============================================================================

TEST(test_viewparser_reject_missing_file) {
    TEST_CASE("Missing template file fails the run");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_no_such_file.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_ASSERT_EQUAL(0, viewparser_run(parser), "Run should fail on missing file");

    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_reject_stray_close_tags) {
    TEST_CASE("endif/endfor without opening tag are rejected, not a crash");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    // до фикса оба разыменовывали NULL: current_tag->parent->parent у корня
    TEST_ASSERT_EQUAL(0, vp_parse("vp_e1.html", "A{% endif %}B"),
                      "Stray endif should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_e2.html", "A{% endfor %}B"),
                      "Stray endfor should be a parse error");

    vp_env_free(fs);
}

TEST(test_viewparser_reject_garbage_branch_words) {
    TEST_CASE("Partially matching branch words are rejected");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    // до фикса посимвольное сравнение принимало эти слова как if/endif/endfor
    TEST_ASSERT_EQUAL(0, vp_parse("vp_g1.html", "{% ef a %}X{% endif %}"),
                      "'ef' should not be accepted as 'if'");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_g2.html", "{% eabcd %}"),
                      "5-letter word starting with 'e' should not be accepted as 'endif'");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_g3.html", "{% endzzz %}"),
                      "'endzzz' should not be accepted as 'endfor'");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_g4.html", "A{% unknown %}B"),
                      "Unknown branch word should be a parse error");

    vp_env_free(fs);
}

TEST(test_viewparser_reject_mismatched_close_tags) {
    TEST_CASE("Closing tag of the wrong kind is rejected");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    TEST_ASSERT_EQUAL(0, vp_parse("vp_m1.html", "{% if a %}X{% endfor %}"),
                      "endfor should not close an if");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_m2.html", "{% for x in xs %}X{% endif %}"),
                      "endif should not close a for");

    vp_env_free(fs);
}

TEST(test_viewparser_reject_unterminated_tags) {
    TEST_CASE("Tags left open at end of template are rejected");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    // до фикса всё это молча парсилось как валидный шаблон
    TEST_ASSERT_EQUAL(0, vp_parse("vp_u1.html", "A{{ name"),
                      "Unterminated variable should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_u2.html", "A{{ name }"),
                      "Variable closed with single brace should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_u3.html", "{% if a %}X"),
                      "if without endif should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_u4.html", "{% for x in xs %}X"),
                      "for without endfor should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_u5.html", "A{% if a"),
                      "Unterminated branch tag should be a parse error");

    vp_env_free(fs);
}

TEST(test_viewparser_reject_empty_and_broken_variables) {
    TEST_CASE("Empty and malformed variables are rejected");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    // до фикса {{}} оставлял тег переменной текущим и портил дерево
    TEST_ASSERT_EQUAL(0, vp_parse("vp_v1.html", "A{{}}B"),
                      "Empty variable should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_v2.html", "A{{ }}B"),
                      "Whitespace-only variable should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_v3.html", "{{ a b }}"),
                      "Space inside variable name should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_v4.html", "{{ a. }}"),
                      "Trailing dot should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_v5.html", "{{ a }b}}"),
                      "Text after single closing brace should be a parse error");

    vp_env_free(fs);
}

TEST(test_viewparser_reject_bad_indexes) {
    TEST_CASE("Malformed indexes are rejected");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    TEST_ASSERT_EQUAL(0, vp_parse("vp_i1.html", "{{ items[1x] }}"),
                      "Non-digit index should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_i2.html", "{{ items[] }}"),
                      "Empty index should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_i3.html", "{{ items[2 }}"),
                      "Unclosed index should be a parse error");

    // границы индексов теперь проверяются при рендере, а не при парсинге
    TEST_ASSERT_EQUAL(1, vp_parse("vp_i4.html", "{{ items[9999999999] }}"),
                      "Index above INT_MAX should parse and resolve to nothing at render");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_i5.html", "{{ items[2147483647] }}"),
                      "INT_MAX index should still be accepted");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_i6.html", "{{ items[i + 1] }}"),
                      "Index may be an arbitrary expression");

    vp_env_free(fs);
}

TEST(test_viewparser_expression_tags) {
    TEST_CASE("Recursive descent expressions parse in variable and branch tags");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    TEST_ASSERT_EQUAL(1, vp_parse("vp_x1.html", "{{ a + b * 2 }}"),
                      "Arithmetic expression should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_x2.html", "{{ (a + b) * (c - d) }}"),
                      "Parenthesized expression should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_x3.html", "{% if a && (b || !c) %}X{% endif %}"),
                      "Logical expression should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_x4.html", "{% if role == 'admin' %}X{% endif %}"),
                      "String comparison should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_x5.html", "{% if count % 2 == 0 %}X{% endif %}"),
                      "Modulo in condition should not close the branch tag");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_x6.html", "{{ 'literal }} braces' }}"),
                      "Close braces inside a string literal should not close the tag");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_x7.html", "{% if price >= 10.5 %}X{% endif %}"),
                      "Float literal should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_x8.html", "{% for x in list[2].items %}{{ x }}{% endfor %}"),
                      "Collection may be a path expression");

    TEST_ASSERT_EQUAL(0, vp_parse("vp_x9.html", "{{ a + }}"),
                      "Dangling operator should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_x10.html", "{{ (a }}"),
                      "Unbalanced paren should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_x11.html", "{{ a = b }}"),
                      "Single '=' should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_x12.html", "{{ 'unterminated }}"),
                      "Unterminated string literal should be a parse error");

    vp_env_free(fs);
}

TEST(test_viewparser_reject_broken_includes) {
    TEST_CASE("Broken include statements are rejected");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    // до фикса ошибка ключевого слова игнорировалась и тег include
    // оставался текущим навсегда
    TEST_ASSERT_EQUAL(0, vp_parse("vp_b1.html", "A{* bogus /p.html *}B"),
                      "Invalid include keyword should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_b2.html", "A{* include *}B"),
                      "Include without path should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_b3.html", "A{**}B"),
                      "Empty include should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_b4.html", "A{* include /vp_missing_part.html *}B"),
                      "Include of missing file should be a parse error");

    vp_env_free(fs);
}

TEST(test_viewparser_reject_broken_conditions_and_loops) {
    TEST_CASE("Malformed condition and loop headers are rejected");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    TEST_ASSERT_EQUAL(0, vp_parse("vp_c1.html", "{% if %}X{% endif %}"),
                      "if without expression should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_c2.html", "{% if ! %}X{% endif %}"),
                      "if with bare inverse should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_c3.html", "{% elseif b %}X{% endif %}"),
                      "elseif without if should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_c4.html", "{% else %}X{% endif %}"),
                      "else without if should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_c5.html", "{% for in in items %}X{% endfor %}"),
                      "'in' as element name should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_c6.html", "{% for index in items %}X{% endfor %}"),
                      "'index' as element with default key should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_c7.html", "{% for x, x in items %}X{% endfor %}"),
                      "Key equal to element name should be a parse error");
    TEST_ASSERT_EQUAL(0, vp_parse("vp_c8.html", "{% for x in %}X{% endfor %}"),
                      "for without collection should be a parse error");

    vp_env_free(fs);
}

TEST(test_viewparser_reject_include_depth_overflow) {
    TEST_CASE("Self-including template hits the depth limit");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");
    TEST_REQUIRE_GOTO(vp_write_template("vp_self.html", "{* include /vp_self.html *}"),
                      "Template should be written", cleanup);

    viewparser_t* parser = viewparser_init(VP_TEST_STORAGE, "/vp_self.html");
    TEST_REQUIRE_NOT_NULL_GOTO(parser, "Parser should be created", cleanup);

    TEST_ASSERT_EQUAL(0, viewparser_run(parser), "Run should fail on include recursion");

    viewparser_free(parser);
cleanup:
    vp_env_free(fs);
}

TEST(test_viewparser_accepts_valid_edge_cases) {
    TEST_CASE("Valid edge cases still parse");

    storagefs_t* fs = vp_env_init();
    TEST_REQUIRE_NOT_NULL(fs, "Environment should be initialized");

    TEST_ASSERT_EQUAL(1, vp_parse("vp_ok1.html", ""),
                      "Empty template should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_ok2.html", "{{a}}"),
                      "Minimal variable should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_ok3.html", "a{b}c{ {d"),
                      "Single braces in text should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_ok4.html", "{{ items[ 2 ] }}"),
                      "Spaces around index should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_ok5.html", "{% if a %}{% if b %}X{% endif %}{% endif %}"),
                      "Nested conditions should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_ok6.html",
                                  "{% for r in rows %}{% for c in r %}{{ c }}{% endfor %}{% endfor %}"),
                      "Nested loops should parse");
    TEST_ASSERT_EQUAL(1, vp_parse("vp_ok7.html", "text{"),
                      "Trailing single brace should parse");

    vp_env_free(fs);
}

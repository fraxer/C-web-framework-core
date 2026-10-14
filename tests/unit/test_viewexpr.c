#include "framework.h"
#include "viewexpr.h"
#include "viewmodifier.h"
#include "arena.h"

#include <locale.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Helpers: parse + eval with a fixed scope
// ============================================================================

static viewexpr_value_t vx_scope_resolve(const viewexpr_scope_t* scope, const char* name) {
    json_doc_t* doc = scope->data;
    viewexpr_value_t value = { VIEWEXPR_NULL, 0, 0, NULL, NULL, 0 };

    const json_token_t* root = doc != NULL ? json_root(doc) : NULL;
    if (root == NULL || root->type != JSON_OBJECT) return value;

    return viewexpr_value_from_token(json_object_get(root, name));
}

/* Parses and evaluates the expression against a JSON object; -1 on parse
 * error, otherwise 0/1 truthiness of the result. */
static int vx_truth(const char* expression, json_doc_t* doc) {
    viewexpr_node_t* node = viewexpr_parse(expression, strlen(expression));
    if (node == NULL) return -1;

    const viewexpr_scope_t scope = { vx_scope_resolve, doc, NULL };
    const viewexpr_value_t value = viewexpr_eval(node, &scope);

    // the value may borrow a string owned by the AST — consume it first
    const int istrue = viewexpr_value_istrue(&value);

    viewexpr_node_free(node);

    return istrue;
}

/* Parses and evaluates a numeric expression; NAN on parse error or
 * non-number result. */
static long double vx_number(const char* expression, json_doc_t* doc) {
    viewexpr_node_t* node = viewexpr_parse(expression, strlen(expression));
    if (node == NULL) return NAN;

    const viewexpr_scope_t scope = { vx_scope_resolve, doc, NULL };
    const viewexpr_value_t value = viewexpr_eval(node, &scope);
    const long double number = value.type == VIEWEXPR_NUMBER ? value.number : NAN;

    viewexpr_node_free(node);

    return number;
}

static int vx_parses(const char* expression) {
    viewexpr_node_t* node = viewexpr_parse(expression, strlen(expression));
    viewexpr_node_free(node);
    return node != NULL;
}

// ============================================================================
// Разбор: принимаемые и отклоняемые выражения
// ============================================================================

TEST(test_viewexpr_parse_accepts) {
    TEST_CASE("Valid expressions parse");

    TEST_ASSERT(vx_parses("a"), "Identifier should parse");
    TEST_ASSERT(vx_parses("a.b.c"), "Dot path should parse");
    TEST_ASSERT(vx_parses("a[0][1]"), "Index chain should parse");
    TEST_ASSERT(vx_parses("a[b + 1].c"), "Expression index with field should parse");
    TEST_ASSERT(vx_parses("1 + 2 * 3"), "Arithmetic should parse");
    TEST_ASSERT(vx_parses("!(a && b) || c"), "Logic with parens should parse");
    TEST_ASSERT(vx_parses("a == 'text'"), "String comparison should parse");
    TEST_ASSERT(vx_parses("\"double\" != 'single'"), "Both quote kinds should parse");
    TEST_ASSERT(vx_parses("-5.5e2"), "Scientific notation should parse");
    TEST_ASSERT(vx_parses("true && !false"), "Bool literals should parse");
    TEST_ASSERT(vx_parses("a == null"), "Null literal should parse");
    TEST_ASSERT(vx_parses("  a  "), "Surrounding spaces should parse");
}

TEST(test_viewexpr_parse_rejects) {
    TEST_CASE("Malformed expressions are rejected");

    TEST_ASSERT(!vx_parses(""), "Empty expression should fail");
    TEST_ASSERT(!vx_parses("   "), "Whitespace-only expression should fail");
    TEST_ASSERT(!vx_parses("a +"), "Dangling operator should fail");
    TEST_ASSERT(!vx_parses("+ a"), "Leading '+' should fail");
    TEST_ASSERT(!vx_parses("a b"), "Two operands in a row should fail");
    TEST_ASSERT(!vx_parses("(a"), "Unbalanced open paren should fail");
    TEST_ASSERT(!vx_parses("a)"), "Unbalanced close paren should fail");
    TEST_ASSERT(!vx_parses("a[1"), "Unbalanced bracket should fail");
    TEST_ASSERT(!vx_parses("a."), "Trailing dot should fail");
    TEST_ASSERT(!vx_parses(".a"), "Leading dot should fail");
    TEST_ASSERT(!vx_parses("a = b"), "Single '=' should fail");
    TEST_ASSERT(!vx_parses("a & b"), "Single '&' should fail");
    TEST_ASSERT(!vx_parses("a | b"), "Single '|' should fail");
    TEST_ASSERT(!vx_parses("1x"), "Malformed number should fail");
    TEST_ASSERT(!vx_parses("1."), "Number with trailing dot should fail");
    TEST_ASSERT(!vx_parses("1e"), "Number with empty exponent should fail");
    TEST_ASSERT(!vx_parses("'oops"), "Unterminated string should fail");
    TEST_ASSERT(!vx_parses("a ? b"), "Unknown character should fail");
}

TEST(test_viewexpr_parse_depth_limit) {
    TEST_CASE("Deeply nested expressions are rejected, not a stack overflow");

    char deep[512];
    size_t pos = 0;
    for (int i = 0; i < 100; i++) deep[pos++] = '(';
    deep[pos++] = 'a';
    for (int i = 0; i < 100; i++) deep[pos++] = ')';
    deep[pos] = 0;

    TEST_ASSERT(!vx_parses(deep), "100 nested parens should exceed the depth limit");

    char unary[128];
    memset(unary, '!', 100);
    unary[100] = 'a';
    unary[101] = 0;

    TEST_ASSERT(!vx_parses(unary), "100 nested unary operators should exceed the depth limit");
}

// ============================================================================
// Вычисление: арифметика, сравнения, логика
// ============================================================================

TEST(test_viewexpr_eval_arithmetic) {
    TEST_CASE("Arithmetic follows precedence and associativity");

    TEST_ASSERT_EQUAL(7, (int)vx_number("1 + 2 * 3", NULL), "Multiplication binds tighter");
    TEST_ASSERT_EQUAL(9, (int)vx_number("(1 + 2) * 3", NULL), "Parens override precedence");
    TEST_ASSERT_EQUAL(1, (int)vx_number("7 - 4 + 5 - 7", NULL), "Additive is left-associative");
    TEST_ASSERT_EQUAL(2, (int)vx_number("8 / 2 / 2", NULL), "Division is left-associative");
    TEST_ASSERT_EQUAL(3, (int)vx_number("13 % 5", NULL), "Modulo works on numbers");
    TEST_ASSERT_EQUAL(-6, (int)vx_number("-2 * 3", NULL), "Unary minus applies to operand");
    TEST_ASSERT(vx_number("0.1 + 0.2", NULL) > 0.29L && vx_number("0.1 + 0.2", NULL) < 0.31L,
                "Float arithmetic should work");

    TEST_ASSERT(isnan(vx_number("1 / 0", NULL)), "Division by zero should not be a number");
    TEST_ASSERT(isnan(vx_number("1 % 0", NULL)), "Modulo by zero should not be a number");
    TEST_ASSERT(isnan(vx_number("'a' + 1", NULL)), "String plus number should not be a number");
}

TEST(test_viewexpr_eval_comparisons) {
    TEST_CASE("Comparisons work for numbers and strings");

    TEST_ASSERT_EQUAL(1, vx_truth("2 > 1", NULL), "2 > 1 should be true");
    TEST_ASSERT_EQUAL(0, vx_truth("2 > 2", NULL), "2 > 2 should be false");
    TEST_ASSERT_EQUAL(1, vx_truth("2 >= 2", NULL), "2 >= 2 should be true");
    TEST_ASSERT_EQUAL(1, vx_truth("1 < 2", NULL), "1 < 2 should be true");
    TEST_ASSERT_EQUAL(1, vx_truth("2 <= 2", NULL), "2 <= 2 should be true");
    TEST_ASSERT_EQUAL(1, vx_truth("1 + 1 == 2", NULL), "Equality binds looser than addition");
    TEST_ASSERT_EQUAL(1, vx_truth("1 != 2", NULL), "1 != 2 should be true");

    TEST_ASSERT_EQUAL(1, vx_truth("'abc' == 'abc'", NULL), "Equal strings should compare equal");
    TEST_ASSERT_EQUAL(1, vx_truth("'abc' < 'abd'", NULL), "Strings should compare lexicographically");
    TEST_ASSERT_EQUAL(0, vx_truth("'1' == 1", NULL), "String and number should not be equal");
    TEST_ASSERT_EQUAL(0, vx_truth("'a' < 1", NULL), "Mixed types should not be ordered");
    TEST_ASSERT_EQUAL(1, vx_truth("null == null", NULL), "null should equal null");
    TEST_ASSERT_EQUAL(1, vx_truth("true == true", NULL), "true should equal true");
}

TEST(test_viewexpr_eval_logic) {
    TEST_CASE("Logical operators short-circuit and combine");

    TEST_ASSERT_EQUAL(1, vx_truth("true && true", NULL), "true && true");
    TEST_ASSERT_EQUAL(0, vx_truth("true && false", NULL), "true && false");
    TEST_ASSERT_EQUAL(1, vx_truth("false || true", NULL), "false || true");
    TEST_ASSERT_EQUAL(0, vx_truth("false || false", NULL), "false || false");
    TEST_ASSERT_EQUAL(1, vx_truth("!false", NULL), "!false");
    TEST_ASSERT_EQUAL(1, vx_truth("true || unknown && false", NULL),
                      "&& binds tighter than ||");
    TEST_ASSERT_EQUAL(1, vx_truth("!(true && false)", NULL), "Parens with NOT");
}

TEST(test_viewexpr_eval_variables) {
    TEST_CASE("Variables resolve through the scope and json paths");

    json_doc_t* doc = json_parse(
        "{\"num\":5,\"str\":\"hi\",\"flag\":true,"
        "\"user\":{\"name\":\"bob\",\"tags\":[\"x\",\"y\"]},"
        "\"matrix\":[[1,2],[3,4]]}");
    TEST_REQUIRE_NOT_NULL(doc, "Document should be parsed");

    TEST_ASSERT_EQUAL(5, (int)vx_number("num", doc), "Number variable should resolve");
    TEST_ASSERT_EQUAL(6, (int)vx_number("num + 1", doc), "Variable should work in arithmetic");
    TEST_ASSERT_EQUAL(1, vx_truth("str == 'hi'", doc), "String variable should compare");
    TEST_ASSERT_EQUAL(1, vx_truth("flag", doc), "Bool variable should resolve");
    TEST_ASSERT_EQUAL(1, vx_truth("user.name == 'bob'", doc), "Dot path should resolve");
    TEST_ASSERT_EQUAL(1, vx_truth("user.tags[1] == 'y'", doc), "Index path should resolve");
    TEST_ASSERT_EQUAL(4, (int)vx_number("matrix[1][1]", doc), "Chained indexes should resolve");
    TEST_ASSERT_EQUAL(3, (int)vx_number("matrix[num - 4][0]", doc),
                      "Index may be a computed expression");

    TEST_ASSERT_EQUAL(0, vx_truth("missing", doc), "Missing variable should be falsy");
    TEST_ASSERT_EQUAL(0, vx_truth("user.missing.deep", doc), "Missing path should be falsy");
    TEST_ASSERT_EQUAL(0, vx_truth("user.tags[99]", doc), "Out-of-range index should be falsy");
    TEST_ASSERT_EQUAL(0, vx_truth("user.tags[-1]", doc), "Negative index should be falsy");
    TEST_ASSERT_EQUAL(0, vx_truth("num.field", doc), "Field of a scalar should be falsy");
    TEST_ASSERT_EQUAL(1, vx_truth("missing == null", doc), "Missing variable should equal null");

    json_free(doc);
}

TEST(test_viewexpr_eval_truthiness) {
    TEST_CASE("Truthiness of containers and empties");

    json_doc_t* doc = json_parse(
        "{\"full\":[1],\"empty\":[],\"obj\":{\"a\":1},\"eobj\":{},\"estr\":\"\"}");
    TEST_REQUIRE_NOT_NULL(doc, "Document should be parsed");

    TEST_ASSERT_EQUAL(1, vx_truth("full", doc), "Non-empty array should be truthy");
    TEST_ASSERT_EQUAL(0, vx_truth("empty", doc), "Empty array should be falsy");
    TEST_ASSERT_EQUAL(1, vx_truth("obj", doc), "Non-empty object should be truthy");
    TEST_ASSERT_EQUAL(0, vx_truth("eobj", doc), "Empty object should be falsy");
    TEST_ASSERT_EQUAL(0, vx_truth("estr", doc), "Empty string should be falsy");
    TEST_ASSERT_EQUAL(0, vx_truth("0", NULL), "Zero should be falsy");
    TEST_ASSERT_EQUAL(1, vx_truth("0.5", NULL), "Non-zero number should be truthy");
    TEST_ASSERT_EQUAL(0, vx_truth("''", NULL), "Empty string literal should be falsy");
    TEST_ASSERT_EQUAL(0, vx_truth("null", NULL), "null should be falsy");

    json_free(doc);
}

TEST(test_viewexpr_eval_string_escapes) {
    TEST_CASE("String literal escapes decode");

    TEST_ASSERT_EQUAL(1, vx_truth("'a\\'b' == \"a'b\"", NULL), "Escaped quote should decode");
    TEST_ASSERT_EQUAL(1, vx_truth("'a\\\\b' != 'ab'", NULL), "Escaped backslash should stay");
    TEST_ASSERT_EQUAL(1, vx_truth("'\\n' != ''", NULL), "Escaped newline should decode to a char");
}

TEST(test_viewexpr_eval_null_inputs) {
    TEST_CASE("NULL node, scope and free are safe");

    viewexpr_node_free(NULL);

    const viewexpr_value_t value = viewexpr_eval(NULL, NULL);
    TEST_ASSERT_EQUAL(VIEWEXPR_NULL, value.type, "NULL node should evaluate to null");

    viewexpr_node_t* node = viewexpr_parse("a + 1", 5);
    TEST_REQUIRE_NOT_NULL(node, "Expression should parse");

    const viewexpr_value_t no_scope = viewexpr_eval(node, NULL);
    TEST_ASSERT_EQUAL(VIEWEXPR_NULL, no_scope.type,
                      "Variable without scope should evaluate to null");

    viewexpr_node_free(node);

    TEST_ASSERT_NULL(viewexpr_parse(NULL, 5), "NULL expression should not parse");
    TEST_ASSERT_NULL(viewexpr_parse("a", 0), "Zero length should not parse");
}

// ============================================================================
// Форматирование чисел
// ============================================================================

TEST(test_viewexpr_number_format) {
    TEST_CASE("Numbers format without trailing noise");

    char buffer[64];

    TEST_ASSERT(viewexpr_number_format(42.0L, buffer, sizeof(buffer)) > 0, "42 should format");
    TEST_ASSERT_STR_EQUAL("42", buffer, "Integral value should have no fraction");

    TEST_ASSERT(viewexpr_number_format(-7.0L, buffer, sizeof(buffer)) > 0, "-7 should format");
    TEST_ASSERT_STR_EQUAL("-7", buffer, "Negative integral value should format");

    TEST_ASSERT(viewexpr_number_format(9.99L, buffer, sizeof(buffer)) > 0, "9.99 should format");
    TEST_ASSERT_STR_EQUAL("9.99", buffer, "Fraction should use the shortest form");

    TEST_ASSERT(viewexpr_number_format(2.5L, buffer, sizeof(buffer)) > 0, "2.5 should format");
    TEST_ASSERT_STR_EQUAL("2.5", buffer, "Half should format exactly");

    TEST_ASSERT(viewexpr_number_format(0.0L, buffer, sizeof(buffer)) > 0, "0 should format");
    TEST_ASSERT_STR_EQUAL("0", buffer, "Zero should format as 0");

    TEST_ASSERT_EQUAL_SIZE(0, viewexpr_number_format(NAN, buffer, sizeof(buffer)),
                           "NaN should not format");
    TEST_ASSERT_EQUAL_SIZE(0, viewexpr_number_format(INFINITY, buffer, sizeof(buffer)),
                           "Infinity should not format");
    TEST_ASSERT_EQUAL_SIZE(0, viewexpr_number_format(1.0L, NULL, 0),
                           "NULL buffer should not format");
}

TEST(test_viewexpr_numbers_ignore_locale) {
    TEST_CASE("Number literals and printing do not follow the current locale");

    locale_t comma = newlocale(LC_ALL_MASK, "ru_RU.utf8", (locale_t)0);
    if (comma == (locale_t)0) {
        printf("  (skipped: ru_RU.utf8 is not installed)\n");
        return;
    }
    const locale_t previous = uselocale(comma);

    const long double product = vx_number("1.25 * 2", NULL);
    char buffer[64];
    viewexpr_number_format(0.5L, buffer, sizeof(buffer));

    uselocale(previous);
    freelocale(comma);

    TEST_ASSERT(product == 2.5L, "1.25 reads as one and a quarter");
    TEST_ASSERT_STR_EQUAL("0.5", buffer, "A fraction prints with a decimal point");
}

// ============================================================================
// Modifiers
// ============================================================================

static char vx_result[1024];

/* Parses `expression` as a {{ }} tag (viewexpr_parse_output), evaluates it
 * against `doc` with an arena and returns the result as text: strings as is,
 * numbers via viewexpr_number_format, bools "true"/"false", containers
 * "<token>", null "<null>", "<parse-error>" when the parse fails. */
static const char* vx_text(const char* expression, json_doc_t* doc) {
    viewexpr_node_t* node = viewexpr_parse_output(expression, strlen(expression));
    if (node == NULL) {
        snprintf(vx_result, sizeof(vx_result), "<parse-error>");
        return vx_result;
    }

    arena_t arena;
    arena_init(&arena);

    const viewexpr_scope_t scope = { vx_scope_resolve, doc, &arena };
    const viewexpr_value_t value = viewexpr_eval(node, &scope);

    switch (value.type)
    {
    case VIEWEXPR_STRING:
    {
        // NUL bytes inside the value show as the two characters "\0"
        size_t out = 0;
        for (size_t i = 0; i < value.length && out + 3 < sizeof(vx_result); i++) {
            if (value.string[i] == 0) {
                vx_result[out++] = '\\';
                vx_result[out++] = '0';
            }
            else
                vx_result[out++] = value.string[i];
        }
        vx_result[out] = 0;
        break;
    }
    case VIEWEXPR_NUMBER:
        viewexpr_number_format(value.number, vx_result, sizeof(vx_result));
        break;
    case VIEWEXPR_BOOL:
        snprintf(vx_result, sizeof(vx_result), "%s", value.boolean ? "true" : "false");
        break;
    case VIEWEXPR_TOKEN:
        snprintf(vx_result, sizeof(vx_result), "<token>");
        break;
    default:
        snprintf(vx_result, sizeof(vx_result), "<null>");
        break;
    }

    arena_free(&arena);
    viewexpr_node_free(node);

    return vx_result;
}

TEST(test_viewexpr_modifier_binding) {
    TEST_CASE("Modifier binds to the nearest operand");

    json_doc_t* doc = json_parse("{\"price\":2,\"qty\":1.256,\"a\":\"\",\"b\":\"x\",\"count\":null,\"x\":-3,"
                                 "\"login\":\"bob\",\"name\":null,\"items\":{\"k\":\"v\"},\"key\":\"K\"}");
    TEST_REQUIRE_NOT_NULL(doc, "Document should be parsed");

    TEST_ASSERT_STR_EQUAL("2.52", vx_text("price * qty | round(2)", doc), "Modifier applies to qty only");
    TEST_ASSERT_STR_EQUAL("2.51", vx_text("(price * qty) | round(2)", doc), "Parentheses apply it to the product");
    TEST_ASSERT_STR_EQUAL("true", vx_text("a || b | upper", doc), "Modifier binds tighter than ||");
    TEST_ASSERT_STR_EQUAL("1", vx_text("count | default(0) + 1", doc), "Modifier binds tighter than +");
    TEST_ASSERT_STR_EQUAL("-3", vx_text("-x | abs", doc), "Unary minus applies after the modifier");
    TEST_ASSERT_STR_EQUAL("BOB", vx_text("name | default(login | upper)", doc), "Modifier inside an argument");
    TEST_ASSERT_STR_EQUAL("v", vx_text("items[key | lower]", doc), "Modifier inside an index");
    TEST_ASSERT_STR_EQUAL("X", vx_text("b | upper()", doc), "Empty parentheses");
    TEST_ASSERT_STR_EQUAL("X", vx_text("b|upper", doc), "No spaces around |");
    TEST_ASSERT_STR_EQUAL("X", vx_text("b |upper( )", doc), "Space inside parentheses");
    TEST_ASSERT_STR_EQUAL("X", vx_text("b\n| upper", doc), "Line break before |");
    TEST_ASSERT_STR_EQUAL("|", vx_text("b | replace('x', '|')", doc), "| inside a string literal is text");
    TEST_ASSERT_STR_EQUAL("true", vx_text("b || b", doc), "|| is still logical or");

    json_free(doc);
}

TEST(test_viewexpr_modifier_parse_errors) {
    TEST_CASE("Modifier parse errors");

    json_doc_t* doc = json_parse("{\"a\":\"\",\"b\":\"x\"}");
    TEST_REQUIRE_NOT_NULL(doc, "Document should be parsed");

    const char* invalid[] = {
        "b | nope", "b | upper(1)", "b | truncate", "b | truncate(1, 2, 3)",
        "b |", "b | | upper", "b | upper(", "b | (upper)", "| b",
        "b | raw || a", "b | nl2br | upper", "b | default(a | raw)", "b | raw | raw",
        "b | upper(,)", "b | truncate(1,)", "!b | raw"
    };

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        TEST_ASSERT_STR_EQUAL("<parse-error>", vx_text(invalid[i], doc), invalid[i]);

    TEST_ASSERT_STR_EQUAL("X", vx_text("b | upper | raw", doc), "raw last at the root is allowed");
    TEST_ASSERT_STR_EQUAL("x", vx_text("b | nl2br", doc), "nl2br at the root is allowed");
    TEST_ASSERT_STR_EQUAL("x", vx_text("(b | raw)", doc), "Parentheses add no node: raw is still the root");

    json_free(doc);
}

TEST(test_viewexpr_modifier_raw_forbidden_in_parse) {
    TEST_CASE("raw and nl2br are refused outside {{ }}");

    TEST_ASSERT_NULL(viewexpr_parse("b | raw", 7), "raw is refused by viewexpr_parse");
    TEST_ASSERT_NULL(viewexpr_parse("b | nl2br", 9), "nl2br is refused by viewexpr_parse");

    viewexpr_node_t* node = viewexpr_parse("b | upper", 9);
    TEST_ASSERT_NOT_NULL(node, "Value modifiers are allowed by viewexpr_parse");
    viewexpr_node_free(node);
}

TEST(test_viewexpr_modifier_root_kind) {
    TEST_CASE("Modifier node structure");

    const char* expression = "b | upper | raw";
    viewexpr_node_t* root = viewexpr_parse_output(expression, strlen(expression));
    TEST_REQUIRE_NOT_NULL(root, "Expression should parse");

    TEST_ASSERT(root->type == VIEWEXPR_NODE_MODIFIER, "Root is a modifier node");
    TEST_ASSERT(root->modifier != NULL && root->modifier->kind == VIEWMOD_RAW, "Root modifier is raw");
    TEST_ASSERT(root->left != NULL && root->left->modifier == viewmodifier_find("upper", 5), "Operand is the upper node");

    viewexpr_node_free(root);
}

TEST(test_viewexpr_modifier_without_scope) {
    TEST_CASE("Modifiers evaluated without a scope");

    viewexpr_node_t* upper = viewexpr_parse_output("'a' | upper", 11);
    TEST_REQUIRE_NOT_NULL(upper, "Expression should parse");
    const viewexpr_value_t upper_value = viewexpr_eval(upper, NULL);
    TEST_ASSERT(upper_value.type == VIEWEXPR_NULL, "A new string needs an arena");
    viewexpr_node_free(upper);

    viewexpr_node_t* fallback = viewexpr_parse_output("null | default(1)", 17);
    TEST_REQUIRE_NOT_NULL(fallback, "Expression should parse");
    const viewexpr_value_t fallback_value = viewexpr_eval(fallback, NULL);
    TEST_ASSERT(fallback_value.type == VIEWEXPR_NUMBER && fallback_value.number == 1, "default needs no arena");
    viewexpr_node_free(fallback);
}

/* "a" followed by `count` copies of `link`. Free the result. */
static char* vx_chain(const char* link, size_t count) {
    const size_t link_size = strlen(link);
    char* text = malloc(1 + link_size * count + 1);
    if (text == NULL) return NULL;

    char* p = text;
    *p++ = 'a';
    for (size_t i = 0; i < count; i++) {
        memcpy(p, link, link_size);
        p += link_size;
    }
    *p = 0;

    return text;
}

TEST(test_viewexpr_long_chains_are_refused) {
    TEST_CASE("Expressions with too many nodes are a parse error, not a stack overflow");

    const char* links[] = { " | lower", " + a", " || a" };
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
        char* chain = vx_chain(links[i], 20000);
        TEST_REQUIRE_NOT_NULL(chain, "Allocation should succeed");

        viewexpr_node_t* node = viewexpr_parse_output(chain, strlen(chain));
        TEST_ASSERT_NULL(node, links[i]);
        viewexpr_node_free(node);
        free(chain);
    }

    char* fits = vx_chain(" | lower", 300);
    TEST_REQUIRE_NOT_NULL(fits, "Allocation should succeed");
    viewexpr_node_t* node = viewexpr_parse_output(fits, strlen(fits));
    TEST_ASSERT_NOT_NULL(node, "300 links still parse");
    viewexpr_node_free(node);
    free(fits);
}

TEST(test_viewexpr_path_after_group_and_modifier) {
    TEST_CASE("Field and index access after parentheses and after a modifier");

    json_doc_t* doc = json_parse("{\"users\":[{\"name\":\"Ann\"},{\"name\":\"Bob\"}],\"obj\":{\"k\":[\"x\",\"y\"]},\"s\":\"str\"}");
    TEST_REQUIRE_NOT_NULL(doc, "Document should be parsed");

    TEST_ASSERT_STR_EQUAL("Ann", vx_text("(users | first).name", doc), "Field of a grouped modifier result");
    TEST_ASSERT_STR_EQUAL("Ann", vx_text("users | first.name", doc), "Field right after a modifier");
    TEST_ASSERT_STR_EQUAL("Bob", vx_text("users | last().name", doc), "Field after a modifier call");
    TEST_ASSERT_STR_EQUAL("Bob", vx_text("(users | last)['name']", doc), "String index after parentheses");
    TEST_ASSERT_STR_EQUAL("Bob", vx_text("(users)[1].name", doc), "Number index after parentheses");
    TEST_ASSERT_STR_EQUAL("y", vx_text("(obj).k[1]", doc), "Several segments after parentheses");
    TEST_ASSERT_STR_EQUAL("x", vx_text("obj | default(1).k[0]", doc), "Path after a modifier with arguments");
    TEST_ASSERT_STR_EQUAL("ANN", vx_text("(users | first).name | upper", doc), "Modifier after the path");
    TEST_ASSERT_STR_EQUAL("<null>", vx_text("(s).x", doc), "Field of a string is null");
    TEST_ASSERT_STR_EQUAL("<null>", vx_text("('a')[0]", doc), "Index of a literal is null");
    TEST_ASSERT_STR_EQUAL("<null>", vx_text("(users | first).missing", doc), "Missing field is null");

    TEST_ASSERT_STR_EQUAL("<parse-error>", vx_text("(users | first).", doc), "Field name expected after '.'");
    TEST_ASSERT_STR_EQUAL("<parse-error>", vx_text("(users)[", doc), "Unclosed index");
    TEST_ASSERT_STR_EQUAL("<parse-error>", vx_text("s | raw.x", doc), "raw under a path is not the root");
    TEST_ASSERT_STR_EQUAL("<parse-error>", vx_text("(s | raw).x", doc), "raw in parentheses under a path is not the root");

    json_free(doc);
}

TEST(test_viewexpr_strings_with_nul) {
    TEST_CASE("Comparisons, truthiness and lookups use the string length");

    json_doc_t* doc = json_parse("{\"s\":\"a\\u0000b\",\"t\":\"a\",\"z\":\"\\u0000\",\"k\":{\"a\\u0000b\":\"nul\",\"a\":\"plain\"}}");
    TEST_REQUIRE_NOT_NULL(doc, "Document should be parsed");

    TEST_ASSERT_STR_EQUAL("a\\0b", vx_text("s", doc), "The whole value is kept");
    TEST_ASSERT_STR_EQUAL("false", vx_text("s == t", doc), "a\\0b is not a");
    TEST_ASSERT_STR_EQUAL("true", vx_text("s != t", doc), "a\\0b differs from a");
    TEST_ASSERT_STR_EQUAL("true", vx_text("s > t", doc), "The longer string with the same prefix is greater");
    TEST_ASSERT_STR_EQUAL("true", vx_text("z && true", doc), "A NUL string is truthy");
    TEST_ASSERT_STR_EQUAL("nul", vx_text("k[s]", doc), "Key lookup by a string with NUL");
    TEST_ASSERT_STR_EQUAL("plain", vx_text("k[t]", doc), "Key lookup without NUL");
    TEST_ASSERT_STR_EQUAL("3", vx_text("s | length", doc), "length of the whole value");

    json_free(doc);
}

#include "framework.h"
#include "viewexpr.h"

#include <math.h>
#include <string.h>

// ============================================================================
// Helpers: parse + eval with a fixed scope
// ============================================================================

static viewexpr_value_t vx_scope_resolve(const viewexpr_scope_t* scope, const char* name) {
    json_doc_t* doc = scope->data;
    viewexpr_value_t value = { VIEWEXPR_NULL, 0, 0, NULL, NULL };

    const json_token_t* root = doc != NULL ? json_root(doc) : NULL;
    if (root == NULL || root->type != JSON_OBJECT) return value;

    return viewexpr_value_from_token(json_object_get(root, name));
}

/* Parses and evaluates the expression against a JSON object; -1 on parse
 * error, otherwise 0/1 truthiness of the result. */
static int vx_truth(const char* expression, json_doc_t* doc) {
    viewexpr_node_t* node = viewexpr_parse(expression, strlen(expression));
    if (node == NULL) return -1;

    const viewexpr_scope_t scope = { vx_scope_resolve, doc };
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

    const viewexpr_scope_t scope = { vx_scope_resolve, doc };
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

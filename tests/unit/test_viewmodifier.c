#include "framework.h"
#include "viewmodifier.h"
#include "arena.h"
#include "json.h"

#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================================================
// Helpers: apply one modifier to a value and render the result as text
// ============================================================================

static char vm_result[4096];

/* Writes a modifier result into vm_result: strings as is, numbers via
 * viewexpr_number_format, bools "true"/"false", containers "<token>",
 * null "<null>". */
static void vm_format(const viewexpr_value_t* value) {
    switch (value->type)
    {
    case VIEWEXPR_STRING:
    {
        if (value->string == NULL) {
            snprintf(vm_result, sizeof(vm_result), "<null-string>");
            break;
        }

        // NUL bytes inside the value show as the two characters "\0"
        size_t out = 0;
        for (size_t i = 0; i < value->length && out + 3 < sizeof(vm_result); i++) {
            if (value->string[i] == 0) {
                vm_result[out++] = '\\';
                vm_result[out++] = '0';
            }
            else
                vm_result[out++] = value->string[i];
        }
        vm_result[out] = 0;
        break;
    }
    case VIEWEXPR_NUMBER:
        if (viewexpr_number_format(value->number, vm_result, sizeof(vm_result)) == 0)
            snprintf(vm_result, sizeof(vm_result), "<bad-number>");
        break;
    case VIEWEXPR_BOOL:
        snprintf(vm_result, sizeof(vm_result), "%s", value->boolean ? "true" : "false");
        break;
    case VIEWEXPR_TOKEN:
        snprintf(vm_result, sizeof(vm_result), "<token>");
        break;
    default:
        snprintf(vm_result, sizeof(vm_result), "<null>");
        break;
    }
}

/* Applies modifier `name` to `input` with arguments from the JSON array
 * `args_json` ("[]" for none). `use_arena` = 0 passes arena NULL. Returns
 * "<missing>" when the registry has no such modifier, "<bad-json>" when the
 * arguments do not parse. The returned pointer is valid until the next call. */
static const char* vm_apply(const char* name, const viewexpr_value_t* input, const char* args_json, int use_arena) {
    const viewmodifier_t* modifier = viewmodifier_find(name, strlen(name));
    if (modifier == NULL || modifier->apply == NULL) {
        snprintf(vm_result, sizeof(vm_result), "<missing>");
        return vm_result;
    }

    json_doc_t* doc = json_parse(args_json);
    const json_token_t* array = doc != NULL ? json_root(doc) : NULL;
    if (array == NULL || array->type != JSON_ARRAY || json_array_size(array) > VIEWMODIFIER_MAX_ARGS) {
        if (doc != NULL) json_free(doc);
        snprintf(vm_result, sizeof(vm_result), "<bad-json>");
        return vm_result;
    }

    viewexpr_value_t args[VIEWMODIFIER_MAX_ARGS];
    const size_t argc = (size_t)json_array_size(array);
    for (size_t i = 0; i < argc; i++)
        args[i] = viewexpr_value_from_token(json_array_get(array, (int)i));

    arena_t arena;
    arena_init(&arena);

    const viewexpr_value_t result = modifier->apply(use_arena ? &arena : NULL, input, args, argc);
    vm_format(&result);

    arena_free(&arena);
    json_free(doc);

    return vm_result;
}

/* Applies modifier `name` to the value `input_json` with arguments from the
 * JSON array `args_json` ("[]" for none). Returns the result as text (see
 * vm_format). `use_arena` = 0 passes arena NULL. The returned pointer is
 * valid until the next call. */
static const char* vm_call(const char* name, const char* input_json, const char* args_json, int use_arena) {
    char text[1024];
    snprintf(text, sizeof(text), "{\"v\":%s}", input_json);

    json_doc_t* doc = json_parse(text);
    if (doc == NULL) {
        snprintf(vm_result, sizeof(vm_result), "<bad-json>");
        return vm_result;
    }

    const viewexpr_value_t input = viewexpr_value_from_token(json_object_get(json_root(doc), "v"));

    // the input borrows the document's strings: apply before freeing it
    vm_apply(name, &input, args_json, use_arena);

    json_free(doc);

    return vm_result;
}

#define vm(name, input, args) vm_call(name, input, args, 1)

/* A string value built by hand, for bytes json_parse would refuse. */
static viewexpr_value_t vm_string(const char* string) {
    viewexpr_value_t value = { VIEWEXPR_STRING, 0, 0, string, NULL, strlen(string) };
    return value;
}

// ============================================================================
// Registry
// ============================================================================

TEST(test_viewmodifier_find) {
    TEST_CASE("Modifier registry lookup");

    const viewmodifier_t* upper = viewmodifier_find("upper", 5);
    TEST_REQUIRE_NOT_NULL(upper, "upper should be registered");
    TEST_ASSERT(upper->kind == VIEWMOD_VALUE, "upper is a value modifier");
    TEST_ASSERT(upper->min_args == 0 && upper->max_args == 0, "upper takes no arguments");
    TEST_ASSERT(upper->apply != NULL, "upper has apply");

    const viewmodifier_t* raw = viewmodifier_find("raw", 3);
    TEST_REQUIRE_NOT_NULL(raw, "raw should be registered");
    TEST_ASSERT(raw->kind == VIEWMOD_RAW, "raw is a raw modifier");
    TEST_ASSERT(raw->apply == NULL && raw->output == NULL, "raw has neither apply nor output");

    const viewmodifier_t* truncate = viewmodifier_find("truncate", 8);
    TEST_REQUIRE_NOT_NULL(truncate, "truncate should be registered");
    TEST_ASSERT(truncate->min_args == 1 && truncate->max_args == 2, "truncate takes 1-2 arguments");

    TEST_ASSERT_NULL(viewmodifier_find("nope", 4), "Unknown name is not found");
    TEST_ASSERT(viewmodifier_find("upperx", 5) == upper, "Only `length` bytes of the name are compared");
    TEST_ASSERT_NULL(viewmodifier_find("uppe", 4), "A prefix of a name is not a match");
}

// ============================================================================
// String modifiers
// ============================================================================

TEST(test_viewmodifier_upper_lower) {
    TEST_CASE("upper / lower");

    TEST_ASSERT_STR_EQUAL("ПРИВЕТ, WORLD", vm("upper", "\"привет, World\"", "[]"), "upper handles Cyrillic");
    TEST_ASSERT_STR_EQUAL("привет", vm("lower", "\"ПРИВЕТ\"", "[]"), "lower handles Cyrillic");
    TEST_ASSERT_STR_EQUAL("42", vm("upper", "42", "[]"), "Number is converted to text");
    TEST_ASSERT_STR_EQUAL("TRUE", vm("upper", "true", "[]"), "Bool is converted to text");
    TEST_ASSERT_STR_EQUAL("<null>", vm("upper", "null", "[]"), "null stays null");
    TEST_ASSERT_STR_EQUAL("<null>", vm("upper", "[1]", "[]"), "Array gives null");

    // libunistring replaces a broken byte with U+FFFD instead of refusing:
    // the text is kept, the bad byte becomes a visible replacement character
    const viewexpr_value_t broken = vm_string("ab\xff" "c");
    TEST_ASSERT_STR_EQUAL("AB\xef\xbf\xbd" "C", vm_apply("upper", &broken, "[]", 1), "Broken UTF-8 is kept by upper");
    TEST_ASSERT_STR_EQUAL("ab\xef\xbf\xbd" "c", vm_apply("lower", &broken, "[]", 1), "Broken UTF-8 is kept by lower");
}

TEST(test_viewmodifier_capitalize) {
    TEST_CASE("capitalize");

    TEST_ASSERT_STR_EQUAL("МАКС", vm("capitalize", "\"мАКС\"", "[]"), "First letter goes up, the rest is kept");
    TEST_ASSERT_STR_EQUAL("IPhone", vm("capitalize", "\"iPhone\"", "[]"), "The rest is not lowered");
    TEST_ASSERT_STR_EQUAL("", vm("capitalize", "\"\"", "[]"), "Empty string stays empty");

    const viewexpr_value_t broken = vm_string("\xff");
    TEST_ASSERT_STR_EQUAL("\xff", vm_apply("capitalize", &broken, "[]", 1), "Broken first byte is returned unchanged");
}

TEST(test_viewmodifier_trim) {
    TEST_CASE("trim");

    TEST_ASSERT_STR_EQUAL("a b", vm("trim", "\"  a b \\n\"", "[]"), "Spaces and newline are trimmed");
    TEST_ASSERT_STR_EQUAL("x", vm("trim", "\"\\u00a0x\\u00a0\"", "[]"), "NBSP is trimmed");
    TEST_ASSERT_STR_EQUAL("", vm("trim", "\"   \"", "[]"), "Whitespace-only string becomes empty");
}

TEST(test_viewmodifier_truncate) {
    TEST_CASE("truncate");

    TEST_ASSERT_STR_EQUAL("Привет…", vm("truncate", "\"Привет мир\"", "[6]"), "Cut by characters with default suffix");
    TEST_ASSERT_STR_EQUAL("Привет", vm("truncate", "\"Привет\"", "[6]"), "No suffix when the string fits");
    TEST_ASSERT_STR_EQUAL("…", vm("truncate", "\"abc\"", "[0]"), "Zero length leaves only the suffix");
    TEST_ASSERT_STR_EQUAL("abc...", vm("truncate", "\"abcdef\"", "[3, \"...\"]"), "Custom suffix");
    TEST_ASSERT_STR_EQUAL("<null>", vm("truncate", "\"abc\"", "[-1]"), "Negative length gives null");
    TEST_ASSERT_STR_EQUAL("<null>", vm("truncate", "\"abc\"", "[1.5]"), "Fractional length gives null");
    TEST_ASSERT_STR_EQUAL("<null>", vm("truncate", "\"abc\"", "[\"x\"]"), "String length gives null");
    TEST_ASSERT_STR_EQUAL("12…", vm("truncate", "12345", "[2]"), "Number is converted to text");
}

TEST(test_viewmodifier_replace) {
    TEST_CASE("replace");

    TEST_ASSERT_STR_EQUAL("a+b+c", vm("replace", "\"a-b-c\"", "[\"-\", \"+\"]"), "All occurrences are replaced");
    TEST_ASSERT_STR_EQUAL("ba", vm("replace", "\"aaa\"", "[\"aa\", \"b\"]"), "Left to right, without overlap");
    TEST_ASSERT_STR_EQUAL("abc", vm("replace", "\"abc\"", "[\"\", \"x\"]"), "Empty `from` leaves the input");
    TEST_ASSERT_STR_EQUAL("a2", vm("replace", "\"a1\"", "[1, 2]"), "Arguments are converted to text");
    TEST_ASSERT_STR_EQUAL("<null>", vm("replace", "\"abc\"", "[null, \"x\"]"), "null argument gives null");
}

TEST(test_viewmodifier_default) {
    TEST_CASE("default");

    TEST_ASSERT_STR_EQUAL("—", vm("default", "null", "[\"—\"]"), "null is replaced");
    TEST_ASSERT_STR_EQUAL("x", vm("default", "\"\"", "[\"x\"]"), "Empty string is replaced");
    TEST_ASSERT_STR_EQUAL("0", vm("default", "0", "[5]"), "Zero is kept");
    TEST_ASSERT_STR_EQUAL("false", vm("default", "false", "[5]"), "false is kept");
    TEST_ASSERT_STR_EQUAL("a", vm("default", "\"a\"", "[\"b\"]"), "Non-empty string is kept");
    TEST_ASSERT_STR_EQUAL("<token>", vm("default", "null", "[[1,2]]"), "Default may be a container");
}

TEST(test_viewmodifier_null_arena) {
    TEST_CASE("Modifiers without an arena");

    TEST_ASSERT_STR_EQUAL("<null>", vm_call("upper", "\"a\"", "[]", 0), "A new string needs the arena");
    TEST_ASSERT_STR_EQUAL("x", vm_call("default", "null", "[\"x\"]", 0), "default allocates nothing");
}

// ============================================================================
// Number modifiers
// ============================================================================

TEST(test_viewmodifier_abs_round) {
    TEST_CASE("abs / round");

    TEST_ASSERT_STR_EQUAL("5.5", vm("abs", "-5.5", "[]"), "abs of a negative number");
    TEST_ASSERT_STR_EQUAL("<null>", vm("abs", "\"-5\"", "[]"), "abs of a string gives null");
    TEST_ASSERT_STR_EQUAL("3", vm("round", "2.5", "[]"), "Half rounds away from zero");
    TEST_ASSERT_STR_EQUAL("-3", vm("round", "-2.5", "[]"), "Negative half rounds away from zero");
    TEST_ASSERT_STR_EQUAL("9.46", vm("round", "9.456", "[2]"), "Round to two places");
    TEST_ASSERT_STR_EQUAL("9.5", vm("round", "9.5", "[2]"), "Result is a number without trailing zeros");
    TEST_ASSERT_STR_EQUAL("<null>", vm("round", "1", "[16]"), "More than 15 places gives null");
    TEST_ASSERT_STR_EQUAL("<null>", vm("round", "1", "[-1]"), "Negative places give null");
    TEST_ASSERT_STR_EQUAL("2", vm_call("round", "2.4", "[]", 0), "round works without an arena");
}

TEST(test_viewmodifier_number) {
    TEST_CASE("number");

    TEST_ASSERT_STR_EQUAL("50 000,00", vm("number", "50000", "[2, \",\", \" \"]"), "Decimals and both separators");
    TEST_ASSERT_STR_EQUAL("1234567.9", vm("number", "1234567.891", "[1]"), "No thousands separator by default");
    TEST_ASSERT_STR_EQUAL("-1,235", vm("number", "-1234.5", "[0, \".\", \",\"]"), "Half rounds away from zero");
    TEST_ASSERT_STR_EQUAL("0", vm("number", "-0.4", "[]"), "Negative zero prints as 0");
    TEST_ASSERT_STR_EQUAL("1\xc2\xa0" "000.00", vm("number", "999.999", "[2, \".\", \"\\u00a0\"]"), "UTF-8 separator");
    TEST_ASSERT_STR_EQUAL("<null>", vm("number", "\"50000.00\"", "[2]"), "Numeric string gives null");

    const viewmodifier_t* number = viewmodifier_find("number", 6);
    TEST_REQUIRE_NOT_NULL(number, "number should be registered");

    arena_t arena;
    arena_init(&arena);
    const viewexpr_value_t input = { VIEWEXPR_NUMBER, 0, 5, NULL, NULL, 0 };
    const viewexpr_value_t result = number->apply(&arena, &input, NULL, 0);
    TEST_ASSERT(result.type == VIEWEXPR_STRING, "number returns a string");
    arena_free(&arena);
}

// ============================================================================
// Collection modifiers
// ============================================================================

TEST(test_viewmodifier_length) {
    TEST_CASE("length");

    TEST_ASSERT_STR_EQUAL("6", vm("length", "\"Привет\"", "[]"), "String length in characters");
    TEST_ASSERT_STR_EQUAL("3", vm("length", "[1,2,3]", "[]"), "Array length");
    TEST_ASSERT_STR_EQUAL("1", vm("length", "{\"a\":1}", "[]"), "Object length");
    TEST_ASSERT_STR_EQUAL("5", vm("length", "12345", "[]"), "Number text length");
    TEST_ASSERT_STR_EQUAL("4", vm("length", "true", "[]"), "Bool text length");
    TEST_ASSERT_STR_EQUAL("0", vm("length", "null", "[]"), "null has length 0");

    const viewexpr_value_t broken = vm_string("a\xff");
    TEST_ASSERT_STR_EQUAL("2", vm_apply("length", &broken, "[]", 1), "Broken byte counts as one character");
    TEST_ASSERT_STR_EQUAL("1", vm_call("length", "[1]", "[]", 0), "length works without an arena");
}

TEST(test_viewmodifier_first_last) {
    TEST_CASE("first / last");

    TEST_ASSERT_STR_EQUAL("1", vm("first", "[1,2,3]", "[]"), "First array element");
    TEST_ASSERT_STR_EQUAL("3", vm("last", "[1,2,3]", "[]"), "Last array element");
    TEST_ASSERT_STR_EQUAL("<null>", vm("first", "[]", "[]"), "Empty array gives null");
    TEST_ASSERT_STR_EQUAL("<null>", vm("last", "[]", "[]"), "Empty array gives null");
    TEST_ASSERT_STR_EQUAL("x", vm("first", "{\"a\":\"x\",\"b\":\"y\"}", "[]"), "First object value");
    TEST_ASSERT_STR_EQUAL("y", vm("last", "{\"a\":\"x\",\"b\":\"y\"}", "[]"), "Last object value");
    TEST_ASSERT_STR_EQUAL("<token>", vm("first", "[[1],2]", "[]"), "Nested container is returned");
    TEST_ASSERT_STR_EQUAL("П", vm("first", "\"Привет\"", "[]"), "First character");
    TEST_ASSERT_STR_EQUAL("т", vm("last", "\"Привет\"", "[]"), "Last character");
    TEST_ASSERT_STR_EQUAL("<null>", vm("first", "\"\"", "[]"), "Empty string gives null");
    TEST_ASSERT_STR_EQUAL("<null>", vm("first", "42", "[]"), "A number is not a string");
    TEST_ASSERT_STR_EQUAL("<null>", vm("last", "42", "[]"), "A number is not a string");
    TEST_ASSERT_STR_EQUAL("<null>", vm("first", "false", "[]"), "A bool is not a string");
    TEST_ASSERT_STR_EQUAL("<null>", vm("last", "true", "[]"), "A bool is not a string");
    TEST_ASSERT_STR_EQUAL("<null>", vm("first", "null", "[]"), "Null gives null");
    TEST_ASSERT_STR_EQUAL("7", vm_call("first", "[7]", "[]", 0), "Array element needs no arena");
    TEST_ASSERT_STR_EQUAL("<null>", vm_call("first", "\"ab\"", "[]", 0), "A character needs the arena");
}

TEST(test_viewmodifier_join) {
    TEST_CASE("join");

    TEST_ASSERT_STR_EQUAL("a, 1, true", vm("join", "[\"a\",1,true]", "[\", \"]"), "Scalars are joined as text");
    TEST_ASSERT_STR_EQUAL("a---b", vm("join", "[\"a\",null,[1],\"b\"]", "[\"-\"]"), "null and containers are empty pieces");
    TEST_ASSERT_STR_EQUAL("12", vm("join", "{\"x\":1,\"y\":2}", "[]"), "Object values without separator");
    TEST_ASSERT_STR_EQUAL("abc", vm("join", "\"abc\"", "[\",\"]"), "Scalar input gives its text");
    TEST_ASSERT_STR_EQUAL("", vm("join", "[]", "[]"), "Empty array gives empty string");
}

// ============================================================================
// Output modifiers
// ============================================================================

TEST(test_viewmodifier_url) {
    TEST_CASE("url");

    TEST_ASSERT_STR_EQUAL("a%20b%26c%2F%D0%B4", vm("url", "\"a b&c/д\"", "[]"), "Space is %20, UTF-8 bytes in upper hex");
    TEST_ASSERT_STR_EQUAL("AZaz09-_.~", vm("url", "\"AZaz09-_.~\"", "[]"), "Unreserved characters stay");
    TEST_ASSERT_STR_EQUAL("42", vm("url", "42", "[]"), "Number is converted to text");
    TEST_ASSERT_STR_EQUAL("<null>", vm("url", "null", "[]"), "null stays null");
}

/* A JSON text of `depth` nested arrays around 1: [[1]] for 2. */
static const char* vm_nested(int depth) {
    static char text[256];
    int pos = 0;
    for (int i = 0; i < depth; i++) text[pos++] = '[';
    text[pos++] = '1';
    for (int i = 0; i < depth; i++) text[pos++] = ']';
    text[pos] = 0;
    return text;
}

TEST(test_viewmodifier_json) {
    TEST_CASE("json");

    TEST_ASSERT_STR_EQUAL("\"\\u003c/script\\u003e\"", vm("json", "\"</script>\"", "[]"), "Angle brackets are \\u-escaped");
    TEST_ASSERT_STR_EQUAL("\"a\\u0026b\\u0027c\"", vm("json", "\"a&b'c\"", "[]"), "Ampersand and apostrophe are \\u-escaped");
    TEST_ASSERT_STR_EQUAL("\"\\u2028\\u2029\"", vm("json", "\"\\u2028\\u2029\"", "[]"), "Line and paragraph separators are \\u-escaped");
    TEST_ASSERT_STR_EQUAL("\"Привет\"", vm("json", "\"Привет\"", "[]"), "Cyrillic stays UTF-8");
    TEST_ASSERT_STR_EQUAL("\"q\\\"\\\\\\n\\u0001\"", vm("json", "\"q\\\"\\\\\\n\\u0001\"", "[]"), "Standard JSON escapes");
    TEST_ASSERT_STR_EQUAL("null", vm("json", "null", "[]"), "null");
    TEST_ASSERT_STR_EQUAL("true", vm("json", "true", "[]"), "bool");
    TEST_ASSERT_STR_EQUAL("1.5", vm("json", "1.5", "[]"), "number");
    TEST_ASSERT_STR_EQUAL("{\"a\":[1,{\"b\":null}]}", vm("json", "{\"a\":[1,{\"b\":null}]}", "[]"), "Nested containers");
    TEST_ASSERT_STR_EQUAL("{\"\\u003ck\":1}", vm("json", "{\"<k\":1}", "[]"), "Object keys are escaped too");
    TEST_ASSERT_STR_EQUAL("[]", vm("json", "[]", "[]"), "Empty array");

    char expected[256];
    snprintf(expected, sizeof(expected), "%s", vm_nested(32));
    TEST_ASSERT_STR_EQUAL(expected, vm("json", vm_nested(32), "[]"), "32 levels are serialized");
    TEST_ASSERT_STR_EQUAL("<null>", vm("json", vm_nested(33), "[]"), "33 levels give null");
}

/* Writes `input` through a SAFE modifier's output() in `mode` and returns
 * the bytes written. Valid until the next call. */
static const char* vm_output(const char* name, const viewexpr_value_t* input, view_escape_e mode) {
    const viewmodifier_t* modifier = viewmodifier_find(name, strlen(name));
    if (modifier == NULL || modifier->output == NULL) {
        snprintf(vm_result, sizeof(vm_result), "<missing>");
        return vm_result;
    }

    bufferdata_t buf;
    bufferdata_init(&buf);
    modifier->output(&buf, input, mode);
    bufferdata_complete(&buf);

    const size_t size = bufferdata_writed(&buf);
    const size_t copy = size < sizeof(vm_result) - 1 ? size : sizeof(vm_result) - 1;
    memcpy(vm_result, bufferdata_get(&buf), copy);
    vm_result[copy] = 0;

    bufferdata_clear(&buf);

    return vm_result;
}

TEST(test_viewmodifier_nl2br_output) {
    TEST_CASE("nl2br");

    const viewmodifier_t* nl2br = viewmodifier_find("nl2br", 5);
    TEST_REQUIRE_NOT_NULL(nl2br, "nl2br should be registered");
    TEST_ASSERT(nl2br->kind == VIEWMOD_SAFE && nl2br->apply == NULL, "nl2br is a safe modifier");

    const viewexpr_value_t lines = vm_string("a<b>\r\nc\nd\re");
    TEST_ASSERT_STR_EQUAL("a&lt;b&gt;<br>\nc<br>\nd<br>\ne", vm_output("nl2br", &lines, VIEW_ESCAPE), "Escaped, every break is <br>");

    const viewexpr_value_t quotes = vm_string("\"'&");
    TEST_ASSERT_STR_EQUAL("&quot;&#39;&amp;", vm_output("nl2br", &quotes, VIEW_ESCAPE), "Quotes and ampersand are escaped");

    const viewexpr_value_t raw = vm_string("a<b>\nc");
    TEST_ASSERT_STR_EQUAL("a<b>\nc", vm_output("nl2br", &raw, VIEW_RAW), "VIEW_RAW writes the text as is");

    const viewexpr_value_t number = { VIEWEXPR_NUMBER, 0, 5, NULL, NULL, 0 };
    TEST_ASSERT_STR_EQUAL("5", vm_output("nl2br", &number, VIEW_ESCAPE), "Number is converted to text");

    const viewexpr_value_t null = { VIEWEXPR_NULL, 0, 0, NULL, NULL, 0 };
    TEST_ASSERT_STR_EQUAL("", vm_output("nl2br", &null, VIEW_ESCAPE), "null writes nothing");
}

TEST(test_viewmodifier_replace_long_input_is_linear) {
    TEST_CASE("replace over a long string of matches");

    /* 256 KiB of matches: a search that rescans the rest of the string per
     * match (as strstr does under ASan's interceptor) takes tens of seconds. */
    const size_t size = 256 * 1024;
    char* text = malloc(size + 1);
    TEST_REQUIRE_NOT_NULL(text, "Allocation should succeed");
    memset(text, 'A', size);
    text[size] = 0;

    const viewexpr_value_t input = vm_string(text);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    const viewmodifier_t* replace = viewmodifier_find("replace", 7);
    TEST_REQUIRE_NOT_NULL(replace, "replace should be registered");

    arena_t arena;
    arena_init(&arena);
    const viewexpr_value_t args[2] = { vm_string("A"), vm_string("b") };
    const viewexpr_value_t result = replace->apply(&arena, &input, args, 2);
    clock_gettime(CLOCK_MONOTONIC, &end);

    const double seconds = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;

    TEST_ASSERT(result.type == VIEWEXPR_STRING && strlen(result.string) == size, "Every character is replaced");
    TEST_ASSERT(result.type == VIEWEXPR_STRING && result.string[0] == 'b' && result.string[size - 1] == 'b', "Replacement is written");
    TEST_ASSERT(seconds < 2.0, "replace runs in linear time");

    arena_free(&arena);
    free(text);
}

TEST(test_viewmodifier_replace_long_near_match_is_linear) {
    TEST_CASE("replace with a long pattern that almost matches everywhere");

    /* 1 MiB of 'a' and a 512 KiB pattern of 'a' ending in 'b': comparing the
     * pattern at every position is quadratic and takes seconds. */
    const viewmodifier_t* replace = viewmodifier_find("replace", 7);
    TEST_REQUIRE_NOT_NULL(replace, "replace should be registered");

    const size_t size = 1024 * 1024;
    const size_t from_size = size / 2;
    char* text = malloc(size + 1);
    char* from = malloc(from_size + 1);
    if (text == NULL || from == NULL) {
        free(text);
        free(from);
        TEST_ASSERT(0, "Allocation should succeed");
        return;
    }
    memset(text, 'a', size);
    text[size] = 0;
    memset(from, 'a', from_size - 1);
    from[from_size - 1] = 'b';
    from[from_size] = 0;

    const viewexpr_value_t input = vm_string(text);
    const viewexpr_value_t args[2] = { vm_string(from), vm_string("x") };

    arena_t arena;
    arena_init(&arena);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    const viewexpr_value_t result = replace->apply(&arena, &input, args, 2);
    clock_gettime(CLOCK_MONOTONIC, &end);

    const double seconds = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;

    TEST_ASSERT(result.type == VIEWEXPR_STRING && result.length == size && memcmp(result.string, text, size) == 0, "No match leaves the text");
    TEST_ASSERT(seconds < 2.0, "replace runs in linear time");

    // a match at the very end is still found
    text[size - 1] = 'b';
    const viewexpr_value_t found = replace->apply(&arena, &input, args, 2);
    TEST_ASSERT(found.type == VIEWEXPR_STRING && found.length == size - from_size + 1 && found.string[found.length - 1] == 'x', "Match at the end is replaced");

    arena_free(&arena);
    free(from);
    free(text);
}

TEST(test_viewmodifier_infinity) {
    TEST_CASE("Non-finite numbers");

    // arithmetic overflow produces inf; JSON documents cannot carry one
    const viewexpr_value_t inf = { VIEWEXPR_NUMBER, 0, INFINITY, NULL, NULL, 0 };

    TEST_ASSERT_STR_EQUAL("null", vm_apply("json", &inf, "[]", 1), "json writes null");
    TEST_ASSERT_STR_EQUAL("<null>", vm_apply("number", &inf, "[2]", 1), "number gives null");
    TEST_ASSERT_STR_EQUAL("<null>", vm_apply("round", &inf, "[]", 1), "round gives null");
    TEST_ASSERT_STR_EQUAL("0", vm_apply("length", &inf, "[]", 1), "inf has no text, length is 0");
    TEST_ASSERT_STR_EQUAL("<null>", vm_apply("upper", &inf, "[]", 1), "inf has no text form");
    TEST_ASSERT_STR_EQUAL("<bad-number>", vm_apply("abs", &inf, "[]", 1), "abs keeps inf, which prints as nothing");
}

TEST(test_viewmodifier_rounding_keeps_precision) {
    TEST_CASE("number and round do not scale past long double precision");

    TEST_ASSERT_STR_EQUAL("1000000001.000000000000000", vm("number", "1000000001", "[15]"), "Integer with 15 places");
    TEST_ASSERT_STR_EQUAL("1000000001", vm("round", "1000000001", "[15]"), "round keeps an exact integer");
    TEST_ASSERT_STR_EQUAL("123456789012.123", vm("number", "123456789012.1234", "[3]"), "Large value, few places");

    const viewmodifier_t* round = viewmodifier_find("round", 5);
    TEST_REQUIRE_NOT_NULL(round, "round should be registered");
    const viewexpr_value_t big = { VIEWEXPR_NUMBER, 0, 1000000001.0L, NULL, NULL, 0 };
    const viewexpr_value_t places = { VIEWEXPR_NUMBER, 0, 15, NULL, NULL, 0 };
    const viewexpr_value_t rounded = round->apply(NULL, &big, &places, 1);
    TEST_ASSERT(rounded.type == VIEWEXPR_NUMBER && rounded.number == 1000000001.0L, "round(15) value equals the input exactly");

    // 1e18 + 0.25 is exact in long double: a true tie at one place
    const viewexpr_value_t tie = { VIEWEXPR_NUMBER, 0, 1000000000000000000.0L + 0.25L, NULL, NULL, 0 };
    TEST_ASSERT_STR_EQUAL("1000000000000000000.3", vm_apply("number", &tie, "[1]", 1), "A large tie rounds away from zero");
    const viewexpr_value_t negative_tie = { VIEWEXPR_NUMBER, 0, -(1000000000000000000.0L + 0.25L), NULL, NULL, 0 };
    TEST_ASSERT_STR_EQUAL("-1000000000000000000.3", vm_apply("number", &negative_tie, "[1]", 1), "A negative large tie rounds away from zero");

    TEST_ASSERT_STR_EQUAL("0.10", vm("number", "0.095", "[2]"), "Carry into the fraction");
    TEST_ASSERT_STR_EQUAL("1000", vm("number", "999.5", "[]"), "Carry adds a digit");
    TEST_ASSERT_STR_EQUAL("0.001", vm("number", "0.0005", "[3]"), "Half of the last place");
    TEST_ASSERT_STR_EQUAL("2.68", vm("number", "2.675", "[2]"), "Rounds the decimal the user wrote, not its binary approximation");
    TEST_ASSERT_STR_EQUAL("2.68", vm("round", "2.675", "[2]"), "round agrees with number");

    // places past the shortest form print the exact value, not padding zeros
    TEST_ASSERT_STR_EQUAL("1000000001.000030517578125", vm("number", "1000000001.000030517578125", "[15]"), "Exact value with 15 places");
    const viewexpr_value_t sixteenth = { VIEWEXPR_NUMBER, 0, 1000000000000000000.0L + 0.0625L, NULL, NULL, 0 };
    TEST_ASSERT_STR_EQUAL("1000000000000000000.063", vm_apply("number", &sixteenth, "[3]", 1), "Exact tie past the shortest form rounds away from zero");
    const viewexpr_value_t exact = { VIEWEXPR_NUMBER, 0, 1000000001.0L + 0.000030517578125L, NULL, NULL, 0 };
    const viewexpr_value_t exact_rounded = round->apply(NULL, &exact, &places, 1);
    TEST_ASSERT(exact_rounded.type == VIEWEXPR_NUMBER && exact_rounded.number == exact.number, "round(15) keeps an exactly representable value");
    TEST_ASSERT_STR_EQUAL("0.100000000000000", vm("number", "0.1", "[15]"), "A short value is padded, not shown with binary noise");
}

TEST(test_viewmodifier_numbers_ignore_locale) {
    TEST_CASE("number conversions do not follow the current locale");

    // parsed in the C locale: json_parse reads numbers with the current one
    json_doc_t* doc = json_parse("[1.25,2.5]");
    TEST_REQUIRE_NOT_NULL(doc, "Document should parse");
    const viewexpr_value_t array = viewexpr_value_from_token(json_root(doc));

    locale_t comma = newlocale(LC_ALL_MASK, "ru_RU.utf8", (locale_t)0);
    if (comma == (locale_t)0) {
        printf("  (skipped: ru_RU.utf8 is not installed)\n");
        json_free(doc);
        return;
    }
    const locale_t previous = uselocale(comma);

    const viewexpr_value_t value = { VIEWEXPR_NUMBER, 0, 1.25L, NULL, NULL, 0 };
    const viewexpr_value_t third = { VIEWEXPR_NUMBER, 0, 1.0L / 3.0L, NULL, NULL, 0 };
    const viewexpr_value_t large = { VIEWEXPR_NUMBER, 0, 1e300L, NULL, NULL, 0 };
    char json_value[64], json_third[64], json_large[64], json_array[64], rounded[64], formatted[64], printed[64];

    snprintf(json_value, sizeof(json_value), "%s", vm_apply("json", &value, "[]", 1));
    snprintf(json_third, sizeof(json_third), "%s", vm_apply("json", &third, "[]", 1));
    snprintf(json_large, sizeof(json_large), "%s", vm_apply("json", &large, "[]", 1));
    snprintf(json_array, sizeof(json_array), "%s", vm_apply("json", &array, "[]", 1));
    snprintf(rounded, sizeof(rounded), "%s", vm_apply("round", &value, "[2]", 1));
    snprintf(formatted, sizeof(formatted), "%s", vm_apply("number", &value, "[2]", 1));
    viewexpr_number_format(1.25L, printed, sizeof(printed));

    uselocale(previous);
    freelocale(comma);
    json_free(doc);

    TEST_ASSERT_STR_EQUAL("1.25", json_value, "json writes a decimal point");
    TEST_ASSERT(strtold(json_third, NULL) == 1.0L / 3.0L, "json of 1/3 round-trips");
    TEST_ASSERT_STR_EQUAL("1e+300", json_large, "json of a large value uses a point-free exponent");
    TEST_ASSERT_STR_EQUAL("[1.25,2.5]", json_array, "json of an array keeps its elements");
    TEST_ASSERT_STR_EQUAL("1.25", rounded, "round keeps the fraction");
    TEST_ASSERT_STR_EQUAL("1.25", formatted, "number uses its own separator");
    TEST_ASSERT_STR_EQUAL("1.25", printed, "A tag prints a decimal point");
}

TEST(test_viewmodifier_json_embedded_nul) {
    TEST_CASE("json keeps NUL bytes in strings and keys");

    TEST_ASSERT_STR_EQUAL("{\"s\":\"a\\u0000b\"}", vm("json", "{\"s\":\"a\\u0000b\"}", "[]"), "NUL inside a string value");
    TEST_ASSERT_STR_EQUAL("{\"a\\u0000b\":1}", vm("json", "{\"a\\u0000b\":1}", "[]"), "NUL inside a key");
    TEST_ASSERT_STR_EQUAL("[\"\\u0000\",\"x\"]", vm("json", "[\"\\u0000\",\"x\"]", "[]"), "String of a single NUL");
    TEST_ASSERT_STR_EQUAL("\"a\\u0000b\"", vm("json", "\"a\\u0000b\"", "[]"), "Top-level string from the document");
}

TEST(test_viewmodifier_json_number_precision) {
    TEST_CASE("json numbers read back as the same value");

    TEST_ASSERT_STR_EQUAL("[18446744073709551615]", vm("json", "[18446744073709551615]", "[]"), "2^64 - 1 is exact");
    TEST_ASSERT_STR_EQUAL("[-9223372036854775808]", vm("json", "[-9223372036854775808]", "[]"), "-2^63 is exact");
    TEST_ASSERT_STR_EQUAL("[1.234567890123456789]", vm("json", "[1.234567890123456789]", "[]"), "19 significant digits");
    TEST_ASSERT_STR_EQUAL("[0.1,1.5,-2,0]", vm("json", "[0.1,1.5,-2,-0]", "[]"), "Short values stay short, -0 is 0");
    TEST_ASSERT_STR_EQUAL("[1e+300]", vm("json", "[1e300]", "[]"), "Large values use an exponent");

    // whatever the form, the text parses back to the same long double
    const viewexpr_value_t third = { VIEWEXPR_NUMBER, 0, 1.0L / 3.0L, NULL, NULL, 0 };
    const char* text = vm_apply("json", &third, "[]", 1);
    TEST_ASSERT(strtold(text, NULL) == 1.0L / 3.0L, "1/3 round-trips");
}

// ============================================================================
// NUL bytes inside strings
// ============================================================================

TEST(test_viewmodifier_embedded_nul) {
    TEST_CASE("String modifiers keep bytes after a NUL");

    TEST_ASSERT_STR_EQUAL("A\\0B", vm("upper", "\"a\\u0000b\"", "[]"), "upper converts both sides of a NUL");
    TEST_ASSERT_STR_EQUAL("a\\0b", vm("lower", "\"A\\u0000B\"", "[]"), "lower converts both sides of a NUL");
    TEST_ASSERT_STR_EQUAL("A\\0b", vm("capitalize", "\"a\\u0000b\"", "[]"), "capitalize keeps the tail");
    TEST_ASSERT_STR_EQUAL("\\0a", vm("capitalize", "\"\\u0000a\"", "[]"), "A leading NUL is not a letter");
    TEST_ASSERT_STR_EQUAL("a\\0b", vm("trim", "\" a\\u0000b \"", "[]"), "trim keeps an inner NUL");
    TEST_ASSERT_STR_EQUAL("a\\0b", vm("truncate", "\"a\\u0000b\"", "[10]"), "truncate without a cut keeps everything");
    TEST_ASSERT_STR_EQUAL("a\\0…", vm("truncate", "\"a\\u0000b\"", "[2]"), "NUL counts as one character");
    TEST_ASSERT_STR_EQUAL("a-b", vm("replace", "\"a\\u0000b\"", "[\"\\u0000\", \"-\"]"), "NUL can be replaced");
    TEST_ASSERT_STR_EQUAL("a\\0c", vm("replace", "\"a\\u0000b\"", "[\"b\", \"c\"]"), "Replacement after a NUL");
    TEST_ASSERT_STR_EQUAL("3", vm("length", "\"a\\u0000b\"", "[]"), "length counts the NUL");
    TEST_ASSERT_STR_EQUAL("\\0", vm("first", "\"\\u0000b\"", "[]"), "first character is a NUL");
    TEST_ASSERT_STR_EQUAL("b", vm("last", "\"\\u0000b\"", "[]"), "last character after a NUL");
    TEST_ASSERT_STR_EQUAL("a\\0b,c", vm("join", "[\"a\\u0000b\",\"c\"]", "[\",\"]"), "join keeps NUL bytes");
    TEST_ASSERT_STR_EQUAL("a%00b", vm("url", "\"a\\u0000b\"", "[]"), "url encodes NUL as %00");
    TEST_ASSERT_STR_EQUAL("\\0", vm("default", "\"\\u0000\"", "[\"x\"]"), "A NUL string is not empty");
}

TEST(test_viewmodifier_chain_keeps_nul) {
    TEST_CASE("A modifier result with NUL bytes reaches json whole");

    const viewmodifier_t* upper = viewmodifier_find("upper", 5);
    const viewmodifier_t* json = viewmodifier_find("json", 4);
    TEST_REQUIRE(upper != NULL && json != NULL, "Modifiers should be registered");

    arena_t arena;
    arena_init(&arena);
    const viewexpr_value_t input = { VIEWEXPR_STRING, 0, 0, "a\0b", NULL, 3 };
    const viewexpr_value_t upper_value = upper->apply(&arena, &input, NULL, 0);
    const viewexpr_value_t json_value = json->apply(&arena, &upper_value, NULL, 0);
    TEST_ASSERT(json_value.type == VIEWEXPR_STRING, "json returns a string");
    TEST_ASSERT_STR_EQUAL("\"A\\u0000B\"", json_value.string, "upper | json keeps the NUL");
    arena_free(&arena);
}

TEST(test_viewmodifier_nl2br_nul) {
    TEST_CASE("nl2br writes NUL as U+FFFD");

    const viewexpr_value_t value = { VIEWEXPR_STRING, 0, 0, "a\0<", NULL, 3 };
    TEST_ASSERT_STR_EQUAL("a\xEF\xBF\xBD&lt;", vm_output("nl2br", &value, VIEW_ESCAPE), "Escaped with a replacement character");
    TEST_ASSERT_STR_EQUAL("a\xEF\xBF\xBD<", vm_output("nl2br", &value, VIEW_RAW), "A C string cannot carry NUL: replaced in VIEW_RAW too");
}

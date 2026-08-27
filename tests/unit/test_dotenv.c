#include "framework.h"
#include "dotenv.h"
#include <stdio.h>
#include <unistd.h>

// ============================================================================
// dotenv_load / dotenv_parse
//
// dotenv_parse modifies the buffer in place: keys and values delivered to the
// callback point into it and are only valid while it runs. Every test stores
// what it needs inside the callback and asserts afterwards.
// ============================================================================

// Collected pairs, one slot per line, "key" then "value"; quoted per pair.
#define MAX_PAIRS 32

typedef struct {
    char* key[MAX_PAIRS];
    char* value[MAX_PAIRS];
    int quoted[MAX_PAIRS];
    int count;
    int aborted_after; // -1 when the callback never stopped the parse
} collected_t;

static int collect_pair(const char* key, const char* value, int quoted, void* userdata) {
    collected_t* collected = userdata;

    if (collected->count >= MAX_PAIRS) return 0;

    collected->key[collected->count] = strdup(key);
    collected->value[collected->count] = strdup(value);
    collected->quoted[collected->count] = quoted;
    collected->count++;

    return 1;
}

static int abort_after_pair(const char* key, const char* value, int quoted, void* userdata) {
    (void)key;
    (void)value;
    (void)quoted;

    collected_t* collected = userdata;
    return ++collected->count < 2;
}

static void collect_free(collected_t* collected) {
    for (int i = 0; i < collected->count; i++) {
        free(collected->key[i]);
        free(collected->value[i]);
    }
    memset(collected, 0, sizeof *collected);
    collected->aborted_after = -1;
}

// Parses a literal. The trailing NUL is required by dotenv_parse -- it reads
// up to the end of the buffer, not to a line count.
static int parse_literal(char* data, collected_t* collected) {
    return dotenv_parse(data, NULL, collect_pair, collected);
}

TEST(test_dotenv_parse_single_pair) {
    TEST_SUITE("dotenv");

    TEST_CASE("One key=value line yields one pair");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "app_name=backend";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(1, result, "One line -> one pair");
    TEST_ASSERT_EQUAL(1, collected.count, "Callback called once");
    TEST_ASSERT_STR_EQUAL("app_name", collected.key[0], "Key");
    TEST_ASSERT_STR_EQUAL("backend", collected.value[0], "Value");
    TEST_ASSERT_EQUAL(0, collected.quoted[0], "Unquoted value");

    collect_free(&collected);
}

TEST(test_dotenv_parse_comments_and_blank_lines) {
    TEST_SUITE("dotenv");

    TEST_CASE("Comment lines and blank lines are skipped");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "# leading comment\n\napp=1\n   \n# another\n\t\nlast=2\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(2, result, "Only the two pairs are delivered");
    TEST_ASSERT_STR_EQUAL("app", collected.key[0], "First key");
    TEST_ASSERT_STR_EQUAL("last", collected.key[1], "Second key");

    collect_free(&collected);
}

TEST(test_dotenv_parse_export_prefix) {
    TEST_SUITE("dotenv");

    TEST_CASE("Optional export prefix is stripped");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "export plain=1\n  export  spaced=2\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(2, result, "Both export lines parse");
    TEST_ASSERT_STR_EQUAL("plain", collected.key[0], "export stripped");
    TEST_ASSERT_STR_EQUAL("spaced", collected.key[1], "leading spaces then export stripped");

    collect_free(&collected);
}

TEST(test_dotenv_parse_whitespace_trimming) {
    TEST_SUITE("dotenv");

    TEST_CASE("Whitespace around key and value is trimmed");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "  keyed   =   valued  \t \n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(1, result, "One pair");
    TEST_ASSERT_STR_EQUAL("keyed", collected.key[0], "Key trimmed on both sides");
    TEST_ASSERT_STR_EQUAL("valued", collected.value[0], "Value trimmed on both sides");

    collect_free(&collected);
}

TEST(test_dotenv_parse_quotes_mean_string) {
    TEST_SUITE("dotenv");

    TEST_CASE("Matching quotes are stripped and mark the value quoted");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "a=\"double\"\nb='single'\nc=\"unmatched\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(3, result, "All three lines parse");
    TEST_ASSERT_STR_EQUAL("double", collected.value[0], "Double quotes stripped");
    TEST_ASSERT_EQUAL(1, collected.quoted[0], "Double-quoted flag");
    TEST_ASSERT_STR_EQUAL("single", collected.value[1], "Single quotes stripped");
    TEST_ASSERT_EQUAL(1, collected.quoted[1], "Single-quoted flag");
    TEST_ASSERT_STR_EQUAL("\"unmatched", collected.value[2], "Unmatched quote stays in the value");
    TEST_ASSERT_EQUAL(0, collected.quoted[2], "Unmatched quote is not a quoting pair");

    collect_free(&collected);
}

TEST(test_dotenv_parse_quoted_hash_not_comment) {
    TEST_SUITE("dotenv");

    TEST_CASE("A # inside quotes is not a comment, a bare one after a space is");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "pass=\"p@ss # keep\"\nbare=keep # drop\ntight=keep# drop too\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(3, result, "All three lines parse");
    TEST_ASSERT_STR_EQUAL("p@ss # keep", collected.value[0], "Hash inside quotes kept");
    TEST_ASSERT_STR_EQUAL("keep", collected.value[1], "Comment after ' #' dropped");
    TEST_ASSERT_STR_EQUAL("keep# drop too", collected.value[2], "A hash glued to the value is not a comment");

    collect_free(&collected);
}

TEST(test_dotenv_parse_malformed_lines_skipped) {
    TEST_SUITE("dotenv");

    TEST_CASE("A line without =, or with an empty key, is skipped, parsing continues");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "no equals sign\n=emptykey\nvalid=1\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(1, result, "Only the valid line yields a pair");
    TEST_ASSERT_EQUAL(1, collected.count, "Callback called once");
    TEST_ASSERT_STR_EQUAL("valid", collected.key[0], "Valid key survived");

    collect_free(&collected);
}

TEST(test_dotenv_parse_empty_value) {
    TEST_SUITE("dotenv");

    TEST_CASE("An empty value is delivered as an empty string");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "empty=\nquoted=\"\"\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(2, result, "Both lines parse");
    TEST_ASSERT_STR_EQUAL("", collected.value[0], "Empty unquoted value");
    TEST_ASSERT_EQUAL(0, collected.quoted[0], "Empty unquoted flag");
    TEST_ASSERT_STR_EQUAL("", collected.value[1], "Empty quoted value");
    TEST_ASSERT_EQUAL(1, collected.quoted[1], "Empty quoted flag");

    collect_free(&collected);
}

TEST(test_dotenv_parse_crlf) {
    TEST_SUITE("dotenv");

    TEST_CASE("CRLF line endings: the \\r is trimmed off key and value");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "key=value\r\n# comment\r\nlast=1\r\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(2, result, "Both pairs parse");
    TEST_ASSERT_STR_EQUAL("value", collected.value[0], "Trailing \\r trimmed");
    TEST_ASSERT_STR_EQUAL("1", collected.value[1], "Last line without newline");

    collect_free(&collected);
}

TEST(test_dotenv_parse_no_trailing_newline) {
    TEST_SUITE("dotenv");

    TEST_CASE("A buffer without a trailing newline still yields its pair");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "key=value";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(1, result, "Final unterminated line is delivered");
    TEST_ASSERT_STR_EQUAL("value", collected.value[0], "Value intact");

    collect_free(&collected);
}

TEST(test_dotenv_parse_empty_buffer) {
    TEST_SUITE("dotenv");

    TEST_CASE("An empty file yields zero pairs");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(0, result, "Zero pairs");
    TEST_ASSERT_EQUAL(0, collected.count, "Callback never called");

    collect_free(&collected);
}

TEST(test_dotenv_parse_order_preserved) {
    TEST_SUITE("dotenv");

    TEST_CASE("Pairs are delivered in file order");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "b=2\na=1\nc=3\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(3, result, "Three pairs");
    TEST_ASSERT_STR_EQUAL("b", collected.key[0], "First in file order");
    TEST_ASSERT_STR_EQUAL("a", collected.key[1], "Second in file order");
    TEST_ASSERT_STR_EQUAL("c", collected.key[2], "Third in file order");

    collect_free(&collected);
}

TEST(test_dotenv_parse_null_callback) {
    TEST_SUITE("dotenv");

    TEST_CASE("A NULL callback turns dotenv_parse into a validator");

    char data[] = "a=1\nbroken\nb=2\n";
    int result = dotenv_parse(data, NULL, NULL, NULL);

    TEST_ASSERT_EQUAL(2, result, "Count without delivering pairs");
}

TEST(test_dotenv_parse_callback_abort) {
    TEST_SUITE("dotenv");

    TEST_CASE("A callback returning 0 stops the parse with -1");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "a=1\nb=2\nc=3\n";
    int result = dotenv_parse(data, NULL, abort_after_pair, &collected);

    TEST_ASSERT_EQUAL(-1, result, "Aborted parse reported as -1");
    TEST_ASSERT_EQUAL(2, collected.count, "Callback ran for a and b, stopped before c");

    collect_free(&collected);
}

TEST(test_dotenv_parse_value_with_equals) {
    TEST_SUITE("dotenv");

    TEST_CASE("Everything after the first = is the value, = included");

    collected_t collected = { .aborted_after = -1 };
    char data[] = "conn=postgres://u:p@h:5432/db?ssl=1\n";
    int result = parse_literal(data, &collected);

    TEST_ASSERT_EQUAL(1, result, "One pair");
    TEST_ASSERT_STR_EQUAL("conn", collected.key[0], "Key before the first =");
    TEST_ASSERT_STR_EQUAL("postgres://u:p@h:5432/db?ssl=1", collected.value[0], "Rest of the line is the value");

    collect_free(&collected);
}

TEST(test_dotenv_load_missing_file) {
    TEST_SUITE("dotenv");

    TEST_CASE("A file that cannot be opened yields NULL");

    TEST_ASSERT_NULL(dotenv_load("/nonexistent/cwfr/dotenv/missing.env"), "Missing file -> NULL");
}

TEST(test_dotenv_load_parse_file_roundtrip) {
    TEST_SUITE("dotenv");

    TEST_CASE("dotenv_load + dotenv_parse round trip over a real file");

    char path[64];
    snprintf(path, sizeof path, "/tmp/cwfr_dotenv_test_%d.env", (int)getpid());

    FILE* file = fopen(path, "w");
    TEST_REQUIRE_NOT_NULL(file, "Test file created");

    fputs("# generated\napp_name=cwfr\nworkers=4\n", file);
    fclose(file);

    char* data = dotenv_load(path);
    unlink(path);
    TEST_REQUIRE_NOT_NULL(data, "File read back");

    collected_t collected = { .aborted_after = -1 };
    int result = dotenv_parse(data, path, collect_pair, &collected);
    free(data);

    TEST_ASSERT_EQUAL(2, result, "Both pairs from the file");
    TEST_ASSERT_STR_EQUAL("app_name", collected.key[0], "First key from file");
    TEST_ASSERT_STR_EQUAL("cwfr", collected.value[0], "First value from file");
    TEST_ASSERT_STR_EQUAL("workers", collected.key[1], "Second key from file");
    TEST_ASSERT_STR_EQUAL("4", collected.value[1], "Second value from file -- stays a string here, typing is the caller's job");

    collect_free(&collected);
}

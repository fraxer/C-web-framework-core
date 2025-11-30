#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ANSI color codes for terminal output */
#define COLOR_RED "\033[31m"
#define COLOR_RESET "\033[0m"

/* Test statistics structure */
typedef struct {
    int total;
    int passed;
    int failed;
} TestStats;

/* Global test statistics - defined in test_runner.c */
extern TestStats stats;

/* Current test context for delayed output */
typedef struct {
    const char *current_suite;
    const char *current_case;
    int suite_printed;
    int case_printed;
} TestContext;

extern TestContext test_context;

/* Test suite function pointer type */
typedef void (*test_suite_fn)(void);

/* Initial capacity for test suites */
#define INITIAL_TEST_SUITES_CAPACITY 16

/* Test suite registry */
typedef struct {
    test_suite_fn *suites;
    int count;
    int capacity;
} TestRegistry;

extern TestRegistry test_registry;

/* Register a test suite */
static inline void register_test_suite(test_suite_fn suite) {
    if (test_registry.count >= test_registry.capacity) {
        int new_capacity = test_registry.capacity == 0 ? INITIAL_TEST_SUITES_CAPACITY : test_registry.capacity * 2;
        test_suite_fn *new_suites = (test_suite_fn *)realloc(test_registry.suites, new_capacity * sizeof(test_suite_fn));
        if (new_suites == NULL) {
            fprintf(stderr, "ERROR: Failed to allocate memory for test suites!\n");
            return;
        }
        test_registry.suites = new_suites;
        test_registry.capacity = new_capacity;
    }
    test_registry.suites[test_registry.count++] = suite;
}

/* Macro to auto-register test suite */
#define REGISTER_TEST_SUITE(func) \
    static void __attribute__((constructor)) register_##func(void) { \
        register_test_suite(func); \
    }

/* Macro to auto-register individual test case */
#define REGISTER_TEST_CASE(func) \
    static void __attribute__((constructor)) register_##func(void) { \
        register_test_suite(func); \
    }

/* Macro to define and auto-register a test in one line */
#define TEST(name) \
    static void name(void); \
    static void __attribute__((constructor)) register_##name(void) { \
        register_test_suite(name); \
    } \
    static void name(void)

/* Test suite and case macros - only store names, print on failure */
#define TEST_SUITE(name) do { \
    test_context.current_suite = name; \
    test_context.current_case = NULL; \
    test_context.suite_printed = 0; \
    test_context.case_printed = 0; \
} while(0)

#define TEST_CASE(name) do { \
    test_context.current_case = name; \
    test_context.case_printed = 0; \
} while(0)

/* Helper macro to print test context on first failure */
#define PRINT_TEST_CONTEXT() do { \
    if (!test_context.suite_printed && test_context.current_suite) { \
        printf("\n=== Running test suite: %s ===\n", test_context.current_suite); \
        test_context.suite_printed = 1; \
    } \
    if (!test_context.case_printed && test_context.current_case) { \
        printf("\nTest case: %s\n", test_context.current_case); \
        test_context.case_printed = 1; \
    } \
} while(0)

/* Assertion macros */
#define TEST_ASSERT(condition, message) do { \
    stats.total++; \
    if (condition) { \
        stats.passed++; \
    } else { \
        PRINT_TEST_CONTEXT(); \
        stats.failed++; \
        printf("  " COLOR_RED "[FAIL]" COLOR_RESET " %s (line %d)\n", message, __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_EQUAL(expected, actual, message) do { \
    stats.total++; \
    if ((expected) == (actual)) { \
        stats.passed++; \
    } else { \
        PRINT_TEST_CONTEXT(); \
        stats.failed++; \
        printf("  " COLOR_RED "[FAIL]" COLOR_RESET " %s: expected %lld, got %lld (line %d)\n", message, (long long)(expected), (long long)(actual), __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_EQUAL_SIZE(expected, actual, message) do { \
    stats.total++; \
    if ((expected) == (actual)) { \
        stats.passed++; \
    } else { \
        PRINT_TEST_CONTEXT(); \
        stats.failed++; \
        printf("  " COLOR_RED "[FAIL]" COLOR_RESET " %s: expected %zu, got %zu (line %d)\n", message, (size_t)(expected), (size_t)(actual), __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_EQUAL_UINT(expected, actual, message) do { \
    stats.total++; \
    if ((expected) == (actual)) { \
        stats.passed++; \
    } else { \
        PRINT_TEST_CONTEXT(); \
        stats.failed++; \
        printf("  " COLOR_RED "[FAIL]" COLOR_RESET " %s: expected %u, got %u (line %d)\n", message, (unsigned int)(expected), (unsigned int)(actual), __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_STR_EQUAL(expected, actual, message) do { \
    stats.total++; \
    if (strcmp((expected), (actual)) == 0) { \
        stats.passed++; \
    } else { \
        PRINT_TEST_CONTEXT(); \
        stats.failed++; \
        printf("  " COLOR_RED "[FAIL]" COLOR_RESET " %s: expected '%s', got '%s' (line %d)\n", message, expected, actual, __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_NOT_NULL(ptr, message) do { \
    stats.total++; \
    if ((ptr) != NULL) { \
        stats.passed++; \
    } else { \
        PRINT_TEST_CONTEXT(); \
        stats.failed++; \
        printf("  " COLOR_RED "[FAIL]" COLOR_RESET " %s: pointer is NULL (line %d)\n", message, __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_NULL(ptr, message) do { \
    stats.total++; \
    if ((ptr) == NULL) { \
        stats.passed++; \
    } else { \
        PRINT_TEST_CONTEXT(); \
        stats.failed++; \
        printf("  " COLOR_RED "[FAIL]" COLOR_RESET " %s: pointer is not NULL (line %d)\n", message, __LINE__); \
    } \
} while(0)

#endif /* TEST_FRAMEWORK_H */

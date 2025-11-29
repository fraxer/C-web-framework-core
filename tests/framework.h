#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test statistics structure */
typedef struct {
    int total;
    int passed;
    int failed;
} TestStats;

/* Global test statistics - defined in test_runner.c */
extern TestStats stats;

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

/* Test suite and case macros */
#define TEST_SUITE(name) \
    printf("\n=== Running test suite: %s ===\n", name);

#define TEST_CASE(name) \
    printf("\nTest case: %s\n", name);

/* Assertion macros */
#define TEST_ASSERT(condition, message) do { \
    stats.total++; \
    if (condition) { \
        stats.passed++; \
        printf("  [PASS] %s\n", message); \
    } else { \
        stats.failed++; \
        printf("  [FAIL] %s (line %d)\n", message, __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_EQUAL(expected, actual, message) do { \
    stats.total++; \
    if ((expected) == (actual)) { \
        stats.passed++; \
        printf("  [PASS] %s\n", message); \
    } else { \
        stats.failed++; \
        printf("  [FAIL] %s: expected %lld, got %lld (line %d)\n", message, (long long)(expected), (long long)(actual), __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_EQUAL_SIZE(expected, actual, message) do { \
    stats.total++; \
    if ((expected) == (actual)) { \
        stats.passed++; \
        printf("  [PASS] %s\n", message); \
    } else { \
        stats.failed++; \
        printf("  [FAIL] %s: expected %zu, got %zu (line %d)\n", message, (size_t)(expected), (size_t)(actual), __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_EQUAL_UINT(expected, actual, message) do { \
    stats.total++; \
    if ((expected) == (actual)) { \
        stats.passed++; \
        printf("  [PASS] %s\n", message); \
    } else { \
        stats.failed++; \
        printf("  [FAIL] %s: expected %u, got %u (line %d)\n", message, (unsigned int)(expected), (unsigned int)(actual), __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_STR_EQUAL(expected, actual, message) do { \
    stats.total++; \
    if (strcmp((expected), (actual)) == 0) { \
        stats.passed++; \
        printf("  [PASS] %s\n", message); \
    } else { \
        stats.failed++; \
        printf("  [FAIL] %s: expected '%s', got '%s' (line %d)\n", message, expected, actual, __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_NOT_NULL(ptr, message) do { \
    stats.total++; \
    if ((ptr) != NULL) { \
        stats.passed++; \
        printf("  [PASS] %s\n", message); \
    } else { \
        stats.failed++; \
        printf("  [FAIL] %s: pointer is NULL (line %d)\n", message, __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_NULL(ptr, message) do { \
    stats.total++; \
    if ((ptr) == NULL) { \
        stats.passed++; \
        printf("  [PASS] %s\n", message); \
    } else { \
        stats.failed++; \
        printf("  [FAIL] %s: pointer is not NULL (line %d)\n", message, __LINE__); \
    } \
} while(0)

#endif /* TEST_FRAMEWORK_H */

#include "framework.h"

// Global test statistics
TestStats stats = {0, 0, 0};

// Test registry
TestRegistry test_registry = {NULL, 0, 0};

int main(void) {
    printf("Starting test runner...\n");
    printf("======================================\n");

    // Run all registered test suites
    for (int i = 0; i < test_registry.count; i++)
        if (test_registry.suites[i] != NULL)
            test_registry.suites[i]();

    // Print summary
    printf("\n======================================\n");
    printf("Test Results:\n");
    printf("  Total:  %d\n", stats.total);
    printf("  Passed: %d\n", stats.passed);
    printf("  Failed: %d\n", stats.failed);
    printf("======================================\n");

    // Cleanup
    free(test_registry.suites);

    if (stats.failed > 0) {
        printf("\nTests FAILED!\n");
        return EXIT_FAILURE;
    } else {
        printf("\nAll tests PASSED!\n");
        return EXIT_SUCCESS;
    }
}

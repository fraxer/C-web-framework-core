#include <stdio.h>
#include <stdlib.h>

#include "testdb.h"

TestStats stats = {0, 0, 0};
TestContext test_context = {NULL, NULL, 0, 0};
TestRegistry test_registry = {NULL, 0, 0};

int main(int argc, char* argv[]) {
    /* TEST_DBID, TEST_CONFIG_PATH, TEST_MIGRATIONS_DIR
     * are defined via target_compile_definitions in CMakeLists.txt */
    const char* dbid = argc > 1 ? argv[1] : TEST_DBID;
    const char* config = argc > 2 ? argv[2] : TEST_CONFIG_PATH;
    const char* migrations = argc > 3 ? argv[3] : TEST_MIGRATIONS_DIR;

    printf("======================================\n");
    printf("DB Test Runner\n");
    printf("  driver: %s\n", dbid);
    printf("  config: %s\n", config);
    printf("  migrations: %s\n", migrations);
    printf("======================================\n");

    if (!testdb_setup(dbid, config, migrations)) {
        fprintf(stderr, "Failed to set up test database\n");
        return EXIT_FAILURE;
    }

    printf("\nTest database: %s\n", testdb_name());
    printf("======================================\n");

    for (int i = 0; i < test_registry.count; i++)
        if (test_registry.suites[i])
            test_registry.suites[i]();

    printf("\n======================================\n");
    printf("Test Results:\n");
    printf("  Total:  %d\n", stats.total);
    printf("  Passed: %d\n", stats.passed);
    printf("  Failed: %d\n", stats.failed);
    printf("======================================\n");

    testdb_teardown();
    free(test_registry.suites);

    if (stats.failed > 0) {
        printf("\nTests FAILED!\n");
        return EXIT_FAILURE;
    }

    printf("\nAll tests PASSED!\n");
    return EXIT_SUCCESS;
}

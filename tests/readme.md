# Tests for backend/core

This directory contains tests for the cpdy project.

## Test Types

- **Unit tests** (`runner`) — no external dependencies required, verify in-memory logic
- **DB tests** (`db_runner`) — require a database connection (PostgreSQL / MySQL), verify SQL queries

## Structure

```
tests/
├── core/                     # framework and common files
│   ├── framework.h           # TEST, TEST_ASSERT* macros, registration
│   ├── testdb.h              # DB test API (TEST_DB macro)
│   └── testdb.c              # implementation: schemas, migrations, SAVEPOINT
├── unit/                     # unit tests (no DB)
│   ├── runner.c              # unit test runner
│   └── test_*.c              # test files
├── db/                       # DB tests
│   ├── runner.c              # DB test runner
│   ├── test_db_*.c           # test files
│   └── test_config.json      # DB connection config
├── CMakeLists.txt
└── README.md
```

## Building and Running

```bash
cd backend && mkdir -p build && cd build

# Build with tests
cmake .. -DBUILD_TESTS=ON -DINCLUDE_POSTGRESQL=yes
cmake --build .

# Unit tests
./exec/runner

# DB tests (default parameters from CMake)
./exec/db_runner

# DB tests with explicit arguments
./exec/db_runner postgresql.identity path/to/test_config.json path/to/migrations

# Via CTest
ctest --output-on-failure
```

---

## Unit Tests

Create a file `unit/test_<module>.c` — CMake will automatically pick it up. Use the `TEST()` macro to declare and automatically register a test.

### Example

```c
#include "framework.h"
#include "str.h"

TEST(test_str_trim) {
    TEST_SUITE("String Utils");
    TEST_CASE("Trim whitespace");

    char buf[] = "  hello  ";
    char* result = str_trim(buf);

    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello", result, "Should trim spaces");
}

TEST(test_str_empty) {
    TEST_SUITE("String Utils");
    TEST_CASE("Handle empty string");

    char buf[] = "";
    char* result = str_trim(buf);

    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");
    TEST_ASSERT_STR_EQUAL("", result, "Empty string stays empty");
}
```

### Grouping into Test Suites

```c
#include "framework.h"

static void test_basic_ops(void) {
    TEST_CASE("Basic operations");
    TEST_ASSERT_EQUAL(4, 2 + 2, "2 + 2 should equal 4");
}

static void test_edge_cases(void) {
    TEST_CASE("Edge cases");
    TEST_ASSERT_EQUAL(0, 0 * 100, "0 * 100 should equal 0");
}

static void run_math_tests(void) {
    TEST_SUITE("Math Module");
    test_basic_ops();
    test_edge_cases();
}

REGISTER_TEST_SUITE(run_math_tests)
```

### Assertion Macros

| Macro | Description |
|-------|-------------|
| `TEST_ASSERT(cond, msg)` | Check a condition |
| `TEST_ASSERT_EQUAL(expected, actual, msg)` | Compare `long long` values |
| `TEST_ASSERT_EQUAL_UINT(expected, actual, msg)` | Compare `unsigned int` values |
| `TEST_ASSERT_EQUAL_SIZE(expected, actual, msg)` | Compare `size_t` values |
| `TEST_ASSERT_STR_EQUAL(expected, actual, msg)` | Compare strings (`strcmp`) |
| `TEST_ASSERT_NOT_NULL(ptr, msg)` | Pointer is not NULL |
| `TEST_ASSERT_NULL(ptr, msg)` | Pointer is NULL |

### Test Registration

| Method | Description |
|--------|-------------|
| `TEST(name)` | Declaration + registration in one line (recommended) |
| `REGISTER_TEST_CASE(func)` | Explicit registration of a single function |
| `REGISTER_TEST_SUITE(func)` | Registration of a test group |

---

## DB Tests

Files `db/test_db_*.c` are automatically included in `db_runner`. Each test is wrapped in `SAVEPOINT` / `ROLLBACK` — data between tests is fully isolated.

### How It Works

1. `testdb_setup()` initializes the framework, creates a temporary schema (PostgreSQL) or database (MySQL)
2. Migrations from the specified directory are executed
3. Each `TEST_DB` is wrapped in `BEGIN` + `SAVEPOINT` / `ROLLBACK TO SAVEPOINT`
4. `testdb_teardown()` drops the temporary schema/database

### Example: INSERT and SELECT

```c
#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"

TEST_DB(test_db_create_user) {
    TEST_SUITE("User Model");
    TEST_CASE("Insert and retrieve a user");

    const char* dbid = testdb_dbid();

    // INSERT
    dbresult_t* r = dbqueryf(dbid,
        "INSERT INTO user_entity (id, email, email_constraint, enabled) "
        "VALUES ('test-1', 'alice@test.com', 'alice@test.com', TRUE)");
    TEST_ASSERT(dbresult_ok(r), "Insert should succeed");
    dbresult_free(r);

    // SELECT
    r = dbqueryf(dbid, "SELECT email FROM user_entity WHERE id = 'test-1'");
    TEST_ASSERT(dbresult_ok(r), "Select should succeed");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(r), "Should find 1 row");

    db_table_cell_t* cell = dbresult_field(r, "email");
    TEST_ASSERT_NOT_NULL(cell, "Email field should exist");
    if (cell)
        TEST_ASSERT_STR_EQUAL("alice@test.com", cell->value, "Email should match");

    dbresult_free(r);
}
```

### Example: Isolation Check

```c
#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"

TEST_DB(test_db_insert_data) {
    TEST_SUITE("Isolation");
    TEST_CASE("Insert a row");

    const char* dbid = testdb_dbid();
    dbresult_t* r = dbqueryf(dbid,
        "INSERT INTO user_entity (id, email, email_constraint, enabled) "
        "VALUES ('u1', 'bob@test.com', 'bob@test.com', TRUE)");
    TEST_ASSERT(dbresult_ok(r), "Insert should succeed");
    dbresult_free(r);
}

TEST_DB(test_db_data_is_rolled_back) {
    TEST_SUITE("Isolation");
    TEST_CASE("Data from previous test does not persist");

    const char* dbid = testdb_dbid();
    dbresult_t* r = dbqueryf(dbid,
        "SELECT * FROM user_entity WHERE id = 'u1'");
    TEST_ASSERT(dbresult_ok(r), "Query should succeed");
    TEST_ASSERT_EQUAL(0, dbresult_query_rows(r), "Row should not exist");
    dbresult_free(r);
}
```

### testdb API

| Function | Description |
|----------|-------------|
| `testdb_setup(dbid, config, migrations)` | Create a temporary schema/database, run migrations |
| `testdb_teardown()` | Drop the temporary schema/database |
| `testdb_begin_test()` | `BEGIN` + `SAVEPOINT` (called by the `TEST_DB` macro) |
| `testdb_rollback_test()` | `ROLLBACK TO SAVEPOINT` + `COMMIT` (called by the `TEST_DB` macro) |
| `testdb_dbid()` | dbid for queries |
| `testdb_name()` | Name of the temporary schema/database |
| `testdb_driver()` | `TESTDB_DRIVER_POSTGRESQL` or `TESTDB_DRIVER_MYSQL` |

### Configuration

Default parameters are set in CMake:

```cmake
target_compile_definitions(db_runner PRIVATE
    TEST_DBID="postgresql.identity"
    TEST_CONFIG_PATH="${CMAKE_CURRENT_SOURCE_DIR}/db/test_config.json"
    TEST_MIGRATIONS_DIR="${CMAKE_BINARY_DIR}/exec/migrations/identity"
)
```

Overridden via command-line arguments:

```bash
./db_runner mysql.m1 /path/to/config.json /path/to/migrations
```

---

## Debugging

```bash
# GDB
gdb ./exec/runner
(gdb) run

# AddressSanitizer
cmake .. -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON
cmake --build .
./exec/runner
```

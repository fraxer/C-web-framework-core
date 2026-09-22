# Tests for backend/core

This directory contains the tests for the cwfr framework.

Tests are not part of an ordinary build. They are added by the core when the
host project configures with `-DBUILD_TESTS=yes` — the value is compared
literally, so `ON`, `1` and `true` all leave the suite out.

## Test Types

| Binary | What it covers | Requirements |
|--------|----------------|--------------|
| `runner` | every `unit/test_*.c` suite, including form validation | no external service |
| `h2_runner` | the HTTP/2 subset (`test_h2*`, `test_hpack`, `test_httpfields`) | none |
| `h3_runner` | the QUIC / HTTP/3 / QPACK subset | `-DINCLUDE_HTTP3=yes` |
| `db_runner` | `db/test_db_*.c` — real SQL against a real server | a reachable database |
| `quicclient` | a QUIC/HTTP3 client tool, for the shell suites below | `-DINCLUDE_HTTP3=yes` |
| `fuzz_*` | the QUIC/H3/QPACK parsers under a fuzzer | `-DBUILD_FUZZERS=yes`, clang |

`h2_runner` and `h3_runner` are narrower builds of files `runner` already
contains. They exist so a protocol regression stays visible when an unrelated
framework failure breaks the broad runner — additional gates, not replacements.

Beyond the binaries, `tests/` holds the integration suites that need a live
server: `h3_*.sh`, `hot_reload_shadow.sh`, `startup_failure.sh`,
`startup_lifetime.py` and `h2ws_probe.py`. `ci.sh` drives all of it.

## Structure

```
tests/
├── core/                     # test framework and shared helpers
│   ├── framework.h           # TEST, TEST_ASSERT*, TEST_REQUIRE*, registration
│   ├── testdb.h              # DB test API (TEST_DB macro)
│   └── testdb.c              # implementation: schemas, migrations, SAVEPOINT
├── unit/                     # unit tests (no DB)
│   ├── runner.c              # shared main() for runner, h2_runner, h3_runner
│   ├── mail_stubs.c          # taskmanager stub every runner links
│   ├── h3_config_stubs.c     # appconfig the narrow runners cannot borrow
│   ├── test_form.c           # form schema, validators, defaults and ownership
│   ├── test_form_fields.c    # date/time, UUID, JSON, choices and files
│   └── test_*.c              # test files, picked up by a glob
├── db/                       # DB tests
│   ├── runner.c              # DB test runner
│   ├── test_db_*.c           # test files, picked up by a glob
│   └── test_config.json      # DB connection config
├── quicclient/               # QUIC/HTTP3 client used by the h3 shell suites
├── fuzz/                     # fuzz targets, driver and corpus
├── data/                     # fixtures: certificates, shadow-copy modules
├── ci.sh                     # every stage of docs/http3/08-testing.md §8
├── h3_*.sh, hot_reload_*.sh  # integration suites against a live server
├── startup_lifetime.py       # registered with CTest as `startup_lifetime`
├── CMakeLists.txt
└── readme.md
```

## Building and Running

Tests are built by the host project — the directory that holds `core/`,
i.e. `backend/` in this checkout. Every command below is written from the
directory above it.

```bash
cmake -S backend -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
      -DINCLUDE_POSTGRESQL=yes -DINCLUDE_HTTP3=yes
cmake --build build
```

Built test binaries land in `build/exec/`:

```bash
# Unit tests
./build/exec/runner

# Just the HTTP/2 or the QUIC/HTTP/3 suites
./build/exec/h2_runner
./build/exec/h3_runner

# DB tests (defaults come from CMake: postgresql.test, db/test_config.json,
# no migrations)
./build/exec/db_runner

# DB tests with explicit arguments: dbid, config, migrations directory
./build/exec/db_runner mysql.m1 /path/to/config.json /path/to/migrations
```

### Via CTest

```bash
ctest --test-dir build --output-on-failure
```

Registered tests:

| Name | Runs | Present when |
|------|------|--------------|
| `core_tests` | `runner` | always |
| `h2_unit_tests` | `h2_runner` | always |
| `h3_unit_tests` | `h3_runner` | `-DINCLUDE_HTTP3=yes` |
| `startup_lifetime` | `startup_lifetime.py` | Python 3 was found |
| `db_tests` | `db_runner` | a database driver was enabled |

The form tests are part of `core_tests`: CMake includes both
`unit/test_form.c` and `unit/test_form_fields.c` in `runner`. They do not have
separate executables or CTest names.

`enable_testing()` covers the calling directory and everything below it, never
the parent. A host project that embeds the core with `add_subdirectory()` must
therefore call it **itself, before that line** — otherwise no
`CTestTestfile.cmake` is written at the top of the build tree and `ctest` finds
nothing at all, in the core and in the application alike.

### Every stage at once

```bash
backend/core/tests/ci.sh                  # all stages
backend/core/tests/ci.sh asan h3unit      # a subset, in the order given
CI_BUILD_DIR=/var/tmp/ci backend/core/tests/ci.sh
```

`ci.sh` builds its own trees, runs the unit runners and every integration
suite, and prints which stage failed. Its header lists the stages.

---

## Unit Tests

### Form tests

`unit/test_form.c` checks required and optional input, defaults, text length
and regex rules, integer and decimal bounds, boolean values, custom parsers,
validators, cross-field errors and ownership of input objects.

`unit/test_form_fields.c` checks `DateField`, `TimeField`, `DateTimeField`,
`UUIDField`, `JSONField`, `ChoiceField`, `FilePathField`, `FileField` and
`MultipleChoiceField`. It covers valid values, malformed input, file size and
empty-file rules, paths outside the configured directory, symlinks, and empty
or defaulted choice lists. The file tests create temporary fixtures and remove
them when the test finishes; they need no database or running server.

From the repository root, build and run the unit runner with:

```bash
cmake -S backend -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes
cmake --build build --target runner
ctest --test-dir build -R '^core_tests$' --output-on-failure
```

`core_tests` runs every unit suite in `runner`. The runner has no option to
select only the form tests. Field configuration and input examples are in
[`framework/form/EXAMPLES.md`](../framework/form/EXAMPLES.md).

### Adding a unit test

Create a file `unit/test_<module>.c` — CMake globs it into `runner`
automatically, and `runner.c` needs no edit: the `TEST()` macro registers the
function through a constructor.

Because the glob runs at configure time, a newly added file needs one
`cmake -S … -B build` before it is picked up.

All suites share one process. A test that dereferences a NULL pointer takes
down every other suite with it, so guard anything the next line dereferences
with `TEST_REQUIRE*` rather than `TEST_ASSERT*`, and free what you allocate —
the runner is also built under AddressSanitizer, where a leak fails the whole
binary.

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

`TEST_SUITE()` and `TEST_CASE()` only record names; they are printed when
something fails. `TEST_CASE()` does not touch the suite name, so a test that
sets no `TEST_SUITE()` reports its failures under whichever suite ran before
it — set both.

### Releasing resources on a failed guard

`TEST_REQUIRE*` returns from the test, which is wrong once something is already
allocated. Use the `_GOTO` forms and a cleanup label:

```c
TEST(test_form_defaults) {
    TEST_SUITE("Form");
    TEST_CASE("A default value still goes through the validators");

    form_t* form = form_create(&schema, inputs);
    TEST_REQUIRE_NOT_NULL(form, "Form should be created");
    TEST_REQUIRE_GOTO(form_is_valid(form), "Form should be valid", cleanup);

    TEST_ASSERT_EQUAL(21, form_cleaned_data(form, 0)->data.integer, "Age should default to 21");

cleanup:
    form_free(form);
}
```

### Grouping several cases under one registration

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

Failing assertions are recorded and execution continues:

| Macro | Description |
|-------|-------------|
| `TEST_ASSERT(cond, msg)` | Check a condition |
| `TEST_ASSERT_EQUAL(expected, actual, msg)` | Compare as `long long` — not for floating point |
| `TEST_ASSERT_EQUAL_UINT(expected, actual, msg)` | Compare `unsigned int` values |
| `TEST_ASSERT_EQUAL_SIZE(expected, actual, msg)` | Compare `size_t` values |
| `TEST_ASSERT_STR_EQUAL(expected, actual, msg)` | Compare strings; a NULL `actual` is a clean failure |
| `TEST_ASSERT_NOT_NULL(ptr, msg)` | Pointer is not NULL |
| `TEST_ASSERT_NULL(ptr, msg)` | Pointer is NULL |
| `TEST_FAIL(msg)` | Record a failure unconditionally |

Failing preconditions abort the current test instead:

| Macro | Description |
|-------|-------------|
| `TEST_REQUIRE(cond, msg)` | Record a failure and `return` |
| `TEST_REQUIRE_NOT_NULL(ptr, msg)` | Same, for a pointer |
| `TEST_REQUIRE_GOTO(cond, msg, label)` | Record a failure and `goto label` |
| `TEST_REQUIRE_NOT_NULL_GOTO(ptr, msg, label)` | Same, for a pointer |

The comparison macros evaluate each argument exactly once, so an argument with
side effects is safe.

### Test Registration

| Method | Description |
|--------|-------------|
| `TEST(name)` | Declaration + registration in one line (recommended) |
| `REGISTER_TEST_CASE(func)` | Explicit registration of a single function |
| `REGISTER_TEST_SUITE(func)` | Registration of a test group |

---

## DB Tests

Files `db/test_db_*.c` are automatically included in `db_runner`. Each test is
wrapped in `SAVEPOINT` / `ROLLBACK` — data between tests is fully isolated.

`db_runner` is built only when at least one database driver was enabled at
configure time (`INCLUDE_POSTGRESQL`, `INCLUDE_MYSQL`, `INCLUDE_SQLITE`), and
it needs a reachable server: it creates a temporary schema and drops it again.

### How It Works

1. `testdb_setup()` initializes the framework, creates a temporary schema (PostgreSQL) or database (MySQL)
2. Migrations from the specified directory are executed, when one was given
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
    TEST_DBID="postgresql.test"
    TEST_CONFIG_PATH="${CMAKE_CURRENT_SOURCE_DIR}/db/test_config.json"
    TEST_MIGRATIONS_DIR=""
)
```

`postgresql.test` names the `host_id` of `db/test_config.json`. An empty
migrations directory means none are run — pass one as the third argument when
the tests need a schema.

Overridden via command-line arguments:

```bash
./build/exec/db_runner mysql.m1 /path/to/config.json /path/to/migrations
```

---

## Fuzzing

```bash
cmake -S backend -B build-fuzz -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
      -DINCLUDE_HTTP3=yes -DBUILD_FUZZERS=yes -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz
./build-fuzz/exec/fuzz_quic_packet backend/core/tests/fuzz/corpus/quic_packet
```

Targets, each with a seed corpus under `fuzz/corpus/`:

| Target | Reached by |
|---|---|
| `quic_packet`, `quic_frame`, `quic_tp` | a datagram, before decryption or a finished handshake |
| `h3_frame`, `h3_priority`, `qpack_decode`, `qpack_streams` | any stream the peer opens |
| `huffman` | QPACK and HPACK both, on names and values |
| `hpack` | an HTTP/2 field section |
| `cookie`, `urlencoded`, `multipart` | every HTTP/1.1 request that carries the header or the body |

The last four are newer than the rest and cover what the HTTP/1.1 and HTTP/2
side reaches before a handler sees anything. `httprequestparser` itself is
still uncovered: it wants a `connection_t`, so a target for it needs a stub
the others do not. `-DBUILD_FUZZERS=yes` requires `-DINCLUDE_HTTP3=yes`
even for `hpack` and the HTTP/1.1 targets, which need none of it — the flag gates the
whole block rather than a target at a time.

clang builds the targets against libFuzzer (`-fsanitize=fuzzer,address`) and
is the better choice where it is available. gcc works too, and the link error
this note used to describe is not a property of the gcc branch but of building
it without a sanitizer: `fuzz_main.c` calls `__sanitizer_set_death_callback`,
so the runtime that defines it has to be on the line. Put it there and the
same targets build and run:

```bash
cmake -S backend -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DBUILD_TESTS=yes -DBUILD_FUZZERS=yes -DINCLUDE_HTTP3=yes \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-fuzz --target fuzz_hpack
./build-fuzz/exec/fuzz_hpack -seconds=120 backend/core/tests/fuzz/corpus/hpack
```

The driver takes `-seconds=`, `-runs=`, `-seed=` and `-artifacts=<dir>`, and
writes the crashing input to the artifacts directory; a reproducer belongs in
the seed corpus once the bug behind it is fixed.

`corpus/hpack/regression_dynamic_index_oob.bin` is there for a different
reason, and stands for no bug this code ever had: the bounds check in
`hpack_resolve_index` was loosened by one on purpose, to establish that the
target reaches the dynamic table at all rather than exercising the static one
and reporting nothing. The fuzzer answered in under two minutes with these
three bytes — `82 be 45`, an indexed field naming dynamic entry 1 of an empty
table — and they are kept as a seed because that boundary is worth landing on
from the first run.

---

## Debugging

```bash
# GDB
gdb ./build/exec/runner
(gdb) run
```

`CMAKE_BUILD_TYPE=Debug` adds debug symbols; it does **not** turn on
sanitizers by itself. Pass them explicitly, to the compiler and to both linker
flavours (the framework is a shared library):

```bash
# AddressSanitizer + LeakSanitizer
cmake -S backend -B build-asan -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
      -DINCLUDE_POSTGRESQL=yes -DINCLUDE_HTTP3=yes \
      -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address"
cmake --build build-asan
./build-asan/exec/runner

# ThreadSanitizer
cmake -S backend -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
      -DINCLUDE_POSTGRESQL=yes -DINCLUDE_HTTP3=yes \
      -DCMAKE_C_FLAGS="-fsanitize=thread" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=thread"
cmake --build build-tsan
./build-tsan/exec/runner
```

When the sanitized binary is a *server* rather than the unit runner, export
`ASAN_OPTIONS=detect_stack_use_after_return=0` first: the fake-stack region
makes an idle process look like it leaks ~4.5 KB/s. `core/INSTALL.md` §4
explains how to tell the artefact from a real leak.

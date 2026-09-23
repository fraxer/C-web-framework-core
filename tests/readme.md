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
| `fuzz_*` | the protocol parsers under a fuzzer; run by `fuzz/run.sh` | `-DBUILD_FUZZERS=yes` (clang or gcc) |

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
cmake -S backend -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
      -DINCLUDE_HTTP3=yes -DBUILD_FUZZERS=yes
cmake --build build-fuzz
backend/core/tests/fuzz/run.sh build-fuzz              # every target, 10 s each
./build-fuzz/exec/fuzz_quic_packet backend/core/tests/fuzz/corpus/quic_packet
```

`-DBUILD_FUZZERS=yes` needs `-DBUILD_TESTS=yes` and nothing else: the targets
that touch QUIC are added when `INCLUDE_HTTP3=yes`, the rest build either way.
The flag instruments the whole tree, not just the target binaries
(`cmake/fuzz.cmake`, `cwfr_fuzz_instrument()`): the framework and an
application built alongside it get ASan, UBSan with `-fno-sanitize-recover`
and coverage feedback, so a bug in the code under test is caught where it
happens and a new edge in it counts as progress. Under OSS-Fuzz, where
`LIB_FUZZING_ENGINE` is set, the flags come from the environment instead.

### Running them: `tests/fuzz/run.sh`

`run.sh BUILD_DIR [OUTPUT_DIR]` runs exactly what the build registered.
`cwfr_add_fuzzer()` writes each target to `BUILD_DIR/fuzz-targets.txt` with its
seed corpus, dictionary, engine and leak policy, and `run.sh` reads that
manifest -- so an application's own targets run alongside the framework's
without a list to keep in step. It is what `tests/ci.sh fuzz` calls, for a
build with HTTP/3 and one without.

The one list it does keep is the independent half: the framework's targets for
the build at hand. A target missing from the manifest, registered but not
built, or without seeds fails the run; `FUZZ_EXPECT_EXTRA=fuzz_feedback` adds
an application's to what must be there.

| Profile (`FUZZ_PROFILE`) | Time per target | Largest input | Seed | For |
|---|---|---|---|---|
| `smoke` (default) | 10 s | 8 KiB | 1 | every change |
| `long` | 24 h | 256 KiB | fresh | a schedule |
| `large` | 120 s | 1 MiB | fresh | inputs that cross buffer sizes |

`FUZZ_SECONDS`, `FUZZ_MAX_LEN`, `FUZZ_TIMEOUT` (seconds one input may take,
default 5), `FUZZ_SEED` and `FUZZ_JOBS` (parallel targets, default `nproc`)
override the profile; `FUZZ_ONLY` narrows the run to the targets it names.

Nothing is written next to the seeds. `OUTPUT_DIR` keeps, per target, the
corpus the runs grew (reused by the next run), `artifacts/` with failing
inputs, `run.log`, the exact `command.txt`, and a `summary.txt` for the run.
When a run fails, `run.sh` replays the saved input on its own and says whether
it reproduces -- a failure that a stored input does not reproduce is one nobody
can fix. Replaying by hand is the same call: the target with a file instead of
a directory.

Targets, each with a seed corpus under `fuzz/corpus/`:

| Target | Reached by |
|---|---|
| `quic_packet`, `quic_frame`, `quic_tp` | a datagram, before decryption or a finished handshake |
| `h3_frame`, `h3_priority`, `qpack_decode`, `qpack_streams` | any stream the peer opens |
| `huffman` | QPACK and HPACK both, on names and values |
| `hpack` | an HTTP/2 field section |
| `cookie`, `urlencoded`, `multipart` | every HTTP/1.1 request that carries the header or the body |
| `request` | every HTTP/1.1 request, before a route is chosen |
| `h2_frame` | every HTTP/2 connection, one frame at a time |
| `h2_session` | every HTTP/2 connection, as a stream of frames with state between them |
| `json` | a request body a handler asks for as JSON, and the document it builds in reply |
| `websocket` | a websocket frame, where a route accepts them |
| `ws_deflate` | permessage-deflate: the negotiated header and the inflate behind it |
| `request_sequence` | one keep-alive HTTP/1.1 connection: pipelined requests, delivered in reads of any size |
| `websocket_sequence` | websocket frames across reads, control frames between fragments |
| `qpack_dynamic` | the QPACK encoder stream changing a live dynamic table under a field section |

An application registers its own with the same function, and `run.sh` picks
them up from the manifest; the site's `fuzz_feedback` (in `backend/tests/`) is
one.

### What the targets check

A target that only feeds bytes finds crashes and sanitizer reports. Several
also hold the code to a property, and trap when it breaks, so the input that
broke it is saved like any crash:

- **Round trips.** `huffman`: decode(encode(x)) is x. `hpack`: a decoded
  field section, re-encoded by one encoder and decoded by one decoder that
  both keep their tables across the plain and Huffman passes, comes back the
  same. `ws_deflate`: two messages through one context, with and without
  context takeover, inflate to what was deflated. `json`: a parsed document
  serializes to JSON that parses again and serializes to the same bytes.
- **Delivery does not matter.** `request_sequence` parses the same stream in
  one read, one byte per read, and in reads of 1..256 bytes, and compares the
  requests that came out: method, version, target, fields, trailers, body and
  the keep-alive decision. Each completed request must also have at most one
  Host and Content-Length, no Transfer-Encoding (the parser refuses it) and a
  body exactly as long as Content-Length said -- a byte of one request in the
  next breaks one of these. `multipart` does the same with whole, byte and
  random-sized reads, each in its own buffer freed after the call, as
  `httprequest.c` reuses one.
- **Tables stay within bounds.** `qpack_dynamic`: bytes never exceed the
  capacity, capacity never exceeds what was advertised, and a section that
  decoded before the encoder stream cannot block after it.

The first runs of these found two bugs, both kept as seeds and unit tests:
an Insert With Name Reference to the entry its own insertion evicts read the
name after `free` (`qpack.c`), and a number whose exponent overflows `long
double` was accepted and serialized as `inf` (`json.c`).


Everything below `huffman` in that table is newer than the QUIC targets above
it and covers what the HTTP/1.1 and HTTP/2 sides reach before a handler sees
anything.

`h2_session` is the only stateful one. The frame target reads a frame and
forgets it; the session target feeds a stream of bytes in chunks the input
sizes, and what it tests is what the previous frame left behind -- the stream
table, flow control, the token buckets. The named HTTP/2 denial-of-service
families live at that level and none of them is a malformed frame: Rapid Reset
and a CONTINUATION flood are both sequences of correct ones, which a target
that validates frames in isolation cannot reach. It runs with
`detect_leaks=0`, and the comment on the target says why at length: a
dispatched response is owned in turn by the stream, the publish queue, the
worker's write pass and the response pool, and a fixture without an event loop
cannot follow it all the way. ASan and UBSan stay on, and they are what turned
up the null `memcpy` in `h2_on_headers` on this target's first run.

`request` is the one with a fixture rather than a bare call: `httpparser_run`
wants a connection, a server context and a configuration to ask about
`client_max_body_size`. The mocks follow
`tests/unit/test_httprequestparser_dumb_fuzzing.c`, which had to build the same
ones; the differences are that the domain is literal (so `domain_matches` does
not reach a NULL pcre pattern, and the branch that adopts a vhost is reachable
at all), that the context is per-iteration rather than file-static (the parser
caches a recycled request on it, and a cache shared between runs is a leak
reported on every input), and that `env()` is overridden the way
`test_httprequestparser.c` overrides it. That last one is not optional: without
it the target crashes on the first well-formed `Content-Length` it sees, inside
`env()`, and a target that crashes on valid input tests nothing but its own
fixture.

Those two tests remain worth keeping and are not what this replaces: they walk
100 buffers from a seeded PRNG, which is a different question from what
coverage feedback answers. A header spelled correctly enough to reach
`__validate_content_length` is not something a random draw produces.

clang builds the targets against libFuzzer and is the better engine where it
is available. With gcc, which has none, `fuzz_main.c` supplies the loop and
`-fsanitize-coverage=trace-pc` the feedback; `cwfr_fuzz_instrument()` sets
both up, so the build line above is the same for either compiler. The driver
takes `-seconds=`, `-runs=`, `-seed=`, `-artifacts=<dir>`, `-dict=<file>`,
`-timeout=<s>` and `-max_len=<bytes>` (at most 1 MiB), and a file instead of
a directory to replay one input. A trap, an abort, a UBSan report or an input
running past `-timeout` all save the input first.

### Dictionaries

`-dict=<file>` gives the mutator a list of tokens to splice in whole. It earns
its place where the grammar has long literals: `Transfer-Encoding` is
seventeen bytes that have to land in order before the branch behind it means
anything, and random edits get there slowly. Measured over a minute at a fixed
seed, on `request`, the edge count went from 135 to 184, and taken branches in
`httprequestparser.c` from 71.8% to 75.6%.

Dictionaries live in `fuzz/dict/<target>.dict`; `cwfr_add_fuzzer()` records
the path in the manifest and `run.sh` passes it when the file exists. The format is libFuzzer's, and libFuzzer
is the stricter parser of the two: it knows `\xNN`, `\\` and `\"` and rejects
the whole file on the first line it cannot read. `\r\n` is not among them, so
the files use `\x0d\x0a`.

The driver prints `dict N` in its summary when it loaded one, because a run
given a dictionary it could not read otherwise looks exactly like a run given
none.

### Coverage

The targets say how many edges they reached, which is a number without a scale.
For one with a scale, build with `--coverage` and read it with gcov:

```bash
cmake -S backend -B build-cov -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DBUILD_TESTS=yes -DBUILD_FUZZERS=yes -DINCLUDE_HTTP3=yes \
      -DCMAKE_C_FLAGS="--coverage -fsanitize=address -O0 -g" \
      -DCMAKE_EXE_LINKER_FLAGS="--coverage -fsanitize=address" \
      -DCMAKE_SHARED_LINKER_FLAGS="--coverage -fsanitize=address"
cmake --build build-cov --target fuzz_request
find build-cov -name '*.gcda' -delete
./build-cov/exec/fuzz_request -seconds=60 backend/core/tests/fuzz/corpus/request
gcov -b -o build-cov/core/protocols/http/server/parsers/CMakeFiles/*.dir \
     httprequestparser.c.o
```

Delete the `.gcda` files before each run or the counters accumulate across
targets, and a number measured that way says nothing about any one of them.

At a minute a target with dictionaries, the parsers sit at 80–91% of lines.
Worth reading per function rather than per file: `hpack` looked like 60% until
the encoder half was accounted for, and the encoder was not 60% covered — it
was not entered at all. Adding the round trip to the target took the file to
91%, which is the number the decoder alone had deserved all along.

### Continuous fuzzing

`fuzz/oss-fuzz/` holds a tested OSS-Fuzz / ClusterFuzzLite integration — build
script, Dockerfile and `project.yaml` — with its own readme.

`tests/ci.sh fuzz` is the gate; `FUZZ_PROFILE=long tests/ci.sh fuzz` is the
scheduled run. A reproducer belongs in the seed corpus once the bug behind it
is fixed, next to a unit test that pins the fix. Targets registered with
`NO_LEAK_CHECK` (`h2_session`) run with `detect_leaks=0` both here and under
OSS-Fuzz, where `build.sh` writes the matching `.options` file.

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

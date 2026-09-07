# Installing cwfr

This document describes how to build, test, and install the cwfr framework.

There are two ways to build against cwfr, and they are not alternatives so much
as two stages of the same workflow:

* **Embedded** — the framework is a git submodule (conventionally at `core/`)
  pulled into a host project with `add_subdirectory(core)`, which builds the
  framework and the application together. See [Integrating into a host
  project](#3-integrating-into-a-host-project).

* **Against an installed framework** — the framework is built and installed
  once, and the application is a separate CMake project that finds it with
  `find_package(cwfr)`. Handlers are then written and rebuilt without the core
  sources present at all. See [Building an application against an installed
  framework](#8-building-an-application-against-an-installed-framework).

Nothing from the application is compiled into `libcwfr_framework.so`: the
framework binary is application-independent, so one installed copy serves any
number of applications. An application reaches the framework through
`main.modules` in its config — see
[The application module](#the-application-module).

## 1. Requirements

### Toolchain

| Tool  | Minimum version |
|-------|-----------------|
| Linux kernel with epoll | any modern distribution |
| Glibc | 2.35 |
| GCC   | 9.5.0 |
| CMake | 3.12.4 |
| Ninja or GNU Make | any recent |

### Required libraries (development packages)

| Library | Used for |
|---------|----------|
| PCRE2 (`libpcre2-8.so.0`) | routing and redirect regular expressions |
| Zlib | gzip compression |
| OpenSSL 1.1.1k+ | TLS/SSL, hashing |
| LibXml2 | XML processing |
| libidn2 | internationalized domain names |
| libunistring | Unicode string handling |
| POSIX threads (`pthread`) | worker threads |

### Optional libraries (database drivers)

| Library | CMake switch |
|---------|--------------|
| PostgreSQL client (`libpq`) | `-DINCLUDE_POSTGRESQL=yes` |
| MySQL / MariaDB client | `-DINCLUDE_MYSQL=yes` |
| hiredis (Redis) | `-DINCLUDE_REDIS=yes` |
| SQLite 3 | `-DINCLUDE_SQLITE=yes` |

A driver is compiled in only when its switch is `yes` **and** the library is
found; `cmake/` ships the `Find*.cmake` modules used for lookup.

### Installing dependencies

Debian / Ubuntu:

```bash
sudo apt install build-essential cmake ninja-build \
    libpcre2-dev zlib1g-dev libssl-dev libxml2-dev \
    libidn2-dev libunistring-dev

# Optional database drivers
sudo apt install libpq-dev libmariadb-dev libhiredis-dev libsqlite3-dev
```

Fedora / RHEL:

```bash
sudo dnf install gcc cmake ninja-build \
    pcre2-devel zlib-devel openssl-devel libxml2-devel \
    libidn2-devel libunistring-devel

# Optional database drivers
sudo dnf install libpq-devel mariadb-connector-c-devel hiredis-devel sqlite-devel
```

## 2. Getting the sources

As a submodule of a host project:

```bash
git submodule add <cwfr-repo-url> core
git submodule update --init --recursive
```

Or, when cloning a host project that already embeds cwfr:

```bash
git clone --recurse-submodules <host-repo-url>
```

## 3. Integrating into a host project

Minimal host `CMakeLists.txt` (the framework lives in `core/`):

```cmake
cmake_minimum_required(VERSION 3.12.4)
project(myapp LANGUAGES C)

# Find*.cmake modules shipped with the framework
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/core/cmake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/exec")

add_compile_options(-fPIC)
add_link_options(-rdynamic)

# Required dependencies
find_package(Threads REQUIRED)
find_package(PCRE2 REQUIRED)
add_definitions(-DPCRE2_CODE_UNIT_WIDTH=8)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(IDN2 REQUIRED)
find_package(UNISTRING REQUIRED)

# Optional database drivers (repeat for MySQL / Redis / SQLite)
if(INCLUDE_POSTGRESQL STREQUAL yes)
    find_package(PostgreSQL)
endif()
if(PostgreSQL_FOUND AND INCLUDE_POSTGRESQL STREQUAL yes)
    add_definitions(-DPostgreSQL_FOUND)
endif()

add_subdirectory(core)
add_subdirectory(myapp)

# cwfr, migrate, libcwfr_framework.so, the headers and the CMake package all
# install themselves from core/cmake/install.cmake. Only the application's own
# output is left to declare here.
install(TARGETS app LIBRARY DESTINATION lib/cwfr)
cwfr_install_handlers()
cwfr_install_migrations()
```

That listing is complete: everything the core needs beyond it, `CMAKE_BUILD_TYPE`
included, it defines for itself. Drop the two application lines and it is also a
valid **framework-only** host project — which is how the framework gets built and
installed once, for applications that are built separately afterwards
(section 8).

What `add_subdirectory(core)` provides:

* **`cwfr`** — the server executable.
* **`migrate`** — the database migration runner.
* **`cwfr::framework`** — a single shared library (`libcwfr_framework.so`)
  aggregating the entire framework. Both `cwfr` and every dynamically loaded
  handler `.so` link against it, so the framework state (database pools,
  configuration, i18n) exists as one instance at runtime. The plain target name
  `cwfr_framework` still works; `cwfr::framework` is the spelling that is also
  valid against an installed package.
* **CMake helpers** — `cwfr_add_lib()` and `cwfr_add_subdirs()` from
  `cmake/cwfr.cmake`, and `cwfr_add_handlers()`, `cwfr_add_migrations()`,
  `cwfr_install_handlers()`, `cwfr_install_migrations()` from `cmake/app.cmake`.
* **`install()` rules** for everything the framework owns, from
  `cmake/install.cmake`.

Handlers are compiled as separate shared libraries linking `cwfr::framework`
and are mapped to routes in `config.json`.

### The application module

The framework needs three things from an application that it cannot invent
itself: the middlewares the config refers to by name, and the destructors for
whatever the application hangs off `httpctx_t`/`wsctx_t`. It obtains them at
runtime, not at link time.

Build the application's own code — models, middlewares, contexts, helpers — into
one shared library, and have it export `app_init()`:

```c
/* app_init.c */
#include "model.h"
#include "httpcontext.h"
#include "wscontext.h"
#include "middleware_registry.h"

int app_init(void) {
    /* ctx->user_data is set by the application, so the application says how it
     * is released. NULL (the default) means the core frees nothing.
     *
     * One owner per process: with several modules in main.modules, a second one
     * claiming the destructor is refused rather than silently taking over. */
    if (!httpctx_set_user_data_free(model_free) || !wsctx_set_user_data_free(model_free))
        return 0;

    if (!middleware_registry_register("middleware_http_auth", middleware_http_auth))
        return 0;

    return 1;
}
```

```cmake
add_library(app SHARED app_init.c)
target_link_libraries(app PRIVATE
    "-Wl,--whole-archive" mymodels mymiddlewares "-Wl,--no-whole-archive"
    cwfr::framework)
```

Then name it in the config:

```json
"main": {
    "modules": ["/opt/myapp/lib/cwfr/libapp.so"]
}
```

`cwfr` and `migrate` `dlopen()` each listed module and call its `app_init()`
before the `servers` section is parsed — the middleware names have to exist
before a route can reference one. Paths are passed to `dlopen()` verbatim,
exactly like a route's `"file"`.

On a hard reload the middleware registry is cleared and `app_init()` runs again,
so it must be idempotent. The module itself is never `dlclose()`d: a rebuilt
application module needs a restart, not a reload — the same constraint handler
`.so` files carry.

> **Migrating from `CWFR_EXTRA_FW_LIBS`.** Applications used to be baked into
> `libcwfr_framework.so` by listing their static archives in that variable, and
> to supply `middlewares_init()`, `httpctx_init/clear` and `wsctx_init/clear` as
> link-time symbols. All five are gone from the core:
>
> * `httpctx_init/clear` and `wsctx_init/clear` now **belong to the core**.
>   Delete them from the application — leaving them in place is a
>   `multiple definition` link error — and register the destructor for
>   `ctx->user_data` with `httpctx_set_user_data_free()` /
>   `wsctx_set_user_data_free()` instead.
> * `middlewares_init()` is **no longer declared or called**. Rename it to
>   `app_init()` and move the application into a module named by
>   `main.modules`. A module that still exports `middlewares_init()` is
>   diagnosed by name at start-up rather than failing later as an
>   unrelated-looking "failed to find middleware".
>
> `CWFR_EXTRA_FW_LIBS` itself still works, but it produces an
> application-specific framework binary that cannot be shared — and it can no
> longer supply the registrations, which have to come from a module either way.

## 4. Configuring and building

From the host project root:

```bash
cmake -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DINCLUDE_POSTGRESQL=yes \
      -DINCLUDE_MYSQL=yes \
      -DINCLUDE_REDIS=yes \
      -DINCLUDE_SQLITE=yes \
      -B build .

ninja -C build
```

Build output goes to `build/exec/`: the `cwfr` and `migrate` executables,
`libcwfr_framework.so`, and (depending on the host project layout) `handlers/`
and `migrations/` subdirectories with the compiled `.so` modules.

### Configure options

| Option | Default | Meaning |
|--------|---------|---------|
| `CMAKE_BUILD_TYPE` | — | `Release`, `Debug`, or `RelWithDebInfo` |
| `INCLUDE_POSTGRESQL` | off | build the PostgreSQL driver (`yes`) |
| `INCLUDE_MYSQL` | off | build the MySQL/MariaDB driver (`yes`) |
| `INCLUDE_REDIS` | off | build the Redis (hiredis) driver (`yes`) |
| `INCLUDE_SQLITE` | off | build the SQLite driver (`yes`) |
| `BUILD_TESTS` | off | build the framework test suite (`yes`) |

### Build modes

* **Release** — optimized production build.
* **Debug** — debug symbols plus `-fsanitize=address`, `-fsanitize=leak`, and
  `-fanalyzer` (when enabled by the host project). Use for development; do not
  deploy sanitized builds to production.
* **RelWithDebInfo** — optimized build with debug information.

#### Profiling memory under AddressSanitizer

Always export `detect_stack_use_after_return=0` before measuring memory on a
sanitized build:

```bash
ASAN_OPTIONS=detect_stack_use_after_return=0 ./exec/cwfr -c ../config.json
```

Recent AddressSanitizer runtimes enable use-after-return detection by default.
It gives every thread a private *fake stack* region (~11 MB) and hands out
frames round-robin, so its pages fault in gradually — a completely idle server
shows a steady RSS climb of roughly 4.5 KB/s (~16 MB/h) that looks exactly like
a leak. Growth is bounded by the fake-stack regions (≈11 MB per thread, plus
1/8 for shadow memory), and Release builds are unaffected.

Telling the artifact apart from a real leak:

* `ASAN_OPTIONS=print_stats=1` reports **identical** malloc/free counters at
  15 s and 150 s of idle — a real leak allocates.
* LeakSanitizer stays silent at exit.
* `strace -c` shows no new `mmap`/`brk`; only already-mapped anonymous regions
  grow.
* Setting `detect_stack_use_after_return=0` makes the growth disappear.

## 5. Running the tests

Configure with tests enabled, build, then run through CTest:

```bash
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
      -DINCLUDE_POSTGRESQL=yes -B build .
ninja -C build
ctest --test-dir build --output-on-failure
```

The database driver tests only run for drivers that were enabled at configure
time.

## 6. Installing

```bash
cmake --install build --prefix /opt/cwfr
```

Installed layout:

```
<prefix>/
├── bin/
│   ├── cwfr                      # server executable
│   └── migrate                   # migration runner
├── include/cwfr/                 # public headers, flat (see below)
└── lib/
    ├── cwfr/
    │   ├── libcwfr_framework.so  # shared framework library
    │   ├── libapp.so             # the application module
    │   ├── handlers/             # handler .so modules (per service/route)
    │   └── migrations/           # migration .so modules
    └── cmake/cwfr/               # the CMake package: find_package(cwfr)
```

`cwfr` and `migrate` carry an `INSTALL_RPATH` of `$ORIGIN/../lib/cwfr`, so the
installed tree is relocatable — no `ldconfig` or `LD_LIBRARY_PATH` needed as
long as the `bin/` ↔ `lib/cwfr/` layout is preserved.

`libcwfr_framework.so` carries a `SONAME` of `libcwfr_framework.so.<major>`.
Handler modules record it, so a framework upgrade that breaks them fails at load
time with a clear error instead of at runtime with a corrupt struct.

The headers are installed **flat** into one directory. The framework's sources
include each other by bare name (`"httprequest.h"`, not
`"protocols/http/httprequest.h"`) and rely on some fifty include directories to
resolve them; flattening reproduces that with a single `-I` and keeps the
internal layout out of the published interface. The install refuses to run if two
headers anywhere in the core ever share a basename.

Host projects may redirect the handler and migration trees independently of
the prefix at configure time:

```bash
cmake ... \
    -DCWFR_HANDLER_INSTALL_DIR=/srv/myapp/handlers \
    -DCWFR_MIGRATION_INSTALL_DIR=/srv/myapp/migrations \
    -B build .
```

## 7. Running the server

```bash
<prefix>/bin/cwfr -c /path/to/config.json      # detaches (Release builds)
<prefix>/bin/cwfr -c /path/to/config.json -f   # stays in the foreground
```

A `Release` or `RelWithDebInfo` build detaches from the terminal unless `-f` is
given; `-f` is what a container runtime wants, since a supervisor watching a
process that forks and exits reads it as one that died.

**Either way the exit status is meaningful.** The process does not report success
until the configuration has been read, accepted and applied *and every worker is
listening*, so `cwfr -c config.json && ...` behaves as written: a rejected
configuration and a socket that cannot be bound both exit non-zero, and neither
leaves a process behind. The detaching parent stays alive until the child gets
that far, which also means the server is already accepting connections by the
time the command returns.

`config.json` defines workers/threads, servers (virtual hosts with
route-to-handler mappings), database connections, storage backends, and the
task manager. See the documentation for the full reference:
[https://cwebframework.tech/en/introduction.html](https://cwebframework.tech/en/introduction.html)

### Deploying a rebuilt handler

A handler `.so` rebuilt at the same path is picked up by `SIGUSR1` — the path in
`config.json` does not have to change. The loader will not do that on its own, so
the server loads such a file through a copy it puts next to the original,
`.cwfr-shadow-<pid>-<seq>-<name>`; that is what keeps `$ORIGIN` in the module's
RPATH pointing at its own directory, and what keeps ASan reports, gdb and core
dumps able to name a function, a file and a line.

Two things this asks of a deployment:

* **the directory holding the `.so` should be writable** by the server. Where it
  is not, the copy falls back to `main.tmp` and `$ORIGIN` no longer resolves to
  the module's own directory — private libraries next to the handler stop being
  found. It is logged when it happens.
* **send `SIGUSR1` after the build has finished**, not during it. A linker writes
  a `.so` by unlinking and re-creating it, so mid-write the path holds a truncated
  ELF; a signal arriving then is refused at the validation stage (the server keeps
  serving the old configuration) and has to be repeated. Building into a temporary
  directory and publishing with an atomic `rename` avoids the window entirely.

The copies are unlinked when the process exits, and copies left behind by a
process that was killed are swept by the next start. A copy deliberately outlives
the library's unload, so a core dump has to be investigated *before* the server is
restarted.

The application module from `main.modules` is picked up the same way, with one
extra step: handlers reach it by SONAME rather than by path, so its copy is given
a SONAME of its own for each generation and the copies of the handlers that need
it are pointed at that name (`docs/hotreload/01-soname-per-generation.md`). Two
consequences for an application:

* a module built **without a SONAME** (`NO_SONAME` in CMake, no `-Wl,-soname`)
  cannot be renamed, so it is not swapped -- the running one is kept, the reason
  is logged, and the rest of the reload happens as usual. `cwfr_add_lib()` and a
  plain `add_library(app SHARED ...)` both give one, so this is only reachable on
  purpose;
* **static state inside the module does not survive a reload.** Each generation
  runs the `app_init()` of its own instance. Anything that must outlive a reload
  belongs in the database, a cache or a session.

**API changes** in the public headers. All three are called by the core only, but
a consumer that did call them needs updating:

* `routeloader_load_lib()` takes the fallback directory for the copy and the
  generation's SONAME map;
* `httpctx_init()` / `wsctx_init()` take the destructor for `ctx->user_data`,
  which now belongs to the configuration generation rather than to the process;
  `httpctx_t` and `wsctx_t` carry a field for it. `httpctx_set_user_data_free()`
  and `wsctx_set_user_data_free()` keep their signatures and are still what an
  `app_init()` calls -- they now record into the configuration being built, so
  calling them from anywhere else fails and says so.

Applying database migrations:

```bash
<prefix>/bin/migrate -c /path/to/config.json up
```

## 8. Building an application against an installed framework

This is what makes the framework worth installing: build and install it once,
then write and rebuild handlers afterwards, with the core sources absent.

Install the framework (section 6), then point a standalone application project
at the package:

```bash
cmake -S myapp -B build -DCMAKE_BUILD_TYPE=Release \
      -Dcwfr_DIR=/opt/cwfr/lib/cmake/cwfr
cmake --build build -j$(nproc)
cmake --install build --prefix /srv/myapp
```

(`-Dcwfr_DIR=...` is only needed when the framework was installed to a prefix
CMake does not search by default; with `--prefix /usr/local`, `find_package(cwfr)`
locates it on its own.)

The application's `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.12.4)
project(myapp LANGUAGES C)

find_package(cwfr 1.0 REQUIRED)

add_compile_options(-fPIC)
add_link_options(-rdynamic)

add_subdirectory(models)        # cwfr_add_lib(models LINK_LIBS cwfr::framework)
add_subdirectory(middlewares)

# The application module -- see "The application module" in section 3.
add_library(app SHARED app_init.c)
target_link_libraries(app PRIVATE
    "-Wl,--whole-archive" models middlewares "-Wl,--no-whole-archive"
    cwfr::framework)
set_target_properties(app PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/exec"
    INSTALL_RPATH "$ORIGIN")

add_subdirectory(routes)        # cwfr_add_handlers(LINK_LIBS cwfr::framework app)
add_subdirectory(migrations)    # cwfr_add_migrations(LINK_LIBS cwfr::framework app)

install(TARGETS app LIBRARY DESTINATION lib/cwfr)
cwfr_install_handlers()
cwfr_install_migrations()
```

`find_package(cwfr)` supplies:

* **`cwfr::framework`** — the imported shared library, carrying the include path
  for `<prefix>/include/cwfr` *and* the third-party include paths and feature
  macros the public headers need (`PCRE2_CODE_UNIT_WIDTH`, `PostgreSQL_FOUND`,
  …). Those macros gate struct members in the database headers, so the package
  imposes exactly the set the framework was built with — an application does not
  get to choose a different one.
* **the build helpers** — `cwfr_add_lib()`, `cwfr_add_handlers()`,
  `cwfr_add_migrations()`, `cwfr_add_subdirs()`, `cwfr_install_handlers()`,
  `cwfr_install_migrations()`.

`find_package(cwfr 1.0 REQUIRED)` matches by major version, so an application
refuses to configure against a framework release it was not written for.

The example application in this repository builds both ways from the same files:
as `add_subdirectory(app)` from the monorepo root, and on its own with
`cmake -S backend/app -B build -Dcwfr_DIR=...`. Its `CMakeLists.txt` shows how
the standalone preamble is kept to the one `if()` block that differs.

## Troubleshooting

* **`Could NOT find PCRE2`** — install the PCRE2 development package
  (`libpcre2-dev` / `pcre2-devel`), not the legacy PCRE 8.x one.
* **A database driver silently missing** — the corresponding
  `-DINCLUDE_<DB>=yes` switch was not passed, or the client library was not
  found at configure time; check the CMake output for
  `Include Postgresql/Mysql/Redis/Sqlite` status lines.
* **`libcwfr_framework.so: cannot open shared object file`** — the executable
  was moved without the `lib/cwfr/` directory; keep the installed layout
  intact or reinstall.
* **Stale configure results** after installing a missing dependency — remove
  the build directory (or at least `CMakeCache.txt`) and reconfigure.

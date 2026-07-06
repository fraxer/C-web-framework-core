# Installing cwfr

This document describes how to build, test, and install the cwfr framework.

cwfr is not built standalone. The framework is embedded into a host project as a
git submodule (conventionally at `core/`) and pulled in with
`add_subdirectory(core)`. The host project owns the toolchain setup: it calls
`project()`, locates the dependencies with `find_package()`, sets compile
options, and defines the `install()` rules. See [Integrating into a host
project](#integrating-into-a-host-project) for a minimal host `CMakeLists.txt`.

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
| PCRE 8.x (`libpcre.so.3`) | routing and redirect regular expressions |
| Zlib | gzip compression |
| OpenSSL 1.1.1k+ | TLS/SSL, hashing |
| LibXml2 | XML processing |
| libidn2 | internationalized domain names |
| libunistring | Unicode string handling |
| Argon2 (`libargon2`) | password hashing |
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
    libpcre3-dev zlib1g-dev libssl-dev libxml2-dev \
    libidn2-dev libunistring-dev libargon2-dev

# Optional database drivers
sudo apt install libpq-dev libmariadb-dev libhiredis-dev libsqlite3-dev
```

Fedora / RHEL:

```bash
sudo dnf install gcc cmake ninja-build \
    pcre-devel zlib-devel openssl-devel libxml2-devel \
    libidn2-devel libunistring-devel libargon2-devel

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
find_package(PCRE REQUIRED)
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

# Application static archives to bake into libcwfr_framework.so
# (models, middlewares, contexts, ...). Optional.
set(CWFR_EXTRA_FW_LIBS mymodels mymiddlewares)

add_subdirectory(core)
add_subdirectory(myservice)

install(TARGETS cwfr migrate RUNTIME DESTINATION bin)
install(TARGETS cwfr_framework LIBRARY DESTINATION lib/cwfr)
```

What `add_subdirectory(core)` provides:

* **`cwfr`** — the server executable.
* **`migrate`** — the database migration runner.
* **`cwfr_framework`** — a single shared library (`libcwfr_framework.so`)
  aggregating the entire framework. Both `cwfr` and every dynamically loaded
  handler `.so` link against it, so the framework state (database pools,
  configuration, i18n) exists as one instance at runtime.
* **CMake helpers** — `cwfr_add_lib()` and `cwfr_add_subdirs()` from
  `cmake/cwfr.cmake` for declaring static libraries and recursing into
  subdirectories.
* **`CWFR_EXTRA_FW_LIBS` extension point** — set this list *before*
  `add_subdirectory(core)` to aggregate your application's static archives
  (models, middlewares implementing the `middlewares_init()` hook, contexts)
  into `libcwfr_framework.so`, making their symbols visible to handler modules.

Handlers are compiled as separate shared libraries linking `cwfr_framework`
and are mapped to routes in `config.json`.

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
└── lib/cwfr/
    ├── libcwfr_framework.so      # shared framework library
    ├── handlers/                 # handler .so modules (per service/route)
    └── migrations/               # migration .so modules
```

`cwfr` and `migrate` carry an `INSTALL_RPATH` of `$ORIGIN/../lib/cwfr`, so the
installed tree is relocatable — no `ldconfig` or `LD_LIBRARY_PATH` needed as
long as the `bin/` ↔ `lib/cwfr/` layout is preserved.

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
<prefix>/bin/cwfr -c /path/to/config.json
```

`config.json` defines workers/threads, servers (virtual hosts with
route-to-handler mappings), database connections, storage backends, and the
task manager. See the documentation for the full reference:
[https://cwebframework.tech/en/introduction.html](https://cwebframework.tech/en/introduction.html)

Applying database migrations:

```bash
<prefix>/bin/migrate -c /path/to/config.json up
```

## Troubleshooting

* **`Could NOT find PCRE`** — install the PCRE **8.x** development package
  (`libpcre3-dev` / `pcre-devel`), not PCRE2.
* **A database driver silently missing** — the corresponding
  `-DINCLUDE_<DB>=yes` switch was not passed, or the client library was not
  found at configure time; check the CMake output for
  `Include Postgresql/Mysql/Redis/Sqlite` status lines.
* **`libcwfr_framework.so: cannot open shared object file`** — the executable
  was moved without the `lib/cwfr/` directory; keep the installed layout
  intact or reinstall.
* **Stale configure results** after installing a missing dependency — remove
  the build directory (or at least `CMakeCache.txt`) and reconfigure.

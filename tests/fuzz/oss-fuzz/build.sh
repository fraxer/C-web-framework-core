#!/bin/bash -eu
#
# Build script for OSS-Fuzz and ClusterFuzzLite.
#
# Both set CC/CXX, CFLAGS and LIB_FUZZING_ENGINE, and expect the finished
# targets in $OUT together with the seeds and dictionaries they should start
# from. Nothing here picks a sanitizer or an engine: those arrive in the
# environment, and tests/CMakeLists.txt links $LIB_FUZZING_ENGINE when it sees
# one.
#
# HTTP/3 is off: it wants OpenSSL 3.5 and the base image carries an older one.
# The targets that do not touch QUIC no longer depend on it. PostgreSQL is off
# for the same reason it is off in any build that only needs the parsers --
# nothing the fuzzers reach goes near a database.

# The framework builds from a host project rather than on its own: the
# find_package calls for PCRE2, OpenSSL and the rest belong to the host, not to
# core/. This is the framework-only listing from INSTALL.md section 3, with the
# two application lines dropped as that section describes.
mkdir -p "$SRC/host"
cp -r "$SRC/cwfr" "$SRC/host/core"

cat > "$SRC/host/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.12.4)
project(cwfr_fuzz LANGUAGES C)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/core/cmake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/exec")

add_compile_options(-fPIC)
add_link_options(-rdynamic)

find_package(Threads REQUIRED)
find_package(PCRE2 REQUIRED)
add_definitions(-DPCRE2_CODE_UNIT_WIDTH=8)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(IDN2 REQUIRED)
find_package(UNISTRING REQUIRED)

enable_testing()
add_subdirectory(core)
CMAKE

# The framework is a shared library and the targets link it dynamically, so
# each binary has to be able to find it where ClusterFuzz will put it: next to
# itself, under lib/. $ORIGIN is resolved by the loader at run time, and the
# single quotes keep cmake and the shell from expanding it first.
cmake -S "$SRC/host" -B "$SRC/build" \
      -DCMAKE_BUILD_TYPE=Debug \
      -DBUILD_TESTS=yes \
      -DBUILD_FUZZERS=yes \
      -DINCLUDE_HTTP3=no \
      -DINCLUDE_POSTGRESQL=no \
      -DCMAKE_EXE_LINKER_FLAGS="-Wl,-rpath,\$ORIGIN/lib" \
      -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON

cmake --build "$SRC/build" -j"$(nproc)"

# Everything the targets need at run time travels with them: OSS-Fuzz copies
# $OUT somewhere else entirely before running anything in it.
mkdir -p "$OUT/lib"
cp -a "$SRC"/build/core/framework_shared/libcwfr_framework.so* "$OUT/lib/"

for exe in "$SRC"/build/exec/fuzz_*; do
    name=$(basename "$exe")
    target=${name#fuzz_}

    cp "$exe" "$OUT/$name"

    # The seed corpus travels as a zip named after the target; ClusterFuzz
    # unpacks it on the first run and grows it from there.
    if [ -d "$SRC/cwfr/tests/fuzz/corpus/$target" ]; then
        zip -qj "$OUT/${name}_seed_corpus.zip" "$SRC/cwfr/tests/fuzz/corpus/$target"/*
    fi

    if [ -f "$SRC/cwfr/tests/fuzz/dict/$target.dict" ]; then
        cp "$SRC/cwfr/tests/fuzz/dict/$target.dict" "$OUT/$name.dict"
    fi

    # A target registered with NO_LEAK_CHECK (cmake/fuzz.cmake) runs without
    # LeakSanitizer here too, the way tests/fuzz/run.sh runs it locally.
    if grep -q "^$name|.*|0\$" "$SRC/build/fuzz-targets.txt"; then
        printf '[asan]\ndetect_leaks=0\n' > "$OUT/$name.options"
    fi
done

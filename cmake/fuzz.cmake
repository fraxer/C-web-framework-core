# Shared by framework and application fuzz targets. Keep instrumentation on the
# code under test, not just on LLVMFuzzerTestOneInput.
function(cwfr_fuzz_instrument)
    if(DEFINED ENV{LIB_FUZZING_ENGINE})
        return() # OSS-Fuzz supplies both coverage and sanitizers in CFLAGS.
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined
                        -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_compile_options(-fsanitize=fuzzer-no-link)
        add_link_options(-fsanitize=fuzzer-no-link)
    else()
        add_compile_options(-fsanitize-coverage=trace-pc)
        add_compile_definitions(CWFR_FUZZ_COVERAGE)
    endif()
endfunction()

# Registers a fuzz target and records it in fuzz-targets.txt, the manifest
# tests/fuzz/run.sh runs from:
#
#   name|executable|seed corpus|dictionary|engine|leaks
#
# NO_LEAK_CHECK marks a target whose fixture cannot release everything the code
# under test hands to an event loop it does not have; run.sh then runs it with
# detect_leaks=0 and says so. ASan and UBSan stay on.
function(cwfr_add_fuzzer name)
    cmake_parse_arguments(FUZZ "NO_LEAK_CHECK" "CORPUS;DICTIONARY" "SOURCES;LIBRARIES" ${ARGN})
    add_executable(${name} ${FUZZ_SOURCES})
    if(NOT DEFINED ENV{LIB_FUZZING_ENGINE})
        target_compile_options(${name} PRIVATE -fsanitize=address,undefined
            -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
        target_link_options(${name} PRIVATE -fsanitize=address,undefined)
    endif()
    if(DEFINED ENV{LIB_FUZZING_ENGINE})
        target_link_options(${name} PRIVATE $ENV{LIB_FUZZING_ENGINE})
        set(engine libfuzzer)
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_compile_options(${name} PRIVATE -fsanitize=fuzzer-no-link)
        target_link_options(${name} PRIVATE -fsanitize=fuzzer)
        set(engine libfuzzer)
    else()
        target_compile_options(${name} PRIVATE -fsanitize-coverage=trace-pc)
        target_sources(${name} PRIVATE ${CWFR_FUZZ_DRIVER})
        # Coverage of the mutator/driver itself is not target coverage.
        set_source_files_properties(${CWFR_FUZZ_DRIVER} PROPERTIES
            COMPILE_OPTIONS "-fno-sanitize-coverage=trace-pc")
        set(engine gcc)
    endif()
    target_link_libraries(${name} PRIVATE ${FUZZ_LIBRARIES})
    if(FUZZ_NO_LEAK_CHECK)
        set(leaks 0)
    else()
        set(leaks 1)
    endif()
    file(APPEND "${CMAKE_BINARY_DIR}/fuzz-targets.txt"
         "${name}|${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${name}|${FUZZ_CORPUS}|${FUZZ_DICTIONARY}|${engine}|${leaks}\n")
endfunction()

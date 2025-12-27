cmake_minimum_required(VERSION 3.12.4)

# Include directories for the main project
# Use relative paths since backend/core is a git submodule
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../misc
    ${CMAKE_CURRENT_SOURCE_DIR}/../framework
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols
)

# Automatically collect all test files (exclude test_runner.c)
file(GLOB ALL_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/test_*.c")
list(REMOVE_ITEM ALL_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/runner.c")

# Test runner executable
add_executable(
    runner
    runner.c
    ${ALL_TEST_FILES}
    httprequestparser_stubs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../framework/taskmanager/taskmanager_calc.c
)

# Link test libraries
target_link_libraries(runner PRIVATE
    misc
    http_server_parsers
    http_server
    http
    connection
    domain
    socket
    openssl
    server
    route
    ratelimiter
    multiplexing
    ${PCRE_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    Threads::Threads
)

# Add test to CTest
add_test(NAME core_tests COMMAND runner)

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
)

# Link test libraries
target_link_libraries(runner PRIVATE misc ${CMAKE_DL_LIBS})

# Add test to CTest
add_test(NAME core_tests COMMAND runner)

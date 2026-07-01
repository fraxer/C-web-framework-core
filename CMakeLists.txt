cmake_minimum_required(VERSION 3.12.4)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/cwfr.cmake)

add_subdirectory(framework)
add_subdirectory(misc)
add_subdirectory(protocols)
add_subdirectory(src)
# cwfr_framework aggregates the framework static archives above, so it must be
# defined after them. apps (cwfr/migrate) link it, so they come last.
add_subdirectory(framework_shared)

# Enable tests if building with tests enabled
if(BUILD_TESTS STREQUAL yes)
    message(STATUS "Core tests found")
    add_subdirectory(tests)
endif()

add_subdirectory(apps)

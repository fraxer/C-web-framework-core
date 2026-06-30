cmake_minimum_required(VERSION 3.12.4)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/cpdy.cmake)

add_subdirectory(apps)
add_subdirectory(framework)
add_subdirectory(misc)
add_subdirectory(protocols)
add_subdirectory(src)

# Enable tests if building with tests enabled
if(BUILD_TESTS STREQUAL yes)
    message(STATUS "Core tests found")
    add_subdirectory(tests)
endif()

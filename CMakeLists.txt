cmake_minimum_required(VERSION 3.12.4)

add_subdirectory(apps)
add_subdirectory(framework)
add_subdirectory(misc)
add_subdirectory(protocols)
add_subdirectory(src)

# Enable tests if building with tests enabled
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    message(STATUS "Core tests found")
    add_subdirectory(tests)
endif()

cmake_minimum_required(VERSION 3.12.4)

project(migrate LANGUAGES C)

FILE(GLOB_RECURSE SOURCES *.c)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE cwfr_framework pthread)

# Find libcwfr_framework.so at install time (mirrors cwfr).
set_target_properties(${PROJECT_NAME} PROPERTIES INSTALL_RPATH "$ORIGIN/../lib/cwfr")

cmake_minimum_required(VERSION 3.12.4)

project(migrate LANGUAGES C)

FILE(GLOB_RECURSE SOURCES *.c)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE cpdy_framework pthread)

# Find libcpdy_framework.so at install time (mirrors cpdy).
set_target_properties(${PROJECT_NAME} PROPERTIES INSTALL_RPATH "$ORIGIN/../lib/cpdy")

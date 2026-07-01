cmake_minimum_required(VERSION 3.12.4)

project(cwfr LANGUAGES C)

FILE(GLOB_RECURSE SOURCES *.c)

add_executable(${PROJECT_NAME} ${SOURCES})

# cwfr gets the whole framework (moduleloader/misc/database/signal/...) from the
# shared library; handlers will link the same .so so the framework is a single
# shared instance. pthread/dl are used directly by the server main.
target_link_libraries(${PROJECT_NAME} PUBLIC cwfr_framework pthread dl)

# Find libcwfr_framework.so at install time: cwfr -> <prefix>/bin/, .so -> <prefix>/lib/cwfr/
set_target_properties(${PROJECT_NAME} PROPERTIES INSTALL_RPATH "$ORIGIN/../lib/cwfr")

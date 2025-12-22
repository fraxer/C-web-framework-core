cmake_minimum_required(VERSION 3.12.4)

FILE(GLOB SOURCES *.c *.h)

set(LIB_NAME misc)

add_library(${LIB_NAME} STATIC ${SOURCES})

target_include_directories(${LIB_NAME} PUBLIC . ${IDN2_INCLUDE_DIRS})

target_link_libraries(${LIB_NAME} config ZLIB::ZLIB OpenSSL::Crypto ${IDN2_LIBRARIES})

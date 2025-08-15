cmake_minimum_required(VERSION 3.12.4)

FILE(GLOB SOURCES *.c *.h)

set(LIB_NAME protocols)

add_library(${LIB_NAME} STATIC ${SOURCES})
set_target_properties(protocols PROPERTIES LINKER_LANGUAGE C)

target_include_directories(${LIB_NAME} PUBLIC .)

target_link_libraries(${LIB_NAME} connection smtp smtp_client websocket websocket_server http http_server http_client openssl)

MACRO(SUBDIRLIST result curdir)
    FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
    SET(dirlist "")
    FOREACH(child ${children})
        IF(IS_DIRECTORY ${curdir}/${child})
        LIST(APPEND dirlist ${child})
        ENDIF()
    ENDFOREACH()
    SET(${result} ${dirlist})
ENDMACRO()

SUBDIRLIST(SUBDIRS ${CMAKE_CURRENT_SOURCE_DIR})

foreach(DIR ${SUBDIRS})
    add_subdirectory(${DIR})
endforeach()
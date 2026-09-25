cmake_minimum_required(VERSION 3.12.4)

# Include directories for the main project
# Use relative paths since backend/core is a git submodule
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../misc
    ${CMAKE_CURRENT_SOURCE_DIR}/../misc/validation
    ${CMAKE_CURRENT_SOURCE_DIR}/../framework
    ${CMAKE_CURRENT_SOURCE_DIR}/../framework/session
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp
    ${CMAKE_CURRENT_SOURCE_DIR}/core
)

# --- Unit tests (no database required) ---
file(GLOB UNIT_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/unit/test_*.c")

# QUIC / HTTP/3 / QPACK tests only exist in an h3 build: the symbols they call
# are not linked into libcwfr_framework.so otherwise (framework_shared), so
# leaving them in the glob would fail the link rather than skip the tests.
# Suites self-register through a constructor, so dropping the file is all it
# takes -- runner.c needs no #ifdef.
if(NOT INCLUDE_HTTP3 STREQUAL yes)
    list(FILTER UNIT_TEST_FILES EXCLUDE REGEX "/test_(quic|h3|qpack)")
endif()

# The test client, linked into the runner as well as into its own tool.
#
# test_quic_conn.c runs it against a real server connection in one process
# (docs/http3/08-testing.md §2), which is the only way the timing-defined half
# of RFC 9002 -- the PTO exponent, persistent congestion, the idle timeout --
# is testable at all: those are minutes of wall clock and a lossy path, and
# here they are an injected clock and a queue. h3client.c is deliberately not
# included: the stand stops at the transport.
set(QUIC_CLIENT_SOURCES "")
if(INCLUDE_HTTP3 STREQUAL yes)
    set(QUIC_CLIENT_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/quicclient/quicclient.c)
endif()

add_executable(
    runner
    unit/runner.c
    ${UNIT_TEST_FILES}
    ${QUIC_CLIENT_SOURCES}
    unit/mail_stubs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../framework/taskmanager/taskmanager_calc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../framework/session/session.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/dkim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/mailheader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/mailattachment.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/mailmessage.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/dkimcanonparser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/dkimheaderparser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/mail.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/smtprequest.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/smtpresponse.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/client/smtpclienthandlers.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/client/parsers/smtpresponseparser.c
)

target_link_libraries(runner PRIVATE
    cwfr_framework
    ${PCRE2_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    idn2
    resolv
    ${CMAKE_DL_LIBS}
    Threads::Threads
)

# The QUIC TLS bridge test runs a real TLS 1.3 handshake between two instances
# in one process, which needs a certificate. Generated once and committed (valid
# to 2126) rather than produced at build time: a test that shells out to openssl
# fails differently on every machine, and this one is worthless without it.
if(INCLUDE_HTTP3 STREQUAL yes)
    target_compile_definitions(runner PRIVATE
        TEST_QUIC_CERT="${CMAKE_CURRENT_SOURCE_DIR}/data/quic_test_cert.pem"
        TEST_QUIC_KEY="${CMAKE_CURRENT_SOURCE_DIR}/data/quic_test_key.pem"
    )

    # The client's own header, and the endpoint's -- the stand builds a
    # connection the way quicendpoint.c does, so it needs to see both sides.
    target_include_directories(runner PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/quicclient
        ${CMAKE_CURRENT_SOURCE_DIR}/quic
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/udp
    )
endif()

# Two tiny shared objects the shadow-copy suite rebuilds in place: it publishes
# one at a working path, loads it, publishes the other over the same path and
# loads again. Both carry the SONAME libshadow_test_v1.so -- a rebuilt handler
# keeps its own, and the suite should not accidentally pass because they differ
# -- which is why the second one is built under the first one's name in a
# directory of its own.
add_library(shadow_test_v1 SHARED ${CMAKE_CURRENT_SOURCE_DIR}/data/shadow_module_v1.c)
add_library(shadow_test_v2 SHARED ${CMAKE_CURRENT_SOURCE_DIR}/data/shadow_module_v2.c)
set_target_properties(shadow_test_v2 PROPERTIES
    OUTPUT_NAME shadow_test_v1
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/shadow_v2)

# A pair of SONAMEs where one is the tail of the other, and a library that needs
# both: GNU ld then stores one string and points the second DT_NEEDED two bytes
# into it, which is the case elfsoname.c must refuse instead of overwriting.
add_library(shadow_dep_long SHARED ${CMAKE_CURRENT_SOURCE_DIR}/data/shadow_dep.c)
set_target_properties(shadow_dep_long PROPERTIES
    OUTPUT_NAME xxlibshadowdep
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/shadow_dep)
target_compile_definitions(shadow_dep_long PRIVATE SHADOW_DEP_NAME="long")

add_library(shadow_dep_short SHARED ${CMAKE_CURRENT_SOURCE_DIR}/data/shadow_dep_other.c)
set_target_properties(shadow_dep_short PROPERTIES
    OUTPUT_NAME shadowdep
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/shadow_dep)

add_library(shadow_merged SHARED ${CMAKE_CURRENT_SOURCE_DIR}/data/shadow_merged.c)
set_target_properties(shadow_merged PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/shadow_dep)
target_link_libraries(shadow_merged PRIVATE shadow_dep_long shadow_dep_short)

target_compile_definitions(runner PRIVATE
    TEST_SHADOW_V1="$<TARGET_FILE:shadow_test_v1>"
    TEST_SHADOW_V2="$<TARGET_FILE:shadow_test_v2>"
    TEST_SHADOW_MERGED="$<TARGET_FILE:shadow_merged>")
add_dependencies(runner shadow_test_v1 shadow_test_v2 shadow_merged)

add_test(NAME core_tests COMMAND runner)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_library(pthread_create_fail SHARED data/pthread_create_fail.c)
    target_link_libraries(pthread_create_fail PRIVATE ${CMAKE_DL_LIBS})
    add_test(NAME startup_lifetime
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/startup_lifetime.py
                $<TARGET_FILE:cwfr> $<TARGET_FILE:pthread_create_fail> ${CMAKE_BUILD_TYPE})
    set_tests_properties(startup_lifetime PROPERTIES TIMEOUT 120)
endif()

# HTTP/2 regressions can run independently of database and HTTP client suites.
set(H2_UNIT_TEST_FILES ${UNIT_TEST_FILES})
list(FILTER H2_UNIT_TEST_FILES INCLUDE REGEX "/test_(h2|hpack|httpfields)")
add_executable(h2_runner
    unit/runner.c ${H2_UNIT_TEST_FILES}
    unit/h3_config_stubs.c unit/mail_stubs.c)
target_link_libraries(h2_runner PRIVATE cwfr_framework
    ${OPENSSL_LIBRARIES} Threads::Threads ${CMAKE_DL_LIBS})
add_test(NAME h2_unit_tests COMMAND h2_runner)

# A small protocol-only runner keeps the QUIC/H3/QPACK signal visible when an
# unrelated framework regression breaks the broad runner.  It is an additional
# gate, not a replacement for core_tests.
if(INCLUDE_HTTP3 STREQUAL yes)
    set(H3_UNIT_TEST_FILES ${UNIT_TEST_FILES})
    list(FILTER H3_UNIT_TEST_FILES INCLUDE REGEX "/test_(quic|h3|qpack)")
    add_executable(h3_runner
        unit/runner.c
        ${H3_UNIT_TEST_FILES}
        ${QUIC_CLIENT_SOURCES}
        unit/h3_config_stubs.c
            unit/mail_stubs.c
    )
    target_include_directories(h3_runner PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/quicclient
        ${CMAKE_CURRENT_SOURCE_DIR}/quic
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/udp
    )
    target_compile_definitions(h3_runner PRIVATE
        TEST_QUIC_CERT="${CMAKE_CURRENT_SOURCE_DIR}/data/quic_test_cert.pem"
        TEST_QUIC_KEY="${CMAKE_CURRENT_SOURCE_DIR}/data/quic_test_key.pem"
    )
    target_link_libraries(h3_runner PRIVATE
        cwfr_framework ${PCRE_LIBRARIES} ${ZLIB_LIBRARIES}
        ${OPENSSL_LIBRARIES} idn2 resolv ${CMAKE_DL_LIBS} Threads::Threads
    )
    add_test(NAME h3_unit_tests COMMAND h3_runner)
endif()

# --- QUIC test client ---
#
# Not part of `runner`: it needs a server to talk to, so it is a tool rather
# than a unit test. It exists because nothing else on a typical machine can
# speak QUIC to this server -- the system curl is built without HTTP/3 -- and
# because the loss and reordering cases of docs/http3/08-testing.md §2 need a
# peer whose behaviour the test controls.
if(INCLUDE_HTTP3 STREQUAL yes)
    add_executable(quicclient
        quicclient/main.c
        quicclient/quicclient.c
        quicclient/h3client.c
    )

    target_include_directories(quicclient PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/quic/common
        ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/quic/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/quic/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http3/frame
        ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http3/qpack
        ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http3/server
    )

    target_link_libraries(quicclient PRIVATE
        cwfr_framework
        ${OPENSSL_LIBRARIES}
        Threads::Threads
        ${CMAKE_DL_LIBS}
    )
endif()

# --- Fuzzing (docs/http3/08-testing.md §5) ---
#
# Behind a flag because it changes how the *target* code is compiled: coverage
# instrumentation belongs to the whole framework, not to these binaries, and an
# ordinary build must not carry it.
#
# Two toolchains, one set of targets. With clang the entry point is libFuzzer's
# own (`-fsanitize=fuzzer`); with gcc, which has no libFuzzer, the driver in
# fuzz_main.c supplies the loop and gcc's `-fsanitize-coverage=trace-pc` supplies
# the feedback. The target files do not know the difference.
if(BUILD_FUZZERS STREQUAL "yes")
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT DEFINED ENV{LIB_FUZZING_ENGINE})
        add_executable(fuzz_driver_tests fuzz/test_driver.c)
        target_compile_options(fuzz_driver_tests PRIVATE -fno-sanitize-coverage=trace-pc)
        add_test(NAME fuzz_driver_tests COMMAND fuzz_driver_tests)
    endif()
    # Two groups. The HTTP/1.1 parsers, HPACK and Huffman need nothing beyond
    # the framework, and gating them on INCLUDE_HTTP3 -- as this block used to
    # -- kept them out of any build without the HTTP/3 stack, including the
    # stock OSS-Fuzz base image, whose OpenSSL is older than the 3.5 that
    # INCLUDE_HTTP3 requires.
    set(FUZZ_TARGET_NAMES
        huffman hpack h2_frame json cookie urlencoded multipart request request_sequence
        websocket websocket_sequence ws_deflate h2_session h2_connection http_response
        smtp_response jwt h1_connection text mail_message)

    if(INCLUDE_HTTP3 STREQUAL yes)
        list(APPEND FUZZ_TARGET_NAMES
            quic_packet quic_frame quic_tp h3_frame qpack_decode qpack_streams
            h3_priority qpack_dynamic qpack_session quic_stream h3_request quic_conn)
    endif()

    set(FUZZ_ID_quic_packet    1)
    set(FUZZ_ID_quic_frame     2)
    set(FUZZ_ID_quic_tp        3)
    set(FUZZ_ID_h3_frame       4)
    set(FUZZ_ID_qpack_decode   5)
    set(FUZZ_ID_qpack_streams  6)
    set(FUZZ_ID_huffman        7)
    set(FUZZ_ID_h3_priority    8)
    set(FUZZ_ID_hpack          9)
    set(FUZZ_ID_cookie         10)
    set(FUZZ_ID_urlencoded     11)
    set(FUZZ_ID_multipart      12)
    set(FUZZ_ID_request        13)
    set(FUZZ_ID_h2_frame       14)
    set(FUZZ_ID_json           15)
    set(FUZZ_ID_websocket      16)
    set(FUZZ_ID_ws_deflate     17)
    set(FUZZ_ID_h2_session     18)
    set(FUZZ_ID_request_sequence 19)
    set(FUZZ_ID_qpack_dynamic 20)
    set(FUZZ_ID_websocket_sequence 21)
    set(FUZZ_ID_qpack_session 22)
    set(FUZZ_ID_h2_connection 23)
    set(FUZZ_ID_quic_stream 24)
    set(FUZZ_ID_h3_request 25)
    set(FUZZ_ID_http_response 26)
    set(FUZZ_ID_smtp_response 27)
    set(FUZZ_ID_jwt 28)
    set(FUZZ_ID_h1_connection 29)
    set(FUZZ_ID_text 30)
    set(FUZZ_ID_mail_message 31)
    set(FUZZ_ID_quic_conn 32)

    foreach(name ${FUZZ_TARGET_NAMES})
        set(exe fuzz_${name})

        # h2_session: see the comment above its target in fuzz_targets.c.
        set(fuzz_leak_option)
        if(name STREQUAL h2_session)
            set(fuzz_leak_option NO_LEAK_CHECK)
        endif()

        cwfr_add_fuzzer(${exe} ${fuzz_leak_option}
            SOURCES fuzz/fuzz_targets.c
            CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/${name}"
            DICTIONARY "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/dict/${name}.dict"
            LIBRARIES cwfr_framework ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} Threads::Threads ${CMAKE_DL_LIBS})

        string(TOUPPER ${name} upper)
        target_compile_definitions(${exe} PRIVATE
            FUZZ_QUIC_PACKET=1
            FUZZ_QUIC_FRAME=2
            FUZZ_QUIC_TP=3
            FUZZ_H3_FRAME=4
            FUZZ_QPACK_DECODE=5
            FUZZ_QPACK_STREAMS=6
            FUZZ_HUFFMAN=7
            FUZZ_H3_PRIORITY=8
            FUZZ_HPACK=9
            FUZZ_COOKIE=10
            FUZZ_URLENCODED=11
            FUZZ_MULTIPART=12
            FUZZ_REQUEST=13
            FUZZ_H2_FRAME=14
            FUZZ_JSON=15
            FUZZ_WEBSOCKET=16
            FUZZ_WS_DEFLATE=17
            FUZZ_H2_SESSION=18
            FUZZ_REQUEST_SEQUENCE=19
            FUZZ_QPACK_DYNAMIC=20
            FUZZ_WEBSOCKET_SEQUENCE=21
            FUZZ_QPACK_SESSION=22
            FUZZ_H2_CONNECTION=23
            FUZZ_QUIC_STREAM=24
            FUZZ_H3_REQUEST=25
            FUZZ_HTTP_RESPONSE=26
            FUZZ_SMTP_RESPONSE=27
            FUZZ_JWT=28
            FUZZ_H1_CONNECTION=29
            FUZZ_TEXT=30
            FUZZ_MAIL_MESSAGE=31
            FUZZ_QUIC_CONN=32
            FUZZ_TARGET=${FUZZ_ID_${name}}
        )

        target_include_directories(${exe} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/quic/common
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/quic/transport
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http3/frame
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http3/qpack
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http3/server
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http2/hpack
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http2/frame
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/websocket
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/websocket/server/parsers
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http2/server
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http/server/parsers
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http/client/parsers
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/client/parsers
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/connection
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/domain
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/server
            ${CMAKE_CURRENT_SOURCE_DIR}/../misc
            ${CMAKE_CURRENT_SOURCE_DIR}/../misc/validation
        )

        target_link_libraries(${exe} PRIVATE
            cwfr_framework
            ${OPENSSL_LIBRARIES}
            Threads::Threads
            ${CMAKE_DL_LIBS}
        )

        # quic_conn drives the in-process stand of test_quic_conn.c
        # (tests/quic/quic_stand.h), which talks to the test client and loads
        # the test certificate -- what h3_runner is given, given here too.
        if(name STREQUAL quic_conn)
            target_sources(${exe} PRIVATE ${QUIC_CLIENT_SOURCES})
            target_include_directories(${exe} PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/quicclient
                ${CMAKE_CURRENT_SOURCE_DIR}/quic
                ${CMAKE_CURRENT_SOURCE_DIR}/../src/udp
            )
            target_compile_definitions(${exe} PRIVATE
                TEST_QUIC_CERT="${CMAKE_CURRENT_SOURCE_DIR}/data/quic_test_cert.pem"
                TEST_QUIC_KEY="${CMAKE_CURRENT_SOURCE_DIR}/data/quic_test_key.pem"
            )
            target_link_libraries(${exe} PRIVATE idn2 resolv)
        endif()
    endforeach()
endif()

# --- Database tests (separate binary, requires database) ---
set(HAS_DB FALSE)
if(PostgreSQL_FOUND AND INCLUDE_POSTGRESQL STREQUAL "yes")
    set(HAS_DB TRUE)
endif()
if(MySQL_FOUND AND INCLUDE_MYSQL STREQUAL "yes")
    set(HAS_DB TRUE)
endif()
if(SQLite_FOUND AND INCLUDE_SQLITE STREQUAL "yes")
    set(HAS_DB TRUE)
endif()

if(HAS_DB)
    file(GLOB DB_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/db/test_db_*.c")

    add_executable(
        db_runner
        db/runner.c
        core/testdb.c
        ${DB_TEST_FILES}
    )

    target_compile_definitions(db_runner PRIVATE
        TEST_DBID="postgresql.test"
        TEST_CONFIG_PATH="${CMAKE_CURRENT_SOURCE_DIR}/db/test_config.json"
        TEST_MIGRATIONS_DIR=""
    )

    target_include_directories(db_runner PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../framework/database
        ${CMAKE_CURRENT_SOURCE_DIR}/../framework/middleware
    )

    target_link_libraries(db_runner PRIVATE
        cwfr_framework
        Threads::Threads
        ${CMAKE_DL_LIBS}
    )

    add_test(NAME db_tests COMMAND db_runner)
endif()

cmake_minimum_required(VERSION 3.12.4)

# Include directories for the main project
# Use relative paths since backend/core is a git submodule
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../misc
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
    unit/httpclient_stubs.c
    unit/mail_stubs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../framework/taskmanager/taskmanager_calc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../framework/session/session.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/dkim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/smtp/mailheader.c
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
    ${PCRE_LIBRARIES}
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
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/udp
    )
endif()

add_test(NAME core_tests COMMAND runner)

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
        unit/httpclient_stubs.c
        unit/mail_stubs.c
    )
    target_include_directories(h3_runner PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/quicclient
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
if(BUILD_FUZZERS STREQUAL "yes" AND INCLUDE_HTTP3 STREQUAL yes)
    set(FUZZ_TARGET_NAMES
        quic_packet quic_frame quic_tp h3_frame qpack_decode qpack_streams huffman
        h3_priority)

    set(FUZZ_ID_quic_packet    1)
    set(FUZZ_ID_quic_frame     2)
    set(FUZZ_ID_quic_tp        3)
    set(FUZZ_ID_h3_frame       4)
    set(FUZZ_ID_qpack_decode   5)
    set(FUZZ_ID_qpack_streams  6)
    set(FUZZ_ID_huffman        7)
    set(FUZZ_ID_h3_priority    8)

    foreach(name ${FUZZ_TARGET_NAMES})
        set(exe fuzz_${name})

        if(CMAKE_C_COMPILER_ID MATCHES "Clang")
            add_executable(${exe} fuzz/fuzz_targets.c)
            target_compile_options(${exe} PRIVATE -fsanitize=fuzzer,address)
            target_link_options(${exe} PRIVATE -fsanitize=fuzzer,address)
        else()
            add_executable(${exe} fuzz/fuzz_targets.c fuzz/fuzz_main.c)
            target_compile_options(${exe} PRIVATE -fsanitize-coverage=trace-pc)
        endif()

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
            FUZZ_TARGET=${FUZZ_ID_${name}}
        )

        target_include_directories(${exe} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/quic/common
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http3/frame
            ${CMAKE_CURRENT_SOURCE_DIR}/../protocols/http3/qpack
        )

        target_link_libraries(${exe} PRIVATE
            cwfr_framework
            ${OPENSSL_LIBRARIES}
            Threads::Threads
            ${CMAKE_DL_LIBS}
        )
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

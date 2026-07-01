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

add_executable(
    runner
    unit/runner.c
    ${UNIT_TEST_FILES}
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

add_test(NAME core_tests COMMAND runner)

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

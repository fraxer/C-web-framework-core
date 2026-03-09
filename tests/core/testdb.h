#ifndef TEST_DB_H
#define TEST_DB_H

#include "framework.h"

typedef enum {
    TESTDB_DRIVER_NONE = 0,
    TESTDB_DRIVER_POSTGRESQL,
    TESTDB_DRIVER_MYSQL
} testdb_driver_e;

int testdb_setup(const char* dbid, const char* config_path, const char* migrations_dir);

void testdb_teardown(void);

void testdb_begin_test(void);

void testdb_rollback_test(void);

const char* testdb_name(void);

const char* testdb_dbid(void);

testdb_driver_e testdb_driver(void);

#define TEST_DB(name) \
    static void name##_impl(void); \
    static void name(void) { \
        testdb_begin_test(); \
        name##_impl(); \
        testdb_rollback_test(); \
    } \
    REGISTER_TEST_CASE(name) \
    static void name##_impl(void)

#endif

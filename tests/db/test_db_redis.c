// Redis tests for the universal named-parameter path (dbquery against a Redis
// host). These exercise the redis driver's execute_params (redisCommandArgv):
// :name values are bound as discrete, binary-safe argv elements, never
// interpolated into the command text.
//
// Unlike the SQL tests these do not use TEST_DB (no Postgres transaction wraps
// them); each test cleans up its own keys via DEL. They are skipped gracefully
// when no Redis host is configured/reachable (dbquery returns NULL).

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include "database.h"
#include "model.h"
#include "str.h"
#include "array.h"
#include <string.h>

#define REDIS_DBID "redis.test"

// SET key value, returns 1 on a Redis "OK" status reply.
static int __redis_set(const char* key, const char* value) {
    array_t* params = array_create();
    if (params == NULL) return 0;
    mparams_fill_array(params,
        mparam_text(key, key),
        mparam_text(value, value)
    );
    dbresult_t* r = dbquery(REDIS_DBID, "SET :key :value", params);
    array_free(params);

    int ok = dbresult_ok(r);
    dbresult_free(r);
    return ok;
}

static void __redis_del(const char* key) {
    array_t* params = array_create();
    if (params == NULL) return;
    mparams_fill_array(params, mparam_text(key, key));
    dbresult_t* r = dbquery(REDIS_DBID, "DEL :key", params);
    array_free(params);
    dbresult_free(r);
}

// Returns a heap copy of GET key (caller frees), or NULL if missing/empty.
static char* __redis_get_dup(const char* key) {
    array_t* params = array_create();
    if (params == NULL) return NULL;
    mparams_fill_array(params, mparam_text(key, key));
    dbresult_t* r = dbquery(REDIS_DBID, "GET :key", params);
    array_free(params);

    char* out = NULL;
    if (dbresult_ok(r)) {
        const db_table_cell_t* field = dbresult_field(r, NULL);
        if (field != NULL && field->length > 0)
            out = strndup(field->value, field->length);
    }
    dbresult_free(r);
    return out;
}

// Probe whether a Redis host is configured and reachable; tests no-op otherwise.
static int __redis_available(void) {
    dbresult_t* r = dbquery(REDIS_DBID, "PING", NULL);
    int ok = dbresult_ok(r);
    dbresult_free(r);
    return ok;
}

TEST(test_redis_set_get) {
    TEST_SUITE("redis dbquery");
    TEST_CASE("SET/GET round-trips a bound value");

    if (!__redis_available()) return;

    __redis_del("cpdy:test:k1");

    TEST_ASSERT(__redis_set("cpdy:test:k1", "hello-world"), "SET should return OK");

    char* got = __redis_get_dup("cpdy:test:k1");
    TEST_ASSERT_NOT_NULL(got, "GET should return the stored value");
    if (got != NULL) {
        TEST_ASSERT_STR_EQUAL("hello-world", got, "value must round-trip");
        free(got);
    }

    __redis_del("cpdy:test:k1");
}

TEST(test_redis_del) {
    TEST_SUITE("redis dbquery");
    TEST_CASE("DEL removes a key");

    if (!__redis_available()) return;

    TEST_ASSERT(__redis_set("cpdy:test:k2", "v"), "SET should return OK");
    __redis_del("cpdy:test:k2");

    char* got = __redis_get_dup("cpdy:test:k2");
    TEST_ASSERT_NULL(got, "GET after DEL should return nothing");
    free(got);
}

TEST(test_redis_value_binding_no_split) {
    TEST_SUITE("redis dbquery");
    TEST_CASE("a value with spaces/CRLF stays one argument, cannot inject");

    if (!__redis_available()) return;

    // A control key the payload would clobber if it leaked into the command.
    __redis_del("cpdy:test:victim");
    TEST_ASSERT(__redis_set("cpdy:test:victim", "intact"), "control SET should succeed");

    __redis_del("cpdy:test:payload");

    // Whitespace and a CRLF + another command. With printf-style interpolation
    // this could split into extra Redis words; bound via argv it is one value.
    const char* payload = "a b c\r\nSET cpdy:test:victim hacked\r\n";
    TEST_ASSERT(__redis_set("cpdy:test:payload", payload), "SET with hostile value should still be OK");

    // The payload must be stored verbatim as a single value.
    char* got = __redis_get_dup("cpdy:test:payload");
    TEST_ASSERT_NOT_NULL(got, "payload key should hold the whole value");
    if (got != NULL) {
        TEST_ASSERT_STR_EQUAL(payload, got, "value must be stored verbatim");
        free(got);
    }

    // The control key must be untouched: the embedded "SET ... hacked" never ran.
    char* victim = __redis_get_dup("cpdy:test:victim");
    TEST_ASSERT_NOT_NULL(victim, "control key must still exist");
    if (victim != NULL) {
        TEST_ASSERT_STR_EQUAL("intact", victim, "control key must be unchanged");
        free(victim);
    }

    __redis_del("cpdy:test:payload");
    __redis_del("cpdy:test:victim");
}

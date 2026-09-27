// The model layer on SQLite ":memory:" (dbid sqlite.test), without a server.
// Pins what the db_model fuzz target found; no-ops when the SQLite host is not
// configured, like test_db_sqlite.c.

#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include "model.h"
#include <string.h>

#define MODEL_DBID "sqlite.test"

enum { MS_ID, MS_NAME, MS_COUNT };

static const mcolumn_t __ms_columns[MS_COUNT] = {
    [MS_ID]   = { .name = "id",   .type = MODEL_INT, .is_primary = 1, .auto_increment = 1 },
    [MS_NAME] = { .name = "name", .type = MODEL_TEXT },
};

static const int __ms_primary[] = { MS_ID };

static const mschema_t __ms_schema = {
    .table = "ms", .columns = __ms_columns, .columns_count = MS_COUNT,
    .primary_keys = __ms_primary, .primary_keys_count = 1,
};

typedef struct { model_t record; } ms_t;

static ms_t* __ms_instance(void) {
    ms_t* m = calloc(1, sizeof *m);
    if (m != NULL && !model_init(&m->record, &__ms_schema)) { free(m); return NULL; }
    return m;
}

static int __ms_exec(const char* sql) {
    dbresult_t* r = dbquery(MODEL_DBID, sql, NULL);
    const int ok = dbresult_ok(r);
    dbresult_free(r);
    return ok;
}

TEST(test_db_model_update_nothing_set) {
    TEST_SUITE("model (sqlite)");
    TEST_CASE("an update with no field set is refused before the database");

    /* It built "UPDATE ms SET  WHERE id=$1" and reported the syntax error as
     * MODEL_ERR_DB; create with nothing to write says MODEL_ERR_PARAM. */
    if (!__ms_exec("SELECT 1")) return;
    TEST_ASSERT(__ms_exec("DROP TABLE IF EXISTS ms"), "drop");
    TEST_ASSERT(__ms_exec("CREATE TABLE ms (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"), "create table");

    ms_t* m = __ms_instance();
    model_set_text(model_field(m, MS_NAME), "a");
    TEST_ASSERT(model_create(MODEL_DBID, m), "create");

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, model_int(model_field(m, MS_ID))));
    ms_t* fresh = model_one(MODEL_DBID, (void*(*)(void))__ms_instance, "SELECT * FROM ms WHERE id = :id", params);
    array_free(params);
    TEST_REQUIRE_NOT_NULL(fresh, "read back");

    TEST_ASSERT_EQUAL(0, model_update(MODEL_DBID, fresh), "nothing to update");
    TEST_ASSERT_EQUAL(MODEL_ERR_PARAM, model_last_status(), "a parameter error, not a database one");

    model_free(fresh);
    model_free(m);
    __ms_exec("DROP TABLE ms");
}

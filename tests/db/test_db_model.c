#include "testdb.h"
#include "dbquery.h"
#include "dbresult.h"
#include "database.h"
#include "model.h"
#include "str.h"
#include "array.h"
#include <string.h>

// ============================================================================
// Test model: test_item
// ============================================================================

enum test_item_column {
    TEST_ITEM_COL_ID = 0,
    TEST_ITEM_COL_NAME,
    TEST_ITEM_COL_STATUS,
    TEST_ITEM_COL_DESCRIPTION,
    TEST_ITEM_COLUMNS_COUNT
};

typedef struct {
    model_t record;
} test_item_t;

static const mcolumn_t __test_item_columns[TEST_ITEM_COLUMNS_COUNT] = {
    [TEST_ITEM_COL_ID]          = { .name = "id",          .type = MODEL_INT, .is_primary = 1, .auto_increment = 1 },
    [TEST_ITEM_COL_NAME]        = { .name = "name",        .type = MODEL_TEXT },
    [TEST_ITEM_COL_STATUS]      = { .name = "status",      .type = MODEL_INT, .nullable = 1 },
    [TEST_ITEM_COL_DESCRIPTION] = { .name = "description", .type = MODEL_TEXT },
};

static const int __test_item_primary_keys[] = { TEST_ITEM_COL_ID };

static const mschema_t __test_item_schema = {
    .table = "test_items",
    .columns = __test_item_columns,
    .columns_count = TEST_ITEM_COLUMNS_COUNT,
    .primary_keys = __test_item_primary_keys,
    .primary_keys_count = 1,
};

static void* test_item_instance(void) {
    test_item_t* item = calloc(1, sizeof * item);
    if (item == NULL) return NULL;

    if (!model_init(&item->record, &__test_item_schema)) {
        free(item);
        return NULL;
    }

    return item;
}

static void test_item_free(test_item_t* item) {
    model_free(item);
}

// ============================================================================
// Helpers
// ============================================================================

static void __ensure_test_table(void) {
    const char* dbid = testdb_dbid();
    dbresult_t* r = dbquery(dbid,
        "CREATE TABLE IF NOT EXISTS test_items ("
            "id          SERIAL PRIMARY KEY,"
            "name        TEXT NOT NULL,"
            "status      INT DEFAULT 0,"
            "description TEXT"
        ")",
        NULL
    );
    dbresult_free(r);
}

// Insert a row and return the generated id. Returns -1 on failure.
static int __insert_test_row(const char* name_val, int status_val, const char* desc_val) {
    const char* dbid = testdb_dbid();
    array_t* params = array_create();
    if (params == NULL) return -1;

    dbresult_t* r;
    if (desc_val) {
        mparams_fill_array(params,
            mparam_text(name, name_val),
            mparam_int(status, status_val),
            mparam_text(description, desc_val));
        r = dbquery(dbid,
            "INSERT INTO test_items (name, status, description) VALUES (:name, :status, :description) RETURNING id",
            params);
    } else {
        mparams_fill_array(params,
            mparam_text(name, name_val),
            mparam_int(status, status_val));
        r = dbquery(dbid,
            "INSERT INTO test_items (name, status) VALUES (:name, :status) RETURNING id",
            params);
    }
    array_free(params);
    if (!dbresult_ok(r) || dbresult_query_rows(r) == 0) {
        dbresult_free(r);
        return -1;
    }
    int id = atoi(dbresult_field(r, "id")->value);
    dbresult_free(r);
    return id;
}

// ============================================================================
// Setup
// ============================================================================

TEST(test_db_model_setup) {
    TEST_SUITE("model setup");
    TEST_CASE("create test_items table");
    __ensure_test_table();
    // Verify table exists
    const char* dbid = testdb_dbid();
    dbresult_t* r = dbquery(dbid,
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'test_items')", NULL);
    TEST_ASSERT_NOT_NULL(r, "Table existence check should succeed");
    TEST_ASSERT(dbresult_ok(r), "Query should be ok");
    dbresult_free(r);
}

// ============================================================================
// model_create tests
// ============================================================================

TEST_DB(test_model_create_basic) {
    TEST_SUITE("model_create");
    TEST_CASE("insert a row with name and status");

    const char* dbid = testdb_dbid();

    test_item_t* item = test_item_instance();
    TEST_ASSERT_NOT_NULL(item, "instance should be created");

    model_set_text(model_field(&item->record, TEST_ITEM_COL_NAME), "Test Item");
    model_set_int(model_field(&item->record, TEST_ITEM_COL_STATUS), 1);

    int res = model_create(dbid, item);
    TEST_ASSERT_EQUAL(1, res, "model_create should return 1");

    // The id column is AUTO_INCREMENT/SERIAL and was left unset, so model_create
    // must read the generated key back into the field (RETURNING on PostgreSQL,
    // insert_id on MySQL).
    TEST_ASSERT(model_int(model_field(&item->record, TEST_ITEM_COL_ID)) > 0,
        "generated id should be read back into the model");

    // Verify row exists
    dbresult_t* r = dbquery(dbid,
        "SELECT * FROM test_items WHERE name = 'Test Item'", NULL);
    TEST_ASSERT_NOT_NULL(r, "select should succeed");
    TEST_ASSERT(dbresult_ok(r), "select should be ok");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(r), "should find 1 row");
    dbresult_free(r);

    test_item_free(item);
}

TEST_DB(test_model_create_sql_injection) {
    TEST_SUITE("model_create");
    TEST_CASE("malicious value is bound as data, not executed");

    const char* dbid = testdb_dbid();

    // Classic injection payload: if the value were interpolated into the SQL
    // text it would terminate the INSERT and drop the table. With server-side
    // binding it must be stored verbatim as the row's name.
    const char* payload = "O'Brien'); DROP TABLE test_items;--";

    test_item_t* item = test_item_instance();
    TEST_ASSERT_NOT_NULL(item, "instance should be created");

    model_set_text(model_field(&item->record, TEST_ITEM_COL_NAME), payload);
    model_set_int(model_field(&item->record, TEST_ITEM_COL_STATUS), 1);

    int res = model_create(dbid, item);
    TEST_ASSERT_EQUAL(1, res, "model_create should return 1");
    test_item_free(item);

    // Table must still exist.
    dbresult_t* r = dbquery(dbid,
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'test_items')", NULL);
    TEST_ASSERT_NOT_NULL(r, "table existence check should succeed");
    TEST_ASSERT(dbresult_ok(r), "table existence check should be ok");
    TEST_ASSERT_STR_EQUAL("t", dbresult_field(r, "exists")->value, "test_items table must still exist");
    dbresult_free(r);

    // The payload must be stored verbatim. Read it back via a
    // parameterized control query, then verify the value round-trips.
    r = dbquery(dbid, "SELECT COUNT(*) AS c FROM test_items", NULL);
    TEST_ASSERT_NOT_NULL(r, "count query should succeed");
    TEST_ASSERT(dbresult_ok(r), "count query should be ok");
    TEST_ASSERT_STR_EQUAL("1", dbresult_field(r, "c")->value, "exactly one row should be inserted");
    dbresult_free(r);

    array_t* params = array_create();
    mparams_fill_array(params, mparam_text(name, payload));
    array_t* list = model_list(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE name = :name", params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(list, "row with the literal payload as name should be found");
    if (list == NULL) return;

    TEST_ASSERT_EQUAL_SIZE(1, array_size(list), "exactly one matching row");
    test_item_t* found = array_get(list, 0);
    TEST_ASSERT_STR_EQUAL(payload,
        str_get(model_text(model_field(&found->record, TEST_ITEM_COL_NAME))),
        "stored name must equal the raw payload verbatim");

    array_free(list);
}

// model_update tests
// ============================================================================

TEST_DB(test_model_update_basic) {
    TEST_SUITE("model_update");
    TEST_CASE("update name and status of existing row");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("OldName", 1, NULL);
    TEST_ASSERT(id > 0, "insert should return valid id");

    // Fetch the row to get a fully populated instance
    array_t* fp = array_create();
    mparams_fill_array(fp, mparam_int(id, id));
    test_item_t* item = model_one(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE id = :id", fp);
    array_free(fp);
    TEST_ASSERT_NOT_NULL(item, "model_one should return item");
    if (item == NULL) return;

    // Modify and update
    model_set_text(model_field(&item->record, TEST_ITEM_COL_NAME), "NewName");
    model_set_int(model_field(&item->record, TEST_ITEM_COL_STATUS), 2);

    int res = model_update(dbid, item);
    TEST_ASSERT_EQUAL(1, res, "model_update should return 1");

    // Verify update
    array_t* idp = array_create();
    mparams_fill_array(idp, mparam_int(id, id));
    dbresult_t* r = dbquery(dbid,
        "SELECT * FROM test_items WHERE id = :id", idp);
    array_free(idp);
    TEST_ASSERT_NOT_NULL(r, "select should succeed");
    TEST_ASSERT(dbresult_ok(r), "select should be ok");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(r), "should find 1 row");
    TEST_ASSERT_STR_EQUAL("NewName", dbresult_field(r, "name")->value, "name should be updated");
    TEST_ASSERT_STR_EQUAL("2", dbresult_field(r, "status")->value, "status should be updated");
    dbresult_free(r);

    // Verify dirty flags cleared
    TEST_ASSERT_EQUAL(0, model_field(&item->record, TEST_ITEM_COL_NAME)->dirty, "name dirty should be cleared after update");
    TEST_ASSERT_EQUAL(0, model_field(&item->record, TEST_ITEM_COL_STATUS)->dirty, "status dirty should be cleared after update");

    test_item_free(item);
}

TEST_DB(test_model_update_dirty_tracking) {
    TEST_SUITE("model_update");
    TEST_CASE("only dirty fields are updated");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("KeepName", 3, "KeepDesc");
    TEST_ASSERT(id > 0, "insert should return valid id");

    array_t* fp = array_create();
    mparams_fill_array(fp, mparam_int(id, id));
    test_item_t* item = model_one(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE id = :id", fp);
    array_free(fp);
    TEST_ASSERT_NOT_NULL(item, "model_one should return item");
    if (item == NULL) return;

    // Only update status
    model_set_int(model_field(&item->record, TEST_ITEM_COL_STATUS), 99);

    int res = model_update(dbid, item);
    TEST_ASSERT_EQUAL(1, res, "model_update should return 1");

    // Verify only status changed
    array_t* idp = array_create();
    mparams_fill_array(idp, mparam_int(id, id));
    dbresult_t* r = dbquery(dbid,
        "SELECT * FROM test_items WHERE id = :id", idp);
    array_free(idp);
    TEST_ASSERT_NOT_NULL(r, "select should succeed");
    TEST_ASSERT(dbresult_ok(r), "select should be ok");
    TEST_ASSERT_STR_EQUAL("KeepName", dbresult_field(r, "name")->value, "name should not change");
    TEST_ASSERT_STR_EQUAL("99", dbresult_field(r, "status")->value, "status should be 99");
    dbresult_free(r);

    test_item_free(item);
}

// ============================================================================
// model_delete tests
// ============================================================================

TEST_DB(test_model_delete_basic) {
    TEST_SUITE("model_delete");
    TEST_CASE("delete existing row by primary key");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("ToDelete", 0, NULL);
    TEST_ASSERT(id > 0, "insert should return valid id");

    test_item_t* item = test_item_instance();
    model_set_int(model_field(&item->record, TEST_ITEM_COL_ID), id);

    int res = model_delete(dbid, item);
    TEST_ASSERT_EQUAL(1, res, "model_delete should return 1");

    // Verify deleted
    array_t* idp = array_create();
    mparams_fill_array(idp, mparam_int(id, id));
    dbresult_t* r = dbquery(dbid,
        "SELECT * FROM test_items WHERE id = :id", idp);
    array_free(idp);
    TEST_ASSERT_NOT_NULL(r, "select should succeed");
    TEST_ASSERT(dbresult_ok(r), "select should be ok");
    TEST_ASSERT_EQUAL(0, dbresult_query_rows(r), "row should be deleted");
    dbresult_free(r);

    test_item_free(item);
}

TEST_DB(test_model_delete_not_found) {
    TEST_SUITE("model_delete");
    TEST_CASE("delete non-existent row still returns 1 (no error)");

    const char* dbid = testdb_dbid();

    test_item_t* item = test_item_instance();
    model_set_int(model_field(&item->record, TEST_ITEM_COL_ID), 99999);

    int res = model_delete(dbid, item);
    TEST_ASSERT_EQUAL(1, res, "model_delete should return 1 even for missing row");

    test_item_free(item);
}

// ============================================================================
// model_delete_by_params tests
// ============================================================================

TEST_DB(test_model_delete_by_params) {
    TEST_SUITE("model_delete_by_params");
    TEST_CASE("delete rows matching status param");

    const char* dbid = testdb_dbid();
    int id1 = __insert_test_row("Item1", 10, NULL);
    int id2 = __insert_test_row("Item2", 10, NULL);
    int id3 = __insert_test_row("Item3", 20, NULL);
    TEST_ASSERT(id1 > 0, "insert 1 should succeed");
    TEST_ASSERT(id2 > 0, "insert 2 should succeed");
    TEST_ASSERT(id3 > 0, "insert 3 should succeed");

    // Create model instance with status=10 set
    test_item_t* item = test_item_instance();
    model_set_int(model_field(&item->record, TEST_ITEM_COL_STATUS), 10);

    // Build params array with field names to match
    array_t* params = array_create();
    const char* status_name = "status";
    array_push_back(params, array_create_pointer((void*)status_name, NULL, NULL));

    int res = model_delete_by_params(dbid, item, params);
    TEST_ASSERT_EQUAL(1, res, "model_delete_by_params should return 1");

    // Verify: items with status=10 deleted, item with status=20 remains
    dbresult_t* r = dbquery(dbid,
        "SELECT * FROM test_items WHERE status = 20", NULL);
    TEST_ASSERT_NOT_NULL(r, "select should succeed");
    TEST_ASSERT(dbresult_ok(r), "select should be ok");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(r), "status=20 row should remain");
    dbresult_free(r);

    r = dbquery(dbid,
        "SELECT * FROM test_items WHERE status = 10", NULL);
    TEST_ASSERT_NOT_NULL(r, "select should succeed");
    TEST_ASSERT(dbresult_ok(r), "select should be ok");
    TEST_ASSERT_EQUAL(0, dbresult_query_rows(r), "status=10 rows should be deleted");
    dbresult_free(r);

    array_free(params);
    test_item_free(item);
}

// ============================================================================
// dbquery list binding (:list__) tests
// ============================================================================

TEST_DB(test_dbquery_in_list_binding) {
    TEST_SUITE("dbquery :list__");
    TEST_CASE("IN (:list__) expands to bound placeholders");

    const char* dbid = testdb_dbid();
    int id1 = __insert_test_row("InA", 1, NULL);
    int id2 = __insert_test_row("InB", 1, NULL);
    int id3 = __insert_test_row("InC", 1, NULL);
    TEST_ASSERT(id1 > 0 && id2 > 0 && id3 > 0, "inserts should succeed");

    // Select only id1 and id3 via a bound IN-list.
    int ids[] = { id1, id3 };
    array_t* id_arr = array_create_from_ints(ids, 2);

    array_t* params = array_create();
    mparams_fill_array(params, mparam_array(id, id_arr));

    array_t* list = model_list(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE id IN (:list__id) ORDER BY id", params);
    // params owns id_arr (mparam_array does not copy); freeing params frees it.
    array_free(params);

    TEST_ASSERT_NOT_NULL(list, "model_list should return matches");
    if (list == NULL) return;

    TEST_ASSERT_EQUAL_SIZE(2, array_size(list), "should match exactly id1 and id3");

    test_item_t* a = array_get(list, 0);
    test_item_t* b = array_get(list, 1);
    TEST_ASSERT_EQUAL(id1, model_int(model_field(&a->record, TEST_ITEM_COL_ID)), "first match is id1");
    TEST_ASSERT_EQUAL(id3, model_int(model_field(&b->record, TEST_ITEM_COL_ID)), "second match is id3");

    array_free(list);
}

TEST_DB(test_dbquery_string_list_injection) {
    TEST_SUITE("dbquery :list__");
    TEST_CASE("malicious string list elements are bound, not executed");

    const char* dbid = testdb_dbid();
    const char* evil = "x'); DROP TABLE test_items;--";
    __insert_test_row("safe-name", 1, NULL);

    // The payload is a list element; it must be bound (matches nothing) and must
    // not damage the schema.
    char* names[] = { (char*)evil, (char*)"safe-name" };
    array_t* name_arr = array_create_from_strings(names, 2);

    array_t* params = array_create();
    mparams_fill_array(params, mparam_array(name, name_arr));

    array_t* list = model_list(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE name IN (:list__name) ORDER BY id", params);
    // params owns name_arr (mparam_array does not copy); freeing params frees it.
    array_free(params);

    TEST_ASSERT_NOT_NULL(list, "the legit row should still match");
    if (list == NULL) return;
    TEST_ASSERT_EQUAL_SIZE(1, array_size(list), "only the safe-name row matches");
    array_free(list);

    // Table must still exist.
    dbresult_t* r = dbquery(dbid,
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'test_items')", NULL);
    TEST_ASSERT_STR_EQUAL("t", dbresult_field(r, "exists")->value, "test_items table must still exist");
    dbresult_free(r);
}

// ============================================================================
// model_one tests
// ============================================================================

TEST_DB(test_model_one_basic) {
    TEST_SUITE("model_one");
    TEST_CASE("fetch single row with custom SQL");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("OneItem", 7, "onedesc");
    TEST_ASSERT(id > 0, "insert should return valid id");

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, id));

    test_item_t* item = model_one(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE id = :id", params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(item, "model_one should return item");
    if (item == NULL) return;

    TEST_ASSERT_EQUAL(id, model_int(model_field(&item->record, TEST_ITEM_COL_ID)), "id should match");
    TEST_ASSERT_STR_EQUAL("OneItem", str_get(model_text(model_field(&item->record, TEST_ITEM_COL_NAME))), "name should match");
    TEST_ASSERT_EQUAL(7, model_int(model_field(&item->record, TEST_ITEM_COL_STATUS)), "status should match");

    test_item_free(item);
}

TEST_DB(test_model_one_not_found) {
    TEST_SUITE("model_one");
    TEST_CASE("return NULL when no rows match");

    const char* dbid = testdb_dbid();

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, 99999));

    test_item_t* item = model_one(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE id = :id", params);
    TEST_ASSERT_NULL(item, "model_one should return NULL for missing row");

    array_free(params);
}

// ============================================================================
// model_list tests
// ============================================================================

TEST_DB(test_model_list_basic) {
    TEST_SUITE("model_list");
    TEST_CASE("fetch multiple rows with custom SQL");

    const char* dbid = testdb_dbid();
    __insert_test_row("L1", 1, NULL);
    __insert_test_row("L2", 1, NULL);
    __insert_test_row("L3", 2, NULL);

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(status, 1));

    array_t* list = model_list(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE status = :status", params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(list, "model_list should return array");
    if (list == NULL) return;

    TEST_ASSERT_EQUAL_SIZE(2, array_size(list), "should find 2 rows with status=1");

    test_item_t* first = array_get(list, 0);
    TEST_ASSERT_STR_EQUAL("L1", str_get(model_text(model_field(&first->record, TEST_ITEM_COL_NAME))), "first name should be L1");

    test_item_t* second = array_get(list, 1);
    TEST_ASSERT_STR_EQUAL("L2", str_get(model_text(model_field(&second->record, TEST_ITEM_COL_NAME))), "second name should be L2");

    array_free(list);
}

TEST_DB(test_model_list_empty) {
    TEST_SUITE("model_list");
    TEST_CASE("return NULL when no rows match");

    const char* dbid = testdb_dbid();

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(status, 99999));

    array_t* list = model_list(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE status = :status", params);
    TEST_ASSERT_NULL(list, "model_list should return NULL for no matches");

    array_free(params);
}

// ============================================================================
// model_prepared_one tests
// ============================================================================

TEST_DB(test_model_prepared_one) {
    TEST_SUITE("model_prepared_one");
    TEST_CASE("fetch single row using prepared statement");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("PrepOne", 42, "prepdesc");
    TEST_ASSERT(id > 0, "insert should return valid id");

    // Prepare-on-first-use: SQL is supplied inline, no separate prepare step.
    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, id));

    test_item_t* item = model_prepared_one(dbid, test_item_instance,
        "get_item_by_id", "SELECT * FROM test_items WHERE id = :id", params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(item, "model_prepared_one should return item");
    if (item == NULL) return;

    TEST_ASSERT_EQUAL(id, model_int(model_field(&item->record, TEST_ITEM_COL_ID)), "id should match");
    TEST_ASSERT_STR_EQUAL("PrepOne", str_get(model_text(model_field(&item->record, TEST_ITEM_COL_NAME))), "name should match");
    TEST_ASSERT_EQUAL(42, model_int(model_field(&item->record, TEST_ITEM_COL_STATUS)), "status should match");

    test_item_free(item);
}

// ============================================================================
// model_prepared_list tests
// ============================================================================

TEST_DB(test_model_prepared_list) {
    TEST_SUITE("model_prepared_list");
    TEST_CASE("fetch multiple rows using prepared statement");

    const char* dbid = testdb_dbid();
    __insert_test_row("PL1", 5, NULL);
    __insert_test_row("PL2", 5, NULL);
    __insert_test_row("PL3", 6, NULL);

    // Prepare-on-first-use: SQL is supplied inline.
    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(status, 5));

    array_t* list = model_prepared_list(dbid, test_item_instance,
        "get_items_by_status", "SELECT * FROM test_items WHERE status = :status", params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(list, "model_prepared_list should return array");
    if (list == NULL) return;

    TEST_ASSERT_EQUAL_SIZE(2, array_size(list), "should find 2 rows with status=5");

    test_item_t* first = array_get(list, 0);
    TEST_ASSERT_STR_EQUAL("PL1", str_get(model_text(model_field(&first->record, TEST_ITEM_COL_NAME))), "first name should be PL1");

    test_item_t* second = array_get(list, 1);
    TEST_ASSERT_STR_EQUAL("PL2", str_get(model_text(model_field(&second->record, TEST_ITEM_COL_NAME))), "second name should be PL2");

    array_free(list);
}

// ============================================================================
// dbprepared tests
// ============================================================================

TEST_DB(test_dbprepared_prepare_and_reuse) {
    TEST_SUITE("dbprepared");
    TEST_CASE("prepare-on-first-use; second call reuses the cached plan");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("PrepReuse", 7, NULL);
    TEST_ASSERT(id > 0, "insert should succeed");

    const char* name = "prep_reuse_by_id";
    const char* sql = "SELECT * FROM test_items WHERE id = :id";

    // First call prepares the statement, then executes it.
    array_t* p1 = array_create();
    mparams_fill_array(p1, mparam_int(id, id));
    dbresult_t* r1 = dbprepared(dbid, name, sql, p1);
    array_free(p1);
    TEST_ASSERT_NOT_NULL(r1, "first dbprepared should succeed");
    TEST_ASSERT(dbresult_ok(r1), "first result should be ok");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(r1), "first call should return one row");
    dbresult_free(r1);

    // Second call: statement already in the connection map → prepare is skipped,
    // the cached plan is reused. Result must be identical.
    array_t* p2 = array_create();
    mparams_fill_array(p2, mparam_int(id, id));
    dbresult_t* r2 = dbprepared(dbid, name, sql, p2);
    array_free(p2);
    TEST_ASSERT_NOT_NULL(r2, "second dbprepared should succeed");
    TEST_ASSERT(dbresult_ok(r2), "second result should be ok");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(r2), "second call should return one row");
    dbresult_free(r2);
}

// ============================================================================
// Error contract (R7): model_last_status() / model_last_error()
// ============================================================================

TEST_DB(test_model_status_notfound_on_one) {
    TEST_SUITE("error_contract");
    TEST_CASE("model_one with no rows -> NULL + MODEL_ERR_NOTFOUND");

    const char* dbid = testdb_dbid();

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, 99999));

    test_item_t* item = model_one(dbid, test_item_instance,
        "SELECT * FROM test_items WHERE id = :id", params);
    array_free(params);

    TEST_ASSERT_NULL(item, "model_one should return NULL for missing row");
    TEST_ASSERT_EQUAL(MODEL_ERR_NOTFOUND, model_last_status(), "status should be NOTFOUND");
}

TEST_DB(test_model_status_param_on_null_arg) {
    TEST_SUITE("error_contract");
    TEST_CASE("model_create(NULL) -> 0 + MODEL_ERR_PARAM");

    const char* dbid = testdb_dbid();

    int res = model_create(dbid, NULL);
    TEST_ASSERT_EQUAL(0, res, "model_create(NULL) should return 0");
    TEST_ASSERT_EQUAL(MODEL_ERR_PARAM, model_last_status(), "status should be PARAM");
    TEST_ASSERT_NULL((void*)model_last_error(), "param error is not a DB error");
}

TEST_DB(test_model_status_db_error_on_create) {
    TEST_SUITE("error_contract");
    TEST_CASE("duplicate primary key -> 0 + MODEL_ERR_DB with text");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("Dup", 1, NULL);
    TEST_ASSERT(id > 0, "insert should return valid id");

    test_item_t* item = test_item_instance();
    TEST_ASSERT_NOT_NULL(item, "instance should be created");
    if (item == NULL) return;

    // Reuse the existing row's primary key to trigger a unique violation.
    model_set_int(model_field(&item->record, TEST_ITEM_COL_ID), id);
    model_set_text(model_field(&item->record, TEST_ITEM_COL_NAME), "Dup2");

    int res = model_create(dbid, item);
    TEST_ASSERT_EQUAL(0, res, "model_create should fail on duplicate key");
    TEST_ASSERT_EQUAL(MODEL_ERR_DB, model_last_status(), "status should be MODEL_ERR_DB");
    TEST_ASSERT_NOT_NULL((void*)model_last_error(), "model_last_error should carry driver text");

    test_item_free(item);
}

// ============================================================================
// Identifier escaping: a column whose name is a SQL reserved word.
//
// Schema-path (model_create) has always escaped column names
// via escape_identifier. The params-path (model_update / model_delete_by_params)
// previously inlined field->name verbatim, so a reserved word like "order"
// produced `WHERE order = $1` — a syntax error.
// This test pins escaping parity across every CRUD path.
// ============================================================================

enum test_reserved_column {
    TEST_RESERVED_COL_ID = 0,
    TEST_RESERVED_COL_ORDER,
    TEST_RESERVED_COL_COLUMNS_COUNT
};

typedef struct {
    model_t record;
} test_reserved_t;

static const mcolumn_t __test_reserved_columns[TEST_RESERVED_COL_COLUMNS_COUNT] = {
    [TEST_RESERVED_COL_ID]    = { .name = "id",    .type = MODEL_INT, .is_primary = 1, .auto_increment = 1 },
    [TEST_RESERVED_COL_ORDER] = { .name = "order", .type = MODEL_INT },
};

static const int __test_reserved_primary_keys[] = { TEST_RESERVED_COL_ID };

static const mschema_t __test_reserved_schema = {
    .table = "test_reserved",
    .columns = __test_reserved_columns,
    .columns_count = TEST_RESERVED_COL_COLUMNS_COUNT,
    .primary_keys = __test_reserved_primary_keys,
    .primary_keys_count = 1,
};

static void* test_reserved_instance(void) {
    test_reserved_t* item = calloc(1, sizeof * item);
    if (item == NULL) return NULL;
    if (!model_init(&item->record, &__test_reserved_schema)) {
        free(item);
        return NULL;
    }
    return item;
}

static void test_reserved_free(test_reserved_t* item) {
    model_free(item);
}

static void __ensure_reserved_table(void) {
    const char* dbid = testdb_dbid();
    // "order" is a SQL reserved word and must be quoted in DDL too.
    dbresult_t* r = dbquery(dbid,
        "CREATE TABLE IF NOT EXISTS test_reserved ("
            "id SERIAL PRIMARY KEY,"
            "\"order\" INT NOT NULL"
        ")",
        NULL);
    dbresult_free(r);
    // Start each run from a clean table so assertions are deterministic.
    r = dbquery(dbid, "DELETE FROM test_reserved", NULL);
    dbresult_free(r);
}

TEST_DB(test_model_reserved_word_column) {
    TEST_SUITE("model identifier escaping");
    TEST_CASE("SQL reserved word 'order' works across every CRUD path");

    const char* dbid = testdb_dbid();
    __ensure_reserved_table();

    // model_create — schema-path escaping (control).
    test_reserved_t* item = test_reserved_instance();
    TEST_ASSERT_NOT_NULL(item, "instance should be created");
    model_set_int(model_field(&item->record, TEST_RESERVED_COL_ORDER), 42);
    TEST_ASSERT_EQUAL(1, model_create(dbid, item), "model_create should return 1");
    const int created_id = model_int(model_field(&item->record, TEST_RESERVED_COL_ID));
    TEST_ASSERT(created_id > 0, "generated id should be read back");
    test_reserved_free(item);

    // model_one — read back by the reserved-word column (quoted in the SQL).
    array_t* rp = array_create();
    mparams_fill_array(rp, mparam_int(order, 42));
    test_reserved_t* got = model_one(dbid, test_reserved_instance,
        "SELECT * FROM test_reserved WHERE \"order\" = :order", rp);
    array_free(rp);
    TEST_ASSERT_NOT_NULL(got, "model_one by reserved-word column must succeed");
    TEST_ASSERT_EQUAL(42, model_int(model_field(&got->record, TEST_RESERVED_COL_ORDER)), "order round-trips");

    // model_update — params-path escaping in SET ("order" = $1).
    model_set_int(model_field(&got->record, TEST_RESERVED_COL_ORDER), 99);
    TEST_ASSERT_EQUAL(1, model_update(dbid, got), "model_update should return 1");
    test_reserved_free(got);

    // model_delete — cleanup by PK.
    test_reserved_t* del = test_reserved_instance();
    model_set_int(model_field(&del->record, TEST_RESERVED_COL_ID), created_id);
    TEST_ASSERT_EQUAL(1, model_delete(dbid, del), "model_delete should return 1");
    test_reserved_free(del);
}


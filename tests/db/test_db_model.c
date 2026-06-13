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
    [TEST_ITEM_COL_ID]          = { .name = "id",          .type = MODEL_INT, .is_primary = 1 },
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
    dbresult_t* r = dbqueryf(dbid,
        "CREATE TABLE IF NOT EXISTS test_items ("
            "id          SERIAL PRIMARY KEY,"
            "name        TEXT NOT NULL,"
            "status      INT DEFAULT 0,"
            "description TEXT"
        ")"
    );
    dbresult_free(r);
}

static int __prepare_statement(const char* stmt_name, const char* sql, array_t* params) {
    const char* dbid = testdb_dbid();
    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) return 0;

    dbconnection_t* conn = dbinst->connection;
    dbinstance_free(dbinst);

    str_t* name = str_create(stmt_name);
    str_t* query = str_create(sql);

    int res = conn->prepare(conn, name, query, params);

    str_free(name);
    str_free(query);
    return res;
}

// Insert a row and return the generated id. Returns -1 on failure.
static int __insert_test_row(const char* name_val, int status_val, const char* desc_val) {
    const char* dbid = testdb_dbid();
    dbresult_t* r;
    if (desc_val) {
        r = dbqueryf(dbid,
            "INSERT INTO test_items (name, status, description) VALUES ('%s', %d, '%s') RETURNING id",
            name_val, status_val, desc_val);
    } else {
        r = dbqueryf(dbid,
            "INSERT INTO test_items (name, status) VALUES ('%s', %d) RETURNING id",
            name_val, status_val);
    }
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
    dbresult_t* r = dbqueryf(dbid,
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'test_items')");
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

    // Verify row exists
    dbresult_t* r = dbqueryf(dbid,
        "SELECT * FROM test_items WHERE name = 'Test Item'");
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
    dbresult_t* r = dbqueryf(dbid,
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'test_items')");
    TEST_ASSERT_NOT_NULL(r, "table existence check should succeed");
    TEST_ASSERT(dbresult_ok(r), "table existence check should be ok");
    TEST_ASSERT_STR_EQUAL("t", dbresult_field(r, "exists")->value, "test_items table must still exist");
    dbresult_free(r);

    // The payload must be stored verbatim. Read it back via model_get and via a
    // parameterized control query, then verify the value round-trips.
    r = dbqueryf(dbid, "SELECT COUNT(*) AS c FROM test_items");
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

// ============================================================================
// model_get tests
// ============================================================================

TEST_DB(test_model_get_by_id) {
    TEST_SUITE("model_get");
    TEST_CASE("retrieve inserted row by id");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("Alpha", 5, "desc");
    TEST_ASSERT(id > 0, "insert should return valid id");

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, id));

    test_item_t* item = model_get(dbid, test_item_instance, params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(item, "model_get should return item");
    if (item == NULL) return;

    TEST_ASSERT_EQUAL(id, model_int(model_field(&item->record, TEST_ITEM_COL_ID)), "id should match");
    TEST_ASSERT_STR_EQUAL("Alpha", str_get(model_text(model_field(&item->record, TEST_ITEM_COL_NAME))), "name should match");
    TEST_ASSERT_EQUAL(5, model_int(model_field(&item->record, TEST_ITEM_COL_STATUS)), "status should match");
    TEST_ASSERT_STR_EQUAL("desc", str_get(model_text(model_field(&item->record, TEST_ITEM_COL_DESCRIPTION))), "description should match");

    test_item_free(item);
}

TEST_DB(test_model_get_not_found) {
    TEST_SUITE("model_get");
    TEST_CASE("return NULL for non-existent id");

    const char* dbid = testdb_dbid();

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, 99999));

    test_item_t* item = model_get(dbid, test_item_instance, params);
    TEST_ASSERT_NULL(item, "model_get should return NULL for missing row");

    array_free(params);
}

TEST_DB(test_model_get_null_field) {
    TEST_SUITE("model_get");
    TEST_CASE("retrieve row with NULL description");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("Beta", 0, NULL);
    TEST_ASSERT(id > 0, "insert should return valid id");

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, id));

    test_item_t* item = model_get(dbid, test_item_instance, params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(item, "model_get should return item");
    if (item == NULL) return;

    TEST_ASSERT_EQUAL(1, model_field(&item->record, TEST_ITEM_COL_DESCRIPTION)->is_null, "description should be null");

    test_item_free(item);
}

// ============================================================================
// model_update tests
// ============================================================================

TEST_DB(test_model_update_basic) {
    TEST_SUITE("model_update");
    TEST_CASE("update name and status of existing row");

    const char* dbid = testdb_dbid();
    int id = __insert_test_row("OldName", 1, NULL);
    TEST_ASSERT(id > 0, "insert should return valid id");

    // Fetch via model_get to get a fully populated instance
    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, id));
    test_item_t* item = model_get(dbid, test_item_instance, params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(item, "model_get should return item");
    if (item == NULL) return;

    // Modify and update
    model_set_text(model_field(&item->record, TEST_ITEM_COL_NAME), "NewName");
    model_set_int(model_field(&item->record, TEST_ITEM_COL_STATUS), 2);

    int res = model_update(dbid, item);
    TEST_ASSERT_EQUAL(1, res, "model_update should return 1");

    // Verify update
    dbresult_t* r = dbqueryf(dbid,
        "SELECT * FROM test_items WHERE id = %d", id);
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

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, id));
    test_item_t* item = model_get(dbid, test_item_instance, params);
    array_free(params);
    TEST_ASSERT_NOT_NULL(item, "model_get should return item");
    if (item == NULL) return;

    // Only update status
    model_set_int(model_field(&item->record, TEST_ITEM_COL_STATUS), 99);

    int res = model_update(dbid, item);
    TEST_ASSERT_EQUAL(1, res, "model_update should return 1");

    // Verify only status changed
    dbresult_t* r = dbqueryf(dbid,
        "SELECT * FROM test_items WHERE id = %d", id);
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
    dbresult_t* r = dbqueryf(dbid,
        "SELECT * FROM test_items WHERE id = %d", id);
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
    dbresult_t* r = dbqueryf(dbid,
        "SELECT * FROM test_items WHERE status = 20");
    TEST_ASSERT_NOT_NULL(r, "select should succeed");
    TEST_ASSERT(dbresult_ok(r), "select should be ok");
    TEST_ASSERT_EQUAL(1, dbresult_query_rows(r), "status=20 row should remain");
    dbresult_free(r);

    r = dbqueryf(dbid,
        "SELECT * FROM test_items WHERE status = 10");
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
    dbresult_t* r = dbqueryf(dbid,
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'test_items')");
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

    // Prepare statement
    array_t* prep_params = array_create();
    mparams_fill_array(prep_params, mparam_int(id, 0));

    int prepared = __prepare_statement("get_item_by_id",
        "SELECT * FROM test_items WHERE id = :id", prep_params);
    array_free(prep_params);
    TEST_ASSERT_EQUAL(1, prepared, "prepare should succeed");

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, id));

    test_item_t* item = model_prepared_one(dbid, test_item_instance,
        "get_item_by_id", params);
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

    // Prepare statement
    array_t* prep_params = array_create();
    mparams_fill_array(prep_params, mparam_int(status, 0));

    int prepared = __prepare_statement("get_items_by_status",
        "SELECT * FROM test_items WHERE status = :status", prep_params);
    array_free(prep_params);
    TEST_ASSERT_EQUAL(1, prepared, "prepare should succeed");

    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(status, 5));

    array_t* list = model_prepared_list(dbid, test_item_instance,
        "get_items_by_status", params);
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

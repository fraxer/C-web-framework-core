#include "framework.h"
#include "appconfig.h"
#include "session.h"
#include <string.h>
#include <ctype.h>
#include <time.h>

// ============================================================================
// Mock driver for testing session dispatch
// ============================================================================

static const char* mock_last_key = NULL;
static const char* mock_last_session_id = NULL;
static const char* mock_last_data = NULL;
static long mock_last_duration = 0;
static int mock_remove_expired_called = 0;
static int mock_expired_call_count = 0;

static void mock_reset(void) {
    mock_last_key = NULL;
    mock_last_session_id = NULL;
    mock_last_data = NULL;
    mock_last_duration = 0;
    mock_remove_expired_called = 0;
    mock_expired_call_count = 0;
}

static char* mock_create(const char* key, const char* data, long duration) {
    mock_last_key = key;
    mock_last_data = data;
    mock_last_duration = duration;
    return strdup("mock_session_id_001");
}

static char* mock_get(const char* key, const char* session_id) {
    mock_last_key = key;
    mock_last_session_id = session_id;
    return strdup("{\"user\":\"test\"}");
}

static int mock_update(const char* key, const char* session_id, const char* data) {
    mock_last_key = key;
    mock_last_session_id = session_id;
    mock_last_data = data;
    return 1;
}

static int mock_destroy(const char* key, const char* session_id) {
    mock_last_key = key;
    mock_last_session_id = session_id;
    return 1;
}

static void mock_remove_expired(const char* key) {
    mock_last_key = key;
    mock_remove_expired_called = 1;
}

static void mock_count_expired(const char* key) {
    (void)key;
    mock_expired_call_count++;
}

static const char* mock_svc_a_last_key = NULL;
static const char* mock_svc_b_last_key = NULL;

static char* mock_svc_a_create(const char* key, const char* data, long duration) {
    (void)data; (void)duration;
    mock_svc_a_last_key = key;
    return strdup("id_a");
}

static char* mock_svc_b_create(const char* key, const char* data, long duration) {
    (void)data; (void)duration;
    mock_svc_b_last_key = key;
    return strdup("id_b");
}

static session_t* mock_session_init(void) {
    session_t* session = malloc(sizeof(session_t));
    if (session == NULL) return NULL;

    session->create = mock_create;
    session->get = mock_get;
    session->update = mock_update;
    session->destroy = mock_destroy;
    session->remove_expired = mock_remove_expired;

    return session;
}

// ============================================================================
// Test helpers
// ============================================================================

static map_t* create_test_sessionconfigs(void) {
    map_t* map = map_create_ex(
        map_compare_string,
        map_copy_string,
        free,
        NULL,
        (map_free_fn)sessionconfig_free
    );
    if (map == NULL) return NULL;

    sessionconfig_t* sc = calloc(1, sizeof(sessionconfig_t));
    if (sc == NULL) { map_free(map); return NULL; }

    sc->driver = SESSION_TYPE_FS;
    strcpy(sc->storage_name, "test_sessions");
    sc->session = mock_session_init();

    map_insert(map, "test_service", sc);

    return map;
}

static void setup_test_sessionconfigs(void) {
    appconfig()->sessionconfigs = create_test_sessionconfigs();
}

static void teardown_test_sessionconfigs(void) {
    if (appconfig()->sessionconfigs != NULL) {
        map_free(appconfig()->sessionconfigs);
        appconfig()->sessionconfigs = NULL;
    }
}

// ============================================================================
// Test: session_create_id
// ============================================================================

TEST(test_session_create_id) {
    TEST_SUITE("session");
    TEST_CASE("session_create_id: returns non-NULL");

    char* id = session_create_id();
    TEST_ASSERT_NOT_NULL(id, "session_create_id should return non-NULL");

    TEST_CASE("session_create_id: returns 80-char hex string");
    TEST_ASSERT_EQUAL(80, (int)strlen(id), "session id length should be 80");

    for (size_t i = 0; i < strlen(id); i++) {
        if (!isxdigit((unsigned char)id[i])) {
            TEST_ASSERT(0, "session id should contain only hex characters");
            break;
        }
        if (i == strlen(id) - 1) {
            TEST_ASSERT(1, "all characters are hex");
        }
    }

    free(id);
}

TEST(test_session_create_id_uniqueness) {
    TEST_SUITE("session");
    TEST_CASE("session_create_id: generates unique IDs");

    #define NUM_IDS 100
    char* ids[NUM_IDS];

    for (int i = 0; i < NUM_IDS; i++) {
        ids[i] = session_create_id();
        TEST_ASSERT_NOT_NULL(ids[i], "session_create_id should not return NULL");
    }

    int duplicates = 0;
    for (int i = 0; i < NUM_IDS && !duplicates; i++) {
        for (int j = i + 1; j < NUM_IDS && !duplicates; j++) {
            if (ids[i] != NULL && ids[j] != NULL && strcmp(ids[i], ids[j]) == 0)
                duplicates = 1;
        }
    }
    TEST_ASSERT_EQUAL(0, duplicates, "no duplicate session IDs among 100 generated");

    for (int i = 0; i < NUM_IDS; i++)
        free(ids[i]);

    #undef NUM_IDS
}

TEST(test_session_create_id_no_path_traversal) {
    TEST_SUITE("session");
    TEST_CASE("session_create_id: no path traversal chars");

    char* id = session_create_id();
    TEST_ASSERT_NOT_NULL(id, "session_create_id should return non-NULL");

    int has_slash = 0;
    int has_dot = 0;
    int has_backslash = 0;
    int has_null_byte = 0;

    for (size_t i = 0; i < strlen(id); i++) {
        if (id[i] == '/') has_slash = 1;
        if (id[i] == '.') has_dot = 1;
        if (id[i] == '\\') has_backslash = 1;
        if (id[i] == '\0' && i < strlen(id)) has_null_byte = 1;
    }

    TEST_ASSERT_EQUAL(0, has_slash, "session id must not contain '/'");
    TEST_ASSERT_EQUAL(0, has_dot, "session id must not contain '.'");
    TEST_ASSERT_EQUAL(0, has_backslash, "session id must not contain '\\\\'");
    TEST_ASSERT_EQUAL(0, has_null_byte, "session id must not contain null bytes");

    free(id);
}

TEST(test_session_create_id_entropy) {
    TEST_SUITE("session");
    TEST_CASE("session_create_id: basic entropy check");

    char* id = session_create_id();
    TEST_ASSERT_NOT_NULL(id, "session_create_id should return non-NULL");

    int char_counts[16] = {0};
    for (size_t i = 0; i < strlen(id); i++) {
        char c = id[i];
        int idx = -1;
        if (c >= '0' && c <= '9') idx = c - '0';
        else if (c >= 'a' && c <= 'f') idx = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') idx = 10 + (c - 'A');

        if (idx >= 0 && idx < 16)
            char_counts[idx]++;
    }

    int distinct_chars = 0;
    for (int i = 0; i < 16; i++) {
        if (char_counts[i] > 0)
            distinct_chars++;
    }

    TEST_ASSERT(distinct_chars >= 8,
        "session id should use at least 8 distinct hex digits (basic entropy)");

    free(id);
}

// ============================================================================
// Test: sessionconfig_find
// ============================================================================

TEST(test_sessionconfig_find_null_key) {
    TEST_SUITE("session");
    TEST_CASE("sessionconfig_find: NULL key returns NULL");

    sessionconfig_t* result = sessionconfig_find(NULL);
    TEST_ASSERT_NULL(result, "sessionconfig_find(NULL) should return NULL");
}

TEST(test_sessionconfig_find_null_map) {
    TEST_SUITE("session");
    TEST_CASE("sessionconfig_find: NULL sessionconfigs returns NULL");

    appconfig()->sessionconfigs = NULL;

    sessionconfig_t* result = sessionconfig_find("anything");
    TEST_ASSERT_NULL(result, "sessionconfig_find with NULL map should return NULL");
}

TEST(test_sessionconfig_find_nonexistent_key) {
    TEST_SUITE("session");
    TEST_CASE("sessionconfig_find: nonexistent key returns NULL");

    setup_test_sessionconfigs();

    sessionconfig_t* result = sessionconfig_find("nonexistent_service");
    TEST_ASSERT_NULL(result, "sessionconfig_find for missing key should return NULL");

    teardown_test_sessionconfigs();
}

TEST(test_sessionconfig_find_valid_key) {
    TEST_SUITE("session");
    TEST_CASE("sessionconfig_find: valid key returns config");

    setup_test_sessionconfigs();

    sessionconfig_t* result = sessionconfig_find("test_service");
    TEST_ASSERT_NOT_NULL(result, "sessionconfig_find for existing key should return config");
    TEST_ASSERT_EQUAL(SESSION_TYPE_FS, result->driver, "driver should be SESSION_TYPE_FS");
    TEST_ASSERT_STR_EQUAL("test_sessions", result->storage_name, "storage_name should match");
    TEST_ASSERT_NOT_NULL(result->session, "session driver should be set");

    teardown_test_sessionconfigs();
}

TEST(test_sessionconfig_find_empty_key) {
    TEST_SUITE("session");
    TEST_CASE("sessionconfig_find: empty string key returns NULL");

    setup_test_sessionconfigs();

    sessionconfig_t* result = sessionconfig_find("");
    TEST_ASSERT_NULL(result, "sessionconfig_find for empty key should return NULL");

    teardown_test_sessionconfigs();
}

// ============================================================================
// Test: session dispatch - NULL safety
// ============================================================================

TEST(test_session_create_null_key) {
    TEST_SUITE("session");
    TEST_CASE("session_create: NULL key returns NULL");

    setup_test_sessionconfigs();

    char* id = session_create(NULL, "data", 3600);
    TEST_ASSERT_NULL(id, "session_create with NULL key should return NULL");

    teardown_test_sessionconfigs();
}

TEST(test_session_create_invalid_key) {
    TEST_SUITE("session");
    TEST_CASE("session_create: invalid key returns NULL");

    setup_test_sessionconfigs();

    char* id = session_create("nonexistent", "data", 3600);
    TEST_ASSERT_NULL(id, "session_create with invalid key should return NULL");

    teardown_test_sessionconfigs();
}

TEST(test_session_get_null_key) {
    TEST_SUITE("session");
    TEST_CASE("session_get: NULL key returns NULL");

    setup_test_sessionconfigs();

    char* data = session_get(NULL, "session_id");
    TEST_ASSERT_NULL(data, "session_get with NULL key should return NULL");

    teardown_test_sessionconfigs();
}

TEST(test_session_get_invalid_key) {
    TEST_SUITE("session");
    TEST_CASE("session_get: invalid key returns NULL");

    setup_test_sessionconfigs();

    char* data = session_get("nonexistent", "session_id");
    TEST_ASSERT_NULL(data, "session_get with invalid key should return NULL");

    teardown_test_sessionconfigs();
}

TEST(test_session_update_null_key) {
    TEST_SUITE("session");
    TEST_CASE("session_update: NULL key returns 0");

    setup_test_sessionconfigs();

    int result = session_update(NULL, "session_id", "data");
    TEST_ASSERT_EQUAL(0, result, "session_update with NULL key should return 0");

    teardown_test_sessionconfigs();
}

TEST(test_session_update_invalid_key) {
    TEST_SUITE("session");
    TEST_CASE("session_update: invalid key returns 0");

    setup_test_sessionconfigs();

    int result = session_update("nonexistent", "session_id", "data");
    TEST_ASSERT_EQUAL(0, result, "session_update with invalid key should return 0");

    teardown_test_sessionconfigs();
}

TEST(test_session_destroy_null_key) {
    TEST_SUITE("session");
    TEST_CASE("session_destroy: NULL key returns 0");

    setup_test_sessionconfigs();

    int result = session_destroy(NULL, "session_id");
    TEST_ASSERT_EQUAL(0, result, "session_destroy with NULL key should return 0");

    teardown_test_sessionconfigs();
}

TEST(test_session_destroy_invalid_key) {
    TEST_SUITE("session");
    TEST_CASE("session_destroy: invalid key returns 0");

    setup_test_sessionconfigs();

    int result = session_destroy("nonexistent", "session_id");
    TEST_ASSERT_EQUAL(0, result, "session_destroy with invalid key should return 0");

    teardown_test_sessionconfigs();
}

// ============================================================================
// Test: session dispatch - correct routing to driver
// ============================================================================

TEST(test_session_create_dispatch) {
    TEST_SUITE("session");
    TEST_CASE("session_create: dispatches to correct driver with key");

    setup_test_sessionconfigs();
    mock_reset();

    char* id = session_create("test_service", "{\"token\":\"abc\"}", 7200);
    TEST_ASSERT_NOT_NULL(id, "session_create should return session id");
    TEST_ASSERT_STR_EQUAL("mock_session_id_001", id, "should return mock session id");
    TEST_ASSERT_STR_EQUAL("test_service", mock_last_key, "driver should receive correct key");
    TEST_ASSERT_STR_EQUAL("{\"token\":\"abc\"}", mock_last_data, "driver should receive correct data");
    TEST_ASSERT_EQUAL(7200, (int)mock_last_duration, "driver should receive correct duration");

    free(id);
    teardown_test_sessionconfigs();
}

TEST(test_session_get_dispatch) {
    TEST_SUITE("session");
    TEST_CASE("session_get: dispatches to correct driver with key");

    setup_test_sessionconfigs();
    mock_reset();

    char* data = session_get("test_service", "sid_123");
    TEST_ASSERT_NOT_NULL(data, "session_get should return data");
    TEST_ASSERT_STR_EQUAL("{\"user\":\"test\"}", data, "should return mock data");
    TEST_ASSERT_STR_EQUAL("test_service", mock_last_key, "driver should receive correct key");
    TEST_ASSERT_STR_EQUAL("sid_123", mock_last_session_id, "driver should receive correct session_id");

    free(data);
    teardown_test_sessionconfigs();
}

TEST(test_session_update_dispatch) {
    TEST_SUITE("session");
    TEST_CASE("session_update: dispatches to correct driver with key");

    setup_test_sessionconfigs();
    mock_reset();

    int result = session_update("test_service", "sid_123", "{\"updated\":true}");
    TEST_ASSERT_EQUAL(1, result, "session_update should return 1");
    TEST_ASSERT_STR_EQUAL("test_service", mock_last_key, "driver should receive correct key");
    TEST_ASSERT_STR_EQUAL("sid_123", mock_last_session_id, "driver should receive correct session_id");
    TEST_ASSERT_STR_EQUAL("{\"updated\":true}", mock_last_data, "driver should receive correct data");

    teardown_test_sessionconfigs();
}

TEST(test_session_destroy_dispatch) {
    TEST_SUITE("session");
    TEST_CASE("session_destroy: dispatches to correct driver with key");

    setup_test_sessionconfigs();
    mock_reset();

    int result = session_destroy("test_service", "sid_456");
    TEST_ASSERT_EQUAL(1, result, "session_destroy should return 1");
    TEST_ASSERT_STR_EQUAL("test_service", mock_last_key, "driver should receive correct key");
    TEST_ASSERT_STR_EQUAL("sid_456", mock_last_session_id, "driver should receive correct session_id");

    teardown_test_sessionconfigs();
}

// ============================================================================
// Test: sessionconfig_clear / sessionconfig_free
// ============================================================================

TEST(test_sessionconfig_clear) {
    TEST_SUITE("session");
    TEST_CASE("sessionconfig_clear: frees session and zeroes struct");

    sessionconfig_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.driver = SESSION_TYPE_REDIS;
    strcpy(sc.host_id, "redis.test");
    sc.session = mock_session_init();

    sessionconfig_clear(&sc);

    TEST_ASSERT_EQUAL(SESSION_TYPE_NONE, sc.driver, "driver should be zeroed");
    TEST_ASSERT_NULL(sc.session, "session should be NULL after clear");
    TEST_ASSERT_EQUAL(0, (int)sc.host_id[0], "host_id should be zeroed");
}

TEST(test_sessionconfig_free_null) {
    TEST_SUITE("session");
    TEST_CASE("sessionconfig_free: NULL doesn't crash");

    sessionconfig_free(NULL);
    TEST_ASSERT(1, "sessionconfig_free(NULL) should not crash");
}

TEST(test_sessionconfig_clear_null_session) {
    TEST_SUITE("session");
    TEST_CASE("sessionconfig_clear: handles NULL session pointer");

    sessionconfig_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.driver = SESSION_TYPE_FS;
    sc.session = NULL;

    sessionconfig_clear(&sc);

    TEST_ASSERT_EQUAL(SESSION_TYPE_NONE, sc.driver, "driver should be zeroed");
    TEST_ASSERT_NULL(sc.session, "session should remain NULL");
}

// ============================================================================
// Test: session dispatch with NULL session driver pointer
// ============================================================================

TEST(test_session_create_null_driver) {
    TEST_SUITE("session");
    TEST_CASE("session_create: config with NULL session driver returns NULL");

    map_t* map = map_create_ex(
        map_compare_string, map_copy_string, free,
        NULL, (map_free_fn)sessionconfig_free
    );

    sessionconfig_t* sc = calloc(1, sizeof(sessionconfig_t));
    sc->driver = SESSION_TYPE_FS;
    sc->session = NULL;
    map_insert(map, "broken", sc);

    appconfig()->sessionconfigs = map;

    char* id = session_create("broken", "data", 3600);
    TEST_ASSERT_NULL(id, "session_create with NULL session driver should return NULL");

    char* data = session_get("broken", "sid");
    TEST_ASSERT_NULL(data, "session_get with NULL session driver should return NULL");

    int upd = session_update("broken", "sid", "data");
    TEST_ASSERT_EQUAL(0, upd, "session_update with NULL session driver should return 0");

    int del = session_destroy("broken", "sid");
    TEST_ASSERT_EQUAL(0, del, "session_destroy with NULL session driver should return 0");

    map_free(map);
    appconfig()->sessionconfigs = NULL;
}

// ============================================================================
// Test: multiple configs - isolation between services
// ============================================================================

TEST(test_session_multiple_configs_isolation) {
    TEST_SUITE("session");
    TEST_CASE("multiple configs: each service uses its own config");

    mock_svc_a_last_key = NULL;
    mock_svc_b_last_key = NULL;

    map_t* map = map_create_ex(
        map_compare_string, map_copy_string, free,
        NULL, (map_free_fn)sessionconfig_free
    );

    sessionconfig_t* sc_a = calloc(1, sizeof(sessionconfig_t));
    sc_a->driver = SESSION_TYPE_FS;
    sc_a->session = calloc(1, sizeof(session_t));
    sc_a->session->create = mock_svc_a_create;
    sc_a->session->remove_expired = mock_remove_expired;
    map_insert(map, "service_a", sc_a);

    sessionconfig_t* sc_b = calloc(1, sizeof(sessionconfig_t));
    sc_b->driver = SESSION_TYPE_REDIS;
    sc_b->session = calloc(1, sizeof(session_t));
    sc_b->session->create = mock_svc_b_create;
    sc_b->session->remove_expired = mock_remove_expired;
    map_insert(map, "service_b", sc_b);

    appconfig()->sessionconfigs = map;

    char* id_a = session_create("service_a", "data", 100);
    TEST_ASSERT_NOT_NULL(id_a, "service_a create should succeed");
    TEST_ASSERT_STR_EQUAL("id_a", id_a, "service_a should return its own id");
    TEST_ASSERT_STR_EQUAL("service_a", mock_svc_a_last_key, "service_a driver should receive its key");

    char* id_b = session_create("service_b", "data", 200);
    TEST_ASSERT_NOT_NULL(id_b, "service_b create should succeed");
    TEST_ASSERT_STR_EQUAL("id_b", id_b, "service_b should return its own id");
    TEST_ASSERT_STR_EQUAL("service_b", mock_svc_b_last_key, "service_b driver should receive its key");

    TEST_ASSERT(strcmp(id_a, id_b) != 0, "different services should return different ids");

    free(id_a);
    free(id_b);
    map_free(map);
    appconfig()->sessionconfigs = NULL;
}

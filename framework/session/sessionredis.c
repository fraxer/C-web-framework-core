#include "db.h"
#include "log.h"
#include "appconfig.h"
#include "helpers.h"
#include "sessionredis.h"
#include "aes256gcm.h"

static char* __create(const char* key, const char* data, long duration);
static char* __get(const char* key, const char* session_id);
static int __update(const char* key, const char* session_id, const char* data);
static int __destroy(const char* key, const char* session_id);
static void __remove_expired(const char* key);

session_t* sessionredis_init() {
    session_t* session = malloc(sizeof * session);
    if (session == NULL) return NULL;

    session->create = __create;
    session->get = __get;
    session->update = __update;
    session->destroy = __destroy;
    session->remove_expired = __remove_expired;

    return session;
}

char* __create(const char* key, const char* data, long duration) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL) return NULL;

    char* session_id = session_create_id();
    if (session_id == NULL) {
        log_error("sessionredis__create: alloc memory for id failed\n");
        return NULL;
    }

    char* encrypted_data = aes256gcm_encrypt(data, config->secret);
    if (encrypted_data == NULL) {
        log_error("sessionredis__create: encryption failed\n");
        free(session_id);
        return NULL;
    }

    int res = 0;
    const db_table_cell_t* field = NULL;

    dbresult_t* result = dbqueryf(config->host_id, "SET %s %s EX %ld", session_id, encrypted_data, duration);
    free(encrypted_data);

    if (!dbresult_ok(result))
        goto failed;

    field = dbresult_field(result, NULL);
    if (field == NULL)
        goto failed;
    if (!cmpstr_lower(field->value, "OK"))
        goto failed;

    res = 1;

    failed:

    dbresult_free(result);

    if (!res) {
        log_error("sessionredis__create: create failed\n");
        free(session_id);
        return NULL;
    }

    return session_id;
}

char* __get(const char* key, const char* session_id) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL) return NULL;

    char* data = NULL;

    dbresult_t* result = dbqueryf(config->host_id, "GET %s", session_id);
    if (!dbresult_ok(result))
        goto failed;

    const db_table_cell_t* field = dbresult_field(result, NULL);
    if (field == NULL)
        goto failed;

    if (field->length > 0)
        data = aes256gcm_decrypt(field->value, config->secret);

    failed:

    dbresult_free(result);

    return data;
}

int __update(const char* key, const char* session_id, const char* data) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL) return 0;

    int res = 0;
    const db_table_cell_t* field = NULL;

    char* encrypted_data = aes256gcm_encrypt(data, config->secret);
    if (encrypted_data == NULL) {
        log_error("sessionredis__update: encryption failed\n");
        return 0;
    }

    dbresult_t* result = dbqueryf(config->host_id, "SET %s %s KEEPTTL", session_id, encrypted_data);
    free(encrypted_data);

    if (!dbresult_ok(result))
        goto failed;

    field = dbresult_field(result, NULL);
    if (field == NULL)
        goto failed;
    if (!cmpstr_lower(field->value, "OK"))
        goto failed;

    res = 1;

    failed:

    dbresult_free(result);

    return res;
}

int __destroy(const char* key, const char* session_id) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL) return 0;

    dbresult_t* result = dbqueryf(config->host_id, "DEL %s", session_id);
    dbresult_free(result);

    return 1;
}

void __remove_expired(const char* key) {
    (void)key;
}

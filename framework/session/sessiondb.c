#define _GNU_SOURCE

#include "db.h"
#include "log.h"
#include "appconfig.h"
#include "helpers.h"
#include "model.h"
#include "sessiondb.h"
#include "aes256gcm.h"

static char* __create(const char* key, const char* data, long duration);
static char* __get(const char* key, const char* session_id);
static int __update(const char* key, const char* session_id, const char* data);
static int __destroy(const char* key, const char* session_id);
static void __remove_expired(const char* key);

session_t* sessiondb_init() {
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
        log_error("sessiondb__create: alloc memory for id failed\n");
        return NULL;
    }

    char* encrypted_data = aes256gcm_encrypt(data, config->secret);
    if (encrypted_data == NULL) {
        log_error("sessiondb__create: encryption failed\n");
        free(session_id);
        return NULL;
    }

    const long long expired_at = (long long)time(NULL) + duration;

    array_t* params = array_create();
    if (params == NULL) {
        free(session_id);
        free(encrypted_data);
        return NULL;
    }

    mparams_fill_array(params,
        mparam_text(session_id, session_id),
        mparam_text(encrypted_data, encrypted_data),
        mparam_bigint(expired_at, expired_at)
    );

    dbresult_t* result = dbquery(config->host_id,
        "INSERT INTO sessions (session_id, data, expired_at) "
        "VALUES (:session_id, :data, :expired_at)",
        params);

    const int ok = dbresult_ok(result);
    dbresult_free(result);
    array_free(params);
    free(encrypted_data);

    if (!ok) {
        log_error("sessiondb__create: insert failed\n");
        free(session_id);
        return NULL;
    }

    return session_id;
}

char* __get(const char* key, const char* session_id) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL) return NULL;

    array_t* params = array_create();
    if (params == NULL) return NULL;

    mparams_fill_array(params,
        mparam_text(session_id, session_id)
    );

    dbresult_t* result = dbquery(config->host_id,
        "SELECT data, expired_at FROM sessions WHERE session_id = :session_id",
        params);

    char* data = NULL;

    if (!dbresult_ok(result) || dbresult_query_rows(result) == 0)
        goto done;

    db_table_cell_t* field_expired = dbresult_field(result, "expired_at");
    if (field_expired == NULL)
        goto done;

    const long long expired_at = strtoll(field_expired->value, NULL, 10);
    if (expired_at <= (long long)time(NULL)) {
        dbresult_free(result);
        array_free(params);
        __destroy(key, session_id);
        return NULL;
    }

    db_table_cell_t* field_data = dbresult_field(result, "data");
    if (field_data != NULL && field_data->length > 0)
        data = aes256gcm_decrypt(field_data->value, config->secret);

    done:

    dbresult_free(result);
    array_free(params);

    return data;
}

int __update(const char* key, const char* session_id, const char* data) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL) return 0;

    const long long now = (long long)time(NULL);
    char* encrypted_data = aes256gcm_encrypt(data, config->secret);
    if (encrypted_data == NULL) {
        log_error("sessiondb__update: encryption failed\n");
        return 0;
    }

    array_t* params = array_create();
    if (params == NULL) {
        free(encrypted_data);
        return 0;
    }

    mparams_fill_array(params,
        mparam_text(encrypted_data, encrypted_data),
        mparam_text(session_id, session_id),
        mparam_bigint(now, now)
    );

    dbresult_t* result = dbquery(config->host_id,
        "UPDATE sessions SET data = :data "
        "WHERE session_id = :session_id AND expired_at > :now",
        params);

    const int ok = dbresult_ok(result);
    dbresult_free(result);
    array_free(params);
    free(encrypted_data);

    return ok;
}

int __destroy(const char* key, const char* session_id) {
    if (session_id == NULL) return 0;

    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL) return 0;

    array_t* params = array_create();
    if (params == NULL) return 0;

    mparams_fill_array(params,
        mparam_text(session_id, session_id)
    );

    dbresult_t* result = dbquery(config->host_id,
        "DELETE FROM sessions WHERE session_id = :session_id",
        params);

    const int ok = dbresult_ok(result);
    dbresult_free(result);
    array_free(params);

    return ok;
}

void __remove_expired(const char* key) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL) return;

    const long long now = (long long)time(NULL);

    array_t* params = array_create();
    if (params == NULL) return;

    mparams_fill_array(params,
        mparam_bigint(now, now)
    );

    dbresult_t* result = dbquery(config->host_id,
        "DELETE FROM sessions WHERE expired_at <= :now",
        params);

    dbresult_free(result);
    array_free(params);
}

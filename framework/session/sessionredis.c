#include "db.h"
#include "log.h"
#include "appconfig.h"
#include "helpers.h"
#include "sessionredis.h"

static char* __create(const char* data, long duration);
static char* __get(const char* session_id);
static int __update(const char* session_id, const char* data);
static int __destroy(const char* session_id);
static void __remove_expired(void);

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

char* __create(const char* data, long duration) {
    char* session_id = session_create_id();
    if (session_id == NULL) {
        log_error("sessionredis__create: alloc memory for id failed\n");
        return NULL;
    }

    int res = 0;
    const db_table_cell_t* field = NULL;

    dbresult_t* result = dbqueryf(appconfig()->sessionconfig.host_id, "SET %s %s EX %ld", session_id, data, duration);
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

char* __get(const char* session_id) {
    char* data = NULL;

    dbresult_t* result = dbqueryf(appconfig()->sessionconfig.host_id, "GET %s", session_id);
    if (!dbresult_ok(result))
        goto failed;

    const db_table_cell_t* field = dbresult_field(result, NULL);
    if (field == NULL)
        goto failed;

    if (field->length > 0)
        data = strdup(field->value);

    failed:

    dbresult_free(result);

    return data;
}

int __update(const char* session_id, const char* data) {
    int res = 0;
    const db_table_cell_t* field = NULL;

    dbresult_t* result = dbqueryf(appconfig()->sessionconfig.host_id, "SET %s %s KEEPTTL", session_id, data);
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

int __destroy(const char* session_id) {
    dbresult_t* result = dbqueryf(appconfig()->sessionconfig.host_id, "DEL %s", session_id);
    dbresult_free(result);

    return 1;
}

void __remove_expired(void) {}

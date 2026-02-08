#define _GNU_SOURCE

#include "storage.h"
#include "log.h"
#include "appconfig.h"
#include "sessionfile.h"

static const char* __folder = "sessions";

static char* __create(const char* data, long duration);
static char* __get(const char* session_id);
static int __update(const char* session_id, const char* data);
static int __destroy(const char* session_id);
static void __remove_expired(void);

session_t* sessionfile_init() {
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
        log_error("sessionfile__create: alloc memory for id failed\n");
        return NULL;
    }

    const long expired_at = (long)time(NULL) + duration;
    char* content = NULL;
    const int content_len = asprintf(&content, "%ld\n%s", expired_at, data);
    if (content_len == -1) {
        log_error("sessionfile__create: alloc memory for content failed\n");
        free(session_id);
        return NULL;
    }

    if (!storage_file_data_put(appconfig()->sessionconfig.storage_name, content, content_len, "%s/%s", __folder, session_id)) {
        log_error("sessionfile__create: storage_file_data_put failed\n");
        free(content);
        free(session_id);
        return NULL;
    }

    free(content);
    return session_id;
}

char* __get(const char* session_id) {
    file_t file = storage_file_get(appconfig()->sessionconfig.storage_name, "%s/%s", __folder, session_id);
    if (!file.ok) return NULL;

    char* content = file.content(&file);
    file.close(&file);

    if (content == NULL) return NULL;

    char* endptr = NULL;
    const time_t expired_at = (time_t)strtol(content, &endptr, 10);
    if (endptr == NULL || *endptr != '\n' || expired_at <= time(NULL)) {
        free(content);
        storage_file_remove(appconfig()->sessionconfig.storage_name, "%s/%s", __folder, session_id);
        return NULL;
    }

    char* data = endptr + 1;
    memmove(content, data, strlen(data) + 1);

    return content;
}

int __update(const char* session_id, const char* data) {
    file_t file = storage_file_get(appconfig()->sessionconfig.storage_name, "%s/%s", __folder, session_id);
    if (!file.ok) return 0;

    char* old_content = file.content(&file);
    file.close(&file);

    if (old_content == NULL) return 0;

    char* endptr = NULL;
    const long expired_at = strtol(old_content, &endptr, 10);
    free(old_content);

    if (endptr == NULL || *endptr != '\n' || expired_at <= (long)time(NULL)) {
        storage_file_remove(appconfig()->sessionconfig.storage_name, "%s/%s", __folder, session_id);
        return 0;
    }

    char* content = NULL;
    const int content_len = asprintf(&content, "%ld\n%s", expired_at, data);
    if (content_len == -1) {
        log_error("sessionfile__update: alloc memory for content failed\n");
        return 0;
    }

    if (!storage_file_data_put(appconfig()->sessionconfig.storage_name, content, content_len, "%s/%s", __folder, session_id)) {
        log_error("sessionfile__update: storage_file_data_put failed\n");
        free(content);
        return 0;
    }

    free(content);
    return 1;
}

int __destroy(const char* session_id) {
    if (session_id == NULL) return 0;

    if (!storage_file_remove(appconfig()->sessionconfig.storage_name, "%s/%s", __folder, session_id)) {
        log_error("sessionfile__destroy: storage_file_remove failed\n");
        return 0;
    }

    return 1;
}

void __remove_expired(void) {
    if (!storage_file_exist(appconfig()->sessionconfig.storage_name, __folder))
        return;

    array_t* files = storage_file_list(appconfig()->sessionconfig.storage_name, __folder);
    if (files == NULL) return;

    const time_t now = time(NULL);

    for (size_t i = 0; i < array_size(files); i++) {
        file_t file = storage_file_get(appconfig()->sessionconfig.storage_name, "%s", array_get(files, i));
        if (!file.ok) continue;

        char* content = file.content(&file);
        file.close(&file);

        int expired = 1;
        if (content != NULL) {
            char* endptr = NULL;
            const time_t expired_at = (time_t)strtol(content, &endptr, 10);
            if (endptr != NULL && *endptr == '\n')
                expired = expired_at <= now;
            free(content);
        }

        if (expired)
            storage_file_remove(appconfig()->sessionconfig.storage_name, "%s", array_get(files, i));
    }

    array_free(files);
}

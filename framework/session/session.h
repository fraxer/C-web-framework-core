#ifndef __SESSION__
#define __SESSION__

#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/limits.h>

#include "aes256gcm.h"

typedef enum {
    SESSION_TYPE_NONE = 0,
    SESSION_TYPE_FS,
    SESSION_TYPE_REDIS,
    SESSION_TYPE_DB,
} session_type_e;

/**
 * @brief Session handler interface - defines callbacks for session operations.
 */
typedef struct session {
    /**
     * @brief Creates a new session.
     * @param key Session configuration key.
     * @param data Session data to store.
     * @param duration Session lifetime.
     * @return Pointer to the created session ID, or NULL on failure.
     */
    char*(*create)(const char* key, const char* data, long duration);

    /**
     * @brief Retrieves session data by ID.
     * @param key Session configuration key.
     * @param session_id ID of the session to retrieve.
     * @return Pointer to session data, or NULL on failure.
     */
    char*(*get)(const char* key, const char* session_id);

    /**
     * @brief Updates session data.
     * @param key Session configuration key.
     * @param session_id ID of the session to update.
     * @param data New session data.
     * @return 1 on success, 0 on failure.
     */
    int(*update)(const char* key, const char* session_id, const char* data);

    /**
     * @brief Destroys a session by ID.
     * @param key Session configuration key.
     * @param session_id ID of the session to destroy.
     * @return 1 on success, 0 on failure.
     */
    int(*destroy)(const char* key, const char* session_id);

    /**
     * @brief Removes all expired sessions for the given key.
     * @param key Session configuration key.
     */
    void(*remove_expired)(const char* key);
} session_t;

typedef struct sessionconfig {
    session_type_e driver;
    char storage_name[NAME_MAX];
    char host_id[NAME_MAX];
    session_t* session;
    unsigned char secret[AES256GCM_KEY_SIZE];
} sessionconfig_t;

char* session_create_id();
char* session_create(const char* key, const char* data, long duration);
int session_destroy(const char* key, const char* session_id);
int session_update(const char* key, const char* session_id, const char* data);
char* session_get(const char* key, const char* session_id);
void session_remove_expired(void);
void sessionconfig_clear(sessionconfig_t* sessionconfig);

session_t* sessionfile_init();
session_t* sessionredis_init();
session_t* sessiondb_init();

sessionconfig_t* sessionconfig_find(const char* key);
void sessionconfig_free(sessionconfig_t* sessionconfig);

#endif
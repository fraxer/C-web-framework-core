#include <openssl/evp.h>
#include <openssl/rand.h>

#include "log.h"
#include "appconfig.h"
#include "helpers.h"
#include "session.h"

/** Size of the session ID in bytes (40 bytes) */
#define SESSION_ID_SIZE 40

/** Size of the hexadecimal representation of the session ID (80 characters + terminating null) */
#define SESSION_ID_HEX_SIZE 81

/**
 * @brief Generates a random session ID and returns it as a hexadecimal string.
 *
 * The session ID is a random 40-byte string represented as an
 * 80-character hexadecimal string. The result is null-terminated and allocated
 * in dynamic memory via malloc. The caller is responsible for freeing
 * the memory using free() when the ID is no longer needed.
 *
 * @return Pointer to a randomly generated session ID as a hexadecimal string,
 *         or NULL on error (RAND_bytes failure or memory allocation failure).
 */
char* session_create_id() {
    unsigned char id[SESSION_ID_SIZE];
    if (RAND_bytes(id, SESSION_ID_SIZE - 1) != 1) {
        log_error("session_create_id: create session id failed\n");
        return 0;
    }

    char* id_hex = malloc(SESSION_ID_HEX_SIZE);
    if (id_hex == NULL) return NULL;

    bytes_to_hex(id, SESSION_ID_SIZE, id_hex);

    return id_hex;
}

/**
 * @brief Finds a session configuration by the specified key.
 *
 * Searches for a session configuration in the global configuration table (sessionconfigs)
 * belonging to the current application configuration. Search is performed by string key.
 *
 * @param key Key to search for the session configuration. Must not be NULL.
 * @return Pointer to the found sessionconfig_t structure, or NULL if:
 *         - key is NULL
 *         - session configuration table is not initialized
 *         - configuration with the specified key is not found
 */
sessionconfig_t* sessionconfig_find(const char* key) {
    if (key == NULL) return NULL;
    if (appconfig()->sessionconfigs == NULL) return NULL;

    return (sessionconfig_t*)map_find(appconfig()->sessionconfigs, key);
}

/**
 * @brief Creates a new session with the specified parameters.
 *
 * Before creating a session, removes expired sessions from all registered
 * configurations. Then finds the configuration by key and delegates session creation
 * to the appropriate handler (create callback).
 *
 * @param key Session configuration key that defines the session type or context.
 * @param data Session data to store (e.g., serialized state).
 * @param duration Session lifetime (in seconds or other units depending on implementation).
 * @return Pointer to the created session ID, or NULL if:
 *         - configuration with the specified key is not found
 *         - session handler is not initialized
 *         - session creation failed
 */
char* session_create(const char* key, const char* data, long duration) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL || config->session == NULL) return NULL;

    config->session->remove_expired(key);

    return config->session->create(key, data, duration);
}

/**
 * @brief Destroys a session by its ID.
 *
 * Finds the session configuration by key and delegates session destruction
 * to the appropriate handler (destroy callback).
 *
 * @param key Session configuration key.
 * @param session_id ID of the session to be destroyed.
 * @return 1 if session was successfully destroyed, 0 on error or if session not found.
 */
int session_destroy(const char* key, const char* session_id) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL || config->session == NULL) return 0;

    return config->session->destroy(key, session_id);
}

/**
 * @brief Updates data of an existing session.
 *
 * Finds the session configuration by key and delegates data update
 * to the appropriate handler (update callback).
 *
 * @param key Session configuration key.
 * @param session_id ID of the session whose data needs to be updated.
 * @param data New session data.
 * @return 1 if session was successfully updated, 0 on error or if session not found.
 */
int session_update(const char* key, const char* session_id, const char* data) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL || config->session == NULL) return 0;

    return config->session->update(key, session_id, data);
}

/**
 * @brief Retrieves session data by its ID.
 *
 * Finds the session configuration by key and delegates data retrieval
 * to the appropriate handler (get callback).
 *
 * @param key Session configuration key.
 * @param session_id ID of the session whose data needs to be retrieved.
 * @return Pointer to session data, or NULL if:
 *         - configuration with the specified key is not found
 *         - session handler is not initialized
 *         - session is not found or has expired
 *
 * @note The caller may be responsible for freeing the returned memory,
 *       depending on the handler implementation.
 */
char* session_get(const char* key, const char* session_id) {
    sessionconfig_t* config = sessionconfig_find(key);
    if (config == NULL || config->session == NULL) return NULL;

    return config->session->get(key, session_id);
}

/**
 * @brief Clears a session configuration structure, freeing allocated memory.
 *
 * Frees memory allocated for the session handler (session) and zeroes out
 * the entire configuration structure using memset. Does not free the
 * sessionconfig_t structure itself — this should be done separately via
 * sessionconfig_free().
 *
 * @param sessionconfig Pointer to the session configuration structure to clear.
 *
 * @note This function assumes the sessionconfig_t structure is already allocated.
 *       After calling this function, the structure will contain zero bytes.
 */
void sessionconfig_clear(sessionconfig_t* sessionconfig) {
    if (sessionconfig->session != NULL)
        free(sessionconfig->session);

    memset(sessionconfig, 0, sizeof(sessionconfig_t));
}

/**
 * @brief Frees a session configuration structure and all associated memory.
 *
 * Performs complete cleanup of the session configuration: first calls
 * sessionconfig_clear() to free internal structures (session handler),
 * then frees the sessionconfig_t structure itself.
 *
 * @param sessionconfig Pointer to the session configuration structure to free.
 *
 * @note If NULL is passed, the function simply returns without any action.
 *       After calling this function, the sessionconfig pointer becomes invalid.
 */
void sessionconfig_free(sessionconfig_t* sessionconfig) {
    if (sessionconfig == NULL) return;

    sessionconfig_clear(sessionconfig);
    free(sessionconfig);
}

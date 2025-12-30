#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

#include "httpclientpool.h"
#include "connection.h"
#include "log.h"

static connection_pool_t* global_pool = NULL;
static pthread_once_t global_pool_once = PTHREAD_ONCE_INIT;

static void __global_pool_init_once(void);
static char* __make_host_key(const char* host, short port);
static void __host_connections_free(void* arg);
static void __close_pooled_connection(pooled_connection_t* pc);
static int __is_connection_alive(connection_t* connection);

connection_pool_t* httpclientpool_create(void) {
    connection_pool_t* pool = malloc(sizeof * pool);
    if (pool == NULL) return NULL;

    pool->hosts = map_create_ex(
        map_compare_string,
        map_copy_string,
        free,
        NULL,
        __host_connections_free
    );

    if (pool->hosts == NULL) {
        free(pool);
        return NULL;
    }

    pthread_mutex_init(&pool->mutex, NULL);

    return pool;
}

void httpclientpool_free(connection_pool_t* pool) {
    if (pool == NULL) return;

    pthread_mutex_lock(&pool->mutex);
    map_free(pool->hosts);
    pthread_mutex_unlock(&pool->mutex);
    pthread_mutex_destroy(&pool->mutex);

    free(pool);
}

connection_t* httpclientpool_acquire(connection_pool_t* pool, const char* host, short port, int use_ssl) {
    if (pool == NULL || host == NULL) return NULL;

    char* key = __make_host_key(host, port);
    if (key == NULL) return NULL;

    connection_t* result = NULL;
    time_t now = time(NULL);

    pthread_mutex_lock(&pool->mutex);

    host_connections_t* hc = map_find(pool->hosts, key);
    if (hc != NULL) {
        pooled_connection_t* prev = NULL;
        pooled_connection_t* pc = hc->connections;

        while (pc != NULL) {
            // Skip busy or expired connections
            if (pc->busy || pc->expires_at <= now || pc->use_ssl != use_ssl) {
                prev = pc;
                pc = pc->next;
                continue;
            }

            // Check if connection is still alive
            if (!__is_connection_alive(pc->connection)) {
                // Remove dead connection
                pooled_connection_t* dead = pc;
                if (prev == NULL) {
                    hc->connections = pc->next;
                } else {
                    prev->next = pc->next;
                }
                pc = pc->next;
                hc->count--;

                __close_pooled_connection(dead);
                free(dead);
                continue;
            }

            // Found a valid connection
            pc->busy = 1;
            result = pc->connection;
            break;
        }
    }

    pthread_mutex_unlock(&pool->mutex);
    free(key);

    return result;
}

void httpclientpool_release(connection_pool_t* pool, const char* host, short port, connection_t* connection, int use_ssl) {
    if (pool == NULL || host == NULL || connection == NULL) return;

    char* key = __make_host_key(host, port);
    if (key == NULL) {
        // Can't create key, just close the connection
        connection->close(connection);
        connection_free(connection);
        return;
    }

    pthread_mutex_lock(&pool->mutex);

    host_connections_t* hc = map_find(pool->hosts, key);

    if (hc == NULL) {
        // Create new host entry
        hc = malloc(sizeof(host_connections_t));
        if (hc == NULL) {
            pthread_mutex_unlock(&pool->mutex);
            free(key);
            connection->close(connection);
            connection_free(connection);
            return;
        }
        hc->connections = NULL;
        hc->count = 0;
        map_insert(pool->hosts, key, hc);
    }

    // Check if this connection is already in the pool
    pooled_connection_t* pc = hc->connections;
    while (pc != NULL) {
        if (pc->connection == connection) {
            // Mark as not busy and update TTL
            pc->busy = 0;
            pc->expires_at = time(NULL) + POOL_CONNECTION_TTL;
            pthread_mutex_unlock(&pool->mutex);
            free(key);
            return;
        }
        pc = pc->next;
    }

    // Add new pooled connection
    pooled_connection_t* new_pc = malloc(sizeof * new_pc);
    if (new_pc == NULL) {
        pthread_mutex_unlock(&pool->mutex);
        free(key);
        connection->close(connection);
        connection_free(connection);
        return;
    }

    new_pc->connection = connection;
    new_pc->use_ssl = use_ssl;
    new_pc->expires_at = time(NULL) + POOL_CONNECTION_TTL;
    new_pc->busy = 0;
    new_pc->next = hc->connections;
    hc->connections = new_pc;
    hc->count++;

    pthread_mutex_unlock(&pool->mutex);
    free(key);
}

void httpclientpool_discard(connection_pool_t* pool, const char* host, short port, connection_t* connection) {
    if (pool == NULL || host == NULL || connection == NULL) return;

    char* key = __make_host_key(host, port);
    if (key == NULL) {
        connection->close(connection);
        connection_free(connection);
        return;
    }

    pthread_mutex_lock(&pool->mutex);

    host_connections_t* hc = map_find(pool->hosts, key);
    if (hc != NULL) {
        pooled_connection_t* prev = NULL;
        pooled_connection_t* pc = hc->connections;

        while (pc != NULL) {
            if (pc->connection == connection) {
                if (prev == NULL) {
                    hc->connections = pc->next;
                } else {
                    prev->next = pc->next;
                }
                hc->count--;

                __close_pooled_connection(pc);
                free(pc);
                break;
            }
            prev = pc;
            pc = pc->next;
        }
    }

    pthread_mutex_unlock(&pool->mutex);
    free(key);

    // If not found in pool, just close it
    connection->close(connection);
    connection_free(connection);
}

void httpclientpool_cleanup_expired(connection_pool_t* pool) {
    if (pool == NULL) return;

    time_t now = time(NULL);

    pthread_mutex_lock(&pool->mutex);

    map_iterator_t it = map_begin(pool->hosts);
    while (map_iterator_valid(it)) {
        host_connections_t* hc = map_iterator_value(it);

        pooled_connection_t* prev = NULL;
        pooled_connection_t* pc = hc->connections;

        while (pc != NULL) {
            if (!pc->busy && pc->expires_at <= now) {
                pooled_connection_t* expired = pc;
                if (prev == NULL) {
                    hc->connections = pc->next;
                } else {
                    prev->next = pc->next;
                }
                pc = pc->next;
                hc->count--;

                __close_pooled_connection(expired);
                free(expired);
            } else {
                prev = pc;
                pc = pc->next;
            }
        }

        it = map_next(it);
    }

    pthread_mutex_unlock(&pool->mutex);
}

connection_pool_t* httpclientpool_global(void) {
    pthread_once(&global_pool_once, __global_pool_init_once);
    return global_pool;
}

void httpclientpool_global_init(void) {
    pthread_once(&global_pool_once, __global_pool_init_once);
}

void httpclientpool_global_free(void) {
    if (global_pool != NULL) {
        httpclientpool_free(global_pool);
        global_pool = NULL;
    }
}

static void __global_pool_init_once(void) {
    global_pool = httpclientpool_create();
}

// Internal functions

static char* __make_host_key(const char* host, short port) {
    size_t len = strlen(host) + 8;  // :port + null
    char* key = malloc(len);
    if (key == NULL) return NULL;

    snprintf(key, len, "%s:%d", host, port);
    return key;
}

static void __host_connections_free(void* arg) {
    host_connections_t* hc = arg;
    if (hc == NULL) return;

    pooled_connection_t* pc = hc->connections;
    while (pc != NULL) {
        pooled_connection_t* next = pc->next;
        __close_pooled_connection(pc);
        free(pc);
        pc = next;
    }

    free(hc);
}

static void __close_pooled_connection(pooled_connection_t* pc) {
    if (pc == NULL || pc->connection == NULL) return;

    connection_t* conn = pc->connection;

    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    if (conn->fd > 0) {
        shutdown(conn->fd, SHUT_RDWR);
        close(conn->fd);
    }

    connection_free(conn);
}

static int __is_connection_alive(connection_t* connection) {
    if (connection == NULL || connection->fd <= 0) return 0;

    // Check if socket is still valid using non-blocking peek
    char buf;
    int flags = MSG_PEEK | MSG_DONTWAIT;

    ssize_t result = recv(connection->fd, &buf, 1, flags);

    if (result == 0) {
        // Connection closed by peer
        return 0;
    }

    if (result < 0) {
        // EAGAIN/EWOULDBLOCK means socket is alive but no data
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }
        // Other errors mean connection is dead
        return 0;
    }

    // Data available - connection is alive
    return 1;
}

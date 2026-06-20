#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

#include "httpclientpool.h"
#include "connection.h"
#include "log.h"

static connection_pool_t* global_pool = NULL;
static pthread_once_t global_pool_once = PTHREAD_ONCE_INIT;

static void __global_pool_init_once(void);
static char* __make_host_key(const char* host, unsigned short port);
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

connection_t* httpclientpool_acquire(connection_pool_t* pool, const char* host, unsigned short port, int use_ssl) {
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

void httpclientpool_release(connection_pool_t* pool, const char* host, unsigned short port, connection_t* connection, int use_ssl) {
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

    // Cap per-host cached connections so a burst of outbound requests to one
    // host cannot grow fds without bound. If the host is already at the cap,
    // close the incoming connection instead of pooling it.
    if (hc->count >= POOL_MAX_CONNECTIONS_PER_HOST) {
        pthread_mutex_unlock(&pool->mutex);
        free(key);
        connection->close(connection);
        connection_free(connection);
        return;
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

void httpclientpool_discard(connection_pool_t* pool, const char* host, unsigned short port, connection_t* connection) {
    if (pool == NULL || host == NULL || connection == NULL) return;

    char* key = __make_host_key(host, port);
    if (key == NULL) {
        connection->close(connection);
        connection_free(connection);
        return;
    }

    pthread_mutex_lock(&pool->mutex);

    int found = 0;
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

                // __close_pooled_connection frees the connection, so the
                // fallback close below must NOT run when the connection was
                // found in the pool (otherwise: use-after-free / double-free).
                __close_pooled_connection(pc);
                free(pc);
                found = 1;
                break;
            }
            prev = pc;
            pc = pc->next;
        }
    }

    pthread_mutex_unlock(&pool->mutex);
    free(key);

    // Only close+free when the connection was NOT pooled (otherwise it was
    // already freed inside __close_pooled_connection above).
    if (!found) {
        connection->close(connection);
        connection_free(connection);
    }
}

void httpclientpool_cleanup_expired(connection_pool_t* pool) {
    if (pool == NULL) return;

    time_t now = time(NULL);

    // Host entries that become empty during the scan are erased after the
    // iteration completes — erasing while iterating would invalidate the map
    // iterator. Keys are strdup'd because the map owns (and frees) the stored
    // key on erase.
    char** empty_keys = NULL;
    size_t empty_count = 0;
    size_t empty_cap = 0;

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

        // Every connection for this host expired: schedule the now-empty host
        // entry for removal so the map does not leak a node per host ever seen.
        if (hc->count == 0) {
            char* key_copy = strdup((const char*)map_iterator_key(it));
            if (key_copy != NULL) {
                if (empty_count == empty_cap) {
                    const size_t new_cap = empty_cap ? empty_cap * 2 : 4;
                    char** grown = realloc(empty_keys, new_cap * sizeof(*empty_keys));
                    if (grown != NULL) {
                        empty_keys = grown;
                        empty_cap = new_cap;
                    } else {
                        free(key_copy);   // can't grow the list; leave this host
                        key_copy = NULL;
                    }
                }
                if (key_copy != NULL)
                    empty_keys[empty_count++] = key_copy;
            }
        }

        it = map_next(it);
    }

    for (size_t i = 0; i < empty_count; i++) {
        map_erase(pool->hosts, empty_keys[i]);
        free(empty_keys[i]);
    }
    free(empty_keys);

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

static char* __make_host_key(const char* host, unsigned short port) {
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

    // Probe the socket state without reading any bytes. This is safe for BOTH
    // plain and TLS connections: requesting no events (events=0) means poll only
    // reports the exceptional conditions (POLLERR/POLLHUP/POLLNVAL), which are
    // always filled in revents regardless of events. Reading bytes here (the old
    // recv(MSG_PEEK)) would corrupt the SSL state machine for HTTPS connections,
    // and would also block on a live idle connection.
    struct pollfd pfd = { .fd = connection->fd, .events = 0 };
    const int rc = poll(&pfd, 1, 0);

    if (rc < 0) {
        // EINTR is transient — treat the connection as still alive; anything
        // else means the fd is bad.
        return (errno == EINTR) ? 1 : 0;
    }

    if (rc == 0) {
        // No events pending: idle and alive.
        return 1;
    }

    if (pfd.revents & POLLNVAL) return 0;            // invalid fd
    if (pfd.revents & (POLLERR | POLLHUP)) return 0; // peer closed / error
#ifdef POLLRDHUP
    if (pfd.revents & POLLRDHUP) return 0;           // peer half-closed (Linux)
#endif

    // Only ordinary data events remain (e.g. unsolicited bytes the server
    // pushed): the connection is still alive.
    return 1;
}

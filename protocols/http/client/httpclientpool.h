#ifndef __HTTPCLIENTPOOL__
#define __HTTPCLIENTPOOL__

#include <time.h>
#include <pthread.h>

#include "connection.h"
#include "map.h"

#define POOL_CONNECTION_TTL 300  // 5 minutes in seconds

typedef struct pooled_connection {
    connection_t* connection;
    int use_ssl;
    time_t expires_at;
    unsigned int busy : 1;
    struct pooled_connection* next;
} pooled_connection_t;

typedef struct host_connections {
    pooled_connection_t* connections;
    int count;
} host_connections_t;

typedef struct connection_pool {
    map_t* hosts;  // key: "host:port", value: host_connections_t*
    pthread_mutex_t mutex;
} connection_pool_t;

// Pool lifecycle
connection_pool_t* httpclientpool_create(void);
void httpclientpool_free(connection_pool_t* pool);

// Connection management
connection_t* httpclientpool_acquire(connection_pool_t* pool, const char* host, short port, int use_ssl);
void httpclientpool_release(connection_pool_t* pool, const char* host, short port, connection_t* connection, int use_ssl);
void httpclientpool_discard(connection_pool_t* pool, const char* host, short port, connection_t* connection);

// Maintenance
void httpclientpool_cleanup_expired(connection_pool_t* pool);

// Global pool
connection_pool_t* httpclientpool_global(void);
void httpclientpool_global_init(void);
void httpclientpool_global_free(void);

#endif

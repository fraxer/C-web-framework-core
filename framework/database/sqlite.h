#ifndef __SQLITE__
#define __SQLITE__

#include <sqlite3.h>

#include "database.h"

// SQLite — embedded, file-based (or in-memory) database. Unlike the network
// drivers (postgresql/mysql/redis) it has no host/port: a connection is opened
// directly against a file `path`. Each worker thread keeps its own `sqlite3*`
// handle through the shared connection pool (db_connection_find by thread_id),
// which is the safe concurrency model for SQLite; combined with WAL mode and a
// busy_timeout it allows multi-threaded access without SQLITE_BUSY.
typedef struct sqlitehost {
    dbhost_t base;
    char* path;           // path to the database file (":memory:" for in-memory); required
    char* journal_mode;   // PRAGMA journal_mode; default "WAL"
    int busy_timeout;     // PRAGMA busy_timeout (ms); default 5000
} sqlitehost_t;

typedef struct sqliteconnection {
    dbconnection_t base;
    sqlite3* connection;
} sqliteconnection_t;

// Build a database descriptor from the "sqlite" array in config.json.
// Mirrors postgresql_load / redis_load: parses each object, validates required
// fields, and registers a host per entry.
db_t* sqlite_load(const char* database_id, const json_token_t* token_array);

#endif

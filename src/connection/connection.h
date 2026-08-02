#ifndef __CONNECTION__
#define __CONNECTION__

#include <openssl/ssl.h>

#include "socket.h"

typedef struct {
    void(*free)(void*);
    void(*reset)(void*);
} connection_ctx_t;

typedef struct connection {
    int fd;
    char* buffer;
    void* ctx; // connection_ctx_t

    SSL* ssl;
    SSL_CTX* ssl_ctx;
    in_addr_t ip;
    unsigned short int port;
    in_addr_t remote_ip;
    unsigned short int remote_port;
    unsigned keepalive: 1;

    size_t buffer_size;

    int(*close)(struct connection* connection);
    int(*read)(struct connection* connection);
    int(*write)(struct connection* connection);

    /* Intrusive links in the owning worker's connection list (multiplexing.h
     * mpxapi_t::conns). Maintained by the epoll layer on control_add/del, which
     * both run on the worker thread that owns the epoll, so no lock is needed.
     * The timer sweep walks this list to apply idle/PING/shutdown policy. */
    struct connection* prev;
    struct connection* next;
} connection_t;

void connection_reset(connection_t* connection);
void connection_free(connection_t* connection);
ssize_t connection_data_read(connection_t* connection);

/* INVARIANT: only the worker thread that owns this connection's epoll writes to
 * the socket. Handler threads fill response buffers and then hand back through
 * connection_after_read() / h2_server_response_ready(), which do nothing but
 * epoll_ctl — the bytes go out later, from connection->write().
 *
 * This is not stylistic. SSL* is not safe for concurrent SSL_write, and h2
 * frames a torn write cannot be recovered from: a DATA frame half on the wire
 * with another stream's frame interleaved is an unrecoverable protocol error.
 *
 * Verified for every socket-write path (docs/concurrency/00 §4.5): this
 * function, http_write_filter's __write, and h2_write_filter's __raw_write are
 * the only three, and all three are reachable only from connection->write() or
 * the worker's read path. The SMTP client (protocols/smtp) writes from a handler
 * thread, but to its own client connection, which no worker owns.
 *
 * Narrowing the connection lock (phase B) does not weaken this — it is what
 * makes narrowing safe. Anything that starts writing from a handler thread must
 * go through a queue instead. */
ssize_t connection_data_write(connection_t* connection, const char* data, size_t size);

#endif
